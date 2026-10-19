from __future__ import annotations

import ast
import builtins
import io
import re
import tokenize
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.quality._object_auth import defeated_owner_guard
from skylos.rules.quality._receivers import (
    class_method_nodes,
    context_method_kinds,
    possible_method_receiver,
)
from skylos.rules.quality._scope import is_sample_or_build_python
from skylos.rules.quality._typing import (
    comment_contract,
    is_typing_test_path,
    parameters,
    pytest_fixture_ids,
)


AUTH_MARKERS = (
    "auth",
    "login",
    "permission",
    "permit",
    "jwt",
    "token",
    "principal",
    "current_user",
    "require_user",
    "require_admin",
    "security",
)

MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROUTE_METHOD_NAMES = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
}
FASTAPI_ROUTE_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
    "websocket",
}


def _basename(filename: str | None) -> str:
    return Path(filename or "").name


def _is_non_production_path(filename: str | None) -> bool:
    normalized = str(filename or "").replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    base = Path(normalized).name
    return (
        "test" in parts
        or "tests" in parts
        or "corpus" in parts
        or base.startswith("test_")
        or base.endswith("_test.py")
    )


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _decorator_call(decorator: ast.AST) -> ast.Call | None:
    return decorator if isinstance(decorator, ast.Call) else None


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _dotted_name(decorator.func)
    return _dotted_name(decorator)


def _last_name_part(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _has_auth_marker(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in AUTH_MARKERS)


def _string_values(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for elt in node.elts:
            values.extend(_string_values(elt))
        return values
    return []


def _route_methods(decorator: ast.AST) -> tuple[str | None, set[str]]:
    name = _decorator_name(decorator)
    method_name = _last_name_part(name)
    if method_name not in ROUTE_METHOD_NAMES:
        return None, set()

    framework = "fastapi"
    if method_name == "route":
        framework = "flask"
    if name.startswith("app.") or name.startswith("blueprint."):
        if method_name == "route":
            framework = "flask"

    methods: set[str] = set()
    if method_name.upper() in MUTATING_HTTP_METHODS | {"GET"}:
        methods.add(method_name.upper())

    call = _decorator_call(decorator)
    if call is not None:
        for keyword in call.keywords:
            if keyword.arg == "methods":
                methods.update(value.upper() for value in _string_values(keyword.value))

    return framework, methods


def _mock_patch_decorators(module: ast.Module) -> set[int]:
    """Identify stdlib patch decorators without trusting their spelling.

    Import spelling alone does not prove runtime identity. Require a collected
    unittest.TestCase test method and a dotted mock target as well as an
    imported API with no possible rebinding. The rebinding check is deliberately
    conservative across nested scopes.
    """
    imports: dict[str, str] = {}
    for statement in module.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                imports[local] = alias.name if alias.asname else local
        elif isinstance(statement, ast.ImportFrom) and not statement.level:
            for alias in statement.names:
                imports[alias.asname or alias.name] = f"{statement.module}.{alias.name}"

    if not any(
        value == "unittest" or value.startswith("unittest.")
        for value in imports.values()
    ):
        return set()

    rebound: set[str] = set()
    for part in ast.walk(module):
        if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
            rebound.add(part.id)
        elif isinstance(part, ast.Attribute) and isinstance(
            part.ctx, (ast.Store, ast.Del)
        ):
            head = _dotted_name(part).split(".")[0]
            rebound.add(head)
            if head in imports:
                # Imported module aliases can refer to the same mutable
                # object. An assignment through another alias is uncertain.
                rebound.update(imports)
        elif isinstance(part, ast.arg):
            rebound.add(part.arg)
        elif isinstance(part, ast.ExceptHandler) and part.name:
            rebound.add(part.name)
        elif isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name:
            rebound.add(part.name)
        elif isinstance(part, ast.MatchMapping) and part.rest:
            rebound.add(part.rest)
        elif isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(part.name)
        elif isinstance(part, ast.Import):
            for alias in part.names:
                local = alias.asname or alias.name.split(".")[0]
                resolved = alias.name if alias.asname else local
                if imports.get(local) != resolved:
                    rebound.add(local)
        elif isinstance(part, ast.ImportFrom):
            for alias in part.names:
                if alias.name == "*":
                    rebound.update(imports)
                local = alias.asname or alias.name
                resolved = f"{part.module}.{alias.name}"
                if part.level or imports.get(local) != resolved:
                    rebound.add(local)

    def resolved_name(name: str) -> str:
        head, dot, tail = name.partition(".")
        if head in rebound:
            return ""
        return imports.get(head, "") + (dot + tail if dot else "")

    test_methods = {
        id(method)
        for cls in ast.walk(module)
        if isinstance(cls, ast.ClassDef)
        and any(
            resolved_name(_dotted_name(base)) == "unittest.TestCase"
            for base in cls.bases
        )
        for method in cls.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        and method.name.startswith("test_")
    }
    decorators: set[int] = set()
    for function in ast.walk(module):
        if id(function) not in test_methods:
            continue
        for decorator in function.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            target = decorator.args[0]
            if not (
                isinstance(target, ast.Constant)
                and isinstance(target.value, str)
                and "." in target.value
                and all(part.isidentifier() for part in target.value.split("."))
            ):
                continue
            if resolved_name(_decorator_name(decorator)) == "unittest.mock.patch":
                decorators.add(id(decorator))
    return decorators


def _is_fastapi_route(decorator: ast.AST) -> bool:
    name = _decorator_name(decorator)
    method_name = _last_name_part(name)
    if method_name not in FASTAPI_ROUTE_METHODS:
        return False
    return name.startswith(("app.", "router.", "api.", "server."))


def _call_uses_auth(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        name = _dotted_name(node.func)
        if _has_auth_marker(name):
            return True
        return any(_call_uses_auth(arg) for arg in node.args) or any(
            _call_uses_auth(keyword.value) for keyword in node.keywords
        )
    if isinstance(node, ast.Name):
        return _has_auth_marker(node.id)
    if isinstance(node, ast.Attribute):
        return _has_auth_marker(_dotted_name(node))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_call_uses_auth(elt) for elt in node.elts)
    return False


def _decorator_has_response_contract(decorator: ast.AST) -> bool:
    call = _decorator_call(decorator)
    if call is None:
        return False
    return any(
        keyword.arg in {"response_model", "response_class"}
        and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value is None
        )
        for keyword in call.keywords
    )


def _has_dependency_call(node: ast.AST | None) -> bool:
    """``[Depends(guard)]`` / ``[Security(guard, scopes=...)]``."""
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _last_name_part(_dotted_name(sub.func)) in {
            "depends",
            "security",
        }:
            return True
    return False


def _guarded_router_names(module: ast.AST) -> set[str]:
    """``router = APIRouter(dependencies=[Depends(guard)])``: every route on
    the router runs the guard."""
    names: set[str] = set()
    for stmt in ast.walk(module):
        if not isinstance(stmt, ast.Assign) or not isinstance(stmt.value, ast.Call):
            continue
        if _last_name_part(_dotted_name(stmt.value.func)) not in {
            "apirouter",
            "fastapi",
        }:
            continue
        if any(
            kw.arg == "dependencies" and _has_dependency_call(kw.value)
            for kw in stmt.value.keywords
        ):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


_SIGNATURE_VERIFY_RE = re.compile(
    r"^(?:verify|check|validate)_?(?:webhook_|request_|hmac_)?signature$"
    r"|^construct_event$|^verify_webhook$|^verify_header$"
)


def _is_signature_check(call: ast.Call) -> bool:
    """``hmac.compare_digest(...)``, ``verify_signature(...)``,
    ``signature.verify(...)``, ``stripe.Webhook.construct_event(...)``."""
    name = _dotted_name(call.func) or ""
    parts = [part.lower() for part in name.split(".") if part]
    if not parts:
        return False
    if parts[-2:] == ["hmac", "compare_digest"]:
        return True
    if _SIGNATURE_VERIFY_RE.match(parts[-1]):
        return True
    return parts[-1] == "verify" and any(
        "signature" in part or "webhook" in part or "hmac" in part
        for part in parts[:-1]
    )


def _body_verifies_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A webhook handler authenticates the sender by checking the request's
    signature first. Only the handler's own top-level statements count (an
    expression, assignment or ``if`` test, or the body of a top-level
    ``try``), so a check buried in a branch or helper doesn't."""
    statements = list(node.body)
    candidates: list[ast.AST] = []
    for stmt in statements:
        if isinstance(stmt, ast.Try):
            candidates.extend(stmt.body)
        else:
            candidates.append(stmt)
    for stmt in candidates:
        if isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign)):
            target = stmt.value
        elif isinstance(stmt, ast.If):
            target = stmt.test
        else:
            continue
        if target is None:
            continue
        for sub in ast.walk(target):
            if isinstance(sub, ast.Await):
                continue
            if isinstance(sub, ast.Call) and _is_signature_check(sub):
                return True
    return False


def _route_has_auth_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    guarded_routers: set[str] | None = None,
) -> bool:
    for decorator in node.decorator_list:
        name = _decorator_name(decorator)
        method_name = _last_name_part(name)
        if method_name not in ROUTE_METHOD_NAMES and _has_auth_marker(name):
            return True
        if guarded_routers and name.rsplit(".", 1)[0] in guarded_routers:
            return True

        call = _decorator_call(decorator)
        if call is not None:
            for keyword in call.keywords:
                if keyword.arg in {"dependencies", "dependency_overrides"}:
                    if _call_uses_auth(keyword.value):
                        return True
                    # Path-operation dependencies run only for their side
                    # effects (FastAPI discards the return value), so a
                    # Depends() there is a guard whatever the callable is named.
                    if keyword.arg == "dependencies" and _has_dependency_call(
                        keyword.value
                    ):
                        return True

    args = [
        *node.args.args,
        *node.args.posonlyargs,
        *node.args.kwonlyargs,
    ]
    defaults = [*node.args.defaults, *[d for d in node.args.kw_defaults if d]]
    for arg in args:
        if _has_auth_marker(arg.arg):
            return True
        if arg.annotation is not None and _has_auth_marker(
            _dotted_name(arg.annotation)
        ):
            return True
    if any(_call_uses_auth(default) for default in defaults):
        return True
    return _body_verifies_signature(node)


# PUT, PATCH and DELETE change state by definition. POST is also used for
# read-only RPC (search, inference, embedding): a POST route whose name or
# path reads as a query counts as mutating only when its body shows a state
# change. Any other POST keeps counting as mutating, since it may change
# state through calls whose names say nothing (``remote.fork(...)``).
STATE_CHANGING_HTTP_METHODS = {"PUT", "PATCH", "DELETE"}

# Words in a route's function name or URL path that read as a query.
_QUERY_ROUTE_WORDS = frozenset(
    {
        "analyse", "analyze", "ask", "autocomplete", "calculate", "caption",
        "chat", "check", "classify", "compare", "completion", "completions",
        "compute", "convert", "count", "decode", "describe", "detect", "diff",
        "download", "echo", "embed", "embedding", "embeddings", "encode",
        "estimate", "eval", "evaluate", "explain", "extract", "fetch", "find",
        "format", "generate", "get", "health", "healthz", "infer", "inference",
        "inspect", "lint", "list", "lookup", "match", "ocr", "parse", "ping",
        "predict", "prediction", "predictions", "preview", "query", "rank",
        "read", "recognize", "recommend", "render", "rerank", "retrieval",
        "retrieve", "score", "search", "segment", "show", "similar",
        "similarity", "suggest", "summarize", "tokenize", "transcribe",
        "translate", "validate", "view",
    }
)  # fmt: skip

# Words in a route's function name or URL path that name a state change.
# Common nouns ("order", "book") and read-only actions of inference or file
# tools ("run", "complete", "apply", "merge") are left out.
_STATE_CHANGE_ROUTE_WORDS = frozenset(
    {
        "accept", "activate", "add", "append", "approve", "archive", "assign",
        "ban", "block", "callback", "cancel", "charge", "checkout", "claim",
        "clear", "close", "comment", "commit", "confirm", "create",
        "deactivate", "decline", "decrement", "delete", "deploy", "destroy",
        "disable", "drop", "edit", "enable", "enqueue", "exec", "execute",
        "finish", "follow", "grant", "hook", "hooks", "import", "increment",
        "ingest", "insert", "install", "invite", "join", "kill", "leave",
        "like", "lock", "login", "logout", "mark", "migrate", "modify", "move",
        "notify", "pay", "publish", "purchase", "purge", "push", "refund",
        "rebuild", "refresh", "register", "reindex", "reject", "release",
        "reload", "remove", "rename", "reserve", "reset", "restart", "restore",
        "revoke", "save", "schedule", "send",
        "set", "share", "shutdown", "signin", "signout", "signup", "start",
        "stop", "store", "submit", "subscribe", "sync", "terminate", "toggle",
        "train", "transfer", "trigger", "unassign", "unblock", "unfollow",
        "uninstall", "unlike", "unlock", "unsubscribe", "update", "upload",
        "upsert", "vote", "webhook", "webhooks", "write",
    }
)  # fmt: skip

# Call names that persist data or cause an external side effect: ORM /
# session / cursor writes, key-value stores, queues, messaging, outgoing
# writes over HTTP, file-system changes.
_STATE_CHANGE_CALL_NAMES = frozenset(
    {
        "add", "apply_async", "approve", "cancel", "charge", "chmod", "chown",
        "commit", "create", "decr", "decrement", "delay", "delete", "deploy",
        "destroy", "dispatch", "drop", "dump", "emit", "enqueue", "evict",
        "execute", "executemany", "executescript", "expire", "flush", "grant",
        "hdel", "hmset", "hset", "incr", "incrby", "increment", "insert",
        "install", "invalidate", "kill", "lpush", "makedirs", "merge", "mkdir",
        "notify", "patch", "persist", "post", "publish", "purge", "push",
        "put", "refund", "register", "reject", "remove", "rename", "reset",
        "revoke", "rmdir", "rmtree", "rpush", "sadd", "save", "schedule",
        "send", "send_task", "sendall", "sendmail", "set", "setex", "setnx",
        "srem", "store", "submit", "terminate", "touch", "train", "transfer",
        "trigger", "truncate", "unlink", "update", "upload", "upsert", "write",
        "writelines", "zadd", "zrem",
    }
)  # fmt: skip

# Leading words of compound call names that do the same (``add_task``,
# ``insert_one``, ``put_object``, ``send_email``). Words whose compounds are
# common read-only data helpers (``post_process``, ``drop_duplicates``,
# ``reset_index``, ``train_test_split``) only count as whole names.
_STATE_CHANGE_CALL_PREFIXES = frozenset(
    {
        "add", "approve", "bulk", "cancel", "charge", "commit", "create",
        "decrement", "delete", "deploy", "destroy", "enqueue", "execute",
        "grant", "increment", "insert", "install", "invalidate", "notify",
        "persist", "publish", "purge", "push", "put", "refund", "register",
        "remove", "revoke", "save", "schedule", "send", "set", "store",
        "submit", "transfer", "trigger", "update", "upload", "upsert", "write",
    }
)  # fmt: skip

# Framework helpers that build a read-only response.
_READ_ONLY_CALL_NAMES = frozenset({"send_file", "send_from_directory"})

# Words that mark a write anywhere in a compound call name
# (``get_or_create``, ``find_one_and_update``, ``batch_write_item``).
_STATE_CHANGE_CALL_ANY_WORDS = frozenset(
    {
        "commit", "create", "delete", "destroy", "insert", "persist", "purge",
        "remove", "save", "update", "upload", "upsert", "write",
    }
)  # fmt: skip

# Container methods that change only the receiver: a state change only when
# the receiver outlives the request (module state, ``self``, an injected
# object), not when it is a local built during the request.
_RECEIVER_MUTATORS = frozenset(
    {
        "add", "append", "clear", "discard", "drop", "extend", "insert",
        "pop", "popitem", "put", "remove", "reverse", "set", "setdefault",
        "sort", "update", "write", "writelines",
    }
)  # fmt: skip

_OS_SIDE_EFFECTS = frozenset(
    {
        "chmod", "chown", "kill", "killpg", "link", "makedirs", "mkdir",
        "popen", "putenv", "remove", "removedirs", "rename", "renames",
        "replace", "rmdir", "startfile", "symlink", "system", "truncate",
        "unlink", "unsetenv", "utime", "write",
    }
)  # fmt: skip
_SHUTIL_READ_ONLY = frozenset({"disk_usage", "get_terminal_size", "which"})
# A call proves nothing about state unless it is known to be read-only:
# builtins, same-module helpers (their bodies are checked), the modules and
# value methods below, response helpers, and callees whose own name reads as
# a query. Any other callee (``coupons.redeem``, ``frame.to_sql``,
# ``client.invoke``) counts as a state change.
_READ_ONLY_CALL_MODULES = frozenset(
    {"json", "re", "math", "logging", "time", "datetime", "uuid", "statistics",
     "itertools", "functools", "operator", "string", "textwrap", "base64",
     "hashlib", "html", "typing", "copy", "decimal", "fractions", "os.path",
     "posixpath", "urllib.parse", "unicodedata"}
)  # fmt: skip
# Value methods prove nothing on a long-lived object (``s3.copy(...)``
# copies an object in a bucket, ``es.index(...)`` stores a document), so they
# count only on values made during the request; see ``_is_request_value``.
_READ_ONLY_VALUE_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "title", "split",
     "rsplit", "splitlines", "join", "replace", "format", "encode", "decode",
     "startswith", "endswith", "get", "items", "keys", "values", "copy",
     "count", "find", "tolist", "item", "isoformat", "hexdigest",
     "model_dump", "dict", "json", "to_dict", "numpy", "cpu", "detach",
     "astype", "reshape", "mean", "sum", "max", "min", "argmax", "argmin"}
)  # fmt: skip
# ``list.index`` / ``str.index``; on anything but a literal it may be a
# search-engine write (``es.index(document=...)``).
_LITERAL_NODES = (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.ListComp)
# Logging methods are read-only only on a logger (``audit.log(...)`` may
# write an audit record).
_LOG_METHODS = frozenset(
    {"critical", "debug", "error", "exception", "fatal", "info", "log",
     "warn", "warning"}
)  # fmt: skip
_LOGGER_FACTORIES = frozenset({"getLogger", "get_logger"})
_LOGGER_MODULES = frozenset({"loguru", "structlog"})
# The framework request object: reading its body, query, form, headers or
# files changes nothing (``request.get_json()``, ``request.args.get("q")``,
# ``await request.form()``, ``request.files["f"].read()``).
_REQUEST_NAMES = frozenset({"request", "req"})
_REQUEST_READ_METHODS = frozenset(
    {"body", "form", "get_data", "get_json", "json", "read", "stream", "text"}
)  # fmt: skip
_REQUEST_CONTAINERS = frozenset(
    {"args", "cookies", "data", "files", "form", "GET", "headers", "json",
     "META", "params", "path_params", "POST", "query", "query_params",
     "values"}
)  # fmt: skip
_INJECTION_CALLS = frozenset({"Depends", "Security"})
_RESPONSE_HELPERS = frozenset(
    {"jsonify", "make_response", "Response", "JSONResponse",
     "PlainTextResponse", "HTMLResponse", "StreamingResponse", "FileResponse",
     "HTTPException", "abort", "render_template", "redirect", "url_for",
     "escape"}
)  # fmt: skip
# Words that make a callee's own name read as a query (``search_documents``,
# ``predict_proba``, ``batch_search``). ``get`` is left out: getters often
# create or claim (``get_or_create``, ``get_lock``, ``get_next_id``); so are
# ``count``, ``match`` and ``score``, which as verbs often record something
# (count a vote, match a rider, score a submission).
_QUERY_CALL_WORDS = frozenset(
    {"search", "retrieve", "retrieval", "predict", "prediction", "predictions",
     "infer", "inference", "classify", "embed", "embedding", "embeddings",
     "encode", "decode", "find", "lookup", "query", "read", "fetch",
     "describe", "rank", "rerank", "similar", "similarity", "parse",
     "tokenize"}
)  # fmt: skip
# A name that joins a second action (``fetch_and_store``) or names a write
# anywhere (``mark_as_read``, ``record_query``, ``find_one_and_replace``)
# does not read as a query, even where the write word is a noun
# (``fetch_record``): the name alone cannot tell.
_ACTION_JOINERS = frozenset({"and", "or", "then"})
_WRITE_WORDS = frozenset(
    {"add", "append", "apply", "approve", "archive", "assign", "ban", "block",
     "book", "cache", "cancel", "charge", "claim", "clear", "commit",
     "confirm", "copy", "create", "decrement", "delete", "destroy", "disable",
     "drop", "edit", "emit", "enable", "enqueue", "extend", "fit", "flush",
     "grant", "increment", "index", "insert", "invalidate", "lock", "log",
     "mark", "merge", "modify", "move", "notify", "patch", "pay", "persist",
     "pop", "post", "publish", "purge", "push", "put", "record", "refresh",
     "refund", "register", "reject", "remove", "rename", "replace", "reserve",
     "reset", "revoke", "save", "send", "set", "store", "submit",
     "subscribe", "sync", "toggle", "track", "train", "unlock", "update",
     "upload", "upsert", "vote", "write"}
)  # fmt: skip
_SHARED_STATE_ATTRIBUTES = frozenset({"session", "cookies", "state"})
_WRITE_MODE_CHARACTERS = frozenset("wax+")
_FILE_MODE_RE = re.compile(r"^[rwaxbtU+]{1,4}$")
_HELPER_DEPTH = 3
# Builtins that run code or stop the process (``eval(expr)``).
_CODE_EXECUTION_BUILTINS = frozenset(
    {"eval", "exec", "compile", "__import__", "breakpoint", "exit", "quit"}
)
# Builtins that hand back an existing object (an element, an attribute, a
# namespace) rather than a value the call makes.
_PASS_THROUGH_BUILTINS = frozenset(
    {"next", "iter", "getattr", "vars", "globals", "locals", "super", "memoryview"}
)
# Callees whose first positional argument is a function they call.
_HIGHER_ORDER_CALLEES = frozenset({"map", "filter", "reduce", "partial", "starmap"})
# Request attributes that reach state shared across requests
# (``request.app.state.vectors``, ``request.session``).
_SHARED_REQUEST_ATTRIBUTES = frozenset({"app", "session"})
# Value methods that are also client or file operations (``s3.copy``,
# ``path.replace`` renames, ``sio.join(room)``): read-only only on a value
# made during the request.
_CLIENT_VALUE_METHODS = frozenset({"copy", "replace", "join"})
_READ_ONLY_MODULE_ROOTS = frozenset(
    {"json", "re", "math", "logging", "itertools", "functools", "operator"}
)
# Nodes that always evaluate to a new object.
_NEW_VALUE_NODES = (
    ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Set, ast.Dict,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.BinOp,
    ast.UnaryOp, ast.Compare, ast.Lambda,
)  # fmt: skip
# SQL sent through a query-named method (``db.query(sql)``): the statement,
# not the method name, says whether it writes.
_SQL_CALL_WORDS = frozenset({"query", "execute"})
# Receivers that name a database connection; SQL built at run time and sent
# to one may write.
_SQL_RECEIVER_WORDS = frozenset(
    {"conn", "connection", "cur", "cursor", "database", "databases", "db",
     "dbapi", "duckdb", "clickhouse", "mariadb", "mysql", "pg", "postgres",
     "postgresql", "psql", "sql", "sqlite", "sqlite3", "warehouse"}
)  # fmt: skip
_SQL_READ_STATEMENTS = frozenset(
    {"select", "with", "show", "explain", "describe", "desc", "values", "table"}
)
_SQL_STATEMENTS = _SQL_READ_STATEMENTS | frozenset(
    {"insert", "update", "delete", "merge", "upsert", "replace", "create",
     "drop", "alter", "truncate", "grant", "revoke", "call", "copy", "lock",
     "vacuum", "reindex", "set", "attach", "detach", "pragma", "commit",
     "rollback"}
)  # fmt: skip
# A write keyword anywhere in a read statement (``WITH x AS (DELETE ...)``,
# ``SELECT ... INTO``, ``FOR UPDATE``); ``replace(`` is the string function.
_SQL_WRITE_RE = re.compile(
    r"\b(?:insert|update|delete|merge|upsert|replace|create|drop|alter|"
    r"truncate|grant|revoke|call|copy|into|lock|vacuum|reindex|attach|"
    r"detach)\b(?!\s*\()",
    re.IGNORECASE,
)
# Comments and quoted strings or identifiers, which never change the statement.
_SQL_NOISE_RE = re.compile(
    r"--[^\n]*|/\*.*?\*/|'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"", re.DOTALL
)
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|[^A-Za-z]|$)|[A-Z]?[a-z]+|[0-9]+")


def _words(value: str) -> list[str]:
    return [word.lower() for word in _WORD_RE.findall(value)]


def _route_paths(decorators: list[ast.AST]) -> list[str]:
    paths = []
    for decorator in decorators:
        call = _decorator_call(decorator)
        if call is None:
            continue
        if call.args:
            paths.extend(_string_values(call.args[0]))
        for keyword in call.keywords:
            if keyword.arg in {"path", "rule"}:
                paths.extend(_string_values(keyword.value))
    return paths


def _route_words(function, route_decorators) -> set[str]:
    words = set(_words(function.name))
    for path in _route_paths(route_decorators):
        words.update(_words(path))
    return words


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.Await)):
        if isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _chain_attributes(node: ast.AST) -> set[str]:
    names = set()
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(node, ast.Attribute):
            names.add(node.attr.lower())
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    return names


def _bound_names(target: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _local_names(function) -> tuple[set[str], set[str], set[str]]:
    """Names a function binds, its parameters, and names declared global or
    nonlocal (which bind outer state)."""
    params = {
        arg.arg
        for arg in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            function.args.vararg,
            function.args.kwarg,
        ]
        if arg is not None
    }
    outer: set[str] = set()
    bound: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            outer.update(node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
                    bound.update(_bound_names(target))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            bound.update(_bound_names(node.target))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            bound.update(_bound_names(node.optional_vars))
        elif isinstance(node, ast.NamedExpr):
            bound.update(_bound_names(node.target))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update(
                (alias.asname or alias.name).split(".", 1)[0] for alias in node.names
            )
    return bound - outer, params, outer


def _shared_aliases(function, local, params) -> dict[str, str]:
    """Locals that stand for shared state, not a value made during the
    request, mapped to the dotted name they stand for: anything imported in
    the function (``import shutil as file_ops``), and names assigned a module,
    a global, ``self``/``cls`` state or another such alias (``file_ops =
    shutil``, ``store = cache``, ``store = request.app.state.vectors``).
    Request data (``query = request.json``) stays request data."""
    aliases: dict[str, str] = {}
    assigned = []
    for node in ast.walk(function):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".", 1)[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom):
            module = "." * (node.level or 0) + (node.module or "")
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node.value, (ast.Name, ast.Attribute)):
                assigned.extend(
                    (target.id, node.value)
                    for target in targets
                    if isinstance(target, ast.Name)
                )
    changed = True
    while changed:
        changed = False
        for name, value in assigned:
            root = _root_name(value)
            if name in aliases or root is None:
                continue
            dotted = _dotted_name(value)
            if root in _REQUEST_NAMES:
                if not _chain_attributes(value) & _SHARED_REQUEST_ATTRIBUTES:
                    continue
                aliases[name] = dotted
            elif root in aliases:
                aliases[name] = aliases[root] + dotted[len(root) :]
            elif root in {"self", "cls"} or (root not in local and root not in params):
                aliases[name] = dotted
            else:
                continue
            changed = True
    return aliases


def _resolve_alias(dotted: str, aliases) -> str:
    root, _, rest = dotted.partition(".")
    if root not in aliases:
        return dotted
    return f"{aliases[root]}.{rest}" if rest else aliases[root]


def _store_changes_state(target, scope: _RouteScope) -> bool:
    if isinstance(target, (ast.Tuple, ast.List, ast.Starred)):
        elts = target.elts if not isinstance(target, ast.Starred) else [target.value]
        return any(_store_changes_state(elt, scope) for elt in elts)
    if isinstance(target, ast.Name):
        return target.id in scope.outer
    if not isinstance(target, (ast.Attribute, ast.Subscript)):
        return False
    root = _root_name(target)
    if root is None:
        return False
    if root in {"self", "cls"} or root in scope.outer:
        return True
    if root in scope.params:
        # A request model is the caller's copy; its session, cookies or
        # app state are not.
        return bool(_chain_attributes(target) & _SHARED_STATE_ATTRIBUTES)
    # A local may hold shared state (``cache = results_cache()``) unless it
    # was made during the request.
    return root not in scope.request_locals


def _open_writes(call: ast.Call) -> bool:
    name = _dotted_name(call.func)
    if name in {"open", "io.open", "codecs.open"}:
        mode_node = call.args[1] if len(call.args) > 1 else None
    elif isinstance(call.func, ast.Attribute) and call.func.attr == "open":
        mode_node = call.args[0] if call.args else None
    else:
        return False
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    # ``Image.open("cat.png")`` passes a path where ``Path.open`` takes a mode.
    return any(
        _FILE_MODE_RE.match(mode) and set(mode) & _WRITE_MODE_CHARACTERS
        for mode in _string_values(mode_node)
    )


def _call_changes_state(call: ast.Call, scope: _RouteScope) -> bool:
    if _open_writes(call):
        return True
    func = call.func
    if isinstance(func, ast.Name):
        name = func.id
        if name in _CODE_EXECUTION_BUILTINS and name not in scope.bound:
            return True
        if name in {"setattr", "delattr"} and call.args:
            receiver = _root_name(call.args[0])
            return receiver is not None and receiver not in scope.request_locals
        if hasattr(builtins, name):
            return False
    elif isinstance(func, ast.Attribute):
        name = func.attr
    else:
        # A dispatch-table entry, a returned callable or a lambda: nothing
        # says what it does.
        return True
    dotted = _resolve_alias(_dotted_name(func), scope.aliases)
    module = dotted.split(".", 1)[0] if "." in dotted else ""
    if module == "subprocess":
        return True
    if module == "shutil" and name not in _SHUTIL_READ_ONLY:
        return True
    if module == "os" and (
        name in _OS_SIDE_EFFECTS or name.startswith(("exec", "spawn"))
    ):
        return True
    lowered = name.lower()
    if lowered in _READ_ONLY_CALL_NAMES:
        return False
    if isinstance(func, ast.Attribute) and lowered in _RECEIVER_MUTATORS:
        receiver = _root_name(func.value)
        return receiver is not None and receiver not in scope.request_locals
    if lowered in _STATE_CHANGE_CALL_NAMES:
        return True
    words = _words(name)
    if len(words) >= 2 and (
        words[0] in _STATE_CHANGE_CALL_PREFIXES
        or set(words) & _STATE_CHANGE_CALL_ANY_WORDS
    ):
        return True
    return not _call_is_read_only(call, func, name, dotted, scope)


def _call_is_read_only(call, func, name: str, dotted: str, scope: _RouteScope) -> bool:
    if isinstance(func, ast.Name):
        if name in scope.module_functions or name in _RESPONSE_HELPERS:
            return True
    module = dotted.rsplit(".", 1)[0] if "." in dotted else ""
    if module in _READ_ONLY_CALL_MODULES or module.split(".", 1)[0] in (
        _READ_ONLY_MODULE_ROOTS
    ):
        return True
    if isinstance(func, ast.Attribute):
        lowered = name.lower()
        if lowered in _LOG_METHODS:
            return _is_logger(func.value, scope.loggers)
        if lowered == "index":
            return isinstance(func.value, _LITERAL_NODES)
        if _reads_request(func):
            return True
        if lowered in _READ_ONLY_VALUE_METHODS and scope.value_method_is_read_only(
            func.value, lowered
        ):
            return True
    if not _name_reads_as_query(name):
        return False
    return _sql_call_writes(call, name, scope) is not True


def _sql_text(node) -> str | None:
    """The text of a string literal, with ``?`` for an f-string's fields."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else " ? "
            for part in node.values
        )
    return None


def _sql_writes(text: str) -> bool | None:
    """True for SQL that may write, False for a read-only statement, None
    when the text is not SQL (a question in words, a filter expression)."""
    code = _SQL_NOISE_RE.sub(" ", text)
    match = re.match(r"[\s(]*([A-Za-z]+)", code)
    if match is None or match.group(1).lower() not in _SQL_STATEMENTS:
        return None
    statement = match.group(1).lower()
    return statement not in _SQL_READ_STATEMENTS or bool(_SQL_WRITE_RE.search(code))


def _receiver_words(node) -> set[str]:
    words: set[str] = set()
    while True:
        if isinstance(node, ast.Attribute):
            words.update(_words(node.attr))
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            if isinstance(node, ast.Name):
                words.update(_words(node.id))
            return words


def _sql_call_writes(call: ast.Call, name: str, scope: _RouteScope) -> bool | None:
    """Whether SQL sent through a query-named call may write: decided by the
    statement when it is a literal (or a local only ever bound to literals),
    and True for SQL built at run time (a local or parameter) sent to a
    database connection. None when the call says nothing about SQL (an ORM
    model, a question for a retrieval engine)."""
    if not call.args or not set(_words(name)) & _SQL_CALL_WORDS:
        return None
    first = call.args[0]
    text = _sql_text(first)
    if text is not None:
        return _sql_writes(text)
    if not isinstance(first, ast.Name) or first.id not in scope.bound:
        return None
    texts = scope.literal_strings.get(first.id)
    if texts:
        verdicts = {_sql_writes(text) for text in texts}
        if True in verdicts:
            return True
        return False if verdicts == {False} else None
    if isinstance(call.func, ast.Attribute) and (
        _receiver_words(call.func.value) & _SQL_RECEIVER_WORDS
    ):
        return True
    return None


def _name_reads_as_query(name: str) -> bool:
    words = set(_words(name))
    if words & (_ACTION_JOINERS | _WRITE_WORDS):
        return False
    return bool(words & _QUERY_CALL_WORDS)


def _reads_request(func: ast.Attribute) -> bool:
    receiver = func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in _REQUEST_NAMES and func.attr in _REQUEST_READ_METHODS
    node = receiver
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id in _REQUEST_NAMES and node.attr in _REQUEST_CONTAINERS
        node = node.value
    return False


def _is_logger_factory(node) -> bool:
    return (
        isinstance(node, ast.Call)
        and _dotted_name(node.func).rsplit(".", 1)[-1] in _LOGGER_FACTORIES
    )


def _is_logger(receiver: ast.AST, loggers) -> bool:
    """``logger`` bound to ``logging.getLogger(...)`` (or imported from
    loguru/structlog), ``app.logger`` / ``self.logger``, or the factory call."""
    if isinstance(receiver, ast.Name):
        return receiver.id in loggers
    if isinstance(receiver, ast.Attribute):
        return receiver.attr == "logger"
    return _is_logger_factory(receiver)


def _logger_names(statements) -> set[str]:
    names = set()
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and _is_logger_factory(
                node.value
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                names.update(t.id for t in targets if isinstance(t, ast.Name))
            elif (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".", 1)[0] in _LOGGER_MODULES
            ):
                names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "logger"
                )
    return names


def _injected_parameters(function) -> set[str]:
    """Parameters the framework fills with a shared object
    (``db=Depends(get_db)``, ``Annotated[Redis, Depends(get_redis)]``)."""
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = list(
        zip(positional[len(positional) - len(args.defaults) :], args.defaults)
    )
    defaults += list(zip(args.kwonlyargs, args.kw_defaults))
    injected = set()
    for arg in [*positional, *args.kwonlyargs]:
        nodes = [default for owner, default in defaults if owner is arg and default]
        if arg.annotation is not None:
            nodes.append(arg.annotation)
        if any(
            isinstance(node, ast.Call)
            and _dotted_name(node.func).rsplit(".", 1)[-1] in _INJECTION_CALLS
            for root in nodes
            for node in ast.walk(root)
        ):
            injected.add(arg.arg)
    return injected


def _local_bindings(function) -> dict[str, list[tuple[str, ast.AST | None]]]:
    """Every binding of each local, as ``(kind, expression)``: ``value`` (the
    name holds the expression's value), ``item`` (an element or unpacked
    part of it), ``aug`` (an augmented assignment), ``new`` (an exception
    object or a nested definition) or ``shared`` (an import)."""
    bindings: dict[str, list[tuple[str, ast.AST | None]]] = {}

    def bind(target, kind, value):
        if isinstance(target, ast.Name):
            bindings.setdefault(target.id, []).append((kind, value))
        elif isinstance(target, (ast.Tuple, ast.List)):
            if (
                kind == "value"
                and isinstance(value, (ast.Tuple, ast.List))
                and len(value.elts) == len(target.elts)
                and not any(isinstance(elt, ast.Starred) for elt in target.elts)
            ):
                for elt, part in zip(target.elts, value.elts):
                    bind(elt, "value", part)
            else:
                for elt in target.elts:
                    bind(elt, "item", value)
        elif isinstance(target, ast.Starred):
            bind(target.value, "item", value)

    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, "value", node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, "value", node.value)
        elif isinstance(node, ast.AugAssign):
            bind(node.target, "aug", node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            bind(node.target, "item", node.iter)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            bind(node.optional_vars, "value", node.context_expr)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, "value", node.value)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bindings.setdefault(node.name, []).append(("new", None))
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node is not function
        ):
            bindings.setdefault(node.name, []).append(("new", None))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".", 1)[0]
                bindings.setdefault(name, []).append(("shared", None))
    return bindings


def _returns_shared_state(function) -> bool:
    """A helper that hands back module or instance state (``return _CACHE``)."""
    local, params, outer = _local_names(function)
    for node in ast.walk(function):
        if isinstance(node, ast.Return) and isinstance(
            node.value, (ast.Name, ast.Attribute, ast.Subscript)
        ):
            root = _root_name(node.value)
            if root is None:
                continue
            if root in {"self", "cls"} or root in outer:
                return True
            if root not in local and root not in params and not hasattr(builtins, root):
                return True
    return False


class _RouteScope:
    """What a route's names hold.

    ``request_locals`` are locals made during the request: new objects
    (literals, displays, comprehensions, builtin results), request data and
    values computed from it. A call whose callee and arguments say nothing
    about the request (``results_cache()``, ``lookup_store()``) may return
    shared state, so a local bound to one is not request-local.
    """

    def __init__(self, function, module_functions, module_loggers=frozenset()):
        local, params, outer = _local_names(function)
        self.module_functions = module_functions
        self.outer = outer
        self.params = params
        self.request_params = params - _injected_parameters(function)
        self.bound = frozenset(local | params)
        self.aliases = _shared_aliases(function, local, params)
        candidates = local - set(self.aliases)
        self.loggers = (set(module_loggers) - candidates - params) | _logger_names(
            function.body
        )
        bindings = _local_bindings(function)
        self.literal_strings = {
            name: tuple(_sql_text(value) for _kind, value in entries)
            for name, entries in bindings.items()
            if all(kind == "value" and _sql_text(value) is not None for kind, value in entries)
        }
        # Greatest fixed point: drop a local while one of its bindings is not
        # request-local.
        self.request_locals = set(candidates)
        changed = True
        while changed:
            changed = False
            for name in list(self.request_locals):
                if not all(
                    self._binding_is_request_local(kind, value)
                    for kind, value in bindings.get(name, ())
                ):
                    self.request_locals.discard(name)
                    changed = True
        self.request_locals = frozenset(self.request_locals)
        self.other_locals = frozenset(candidates - self.request_locals)

    def _binding_is_request_local(self, kind, value) -> bool:
        if kind in {"new", "aug"}:
            return True
        if kind == "shared":
            return False
        return self.is_request_local(value)

    def _request_name(self, name: str) -> bool:
        return (
            name in self.request_locals
            or name in self.request_params
            or (name in _REQUEST_NAMES and name not in self.bound)
        )

    def is_request_local(self, node) -> bool:
        if isinstance(node, _NEW_VALUE_NODES):
            return True
        if isinstance(node, ast.BoolOp):
            return all(self.is_request_local(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_request_local(node.body) and self.is_request_local(
                node.orelse
            )
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.is_request_local(node.value)
        if isinstance(node, ast.Name):
            return self._request_name(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if _root_name(node) in _REQUEST_NAMES and (
                _chain_attributes(node) & _SHARED_REQUEST_ATTRIBUTES
            ):
                return False
            return self.is_request_local(node.value)
        if isinstance(node, ast.Call):
            return self._call_result_is_request_local(node)
        return False

    def _mentions_request_data(self, node) -> bool:
        return any(
            isinstance(child, ast.Name) and self._request_name(child.id)
            for child in ast.walk(node)
        )

    def _call_result_is_request_local(self, call: ast.Call) -> bool:
        func = call.func
        if isinstance(func, ast.Name) and func.id not in self.bound:
            if hasattr(builtins, func.id):
                return (
                    func.id not in _PASS_THROUGH_BUILTINS
                    and func.id not in _CODE_EXECUTION_BUILTINS
                )
            helper = self.module_functions.get(func.id)
            if helper is not None and _returns_shared_state(helper):
                return False
        dotted = _resolve_alias(_dotted_name(func), self.aliases)
        module = dotted.rsplit(".", 1)[0] if "." in dotted else ""
        if module and (
            module in _READ_ONLY_CALL_MODULES
            or module.split(".", 1)[0] in _READ_ONLY_MODULE_ROOTS
        ):
            return True
        if isinstance(func, ast.Attribute) and (
            _reads_request(func) or self.is_request_local(func.value)
        ):
            return True
        return any(
            self._mentions_request_data(argument)
            for argument in [*call.args, *(keyword.value for keyword in call.keywords)]
        )

    def value_method_is_read_only(self, receiver, method: str) -> bool:
        """``text.strip()``, ``rows.copy()``: read-only on a value made during
        the request; on a value a query returned, unless the method is also a
        client operation; never on shared state (``s3.copy(...)``)."""
        if _root_name(receiver) in _REQUEST_NAMES and (
            _chain_attributes(receiver) & _SHARED_REQUEST_ATTRIBUTES
        ):
            return False
        node = receiver
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        if isinstance(node, ast.Name):
            if self._request_name(node.id):
                return True
            if node.id in self.other_locals:
                return method not in _CLIENT_VALUE_METHODS
            return False
        if isinstance(node, ast.Call):
            return (
                self._call_result_is_request_local(node)
                or method not in _CLIENT_VALUE_METHODS
            )
        return True

    def holds_shared_state(self, name: str) -> bool:
        return name in self.aliases or name in self.other_locals


def _function_arguments(call: ast.Call) -> list[ast.AST]:
    """Arguments the callee calls: the function given to ``map``/``filter``/
    ``partial``/``reduce``/``starmap`` and any ``key=`` function."""
    functions = [keyword.value for keyword in call.keywords if keyword.arg == "key"]
    if call.args and _dotted_name(call.func).rsplit(".", 1)[-1] in _HIGHER_ORDER_CALLEES:
        functions.append(call.args[0])
    return functions


def _body_changes_state(
    function, module_functions, depth=0, seen=None, module_loggers=frozenset()
) -> bool:
    """Evidence in the function body, or in a same-module helper it calls,
    that it persists data or has an external side effect. Helpers past the
    inspection depth are unchecked, so they count as a state change."""
    seen = set() if seen is None else seen
    seen.add(id(function))
    scope = _RouteScope(function, module_functions, module_loggers)
    helpers = []
    for statement in function.body:
        for node in ast.walk(statement):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(_store_changes_state(target, scope) for target in targets):
                    return True
                # ``cache += [q]`` extends a shared list in place.
                if (
                    isinstance(node, ast.AugAssign)
                    and isinstance(node.target, ast.Name)
                    and scope.holds_shared_state(node.target.id)
                ):
                    return True
            elif isinstance(node, ast.Delete):
                if any(_store_changes_state(target, scope) for target in node.targets):
                    return True
            elif isinstance(node, ast.Call):
                if _call_changes_state(node, scope):
                    return True
                called = [node.func, *_function_arguments(node)]
                # A same-module function passed as a value (a callback, a
                # ``map`` function) runs too; its body is checked.
                called += [
                    argument
                    for argument in [*node.args, *(k.value for k in node.keywords)]
                    if isinstance(argument, ast.Name)
                    and argument.id in module_functions
                ]
                for callee in called:
                    if not isinstance(callee, ast.Name) or callee.id in scope.bound:
                        continue
                    helper = module_functions.get(callee.id)
                    if helper is not None:
                        if id(helper) not in seen:
                            helpers.append(helper)
                    elif callee is not node.func and _call_changes_state(
                        ast.Call(func=callee, args=[], keywords=[]), scope
                    ):
                        return True
    if depth >= _HELPER_DEPTH:
        return bool(helpers)
    return any(
        _body_changes_state(helper, module_functions, depth + 1, seen, module_loggers)
        for helper in helpers
        if id(helper) not in seen
    )


def _route_changes_state(
    function,
    route_decorators,
    methods: set[str],
    module_functions,
    module_loggers=frozenset(),
) -> bool:
    if methods & STATE_CHANGING_HTTP_METHODS:
        return True
    if "POST" not in methods:
        return False
    words = _route_words(function, route_decorators)
    if words & _STATE_CHANGE_ROUTE_WORDS or not words & _QUERY_ROUTE_WORDS:
        return True
    return _body_changes_state(
        function, module_functions, module_loggers=module_loggers
    )


def _is_public_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if node.name.startswith("_"):
        return False
    if node.name.startswith("__") and node.name.endswith("__"):
        return False
    return True


def _iter_public_functions(module: ast.Module, receivers):
    exports = _literal_public_exports(module)
    for stmt in module.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_public_function(stmt) and (exports is None or stmt.name in exports):
                yield stmt, stmt.name, None
        elif isinstance(stmt, ast.ClassDef) and not stmt.name.startswith("_") and (
            exports is None or stmt.name in exports
        ):
            for item in sorted(
                class_method_nodes(stmt), key=lambda method: method.lineno
            ):
                if _is_public_function(item):
                    yield item, f"{stmt.name}.{item.name}", receivers.get(id(item))


def _literal_public_exports(module):
    """A complete literal __all__, otherwise keep the normal public-name rule.

    A mutable/dynamic export list is not evidence that a symbol is private.
    Export aliases also make the relationship uncertain, so retain advice.
    """
    declarations = []
    for statement in module.body:
        targets = statement.targets if isinstance(statement, ast.Assign) else (
            [statement.target] if isinstance(statement, ast.AnnAssign) else []
        )
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
            declarations.append((statement, targets))
    if len(declarations) != 1:
        return None
    declaration, targets = declarations[0]
    if len(targets) != 1 or not isinstance(declaration.value, (ast.Tuple, ast.List)):
        return None
    items = declaration.value.elts
    if not all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in items):
        return None
    exports = {item.value for item in items}
    for node in ast.walk(module):
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            # A wildcard import may publish an __all__ of its own or import
            # aliases for local definitions. The final surface is unknown.
            return None
        if isinstance(node, ast.Name) and node.id == "__all__" and node is not targets[0]:
            return None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
            "globals", "locals", "vars", "eval", "exec"
        }:
            return None
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node is not declaration:
            assigned = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id in exports for target in assigned):
                # ``Public = Internal`` can publish a class or function whose
                # definition has a different spelling.
                if isinstance(node.value, (ast.Name, ast.Attribute, ast.Call)):
                    return None
    return exports


# pylint's default ignored-argument-names: a placeholder the body never reads.
_PLACEHOLDER_NAME = re.compile(r"_.*|ignored_.*|unused_.*")


def _unused_placeholders(function, args) -> set[str]:
    """Parameters named as placeholders and never read: nothing to annotate."""
    candidates = {arg.arg for arg in args if _PLACEHOLDER_NAME.fullmatch(arg.arg)}
    if not candidates:
        return set()
    read = {
        node.id
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store)
    }
    return candidates - read


def _accessor_mutator(decorator) -> bool:
    """``@<property>.setter`` / ``.deleter``: the protocol discards the result."""
    return (
        isinstance(decorator, ast.Attribute)
        and decorator.attr in {"setter", "deleter"}
        and isinstance(decorator.value, ast.Name)
    )


def _inferable_none_procedure(function):
    """A concrete procedure has no value-return contract left to discover.

    Do not infer through decorators, generators, nested definitions, abstract
    placeholders, or returned calls. Explicit project typing policy still
    takes precedence over this source-local precision check.
    """
    if function.decorator_list and not all(
        _accessor_mutator(decorator) for decorator in function.decorator_list
    ):
        return False
    body = [statement for statement in function.body if not (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )]
    if not body or all(isinstance(statement, (ast.Pass, ast.Raise)) or (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    ) for statement in body):
        return False
    pending = list(body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(current, (ast.Yield, ast.YieldFrom)):
            return False
        if isinstance(current, ast.Raise) and isinstance(current.exc, ast.Call) and (
            isinstance(current.exc.func, ast.Name) and current.exc.func.id == "NotImplementedError"
        ):
            return False
        if isinstance(current, ast.Return) and current.value is not None and not (
            isinstance(current.value, ast.Constant) and current.value.value is None
        ):
            return False
        pending.extend(ast.iter_child_nodes(current))
    return True


def _has_signature_typing_intent(function, args, comment_lines):
    if function.returns is not None or any(arg.annotation is not None for arg in args):
        return True
    if getattr(function, "type_comment", None) or any(
        getattr(arg, "type_comment", None) for arg in args
    ):
        return True
    return bool(function.body) and any(
        function.lineno <= line < function.body[0].lineno for line in comment_lines
    )


def _route_object_inputs(function):
    positional = [*function.args.posonlyargs, *function.args.args]
    parameters = {arg.arg for arg in [*positional, *function.args.kwonlyargs]}
    defaults = dict(
        zip(
            [arg.arg for arg in positional[-len(function.args.defaults) :]]
            if function.args.defaults
            else [],
            function.args.defaults,
        )
    )
    defaults.update(
        {
            arg.arg: value
            for arg, value in zip(function.args.kwonlyargs, function.args.kw_defaults)
            if value is not None
        }
    )
    principals = {}
    dependencies = set()
    dependency_cache = {}
    for arg in [*positional, *function.args.kwonlyargs]:
        dependency = next(
            (
                item
                for value in [defaults.get(arg.arg), arg.annotation]
                if value is not None
                for item in ast.walk(value)
                if isinstance(item, ast.Call)
                and _last_name_part(_dotted_name(item.func)) in {"depends", "security"}
            ),
            None,
        )
        if dependency is None:
            continue
        dependencies.add(arg.arg)
        if not (_call_uses_auth(dependency) or _has_auth_marker(arg.arg)):
            continue
        key = _dependency_object_key(dependency, arg.arg)
        use_cache = next(
            (
                keyword.value
                for keyword in dependency.keywords
                if keyword.arg == "use_cache"
            ),
            None,
        )
        cached = (
            use_cache is None
            or isinstance(use_cache, ast.Constant)
            and use_cache.value is True
        )
        token = dependency_cache.get(key) if cached else None
        if token is None:
            token = f"dependency:{arg.arg}"
        # FastAPI stores the first result even if that parameter opted out of
        # reading the cache; a later cached parameter still receives it.
        dependency_cache.setdefault(key, token)
        principals[arg.arg] = token
    # FastAPI also binds query/body parameters from the caller. A second
    # selected object need not be named in the path to defeat the first guard.
    return parameters - dependencies, principals


def _dependency_object_key(dependency, parameter):
    """Repeated cached dependency parameters share the same returned object."""
    keywords = {keyword.arg: keyword.value for keyword in dependency.keywords}
    use_cache = keywords.get("use_cache")
    if use_cache is not None and not (
        isinstance(use_cache, ast.Constant) and isinstance(use_cache.value, bool)
    ):
        return f"opaque:{parameter}"
    callable_node = (
        dependency.args[0] if dependency.args else keywords.get("dependency")
    )
    if not isinstance(callable_node, (ast.Name, ast.Attribute)):
        return f"opaque:{parameter}"
    scopes = keywords.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, (ast.List, ast.Tuple)) or any(
            not isinstance(item, ast.Constant) or not isinstance(item.value, str)
            for item in scopes.elts
        ):
            return f"opaque:{parameter}"
        scope_names = tuple(sorted({item.value for item in scopes.elts}))
    else:
        scope_names = ()
    scope = keywords.get("scope")
    return f"cached:{ast.dump(callable_node)}:{scope_names}:{ast.dump(scope) if scope is not None else ''}"


class TypeAnnotationPracticeRule(SkylosRule):
    rule_id = "SKY-T101"
    name = "Typed API Surface"

    def __init__(self, *, coverage_advice=False):
        self.coverage_advice = coverage_advice is True

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename")
        source = context.get("source", context.get("_source"))
        if is_typing_test_path(filename, context.get("project_root"), source=source):
            return None
        lines = source.splitlines(keepends=True) if isinstance(source, str) else []
        from skylos.analysis.typing_policy import annotation_policy
        from skylos.rules.quality._annotation_contract import (
            annotation_contract_evidence,
        )

        policy = annotation_policy(
            filename,
            context.get("project_root"),
            source if isinstance(source, str) else "",
            reader=context.get("typing_source_reader", context.get("receiver_source_reader")),
        )
        sample_or_build = is_sample_or_build_python(
            filename, context.get("project_root")
        )
        if (
            sample_or_build
            and policy.require_complete is not True
            and policy.require_partial is not True
        ):
            # Examples, docs builds and packaging scripts are not public API.
            return None
        kinds = context_method_kinds(node, context)
        receivers = {
            # Do not prescribe annotation of a possible implicit receiver.
            # Proven static methods and free functions keep their first arg.
            id(method): possible_method_receiver(method, kinds=kinds)
            for cls in ast.walk(node)
            if isinstance(cls, ast.ClassDef)
            for method in class_method_nodes(cls)
        }
        functions = list(_iter_public_functions(node, receivers))
        # A multiline default can contain text resembling a type comment.
        # Only real comment tokens establish a source signature contract.
        comment_lines = {
            token.start[0]
            for token in tokenize.generate_tokens(io.StringIO("".join(lines)).readline)
            if token.type == tokenize.COMMENT
            and re.match(r"#\s*type:\s*(?!ignore\b)\S", token.string)
        }
        comments = {
            id(function): comment_contract(function, lines, receivers.get(id(function)))
            for function in ast.walk(node)
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        fixtures = pytest_fixture_ids(node)
        evidence = annotation_contract_evidence(
            node,
            filename=filename or "",
            source_lines=lines,
            method_kinds=kinds,
            project_root=context.get("project_root"),
            source_reader=context.get(
                "typing_source_reader", context.get("receiver_source_reader")
            ),
            exported_names=_literal_public_exports(node),
        )
        coverage = context.setdefault("annotation_coverage", {})
        coverage.update(
            version=1,
            scope="public_source_definitions",
            definition_count=0,
            definitions_with_complete_annotations=0,
            definitions_missing_annotations=0,
            missing_parameter_annotations=0,
            missing_return_annotations=0,
            definitions_with_supplied_contract=0,
            unreported_missing_definitions=0,
        )
        findings = []
        for function, display_name, receiver in functions:
            if id(function) in fixtures:
                continue
            args = parameters(function)
            typed_comments, return_comment = comments[id(function)]
            required = policy.require_complete is True or (
                policy.require_partial is True
                and _has_signature_typing_intent(function, args, comment_lines)
            )
            missing_params = [
                arg.arg
                for arg in args
                if arg.arg != receiver
                and arg.annotation is None
                and arg.arg not in typed_comments
            ]
            missing_return = function.returns is None and not return_comment
            incomplete = bool(missing_params or missing_return)
            supplied = id(function) in evidence.supplied_ids
            coverage["definition_count"] += 1
            coverage["definitions_with_complete_annotations"] += not incomplete
            coverage["definitions_missing_annotations"] += incomplete
            coverage["missing_parameter_annotations"] += len(missing_params)
            coverage["missing_return_annotations"] += missing_return
            coverage["definitions_with_supplied_contract"] += supplied
            explicitly_allowed = (
                policy.require_complete is not True
                and policy.require_partial is False
            )
            optional = (
                self.coverage_advice
                and not explicitly_allowed
                and not sample_or_build
                and id(function) in evidence.boundary_ids
                and not supplied
            )
            if not required and not optional:
                coverage["unreported_missing_definitions"] += incomplete
                continue
            # Placeholder naming can limit optional suggestions; it cannot
            # override an applicable implementation-annotation requirement.
            # Coverage above still counts the actual missing annotations.
            if not required:
                unused_placeholders = _unused_placeholders(function, args)
                missing_params = [
                    name for name in missing_params if name not in unused_placeholders
                ]
            before = len(findings)
            if missing_params:
                findings.append(
                    {
                        "rule_id": "SKY-T101",
                        "kind": "typing",
                        "severity": "LOW",
                        "type": "function",
                        "name": display_name,
                        "simple_name": function.name,
                        "value": ", ".join(missing_params),
                        "threshold": 0,
                        "message": (
                            f"Public function '{display_name}' has untyped parameters: "
                            f"{', '.join(missing_params)}."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

            if missing_return and not (
                not required and _inferable_none_procedure(function)
            ):
                findings.append(
                    {
                        "rule_id": "SKY-T102",
                        "kind": "typing",
                        "severity": "LOW",
                        "type": "function",
                        "name": display_name,
                        "simple_name": function.name,
                        "value": "missing_return_annotation",
                        "threshold": 0,
                        "message": (
                            f"Public function '{display_name}' is missing a return type annotation."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

            for finding in findings[before:]:
                finding["annotation_evidence"] = {
                    "version": 1,
                    "required": required,
                    "source": "annotation_policy" if required else "api_coverage",
                }
            if incomplete and len(findings) == before:
                coverage["unreported_missing_definitions"] += 1

        return findings or None


class FrameworkPracticeRule(SkylosRule):
    rule_id = "SKY-F101"
    name = "Framework Route Practices"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename")
        if _is_non_production_path(filename):
            return None

        findings = []
        response_contracts = None
        guarded_routers = _guarded_router_names(node)
        mock_patch_decorators = _mock_patch_decorators(node)
        module_functions = {
            statement.name: statement
            for statement in node.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        module_loggers = _logger_names(
            statement
            for statement in node.body
            if not isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
        )
        for function in ast.walk(node):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_decorators = [
                decorator
                for decorator in function.decorator_list
                if id(decorator) not in mock_patch_decorators
                and _route_methods(decorator)[0] is not None
            ]
            if not route_decorators:
                continue

            if response_contracts is None:
                from skylos.rules.quality._framework_practices import FrameworkResponseContracts

                response_contracts = FrameworkResponseContracts(node, context)
            if any(
                response_contracts.is_fastapi_route(decorator)
                for decorator in route_decorators
            ):
                has_response_contract = function.returns is not None or any(
                    _decorator_has_response_contract(decorator)
                    for decorator in route_decorators
                )
                if not has_response_contract:
                    findings.append(
                        {
                            "rule_id": "SKY-F101",
                            "kind": "framework",
                            "severity": "LOW",
                            "type": "route",
                            "name": function.name,
                            "simple_name": function.name,
                            "value": "missing_response_contract",
                            "threshold": 0,
                            "message": (
                                f"FastAPI route '{function.name}' has no response_model, "
                                "response_class, or return annotation."
                            ),
                            "file": filename,
                            "basename": _basename(filename),
                            "line": function.lineno,
                            "col": function.col_offset,
                        }
                    )

            methods = set()
            for decorator in route_decorators:
                _, decorator_methods = _route_methods(decorator)
                methods.update(decorator_methods)

            if _route_changes_state(
                function, route_decorators, methods, module_functions, module_loggers
            ) and not _route_has_auth_guard(function, guarded_routers):
                findings.append(
                    {
                        "rule_id": "SKY-F102",
                        "kind": "framework_security",
                        "severity": "MEDIUM",
                        "type": "route",
                        "name": function.name,
                        "simple_name": function.name,
                        "value": ",".join(sorted(methods & MUTATING_HTTP_METHODS)),
                        "threshold": 0,
                        "message": (
                            f"Function '{function.name}' uses a decorator matching a "
                            "mutating HTTP method, with no obvious auth, permission, "
                            "security, or dependency guard. Review whether it registers "
                            "a route and whether access is protected."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

            if any(_is_fastapi_route(decorator) for decorator in route_decorators):
                identifiers, principals = _route_object_inputs(function)
                if defeated_owner_guard(node, function, identifiers, principals):
                    findings.append(
                        {
                            "rule_id": "SKY-F102",
                            "kind": "framework_security",
                            "severity": "HIGH",
                            "type": "route",
                            "name": function.name,
                            "simple_name": function.name,
                            "value": "defeated_owner_guard",
                            "threshold": 0,
                            "message": (
                                f"Route '{function.name}' may expose or change a caller-selected "
                                "object without a valid ownership check on that object. "
                                "Review principal mutation, object rebinding, and guard paths."
                            ),
                            "file": filename,
                            "basename": _basename(filename),
                            "line": function.lineno,
                            "col": function.col_offset,
                        }
                    )

        return findings or None
