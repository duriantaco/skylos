from __future__ import annotations
import ast
import re
import sys
from collections import Counter
from functools import cached_property
from typing import NamedTuple
from skylos.core.test_paths import is_test_source_file
from skylos.rules.danger.module_namespace import module_name_for, module_rebinding
from skylos.rules.danger.taint import TaintVisitor, URL_SANITIZERS
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex
from .url_scheme import audit_urlopen

# ``scheme://host`` followed by a path/query/fragment delimiter: once a literal
# prefix reaches this point, interpolation afterwards cannot change the host.
_CONSTANT_HOST_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}%\s]+[/?#]")
_CONSTANT_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}%\s]+$")

# Host allowlist guards: ``if urlparse(url).hostname not in ALLOWED: raise``.
_URL_PARSERS = frozenset({"urllib.parse.urlparse", "urllib.parse.urlsplit"})
_URL_HOST_ATTRS = frozenset({"hostname", "netloc"})
_GUARD_EXIT_CALLS = frozenset(
    {"flask.abort", "werkzeug.exceptions.abort", "sys.exit", "os._exit"}
)
_MAX_GUARD_DERIVATION_DEPTH = 2


HTTP_MODULES = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "urllib3",
        "http",
        "treq",
        "asks",
        "pycurl",
        "grequests",
    }
)

HTTP_RECEIVER_NAMES = frozenset(
    {
        "requests",
        "httpx",
        "client",
        "http_client",
        "http",
        "session",
        "aiohttp",
        "resp",
        "response",
    }
)

# ORM sessions share method names with HTTP sessions (``get``, ``delete``...),
# so ``session.delete(item)`` in a FastAPI/SQLModel route is a database call,
# not an outbound request. A receiver counts as an ORM session only on proof:
# an ORM session type annotation or constructor, or a unit-of-work method that
# HTTP clients (requests, httpx, aiohttp, urllib3) do not have.
_ORM_MODULE_ROOTS = frozenset({"sqlalchemy", "sqlmodel", "flask_sqlalchemy"})
_ORM_SESSION_CLASSES = frozenset(
    {"Session", "AsyncSession", "scoped_session", "async_scoped_session"}
)
_ORM_SESSION_FACTORIES = frozenset(
    {"sessionmaker", "async_sessionmaker", "scoped_session", "async_scoped_session"}
)
_ORM_ONLY_SESSION_METHODS = frozenset(
    {
        "add",
        "add_all",
        "commit",
        "rollback",
        "flush",
        "refresh",
        "expunge",
        "expunge_all",
        "exec",
        "execute",
        "scalars",
        "query",
    }
)
_MAX_ORM_ALIAS_DEPTH = 3

NON_HTTP_RECEIVER_NAMES = frozenset(
    {
        "dict",
        "defaultdict",
        "cache",
        "registry",
        "resolver",
        "graph",
        "visited",
        "seen",
        "mapping",
        "config",
        "settings",
        "env",
        "os",
        "self",
    }
)

# In-process test clients: their requests are dispatched to the application
# under test, never to the network.
_TEST_CLIENT_CONSTRUCTORS = frozenset(
    {
        "django.test.Client",
        "django.test.AsyncClient",
        "django.test.RequestFactory",
        "django.test.AsyncRequestFactory",
        "django.test.client.Client",
        "django.test.client.AsyncClient",
        "django.test.client.RequestFactory",
        "django.test.client.AsyncRequestFactory",
        "rest_framework.test.APIClient",
        "rest_framework.test.APIRequestFactory",
        "starlette.testclient.TestClient",
        "fastapi.testclient.TestClient",
        "flask.testing.FlaskClient",
        "litestar.testing.TestClient",
        "litestar.testing.AsyncTestClient",
    }
)
# Test cases whose ``self.client`` is a django.test client.
_DJANGO_TEST_CASES = frozenset(
    {
        "django.test.TestCase",
        "django.test.SimpleTestCase",
        "django.test.TransactionTestCase",
        "django.test.LiveServerTestCase",
        "django.test.testcases.TestCase",
        "django.test.testcases.SimpleTestCase",
        "django.test.testcases.TransactionTestCase",
        "django.test.testcases.LiveServerTestCase",
        "django.contrib.staticfiles.testing.StaticLiveServerTestCase",
        "rest_framework.test.APITestCase",
        "rest_framework.test.APISimpleTestCase",
        "rest_framework.test.APITransactionTestCase",
        "rest_framework.test.APILiveServerTestCase",
    }
)
_DJANGO_TEST_CASE_CLIENTS = {
    "client": "client_class",
    "async_client": "async_client_class",
}
# pytest-django fixtures that are django.test clients or request factories.
_PYTEST_DJANGO_CLIENT_FIXTURES = frozenset(
    {"client", "admin_client", "async_client", "async_admin_client", "rf", "async_rf"}
)


def _qualified_name_from_call(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _receiver_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        value = node.func.value
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            return value.attr
    return None


def _qualified_name_from_expr(node: ast.AST) -> str | None:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _has_safe_base_url(node):
    if not node.values:
        return True

    first = node.values[0]

    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        val = first.value

        if "://" in val:
            parts = val.split("://", 1)
            if len(parts) > 1 and "/" in parts[1]:
                return True

    return False


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_absolute_host(value):
    if not isinstance(value, str) or "://" not in value:
        return False
    scheme, rest = value.split("://", 1)
    host = rest.split("/", 1)[0]
    return bool(scheme and host)


def _leftmost_constant_prefix(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            if isinstance(value, ast.FormattedValue):
                return ""
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leftmost_constant_prefix(node.left)
    return ""


def _urljoin_target_can_override_host(node):
    literal = _constant_string(node)
    if literal is not None:
        return literal.startswith(("http://", "https://", "//"))

    prefix = _leftmost_constant_prefix(node)
    if prefix.startswith(("http://", "https://", "//")):
        return True

    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and ("://" in value.value or value.value.startswith("//"))
            for value in node.values
        )

    return False


def _urljoin_target_is_host_constrained(node):
    literal = _constant_string(node)
    if literal is not None:
        return not _urljoin_target_can_override_host(node)

    prefix = _leftmost_constant_prefix(node)
    if not prefix:
        return False
    if prefix.startswith(("http://", "https://", "//")):
        return False
    if prefix.startswith(("/", "\\")):
        return False
    if ":" in prefix:
        return False
    if "/" not in prefix and "\\" not in prefix:
        return False
    if "://" in prefix:
        return False
    return True


def _is_fixed_host_urljoin(node):
    if not isinstance(node, ast.Call):
        return False
    qn = _qualified_name_from_call(node)
    if qn not in {"urljoin", "urllib.parse.urljoin"}:
        return False
    if len(node.args) < 2:
        return False

    base = _constant_string(node.args[0])
    if not _has_absolute_host(base):
        return False

    return _urljoin_target_is_host_constrained(node.args[1])


def _literal_url_prefix(node):
    """Literal text that starts the URL, cut at the first interpolation."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, True
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            else:
                return prefix, False
        return prefix, True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, complete = _literal_url_prefix(node.left)
        if not complete:
            return left, False
        right, right_complete = _literal_url_prefix(node.right)
        return left + right, right_complete
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        base, _ = _literal_url_prefix(node.left)
        return base.split("%", 1)[0], False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        base, _ = _literal_url_prefix(node.func.value)
        return base.split("{", 1)[0], False
    return "", False


def _has_constant_host(node):
    """True when the URL's scheme and host are fixed by a string literal."""
    if _is_fixed_host_urljoin(node):
        return True
    prefix, complete = _literal_url_prefix(node)
    if not prefix:
        return False
    if _CONSTANT_HOST_PREFIX_RE.match(prefix):
        return True
    return complete and bool(_CONSTANT_URL_RE.match(prefix))


# A literal that fixes the host by itself: ``scheme://host``, optionally with
# userinfo, a port or a path. ``https:``, ``https://`` and ``https://user@``
# leave the authority to whatever text follows them.
_LITERAL_HOST_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#{}%\s@]*@)?[^/?#{}%\s@]+(?:[/?#]|$)"
)
# Resolved through the module's imports: a local ``getenv`` or ``environ``
# is not the operator's environment.
_ENV_LOOKUP_CALLS = frozenset({"os.getenv", "os.environ.get"})
_OPERATOR_MAPPINGS = frozenset({"os.environ", "sys.argv"})
_MAX_SETTING_DEPTH = 8
# Decorators that return the decorated function's own result.
_RESULT_PRESERVING_DECORATORS = frozenset({"functools.cache", "functools.lru_cache"})
_NAMED_BINDERS = tuple(
    getattr(ast, name)
    for name in (
        "ExceptHandler",
        "MatchAs",
        "MatchStar",
        "TypeVar",
        "ParamSpec",
        "TypeVarTuple",
    )
    if hasattr(ast, name)
)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _bound_names(node: ast.AST, scope: ast.AST | None = None):
    """Names that ``node`` binds in the scope it appears in (``scope`` itself
    binds its name in the enclosing scope, not its own)."""
    if isinstance(node, ast.Name):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            yield node.id
    elif isinstance(node, ast.arg):
        yield node.arg
    elif isinstance(node, ast.alias):
        yield node.asname or node.name.split(".", 1)[0]
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if node is not scope:
            yield node.name
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from node.names
    elif isinstance(node, _NAMED_BINDERS):
        if node.name:
            yield node.name
    elif isinstance(node, ast.MatchMapping):
        if node.rest:
            yield node.rest


def _concat_parts(node: ast.AST) -> list[ast.AST] | None:
    """Operands of an f-string or a left-nested ``+`` chain, in order."""
    if isinstance(node, ast.JoinedStr):
        return list(node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = []
        current = node
        while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            parts.insert(0, current.right)
            current = current.left
        parts.insert(0, current)
        return parts
    return None


def _formatted_operand(node: ast.AST) -> ast.AST | None:
    """``{x}`` in an f-string is ``x``; a conversion or format spec is not."""
    if isinstance(node, ast.FormattedValue):
        if node.conversion != -1 or node.format_spec is not None:
            return None
        return node.value
    return node


def _operator_lookup(node: ast.AST, resolve) -> tuple[bool, ast.AST | None]:
    """``os.environ[...]``, ``os.getenv(...)`` or ``sys.argv[...]`` with a key
    the developer chose, and the fallback used when the variable is unset.
    ``resolve`` maps a dotted name to what the module's imports bind it to."""
    if isinstance(node, ast.Subscript):
        name = _qualified_name_from_expr(node.value)
        return (
            bool(name)
            and resolve(name) in _OPERATOR_MAPPINGS
            and _is_operator_value(node.slice, resolve)
        ), None
    name = _qualified_name_from_call(node) if isinstance(node, ast.Call) else None
    if (
        name
        and resolve(name) in _ENV_LOOKUP_CALLS
        and node.args
        and _is_operator_value(node.args[0], resolve)
    ):
        if len(node.args) > 1:
            return True, node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "default":
                return True, keyword.value
        return True, None
    return False, None


def _is_str_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _qualified_name_from_call(node) == "str"
        and len(node.args) == 1
        and not node.keywords
    )


def _is_operator_value(node: ast.AST | None, resolve) -> bool:
    """Text chosen by the developer or the operator: literals, environment
    variables and CLI arguments, with no name whose value could change."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.FormattedValue):
        return _is_operator_value(node.value, resolve) and (
            node.format_spec is None or _is_operator_value(node.format_spec, resolve)
        )
    is_lookup, fallback = _operator_lookup(node, resolve)
    if is_lookup:
        return fallback is None or _is_operator_value(fallback, resolve)
    if _is_str_call(node):
        return _is_operator_value(node.args[0], resolve)
    parts = _concat_parts(node)
    return parts is not None and all(
        _is_operator_value(part, resolve) for part in parts
    )


# Modules whose names hold request data or request-scoped proxies (Flask's
# ``request``/``session``/``g``, ``werkzeug.local.LocalProxy``, context
# variables): an imported name from one of them is never a deployment setting.
_REQUEST_SCOPED_MODULES = (
    "flask",
    "werkzeug",
    "quart",
    "starlette",
    "fastapi",
    "django.http",
    "django.contrib.sessions",
    "django.core.handlers",
    "rest_framework.request",
    "tornado.web",
    "sanic",
    "bottle",
    "falcon",
    "pyramid.request",
    "litestar",
    "contextvars",
)


def _is_request_scoped_module(dotted: str) -> bool:
    return dotted.startswith("aiohttp.web") or any(
        dotted == module or dotted.startswith(module + ".")
        for module in _REQUEST_SCOPED_MODULES
    )


class _ModuleScope(NamedTuple):
    bindings: Counter
    definitions: dict[str, ast.AST]
    # imported name -> the dotted names it may come from
    imported: dict[str, tuple[str, ...]]
    declared_global: set[str]
    values: dict[str, ast.AST | None]


def _walk_function_body(func):
    """Nodes of a function's (or lambda's, class's or module's) own scope,
    without nested bodies."""
    stack = [func.body] if isinstance(func, ast.Lambda) else list(func.body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _is_orm_session_class(dotted: str) -> bool:
    parts = dotted.split(".")
    return parts[0] in _ORM_MODULE_ROOTS and parts[-1] in _ORM_SESSION_CLASSES


def _is_orm_session_factory(dotted: str) -> bool:
    parts = dotted.split(".")
    return parts[0] in _ORM_MODULE_ROOTS and parts[-1] in _ORM_SESSION_FACTORIES


def _is_none_annotation(node: ast.AST) -> bool:
    return (isinstance(node, ast.Constant) and node.value is None) or (
        isinstance(node, ast.Name) and node.id == "None"
    )


def _is_generic_annotation(node: ast.AST) -> bool:
    """``Any``/``object``/a bare string: says nothing about the parameter's
    type, so one function's ORM use of it proves nothing about another's."""
    if isinstance(node, ast.Constant):
        return True
    dotted = _qualified_name_from_expr(node)
    if dotted is None:
        return False
    return dotted.rsplit(".", 1)[-1] in {"Any", "object"}


def _calls_orm_unit_of_work(scope: ast.AST, receiver: str) -> bool:
    """``scope`` calls an ORM-only session method (``commit``, ``add``...) on
    ``receiver``. A class is searched whole, for ``self.session`` receivers."""
    nodes = (
        ast.walk(scope)
        if isinstance(scope, ast.ClassDef)
        else _walk_function_body(scope)
    )
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _ORM_ONLY_SESSION_METHODS
            and _qualified_name_from_expr(node.func.value) == receiver
        ):
            return True
    return False


def _parameter(func: ast.AST, name: str) -> ast.arg | None:
    if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    args = func.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        if arg.arg == name:
            return arg
    return None


def _simple_bindings(node: ast.AST):
    """``(target, value)`` pairs a statement binds directly: assignments,
    walrus and ``with ... as name``."""
    if isinstance(node, ast.Assign):
        return [(target, node.value) for target in node.targets]
    if isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        return [(node.target, node.value)]
    if isinstance(node, ast.withitem):
        return [(node.optional_vars, node.context_expr)]
    return []


def _local_binding_values(scope: ast.AST, name: str) -> list[ast.AST | None]:
    """What each binding of ``name`` in ``scope``'s own body is bound to: the
    assigned value or ``with`` context expression, ``None`` for any other
    binding (``for``/``except``/import/tuple target/pattern...)."""
    values: list[ast.AST | None] = []
    simple: set[int] = set()
    nodes = list(_walk_function_body(scope))
    for node in nodes:
        for target, value in _simple_bindings(node):
            if isinstance(target, ast.Name) and target.id == name:
                values.append(value)
                simple.add(id(target))
    for node in nodes:
        if id(node) not in simple and name in _bound_names(node, scope):
            values.append(None)
    return values


_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


class _ScopeInfo(NamedTuple):
    """A function's, lambda's, class's or module's own namespace."""

    # name -> nodes binding it: parameters, assignment/``for``/``with``/
    # ``except``/match targets, imports, nested definitions. Comprehension
    # targets are included (over-approximation).
    bindings: dict[str, list[ast.AST]]
    global_names: frozenset[str]
    nonlocal_names: frozenset[str]


def _scope_info(scope: ast.AST) -> _ScopeInfo:
    bindings: dict[str, list[ast.AST]] = {}
    global_names: set[str] = set()
    nonlocal_names: set[str] = set()
    for node in _walk_function_body(scope):
        if isinstance(node, ast.Global):
            global_names.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            nonlocal_names.update(node.names)
        else:
            for name in _bound_names(node, scope):
                bindings.setdefault(name, []).append(node)
    if isinstance(scope, _FUNCTION_SCOPES):
        args = scope.args
        for arg in (
            *args.posonlyargs,
            *args.args,
            args.vararg,
            *args.kwonlyargs,
            args.kwarg,
        ):
            if arg is not None:
                bindings.setdefault(arg.arg, []).append(arg)
    return _ScopeInfo(bindings, frozenset(global_names), frozenset(nonlocal_names))


def _bound_names_of_statement(statement: ast.AST):
    """``Name`` targets a class-body statement binds (assignments only)."""
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        for target in targets:
            for node in ast.walk(target):
                if isinstance(node, ast.Name):
                    yield node


def _function_ref_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"self", "cls"}
    ):
        return node.attr
    return None


def _dispatched_functions(tree) -> set[str]:
    """Functions reachable from a string-keyed command table
    (``handlers = {"import_asset": self.import_asset}; handlers[cmd](**params)``).

    Their arguments come from whoever sends the command (an MCP client, an
    RPC or socket peer), so they are untrusted like route parameters. Functions
    they forward their own parameters to are included too."""
    if tree is None:
        return set()
    functions = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)
    dispatched = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict) or len(node.keys) < 2:
            continue
        if not all(
            isinstance(key, ast.Constant) and isinstance(key.value, str)
            for key in node.keys
        ):
            continue
        names = [_function_ref_name(value) for value in node.values]
        if names and all(name in functions for name in names):
            dispatched.update(names)
    for _ in range(4):
        grown = False
        for name in list(dispatched):
            func = functions.get(name)
            if func is None:
                continue
            params = {a.arg for a in func.args.args + func.args.kwonlyargs}
            for extra in (func.args.vararg, func.args.kwarg):
                if extra is not None:
                    params.add(extra.arg)
            params.discard("self")
            params.discard("cls")
            for call in ast.walk(func):
                if not isinstance(call, ast.Call):
                    continue
                target = _function_ref_name(call.func)
                if target not in functions or target in dispatched:
                    continue
                passed = [*call.args, *(kw.value for kw in call.keywords)]
                if any(
                    isinstance(sub, ast.Name) and sub.id in params
                    for arg in passed
                    for sub in ast.walk(arg)
                ):
                    dispatched.add(target)
                    grown = True
        if not grown:
            break
    return dispatched


def _only_operator_sources(labels):
    # Deployment settings and process arguments are chosen by the operator.
    # A separate request source still keeps the finding actionable.
    return all(
        label.startswith("`os.environ")
        or label.startswith("`os.getenv")
        or label.startswith("CLI arguments `")
        or label.startswith("CLI parameter `")
        or label.startswith("`sys.argv")
        for label in labels
    )


def _tainted_url_is_ssrf_relevant(checker, node):
    if isinstance(node, ast.JoinedStr) and _has_safe_base_url(node):
        return False
    if _is_fixed_host_urljoin(node):
        return False
    return checker.is_tainted(node) or bool(
        checker.untrusted_sources.for_function(
            checker._current_function()
        ).sources_in(node)
    )


def _is_interpolated_string(node):
    if isinstance(node, ast.JoinedStr):
        if _has_safe_base_url(node):
            return False
        return True

    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _safe_expr_text(node: ast.AST | None, max_length: int = 160) -> str:
    if node is None:
        return "unknown"
    try:
        text = ast.unparse(node)
    except Exception:
        text = type(node).__name__
    text = " ".join(str(text).split())
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text or "unknown"


def _request_base_name(node: ast.AST | None) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _source_label(node: ast.AST, *, interpolated: bool) -> str:
    if _request_base_name(node) == "request":
        return "request-derived URL value"
    if isinstance(node, ast.Name):
        return f"tainted variable `{node.id}`"
    if isinstance(node, ast.JoinedStr) or interpolated:
        return "interpolated URL expression"
    return "tainted URL expression"


def _ssrf_security_evidence(
    *,
    symbol: str,
    sink: str,
    url_arg: ast.AST,
    interpolated: bool,
) -> dict:
    source = _source_label(url_arg, interpolated=interpolated)
    expression = _safe_expr_text(url_arg)
    entrypoint = symbol if symbol and symbol != "<module>" else None

    evidence = {
        "evidence_kind": "source_to_sink",
        "source": source,
        "sink": sink,
        "path": [
            source,
            f"url expression `{expression}`",
            f"HTTP sink `{sink}`",
        ],
        "guards_seen": [],
        "guards_missing": [
            "URL host or scheme allowlist",
            "private, loopback, and metadata host rejection",
        ],
        "confidence_reason": (
            "Untrusted URL data can influence the outbound HTTP request target."
        ),
        "test_hint": (
            "Assert untrusted input cannot control the request host and private "
            "or metadata URLs are rejected before the HTTP client call."
        ),
        "fix_shape": "validate and allowlist the URL before the HTTP request",
    }
    if entrypoint:
        evidence["entrypoint"] = entrypoint
    return evidence


class _SSRFFlowChecker(TaintVisitor):
    HTTP_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}

    def __init__(self, file_path, findings, sanitizers=None, tree=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.tree = tree
        self.http_names: set[str] = set()
        self.http_receiver_alias_stack: list[set[str]] = [set()]
        self.untrusted_sources = UntrustedSourceIndex(tree, follow_local_calls=True)
        self.assigned_values: list[dict[str, ast.AST]] = [{}]
        self.request_url_mutations: list[dict[str, list[ast.AST]]] = [{}]
        self.parents = (
            {
                id(child): parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            if tree is not None
            else {}
        )
        self.dispatched_functions = _dispatched_functions(tree)
        # Per-file memos keyed by node id: every HTTP call would otherwise
        # re-walk the module, its functions or its classes.
        self._scope_infos: dict[int, _ScopeInfo] = {}
        self._declared_writes: dict[int, dict[str, list[ast.AST]]] = {}
        self._subtree_names: dict[int, frozenset[str]] = {}
        self._test_client_bindings: dict[tuple[int, str], bool] = {}
        self._test_client_attributes: dict[tuple[int, str], bool] = {}
        self._fixed_host_helpers: dict[int, bool] = {}
        self._fixed_host_locals: dict[tuple[int, str], bool] = {}
        self._orm_unit_of_work_memo: dict[tuple[int, str], bool] = {}

    def _push(self):
        super()._push()
        self.http_receiver_alias_stack.append(set())
        self.assigned_values.append({})
        self.request_url_mutations.append({})

    def _pop(self):
        if len(self.http_receiver_alias_stack) > 1:
            self.http_receiver_alias_stack.pop()
        if len(self.assigned_values) > 1:
            self.assigned_values.pop()
        if len(self.request_url_mutations) > 1:
            self.request_url_mutations.pop()
        super()._pop()

    def _resolve_url_expr(self, node: ast.AST) -> ast.AST:
        # One hop through a local ``url = f"https://api.example.com/{x}"``.
        if isinstance(node, ast.Name):
            for scope in reversed(self.assigned_values):
                if node.id in scope:
                    return scope[node.id]
        return node

    def _is_urllib_request_constructor(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = _qualified_name_from_call(node)
        if not name:
            return False
        return (
            self.untrusted_sources.resolved_import(self._current_function(), name)
            == "urllib.request.Request"
        )

    def _request_constructor_url(self, node: ast.AST) -> ast.AST | None:
        if not self._is_urllib_request_constructor(node):
            return None
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg == "url":
                return keyword.value
        return None

    def _request_root_name(self, name: str) -> str:
        seen = set()
        while name not in seen:
            seen.add(name)
            value = self._resolve_url_expr(ast.Name(id=name, ctx=ast.Load()))
            if not isinstance(value, ast.Name):
                break
            name = value.id
        return name

    def _request_name_has_one_store(self, name: str) -> bool:
        scope = self._current_function() or self.tree
        return scope is not None and sum(
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Store)
            for node in ast.walk(scope)
        ) == 1

    def _record_request_url_mutation(self, name: str, value: ast.AST) -> None:
        # Preserve the concrete name as well as names that currently alias it.
        # A later rebinding must not erase a mutation to the old Request object.
        root = self._request_root_name(name)
        names = {name, root}
        names.update(
            alias
            for scope in self.assigned_values
            for alias in scope
            if self._request_root_name(alias) == root
        )
        for alias in names:
            self.request_url_mutations[-1].setdefault(alias, []).append(value)

    def _is_tracked_request_use(self, node: ast.Name) -> bool:
        parent = self.parents.get(id(node))
        if not isinstance(parent, ast.Attribute) or parent.value is not node:
            return False
        grandparent = self.parents.get(id(parent))
        if parent.attr == "set_proxy":
            return (
                isinstance(grandparent, ast.Call)
                and grandparent.func is parent
                and bool(grandparent.args)
            )
        if parent.attr not in {"full_url", "host", "type", "selector"}:
            return False
        if isinstance(grandparent, ast.Assign):
            return parent in grandparent.targets
        if isinstance(grandparent, (ast.AnnAssign, ast.AugAssign)):
            return grandparent.target is parent
        return False

    def _request_binding_is_stable(self, arg: ast.Name) -> bool:
        """The local Request is only used at this sink or in tracked URL writes."""
        scope = self._current_function() or self.tree
        if scope is None:
            return False
        stores = 0
        for node in ast.walk(scope):
            if not isinstance(node, ast.Name) or node.id != arg.id:
                continue
            if isinstance(node.ctx, ast.Store):
                stores += 1
                continue
            if node is arg:
                continue
            ancestor = self.parents.get(id(node))
            while ancestor is not None and ancestor is not scope:
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    return False
                ancestor = self.parents.get(id(ancestor))
            if not isinstance(node.ctx, ast.Load) or not self._is_tracked_request_use(node):
                return False
        return stores == 1

    def _urlopen_url_candidates(self, arg: ast.AST) -> list[ast.AST]:
        if isinstance(arg, ast.Name):
            root = self._request_root_name(arg.id)
            mutations = list(
                dict.fromkeys(
                    expr
                    for scope in self.request_url_mutations
                    for name in dict.fromkeys((arg.id, root))
                    for expr in scope.get(name, [])
                )
            )
            if mutations:
                if self._request_binding_is_stable(arg):
                    url = self._request_constructor_url(self._resolve_url_expr(arg))
                    if url is not None:
                        return [*mutations, url]
                return [*mutations, arg]
            if self._request_binding_is_stable(arg):
                url = self._request_constructor_url(self._resolve_url_expr(arg))
                if url is not None:
                    return [url]
        else:
            url = self._request_constructor_url(arg)
            if url is not None:
                return [url]
        return [arg]

    @staticmethod
    def _urlopen_argument(node: ast.Call) -> ast.AST | None:
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg == "url":
                return keyword.value
        return None

    def _record_assignment(self, targets, value) -> None:
        if value is None:
            return
        for target in targets:
            if isinstance(target, ast.Name):
                existing = []
                if isinstance(value, ast.Name):
                    for scope in self.request_url_mutations:
                        existing.extend(scope.get(value.id, []))
                if existing:
                    self.request_url_mutations[-1][target.id] = list(existing)
                else:
                    self.request_url_mutations[-1].pop(target.id, None)
                self.assigned_values[-1][target.id] = value

    def _mark_http_receiver_alias(self, name: str) -> None:
        if not self.http_receiver_alias_stack:
            self.http_receiver_alias_stack.append(set())
        self.http_receiver_alias_stack[-1].add(name)

    def _is_known_http_receiver_name(self, name: str) -> bool:
        if name in self.http_names:
            return True
        return any(name in scope for scope in reversed(self.http_receiver_alias_stack))

    def _is_http_reference(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            return self._is_http_reference(node.func)

        if isinstance(node, ast.Name):
            return self._is_known_http_receiver_name(node.id)

        qual_name = _qualified_name_from_expr(node)
        if not qual_name:
            return False

        root = qual_name.split(".", 1)[0]
        if root in HTTP_MODULES:
            return True
        return self._is_known_http_receiver_name(root)

    def _track_http_receiver_aliases(self, targets, value: ast.AST | None) -> None:
        if value is None or not self._is_http_reference(value):
            return

        for target in targets:
            if isinstance(target, ast.Name):
                self._mark_http_receiver_alias(target.id)
            elif isinstance(target, ast.Attribute):
                self._mark_http_receiver_alias(target.attr)

    def is_tainted(self, node):
        if isinstance(node, ast.JoinedStr) and _has_safe_base_url(node):
            return False
        if _is_fixed_host_urljoin(node):
            return False
        return super().is_tainted(node)

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in HTTP_MODULES:
                self.http_names.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_level = node.module.split(".")[0]
            if top_level in HTTP_MODULES:
                for alias in node.names:
                    self.http_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.attr in {"full_url", "host", "type", "selector"}
            ):
                self._record_request_url_mutation(target.value.id, node.value)
        self._track_http_receiver_aliases(node.targets, node.value)
        self._record_assignment(node.targets, node.value)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        if (
            isinstance(node.target, ast.Attribute)
            and isinstance(node.target.value, ast.Name)
            and node.target.attr in {"full_url", "host", "type", "selector"}
            and node.value is not None
        ):
            self._record_request_url_mutation(node.target.value.id, node.value)
        self._track_http_receiver_aliases([node.target], node.value)
        self._record_assignment([node.target], node.value)
        super().visit_AnnAssign(node)

    def visit_AugAssign(self, node):
        target = node.target
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.attr in {"full_url", "host", "type", "selector"}
        ):
            root = self._request_root_name(target.value.id)
            prior = [
                expr
                for scope in self.request_url_mutations
                for expr in scope.get(root, [])
            ]
            constructor = self._request_constructor_url(
                self._resolve_url_expr(ast.Name(id=root, ctx=ast.Load()))
            )
            prefix = _literal_url_prefix(constructor)[0] if constructor else ""
            if not (
                target.attr == "full_url"
                and isinstance(node.op, ast.Add)
                and not prior
                and target.value.id == root
                and self._request_name_has_one_store(root)
                and _CONSTANT_HOST_PREFIX_RE.match(prefix)
            ):
                self._record_request_url_mutation(target.value.id, node.value)
        self.generic_visit(node)

    @cached_property
    def _in_test_code(self) -> bool:
        return is_test_source_file(self.file_path)

    def _enclosing_function(self, node: ast.AST) -> ast.AST | None:
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = self.parents.get(id(current))
        return None

    def _is_test_client_constructor(self, node: ast.AST | None) -> bool:
        if not isinstance(node, ast.Call):
            return False
        dynamic, rebound = self._module_rebinding
        if dynamic:
            return False  # ``Client`` may have been swapped (star import, ...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "test_client":
            return True  # Flask/Quart ``app.test_client()``
        name = _qualified_name_from_call(node)
        if not name or any(part in rebound for part in name.split(".")):
            return False
        return bool(name) and (
            self.untrusted_sources.resolved_import(self._enclosing_function(node), name)
            in _TEST_CLIENT_CONSTRUCTORS
        )

    def _stores_are_test_clients(self, stores) -> bool:
        for store in stores:
            parent = self.parents.get(id(store))
            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                value = parent.value
            elif isinstance(parent, ast.withitem) and parent.optional_vars is store:
                value = parent.context_expr
            else:
                return False
            if not self._is_test_client_constructor(value):
                return False
        return True

    def _scope_info(self, scope: ast.AST) -> _ScopeInfo:
        info = self._scope_infos.get(id(scope))
        if info is None:
            info = self._scope_infos[id(scope)] = _scope_info(scope)
        return info

    def _binding_scope(self, name: str, node: ast.AST) -> ast.AST | None:
        """The function, lambda or class body whose ``name`` is read at
        ``node``, following Python's scoping rules; ``None`` for the module."""
        in_function = False
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, _FUNCTION_SCOPES) or (
                isinstance(current, ast.ClassDef) and not in_function
            ):
                info = self._scope_info(current)
                if name in info.global_names:
                    return None
                if name not in info.nonlocal_names and name in info.bindings:
                    return current
                in_function = in_function or isinstance(current, _FUNCTION_SCOPES)
            current = self.parents.get(id(current))
        return None

    def _nested_declared_writes(self, root: ast.AST) -> dict[str, list[ast.AST]]:
        """Bindings made inside nested scopes of ``root`` that declare the name
        ``global`` (``root`` is the module) or ``nonlocal`` (a function)."""
        writes = self._declared_writes.get(id(root))
        if writes is not None:
            return writes
        writes = {}
        module = root is self.tree
        for inner in ast.walk(root):
            if inner is root or not isinstance(
                inner, (*_FUNCTION_SCOPES, ast.ClassDef)
            ):
                continue
            info = self._scope_info(inner)
            for name in info.global_names if module else info.nonlocal_names:
                writes.setdefault(name, []).extend(info.bindings.get(name, ()))
        self._declared_writes[id(root)] = writes
        return writes

    def _binding_nodes(self, scope: ast.AST | None, name: str) -> list[ast.AST]:
        """Every binding of ``name`` in ``scope`` (``None``: the module),
        including assignments in nested scopes that declare it ``nonlocal``
        (or, for the module, ``global``)."""
        root = self.tree if scope is None else scope
        if root is None:
            return []
        return [
            *self._scope_info(root).bindings.get(name, ()),
            *self._nested_declared_writes(root).get(name, ()),
        ]

    def _name_is_test_client(self, name: str, node: ast.AST) -> bool:
        """``name`` read at ``node`` resolves to a binding (in the current
        function, an enclosing one, or the module) that only ever holds an
        in-process test client. Bindings in nested scopes do not count."""
        scope = self._binding_scope(name, node)
        key = (id(scope), name)
        result = self._test_client_bindings.get(key)
        if result is None:
            result = self._test_client_bindings[key] = self._binding_is_test_client(
                scope, name
            )
        return result

    def _binding_is_test_client(self, scope: ast.AST | None, name: str) -> bool:
        if scope is None:
            dynamic, rebound = self._module_rebinding
            if dynamic or name in rebound:
                return False
        bindings = self._binding_nodes(scope, name)
        params = [binding for binding in bindings if isinstance(binding, ast.arg)]
        stores = [binding for binding in bindings if not isinstance(binding, ast.arg)]
        if params:
            # A pytest-django fixture requested by a test function. Outside
            # test code, or on a route, ``client`` is whatever the caller or
            # dependency injection passes in.
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            args = scope.args
            fixture_slots = (*args.posonlyargs, *args.args, *args.kwonlyargs)
            return (
                not stores
                and all(any(p is slot for slot in fixture_slots) for p in params)
                and name in _PYTEST_DJANGO_CLIENT_FIXTURES
                and scope.name.startswith("test")
                and self._in_test_code
                and self.untrusted_sources.entrypoint_decorator(scope) is None
            )
        return bool(stores) and self._stores_are_test_clients(stores)

    def _enclosing_class(self, node: ast.AST) -> ast.ClassDef | None:
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, ast.ClassDef):
                return current
            current = self.parents.get(id(current))
        return None

    def _attribute_owner(self, store: ast.Attribute) -> ast.ClassDef | None:
        """The class whose instance ``store`` writes: ``self.x = ...`` where
        ``self`` is the first parameter of a method of that class. ``None``
        for any other object (a closure ``self``, another instance)."""
        receiver = store.value
        if not isinstance(receiver, ast.Name):
            return None
        func = self.parents.get(id(store))
        while func is not None and not isinstance(func, _FUNCTION_SCOPES):
            func = self.parents.get(id(func))
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        positional = [*func.args.posonlyargs, *func.args.args]
        if not positional or positional[0].arg != receiver.id:
            return None
        if any(
            _qualified_name_from_expr(d) == "staticmethod" for d in func.decorator_list
        ):
            return None
        owner = self.parents.get(id(func))
        return owner if isinstance(owner, ast.ClassDef) else None

    @cached_property
    def _client_attribute_index(self):
        """Module-wide attribute writes for the ``self.<attr>`` test-client
        rule: ``attr -> [(store, owning class or None)]``, the names given to
        ``setattr``/``delattr``, and whether any write cannot be followed
        (a computed ``setattr`` name, ``__dict__``, ``vars()``, a
        ``client_class`` assignment or a ``_pre_setup`` override)."""
        stores: dict[str, list[tuple[ast.AST, ast.ClassDef | None]]] = {}
        setattr_names: set[str] = set()
        unknowable = False
        swaps = {*_DJANGO_TEST_CASE_CLIENTS.values(), "_pre_setup"}
        for node in ast.walk(self.tree) if self.tree is not None else ():
            if isinstance(node, ast.Attribute):
                if node.attr == "__dict__" or (
                    node.attr in swaps and not isinstance(node.ctx, ast.Load)
                ):
                    unknowable = True
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    stores.setdefault(node.attr, []).append(
                        (node, self._attribute_owner(node))
                    )
            elif isinstance(node, ast.Name):
                if node.id in swaps and isinstance(node.ctx, (ast.Store, ast.Del)):
                    unknowable = True
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in swaps:
                    unknowable = True
            elif isinstance(node, ast.Call):
                callee = _qualified_name_from_call(node)
                if callee == "vars":
                    unknowable = True
                elif callee in {"setattr", "delattr"}:
                    attr = (
                        _constant_string(node.args[1]) if len(node.args) > 1 else None
                    )
                    if attr is None:
                        unknowable = True
                    else:
                        setattr_names.add(attr)
        return stores, setattr_names, unknowable

    def _module_class(self, name: str) -> ast.ClassDef | None:
        klass = self._module_scope.definitions.get(name)
        if isinstance(klass, ast.ClassDef) and self._module_global_is_stable(name):
            return klass
        return None

    def _is_django_test_case(self, klass: ast.ClassDef) -> bool:
        """A module-level class, bound once, whose bases are Django/DRF test
        cases or same-module classes with such bases (mixins defined in this
        module are allowed; a base from elsewhere may swap ``self.client``)."""
        return self._test_case_kind(klass, set()) == "test case"

    def _test_case_kind(self, klass: ast.ClassDef, seen: set[int]) -> str | None:
        """``"test case"``, ``"mixin"`` (only local, plain bases) or ``None``."""
        if id(klass) in seen or klass.keywords:
            return None
        seen.add(id(klass))
        if (
            self.parents.get(id(klass)) is not self.tree
            or self._module_class(klass.name) is not klass
        ):
            return None
        kind = "mixin"
        for base in klass.bases:
            dotted = _qualified_name_from_expr(base) or ""
            if (
                self.untrusted_sources.resolved_import(None, dotted)
                in _DJANGO_TEST_CASES
            ):
                kind = "test case"
                continue
            if dotted == "object":
                continue
            local = self._module_class(dotted) if isinstance(base, ast.Name) else None
            base_kind = self._test_case_kind(local, seen) if local else None
            if base_kind is None:
                return None
            if base_kind == "test case":
                kind = "test case"
        return kind

    def _related_classes(self, klass: ast.ClassDef) -> set[int]:
        """``klass``, its same-module bases and its same-module subclasses."""
        classes = [
            node for node in ast.walk(self.tree) if isinstance(node, ast.ClassDef)
        ]
        related = {id(klass)}
        names = {klass.name}
        grown = True
        while grown:
            grown = False
            for other in classes:
                if id(other) in related:
                    continue
                base_names = {_qualified_name_from_expr(base) for base in other.bases}
                if base_names & names:
                    related.add(id(other))
                    names.add(other.name)
                    grown = True
        pending = [klass]
        while pending:
            current = pending.pop()
            for base in current.bases:
                local = (
                    self._module_scope.definitions.get(base.id)
                    if isinstance(base, ast.Name)
                    else None
                )
                if isinstance(local, ast.ClassDef) and id(local) not in related:
                    related.add(id(local))
                    pending.append(local)
        return related

    def _self_attribute_is_test_client(self, receiver: ast.Attribute) -> bool:
        if not (
            isinstance(receiver.value, ast.Name)
            and receiver.value.id in {"self", "cls"}
        ):
            return False
        klass = self._enclosing_class(receiver)
        if klass is None:
            return False
        key = (id(klass), receiver.attr)
        result = self._test_client_attributes.get(key)
        if result is None:
            result = self._test_client_attributes[key] = (
                self._class_attribute_is_test_client(klass, receiver.attr)
            )
        return result

    def _class_attribute_is_test_client(self, klass: ast.ClassDef, attr: str) -> bool:
        """``self.<attr>`` in a Django/DRF test case holds an in-process test
        client: every write of ``.<attr>`` that may reach the instance builds
        one, or there is none and Django builds ``client``/``async_client``.
        Outside such test cases ``self.<attr>`` is whatever was assigned."""
        if not self._is_django_test_case(klass):
            return False
        stores_by_attr, setattr_names, unknowable = self._client_attribute_index
        if unknowable or attr in setattr_names:
            return False
        related = self._related_classes(klass)
        stores = [
            store
            for store, owner in stores_by_attr.get(attr, ())
            if owner is None or id(owner) in related
        ]
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and id(node) in related:
                for statement in node.body:
                    for name in _bound_names_of_statement(statement):
                        if name.id == attr:
                            stores.append(name)
        if stores:
            return self._stores_are_test_clients(stores)
        return attr in _DJANGO_TEST_CASE_CLIENTS

    def _is_test_client_receiver(self, node: ast.Call) -> bool:
        """The call goes through an in-process test client, not the network."""
        if not isinstance(node.func, ast.Attribute):
            return False
        receiver = node.func.value
        if isinstance(receiver, ast.Call):
            return self._is_test_client_constructor(receiver)
        if isinstance(receiver, ast.Name):
            return self._name_is_test_client(receiver.id, receiver)
        if isinstance(receiver, ast.Attribute):
            return self._self_attribute_is_test_client(receiver)
        return False

    def _is_likely_http_receiver(self, node: ast.Call) -> bool:
        name = _receiver_name(node)
        if name is None:
            return False

        if self._is_known_http_receiver_name(name):
            return True

        if self._receiver_is_orm_session(node):
            return False

        if name.lower() in NON_HTTP_RECEIVER_NAMES:
            return False

        if name.lower() in HTTP_RECEIVER_NAMES:
            return True

        lower = name.lower()
        if any(hint in lower for hint in ("http", "request", "client", "session")):
            return True

        return False

    def _receiver_is_orm_session(self, node: ast.Call) -> bool:
        """The call's receiver is proven to be an ORM (SQLAlchemy/SQLModel)
        session, so ``get``/``delete``/... on it never leaves the process."""
        if not isinstance(node.func, ast.Attribute):
            return False
        receiver = _qualified_name_from_expr(node.func.value)
        if receiver is None:
            return False
        func = self._enclosing_function(node)
        if receiver.startswith(("self.", "cls.")):
            klass = self._enclosing_class(node)
            return klass is not None and self._calls_orm_unit_of_work(klass, receiver)
        scope = func if func is not None else self.tree
        if scope is not None and self._calls_orm_unit_of_work(scope, receiver):
            return True
        head, _, rest = receiver.partition(".")
        if rest:
            # Flask-SQLAlchemy: ``db = SQLAlchemy(app)`` ... ``db.session``.
            return (
                rest == "session"
                and self._module_global_is_stable(head)
                and self._names_orm_object(
                    self._module_scope.values.get(head), "SQLAlchemy", 0
                )
            )
        if func is not None:
            param = _parameter(func, receiver)
            values = _local_binding_values(func, receiver)
            if param is not None or values:
                proofs = [self._is_orm_session_value(value, 0) for value in values]
                if param is not None:
                    proofs.append(self._parameter_is_orm_session(param))
                return all(proofs)
            if receiver in self._names_bound_under(func):
                return False  # bound by a nested scope or a pattern: unknown
        if not self._module_global_is_stable(receiver):
            return False
        return self._is_orm_session_value(
            self._module_scope.values.get(receiver), 0
        )

    def _calls_orm_unit_of_work(self, scope: ast.AST, receiver: str) -> bool:
        key = (id(scope), receiver)
        known = self._orm_unit_of_work_memo.get(key)
        if known is None:
            known = self._orm_unit_of_work_memo[key] = _calls_orm_unit_of_work(
                scope, receiver
            )
        return known

    def _parameter_is_orm_session(self, param: ast.arg) -> bool:
        annotation = param.annotation
        if annotation is None:
            return False
        return self._names_orm_session_type(
            annotation, 0
        ) or self._annotation_used_as_orm_session(ast.dump(annotation))

    @cached_property
    def _orm_session_annotations(self) -> frozenset[str]:
        """Parameter annotations that some function in this module uses as an
        ORM session (calls ``commit``, ``exec``... on the parameter). Covers a
        ``SessionDep`` alias imported from another module."""
        found: set[str] = set()
        if self.tree is None:
            return frozenset()
        for func in ast.walk(self.tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = func.args
            for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                if arg.annotation is None or _is_generic_annotation(arg.annotation):
                    continue
                key = ast.dump(arg.annotation)
                if key in found or _local_binding_values(func, arg.arg):
                    continue
                if _calls_orm_unit_of_work(func, arg.arg):
                    found.add(key)
        return frozenset(found)

    def _annotation_used_as_orm_session(self, annotation_key: str) -> bool:
        return annotation_key in self._orm_session_annotations

    def _resolved_dotted(self, node: ast.AST) -> str | None:
        """``node``'s dotted name with its imported head replaced by the
        module it comes from (``Session`` -> ``sqlmodel.Session``)."""
        dotted = _qualified_name_from_expr(node)
        if dotted is None:
            return None
        head, _, rest = dotted.partition(".")
        sources = self._module_scope.imported.get(head)
        if not sources or not self._module_global_is_stable(head):
            return None
        return sources[-1] + (f".{rest}" if rest else "")

    def _module_value(self, node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Name) or not self._module_global_is_stable(
            node.id
        ):
            return None
        return self._module_scope.values.get(node.id)

    def _names_orm_session_type(self, node: ast.AST | None, depth: int) -> bool:
        """``node`` (an annotation) names an ORM session class, through
        ``Annotated[...]``, ``Optional[...]``, ``X | None``, string
        annotations and module-level aliases."""
        if node is None or depth > _MAX_ORM_ALIAS_DEPTH:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                parsed = ast.parse(node.value.strip(), mode="eval").body
            except SyntaxError:
                return False
            return self._names_orm_session_type(parsed, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            members = [
                member
                for member in (node.left, node.right)
                if not _is_none_annotation(member)
            ]
            return bool(members) and all(
                self._names_orm_session_type(member, depth + 1) for member in members
            )
        if isinstance(node, ast.Subscript):
            base = _qualified_name_from_expr(node.value) or ""
            base = base.rsplit(".", 1)[-1]
            inner = node.slice
            if base == "Annotated" and isinstance(inner, ast.Tuple) and inner.elts:
                return self._names_orm_session_type(inner.elts[0], depth + 1)
            if base == "Optional":
                return self._names_orm_session_type(inner, depth + 1)
            if base == "Union" and isinstance(inner, ast.Tuple):
                members = [m for m in inner.elts if not _is_none_annotation(m)]
                return bool(members) and all(
                    self._names_orm_session_type(m, depth + 1) for m in members
                )
            return False
        resolved = self._resolved_dotted(node)
        if resolved is not None:
            return _is_orm_session_class(resolved)
        alias = self._module_value(node)
        return alias is not None and self._names_orm_session_type(alias, depth + 1)

    def _names_orm_object(self, node: ast.AST | None, cls: str, depth: int) -> bool:
        """``node`` is a call constructing ``<orm module>.<cls>``."""
        if not isinstance(node, ast.Call) or depth > _MAX_ORM_ALIAS_DEPTH:
            return False
        resolved = self._resolved_dotted(node.func)
        if resolved is None:
            return False
        parts = resolved.split(".")
        return parts[0] in _ORM_MODULE_ROOTS and parts[-1] == cls

    def _is_orm_session_factory_value(self, node: ast.AST | None, depth: int) -> bool:
        """``node`` is (a module alias of) ``sessionmaker(...)`` and friends."""
        if node is None or depth > _MAX_ORM_ALIAS_DEPTH:
            return False
        if isinstance(node, ast.Call):
            resolved = self._resolved_dotted(node.func)
            return resolved is not None and _is_orm_session_factory(resolved)
        alias = self._module_value(node)
        return alias is not None and self._is_orm_session_factory_value(
            alias, depth + 1
        )

    def _is_orm_session_value(self, node: ast.AST | None, depth: int) -> bool:
        """``node`` evaluates to an ORM session: ``Session(engine)``,
        ``SessionLocal()`` for a ``sessionmaker``, ``factory.begin()``, or a
        ``scoped_session`` registry used directly."""
        if node is None or depth > _MAX_ORM_ALIAS_DEPTH:
            return False
        if isinstance(node, ast.Await):
            return self._is_orm_session_value(node.value, depth + 1)
        if isinstance(node, ast.Call):
            func = node.func
            resolved = self._resolved_dotted(func)
            if resolved is not None and _is_orm_session_class(resolved):
                return True
            if self._is_orm_session_factory_value(func, depth + 1):
                return True
            if isinstance(func, ast.Attribute) and func.attr == "begin":
                return self._is_orm_session_factory_value(func.value, depth + 1)
            return False
        if self._is_orm_session_factory_value(node, depth + 1):
            # ``Session = scoped_session(...)`` proxies a session directly.
            value = self._module_value(node)
            resolved = (
                self._resolved_dotted(value.func)
                if isinstance(value, ast.Call)
                else None
            )
            return resolved is not None and resolved.rsplit(".", 1)[-1] in {
                "scoped_session",
                "async_scoped_session",
            }
        alias = self._module_value(node)
        return alias is not None and self._is_orm_session_value(alias, depth + 1)

    @cached_property
    def _module_scope(self) -> _ModuleScope:
        """Module-scope binding counts, top-level definitions, imported names,
        names that any function declares ``global``, and the value each name
        is assigned (``None`` when bound by anything but an assignment)."""
        scope = _ModuleScope(Counter(), {}, {}, set(), {})
        if self.tree is None:
            return scope
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Global):
                scope.declared_global.update(node.names)
        for node in _walk_function_body(self.tree):
            for name in _bound_names(node):
                scope.bindings[name] += 1
                if isinstance(node, ast.alias):
                    statement = self.parents.get(id(node))
                    if isinstance(statement, ast.ImportFrom):
                        module = statement.module or ""
                        sources = (module, f"{module}.{node.name}")
                    else:
                        sources = (node.name,)
                    scope.imported[name] = sources
                elif isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    scope.definitions[name] = node
                else:
                    parent = self.parents.get(id(node))
                    scope.values[name] = (
                        parent.value
                        if isinstance(node, ast.Name)
                        and isinstance(parent, (ast.Assign, ast.AnnAssign))
                        else None
                    )
        return scope

    @cached_property
    def _module_rebinding(self) -> tuple[bool, frozenset[str]]:
        """Whether the module can rebind any global at run time, and the names
        it rebinds through its module object (see ``module_rebinding``)."""
        return module_rebinding(
            self.tree, module_name_for(self.file_path), self.parents
        )

    def _module_global_is_stable(self, name: str) -> bool:
        """``name`` is bound once in module scope and nothing rebinds it: no
        ``global`` statement, second binding, namespace write or ``setattr``."""
        scope = self._module_scope
        dynamic, rebound = self._module_rebinding
        return (
            not dynamic
            and name not in rebound
            and name not in scope.declared_global
            and scope.bindings[name] == 1
        )

    def _name_is_local(self, name: str, node: ast.AST) -> bool:
        """``name`` read at ``node`` may resolve to a binding of an enclosing
        function, lambda, comprehension or class body instead of the module
        global: a parameter, assignment, ``for``/``with``/``except`` target,
        import, nested definition, or ``global``/``nonlocal`` declaration."""
        in_function = False
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, _FUNCTION_SCOPES):
                if name in self._names_bound_under(current):
                    return True
                in_function = True
            elif isinstance(current, _COMPREHENSIONS) or (
                isinstance(current, ast.ClassDef) and not in_function
            ):
                if name in self._names_bound_under(current):
                    return True
            current = self.parents.get(id(current))
        return False

    def _names_bound_under(self, scope: ast.AST) -> frozenset[str]:
        """Names bound anywhere in ``scope``, nested scopes included on
        purpose: over-approximating only keeps a finding."""
        names = self._subtree_names.get(id(scope))
        if names is None:
            names = self._subtree_names[id(scope)] = frozenset(
                name for node in ast.walk(scope) for name in _bound_names(node, scope)
            )
        return names

    def _module_setting_pins_host(self, name: str, depth: int = 0) -> bool:
        """The module global ``name`` holds a URL whose host is fixed by the
        developer or the operator, and nothing in the module rebinds it."""
        if depth > _MAX_SETTING_DEPTH or not self._module_global_is_stable(name):
            return False
        scope = self._module_scope
        if name in scope.definitions:
            return False
        if name in scope.imported:
            # A setting imported from another module, but not request data
            # or a request-scoped proxy imported from a web framework.
            return not any(
                _is_request_scoped_module(source) for source in scope.imported[name]
            )
        return self._value_pins_host(scope.values.get(name), depth + 1)

    def _resolve_module_name(self, dotted: str) -> str | None:
        """What a module-level dotted name is bound to by unambiguous imports."""
        return self.untrusted_sources.resolved_import(None, dotted)

    def _value_pins_host(self, node: ast.AST | None, depth: int) -> bool:
        """A module setting's value fixes ``scheme://host``: a literal URL with
        a host, an environment variable or CLI argument whose fallback (if any)
        is such a literal, or another such setting."""
        if node is None or depth > _MAX_SETTING_DEPTH:
            return False
        literal = _constant_string(node)
        if literal is not None:
            return bool(_LITERAL_HOST_RE.match(literal))
        if isinstance(node, ast.Name):
            return self._module_setting_pins_host(node.id, depth + 1)
        is_lookup, fallback = _operator_lookup(node, self._resolve_module_name)
        if is_lookup:
            return (
                fallback is None
                or (isinstance(fallback, ast.Constant) and fallback.value is None)
                or self._value_pins_host(fallback, depth + 1)
            )
        if _is_str_call(node):
            return self._value_pins_host(node.args[0], depth + 1)
        if isinstance(node, ast.BoolOp):
            return all(self._value_pins_host(value, depth + 1) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self._value_pins_host(
                node.body, depth + 1
            ) and self._value_pins_host(node.orelse, depth + 1)
        parts = _concat_parts(node)
        if not parts:
            return False
        if _has_constant_host(node):
            return True
        return self._value_pins_host(_formatted_operand(parts[0]), depth + 1) and all(
            _is_operator_value(part, self._resolve_module_name) for part in parts[1:]
        )

    def _has_configured_host(self, node: ast.AST) -> bool:
        """``f"{SITE_URL}/api/{x}"``: a module-level setting picks the host and
        the literal after it starts the path, so later data cannot change it.
        ``//`` after the setting would start a new authority instead."""
        parts = _concat_parts(node)
        if not parts or len(parts) < 2:
            return False
        base = _formatted_operand(parts[0])
        literal = _constant_string(parts[1])
        return (
            isinstance(base, ast.Name)
            and bool(literal)
            and literal[0] in "/?#"
            and not literal.startswith("//")
            and not self._name_is_local(base.id, base)
            and self._module_setting_pins_host(base.id)
        )

    def _module_function(self, name: str):
        """The one top-level function ``name``, if nothing else binds it and
        no decorator replaces what it returns."""
        function = self._module_scope.definitions.get(name)
        if not isinstance(
            function, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not self._module_global_is_stable(name):
            return None
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            qualified = _qualified_name_from_expr(target) or ""
            if (
                self.untrusted_sources.resolved_import(None, qualified)
                not in _RESULT_PRESERVING_DECORATORS
            ):
                return None
        return function

    def _helper_returns_fixed_host(self, node: ast.AST) -> bool:
        """A call to the same-module helper (not a parameter or local of the
        same name) whose every return pins the host."""
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        if self._name_is_local(node.func.id, node.func):
            return False
        helper = self._module_function(node.func.id)
        if helper is None:
            return False
        result = self._fixed_host_helpers.get(id(helper))
        if result is None:
            returns = [
                stmt
                for stmt in _walk_function_body(helper)
                if isinstance(stmt, ast.Return)
            ]
            result = self._fixed_host_helpers[id(helper)] = bool(returns) and all(
                ret.value is not None
                and (
                    _has_constant_host(ret.value)
                    or self._has_configured_host(ret.value)
                )
                for ret in returns
            )
        return result

    def _url_value_has_fixed_host(self, node: ast.AST) -> bool:
        return (
            _has_constant_host(node)
            or self._has_configured_host(node)
            or self._helper_returns_fixed_host(node)
        )

    def _url_has_fixed_host(self, url_arg: ast.AST) -> bool:
        func = self._current_function()
        if self._url_value_has_fixed_host(url_arg):
            return True
        if _has_constant_host(self._resolve_url_expr(url_arg)):
            return True
        if not isinstance(url_arg, ast.Name) or func is None:
            return False
        name = url_arg.id
        args = func.args
        params = (
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
            args.vararg,
            args.kwarg,
        )
        if any(arg is not None and arg.arg == name for arg in params):
            return False  # a path that skips the assignments keeps the argument
        if self._binding_scope(name, url_arg) is not func:
            return False  # bound by a lambda or comprehension around the sink
        key = (id(func), name)
        result = self._fixed_host_locals.get(key)
        if result is None:
            result = self._fixed_host_locals[key] = self._local_url_has_fixed_host(
                func, name
            )
        return result

    def _local_url_has_fixed_host(self, func: ast.AST, name: str) -> bool:
        """Every assignment of the local ``name`` in ``func`` pins the host, so
        a branch that assigns request data is never hidden by one that does
        not."""
        info = self._scope_info(func)
        if name in info.global_names or name in info.nonlocal_names:
            return False
        values = []
        for node in info.bindings.get(name, ()):
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)):
                # A parameter, ``del``, ``except ... as``, a match capture, an
                # import or a nested definition: not a URL value.
                return False
            parent = self.parents.get(id(node))
            if (
                not isinstance(parent, (ast.Assign, ast.AnnAssign))
                or parent.value is None
            ):
                return False
            if isinstance(parent, ast.Assign) and node not in parent.targets:
                return False
            values.append(parent.value)
        return bool(values) and all(
            self._url_value_has_fixed_host(value) for value in values
        )

    def _dominating_statements(self, node: ast.AST, func: ast.AST):
        """Statements that run before ``node`` on every path through ``func``:
        the earlier siblings of each statement block on the way up to ``func``
        (nearest first). A ``try`` or ``with`` that holds a statement is not
        looked into, so an exit swallowed by a handler never counts."""
        current = node
        while current is not None and current is not func:
            parent = self.parents.get(id(current))
            if parent is None:
                return
            if isinstance(current, ast.stmt):
                for field in ("body", "orelse", "finalbody"):
                    block = getattr(parent, field, None)
                    if not isinstance(block, list):
                        continue
                    index = next(
                        (i for i, stmt in enumerate(block) if stmt is current), None
                    )
                    if index is not None:
                        yield from reversed(block[:index])
                        break
            current = parent

    def _statement_dominates(self, statement: ast.AST, node: ast.AST, func) -> bool:
        return any(
            earlier is statement for earlier in self._dominating_statements(node, func)
        )

    def _block_always_exits(self, body: list[ast.stmt], func: ast.AST) -> bool:
        """The block ends in ``raise``/``return`` or ``abort()``/``sys.exit()``,
        so the code after its ``if`` only runs when the test was false."""
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Raise, ast.Return)):
            return True
        if not (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call)):
            return False
        qn = _qualified_name_from_call(last.value)
        if not qn:
            return False
        return self.untrusted_sources.resolved_import(func, qn) in _GUARD_EXIT_CALLS

    def _reads_local(self, ref: ast.AST, name: str, func: ast.AST) -> bool:
        return (
            isinstance(ref, ast.Name)
            and ref.id == name
            and self._binding_scope(name, ref) is func
        )

    def _single_local_value(self, ref: ast.Name, func: ast.AST, at: ast.AST):
        """``(value, statement)`` of the only binding of ``ref`` in ``func``: a
        plain assignment that runs before ``at`` on every path."""
        if self._binding_scope(ref.id, ref) is not func:
            return None, None
        bindings = self._binding_nodes(func, ref.id)
        if len(bindings) != 1:
            return None, None
        target = bindings[0]
        statement = self.parents.get(id(target))
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or statement.targets[0] is not target:
                return None, None
        elif not (
            isinstance(statement, ast.AnnAssign)
            and statement.target is target
            and statement.value is not None
        ):
            return None, None
        if not self._statement_dominates(statement, at, func):
            return None, None
        return statement.value, statement

    def _parsed_url_read_line(self, expr, name, func, at, depth=0) -> int | None:
        """Line where ``expr`` (``urlparse(name)`` or a local holding it) read
        the URL, or None."""
        if isinstance(expr, ast.Call):
            qn = _qualified_name_from_call(expr)
            if (
                qn
                and self.untrusted_sources.resolved_import(func, qn) in _URL_PARSERS
                and len(expr.args) == 1
                and not expr.keywords
                and self._reads_local(expr.args[0], name, func)
            ):
                return expr.lineno
            return None
        if isinstance(expr, ast.Name) and depth < _MAX_GUARD_DERIVATION_DEPTH:
            value, statement = self._single_local_value(expr, func, at)
            if value is not None:
                return self._parsed_url_read_line(
                    value, name, func, statement, depth + 1
                )
        return None

    def _url_host_read_line(self, expr, name, func, at, depth=0) -> int | None:
        """Line where ``expr`` (the ``hostname``/``netloc`` of the URL held in
        ``name``, possibly through one local) read the URL, or None."""
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "lower"
            and not expr.args
            and not expr.keywords
        ):
            expr = expr.func.value
        if isinstance(expr, ast.Attribute) and expr.attr in _URL_HOST_ATTRS:
            return self._parsed_url_read_line(expr.value, name, func, at, depth)
        if isinstance(expr, ast.Name) and depth < _MAX_GUARD_DERIVATION_DEPTH:
            value, statement = self._single_local_value(expr, func, at)
            if value is not None:
                return self._url_host_read_line(value, name, func, statement, depth + 1)
        return None

    def _is_host_allowlist(self, node: ast.AST, func: ast.AST) -> bool:
        """A literal collection of strings, or a name/attribute that the
        request cannot choose: a module constant (not a string, whose ``in``
        is a substring test), an import, or an attribute of ``self``/``cls``."""
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            return bool(node.elts) and all(
                _constant_string(element) is not None for element in node.elts
            )
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name):
            return False
        if root is not node and root.id in {"self", "cls"}:
            return True
        if self._binding_scope(root.id, root) is not None:
            return False
        scope = self._module_scope
        if not scope.bindings[root.id]:
            return False
        if root is node:
            value = scope.values.get(root.id)
            if isinstance(value, (ast.Constant, ast.JoinedStr)):
                return False
        return True

    def _host_prefix_check_line(self, test, name, func) -> int | None:
        """``name.startswith("https://fixed.host/")``: the literal pins the
        host, so a scheme-only prefix such as ``"https://"`` does not count."""
        if not (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr == "startswith"
            and len(test.args) == 1
            and not test.keywords
            and self._reads_local(test.func.value, name, func)
        ):
            return None
        prefixes = test.args[0]
        values = prefixes.elts if isinstance(prefixes, ast.Tuple) else [prefixes]
        if values and all(
            _CONSTANT_HOST_PREFIX_RE.match(_constant_string(value) or "")
            for value in values
        ):
            return test.lineno
        return None

    def _allowlist_holds_when_true(self, test, name, func, guard) -> int | None:
        """``test`` being true proves the URL's host is allowlisted; returns
        the line where the URL was last read for the check."""
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            lines = [
                self._allowlist_holds_when_true(value, name, func, guard)
                for value in test.values
            ]
            lines = [line for line in lines if line is not None]
            return max(lines) if lines else None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._allowlist_holds_when_false(test.operand, name, func, guard)
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and self._is_host_allowlist(test.comparators[0], func)
        ):
            return self._url_host_read_line(test.left, name, func, guard)
        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr == "__contains__"
            and len(test.args) == 1
            and not test.keywords
            and self._is_host_allowlist(test.func.value, func)
        ):
            return self._url_host_read_line(test.args[0], name, func, guard)
        return self._host_prefix_check_line(test, name, func)

    def _allowlist_holds_when_false(self, test, name, func, guard) -> int | None:
        """``test`` being false proves the URL's host is allowlisted."""
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            lines = [
                self._allowlist_holds_when_false(value, name, func, guard)
                for value in test.values
            ]
            lines = [line for line in lines if line is not None]
            return max(lines) if lines else None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._allowlist_holds_when_true(test.operand, name, func, guard)
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and self._is_host_allowlist(test.comparators[0], func)
        ):
            return self._url_host_read_line(test.left, name, func, guard)
        return None

    def _host_allowlist_guard_dominates(self, sink: ast.Call, url_arg: ast.AST) -> bool:
        """An earlier ``if <host of url> not in ALLOWED: raise`` (or a
        ``not url.startswith("https://fixed.host/")`` check) in the sink's own
        function rejects every other host before the request is sent.

        Only a guard that always exits, sits before the sink on every path and
        checks the same local URL counts, and only when that URL is not
        rebound at or after the point the guard read it."""
        func = self._current_function()
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        if self.untrusted_sources is None or not isinstance(url_arg, ast.Name):
            return False
        name = url_arg.id
        if not self._reads_local(url_arg, name, func):
            return False
        if self._nested_declared_writes(func).get(name):
            return False
        bindings = self._binding_nodes(func, name)
        for guard in self._dominating_statements(sink, func):
            if not isinstance(guard, ast.If) or not self._block_always_exits(
                guard.body, func
            ):
                continue
            read_line = self._allowlist_holds_when_false(guard.test, name, func, guard)
            if read_line is None:
                continue
            if all(getattr(binding, "lineno", 0) < read_line for binding in bindings):
                return True
        return False

    def _untrusted_evidence(self, url_arg: ast.AST, sink: str):
        """Evidence that attacker-reachable input can pick the request host.

        A parameter of an arbitrary helper, a constant-host URL, a test client
        call or a deployment setting is not SSRF on its own; require a real
        untrusted source (route/CLI/MCP-tool argument, request data, input(),
        argv, stdin) and a host that the literal prefix does not pin."""
        if self._url_has_fixed_host(url_arg):
            return None
        func = self._current_function()
        evidence = self.untrusted_sources.evidence(
            func,
            url_arg,
            sink=f"`{sink}()` request URL",
            missing_guard="URL host allowlist",
            evidence_kind="python_ssrf_taint",
        )
        # Evidence packets show at most four labels. Decide from the complete
        # source set so a later request source cannot hide behind CLI inputs.
        sources = self.untrusted_sources.for_function(func).sources_in(url_arg)
        if evidence is not None and not _only_operator_sources(sources):
            return evidence
        name = getattr(func, "name", None)
        if name in self.dispatched_functions and super().is_tainted(url_arg):
            source = f"command-dispatch argument of `{name}`"
            return {"source": source, "sources": [source]}
        return None

    def _append_finding(self, node: ast.Call, url_arg: ast.AST, sink: str) -> None:
        if self._host_allowlist_guard_dominates(node, url_arg):
            return
        source_evidence = self._untrusted_evidence(url_arg, sink)
        if source_evidence is None:
            return
        interpolated = _is_interpolated_string(url_arg)
        symbol = self._current_symbol()
        self.findings.append(
            {
                "rule_id": "SKY-D216",
                "severity": "CRITICAL",
                "message": "Possible SSRF: tainted URL passed to HTTP client.",
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": symbol,
                "metadata": {
                    "security_evidence": _ssrf_security_evidence(
                        symbol=symbol,
                        sink=sink,
                        url_arg=url_arg,
                        interpolated=interpolated,
                    ),
                    "untrusted_source": source_evidence["source"],
                },
            }
        )

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)
        audit_urlopen(self, node)

        if (
            qn == "setattr"
            and len(node.args) >= 3
            and isinstance(node.args[0], ast.Name)
            and _constant_string(node.args[1]) in {"full_url", "host", "type", "selector"}
        ):
            self._record_request_url_mutation(node.args[0].id, node.args[2])
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_proxy"
            and isinstance(node.func.value, ast.Name)
            and node.args
        ):
            self._record_request_url_mutation(node.func.value.id, node.args[0])

        if qn and "." in qn:
            parts = qn.rsplit(".", 1)
            func = parts[1]
            if func in self.HTTP_METHODS and node.args:
                if self._is_likely_http_receiver(
                    node
                ) and not self._is_test_client_receiver(node):
                    url_arg = node.args[0]
                    if _is_interpolated_string(
                        url_arg
                    ) or _tainted_url_is_ssrf_relevant(self, url_arg):
                        self._append_finding(node, url_arg, qn)

        if qn and (
            qn.endswith(".urlopen")
            or self.untrusted_sources.resolved_import(self._current_function(), qn)
            == "urllib.request.urlopen"
        ):
            raw_arg = self._urlopen_argument(node)
            if raw_arg is not None:
                for url_arg in self._urlopen_url_candidates(raw_arg):
                    if _is_interpolated_string(url_arg) or _tainted_url_is_ssrf_relevant(
                        self, url_arg
                    ):
                        before = len(self.findings)
                        self._append_finding(node, url_arg, qn)
                        if len(self.findings) > before:
                            break

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SSRFFlowChecker(
            file_path, findings, sanitizers=URL_SANITIZERS, tree=tree
        )
        checker.visit(tree)
    except Exception as e:
        print(f"SSRF flow analysis failed for {file_path}: {e}", file=sys.stderr)
