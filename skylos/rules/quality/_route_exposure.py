"""Evidence that an unauthenticated route is open to anyone who reaches it.

SKY-F102 reviews mutating routes without an obvious auth guard. These helpers
decide when such a route is a security finding (SKY-D283): the route belongs
to an app created in the same module, nothing on the route, in its body or in
the module can authenticate the request, and its name, path or method names a
control, destructive, admin or command action. Two more module facts make it
CRITICAL: the module serves the app on every interface and shows no
authentication of any kind, and the handler body really performs the action.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from skylos.rules.danger.import_proof import (
    project_provider_effects_are_stable,
    provider_is_unshadowed,
)
from skylos.rules.danger.module_namespace import module_rebinding
from skylos.rules.danger.project_source import project_source_snapshot

PRIVILEGED_ROUTE_WORDS = {
    "control": frozenset(
        {
            "arm", "disarm", "takeoff", "fire", "power", "poweroff", "reboot",
            "shutdown", "restart", "halt", "control",
        }
    ),
    "destructive": frozenset(
        {"delete", "drop", "destroy", "purge", "wipe", "erase", "truncate"}
    ),
    "admin": frozenset({"admin", "superuser", "sudo", "impersonate"}),
    "command": frozenset({"exec", "execute", "shell", "command", "cmd"}),
}  # fmt: skip

_APP_CONSTRUCTORS = frozenset(
    {
        "fastapi.FastAPI", "fastapi.applications.FastAPI",
        "flask.Flask", "flask.app.Flask", "quart.Quart", "quart.app.Quart",
        "starlette.Starlette", "starlette.applications.Starlette",
        "sanic.Sanic", "sanic.app.Sanic", "apiflask.APIFlask", "apiflask.app.APIFlask",
    }
)  # fmt: skip
_LEGACY_CONSTRUCTORS = {
    "FastAPI": "fastapi.FastAPI", "Flask": "flask.Flask", "Quart": "quart.Quart",
    "Starlette": "starlette.applications.Starlette", "Sanic": "sanic.Sanic",
    "APIFlask": "apiflask.APIFlask", "APIRouter": "fastapi.APIRouter",
    "Blueprint": "flask.Blueprint",
}  # fmt: skip
_ALL_INTERFACE_HOSTS = frozenset({"0.0.0.0", "::", "[::]"})
_SERVER_METHODS = frozenset({"run", "run_app", "serve"})
_ENV_LOOKUPS = frozenset({"os.environ.get", "os.getenv", "environ.get", "getenv"})
_INERT_MIDDLEWARE = frozenset(
    {"CORSMiddleware", "GZipMiddleware", "TrustedHostMiddleware",
     "HTTPSRedirectMiddleware"}
)  # fmt: skip
_REQUEST_HOOKS = frozenset(
    {"middleware", "before_request", "before_app_request", "before_first_request"}
)
_GUARD_KEYWORDS = frozenset(
    {"auth", "guards", "permissions", "permission_classes",
     "authentication_classes", "security", "dependencies", "middleware",
     "before_request", "login_required", "roles"}
)  # fmt: skip
_INERT_ROUTE_KEYWORDS = frozenset(
    {"path", "rule", "methods", "response_model", "response_class",
     "status_code", "tags", "summary", "description", "response_description",
     "responses", "deprecated", "operation_id", "include_in_schema", "name",
     "endpoint", "strict_slashes", "defaults", "provide_automatic_options",
     "response_model_exclude_none", "response_model_exclude_unset",
     "response_model_include", "response_model_exclude",
     "response_model_by_alias", "response_model_exclude_defaults",
     "openapi_extra", "generate_unique_id_function", "callbacks"}
)  # fmt: skip
_REQUEST_PARAMETER_CALLS = frozenset(
    {"Header", "Cookie", "APIKeyHeader", "APIKeyCookie", "APIKeyQuery",
     "HTTPBearer", "HTTPBasic", "OAuth2PasswordBearer"}
)  # fmt: skip
_CREDENTIAL_ATTRIBUTES = frozenset(
    {"headers", "cookies", "session", "user", "auth", "authorization",
     "credentials", "client", "remote_addr", "access_route", "scope", "environ"}
)  # fmt: skip
_AUTH_WORDS = (
    "auth", "login", "permission", "permit", "jwt", "token", "principal",
    "current_user", "require_user", "require_admin", "security", "apikey",
    "api_key", "bearer", "password", "credential", "signature", "hmac",
    "session", "secret",
)  # fmt: skip
_REJECTION_STATUS = frozenset({401, 403})
_REJECTION_NAMES = frozenset(
    {"UNAUTHORIZED", "FORBIDDEN", "HTTP_401_UNAUTHORIZED", "HTTP_403_FORBIDDEN"}
)
_HOOK_CONTINUATIONS = frozenset({"call_next"})
_ACTION_SINK_PREFIXES = (
    "subprocess.", "os.system", "os.kill", "os.killpg", "os.remove",
    "os.unlink", "os.rmdir", "shutil.rmtree", "os.execv", "os.execl",
    "os.spawn", "os.popen",
)  # fmt: skip
_NAMESPACE_WORDS = frozenset({"control", "command", "cmd", "admin"})
_ROUTER_CONSTRUCTORS = frozenset(
    {"fastapi.APIRouter", "fastapi.routing.APIRouter", "flask.Blueprint",
     "flask.blueprints.Blueprint", "quart.Blueprint", "quart.blueprints.Blueprint"}
)  # fmt: skip
_INCLUDE_CALLS = frozenset({"include_router", "register_blueprint"})
_INERT_INCLUDE_KEYWORDS = frozenset({"prefix", "tags", "url_prefix", "name"})
_WSGI_ATTRIBUTES = frozenset({"wsgi_app", "asgi_app"})
_PATH_PARAMETER = re.compile(r"\{[^}]*\}|<[^>]*>")
_WORD = re.compile(
    r"[A-Z]+[0-9]*(?=[A-Z][a-z]|[^A-Za-z0-9]|$)|[A-Z]?[a-z]+[0-9]*|[0-9]+"
)


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _last(node) -> str:
    return _dotted(node).rsplit(".", 1)[-1]


def words(value: str) -> set[str]:
    return {word.lower() for word in _WORD.findall(value)}


def route_words(function, paths) -> set[str]:
    """Words of the function name and of each path, without path parameters."""
    found = words(function.name)
    for path in paths:
        found |= words(_PATH_PARAMETER.sub(" ", path))
    return found


def route_actions(found_words, methods) -> dict[str, list[str]]:
    """Privileged action kinds named by the route; DELETE is destructive."""
    found = {}
    for kind, vocabulary in PRIVILEGED_ROUTE_WORDS.items():
        matched = sorted(set(found_words) & vocabulary)
        if matched:
            found[kind] = matched
    if "DELETE" in methods and "delete" not in found.get("destructive", []):
        found["destructive"] = sorted({*found.get("destructive", []), "delete"})
    return found


def _module_bindings(module) -> dict[str, int]:
    """How often each module-scope name is bound: module-level stores,
    imports and definitions, plus any ``global`` declaration (counted twice,
    so a name a function may rebind is never single). Parameters and locals
    of functions and classes do not bind module names."""
    counts: dict[str, int] = {}

    def add(name, times=1):
        counts[name] = counts.get(name, 0) + times

    pending = list(module.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name)
            for inner in ast.walk(node):
                if isinstance(inner, ast.Global):
                    for name in inner.names:
                        add(name, 2)
            pending.extend(node.decorator_list)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0])
        pending.extend(ast.iter_child_nodes(node))
    return counts


def single_module_values(module) -> dict[str, ast.AST]:
    counts = _module_bindings(module)
    values = {}
    for statement in module.body:
        target = None
        value = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = statement.targets[0], statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target, value = statement.target, statement.value
        if isinstance(target, ast.Name) and counts.get(target.id) == 1:
            values[target.id] = value
    return values


def _inert_route_class(declaration):
    """Positive proof of a plain holder whose routing methods return identity."""
    if declaration.bases or declaration.keywords or declaration.decorator_list:
        return False
    routing = False
    for statement in declaration.body:
        if isinstance(statement, ast.Pass) or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if not isinstance(statement, ast.FunctionDef) or statement.decorator_list:
            return False
        arguments = statement.args
        if (
            arguments.defaults
            or any(value is not None for value in arguments.kw_defaults)
            or statement.returns
        ):
            return False
        if any(
            argument.annotation is not None
            for argument in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ]
        ):
            return False
        if statement.name == "__init__" and all(
            isinstance(part, ast.Pass) for part in statement.body
        ):
            continue
        if statement.name not in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "route",
            "api_route",
        }:
            return False
        if len(statement.body) != 1 or not isinstance(statement.body[0], ast.Return):
            return False
        returned = statement.body[0].value
        if not isinstance(returned, ast.Lambda):
            return False
        args = returned.args
        parameters = args.posonlyargs + args.args
        if (
            len(parameters) != 1
            or args.defaults
            or args.kwonlyargs
            or args.vararg
            or args.kwarg
        ):
            return False
        if (
            not isinstance(returned.body, ast.Name)
            or returned.body.id != parameters[0].arg
        ):
            return False
        routing = True
    return routing


class ModuleFacts:
    """Module-level facts shared by every route of one module."""

    def __init__(self, module, filename=None, project_root=None):
        self.module = module
        self.filename = filename
        self.project_root = project_root
        self.parents = {
            id(child): parent
            for parent in ast.walk(module)
            for child in ast.iter_child_nodes(parent)
        }
        self.scope_bindings = {}
        self.values = single_module_values(module)
        counts = _module_bindings(module)
        self.counts = counts
        self.classes = {
            statement.name: statement
            for statement in module.body
            if isinstance(statement, ast.ClassDef)
        }
        self.imports = {}
        self.import_counts = {}
        pending = list(module.body)
        while pending:
            statement = pending.pop()
            if isinstance(
                statement,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    name = alias.asname or alias.name.split(".")[0]
                    self.imports[name] = alias.name if alias.asname else name
                    self.import_counts[name] = self.import_counts.get(name, 0) + 1
            elif isinstance(statement, ast.ImportFrom) and not statement.level:
                for alias in statement.names:
                    name = alias.asname or alias.name
                    self.imports[name] = f"{statement.module}.{alias.name}"
                    self.import_counts[name] = self.import_counts.get(name, 0) + 1
            pending.extend(ast.iter_child_nodes(statement))
        self.apps = {
            name
            for name, value in self.values.items()
            if self._constructor(value) in _APP_CONSTRUCTORS
        }
        self.routers = {
            name
            for name, value in self.values.items()
            if self._constructor(value) in _ROUTER_CONSTRUCTORS
        }
        self.dependency_aliases = {
            name for name, value in self.values.items() if _contains_dependency(value)
        }
        self.apps |= self._included_routers()
        self._request_auth = None
        self._binds = None
        self._shows_auth = None

    def _constructor(self, value):
        if not isinstance(value, ast.Call):
            return None
        qualified = self._origin(value.func, frozenset())
        if qualified == "!inert":
            return None
        if qualified not in _APP_CONSTRUCTORS | _ROUTER_CONSTRUCTORS:
            qualified = _LEGACY_CONSTRUCTORS.get(_last(value.func))
        if not qualified:
            return None
        if (
            self.filename is not None
            and not provider_is_unshadowed(qualified, self.filename, self.project_root)
            and self._inert_provider(qualified)
        ):
            return None
        return qualified

    def _inert_provider(self, qualified):
        """A local file can reexport/wrap native frameworks; existence is no refutation."""
        # This proof resolves a direct member of one source module. A package's
        # same-named member cannot stand in for an implementation in a submodule.
        if qualified.count(".") != 1 or not project_provider_effects_are_stable(
            qualified, self.module, self.filename, self.project_root
        ):
            return False
        try:
            source = Path(self.filename).resolve()
            root = (
                Path(self.project_root).resolve()
                if self.project_root
                else source.parent
            )
            if not source.is_relative_to(root):
                return False
            sources, complete = project_source_snapshot(root)
            if not complete:
                return False
            module, _, name = qualified.partition(".")
            name = name.rsplit(".", 1)[-1]
            # An absolute import in an imported package module does not select
            # that module's siblings. Only the supplied import root can support
            # this negative proof; filename-only scans use their parent root.
            directory = root
            for _ in range(64):
                if any(
                    path.suffix in {".so", ".pyd"}
                    for path in directory.glob(module + ".*")
                ):
                    return False
                candidates = [
                    path
                    for path in [
                        directory / (module + ".py"),
                        directory / module / "__init__.py",
                    ]
                    if path.is_file()
                ]
                if candidates:
                    if len(candidates) != 1 or candidates[0].stat().st_size > 2_000_000:
                        return False
                    if (
                        candidates[0] == directory / (module + ".py")
                        and (directory / module).exists()
                    ):
                        return False
                    if (
                        candidates[0].is_symlink()
                        or not candidates[0].resolve().is_relative_to(root)
                        or any(
                            path.suffix in {".so", ".pyd"}
                            for path in candidates[0].parent.glob("__init__.*")
                        )
                    ):
                        return False
                    # Reuse the bounded, no-follow project source reader. A
                    # metadata check followed by a separate read is not an
                    # identity proof for an attacker-controlled provider file.
                    tree = sources.get(candidates[0])
                    if tree is None:
                        return False
                    body = [
                        statement
                        for statement in tree.body
                        if not (
                            isinstance(statement, ast.Expr)
                            and isinstance(statement.value, ast.Constant)
                            and isinstance(statement.value.value, str)
                        )
                    ]
                    return (
                        len(body) == 1
                        and isinstance(body[0], ast.ClassDef)
                        and body[0].name == name
                        and _inert_route_class(body[0])
                    )
                if directory == root or directory.parent == directory:
                    return False
                directory = directory.parent
        except (
            OSError,
            UnicodeError,
            SyntaxError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            return False
        return False

    def _local_class_effects_are_stable(self, declaration):
        try:
            source = Path(self.filename or "app.py").resolve()
            root = (
                Path(self.project_root).resolve()
                if self.project_root
                else source.parent
            )
            parts = list(source.relative_to(root).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            if not parts:
                return False
            return project_provider_effects_are_stable(
                ".".join([*parts, declaration.name]),
                self.module,
                self.filename,
                self.project_root,
            )
        except (OSError, RuntimeError, ValueError, TypeError):
            return False

    def _origin(self, node, seen):
        if id(node) in seen or len(seen) >= 32:
            return None
        seen = seen | {id(node)}
        if isinstance(node, ast.Attribute):
            base = self._origin(node.value, seen)
            return f"{base}.{node.attr}" if base else None
        if not isinstance(node, ast.Name):
            return None
        declaration = self.classes.get(node.id)
        if (
            declaration is not None
            and self.counts.get(node.id) == self.import_counts.get(node.id, 0) + 1
            and _inert_route_class(declaration)
            and not module_rebinding(self.module)[0]
            and self._local_class_effects_are_stable(declaration)
        ):
            return "!inert"
        if node.id in self.imports:
            return self.imports[node.id]
        value = self.values.get(node.id)
        if isinstance(value, (ast.Name, ast.Attribute)):
            return self._origin(value, seen)
        if declaration:
            for base in declaration.bases:
                origin = self._origin(base, seen)
                if origin in _APP_CONSTRUCTORS | _ROUTER_CONSTRUCTORS:
                    return origin
        return None

    def _module_reference(self, node):
        """A local parameter/store must not stand in for the module's app."""
        name = node.id
        child = node
        current = self.parents.get(id(child))
        inside_function = False
        while current is not None and current is not self.module:
            if isinstance(
                current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                if any(
                    isinstance(part, ast.Name) and part.id == name
                    for generator in current.generators
                    for part in ast.walk(generator.target)
                ):
                    return False
            if isinstance(
                current,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                header = isinstance(
                    current, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and (
                    child in current.decorator_list
                    or child is current.args
                    or child is current.returns
                )
                if not header and not (
                    inside_function and isinstance(current, ast.ClassDef)
                ):
                    bound = self.scope_bindings.get(id(current))
                    if bound is None:
                        bound = (
                            set(_module_bindings(current))
                            if not isinstance(current, ast.Lambda)
                            else {
                                part.id
                                for part in ast.walk(current.body)
                                if isinstance(part, ast.Name)
                                and isinstance(part.ctx, (ast.Store, ast.Del))
                            }
                        )
                        if not isinstance(current, ast.ClassDef):
                            arguments = current.args
                            bound.update(
                                arg.arg
                                for arg in [
                                    *arguments.posonlyargs,
                                    *arguments.args,
                                    *arguments.kwonlyargs,
                                ]
                            )
                            bound.update(
                                arg.arg
                                for arg in [arguments.vararg, arguments.kwarg]
                                if arg
                            )
                        self.scope_bindings[id(current)] = bound
                    if name in bound:
                        return False
                    if not isinstance(current, ast.ClassDef):
                        inside_function = True
            child, current = current, self.parents.get(id(current))
        return True

    def owned_method(self, node, owners=None):
        owners = self.apps if owners is None else owners
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in owners
            and self._module_reference(node.value)
        )

    def _included_routers(self) -> set[str]:
        """Routers this module creates and mounts, with no options that could
        add a guard, on an app it creates."""
        routers = {
            name
            for name, value in self.values.items()
            if name in self.routers
            and all(
                keyword.arg in _INERT_INCLUDE_KEYWORDS for keyword in value.keywords
            )
        }
        included = set()
        for node in ast.walk(self.module):
            if not (
                isinstance(node, ast.Call)
                and self.owned_method(node.func)
                and node.func.attr in _INCLUDE_CALLS
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
            ):
                continue
            if all(keyword.arg in _INERT_INCLUDE_KEYWORDS for keyword in node.keywords):
                included.add(node.args[0].id)
        return routers & included

    def owns_app(self, decorator) -> bool:
        """The route decorator registers on an app this module creates."""
        func = decorator
        if isinstance(decorator, ast.Call):
            func = decorator.func
        return self.owned_method(func)

    def request_auth_possible(self) -> bool:
        if self._request_auth is None:
            self._request_auth = _request_auth_possible(self)
        return self._request_auth

    def binds_all_interfaces(self) -> bool:
        if self._binds is None:
            self._binds = _binds_all_interfaces(self.module, self.values)
        return self._binds

    def shows_auth(self) -> bool:
        if self._shows_auth is None:
            self._shows_auth = _names_auth(self.module)
        return self._shows_auth


def _contains_dependency(node) -> bool:
    return any(
        isinstance(part, ast.Call) and _last(part.func) in {"Depends", "Security"}
        for part in ast.walk(node)
    )


def _literal_host(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Call)
        and _dotted(node.func) in _ENV_LOOKUPS
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return node.args[1].value
    return None


def _server_host(call: ast.Call):
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr not in _SERVER_METHODS:
        return None
    for keyword in call.keywords:
        if keyword.arg == "host":
            return keyword.value
    if call.func.attr == "run" and call.args and _dotted(call.func) != "uvicorn.run":
        return call.args[0]
    return None


def _binds_all_interfaces(module, values) -> bool:
    """The module starts a server on every interface (``0.0.0.0``/``::``),
    literally or as the default of an environment lookup bound once."""
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        host = _server_host(node)
        if host is None:
            continue
        value = _literal_host(host)
        if value is None and isinstance(host, ast.Name) and host.id in values:
            value = _literal_host(values[host.id])
        if value in _ALL_INTERFACE_HOSTS:
            return True
    return False


def _names(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.arg):
            yield node.arg
        elif isinstance(node, ast.keyword) and node.arg:
            yield node.arg
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                yield alias.name
                if alias.asname:
                    yield alias.asname


def _names_auth(tree) -> bool:
    """Authentication identifiers, rather than prose or ``author`` substrings."""
    return any(_auth_name(text) for text in _names(tree))


def _auth_name(text) -> bool:
    found = words(text)
    return bool(
        found & {*_AUTH_WORDS, "oauth", "oauth2", "permissions", "credentials"}
        or any(word.startswith(("authenticat", "authoriz")) for word in found)
        or any(word in text.lower() for word in _AUTH_WORDS if "_" in word)
    )


def _login_redirect(node) -> bool:
    """A redirect to a login endpoint can reject an unauthenticated caller."""
    if not isinstance(node, ast.Call) or _last(node.func) != "redirect":
        return False
    for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
        target = argument
        if isinstance(target, ast.Call) and _last(target.func) == "url_for":
            target = target.args[0] if target.args else None
        if (
            isinstance(target, ast.Constant)
            and isinstance(target.value, str)
            and "login" in words(target.value)
        ):
            return True
    return False


def _request_names(function) -> set[str]:
    names = {"request", "req", "g"}
    for argument in [*function.args.posonlyargs, *function.args.args]:
        annotation = argument.annotation
        if argument.arg in {"request", "req"} or (
            annotation is not None
            and _last(annotation) in {"Request", "HTTPConnection"}
        ):
            names.add(argument.arg)
    return names


def _root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    return node


def _rejection_status(node) -> bool:
    if isinstance(node, ast.Constant) and node.value in _REJECTION_STATUS:
        return True
    return isinstance(node, ast.Attribute) and node.attr in _REJECTION_NAMES


def _rejects_caller(node) -> bool:
    """``abort(401)``, ``HTTPException(status_code=403)``, ``return body,
    401`` and similar."""
    if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
        return any(_rejection_status(element) for element in node.value.elts)
    if not isinstance(node, ast.Call):
        return False
    return any(
        _rejection_status(argument)
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
    )


def may_authenticate(function) -> bool:
    """A handler or hook that reads the caller's credentials or client, names
    authentication, rejects with 401/403, or hands the request to other code
    can be the authentication. Response objects are not request reads."""
    requests = _request_names(function)
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute) and node.attr in _CREDENTIAL_ATTRIBUTES:
            base = _root(node.value)
            if isinstance(base, ast.Name) and base.id in requests:
                return True
        key = None
        receiver = None
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            key, receiver = node.slice, node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"get", "__getitem__"}
            and node.args
        ):
            key, receiver = node.args[0], node.func.value
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            base = _root(receiver)
            if (
                isinstance(base, ast.Name)
                and base.id in requests
                and _auth_name(key.value)
            ):
                return True
        if _rejects_caller(node) or _login_redirect(node):
            return True
        if isinstance(node, ast.Call):
            if _last(node.func) in _HOOK_CONTINUATIONS:
                continue
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            if any(
                isinstance(argument, ast.Name) and argument.id in requests
                for argument in arguments
            ):
                return True
    return _names_auth(function)


def _guard_option(value, facts) -> bool:
    """Explicitly absent/empty guard options cannot authenticate a request."""
    if isinstance(value, ast.Name) and facts._module_reference(value):
        value = facts.values.get(value.id, value)
    if isinstance(value, ast.Constant) and value.value in {None, False}:
        return False
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)) and not value.elts:
        return False
    if isinstance(value, ast.Dict) and not value.keys:
        return False
    return True


def _request_auth_possible(facts: ModuleFacts) -> bool:
    """Module code that can authenticate every request outside the handler:
    unknown middleware, ``dependencies=``/``auth=`` style options, a hook
    registered by call, or a request hook that may authenticate."""
    module = facts.module
    owners = facts.apps | facts.routers
    constructors = {id(facts.values[name]) for name in owners if name in facts.values}
    decorators = {
        id(decorator)
        for node in ast.walk(module)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        for decorator in node.decorator_list
    }
    for node in ast.walk(module):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = [getattr(node, "target", None), *getattr(node, "targets", [])]
            if any(
                facts.owned_method(target) and target.attr in _WSGI_ATTRIBUTES
                for target in targets
            ):
                return True
        if isinstance(node, ast.Call):
            name = _last(node.func)
            owned = facts.owned_method(node.func, owners)
            if owned and name == "add_middleware":
                if not node.args or _last(node.args[0]) not in _INERT_MIDDLEWARE:
                    return True
            if (
                owned
                and name in _REQUEST_HOOKS
                and node.args
                and id(node) not in decorators
            ):
                return True
            if (owned or id(node) in constructors) and any(
                keyword.arg in _GUARD_KEYWORDS and _guard_option(keyword.value, facts)
                for keyword in node.keywords
            ):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = (
                    decorator.func if isinstance(decorator, ast.Call) else decorator
                )
                if (
                    facts.owned_method(target, owners)
                    and _last(target) in _REQUEST_HOOKS
                    and may_authenticate(node)
                ):
                    return True
    return False


def route_guard_possible(function, route_decorators, facts: ModuleFacts) -> bool:
    """Anything on the route itself that could authenticate: another
    decorator, a decorator option other than routing metadata, a dependency or
    header/cookie/security parameter, or a handler body that may authenticate."""
    if len(function.decorator_list) != len(route_decorators):
        return True
    for decorator in route_decorators:
        if isinstance(decorator, ast.Call) and any(
            keyword.arg is None or keyword.arg not in _INERT_ROUTE_KEYWORDS
            for keyword in decorator.keywords
        ):
            return True
    arguments = function.args
    parts = [*arguments.defaults, *(part for part in arguments.kw_defaults if part)]
    for argument in [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
        arguments.vararg,
        arguments.kwarg,
    ]:
        if argument is not None and argument.annotation is not None:
            parts.append(argument.annotation)
    for part in parts:
        for node in ast.walk(part):
            if isinstance(node, ast.Call) and _last(node.func) in {
                "Depends",
                "Security",
                *_REQUEST_PARAMETER_CALLS,
            }:
                return True
            if isinstance(node, ast.Name) and node.id in facts.dependency_aliases:
                return True
    return may_authenticate(function)


def performs_action(function, actions) -> bool:
    """The handler body calls something named for a specific action word
    (not a namespace word such as ``control``), or a process, signal or
    file-removal sink."""
    matched = {word for found in actions.values() for word in found} - _NAMESPACE_WORDS
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if words(name) & matched:
            return True
        if name.startswith(_ACTION_SINK_PREFIXES):
            return True
    return False


def exposure_severity(facts: ModuleFacts, function, actions) -> str:
    """HIGH; CRITICAL when the module serves every interface, shows no
    authentication anywhere, and the handler performs the named action."""
    if (
        facts.binds_all_interfaces()
        and not facts.shows_auth()
        and performs_action(function, actions)
    ):
        return "CRITICAL"
    return "HIGH"
