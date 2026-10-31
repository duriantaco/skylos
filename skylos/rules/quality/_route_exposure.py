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
    {"FastAPI", "Flask", "Quart", "Starlette", "Sanic", "APIFlask"}
)
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
_ROUTER_CONSTRUCTORS = frozenset({"APIRouter", "Blueprint"})
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


class ModuleFacts:
    """Module-level facts shared by every route of one module."""

    def __init__(self, module):
        self.module = module
        self.values = single_module_values(module)
        self.apps = {
            name
            for name, value in self.values.items()
            if isinstance(value, ast.Call) and _last(value.func) in _APP_CONSTRUCTORS
        }
        self.dependency_aliases = {
            name for name, value in self.values.items() if _contains_dependency(value)
        }
        self.apps |= self._included_routers()
        self._request_auth = None
        self._binds = None
        self._shows_auth = None

    def _included_routers(self) -> set[str]:
        """Routers this module creates and mounts, with no options that could
        add a guard, on an app it creates."""
        routers = {
            name
            for name, value in self.values.items()
            if isinstance(value, ast.Call)
            and _last(value.func) in _ROUTER_CONSTRUCTORS
            and all(
                keyword.arg in _INERT_INCLUDE_KEYWORDS for keyword in value.keywords
            )
        }
        included = set()
        for node in ast.walk(self.module):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _INCLUDE_CALLS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.apps
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
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in self.apps
        )

    def request_auth_possible(self) -> bool:
        if self._request_auth is None:
            self._request_auth = _request_auth_possible(self.module)
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


def _strings(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def _names_auth(tree) -> bool:
    return any(
        word in text.lower()
        for text in (*_names(tree), *_strings(tree))
        for word in _AUTH_WORDS
    )


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
        if _rejects_caller(node):
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


def _request_auth_possible(module) -> bool:
    """Module code that can authenticate every request outside the handler:
    unknown middleware, ``dependencies=``/``auth=`` style options, a hook
    registered by call, or a request hook that may authenticate."""
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
                isinstance(target, ast.Attribute) and target.attr in _WSGI_ATTRIBUTES
                for target in targets
            ):
                return True
        if isinstance(node, ast.Call):
            name = _last(node.func)
            if name in {"add_middleware", "Middleware"}:
                if not node.args or _last(node.args[0]) not in _INERT_MIDDLEWARE:
                    return True
            if name in _REQUEST_HOOKS and node.args and id(node) not in decorators:
                return True
            if any(keyword.arg in _GUARD_KEYWORDS for keyword in node.keywords):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if _last(decorator) in _REQUEST_HOOKS and may_authenticate(node):
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
