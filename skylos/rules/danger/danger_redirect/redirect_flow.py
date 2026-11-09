from __future__ import annotations
import ast
import hashlib
from collections import Counter
import sys
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger import import_proof
from skylos.rules.danger.untrusted_sources import (
    REQUEST_NAMES,
    UntrustedSourceIndex,
    _attribute_source,
    _dotted,
)


LEGACY_REDIRECT_FUNCS = frozenset(
    {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}
)

REDIRECT_FUNCS = {
    "redirect",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "RedirectResponse",
    "HTTPFound",
    "HTTPMovedPermanently",
    "HTTPSeeOther",
    "HTTPTemporaryRedirect",
    "HTTPPermanentRedirect",
}

REDIRECT_TARGET_KEYWORDS = ("to", "redirect_to", "location", "url")

SAFE_REDIRECT_GUARDS = frozenset(
    {
        "django.utils.http.url_has_allowed_host_and_scheme",
        "django.utils.http.is_safe_url",
    }
)

_RESPONSE_FACTORIES = ("Response", "make_response")

_ABSOLUTE_REQUEST_URL_ATTRS = frozenset({"url", "base_url", "url_root", "host_url"})
_FRAMEWORK_REQUEST_PROXIES = frozenset({"flask.request", "quart.request"})
_REQUEST_CLASSES = frozenset(
    {
        "starlette.requests.Request",
        "starlette.requests.HTTPConnection",
        "fastapi.Request",
        "fastapi.requests.Request",
    }
)
_URL_CLASSES = frozenset({"starlette.datastructures.URL"})

_STRING_PROPAGATING_METHODS = frozenset(
    {
        "format",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "casefold",
        "removeprefix",
        "removesuffix",
        "join",
        "encode",
        "decode",
        "get",
        "getlist",
        "getone",
        "pop",
    }
)
_PROPAGATING_FUNCTIONS = frozenset(
    {
        "urllib.parse.urljoin",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "urllib.parse.urlunparse",
        "urllib.parse.urlunsplit",
        "urllib.parse.urlencode",
        "os.path.join",
        "posixpath.join",
    }
)
_MAX_REQUEST_DATA_DEPTH = 16

REQUEST_ARGS_ATTRS = {"args", "params", "query", "GET"}

# Native route builders keep user values in path/query parameters. A matching
# method or local function spelling alone says nothing about the target host.
_NATIVE_URL_BUILDERS = frozenset(
    {
        "flask.url_for",
        "flask.helpers.url_for",
        "quart.url_for",
        "django.urls.reverse",
        "django.urls.reverse_lazy",
        "django.core.urlresolvers.reverse",
        "django.core.urlresolvers.reverse_lazy",
    }
)


def _is_request_args_get(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "get":
        return False
    val = func.value
    if (
        isinstance(val, ast.Attribute)
        and val.attr in REQUEST_ARGS_ATTRS
        and isinstance(val.value, ast.Name)
        and val.value.id == "request"
    ):
        return True
    return False


def _fixed_local_prefix(node):
    """A fixed first path segment keeps a suffix on the current origin.

    A slash alone is insufficient: ``'/' + '/example.com'`` changes the host.
    Require a literal alphanumeric character after that slash, before any
    untrusted suffix. Browser control stripping cannot remove that character.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fixed_local_prefix(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _fixed_local_prefix(node.values[0])
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) > 1
        and node.value[0] == "/"
        and node.value[1].isascii()
        and node.value[1].isalnum()
    )


def _leading_literal(node):
    """The literal text a string expression starts with, or None when it
    starts with a value."""
    while True:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            node = node.left
        elif isinstance(node, ast.JoinedStr) and node.values:
            node = node.values[0]
        else:
            break
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keeps_origin(node) -> bool:
    """The literal start of the URL fixes its origin: a first path segment
    (``"/entry/" + slug``), or the query or fragment of the root path
    (``f"/?next={target}"``)."""
    if _fixed_local_prefix(node):
        return True
    prefix = _leading_literal(node)
    return bool(prefix) and prefix[:2] in {"/?", "/#"}


def _stable_module_classes(tree):
    """A class spelling proves ancestry only while its binding is unique."""
    counts = Counter()
    classes = {}
    pending = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            counts[node.name] += 1
            if isinstance(node, ast.ClassDef):
                if node in tree.body:
                    classes[node.name] = node
                pending.extend(node.bases)
                pending.extend(keyword.value for keyword in node.keywords)
            else:
                pending.extend(node.args.defaults)
                pending.extend(value for value in node.args.kw_defaults if value)
            pending.extend(node.decorator_list)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            counts[node.id] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                counts[alias.asname or alias.name.split(".", 1)[0]] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            counts[node.name] += 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            counts[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            counts[node.rest] += 1
        pending.extend(ast.iter_child_nodes(node))
    global_names = {
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Global)
        for name in node.names
    }
    return {
        name: node
        for name, node in classes.items()
        if counts[name] == 1 and name not in global_names
    }


class _RedirectFlowChecker(TaintVisitor):
    def __init__(self, file_path, findings, tree):
        super().__init__(file_path, findings)
        self.tree = tree
        self.source_ast_sha256 = None
        self._exception_states = []
        self._loop_states = []
        self.untrusted_sources = UntrustedSourceIndex(tree)
        self.redirect_evidence_sources = UntrustedSourceIndex(
            tree, follow_local_calls=True
        )
        self._classes = _stable_module_classes(tree)
        self._class_stack = []
        self._reader_override_cache = {}
        self._class_aliases = {}
        self._reader_writes = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, ast.Name
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        self._class_aliases.setdefault(target.id, set()).add(
                            node.value.id
                        )
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name)
            ):
                self._reader_writes.setdefault(node.attr, set()).add(node.value.id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
            ):
                member = node.args[1]
                name = member.value if isinstance(member, ast.Constant) else None
                self._reader_writes.setdefault(name, set()).add(node.args[0].id)

    def _reader_replaced(self, klass, name):
        key = klass, name
        if key not in self._reader_override_cache:
            aliases = {klass.name}
            for _ in range(24):
                expanded = aliases | {
                    alias
                    for alias, sources in self._class_aliases.items()
                    if sources & aliases
                }
                if expanded == aliases:
                    break
                aliases = expanded
            else:
                self._reader_override_cache[key] = True
                return True
            if aliases & (
                self._reader_writes.get(name, set())
                | self._reader_writes.get(None, set())
            ):
                self._reader_override_cache[key] = True
                return True
            self._reader_override_cache[key] = any(
                (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr == name
                )
                or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and len(node.args) >= 2
                    and (
                        not isinstance(node.args[1], ast.Constant)
                        or node.args[1].value == name
                    )
                )
                for node in ast.walk(klass)
            )
        return self._reader_override_cache[key]

    def visit_ClassDef(self, node):
        self._class_stack.append(node)
        super().visit_ClassDef(node)
        self._class_stack.pop()

    def _noninstance_descriptor(self, decorator):
        pending = [_dotted(decorator)]
        seen = set()
        while pending and len(seen) < 24:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            if name.rsplit(".", 1)[-1] in {"staticmethod", "classmethod"} or (
                self.untrusted_sources.resolved_import(None, name)
                in {"builtins.staticmethod", "builtins.classmethod"}
            ):
                return True
            pending.extend(self._class_aliases.get(name, ()))
        return bool(pending)

    def _tornado_argument_read(self, node):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr
            in {"get_argument", "get_query_argument", "get_body_argument"}
            and isinstance(node.func.value, ast.Name)
            and self._class_stack
            and self._current_function() is not None
        ):
            return False
        function = self._current_function()
        parameters = function.args.posonlyargs + function.args.args
        if not parameters or node.func.value.id != parameters[0].arg:
            return False
        if any(
            self._noninstance_descriptor(decorator)
            for decorator in function.decorator_list
        ):
            return False
        if function not in self._class_stack[-1].body or any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, (ast.Store, ast.Del))
            and child.id == parameters[0].arg
            for statement in function.body
            for child in ast.walk(statement)
        ):
            return False
        visited = set()

        def inherits_handler(klass):
            if id(klass) in visited:
                return False
            visited.add(id(klass))
            if len(klass.bases) != 1:
                # An unknown mixin can override the request-reading method.
                return False
            if self._reader_replaced(klass, node.func.attr):
                return False
            # A local override may return application data instead of a request
            # argument. Do not infer its semantics from the method name.
            if any(
                (
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name == node.func.attr
                )
                or (
                    isinstance(member, (ast.Assign, ast.AnnAssign))
                    and any(
                        isinstance(target, ast.Name) and target.id == node.func.attr
                        for target in (
                            member.targets
                            if isinstance(member, ast.Assign)
                            else [member.target]
                        )
                    )
                )
                for member in klass.body
            ):
                return False
            for base in klass.bases:
                dotted = _dotted(base)
                if self.untrusted_sources.resolved_import(None, dotted) == (
                    "tornado.web.RequestHandler"
                ):
                    return True
                if (
                    isinstance(base, ast.Name)
                    and base.id in self._classes
                    and self._import_names_are_stable(base.id)
                ):
                    if inherits_handler(self._classes[base.id]):
                        return True
            return False

        return inherits_handler(self._class_stack[-1])

    def _visit_block(self, statements):
        """Return whether the block has a path reaching its next statement."""
        for statement in statements:
            continues = self.visit(statement)
            for states in self._exception_states:
                states.append(self._copy_env(self.env_stack))
            if continues is False:
                return False
        return True

    def _visit_function(self, node):
        # Each function has its own flow; a return must not stop its enclosing
        # module or function from being scanned.
        for expression in node.decorator_list + node.args.defaults:
            self.visit(expression)
        for expression in node.args.kw_defaults:
            if expression is not None:
                self.visit(expression)
        self._push()
        outer_exceptions = self._exception_states
        outer_loops = self._loop_states
        self._exception_states = []
        self._loop_states = []
        self._symbol_stack.append(node.name)
        self._function_stack.append(node)
        self._taint_params(node)
        self._visit_block(node.body)
        self._function_stack.pop()
        self._symbol_stack.pop()
        self._pop()
        self._exception_states = outer_exceptions
        self._loop_states = outer_loops

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Return(self, node):
        self.generic_visit(node)
        return False

    def visit_Raise(self, node):
        self.generic_visit(node)
        return False

    def visit_Break(self, node):
        if self._loop_states:
            self._loop_states[-1].append(self._copy_env(self.env_stack))
        return False

    visit_Continue = visit_Break

    def _resolves_to(self, node, names) -> bool:
        dotted = _dotted(node)
        if not dotted:
            return False
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), dotted
        )
        return resolved in names

    def _is_framework_request(self, node) -> bool:
        """The current request: Flask's imported ``request`` proxy, or a
        parameter annotated as a Starlette/FastAPI ``Request`` that the
        function never rebinds."""
        if not isinstance(node, ast.Name):
            return False
        if self._resolves_to(node, _FRAMEWORK_REQUEST_PROXIES):
            return True
        function = self._current_function()
        if function is None:
            return False
        arguments = function.args
        parameters = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        matches = [
            parameter
            for parameter in parameters
            if parameter.arg == node.id
            and parameter.annotation is not None
            and self._resolves_to(parameter.annotation, _REQUEST_CLASSES)
        ]
        if not matches:
            return False
        return not any(
            isinstance(child, ast.Name)
            and child.id == node.id
            and isinstance(child.ctx, (ast.Store, ast.Del))
            for statement in function.body
            for child in ast.walk(statement)
        )

    def _is_current_absolute_url(self, node) -> bool:
        """An absolute URL of the request being served (``request.url``,
        ``request.base_url``, Starlette ``URL(scope=scope)``). Its host is the
        one the browser already sent the request to, so redirecting to it, or
        to a copy with an untainted part replaced, stays on the site. A bare
        path (``request.path``) is not included: ``//evil.example`` is a
        path."""
        if (
            isinstance(node, ast.Attribute)
            and node.attr in _ABSOLUTE_REQUEST_URL_ATTRS
            and self._is_framework_request(node.value)
        ):
            return True
        return (
            isinstance(node, ast.Call)
            and not node.args
            and [keyword.arg for keyword in node.keywords] == ["scope"]
            and self._resolves_to(node.func, _URL_CLASSES)
        )

    def is_tainted(self, node):
        if _fixed_local_prefix(node):
            return False
        if self._tornado_argument_read(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self.is_tainted(node.value)
        if self._starts_with_internal_url(node):
            return False
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
        if isinstance(node, ast.BoolOp):
            return any(self.is_tainted(value) for value in node.values)
        return super().is_tainted(node)

    def _starts_with_internal_url(self, node):
        if isinstance(node, ast.Call):
            if self._native_instance_path(node):
                return True
            dotted = _dotted(node.func)
            if not dotted or not self._import_names_are_stable(dotted):
                return False
            imported = self.untrusted_sources.resolved_import(
                self._current_function(), dotted
            )
            return bool(
                imported in _NATIVE_URL_BUILDERS
                and self._sanitizer_is_unpatched(imported)
                and import_proof.provider_binding_is_stable(
                    imported,
                    self.untrusted_sources.module,
                    self.file_path,
                    getattr(self, "project_root", None),
                )
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._starts_with_internal_url(node.left)
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            return isinstance(
                first, ast.FormattedValue
            ) and self._starts_with_internal_url(first.value)
        return False

    def _native_instance_path(self, node):
        """A native application plus a fixed-prefix, literal route table.

        Native instance methods need receiver proof as well as provider proof.
        In particular, a catch-all '/{path:path}' route is not a fixed-origin
        guarantee merely because its router is Starlette.
        """
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "url_path_for"
            and isinstance(node.func.value, ast.Name)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return False
        tree = self.untrusted_sources.module
        receiver = node.func.value.id
        if not self._import_names_are_stable(receiver):
            return False
        if not self._sanitizer_is_unpatched("starlette.url_path_for"):
            return False
        # Index only module bindings. A local parameter with the same spelling
        # in an unrelated handler cannot invalidate the application binding.
        bindings = {}
        pending = list(tree.body)
        while pending:
            current = pending.pop()
            if isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bindings.setdefault(current.name, []).append(None)
                continue
            if isinstance(current, (ast.Assign, ast.AnnAssign)):
                targets = (
                    current.targets
                    if isinstance(current, ast.Assign)
                    else [current.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings.setdefault(target.id, []).append(
                            current.value if current in tree.body else None
                        )
            elif isinstance(current, (ast.Import, ast.ImportFrom)):
                for alias in current.names:
                    bindings.setdefault(
                        alias.asname or alias.name.split(".", 1)[0], []
                    ).append(None)
            elif isinstance(current, ast.Name) and isinstance(current.ctx, ast.Del):
                bindings.setdefault(current.id, []).append(None)
            pending.extend(ast.iter_child_nodes(current))
        seen = set()
        root_name = receiver
        constructor = None
        for _ in range(32):
            if root_name in seen:
                return False
            seen.add(root_name)
            values = bindings.get(root_name, ())
            if len(values) != 1:
                return False
            value = values[0]
            if isinstance(value, ast.Name):
                root_name = value.id
            elif isinstance(value, ast.Call):
                constructor = value
                break
            else:
                return False
        if constructor is None:
            return False
        aliases = {root_name}
        for _ in range(32):
            expanded = aliases | {
                name
                for name, values in bindings.items()
                if len(values) == 1
                and isinstance(values[0], ast.Name)
                and values[0].id in aliases
            }
            if expanded == aliases:
                break
            aliases = expanded
        else:
            return False
        if receiver not in aliases:
            return False
        function = self._current_function()
        if function is not None:
            if any(
                arg.arg in aliases
                for arg in ast.walk(function.args)
                if isinstance(arg, ast.arg)
            ):
                return False
            if any(
                isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and part is not function
                and part.name in aliases
                or isinstance(part, (ast.Import, ast.ImportFrom))
                and any(
                    (alias.asname or alias.name.split(".", 1)[0]) in aliases
                    for alias in part.names
                )
                for part in ast.walk(function)
            ):
                return False
            if any(
                isinstance(part, ast.Name)
                and part.id in aliases
                and isinstance(part.ctx, (ast.Store, ast.Del))
                for part in ast.walk(function)
            ):
                return False
        parents = {
            id(child): parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for part in ast.walk(tree):
            if (
                not isinstance(part, ast.Name)
                or part.id not in aliases
                or not isinstance(part.ctx, ast.Load)
            ):
                continue
            # Same-spelled parameters/local variables in another scope are
            # separate objects, rather than escapes of the module instance.
            scope = parents.get(id(part))
            local = False
            while scope is not None and scope is not tree:
                if isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    scoped = (
                        list(scope.body)
                        if not isinstance(scope, ast.Lambda)
                        else [scope.body]
                    )
                    local_names = {
                        arg.arg
                        for arg in ast.walk(scope.args)
                        if isinstance(arg, ast.arg)
                    }
                    globals_ = set()
                    while scoped:
                        item = scoped.pop()
                        if isinstance(
                            item,
                            (
                                ast.FunctionDef,
                                ast.AsyncFunctionDef,
                                ast.ClassDef,
                                ast.Lambda,
                            ),
                        ):
                            if not isinstance(item, ast.Lambda):
                                local_names.add(item.name)
                            continue
                        if isinstance(item, ast.Name) and isinstance(
                            item.ctx, (ast.Store, ast.Del)
                        ):
                            local_names.add(item.id)
                        elif isinstance(item, (ast.Import, ast.ImportFrom)):
                            local_names.update(
                                alias.asname or alias.name.split(".", 1)[0]
                                for alias in item.names
                            )
                        elif isinstance(item, ast.Global):
                            globals_.update(item.names)
                        scoped.extend(ast.iter_child_nodes(item))
                    if part.id in globals_:
                        break
                    if part.id in local_names:
                        local = True
                        break
                scope = parents.get(id(scope))
            if local:
                continue
            parent = parents.get(id(part))
            if (
                isinstance(parent, ast.Assign)
                and parent.value is part
                and all(
                    isinstance(target, ast.Name) and target.id in aliases
                    for target in parent.targets
                )
            ):
                continue
            if (
                isinstance(parent, ast.AnnAssign)
                and parent.value is part
                and isinstance(parent.target, ast.Name)
                and parent.target.id in aliases
            ):
                continue
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is part
                and parent.attr == "url_path_for"
            ):
                call = parents.get(id(parent))
                if isinstance(call, ast.Call) and call.func is parent:
                    continue
            return False
        imported = self.untrusted_sources.resolved_import(
            None, _dotted(constructor.func)
        )
        if imported not in {
            "starlette.applications.Starlette",
            "starlette.routing.Router",
            "fastapi.FastAPI",
            "fastapi.applications.FastAPI",
        }:
            return False
        if not import_proof.provider_binding_is_stable(
            imported, tree, self.file_path, getattr(self, "project_root", None)
        ):
            return False
        routes = next(
            (kw.value for kw in constructor.keywords if kw.arg == "routes"), None
        )
        if not isinstance(routes, (ast.List, ast.Tuple)) or any(
            kw.arg is None for kw in constructor.keywords
        ):
            return False
        found = False
        for route in routes.elts:
            if not isinstance(route, ast.Call) or any(
                kw.arg is None for kw in route.keywords
            ):
                return False
            provider = self.untrusted_sources.resolved_import(None, _dotted(route.func))
            if (
                provider != "starlette.routing.Route"
                or not import_proof.provider_binding_is_stable(
                    provider, tree, self.file_path, getattr(self, "project_root", None)
                )
            ):
                return False
            path = (
                route.args[0]
                if route.args
                else next((kw.value for kw in route.keywords if kw.arg == "path"), None)
            )
            name = next((kw.value for kw in route.keywords if kw.arg == "name"), None)
            if (
                not isinstance(path, ast.Constant)
                or not isinstance(path.value, str)
                or not isinstance(name, ast.Constant)
                or not isinstance(name.value, str)
            ):
                return False
            if name.value == node.args[0].value:
                if not _fixed_local_prefix(path):
                    return False
                found = True
        return found

    def visit_NamedExpr(self, node):
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, self.is_tainted(node.value))
        self.generic_visit(node)

    @staticmethod
    def _copy_env(env):
        return [scope.copy() for scope in env]

    @staticmethod
    def _merge_env(states):
        # A name missing in a local scope can still resolve to an outer binding.
        # Keep that inherited taint when only one branch creates a local name.
        merged = []
        for index in range(len(states[0])):
            names = set().union(*(state[index] for state in states))
            scope = {}
            for name in names:
                scope[name] = any(
                    next(
                        (
                            part[name]
                            for part in reversed(state[: index + 1])
                            if name in part
                        ),
                        False,
                    )
                    for state in states
                )
            merged.append(scope)
        return merged

    def _safe_redirect_guard_target(self, test):
        """The local name checked by Django's
        ``url_has_allowed_host_and_scheme(url, ...)``, when the call resolves
        to Django's function through an import that nothing rebinds."""
        if not isinstance(test, ast.Call):
            return None
        name = _dotted(test.func)
        if not name:
            return None
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), name
        )
        if resolved not in SAFE_REDIRECT_GUARDS:
            return None
        target = None
        if test.args:
            target = test.args[0]
        for keyword in test.keywords:
            if keyword.arg == "url":
                target = keyword.value
        if isinstance(target, ast.Name):
            return target.id
        return None

    def _narrow_literal_guard(self, test, truth):
        """Only equality with immutable literal values, or a passing Django
        host-and-scheme check, proves a target bounded.

        A netloc check or leading slash alone is not browser redirect safety,
        and a check on one expression does not validate a later request read.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._narrow_literal_guard(test.operand, not truth)
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And) and truth:
                for value in test.values:
                    self._narrow_literal_guard(value, True)
            elif isinstance(test.op, ast.Or) and not truth:
                for value in test.values:
                    self._narrow_literal_guard(value, False)
            return
        guarded = self._safe_redirect_guard_target(test)
        if guarded is not None:
            if truth:
                self._set(guarded, False)
            return
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return
        left, right, op = test.left, test.comparators[0], test.ops[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            if isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                left, right = right, left
            bounded = isinstance(right, ast.Constant) and isinstance(right.value, str)
            matches = truth if isinstance(op, ast.Eq) else not truth
        elif isinstance(op, (ast.In, ast.NotIn)):
            bounded = isinstance(right, (ast.Tuple, ast.List, ast.Set)) and all(
                isinstance(value, ast.Constant) and isinstance(value.value, str)
                for value in right.elts
            )
            matches = truth if isinstance(op, ast.In) else not truth
        else:
            return
        if isinstance(left, ast.Name) and bounded and matches:
            self._set(left.id, False)

    def visit_If(self, node):
        self.visit(node.test)
        entry = self._copy_env(self.env_stack)
        continuing = []
        for truth, statements in ((True, node.body), (False, node.orelse)):
            self.env_stack = self._copy_env(entry)
            self._narrow_literal_guard(node.test, truth)
            if self._visit_block(statements):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing) if continuing else entry
        return bool(continuing)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item)
        # An unknown context manager can suppress an exception from any body
        # statement, including a rejected target. Do not leak that proof out.
        states = [self._copy_env(self.env_stack)]
        self._exception_states.append(states)
        self._visit_block(node.body)
        self._exception_states.pop()
        self.env_stack = self._merge_env(states)

    visit_AsyncWith = visit_With

    def _visit_loop(self, node):
        expression = node.test if isinstance(node, ast.While) else node.iter
        self.visit(expression)
        entry = self._copy_env(self.env_stack)
        if isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(
            node.target, ast.Name
        ):
            self._set(node.target.id, self.is_tainted(node.iter))
        exits = []
        self._loop_states.append(exits)
        self._visit_block(node.body)
        self._loop_states.pop()
        # Zero iterations and break/continue both retain possible values.
        self.env_stack = self._merge_env([entry, self.env_stack, *exits])
        if node.orelse:
            before_else = self._copy_env(self.env_stack)
            self._visit_block(node.orelse)
            self.env_stack = self._merge_env([before_else, self.env_stack])

    visit_For = _visit_loop
    visit_AsyncFor = _visit_loop
    visit_While = _visit_loop

    def visit_Try(self, node):
        exceptional = [self._copy_env(self.env_stack)]
        self._exception_states.append(exceptional)
        normal = self._visit_block(node.body)
        self._exception_states.pop()
        continuing = []
        if normal and self._visit_block(node.orelse):
            continuing.append(self._copy_env(self.env_stack))
        for handler in node.handlers:
            self.env_stack = self._merge_env(exceptional)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._set(handler.name, True)
            if self._visit_block(handler.body):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing or exceptional)
        final_continues = self._visit_block(node.finalbody)
        return bool(continuing) and final_continues

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        entry = self._copy_env(self.env_stack)
        states = [entry]
        for case in node.cases:
            self.env_stack = self._copy_env(entry)
            for pattern in ast.walk(case.pattern):
                if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
                    self._set(pattern.name, self.is_tainted(node.subject))
            if case.guard is not None:
                self.visit(case.guard)
            if self._visit_block(case.body):
                states.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(states)

    def visit_Call(self, node):
        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name in LEGACY_REDIRECT_FUNCS and node.args:
            self._check_legacy_redirect(node, node.args[0])
        elif func_name in REDIRECT_FUNCS:
            url_arg = _redirect_target(node)
            if url_arg is not None and self._proven_open_redirect(url_arg):
                self._report_redirect(
                    node,
                    "Possible open redirect: request data chooses the redirect target.",
                    url_arg,
                    native_source=True,
                )
        else:
            self._check_location_headers(node)

        self.generic_visit(node)

    def _check_legacy_redirect(self, node, url_arg):
        if _is_request_args_get(url_arg):
            self._report_redirect(
                node,
                "Possible open redirect: request parameter passed to "
                "redirect via .get() — default value does not prevent "
                "attacker-supplied input.",
                url_arg,
            )
        elif self._starts_with_internal_url(url_arg):
            pass
        elif self.is_tainted(url_arg):
            self._report_redirect(
                node,
                "Possible open redirect: user-controlled URL passed to redirect.",
                url_arg,
                native_source=self._carries_tornado_data(url_arg),
            )

    def _carries_tornado_data(self, node, seen=(), depth=0):
        """Retain native RequestHandler proof only along the target's values.

        The project tracer does not model Tornado argument readers. An
        unrelated read elsewhere in a function must not turn a generic
        parameter into a proven request source.
        """
        if depth > _MAX_REQUEST_DATA_DEPTH or node is None:
            return False
        if self._starts_with_internal_url(node) or _keeps_origin(node):
            return False
        if self._tornado_argument_read(node):
            return True
        if isinstance(node, ast.Name):
            if node.id in seen:
                return False
            scope = self._current_function()
            if scope is None or not self._local_bindings(scope, node.id):
                scope = self.untrusted_sources.module
            return any(
                kind == "value"
                and self._carries_tornado_data(value, (*seen, node.id), depth + 1)
                for kind, value in self._local_bindings(scope, node.id)
            )
        if isinstance(node, ast.Call):
            arguments = [*node.args, *(item.value for item in node.keywords)]
            func = node.func
            name = _dotted(func)
            resolved = (
                self.untrusted_sources.resolved_import(self._current_function(), name)
                if name
                else None
            )
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _STRING_PROPAGATING_METHODS
            ):
                arguments.insert(0, func.value)
            elif not (
                name == "str"
                or resolved in _PROPAGATING_FUNCTIONS
                or isinstance(func, ast.Name)
                and self._defines_in_module(func.id)
            ):
                return False
            return any(
                self._carries_tornado_data(value, seen, depth + 1)
                for value in arguments
            )
        if isinstance(
            node, (ast.Attribute, ast.Subscript, ast.NamedExpr, ast.Await, ast.Starred)
        ):
            return self._carries_tornado_data(node.value, seen, depth + 1)
        if isinstance(node, ast.JoinedStr):
            values = [
                item.value
                for item in node.values
                if isinstance(item, ast.FormattedValue)
            ]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            values = [node.left, node.right]
        elif isinstance(node, ast.IfExp):
            values = [node.body, node.orelse]
        elif isinstance(node, ast.BoolOp):
            values = node.values
        elif isinstance(node, ast.Tuple):
            values = node.elts
        else:
            return False
        return any(
            self._carries_tornado_data(value, seen, depth + 1) for value in values
        )

    def _proven_open_redirect(self, value) -> bool:
        """Redirect sinks added after ``redirect``/``HttpResponseRedirect``
        (``RedirectResponse``, the ``HTTPFound`` family, ``Location``
        headers) need request data proven to reach the target, not just a
        function parameter."""
        if self._starts_with_internal_url(value) or _keeps_origin(value):
            return False
        if _is_request_args_get(value):
            return True
        return self.is_tainted(value) and self._carries_request_data(value, (), 0)

    def _function_parameters(self, function) -> set[str]:
        arguments = function.args
        names = {
            argument.arg
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
        }
        for extra in (arguments.vararg, arguments.kwarg):
            if extra is not None:
                names.add(extra.arg)
        return names

    def _local_bindings(self, scope, name):
        """``(kind, value)`` for each statement in ``scope`` (not nested
        functions or classes) that binds ``name``. ``suffix`` is the right
        side of ``name += value``."""
        bindings = []
        pending = list(getattr(scope, "body", []))
        while pending:
            node = pending.pop()
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(node, ast.Assign):
                if any(_binds(target, name) for target in node.targets):
                    bindings.append(("value", node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if _binds(node.target, name):
                    bindings.append(("value", node.value))
            elif isinstance(node, ast.AugAssign) and _binds(node.target, name):
                if isinstance(node.op, ast.Add):
                    bindings.append(("suffix", node.value))
                else:
                    bindings.append(("value", node.value))
            elif isinstance(node, ast.NamedExpr) and _binds(node.target, name):
                bindings.append(("value", node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor)) and _binds(
                node.target, name
            ):
                bindings.append(("value", node.iter))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None and _binds(
                        item.optional_vars, name
                    ):
                        bindings.append(("value", item.context_expr))
            pending.extend(ast.iter_child_nodes(node))
        return bindings

    def _name_carries_request_data(self, name, seen, depth) -> bool:
        if name in seen:
            return False
        seen = (*seen, name)
        function = self._current_function()
        scope = function
        if function is None or (
            name not in self._function_parameters(function)
            and not self._local_bindings(function, name)
        ):
            scope = self.untrusted_sources.module
        if scope is None:
            return False
        if function is not None and scope is function:
            if name in self._function_parameters(function):
                origins = self.untrusted_sources.for_function(function).origins
                if name in origins:
                    return True
        for kind, value in self._local_bindings(scope, name):
            if kind == "suffix":
                continue
            if self._carries_request_data(value, seen, depth + 1):
                return True
        return False

    def _defines_in_module(self, name) -> bool:
        module = self.untrusted_sources.module
        if module is None:
            return False
        return any(
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == name
            for statement in module.body
        )

    def _call_carries_request_data(self, node, seen, depth) -> bool:
        """Data flows through string methods, ``str()``, ``urljoin`` and other
        modelled URL helpers, and through functions defined in this file.
        A call into another module (``get_next_url(request)`` imported from
        a project helper) or any other library ends the flow: its result is
        not proven to carry the request data it was given."""
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _STRING_PROPAGATING_METHODS:
            return any(
                self._carries_request_data(value, seen, depth + 1)
                for value in (func.value, *arguments)
            )
        name = _dotted(func)
        resolved = None
        if name:
            resolved = self.untrusted_sources.resolved_import(
                self._current_function(), name
            )
        if name == "str" or resolved in _PROPAGATING_FUNCTIONS:
            return any(
                self._carries_request_data(value, seen, depth + 1)
                for value in arguments
            )
        if isinstance(func, ast.Name) and self._defines_in_module(func.id):
            return any(
                self._carries_request_data(value, seen, depth + 1)
                for value in arguments
            )
        return False

    def _concatenation_carries_request_data(self, node, seen, depth) -> bool:
        """``prefix + value``: request data on the right only chooses the
        target when the prefix is a literal that does not fix the origin
        (``"https://" + host``). Appended to a value (``url += "&q=" + q``)
        it extends a target chosen elsewhere, as CodeQL's string-concatenation
        sanitizer treats it."""
        if self._carries_request_data(node.left, seen, depth + 1):
            return True
        if not self._carries_request_data(node.right, seen, depth + 1):
            return False
        return _leading_literal(node.left) is not None

    def _carries_request_data(self, node, seen, depth) -> bool:
        """Request data (a read from the request, a route parameter, a
        Tornado argument) reaches ``node`` through modelled operations."""
        if depth > _MAX_REQUEST_DATA_DEPTH:
            return True
        if node is None or isinstance(node, ast.Constant):
            return False
        if self._starts_with_internal_url(node) or _keeps_origin(node):
            return False
        if self._is_current_absolute_url(node):
            return False
        if _is_request_args_get(node) or self._tornado_argument_read(node):
            return True
        if isinstance(node, ast.Name):
            return self._name_carries_request_data(node.id, seen, depth)
        if isinstance(node, ast.Attribute):
            function = self._current_function()
            bindings = self.untrusted_sources._import_bindings_for(function)
            request_names = set(REQUEST_NAMES)
            if function is not None:
                request_names |= self.untrusted_sources.for_function(
                    function
                ).request_names
            if _attribute_source(node, request_names, bindings):
                return True
            return self._carries_request_data(node.value, seen, depth + 1)
        if isinstance(node, ast.Subscript):
            return self._carries_request_data(node.value, seen, depth + 1)
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(value, ast.FormattedValue)
                and self._carries_request_data(value.value, seen, depth + 1)
                for value in node.values
            )
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._concatenation_carries_request_data(node, seen, depth)
            if isinstance(node.op, ast.Mod):
                return self._carries_request_data(
                    node.left, seen, depth + 1
                ) or self._carries_request_data(node.right, seen, depth + 1)
            return False
        if isinstance(node, ast.IfExp):
            return self._carries_request_data(
                node.body, seen, depth + 1
            ) or self._carries_request_data(node.orelse, seen, depth + 1)
        if isinstance(node, ast.BoolOp):
            return any(
                self._carries_request_data(value, seen, depth + 1)
                for value in node.values
            )
        if isinstance(node, (ast.NamedExpr, ast.Await, ast.Starred)):
            return self._carries_request_data(node.value, seen, depth + 1)
        if isinstance(node, ast.Tuple):
            return any(
                self._carries_request_data(value, seen, depth + 1)
                for value in node.elts
            )
        if isinstance(node, ast.Call):
            return self._call_carries_request_data(node, seen, depth)
        return False

    def _report_redirect(self, node, message, operand, *, native_source=False):
        evidence = self.redirect_evidence_sources.evidence(
            self._current_function(),
            operand,
            sink="redirect target",
            missing_guard="redirect origin allowlist",
            evidence_kind="python_redirect_taint",
        )
        metadata = {}
        if evidence is not None:
            metadata["security_evidence"] = evidence
        request_evidence = evidence is not None and any(
            source.startswith(
                ("request data ", "route parameter ", "MCP/agent tool argument ")
            )
            for source in evidence.get("sources", ())
        )
        # Preserve the native checker's richer request/provider semantics.
        # An opaque or replaced URL helper cannot erase a visible request
        # input, while CLI, environment and stdin alone do not prove one.
        tornado_source = self._carries_tornado_data(operand)
        native_source = (
            tornado_source or request_evidence or (native_source and evidence is None)
        )
        if native_source:
            # Newer sink families already require native framework request
            # provenance. The legacy project tracer does not model every
            # supported reader (notably Tornado), so it cannot invalidate
            # that stronger local proof.
            proven_source = bool(tornado_source or request_evidence)
            metadata["source_status"] = "untrusted" if proven_source else "unresolved"
            metadata["redirect_source_proof"] = {
                "kind": "native_framework_request"
                if proven_source
                else "native_request_candidate",
                "analysis_complete": False,
            }
            if not proven_source:
                metadata["audit_only"] = True
        else:
            if self.source_ast_sha256 is None:
                self.source_ast_sha256 = hashlib.sha256(
                    ast.dump(self.tree).encode()
                ).hexdigest()
            metadata["redirect_operand"] = {
                "line": operand.lineno,
                "col": operand.col_offset,
                "end_line": operand.end_lineno,
                "end_col": operand.end_col_offset,
            }
            metadata["redirect_source_ast_sha256"] = self.source_ast_sha256
            metadata["redirect_sink"] = "redirect target"
            if evidence is not None:
                metadata["source_status"] = "untrusted"
            else:
                metadata["source_status"] = "unresolved"
                metadata["audit_only"] = True
                message = (
                    "Review redirect target: its origin is unresolved; "
                    "attacker control has not been established."
                )
        self.findings.append(
            {
                "rule_id": "SKY-D230",
                "severity": "HIGH",
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": self._current_symbol(),
                "metadata": metadata,
            }
        )

    def _location_value_is_open(self, value) -> bool:
        return self._proven_open_redirect(value)

    def _check_location_headers(self, node):
        """``Response(..., headers={"Location": url})`` and
        ``resp.headers.set("Location", url)``."""
        if _is_response_factory(node.func):
            for keyword in node.keywords:
                if keyword.arg == "headers" and isinstance(keyword.value, ast.Dict):
                    for key, value in zip(keyword.value.keys, keyword.value.values):
                        if _is_location_key(key) and self._location_value_is_open(
                            value
                        ):
                            self._report_redirect(
                                node,
                                "Possible open redirect: user-controlled URL set as the Location header.",
                                value,
                                native_source=True,
                            )
                            return
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"set", "add", "setdefault", "__setitem__"}
            and _is_headers_object(node.func.value)
            and len(node.args) >= 2
            and _is_location_key(node.args[0])
            and self._location_value_is_open(node.args[1])
        ):
            self._report_redirect(
                node,
                "Possible open redirect: user-controlled URL set as the Location header.",
                node.args[1],
                native_source=True,
            )

    def visit_Assign(self, node):
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and _is_location_key(target.slice)
                and (
                    _is_headers_object(target.value)
                    or self._is_response_object(target.value)
                )
                and self._location_value_is_open(node.value)
            ):
                self._report_redirect(
                    node,
                    "Possible open redirect: user-controlled URL set as the Location header.",
                    node.value,
                    native_source=True,
                )
                break
        super().visit_Assign(node)

    def _is_response_object(self, node) -> bool:
        """``response["Location"] = url`` on a Django response built in the
        same function (``response = HttpResponse(status=302)``)."""
        function = self._current_function()
        if not isinstance(node, ast.Name) or function is None:
            return False
        values = [
            child.value
            for child in ast.walk(function)
            if isinstance(child, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == node.id
                for target in child.targets
            )
        ]
        return bool(values) and all(
            isinstance(value, ast.Call) and _is_response_factory(value.func)
            for value in values
        )


def _binds(target, name) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_binds(element, name) for element in target.elts)
    if isinstance(target, ast.Starred):
        return _binds(target.value, name)
    return False


def _redirect_target(node):
    """The redirect URL: the first argument, or Django ``to``/``redirect_to``,
    Flask/aiohttp/Pyramid ``location`` or Starlette/FastAPI ``url``."""
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in REDIRECT_TARGET_KEYWORDS:
            return keyword.value
    return None


def _is_response_factory(func) -> bool:
    name = _dotted(func) or ""
    return name.rsplit(".", 1)[-1].endswith(_RESPONSE_FACTORIES)


def _is_location_key(node) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lower() == "location"
    )


def _is_headers_object(node) -> bool:
    """``response.headers``. ``self.headers`` is skipped: a response class
    that sets its own ``Location`` defines a redirect sink; its callers are
    checked where they pass the URL."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "headers"
        and not (isinstance(node.value, ast.Name) and node.value.id == "self")
    )


def scan(tree, file_path, findings, *, project_root=None):
    try:
        checker = _RedirectFlowChecker(file_path, findings, tree)
        checker.project_root = project_root
        checker.visit(tree)
    except Exception as e:
        print(f"Redirect flow analysis failed for {file_path}: {e}", file=sys.stderr)
