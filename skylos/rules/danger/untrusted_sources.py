"""Name the untrusted source behind a Python taint finding.

The Python taint checkers treat every function parameter as tainted, which is
right for a review but says nothing about *where* the data comes from. This
module recognises the same "real" sources the agent-hook policy
(``skylos.commands.hook_policy``) accepts -- parameters of a web-route / CLI /
MCP-tool entry point, ``request.*``, ``input()``, ``sys.argv``,
``os.environ`` / ``os.getenv`` and ``sys.stdin`` -- and turns them into a
``security_evidence`` packet (``source`` / ``sink`` / ``path``) that SARIF
``codeFlows`` and evidence contracts can use.

A finding gets a packet only when such a source reaches the sink expression.
The constants below must stay in sync with ``hook_policy``; a test checks it.
"""

from __future__ import annotations

import ast
from typing import Any

ROUTE_DECORATOR_NAMES = frozenset(
    {
        # web frameworks
        "route", "get", "post", "put", "patch", "delete", "head", "options",
        "websocket", "api_route", "api_view", "view_config", "action",
        # CLIs (click / typer)
        "command", "group", "callback", "argument", "option",
        # MCP / agent tools: arguments come from the model
        "tool", "resource", "prompt",
    }
)  # fmt: skip
_CLI_DECORATORS = frozenset({"command", "group", "callback", "argument", "option"})
_KNOWN_CLI_DECORATOR_ROOTS = frozenset({"click", "typer"})
_TOOL_DECORATORS = frozenset({"tool", "resource", "prompt"})
REQUEST_ANNOTATIONS = frozenset(
    {"Request", "HttpRequest", "WebSocket", "UploadFile", "HTTPConnection"}
)
REQUEST_NAMES = frozenset({"request", "req"})
SOURCE_CALLS = frozenset(
    {"input", "raw_input", "os.getenv", "os.environ.get", "sys.stdin.read",
     "sys.stdin.readline", "sys.stdin.readlines"}
)  # fmt: skip
SOURCE_ATTRS = frozenset({"sys.argv", "os.environ", "sys.stdin"})

_MAX_PROPAGATION_ROUNDS = 4
_MAX_SOURCES = 4


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _params(func: ast.AST) -> list[ast.arg]:
    args = func.args  # type: ignore[attr-defined]
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        params.append(args.vararg)
    if args.kwarg:
        params.append(args.kwarg)
    return params


def entrypoint_decorator(func: ast.AST) -> str | None:
    """Return the dotted decorator that makes ``func`` an entry point."""
    cli_decorator = None
    for decorator in getattr(func, "decorator_list", []) or []:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute):
            name = target.attr
        elif isinstance(target, ast.Name):
            name = target.id
        else:
            continue
        if name in ROUTE_DECORATOR_NAMES:
            dotted = _dotted(target) or name
            if _entrypoint_kind(dotted) != "CLI parameter":
                return dotted
            cli_decorator = dotted
    return cli_decorator


def _entrypoint_kind(decorator: str) -> str:
    last = decorator.rsplit(".", 1)[-1]
    root = decorator.split(".", 1)[0]
    # A bare `.command()` can also expose a Discord/chat bot to remote users.
    # Only known Click/Typer decorators prove operator-owned CLI input.
    if last in _CLI_DECORATORS and root in _KNOWN_CLI_DECORATOR_ROOTS:
        return "CLI parameter"
    if last in _TOOL_DECORATORS:
        return "MCP/agent tool argument"
    return "route parameter"


def _annotation_is_request(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    for node in ast.walk(annotation):
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        else:
            continue
        if name in REQUEST_ANNOTATIONS:
            return True
    return False


def _target_names(targets: list[ast.AST]) -> list[str]:
    names = []
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.append(node.id)
    return names


def _assign_parts(node: ast.AST) -> tuple[ast.AST | None, list[str]]:
    if isinstance(node, ast.Assign):
        return node.value, _target_names(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return node.value, _target_names([node.target])
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return node.iter, _target_names([node.target])
    if isinstance(node, ast.withitem):
        targets = [node.optional_vars] if node.optional_vars is not None else []
        return node.context_expr, _target_names(targets)
    if isinstance(node, ast.NamedExpr):
        return node.value, _target_names([node.target])
    return None, []


def _module_level_nodes(tree: ast.AST):
    stack = list(getattr(tree, "body", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _immediate_nested_functions(func: ast.AST):
    stack = list(getattr(func, "body", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
            continue
        if isinstance(node, ast.ClassDef):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _scope_bindings(scope: ast.AST) -> dict[str, str | None]:
    """Names bound in a scope, with unambiguous imports where available.

    Any assignment or competing import makes a binding uncertain. In that
    case, a spelling such as ``urllib.request`` cannot prove it is the module.
    """
    imports: dict[str, str | None] = {}
    other_bindings: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        other_bindings.update(param.arg for param in _params(scope))

    # _module_level_nodes intentionally skips nested definitions, but their
    # names still rebind imports in the surrounding scope.
    stack = list(getattr(scope, "body", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other_bindings.add(node.name)
            continue
        stack.extend(ast.iter_child_nodes(node))

    for node in _module_level_nodes(scope):
        if isinstance(node, ast.Import):
            pairs = (
                (alias.asname or alias.name.split(".", 1)[0],
                 alias.name if alias.asname else alias.name.split(".", 1)[0])
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            pairs = (
                (alias.asname or alias.name,
                 f"{node.module}.{alias.name}" if node.module and not node.level else None)
                for alias in node.names
                if alias.name != "*"
            )
        else:
            pairs = ()
            other_bindings.update(_assign_parts(node)[1])
            if isinstance(node, ast.ExceptHandler) and node.name:
                other_bindings.add(node.name)
            elif isinstance(node, ast.comprehension):
                other_bindings.update(_target_names([node.target]))
            elif isinstance(node, ast.Lambda):
                other_bindings.update(param.arg for param in _params(node))
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                other_bindings.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                other_bindings.add(node.rest)
        for name, qualified in pairs:
            if name in imports and imports[name] != qualified:
                other_bindings.add(name)
            imports[name] = qualified

    return {
        **{name: None for name in other_bindings},
        **{name: qualified for name, qualified in imports.items()
           if name not in other_bindings},
    }


def _assignment_targets(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return [node.target]
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return [node.target]
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return [node.optional_vars]
    if isinstance(node, ast.Delete):
        return node.targets
    return []


def _is_globals_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "globals"
        and not node.args
        and not node.keywords
    )


def _module_dict_root(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        dotted = _dotted(node.value)
        return dotted.split(".", 1)[0] if dotted else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
    ):
        dotted = _dotted(node.args[0])
        return dotted.split(".", 1)[0] if dotted else None
    return None


def _unsafe_import_roots(module: ast.AST) -> tuple[set[str], bool]:
    """Find writes that can replace an imported module or one of its members.

    This deliberately overapproximates aliases across scopes: uncertain module
    identity must not be used as proof that ``request`` means urllib's module.
    """
    aliases: dict[str, set[str]] = {}
    unsafe: set[str] = set()
    unknown_global_write = False

    for node in ast.walk(module):
        targets = _assignment_targets(node)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
            node.value, (ast.Name, ast.Attribute)
        ):
            source = _dotted(node.value) if isinstance(node.value, ast.Attribute) else node.value.id
            if source:
                root = source.split(".", 1)[0]
                for target in targets:
                    if isinstance(target, ast.Name):
                        aliases.setdefault(target.id, set()).add(root)

        for target in targets:
            for part in ast.walk(target):
                if isinstance(part, ast.Attribute):
                    dotted = _dotted(part)
                    if dotted:
                        unsafe.add(dotted.split(".", 1)[0])
                elif isinstance(part, ast.Subscript) and _is_globals_call(part.value):
                    key = part.slice
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        unsafe.add(key.value)
                    else:
                        unknown_global_write = True
                elif isinstance(part, ast.Subscript):
                    if isinstance(part.value, ast.Name):
                        unsafe.add(part.value.id)
                    else:
                        root = _module_dict_root(part.value)
                        if root:
                            unsafe.add(root)

        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and node.args
            ):
                dotted = _dotted(node.args[0])
                if dotted:
                    unsafe.add(dotted.split(".", 1)[0])
            elif (
                isinstance(node.func, ast.Attribute)
                and _is_globals_call(node.func.value)
                and node.func.attr in {"update", "__setitem__", "pop", "clear"}
            ):
                # Dynamic updates may replace any imported root.
                unknown_global_write = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                "update", "__setitem__", "__delitem__", "setdefault",
                "pop", "popitem", "clear",
            }:
                receiver = node.func.value
                if isinstance(receiver, ast.Name):
                    unsafe.add(receiver.id)
                else:
                    root = _module_dict_root(receiver)
                    if root:
                        unsafe.add(root)

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = list(_module_level_nodes(node))
            declared = {
                name
                for part in body
                if isinstance(part, ast.Global)
                for name in part.names
            }
            writes = {
                name
                for part in body
                for name in _assign_parts(part)[1]
            }
            unsafe.update(declared & writes)

    pending = list(unsafe)
    while pending:
        name = pending.pop()
        for source in aliases.get(name, ()):
            if source not in unsafe:
                unsafe.add(source)
                pending.append(source)
    return unsafe, unknown_global_write


def _attribute_source(
    node: ast.Attribute,
    request_names: set[str],
    import_bindings: dict[str, str | None] | None = None,
) -> str | None:
    dotted = _dotted(node)
    segments = dotted.split(".") if dotted else []
    if segments and import_bindings:
        imported = import_bindings.get(segments[0])
        if imported:
            qualified = ".".join((imported, *segments[1:]))
            # Suppress only a proven import binding, never a same-named local.
            if qualified in {
                "urllib.request",
                "urllib.request.Request",
                "urllib.request.urlopen",
            }:
                return None
    if any(seg in request_names for seg in segments[:-1]):
        return f"request data `{dotted}`"
    if dotted in SOURCE_ATTRS or any(
        dotted.startswith(src + ".") for src in SOURCE_ATTRS
    ):
        return f"`{dotted}`"
    return None


def _call_source(node: ast.Call) -> str | None:
    name = _dotted(node.func)
    if name in SOURCE_CALLS:
        return f"`{name}()`"
    if name.endswith(".parse_args"):
        return f"CLI arguments `{name}()`"
    return None


def _node_sources(
    node: ast.AST,
    origins: dict[str, list[str]],
    request_names: set[str],
    import_bindings: dict[str, str | None] | None = None,
) -> list[str]:
    if isinstance(node, ast.Name):
        return origins.get(node.id, [])
    if isinstance(node, ast.Attribute):
        dotted = _dotted(node)
        root = dotted.split(".", 1)[0] if dotted else ""
        if root in origins and root not in request_names:
            return origins[root]
        label = _attribute_source(node, request_names, import_bindings)
        return [label] if label else []
    if isinstance(node, ast.Call):
        label = _call_source(node)
        return [label] if label else []
    return []


def _direct_sources(
    node: ast.AST,
    origins: dict[str, list[str]],
    request_names: set[str],
    import_bindings: dict[str, str | None] | None = None,
) -> list[str]:
    """Source labels referenced anywhere inside ``node``, in source order."""
    found: list[str] = []
    stack = [node]
    while stack:
        sub = stack.pop()
        labels = _node_sources(sub, origins, request_names, import_bindings)
        if not labels:
            if isinstance(sub, ast.Call):
                # Prefer data arguments over a misleading source-like method name.
                children = [*sub.args, *(k.value for k in sub.keywords), sub.func]
            else:
                children = list(ast.iter_child_nodes(sub))
            stack.extend(reversed(children))
            continue
        for label in labels:
            if label not in found:
                found.append(label)
        if isinstance(sub, ast.Call):
            # input(prompt) / os.getenv(name): arguments may name more sources.
            stack.extend(reversed([*sub.args, *(k.value for k in sub.keywords)]))

    return found


class _FunctionSources:
    """Untrusted names in one function (or the module) and where they came from."""

    def __init__(
        self,
        func: ast.AST | None,
        module: ast.AST | None,
        incoming: dict[str, list[str]] | None = None,
        traversal_incoming: dict[str, list[str]] | None = None,
        import_bindings: dict[str, str | None] | None = None,
    ):
        self.func = func
        self.request_names: set[str] = set(REQUEST_NAMES)
        self.import_bindings = import_bindings or {}
        # name -> human label of the original untrusted source
        self.origins: dict[str, list[str]] = {}
        self.traversal_origins: dict[str, list[str]] = {}
        body: list[ast.AST] = []
        if func is not None:
            decorator = entrypoint_decorator(func)
            fname = getattr(func, "name", "<lambda>")
            for param in _params(func):
                if _annotation_is_request(param.annotation):
                    self.request_names.add(param.arg)
                if decorator and param.arg not in {"self", "cls"}:
                    kind = _entrypoint_kind(decorator)
                    self.origins[param.arg] = [
                        f"{kind} `{param.arg}` of `{fname}` (@{decorator})"
                    ]
                    self.traversal_origins[param.arg] = list(self.origins[param.arg])
            body = list(_module_level_nodes(func))
        elif module is not None:
            body = list(_module_level_nodes(module))
        for name, labels in (incoming or {}).items():
            self._merge_origin(self.origins, name, labels)
        for name, labels in (traversal_incoming or {}).items():
            self._merge_origin(self.traversal_origins, name, labels)
        self._propagate(body)

    @staticmethod
    def _merge_origin(origins: dict[str, list[str]], name: str, labels: list[str]) -> bool:
        if not labels:
            return False
        current = origins.setdefault(name, [])
        fresh = [label for label in labels if label not in current]
        if not fresh:
            return False
        current.extend(fresh)
        return True

    def _propagate(self, body: list[ast.AST]) -> None:
        assigns = [
            parts
            for parts in (_assign_parts(node) for node in body)
            if parts[0] is not None
        ]
        for _ in range(_MAX_PROPAGATION_ROUNDS):
            changed = False
            for parts in assigns:
                changed = self._propagate_one(*parts) or changed
            if not changed:
                break

    def _propagate_one(self, value: ast.AST, targets: list[str]) -> bool:
        labels = _direct_sources(
            value, self.origins, self.request_names, self.import_bindings
        )
        traversal_labels = self.traversal_sources_in(value)
        changed = False
        for name in targets:
            changed = self._merge_origin(self.origins, name, labels) or changed
            changed = (
                self._merge_origin(self.traversal_origins, name, traversal_labels)
                or changed
            )
        return changed

    def sources_in(self, expr: ast.AST) -> list[str]:
        return _direct_sources(
            expr, self.origins, self.request_names, self.import_bindings
        )

    def traversal_sources_in(self, expr: ast.AST) -> list[str]:
        return _direct_sources(
            expr, self.traversal_origins, self.request_names, self.import_bindings
        )

    def direct_sources_in(self, expr: ast.AST) -> list[str]:
        """Sources written directly in an expression, excluding derived names."""
        labels: list[str] = []
        for node in ast.walk(expr):
            if isinstance(node, ast.Attribute):
                label = _attribute_source(
                    node, self.request_names, self.import_bindings
                )
            elif isinstance(node, ast.Call):
                label = _call_source(node)
            else:
                label = None
            if label and label not in labels:
                labels.append(label)
        return labels

    def derived_names_in(self, expr: ast.AST) -> list[str]:
        names = []
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in self.origins:
                if sub.id not in names:
                    names.append(sub.id)
        return names


class UntrustedSourceIndex:
    """Caches per-function source facts for one file."""

    def __init__(
        self, module: ast.AST | None = None, *, follow_local_calls: bool = False
    ):
        self.module = module
        self.follow_local_calls = follow_local_calls
        self._cache: dict[int, _FunctionSources] = {}
        self._calls_indexed = False
        self._parents: dict[int, ast.AST] | None = None
        self._scope_bindings_cache: dict[int, dict[str, str | None]] = {}
        self._import_bindings_cache: dict[int, dict[str, str | None]] = {}
        self._unsafe_import_roots: tuple[set[str], bool] | None = None

    def _import_bindings_for(self, func: ast.AST | None) -> dict[str, str | None]:
        if self.module is None:
            return {}
        key = id(func)
        cached = self._import_bindings_cache.get(key)
        if cached is not None:
            return cached
        scopes = [self.module]
        if func is not None:
            if self._parents is None:
                self._parents = {
                    id(child): parent
                    for parent in ast.walk(self.module)
                    for child in ast.iter_child_nodes(parent)
                }
            chain: list[ast.AST] = []
            current: ast.AST | None = func
            while current is not None and current is not self.module:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    chain.append(current)
                current = self._parents.get(id(current))
            scopes.extend(reversed(chain))
        bindings: dict[str, str | None] = {}
        for scope in scopes:
            scope_bindings = self._scope_bindings_cache.get(id(scope))
            if scope_bindings is None:
                scope_bindings = _scope_bindings(scope)
                self._scope_bindings_cache[id(scope)] = scope_bindings
            bindings.update(scope_bindings)
        if self._unsafe_import_roots is None:
            self._unsafe_import_roots = _unsafe_import_roots(self.module)
        unsafe, unknown_global_write = self._unsafe_import_roots
        for name in bindings:
            if name in unsafe or unknown_global_write:
                bindings[name] = None
        self._import_bindings_cache[key] = bindings
        return bindings

    def resolved_import(self, func: ast.AST | None, name: str) -> str | None:
        """Resolve a dotted name through an unambiguous import binding."""
        root, separator, rest = name.partition(".")
        imported = self._import_bindings_for(func).get(root)
        if imported is None:
            return None
        return f"{imported}.{rest}" if separator else imported

    def _index_local_calls(self) -> None:
        """Carry entry-point sources through direct calls in the same module."""
        if self._calls_indexed or self.module is None or not self.follow_local_calls:
            return
        self._calls_indexed = True
        functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        globals_by_name: dict[str, ast.FunctionDef | ast.AsyncFunctionDef | None] = {}
        methods: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
        owners: dict[int, str | None] = {}
        parents: dict[int, int | None] = {}
        local_defs: dict[int, dict[str, ast.FunctionDef | ast.AsyncFunctionDef | None]] = {}
        local_bindings: dict[int, set[str]] = {}

        def register(func, owner, parent):
            fid = id(func)
            functions.append(func)
            owners[fid] = owner
            parents[fid] = id(parent) if parent is not None else None
            children = list(_immediate_nested_functions(func))
            definitions = {}
            for child in children:
                definitions[child.name] = (
                    child if child.name not in definitions else None
                )
            local_defs[fid] = definitions
            bindings = {arg.arg for arg in _params(func)} | set(definitions)
            for node in _module_level_nodes(func):
                bindings.update(_assign_parts(node)[1])
            local_bindings[fid] = bindings
            for child in children:
                register(child, owner, func)

        for statement in getattr(self.module, "body", []):
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                register(statement, None, None)
                globals_by_name[statement.name] = (
                    statement if statement.name not in globals_by_name else None
                )
            elif isinstance(statement, ast.ClassDef):
                for method in statement.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        register(method, statement.name, None)
                        methods[(statement.name, method.name)] = method

        class CallCollector(ast.NodeVisitor):
            def __init__(self):
                self.calls: list[ast.Call] = []

            def visit_Call(self, node: ast.Call) -> None:
                self.calls.append(node)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                pass

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                pass

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                pass

        def resolve_local(caller_id, name):
            scope_id = caller_id
            while scope_id is not None:
                definitions = local_defs[scope_id]
                if name in definitions:
                    return definitions[name]
                if name in local_bindings[scope_id]:
                    return None
                scope_id = parents[scope_id]
            return globals_by_name.get(name)

        edges: list[tuple[int, int, str, ast.AST]] = []
        direct_calls: set[tuple[int, int]] = set()
        for caller in functions:
            collector = CallCollector()
            for statement in caller.body:
                collector.visit(statement)
            owner = owners[id(caller)]
            for call in collector.calls:
                callee = None
                bound = False
                if isinstance(call.func, ast.Name):
                    callee = resolve_local(id(caller), call.func.id)
                elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                    receiver = call.func.value.id
                    if owner and receiver in {"self", "cls", owner}:
                        callee = methods.get((owner, call.func.attr))
                        bound = receiver in {"self", "cls"}
                if callee is None:
                    continue
                direct_calls.add((id(caller), id(callee)))
                params = _params(callee)
                if bound and params and params[0].arg in {"self", "cls"}:
                    params = params[1:]
                for param, argument in zip(params, call.args):
                    edges.append((id(caller), id(callee), param.arg, argument))
                param_names = {param.arg for param in params}
                for keyword in call.keywords:
                    if keyword.arg in param_names:
                        edges.append((id(caller), id(callee), keyword.arg, keyword.value))

        facts = {
            id(func): _FunctionSources(
                func, None, import_bindings=self._import_bindings_for(func)
            )
            for func in functions
        }
        incoming: dict[int, dict[str, list[str]]] = {id(func): {} for func in functions}
        traversal_incoming: dict[int, dict[str, list[str]]] = {
            id(func): {} for func in functions
        }

        def add_labels(targets, name, labels):
            current = targets.setdefault(name, [])
            fresh = [label for label in labels if label not in current]
            current.extend(fresh)
            return bool(fresh)

        captures = []
        for func in functions:
            fid = id(func)
            parent_id = parents[fid]
            if parent_id is None or (parent_id, fid) not in direct_calls:
                continue
            loaded = {
                node.id
                for node in _module_level_nodes(func)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
            }
            captures.extend(
                (parent_id, fid, name)
                for name in loaded - local_bindings[fid]
            )

        for _ in range(max(1, len(functions) * _MAX_SOURCES)):
            changed: set[int] = set()
            for caller_id, callee_id, param, argument in edges:
                caller_facts = facts[caller_id]
                if add_labels(
                    incoming[callee_id], param, caller_facts.sources_in(argument)
                ):
                    changed.add(callee_id)
                if add_labels(
                    traversal_incoming[callee_id],
                    param,
                    caller_facts.traversal_sources_in(argument),
                ):
                    changed.add(callee_id)
            for parent_id, child_id, name in captures:
                parent_facts = facts[parent_id]
                if add_labels(
                    incoming[child_id], name, parent_facts.origins.get(name, [])
                ):
                    changed.add(child_id)
                if add_labels(
                    traversal_incoming[child_id],
                    name,
                    parent_facts.traversal_origins.get(name, []),
                ):
                    changed.add(child_id)
            if not changed:
                break
            for func in functions:
                if id(func) in changed:
                    fid = id(func)
                    facts[fid] = _FunctionSources(
                        func,
                        None,
                        incoming[fid],
                        traversal_incoming[fid],
                        import_bindings=self._import_bindings_for(func),
                    )
        self._cache.update(facts)

    def for_function(self, func: ast.AST | None) -> _FunctionSources:
        self._index_local_calls()
        key = id(func)
        facts = self._cache.get(key)
        if facts is None:
            facts = _FunctionSources(
                func,
                self.module if func is None else None,
                import_bindings=self._import_bindings_for(func),
            )
            self._cache[key] = facts
        return facts

    def evidence(
        self,
        func: ast.AST | None,
        expr: ast.AST | None,
        *,
        sink: str,
        missing_guard: str,
        evidence_kind: str,
    ) -> dict[str, Any] | None:
        """Return a ``security_evidence`` packet, or None without a real source.

        The packet is deliberately free of file paths and line numbers: review
        decisions hash it into the finding context, so it must stay stable when
        lines shift or the file is analysed from a temporary snapshot. SARIF
        anchors these textual steps at the finding location.
        """
        if expr is None:
            return None
        facts = self.for_function(func)
        labels = facts.sources_in(expr)
        if not labels:
            return None
        labels = labels[:_MAX_SOURCES]
        path = [
            f"untrusted `{name}` from {facts.origins[name][0]}"
            for name in facts.derived_names_in(expr)[:_MAX_SOURCES]
        ]
        if not path:
            path = [f"untrusted input from {labels[0]}"]
        path.append(f"reaches {sink}")
        return {
            "evidence_kind": evidence_kind,
            "source": labels[0],
            "sources": labels,
            "sink": sink,
            "path": path,
            "guards_seen": [],
            "guards_missing": [missing_guard],
            "analysis_complete": False,
        }
