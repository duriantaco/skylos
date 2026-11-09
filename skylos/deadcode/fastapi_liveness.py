"""Source-owned FastAPI application/router registrations; never imports targets."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from skylos.deadcode.framework_liveness import _bound_names, _eager_nodes, _module_name
from skylos.deadcode.python_import_roots import ModuleAliases
from skylos.deadcode.signature_contracts import _merge_c3_mro
from skylos.deadcode.web_framework_liveness import _resolve_from_module


_FACTORY_KINDS = {
    "fastapi.FastAPI": "app",
    "fastapi.applications.FastAPI": "app",
    "fastapi.APIRouter": "router",
    "fastapi.routing.APIRouter": "router",
}
_WILDCARD_PROVIDERS = {
    "fastapi": {
        "FastAPI",
        "APIRouter",
        "Depends",
        "Security",
        "Query",
        "Path",
        "Body",
        "Header",
        "Cookie",
        "Form",
        "File",
    },
    "typing": {"Annotated"},
    "typing_extensions": {"Annotated"},
}
_ROUTE_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "trace",
    "api_route",
    "route",
    "websocket",
    "websocket_route",
}
_IMPERATIVE_ROUTES = {
    "add_api_route",
    "add_route",
    "add_api_websocket_route",
    "add_websocket_route",
}
_HOOK_METHODS = {
    "on_event",
    "middleware",
    "exception_handler",
    "add_event_handler",
    "add_exception_handler",
    "add_middleware",
}
_FOREIGN_FACTORIES = {
    "flask.Flask",
    "flask.Blueprint",
    "starlette.applications.Starlette",
    "starlette.routing.Router",
    "aiohttp.web.Application",
    "sanic.Sanic",
}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
Key = tuple[str, int]
_MAX_ANALYSIS_STEPS = 200_000
_MAX_CALL_EVENTS = 20_000
_MAX_BINDING_ENTRIES = 1_000_000


class FastAPIAnalysisLimit(RuntimeError):
    """The optional proof pass is incomplete; retain legacy analysis hints."""


@dataclass
class FastAPIModule:
    name: str
    path: Path
    tree: ast.Module
    bindings: dict[str, Any] = field(default_factory=dict)
    factory_aliases: dict[str, str] = field(default_factory=dict)
    mentions_fastapi: bool = False
    started: bool = False
    finished: bool = False


@dataclass
class CallableInfo:
    name: str
    node: ast.AST
    module: FastAPIModule
    bindings: dict[str, Any]
    key: Key
    closure: dict[str, Any] = field(default_factory=dict)
    bound: bool = False
    receiver: str | None = None
    invocable: bool = True


@dataclass
class ClassInfo:
    name: str
    node: ast.ClassDef
    module: FastAPIModule
    bindings: dict[str, Any]
    key: Key
    bases: tuple[Any, ...] = ()
    members: dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectInfo:
    key: str
    kind: str
    class_name: str | None
    node: ast.Call
    module: FastAPIModule
    executed: bool
    uncertain: bool = False


@dataclass
class ValueInfo:
    name: str
    node: ast.AST
    module: FastAPIModule
    bindings: dict[str, Any]


@dataclass
class _Returned:
    value: Any


@dataclass
class _Invoked:
    value: Any


@dataclass
class FastAPILivenessReport:
    candidates: set[Key] = field(default_factory=set)
    roots: set[Key] = field(default_factory=set)
    decorator_candidates: set[Key] = field(default_factory=set)
    callback_parameters: set[tuple[str, int, str]] = field(default_factory=set)
    injected_parameters: set[tuple[str, int, str]] = field(default_factory=set)
    uncertain: set[Key] = field(default_factory=set)
    unhandled_decorators: dict[Key, set[str]] = field(default_factory=dict)
    decorator_sites: set[tuple[str, int, int, int]] = field(default_factory=set)
    decorator_nodes: dict[Key, list[ast.AST]] = field(default_factory=dict)
    project: Any = None
    complete: bool = True
    incomplete_reason: str | None = None


class FastAPIProject:
    """A bounded abstract interpreter for source registrations and aliases.

    Values are canonical source/provider names or opaque object/bound-method
    keys. Literal and type-alias assignments are available through ``values``
    and ``resolve_node``. Event environments are snapshots, including events
    found in unexecuted bodies (``executed=False``); only proven actual calls
    supply roots. Sibling protocol proofs consume the same events.
    """

    def __init__(self, definitions, parsed_files, root):
        self.root = Path(root).resolve()
        if self.root.is_file():
            self.root = self.root.parent
        self.definitions = {
            (str(Path(d.filename).resolve()), int(d.line)): d
            for d in definitions.values()
            if getattr(d, "type", None) in {"function", "method", "class"}
        }
        self.modules = {}
        for parsed in parsed_files:
            path = Path(parsed.path).resolve()
            try:
                path.relative_to(self.root)
            except ValueError:
                continue
            name = _module_name(path, self.root)
            self.modules[name] = FastAPIModule(name, path, parsed.tree)
        self.module_aliases = ModuleAliases(self.root, self.modules)
        self.functions: dict[str, CallableInfo] = {}
        self.classes: dict[str, ClassInfo] = {}
        self.objects: dict[str, ObjectInfo] = {}
        self.values: dict[str, ValueInfo] = {}
        self.assignments = self.values
        self.calls = []
        self.decorators = []
        self.constructors = []
        self.registrations = []
        self.includes = defaultdict(set)
        self.possible_includes = []
        self.active_objects = set()
        self.executed_callables = set()
        self.executed_keys = self.executed_callables
        self.bound_methods = {}
        self._bound_cache = {}
        self.decorator_values = {}
        self.attribute_values = {}
        self.shadowed = {name.split(".")[0] for name in self.modules}
        self._dry_scanned = set()
        self._invoking = set()
        self._object_sequence = 0
        self._bound_sequence = 0
        self._decorator_sequence = 0
        self.steps = 0
        self.binding_entries = 0
        self.report = FastAPILivenessReport(project=self)

    def incomplete(self, reason):
        self.report.complete = False
        self.report.incomplete_reason = reason
        self.report.roots.clear()
        self.report.callback_parameters.clear()
        self.report.injected_parameters.clear()
        return self.report

    def _limit(self, reason):
        self.incomplete(reason)
        raise FastAPIAnalysisLimit(reason)

    def _step(self):
        self.steps += 1
        if self.steps > _MAX_ANALYSIS_STEPS:
            self._limit("abstract_step_budget")

    def _snapshot(self, bindings):
        self._step()
        self.binding_entries += len(bindings)
        if self.binding_entries > _MAX_BINDING_ENTRIES:
            self._limit("binding_snapshot_budget")
        return dict(bindings)

    def _module(self, module):
        if isinstance(module, str):
            return self.modules.get(module)
        return module

    def module_named(self, name, importer=None):
        importer = self._module(importer)
        found, blocked = self.module_aliases.scoped(name, importer)
        if blocked:
            return None
        if found is None:
            found = self.modules.get(name)
        if found is None:
            found = self.module_aliases.lookup(name, importer)
        return found

    def resolve(self, expression, bindings, module=None):
        self._step()
        module = self._module(module)
        if isinstance(expression, ast.Name):
            if expression.id in bindings:
                return bindings[expression.id]
            if module is not None:
                return module.bindings.get(expression.id)
            return None
        if isinstance(expression, ast.Attribute):
            owner = self.resolve(expression.value, bindings, module)
            if not isinstance(owner, str):
                return None
            if owner in self.objects:
                override = owner + "." + expression.attr
                if override in self.attribute_values:
                    return self.attribute_values[override]
                obj = self.objects[owner]
                member = self._class_member(obj.class_name, expression.attr)
                if member is not None:
                    role = self._method_role(member)
                    if role == "static":
                        return member
                    if role == "class":
                        return self._bound(
                            obj.class_name, expression.attr, member, False
                        )
                    return self._bound(owner, expression.attr, member, False)
                return self._bound(
                    owner,
                    expression.attr,
                    None,
                    self.method_available(owner, expression.attr),
                )
            source = self.module_named(owner, module)
            if source is not None:
                self.collect_module(source)
                if expression.attr in source.bindings:
                    return source.bindings[expression.attr]
                child = self.module_named(source.name + "." + expression.attr, module)
                if child is not None:
                    self.collect_module(child)
                    return child.name
            qualified = owner + "." + expression.attr
            if qualified in self.attribute_values:
                return self.attribute_values[qualified]
            if owner in self.classes:
                member = self._class_member(owner, expression.attr)
                if self._method_role(member) == "class":
                    return self._bound(owner, expression.attr, member, False)
                return member
            return qualified
        return None

    def resolve_node(self, node, bindings, module=None):
        module = self._module(module)
        seen = set()
        while isinstance(node, (ast.Name, ast.Attribute)):
            value = self.resolve(node, bindings, module)
            if not isinstance(value, str) or value not in self.values or value in seen:
                break
            seen.add(value)
            info = self.values[value]
            node, bindings, module = info.node, info.bindings, info.module
        return node, bindings, module

    def callable(self, value):
        if not isinstance(value, str):
            return None
        if value in self.bound_methods:
            bound = self.bound_methods[value]
            info = self.functions.get(bound.target)
            if info is not None:
                return replace(info, bound=True, receiver=bound.receiver)
            return None
        if value in self.objects:
            obj = self.objects[value]
            target = self._class_member(obj.class_name, "__call__")
            info = self.functions.get(target)
            if info is not None:
                return replace(info, bound=True, receiver=value)
            return None
        if value in self.classes:
            target = self._class_member(value, "__init__")
            info = self.functions.get(target)
            if info is not None:
                return replace(info, bound=True, receiver=value)
            return None
        return self.functions.get(value)

    def is_bound(self, value):
        info = self.callable(value)
        return info is not None and info.bound

    def _bound(self, receiver, method, target, proven):
        identity = receiver, method, target, proven
        existing = self._bound_cache.get(identity)
        if existing is not None:
            return existing
        self._bound_sequence += 1
        key = f"@fastapi-bound:{self._bound_sequence}"
        self.bound_methods[key] = SimpleNamespace(
            receiver=receiver, method=method, target=target, proven=proven
        )
        self._bound_cache[identity] = key
        return key

    def _mro(self, name, trail=()):
        self._step()
        if name in trail:
            return None
        if len(trail) >= 32:
            self._limit("inheritance_depth")
        if name not in self.classes:
            return [name] if isinstance(name, str) else None
        info = self.classes[name]
        bases = info.bases or ("builtins.object",)
        sequences = []
        for base in bases:
            inherited = self._mro(base, (*trail, name))
            if inherited is None:
                return None
            sequences.append(list(inherited))
        sequences.append(list(bases))
        merged = _merge_c3_mro(sequences)
        return [name, *merged] if merged is not None else None

    def _class_member(self, name, member):
        for owner in self._mro(name) or ():
            key = str(owner) + "." + member
            if key in self.attribute_values:
                return self.attribute_values[key]
            info = self.classes.get(owner)
            if info is not None and member in info.members:
                return info.members[member]
        return None

    def _method_role(self, name):
        info = self.functions.get(name)
        if info is None:
            return None
        for decorator in info.node.decorator_list:
            target = self.resolve(decorator, info.bindings, info.module)
            if target == "builtins.staticmethod" or (
                isinstance(decorator, ast.Name)
                and decorator.id == "staticmethod"
                and decorator.id not in info.bindings
            ):
                return "static"
            if target == "builtins.classmethod" or (
                isinstance(decorator, ast.Name)
                and decorator.id == "classmethod"
                and decorator.id not in info.bindings
            ):
                return "class"
        return None

    def _factory_kind(self, name):
        if "fastapi" in self.shadowed:
            return None
        for owner in self._mro(name) or ():
            if owner in _FACTORY_KINDS:
                return _FACTORY_KINDS[owner]
        return None

    def method_available(self, object_key, method):
        obj = self.objects.get(object_key)
        if obj is None or obj.kind not in {"app", "router"}:
            return False
        if object_key + "." + method in self.attribute_values:
            return False
        for owner in self._mro(obj.class_name) or ():
            if str(owner) + "." + method in self.attribute_values:
                return False
            info = self.classes.get(owner)
            if info is not None and method in info.members:
                return False
            if owner in _FACTORY_KINDS:
                return True
        return False

    def _candidate_receiver(self, receiver, module):
        obj = self.objects.get(receiver)
        if obj is not None:
            return obj.kind != "foreign" and (
                obj.kind in {"app", "router", "unknown"} or module.mentions_fastapi
            )
        return module.mentions_fastapi and receiver is None

    def collect_module(self, module):
        if module.started:
            return
        module.started = True
        self._suite(module.tree.body, module.bindings, module, True, None)
        module.finished = True

    def _imports(self, statement, bindings, module):
        package = (
            module.name
            if module.path.name == "__init__.py"
            else module.name.rpartition(".")[0]
        )
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                source = alias.name
                if source.split(".")[0] == "fastapi":
                    module.mentions_fastapi = True
                imported = self.module_named(source, module)
                if imported is not None:
                    self.collect_module(imported)
                if alias.asname and imported is not None:
                    bindings[alias.asname] = imported.name
                elif alias.asname:
                    bindings[alias.asname] = source
                else:
                    bindings[source.split(".")[0]] = source.split(".")[0]
            return
        source = _resolve_from_module(statement, package)
        if not source:
            return
        if source.split(".")[0] == "fastapi":
            module.mentions_fastapi = True
        imported = self.module_named(source, module)
        if imported is not None:
            self.collect_module(imported)
        imported_name = source
        if imported is not None:
            imported_name = imported.name
        for alias in statement.names:
            if alias.name == "*":
                if imported is not None:
                    bindings.update(
                        {
                            k: v
                            for k, v in imported.bindings.items()
                            if not k.startswith("_")
                        }
                    )
                elif (
                    source in _WILDCARD_PROVIDERS
                    and source.split(".", 1)[0] not in self.shadowed
                ):
                    for name in _WILDCARD_PROVIDERS[source]:
                        provider = source + "." + name
                        bindings[name] = provider
                        if provider in _FACTORY_KINDS:
                            module.factory_aliases[name] = _FACTORY_KINDS[provider]
                continue
            name = alias.asname or alias.name
            qualified = imported_name + "." + alias.name
            child = self.module_named(qualified, module)
            if imported is not None and alias.name in imported.bindings:
                value = imported.bindings[alias.name]
            elif child is not None:
                self.collect_module(child)
                value = child.name
            else:
                value = self.attribute_values.get(qualified, qualified)
            bindings[name] = value
            kind = self._factory_kind(value)
            if kind:
                module.factory_aliases[name] = kind
            if value in self.objects and self.objects[value].kind in {"app", "router"}:
                module.mentions_fastapi = True

    def _function(
        self, node, bindings, module, executed, owner, uncertain, class_info=None
    ):
        path = str(module.path)
        key = path, node.lineno
        definition = self.definitions.get(key)
        name = (
            getattr(definition, "name", None)
            or (owner or module.name) + "." + node.name
        )
        captured = self._snapshot(bindings)
        info = CallableInfo(name, node, module, captured, key)
        if owner is not None and class_info is None:
            info.closure = captured
        self.functions[name] = info
        bindings[node.name] = name
        if class_info is not None:
            class_info.members[node.name] = name
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._eval(default, captured, module, executed, owner, uncertain)
        transparencies = []
        pending = []
        for index, decorator in enumerate(node.decorator_list):
            value = self._eval(decorator, captured, module, executed, owner, uncertain)
            record = self.decorator_values.get(value)
            if record is None:
                target = self.resolve(
                    decorator.func if isinstance(decorator, ast.Call) else decorator,
                    captured,
                    module,
                )
                bound = self.bound_methods.get(target)
                if bound is not None and bound.method in _ROUTE_METHODS | _HOOK_METHODS:
                    record = SimpleNamespace(
                        node=decorator,
                        module=module,
                        bindings=self._snapshot(captured),
                        receiver=bound.receiver,
                        method=bound.method,
                        target=target,
                        proven=bound.proven,
                    )
            if record is not None:
                event = SimpleNamespace(
                    **vars(record),
                    callback=info,
                    executed=executed,
                    owner=owner,
                    uncertain=uncertain,
                    source_decorator=decorator,
                )
                self.decorators.append(event)
                transparent = record.proven and record.method in _ROUTE_METHODS | {
                    "middleware",
                    "exception_handler",
                    "on_event",
                }
                if (
                    self._candidate_receiver(event.receiver, module)
                    and event.method in _ROUTE_METHODS
                ):
                    self.report.candidates.add(key)
                    self.report.decorator_candidates.add(key)
                    self.report.decorator_sites.add(
                        (*key, decorator.lineno, decorator.col_offset)
                    )
                    self.report.decorator_nodes.setdefault(key, []).append(decorator)
                    registration = SimpleNamespace(
                        callback=info,
                        object_key=event.receiver,
                        node=event.node,
                        module=module,
                        bindings=event.bindings,
                        executed=executed,
                        proven=event.proven,
                        uncertain=uncertain or (executed and event.receiver is None),
                        owner=owner,
                        owner_key=self.functions[owner].key
                        if owner in self.functions
                        else None,
                    )
                    self.registrations.append(registration)
                    pending.append((index, registration))
            else:
                plain = decorator.func if isinstance(decorator, ast.Call) else decorator
                target = self.resolve(plain, captured, module)
                transparent = target in {
                    "builtins.staticmethod",
                    "builtins.classmethod",
                } or (
                    isinstance(plain, ast.Name)
                    and plain.id in {"staticmethod", "classmethod"}
                    and plain.id not in captured
                )
                self.report.unhandled_decorators.setdefault(key, set()).add(
                    ast.unparse(decorator)
                )
            transparencies.append(bool(transparent))
        info.invocable = all(transparencies)
        for index, registration in pending:
            registration.callback = replace(
                info, invocable=all(transparencies[index + 1 :])
            )
        if key not in self._dry_scanned:
            self._dry_scanned.add(key)
            local = self._snapshot(captured)
            for item in node.body:
                for bound_name in _bound_names(item):
                    local[bound_name] = None
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ):
                local[argument.arg] = None
            self._suite(node.body, local, module, False, name, uncertain)
        return name

    def _class(self, node, bindings, module, executed, owner, uncertain):
        key = str(module.path), node.lineno
        definition = self.definitions.get(key)
        name = (
            getattr(definition, "name", None)
            or (owner or module.name) + "." + node.name
        )
        info = ClassInfo(
            name,
            node,
            module,
            dict(bindings),
            key,
            tuple(self.resolve(base, bindings, module) for base in node.bases),
        )
        self.classes[name] = info
        local = self._snapshot(bindings)
        for member in node.body:
            if isinstance(member, _FUNCTIONS):
                self._function(
                    member, local, module, executed, name, uncertain, class_info=info
                )
            elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                self._assignment(member, local, module, executed, name, uncertain)
                for bound_name in _bound_names(member):
                    info.members[bound_name] = local.get(bound_name)
        bindings[node.name] = name
        if node.name in {"FastAPI", "APIRouter"}:
            module.mentions_fastapi = True
            module.factory_aliases.setdefault(
                node.name, "app" if node.name == "FastAPI" else "router"
            )
        return name

    def _assignment(self, statement, bindings, module, executed, owner, uncertain):
        if isinstance(statement, ast.AnnAssign) and statement.value is None:
            return
        value = self._eval(
            statement.value, bindings, module, executed, owner, uncertain
        )
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        captured = self._snapshot(bindings)
        for target in targets:
            if isinstance(target, ast.Name):
                canonical = (owner or module.name) + "." + target.id
                self.values[canonical] = ValueInfo(
                    canonical, statement.value, module, captured
                )
                bindings[target.id] = value if value is not None else canonical
                kind = self._factory_kind(value)
                if kind:
                    module.factory_aliases.setdefault(target.id, kind)
            elif isinstance(target, ast.Attribute) and executed:
                receiver = self.resolve(target.value, bindings, module)
                if isinstance(receiver, str):
                    self.attribute_values[receiver + "." + target.attr] = value
            elif isinstance(target, (ast.Tuple, ast.List)):
                for name in _bound_names(target):
                    bindings[name] = None

    def _suite(self, statements, bindings, module, executed, owner, uncertain=False):
        for statement in statements:
            self._step()
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._imports(statement, bindings, module)
            elif isinstance(statement, _FUNCTIONS):
                self._function(statement, bindings, module, executed, owner, uncertain)
            elif isinstance(statement, ast.ClassDef):
                self._class(statement, bindings, module, executed, owner, uncertain)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                self._assignment(
                    statement, bindings, module, executed, owner, uncertain
                )
            elif isinstance(statement, ast.Expr):
                self._eval(
                    statement.value, bindings, module, executed, owner, uncertain
                )
            elif isinstance(statement, ast.Return):
                return _Returned(
                    self._eval(
                        statement.value, bindings, module, executed, owner, uncertain
                    )
                )
            elif isinstance(statement, ast.Raise):
                return _Returned(None)
            elif isinstance(statement, ast.If):
                if isinstance(statement.test, ast.Constant):
                    body, other = (
                        (statement.body, statement.orelse)
                        if statement.test.value
                        else (statement.orelse, statement.body)
                    )
                    self._suite(other, dict(bindings), module, False, owner)
                    value = self._suite(
                        body, bindings, module, executed, owner, uncertain
                    )
                    if isinstance(value, _Returned):
                        return value
                elif (
                    owner is None
                    and isinstance(statement.test, ast.Compare)
                    and isinstance(statement.test.left, ast.Name)
                    and statement.test.left.id == "__name__"
                ):
                    self._suite(
                        statement.body, bindings, module, executed, owner, uncertain
                    )
                else:
                    left, right = dict(bindings), dict(bindings)
                    self._suite(statement.body, left, module, False, owner, True)
                    self._suite(statement.orelse, right, module, False, owner, True)
                    for name in left.keys() | right.keys():
                        bindings[name] = (
                            left.get(name)
                            if left.get(name) == right.get(name)
                            else None
                        )
            elif isinstance(statement, ast.Delete):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id] = None
                    elif isinstance(target, ast.Attribute) and executed:
                        receiver = self.resolve(target.value, bindings, module)
                        if isinstance(receiver, str):
                            self.attribute_values[receiver + "." + target.attr] = None
            elif isinstance(
                statement,
                (
                    ast.With,
                    ast.AsyncWith,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.TryStar,
                ),
            ):
                self._suite(
                    getattr(statement, "body", ()),
                    dict(bindings),
                    module,
                    False,
                    owner,
                    True,
                )
                self._suite(
                    getattr(statement, "orelse", ()),
                    dict(bindings),
                    module,
                    False,
                    owner,
                    True,
                )
                self._suite(
                    getattr(statement, "finalbody", ()),
                    dict(bindings),
                    module,
                    False,
                    owner,
                    True,
                )
                for handler in getattr(statement, "handlers", ()):
                    self._suite(
                        handler.body, dict(bindings), module, False, owner, True
                    )
        return None

    def _invoke(self, value, call, bindings, module, executed, owner, uncertain):
        self._step()
        info = self.callable(value)
        if info is None or not info.invocable or not executed:
            return None
        node = info.node
        suspended = isinstance(node, ast.AsyncFunctionDef) or any(
            isinstance(item, (ast.Yield, ast.YieldFrom))
            for child in node.body
            for item in _eager_nodes(child)
        )
        if suspended:
            self.report.uncertain.add(info.key)
            return None
        if info.name in self._invoking or len(self._invoking) >= 32:
            self._limit("recursive_wrapper_or_call_depth")
        local = self._snapshot(info.module.bindings)
        local.update(info.closure)
        global_names = {
            name
            for child in node.body
            for item in _eager_nodes(child)
            if isinstance(item, ast.Global)
            for name in item.names
        }
        for child in node.body:
            for name in _bound_names(child) - global_names:
                local[name] = None
        args = [
            self._eval(item, bindings, module, executed, owner, uncertain)
            for item in call.args
        ]
        if info.bound:
            args.insert(0, info.receiver)
        keywords = {
            keyword.arg: self._eval(
                keyword.value, bindings, module, executed, owner, uncertain
            )
            for keyword in call.keywords
            if keyword.arg is not None
        }
        positional = [*node.args.posonlyargs, *node.args.args]
        required = len(positional) - len(node.args.defaults)
        if len(args) > len(positional) and node.args.vararg is None:
            return None
        for index, argument in enumerate(positional):
            if index < len(args):
                local[argument.arg] = args[index]
            elif argument.arg in keywords:
                local[argument.arg] = keywords.pop(argument.arg)
            elif index >= required:
                local[argument.arg] = self.resolve(
                    node.args.defaults[index - required], info.bindings, info.module
                )
            else:
                return None
        for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if argument.arg in keywords:
                local[argument.arg] = keywords.pop(argument.arg)
            elif default is not None:
                local[argument.arg] = self.resolve(default, info.bindings, info.module)
            else:
                return None
        if keywords and node.args.kwarg is None:
            return None
        self._invoking.add(info.name)
        self.executed_callables.add(info.key)
        try:
            result = self._suite(
                node.body, local, info.module, True, info.name, uncertain
            )
            for name in global_names:
                info.module.bindings[name] = local.get(name)
            return _Invoked(result.value if isinstance(result, _Returned) else result)
        finally:
            self._invoking.remove(info.name)

    def _eval(self, expression, bindings, module, executed, owner, uncertain):
        self._step()
        if expression is None:
            return None
        if isinstance(expression, (ast.Name, ast.Attribute)):
            return self.resolve(expression, bindings, module)
        if isinstance(expression, ast.Lambda):
            local = self._snapshot(bindings)
            for argument in (
                *expression.args.posonlyargs,
                *expression.args.args,
                *expression.args.kwonlyargs,
            ):
                local[argument.arg] = None
            self._eval(expression.body, local, module, False, owner, True)
            return None
        if isinstance(
            expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            local = self._snapshot(bindings)
            for generator in expression.generators:
                for name in _bound_names(generator.target):
                    local[name] = None
            for item in ast.iter_child_nodes(expression):
                self._eval(item, local, module, False, owner, True)
            return None
        if isinstance(expression, ast.BoolOp):
            result = None
            continuing = executed
            possible = uncertain
            stopped = False
            for value in expression.values:
                result = self._eval(
                    value, bindings, module, continuing, owner, possible
                )
                truth = self._truth(value, bindings, module)
                stops = (
                    truth is False
                    if isinstance(expression.op, ast.And)
                    else truth is True
                )
                if stops:
                    continuing = False
                    possible = False
                    stopped = True
                elif truth is None and not stopped:
                    continuing = False
                    possible = True
            return result
        if isinstance(expression, ast.IfExp):
            self._eval(expression.test, bindings, module, executed, owner, uncertain)
            truth = self._truth(expression.test, bindings, module)
            if truth is None:
                self._eval(expression.body, bindings, module, False, owner, True)
                self._eval(expression.orelse, bindings, module, False, owner, True)
                return None
            chosen, other = (
                (expression.body, expression.orelse)
                if truth
                else (expression.orelse, expression.body)
            )
            self._eval(other, bindings, module, False, owner, False)
            return self._eval(chosen, bindings, module, executed, owner, uncertain)
        if not isinstance(expression, ast.Call):
            for child in ast.iter_child_nodes(expression):
                if not isinstance(
                    child,
                    (
                        ast.expr_context,
                        ast.operator,
                        ast.unaryop,
                        ast.cmpop,
                        ast.boolop,
                    ),
                ):
                    self._eval(child, bindings, module, executed, owner, uncertain)
            return None
        if isinstance(expression.func, ast.Lambda):
            function = expression.func
            if not (
                function.args.posonlyargs
                or function.args.args
                or function.args.kwonlyargs
                or function.args.vararg
                or function.args.kwarg
                or expression.args
                or expression.keywords
            ):
                return self._eval(
                    function.body, bindings, module, executed, owner, uncertain
                )
            self._eval(function.body, bindings, module, False, owner, True)
            return None
        target = self.resolve(expression.func, bindings, module)
        bound = self.bound_methods.get(target)
        receiver = (
            bound.receiver
            if bound is not None
            else (
                self.resolve(expression.func.value, bindings, module)
                if isinstance(expression.func, ast.Attribute)
                else None
            )
        )
        method = (
            bound.method
            if bound is not None
            else (
                expression.func.attr
                if isinstance(expression.func, ast.Attribute)
                else None
            )
        )
        proven = bool(bound and bound.proven)
        event = SimpleNamespace(
            node=expression,
            module=module,
            bindings=self._snapshot(bindings),
            receiver=receiver,
            method=method,
            target=target,
            executed=executed,
            owner=owner,
            uncertain=uncertain,
            proven=proven,
        )
        if len(self.calls) >= _MAX_CALL_EVENTS:
            self._limit("call_event_budget")
        self.calls.append(event)
        kind = self._factory_kind(target)
        syntactic_kind = None
        if isinstance(expression.func, ast.Name):
            syntactic_kind = module.factory_aliases.get(expression.func.id)
        elif (
            isinstance(expression.func, ast.Attribute)
            and expression.func.attr in {"FastAPI", "APIRouter"}
            and module.mentions_fastapi
        ):
            syntactic_kind = "app" if expression.func.attr == "FastAPI" else "router"
        if (
            kind
            or target in self.classes
            or target in _FOREIGN_FACTORIES
            or syntactic_kind
        ):
            self._object_sequence += 1
            key = f"@fastapi-object:{self._object_sequence}"
            object_kind = kind or (
                "foreign" if target in _FOREIGN_FACTORIES else "instance"
            )
            obj = ObjectInfo(
                key, object_kind, target, expression, module, executed, uncertain
            )
            self.objects[key] = obj
            if kind:
                module.mentions_fastapi = True
            if kind or syntactic_kind:
                self.constructors.append(
                    SimpleNamespace(
                        node=expression,
                        module=module,
                        bindings=self._snapshot(bindings),
                        object_key=key if kind else None,
                        kind=kind or syntactic_kind,
                        executed=executed,
                        owner=owner,
                        uncertain=uncertain,
                        proven=bool(kind),
                    )
                )
            if kind == "app" and executed:
                self.active_objects.add(key)
            if target in self.classes:
                init = self._class_member(target, "__init__")
                if init is not None:
                    self._invoke(
                        self._bound(key, "__init__", init, False),
                        expression,
                        bindings,
                        module,
                        executed,
                        owner,
                        uncertain,
                    )
            else:
                for argument in expression.args:
                    self._eval(argument, bindings, module, executed, owner, uncertain)
                for keyword in expression.keywords:
                    self._eval(
                        keyword.value, bindings, module, executed, owner, uncertain
                    )
            return key
        if method in _ROUTE_METHODS | _HOOK_METHODS and self._candidate_receiver(
            receiver, module
        ):
            self._decorator_sequence += 1
            value = f"@fastapi-decorator:{self._decorator_sequence}"
            self.decorator_values[value] = SimpleNamespace(
                node=expression,
                module=module,
                bindings=self._snapshot(bindings),
                receiver=receiver,
                method=method,
                target=target,
                proven=proven,
            )
            if bound is not None and bound.target is not None:
                self._invoke(
                    target, expression, bindings, module, executed, owner, uncertain
                )
            return value
        if method in _IMPERATIVE_ROUTES and self._candidate_receiver(receiver, module):
            callback_node = next(
                (kw.value for kw in expression.keywords if kw.arg == "endpoint"), None
            )
            if callback_node is None and len(expression.args) >= 2:
                callback_node = expression.args[1]
            info = self.callable(self.resolve(callback_node, bindings, module))
            if info is not None:
                self.report.candidates.add(info.key)
                self.registrations.append(
                    SimpleNamespace(
                        callback=info,
                        object_key=receiver,
                        node=expression,
                        module=module,
                        bindings=self._snapshot(bindings),
                        executed=executed,
                        proven=proven,
                        uncertain=uncertain or (executed and receiver is None),
                        owner=owner,
                        owner_key=self.functions[owner].key
                        if owner in self.functions
                        else None,
                    )
                )
        if proven and executed and method in {"include_router", "mount"}:
            position = 0 if method == "include_router" else 1
            keyword_name = "router" if method == "include_router" else "app"
            child_node = next(
                (kw.value for kw in expression.keywords if kw.arg == keyword_name), None
            )
            if child_node is None and len(expression.args) > position:
                child_node = expression.args[position]
            child = self._eval(child_node, bindings, module, executed, owner, uncertain)
            if child in self.objects:
                self.includes[receiver].add(child)
            elif method == "mount":
                info = self.callable(child)
                if info is not None:
                    self.report.candidates.add(info.key)
                    self.registrations.append(
                        SimpleNamespace(
                            callback=info,
                            object_key=receiver,
                            node=expression,
                            module=module,
                            bindings=self._snapshot(bindings),
                            executed=True,
                            proven=True,
                            uncertain=uncertain,
                            owner=owner,
                            owner_key=self.functions[owner].key
                            if owner in self.functions
                            else None,
                        )
                    )
        elif proven and uncertain and method in {"include_router", "mount"}:
            position, keyword_name = 0, "router"
            if method == "mount":
                position, keyword_name = 1, "app"
            child_node = next(
                (kw.value for kw in expression.keywords if kw.arg == keyword_name), None
            )
            if child_node is None and len(expression.args) > position:
                child_node = expression.args[position]
            child = self._eval(child_node, bindings, module, executed, owner, uncertain)
            owner_key = None
            if owner in self.functions:
                owner_key = self.functions[owner].key
            if child in self.objects:
                self.possible_includes.append(
                    SimpleNamespace(
                        receiver=receiver,
                        child=child,
                        owner=owner,
                        owner_key=owner_key,
                    )
                )
        if (
            isinstance(expression.func, ast.Name)
            and expression.func.id in {"setattr", "delattr"}
            and expression.func.id not in bindings
        ) or target in {"builtins.setattr", "builtins.delattr"}:
            if (
                executed
                and len(expression.args) >= 2
                and isinstance(expression.args[1], ast.Constant)
                and isinstance(expression.args[1].value, str)
            ):
                changed = self.resolve(expression.args[0], bindings, module)
                if isinstance(changed, str):
                    self.attribute_values[changed + "." + expression.args[1].value] = (
                        self.resolve(expression.args[2], bindings, module)
                        if len(expression.args) >= 3
                        else None
                    )
        result = self._invoke(
            target, expression, bindings, module, executed, owner, uncertain
        )
        if isinstance(result, _Invoked):
            return result.value
        for argument in expression.args:
            self._eval(argument, bindings, module, executed, owner, uncertain)
        for keyword in expression.keywords:
            self._eval(keyword.value, bindings, module, executed, owner, uncertain)
        return None

    def _truth(self, expression, bindings, module):
        seen = set()
        inverted = False
        while True:
            self._step()
            node, local, source = self.resolve_node(expression, bindings, module)
            state = id(node), id(local), id(source)
            # A rebound alias can revisit its captured expression; keep it unknown.
            if state in seen:
                return None
            seen.add(state)
            if isinstance(node, ast.Constant):
                result = bool(node.value)
                return not result if inverted else result
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                inverted = not inverted
                expression, bindings, module = node.operand, local, source
                continue
            return None

    def _possibly_included(self):
        """Objects an include under an unknown condition may attach."""
        if not self.possible_includes:
            return set()
        conditional = defaultdict(set)
        for include in self.possible_includes:
            self._step()
            if (
                include.owner is None
                or include.owner_key in self.executed_callables
                or include.owner_key in self.report.roots
            ):
                conditional[include.receiver].add(include.child)
        possible = set()
        visited = set()
        pending = list(self.active_objects)
        while pending:
            self._step()
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            children = conditional.get(current, set()) | self.includes.get(current, set())
            for child in children:
                self._step()
                if child in self.active_objects or child in possible:
                    continue
                possible.add(child)
                pending.append(child)
        return possible

    def collect(self):
        for module in self.modules.values():
            self.collect_module(module)
        pending = list(self.active_objects)
        while pending:
            for child in self.includes.get(pending.pop(), ()):
                if child not in self.active_objects:
                    self.active_objects.add(child)
                    pending.append(child)
        has_app = any(
            obj.kind == "app" and obj.executed for obj in self.objects.values()
        )
        for record in self.registrations:
            info = record.callback
            self.report.candidates.add(info.key)
            if (
                record.executed
                and record.proven
                and record.object_key in self.active_objects
                and info.invocable
            ):
                self.report.roots.add(info.key)
        possible = self._possibly_included()
        for record in self.registrations:
            info = record.callback
            possible_owner = (
                record.owner is None
                or record.executed
                or record.owner_key in self.executed_callables
                or record.owner_key in self.report.roots
            )
            transformed = record.executed and record.proven and not info.invocable
            if possible_owner and (
                record.uncertain
                or transformed
                or (record.executed and record.proven and record.object_key in possible)
                or (
                    not has_app
                    and record.executed
                    and self.objects.get(record.object_key) is not None
                    and self.objects[record.object_key].kind == "router"
                )
            ):
                self.report.uncertain.add(info.key)
        return self.report


def collect_fastapi_liveness(definitions, parsed_files, root):
    project = FastAPIProject(definitions, parsed_files, root)
    try:
        return project.collect()
    except FastAPIAnalysisLimit:
        return project.report
