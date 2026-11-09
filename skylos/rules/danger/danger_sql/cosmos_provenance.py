"""Bounded source-owned Cosmos SDK receiver factories, without SDK imports."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from skylos.security.receiver_resolution import ReceiverResolver

from pathlib import Path

from ..project_source import project_source_snapshot
from ..untrusted_sources import UntrustedSourceIndex
from ..module_namespace import attribute_write_names, module_name_for, module_rebinding

_MODULES = {"azure", "azure.cosmos", "azure.cosmos.aio"}
_TYPES = {"CosmosClient", "DatabaseProxy", "ContainerProxy"}
_CONTRACT_NAMES = _TYPES | {
    "from_connection_string",
    "get_database_client",
    "get_container_client",
    "query_items",
}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_MAGIC = {"__getattribute__", "__getattr__", "__setattr__", "__delattr__"}

_snapshot_cache = {}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join(reversed([*parts, node.id]))


def _snapshot_providers_stable(trees, root):
    key = str(root)
    cached = _snapshot_cache.get(key)
    if cached is not None and cached[0] is trees:
        return cached[1]
    result = True
    for path, tree in trees.items():
        relative = path.relative_to(root)
        if path.stem == "azure" or "azure" in relative.parts[:-1]:
            result = False
            break
        if not _module_providers_stable(tree, path):
            result = False
            break
    if len(_snapshot_cache) >= 16:
        _snapshot_cache.pop(next(iter(_snapshot_cache)))
    _snapshot_cache[key] = (trees, result)
    return result


def _module_providers_stable(tree, path):
    dynamic, rebound = module_rebinding(tree, module_name_for(path))
    writes, computed = attribute_write_names(tree)
    contracts = _CONTRACT_NAMES | {"ABC"}
    if contracts.intersection(writes | rebound):
        return False
    imports = UntrustedSourceIndex(tree)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    capabilities = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(("azure.cosmos", "abc")):
                    capabilities.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "azure.cosmos",
            "azure.cosmos.aio",
            "abc",
        }:
            capabilities.update(alias.asname or alias.name for alias in node.names)
    if capabilities and (dynamic or computed):
        return False
    changed = True
    alias_rounds = 0
    while changed:
        alias_rounds += 1
        if alias_rounds > 24:
            return False
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = node.value
                while isinstance(value, ast.Attribute):
                    value = value.value
                if isinstance(value, ast.Name) and value.id in capabilities:
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in capabilities
                        ):
                            capabilities.add(target.id)
                            changed = True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = parents.get(node)
        while scope is not None and not isinstance(scope, _FUNCTIONS):
            scope = parents.get(scope)
        name = _dotted(node.func)
        provider = imports.resolved_import(scope, name) if name else None
        leaf = name.rsplit(".", 1)[-1] if name else None
        if leaf in {"setattr", "delattr", "__setattr__", "__delattr__"} or provider in {
            "builtins.setattr",
            "builtins.delattr",
        }:
            attribute = node.args[1] if len(node.args) > 1 else None
            if isinstance(attribute, ast.Constant) and attribute.value in contracts:
                return False
            if not isinstance(attribute, ast.Constant):
                if (
                    capabilities
                    or provider in {"builtins.setattr", "builtins.delattr"}
                    or isinstance(node.func, ast.Name)
                    or leaf.startswith("__")
                ):
                    return False
                target = node.args[0] if node.args else None
                if (
                    isinstance(target, ast.Constant)
                    and isinstance(target.value, str)
                    and target.value.rsplit(".", 1)[-1] in contracts
                ):
                    return False
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
            root = argument
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in capabilities:
                return False
    return True


@dataclass(eq=False)
class _Scope:
    node: ast.AST
    parent: _Scope | None
    kind: str
    bindings: dict = field(default_factory=dict)
    fields: dict = field(default_factory=dict)
    blocked: set = field(default_factory=set)
    instance: str | None = None
    owner: _Scope | None = None


@dataclass(frozen=True)
class _Value:
    kind: str
    target: str = ""
    owner: _Scope | None = None
    steps: frozenset = field(default_factory=frozenset, compare=False)


class CosmosQueryProvenance:
    """A positive API proof; annotations and arbitrary method names do not count.

    Every assignment of a participating name/instance field must resolve to
    the same SDK object kind. Unknown writes, aliases, project providers and
    namespace mutations decline this additional sink model.
    """

    def __init__(self, tree, filename, project_root=None):
        self.tree = tree
        self.filename = str(filename)
        self.root = project_root
        self.resolver = None
        try:
            self.resolver = ReceiverResolver(tree, filename)
        except (OSError, RuntimeError, ValueError, RecursionError):
            pass
        self._plain_classes = {}
        self.scopes = {}
        self.attribute_writes = []
        self.unknown_fields = set()
        self.module = _Scope(tree, None, "module")
        self.enabled = False
        if not isinstance(tree, ast.Module):
            return
        dynamic, rebound = module_rebinding(tree, module_name_for(filename))
        names, computed = attribute_write_names(tree)
        if dynamic or computed or names & (_CONTRACT_NAMES | _MAGIC):
            return
        if any(
            isinstance(node, ast.Attribute) and node.attr in {"__dict__", "__class__"}
            for node in ast.walk(tree)
        ):
            return
        if not self._sdk_imports_stable(tree, filename, project_root):
            return
        self.rebound = rebound
        self._walk(tree, self.module)
        for target, value, scope in self.attribute_writes:
            owner = self._self_owner(scope, target.value)
            if owner is None:
                self.unknown_fields.add(target.attr)
            else:
                owner.fields.setdefault(target.attr, []).append((scope, value))
        self.enabled = not self._has_escaping_receiver()

    def _sdk_imports_stable(self, tree, filename, root):
        if root is None:
            root = getattr(self.resolver, "root", None)
        if root is None:
            return False
        trees, complete = project_source_snapshot(root)
        if not complete or not trees:
            return False
        captured = trees.get(Path(filename).resolve())
        if captured is None or ast.dump(captured) != ast.dump(tree):
            return False
        self.snapshot = trees
        self.snapshot_root = Path(root).resolve()
        return _snapshot_providers_stable(trees, self.snapshot_root)

    def _has_escaping_receiver(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            scope = self.scopes.get(node)
            if scope is None:
                continue
            callee = self._value(node.func, scope)
            if callee is not None and callee.kind in {"constructor", "factory"}:
                continue
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                value = self._value(argument, scope)
                if value is not None and (
                    value.kind == "self"
                    or value.kind == "instance"
                    and value.target.startswith("azure.cosmos.")
                ):
                    return True
        return False

    def _bind(self, scope, name, value):
        scope.bindings.setdefault(name, []).append(value)

    def _target(self, target, value, scope):
        if isinstance(target, ast.Name):
            self._bind(scope, target.id, value)
        elif isinstance(target, ast.Attribute):
            self.attribute_writes.append((target, value, scope))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self._target(child, None, scope)

    def _import(self, node, scope):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                target = alias.name if alias.asname else name
                value = None
                if alias.name == "azure.cosmos" or alias.name == "azure.cosmos.aio":
                    value = _Value("module", target)
                self._bind(scope, name, value)
        else:
            for alias in node.names:
                if alias.name == "*":
                    scope.blocked.add("*")
                    continue
                value = None
                if not node.level and node.module in {
                    "azure.cosmos",
                    "azure.cosmos.aio",
                }:
                    if alias.name in _TYPES:
                        value = _Value("constructor", f"{node.module}.{alias.name}")
                self._bind(scope, alias.asname or alias.name, value)

    def _walk(self, node, scope):
        self.scopes[node] = scope
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._import(node, scope)
            return
        if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                self._bind(scope, node.name, None)
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            parent = scope
            if kind == "function":
                while parent.kind == "class":
                    parent = parent.parent
            child_scope = _Scope(node, parent, kind)
            if isinstance(node, (ast.ClassDef, *_FUNCTIONS)):
                for expression in node.decorator_list:
                    self._walk(expression, scope)
            if isinstance(node, ast.ClassDef):
                if node.decorator_list or node.keywords:
                    child_scope.blocked.add("self")
                for base in node.bases:
                    self._walk(base, scope)
            else:
                arguments = [
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                ]
                if node.args.vararg:
                    arguments.append(node.args.vararg)
                if node.args.kwarg:
                    arguments.append(node.args.kwarg)
                for argument in arguments:
                    self._bind(child_scope, argument.arg, None)
                decorators = getattr(node, "decorator_list", ())
                positional = [*node.args.posonlyargs, *node.args.args]
                if scope.kind == "class" and positional and not decorators:
                    child_scope.instance = arguments[0].arg
                    child_scope.owner = scope
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        self._walk(default, scope)
            body = [node.body] if isinstance(node, ast.Lambda) else node.body
            for statement in body:
                self._walk(statement, child_scope)
            return
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._target(target, node.value, scope)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None or scope.kind != "class":
                self._target(node.target, node.value, scope)
        elif isinstance(node, ast.NamedExpr):
            self._target(node.target, node.value, scope)
        elif isinstance(node, (ast.AugAssign, ast.Delete, ast.For, ast.AsyncFor)):
            for target in getattr(node, "targets", (getattr(node, "target", None),)):
                if target is not None:
                    self._target(target, None, scope)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name, None)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            scope.blocked.update(node.names)
            self.module.blocked.update(node.names)
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope)

    def _self_owner(self, scope, node):
        if not isinstance(node, ast.Name):
            return None
        while scope is not None:
            if node.id in scope.bindings:
                if (
                    scope.instance == node.id
                    and scope.bindings[node.id] == [None]
                    and node.id not in scope.blocked
                ):
                    return scope.owner
                return None
            scope = scope.parent
        return None

    def _join(self, values):
        if not values or any(value is None for value in values):
            return None
        first = values[0]
        if any(value != first for value in values[1:]):
            return None
        return _Value(
            first.kind,
            first.target,
            first.owner,
            frozenset().union(*(v.steps for v in values)),
        )

    def _name(self, scope, name, active, depth):
        while scope is not None:
            if name in scope.blocked or "*" in scope.blocked:
                return None
            if name in scope.bindings:
                owner = self._self_owner(scope, ast.Name(id=name))
                if owner is not None:
                    return _Value("self", owner=owner)
                marker = (id(scope), name)
                if marker in active or name in self.rebound:
                    return None
                values = [
                    value
                    if isinstance(value, _Value)
                    else self._value(value, scope, active | {marker}, depth + 1)
                    for value in scope.bindings[name]
                ]
                return self._join(values)
            scope = scope.parent
        return None

    def _attribute(self, base, name, active, depth):
        if base is None:
            return None
        if base.kind == "module":
            target = f"{base.target}.{name}"
            if target in _MODULES:
                return _Value("module", target)
            if base.target in {"azure.cosmos", "azure.cosmos.aio"} and name in _TYPES:
                return _Value("constructor", target)
        if base.kind == "constructor" and base.target.endswith(".CosmosClient"):
            if name == "from_connection_string":
                return base
        if base.kind == "instance":
            namespace, _, class_name = base.target.rpartition(".")
            factories = {
                ("CosmosClient", "get_database_client"): "DatabaseProxy",
                ("DatabaseProxy", "get_container_client"): "ContainerProxy",
            }
            result = factories.get((class_name, name))
            if result:
                return _Value("factory", f"{namespace}.{result}", steps=base.steps)
        if base.kind == "self":
            owner = base.owner
            marker = (id(owner), name)
            if (
                marker in active
                or name in self.unknown_fields
                or "self" in owner.blocked
            ):
                return None
            if not self._plain_storage(owner) or name in owner.bindings:
                return None
            values = [
                self._value(value, scope, active | {marker}, depth + 1)
                for scope, value in owner.fields.get(name, ())
            ]
            return self._join(values)
        return None

    def _plain_storage(self, owner):
        cached = self._plain_classes.get(id(owner))
        if cached is not None:
            return cached
        module = getattr(self.resolver, "main", None)
        result = self._plain_class(
            owner.node, module, set(owner.fields), frozenset(), False
        )
        self._plain_classes[id(owner)] = result
        return result

    def _plain_class(self, node, module, fields, active, ancestor):
        if (
            id(node) in active
            or len(active) >= 8
            or node.decorator_list
            or node.keywords
        ):
            return False
        active = active | {id(node)}
        if (
            ancestor
            and module is not None
            and fields.intersection(module.bindings(node))
        ):
            return False
        for statement in node.body:
            if isinstance(statement, _FUNCTIONS) and (
                statement.name in _MAGIC or ancestor and statement.name in fields
            ):
                return False
        if ancestor:
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Attribute)
                    and isinstance(child.ctx, (ast.Store, ast.Del))
                    and child.attr in fields
                ):
                    return False
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name)
                    and child.func.id in {"setattr", "delattr", "exec", "eval"}
                ):
                    return False
        for base in node.bases:
            if not self.resolver or module is None:
                return False
            reference = self.resolver._expr(module, base, 0, frozenset())
            if (
                reference is not None
                and reference.kind == "builtin"
                and reference.model == "object"
            ):
                continue
            if reference is not None and isinstance(reference.node, ast.ClassDef):
                if not self._plain_class(
                    reference.node, reference.module, fields, active, True
                ):
                    return False
                continue
            if not self._plain_abc(module, base):
                return False
        return True

    def _plain_abc(self, module, base):
        if (
            not isinstance(base, ast.Name)
            or module.dynamic_namespace
            or base.id in module.mutated
        ):
            return False
        bindings = module.bindings(module.tree).get(base.id, ())
        if len(bindings) != 1:
            return False
        statement, _value, conditional = bindings[0]
        if (
            conditional
            or not isinstance(statement, ast.ImportFrom)
            or statement.level
            or statement.module != "abc"
        ):
            return False
        if not any(
            alias.name == "ABC" and (alias.asname or alias.name) == base.id
            for alias in statement.names
        ):
            return False
        return not any(
            path.stem == "abc"
            or "abc" in path.relative_to(self.snapshot_root).parts[:-1]
            for path in self.snapshot
        )

    def _value(self, node, scope, active=frozenset(), depth=0):
        if node is None or depth > 24:
            return None
        if isinstance(node, ast.Name):
            return self._name(scope, node.id, active, depth)
        if isinstance(node, ast.Attribute):
            return self._attribute(
                self._value(node.value, scope, active, depth + 1),
                node.attr,
                active,
                depth + 1,
            )
        if isinstance(node, ast.Call):
            callee = self._value(node.func, scope, active, depth + 1)
            if callee is not None and callee.kind in {"constructor", "factory"}:
                return _Value(
                    "instance",
                    callee.target,
                    steps=callee.steps | {(node.lineno, callee.target)},
                )
        return None

    def query_receiver(self, call):
        if not self.enabled or not isinstance(call.func, ast.Attribute):
            return None
        scope = self.scopes.get(call)
        if scope is None:
            return None
        value = self._value(call.func.value, scope)
        if (
            value is None
            or value.kind != "instance"
            or value.target
            not in {"azure.cosmos.ContainerProxy", "azure.cosmos.aio.ContainerProxy"}
        ):
            return None
        return {
            "provider": value.target,
            "receiver": ast.unparse(call.func.value),
            "proof_kind": "stable_sdk_factory_chain",
            "factory_steps": [
                {"line": line, "provider": provider}
                for line, provider in sorted(value.steps)
            ],
        }
