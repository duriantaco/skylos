"""Bounded source-owned Cosmos SDK receiver factories, without SDK imports."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from skylos.security.receiver_resolution import ReceiverResolver
from ..untrusted_sources import UntrustedSourceIndex

from ..import_proof import (
    _provider_effects,
    provider_is_unshadowed,
)
from ..project_imports import ProjectImports, project_import_context
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


def _private_import_context(tree, filename, root):
    attested = project_import_context(tree, filename, root)
    if attested is None:
        return None
    private = ProjectImports(tree, attested.source, attested.root, attested.snapshot)
    return private if private.complete else None


def _private_provider_effects(context, names, *, project_sdk=False):
    # The original trees attest source identity. Fresh Module roots own the
    # mutable effect budgets, so this optional model cannot exhaust other rules.
    closure = {path for path, _ in context.entries}
    for path, parsed in context.entries:
        if not _provider_effects(
            names,
            ast.Module(body=list(parsed.body), type_ignores=parsed.type_ignores),
            context.local_symbols(path, names),
        ):
            return False
    if not project_sdk:
        return True
    for path, parsed in context.trees.items():
        if path not in closure and not _provider_effects(
            names, _annotation_effect_tree(parsed), context.local_symbols(path, names)
        ):
            return False
    return True


def _annotation_effect_tree(tree):
    """Ignore only inert SDK ``Type | None`` annotations in other modules.

    These types use Python's ordinary type union operation. The main import
    closure keeps its original strict effect proof. Calls, subscriptions,
    arbitrary type expressions and all provider mutations remain visible.
    """
    imports = UntrustedSourceIndex(tree)
    native_types = {
        f"{module}.{kind}"
        for module in ("azure.cosmos", "azure.cosmos.aio")
        for kind in _TYPES
    }
    annotations = set()

    def inert_union(node, scope):
        values = []
        pending = [node]
        while pending:
            value = pending.pop()
            if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
                pending.extend((value.left, value.right))
            elif isinstance(value, ast.Constant) and value.value is None:
                values.append(None)
            else:
                parts = []
                current = value
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if not isinstance(current, ast.Name):
                    return False
                name = ".".join(reversed([*parts, current.id]))
                if imports.resolved_import(scope, name) not in native_types:
                    return False
                values.append(name)
        return None in values and any(value is not None for value in values)

    def collect(node, scope=None):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = node
        for field_name, value in ast.iter_fields(node):
            if field_name in {"annotation", "returns"} and isinstance(value, ast.BinOp):
                if inert_union(value, scope):
                    annotations.add(id(value))
            if isinstance(value, ast.AST):
                collect(value, scope)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, ast.AST):
                        collect(child, scope)

    collect(tree)
    if not annotations:
        return ast.Module(body=list(tree.body), type_ignores=tree.type_ignores)

    def clone(value):
        if isinstance(value, ast.AST):
            if id(value) in annotations:
                return ast.copy_location(ast.Constant(value=None), value)
            copied = type(value)(
                **{key: clone(item) for key, item in ast.iter_fields(value)}
            )
            for key in value._attributes:
                if hasattr(value, key):
                    setattr(copied, key, getattr(value, key))
            return copied
        if isinstance(value, list):
            return [clone(item) for item in value]
        return value

    return clone(tree)


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
            if project_root and not self.resolver.root.resolve().is_relative_to(
                Path(project_root).resolve()
            ):
                self.resolver = ReceiverResolver(tree, filename, project_root)
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
        if not provider_is_unshadowed("azure.cosmos", filename, project_root):
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
        contracts = set()
        for namespace in ("azure.cosmos", "azure.cosmos.aio"):
            contracts.update(f"{namespace}.{name}" for name in _TYPES)
            contracts.update(
                f"{namespace}.{name}"
                for name in (
                    "CosmosClient.from_connection_string",
                    "CosmosClient.get_database_client",
                    "DatabaseProxy.get_container_client",
                    "ContainerProxy.query_items",
                )
            )
        context = _private_import_context(tree, filename, root)
        if context is None:
            return False
        names = set()
        for contract in contracts:
            names.update(context.qualified_names(contract))
        return _private_provider_effects(context, names, project_sdk=True)

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
        if not provider_is_unshadowed("abc.ABC", module.path, self.root):
            return False
        context = _private_import_context(module.tree, module.path, self.root)
        if context is None or "abc" in context.modules:
            return False
        return _private_provider_effects(context, context.qualified_names("abc.ABC"))

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
