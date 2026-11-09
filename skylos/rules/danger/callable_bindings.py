"""Source-ordered identities of captured code, pickle and command callables."""

from __future__ import annotations

import ast

from .flow_env import ValueFlow, _scope_bindings, _scope_children
from .import_proof import provider_is_unshadowed

_UNKNOWN = "?"
_LOCAL = "!local"
_MEMBER = "$member:"
_ROOTS = frozenset({"pickle", "cloudpickle", "os", "subprocess", "asyncio"})
_BUILTINS = frozenset({"eval", "exec"})
_UNPICKLER_BASES = {
    "pickle.Unpickler": "pickle.Unpickler",
    "_pickle.Unpickler": "pickle.Unpickler",
    "dill.Unpickler": "dill.Unpickler",
}
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _tracked(name):
    return name in _BUILTINS or name.split(".", 1)[0] in _ROOTS


def _canonical(name):
    if name in {"builtins.eval", "builtins.exec"}:
        return name.rsplit(".", 1)[1]
    return name


class _CallableFlow(ValueFlow):
    def __init__(self, scope, owner, outer, max_steps):
        self.owner = owner
        self.snapshots = {}
        self.bindings = {}
        self.position = 0
        self.member_keys = set()
        super().__init__(
            scope, self._expression, outer=outer, top={_UNKNOWN}, max_steps=max_steps
        )

    def _bind(self, name, labels):
        super()._bind(name, labels)
        self.bindings.setdefault(name, []).append((self.position, frozenset(labels)))

    def _expression(self, node, value):
        if isinstance(node, ast.Attribute):
            labels = set()
            for label in value(node.value):
                if label in {_UNKNOWN, _LOCAL}:
                    labels.add(label)
                else:
                    name = _canonical(label + "." + node.attr)
                    labels.update(
                        self._current(_MEMBER + name) if _tracked(name) else {name}
                    )
            return labels
        if isinstance(node, ast.Call):
            # Retain the existing Unpickler(...).load() constructor spelling.
            constructors = value(node.func)
            if any(name.endswith(".Unpickler") for name in constructors):
                return constructors
            if constructors == {_LOCAL}:
                return {_LOCAL}
            return {_UNKNOWN}
        if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return {_LOCAL}
        return {_UNKNOWN}

    def value(self, node):
        if isinstance(node, ast.Lambda):
            return frozenset({_LOCAL})
        return super().value(node)

    def _assign(self, target, labels, value_node=None):
        if isinstance(target, ast.Attribute):
            providers = self.value(target.value)
            names = {
                _canonical(name + "." + target.attr)
                for name in providers
                if name not in {_UNKNOWN, _LOCAL}
            }
            if names and all(_tracked(name) for name in names):
                for name in names:
                    key = _MEMBER + name
                    self.member_keys.add(key)
                    if len(providers) == 1:
                        self._bind(key, labels)
                    else:
                        self._weak(key, labels)
                return
        super()._assign(target, labels, value_node)

    def _statement(self, node):
        self.position = getattr(node, "lineno", 0)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    continue
                if isinstance(node, ast.Import):
                    local = alias.asname or alias.name.split(".", 1)[0]
                    target = alias.name if alias.asname else local
                else:
                    local = alias.asname or alias.name
                    target = (
                        f"{node.module}.{alias.name}"
                        if node.module and not node.level
                        else _UNKNOWN
                    )
                self._bind(local, {_canonical(target)})
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            constructors = set()
            if isinstance(node, ast.ClassDef) and not any(
                isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name == "find_class"
                for member in node.body
            ):
                # Resolve bases before binding the new class name. An inherited
                # native load remains native; a replaced provider stays local.
                constructors = {
                    _UNPICKLER_BASES[label]
                    for base in node.bases
                    for label in self.value(base)
                    if label in _UNPICKLER_BASES
                    and self.owner.provider_available(
                        label, *(self.owner.provider_context or (None, None))
                    )
                }
            self.snapshots[id(node)] = {
                name: self._current(name)
                for name in self.owner.free_names(node) | self.member_keys
            }
            super()._statement(node)
            if not node.decorator_list:
                self._bind(node.name, constructors or {_LOCAL})
            return True
        return super()._statement(node)


class _CallableIndex:
    def __init__(self, module):
        self.module = module
        self._ready = True
        self.parents = {}
        self.flows = {}
        self.watched = {}
        self.remaining = 200000
        self.reads = {}
        self.read_work = 0
        self.mutable_outer = set()
        self.dynamic = False
        self.complete = True
        self.provider_checks = {}
        self.provider_context = None
        nodes = []
        for node in ast.walk(module):
            nodes.append(node)
            if len(nodes) > 50000:
                self.complete = False
                break
            for child in ast.iter_child_nodes(node):
                self.parents[id(child)] = node
        if not self.complete:
            return
        for node in nodes:
            if isinstance(node, ast.Call):
                self.watched.setdefault(id(self.scope(node)), []).append(node.func)
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "globals",
                    "locals",
                    "vars",
                }:
                    self.dynamic = True
            elif isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                self.dynamic = True
            elif isinstance(node, ast.Attribute) and node.attr in {
                "__globals__",
                "__dict__",
                "f_globals",
                "f_locals",
                "modules",
            }:
                self.dynamic = True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local, declared = _scope_bindings(node)
                for part in _scope_children(node):
                    if (
                        isinstance(part, ast.Name)
                        and isinstance(part.ctx, (ast.Store, ast.Del))
                        and part.id in declared
                    ):
                        self.mutable_outer.add(part.id)
                    elif isinstance(part, ast.Attribute) and not isinstance(
                        part.ctx, ast.Load
                    ):
                        root = part.value
                        while isinstance(root, ast.Attribute):
                            root = root.value
                        if isinstance(root, ast.Name) and root.id not in local:
                            self.mutable_outer.add(root.id)

    def __getstate__(self):
        # Worker results travel back through pickle, and a Definition's node
        # reaches this module through parent pointers. The flow caches hold
        # closures (flow.<locals>.outer), and every cache is keyed by id(),
        # so the unpickled index rebuilds them from the module on first use.
        return {"module": self.module}

    def __setstate__(self, state):
        self.module = state["module"]
        self._ready = False

    def _ensure_ready(self):
        if not self._ready:
            self.__init__(self.module)

    def scope(self, node):
        self._ensure_ready()
        while node is not None:
            if isinstance(node, _SCOPES):
                return node
            node = self.parents.get(id(node))
        return self.module

    def free_names(self, scope):
        self._ensure_ready()
        key = id(scope)
        if key not in self.reads:
            names = set()
            for node in ast.walk(scope):
                self.read_work += 1
                if self.read_work > 200000:
                    self.complete = False
                    break
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    names.add(node.id)
            self.reads[key] = names
        return self.reads[key]

    def flow(self, scope):
        self._ensure_ready()
        key = id(scope)
        if key in self.flows:
            return self.flows[key]
        self.flows[key] = None
        if self.remaining <= 0:
            return None
        if scope is self.module:

            def outer(name):
                if name.startswith(_MEMBER):
                    return {name.removeprefix(_MEMBER)}
                return {name} if name in _BUILTINS else {_UNKNOWN}
        else:
            anchor = scope
            parent = self.parents.get(id(scope))
            while parent is not None and not isinstance(parent, _SCOPES):
                parent = self.parents.get(id(parent))
            # Class namespaces are not enclosing lexical scopes of methods.
            while isinstance(parent, ast.ClassDef) and not isinstance(
                scope, ast.ClassDef
            ):
                anchor = parent
                parent = self.parents.get(id(parent))
                while parent is not None and not isinstance(parent, _SCOPES):
                    parent = self.parents.get(id(parent))
            parent_flow = self.flow(parent or self.module)
            if parent_flow is None:
                return None
            parent_engine, _ = parent_flow
            snapshot = parent_engine.snapshots.get(id(anchor), {})

            def outer(name):
                labels = snapshot.get(name, parent_engine._absent(name))
                # A deferred body can run before or after later outer writes.
                for line, assigned in parent_engine.bindings.get(name, ()):
                    if line >= getattr(anchor, "lineno", 0):
                        labels |= assigned
                if name in self.mutable_outer:
                    labels |= {_UNKNOWN}
                return labels

        engine = _CallableFlow(scope, self, outer, min(60000, self.remaining))
        result = engine.run(self.watched.get(key, ()))
        self.remaining -= engine._steps
        if result is not None:
            self.flows[key] = engine, result
        return self.flows[key]

    def names(self, node, legacy, filename, project_root):
        self._ensure_ready()
        context = filename, project_root
        if self.provider_context != context:
            # A shared AST may be checked with a wider project inventory by
            # another scanner. Its constructor proofs must use that inventory.
            self.provider_context = context
            self.flows.clear()
        if not self.complete:
            return (legacy,) if legacy else ()
        flow = self.flow(self.scope(node))
        if flow is None or not self.complete:
            return (legacy,) if legacy else ()
        _, results = flow
        labels = results.get(id(node.func))
        if labels is None:
            return (legacy,) if legacy else ()
        found = {
            name
            for name in labels
            if _tracked(name)
            and (
                name == legacy
                or name in _BUILTINS
                or self.provider_available(name, filename, project_root)
            )
        }
        if legacy and (not _tracked(legacy) or _UNKNOWN in labels or self.dynamic):
            found.add(legacy)
        return tuple(sorted(found))

    def provider_available(self, name, filename, project_root):
        self._ensure_ready()
        key = name.split(".", 1)[0], filename, project_root
        if key not in self.provider_checks:
            self.provider_checks[key] = provider_is_unshadowed(
                name, filename, project_root
            )
        return self.provider_checks[key]


def callable_names(node, legacy, module, filename=None, project_root=None):
    """Possible native identities, retaining legacy warnings for unknown flow.

    Names rebound to a known different provider or source-owned definition do
    not keep an obsolete import identity. Work limits retain the legacy result.
    """
    if not isinstance(module, ast.Module):
        return (legacy,) if legacy else ()
    index = getattr(module, "_skylos_danger_callable_index", None)
    if index is None:
        index = module._skylos_danger_callable_index = _CallableIndex(module)
    return index.names(node, legacy, filename, project_root)
