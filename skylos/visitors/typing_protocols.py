"""Bounded, source-ordered identities for Python typing declarations."""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

from skylos.core.python_local_bindings import parsed_python_source
from skylos.rules.danger.flow_env import ValueFlow, _scope_bindings, _scope_children
from skylos.rules.danger.import_proof import provider_is_unshadowed

_MODULES = {"typing", "typing_extensions"}
_PROTOCOLS = {module + ".Protocol" for module in _MODULES}
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_MEMBER = "$member:"
_INVALID = "$invalid:"
_FUNCTION = "$function:"
_UNKNOWN = "?"
_SETTERS = {"setattr", "delattr", "builtins.setattr", "builtins.delattr"}


def _root(name):
    return name.split(".", 1)[0]


class _ProtocolFlow(ValueFlow):
    def __init__(self, scope, index, outer, budget):
        self.index = index
        self.snapshots = {}
        self.bindings = {}
        self.position = 0
        super().__init__(
            scope, self._expression, outer=outer, top={_UNKNOWN}, max_steps=budget
        )

    def _bind(self, name, labels):
        super()._bind(name, labels)
        self.bindings.setdefault(name, []).append((self.position, frozenset(labels)))

    def _known(self, labels):
        return frozenset(
            _UNKNOWN
            if _root(label) in _MODULES
            and (
                self._current(_INVALID + _root(label))
                or self._current(_INVALID + label)
            )
            else label
            for label in labels
        )

    def value(self, node):
        return self._known(super().value(node))

    def _expression(self, node, value):
        if isinstance(node, ast.Attribute):
            result = set()
            for base in value(node.value):
                name = base + "." + node.attr
                result.update(
                    self._current(_MEMBER + name) if base in _MODULES else {name}
                )
            return result or {_UNKNOWN}
        return {_UNKNOWN}

    def _invalidate(self, labels):
        for label in labels:
            if _root(label) in _MODULES:
                self._weak(_INVALID + _root(label), {_UNKNOWN})

    def _effects(self, node, conditional=False):
        super()._effects(node, conditional)
        if not isinstance(node, ast.Call):
            return
        functions = self.value(node.func)
        for function in functions:
            self._local_function_effects(function)
        if functions and functions <= _SETTERS and len(node.args) >= 2:
            owners = self.value(node.args[0])
            member = node.args[1]
            if (
                owners <= _MODULES
                and isinstance(member, ast.Constant)
                and isinstance(member.value, str)
            ):
                for owner in owners:
                    self._weak(_MEMBER + owner + "." + member.value, {_UNKNOWN})
                return
        if functions & {
            "globals",
            "locals",
            "vars",
            "exec",
            "eval",
            "builtins.exec",
            "builtins.eval",
        }:
            for module in _MODULES:
                self._weak(_INVALID + module, {_UNKNOWN})
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
            self._invalidate(self.value(argument))

    def _local_function_effects(self, identity):
        summary = self.index.function_effects.get(identity)
        if summary is None:
            return
        function, writes = summary
        scope = self.index.scope(function)
        while isinstance(scope, ast.ClassDef):
            scope = self.index.scope(scope)
        for root, attributes, global_name in writes:
            owner_scope = self.index.tree if global_name else scope
            engine = self.index.active_flows.get(id(owner_scope))
            if engine is None:
                cached = self.index.flows.get(id(owner_scope))
                engine = cached[0] if cached is not None else None
            if engine is None:
                continue
            owners = engine._current(root)
            for attribute in attributes[:-1]:
                resolved = set()
                for owner in owners:
                    name = owner + "." + attribute
                    resolved.update(
                        engine._current(_MEMBER + name) if owner in _MODULES else {name}
                    )
                owners = resolved
            for owner in owners:
                if owner in _MODULES:
                    self._weak(_MEMBER + owner + "." + attributes[-1], {_UNKNOWN})
                else:
                    self._invalidate({owner})

    def _assign(self, target, labels, value_node=None):
        if isinstance(target, ast.Attribute):
            owners = self.value(target.value)
            if owners and owners <= _MODULES:
                for owner in owners:
                    self._bind(_MEMBER + owner + "." + target.attr, labels)
                return
            self._invalidate(owners)
        elif isinstance(target, ast.Subscript):
            self._invalidate(self.value(target.value))
        super()._assign(target, labels, value_node)

    def _delete(self, target):
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            self._assign(target, {_UNKNOWN})
            return
        super()._delete(target)

    def _eager_class_effects(self, node, prior_name):
        # A class body runs now, but its imports and ordinary names stay in
        # the class namespace. Only shared provider capabilities flow back.
        def outer(name):
            if isinstance(self.scope, ast.ClassDef) and not name.startswith(
                (_MEMBER, _INVALID)
            ):
                return self._outer(name)
            return prior_name if name == node.name else self._current(name)

        body = _ProtocolFlow(
            node,
            self.index,
            outer,
            min(60000, max(1, self.index.remaining - self._steps)),
        )
        result = body.run(())
        self.index.remaining -= body._steps
        if result is None or self.index.remaining <= 0:
            for module in _MODULES:
                self._weak(_INVALID + module, {_UNKNOWN})
            return
        for name, labels in body.state.names.items():
            if name.startswith((_MEMBER, _INVALID)):
                self._bind(name, labels)

    def _statement(self, node):
        self.position = getattr(node, "lineno", 0)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    for module in _MODULES:
                        self._weak(_INVALID + module, {_UNKNOWN})
                    continue
                local = alias.asname or alias.name.split(".", 1)[0]
                if isinstance(node, ast.Import):
                    target = alias.name if alias.asname else local
                    labels = {target}
                else:
                    target = (
                        f"{node.module}.{alias.name}"
                        if node.module and not node.level
                        else _UNKNOWN
                    )
                    labels = (
                        self._current(_MEMBER + target)
                        if node.module in _MODULES
                        else {target}
                    )
                self._bind(local, self._known(labels))
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            snapshot = self.snapshots.setdefault(id(node), {})
            for name in (
                self.index.free_names(node)
                | {_INVALID + module for module in _MODULES}
                | {_MEMBER + protocol for protocol in _PROTOCOLS}
            ):
                snapshot[name] = snapshot.get(name, frozenset()) | self._current(name)
            prior_name = self._current(node.name)
            result = super()._statement(node)
            if isinstance(node, ast.FunctionDef) and not node.decorator_list:
                self._bind(node.name, {_FUNCTION + str(id(node))})
            if isinstance(node, ast.ClassDef):
                self._overlays.append({node.name: prior_name})
                try:
                    for base in node.bases:
                        expression = (
                            base.value if isinstance(base, ast.Subscript) else base
                        )
                        # Headers read the previous class-name binding, while
                        # provider effects elsewhere in the header still apply.
                        self._results[id(expression)] = self._results.get(
                            id(expression), frozenset()
                        ) | self.value(expression)
                finally:
                    self._overlays.pop()
                self._eager_class_effects(node, prior_name)
                for child in _scope_children(node):
                    if isinstance(child, (ast.Global, ast.Nonlocal)):
                        for name in child.names:
                            self._weak(name, {_UNKNOWN})
            return result
        return super()._statement(node)


class _ProtocolIndex:
    def __init__(self, tree, filename):
        self.tree = tree
        self.filename = filename
        self.parents = {}
        self.flows = {}
        self.active_flows = {}
        self.function_effects = {}
        self.reads = {}
        self.remaining = 200000
        self.read_work = 0
        self.complete = True
        self.mutable_outer = set()
        self.classes = []
        self.watched = {}
        nodes = list(ast.walk(tree))
        if len(nodes) > 50000:
            self.complete = False
            return
        for node in nodes:
            for child in ast.iter_child_nodes(node):
                self.parents[id(child)] = node
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                self.classes.append(node)
                self.watched.setdefault(id(self.scope(node)), []).extend(
                    base.value if isinstance(base, ast.Subscript) else base
                    for base in node.bases
                )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local, declared = _scope_bindings(node)
                self.mutable_outer.update(declared)
                globals_ = {
                    name
                    for part in _scope_children(node)
                    if isinstance(part, ast.Global)
                    for name in part.names
                }
                writes = []
                for part in _scope_children(node):
                    if isinstance(part, ast.Attribute) and isinstance(
                        part.ctx, (ast.Store, ast.Del)
                    ):
                        attributes = [part.attr]
                        owner = part.value
                        while isinstance(owner, ast.Attribute):
                            attributes.append(owner.attr)
                            owner = owner.value
                        if isinstance(owner, ast.Name) and owner.id not in local:
                            self.mutable_outer.add(owner.id)
                            writes.append(
                                (
                                    owner.id,
                                    tuple(reversed(attributes)),
                                    owner.id in globals_,
                                )
                            )
                if isinstance(node, ast.FunctionDef) and not node.decorator_list:
                    self.function_effects[_FUNCTION + str(id(node))] = node, writes

    def scope(self, node):
        node = self.parents.get(id(node))
        while node is not None and not isinstance(node, _SCOPES):
            node = self.parents.get(id(node))
        return node or self.tree

    def free_names(self, node):
        if id(node) not in self.reads:
            names = set()
            for part in ast.walk(node):
                self.read_work += 1
                if self.read_work > 200000:
                    self.complete = False
                    break
                if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load):
                    names.add(part.id)
            self.reads[id(node)] = names
        return self.reads[id(node)]

    def flow(self, scope):
        if id(scope) in self.flows:
            return self.flows[id(scope)]
        self.flows[id(scope)] = None
        if self.remaining <= 0:
            return None
        if scope is self.tree:

            def outer(name):
                if name.startswith(_MEMBER):
                    return {name.removeprefix(_MEMBER)}
                if name.startswith(_INVALID):
                    return set()
                return (
                    {name}
                    if name
                    in {
                        "setattr",
                        "delattr",
                        "globals",
                        "locals",
                        "vars",
                        "exec",
                        "eval",
                    }
                    else {_UNKNOWN}
                )
        else:
            anchor = scope
            parent = self.scope(scope)
            # Class bodies are not closure scopes for nested classes/methods.
            while isinstance(parent, ast.ClassDef):
                anchor = parent
                parent = self.scope(parent)
            result = self.flow(parent)
            if result is None:
                return None
            parent_engine, _results = result
            snapshot = parent_engine.snapshots.get(id(anchor), {})

            def outer(name):
                labels = snapshot.get(name, parent_engine._absent(name))
                if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for line, assigned in parent_engine.bindings.get(name, ()):
                        if line >= getattr(anchor, "lineno", 0):
                            labels |= assigned
                    if name in self.mutable_outer:
                        labels |= {_UNKNOWN}
                return labels

        engine = _ProtocolFlow(scope, self, outer, min(60000, self.remaining))
        self.active_flows[id(scope)] = engine
        try:
            results = engine.run(self.watched.get(id(scope), ()))
        finally:
            self.active_flows.pop(id(scope), None)
        self.remaining -= engine._steps
        if results is not None and self.complete:
            self.flows[id(scope)] = engine, results
        return self.flows[id(scope)]

    def protocol_bases(self):
        found = set()
        root = Path(self.filename).absolute().parent
        for candidate in [root, *root.parents]:
            if any(
                (candidate / marker).exists()
                for marker in (".git", "pyproject.toml", "setup.cfg", "setup.py")
            ):
                root = candidate
                break
        available = {
            protocol
            for protocol in _PROTOCOLS
            if provider_is_unshadowed(protocol, self.filename, root)
        }
        for cls in self.classes:
            result = self.flow(self.scope(cls))
            if result is None or not self.complete:
                continue
            _engine, values = result
            for base in cls.bases:
                expression = base.value if isinstance(base, ast.Subscript) else base
                labels = values.get(id(expression), frozenset())
                if len(labels) == 1 and labels <= available:
                    found.add(id(expression))
        return found if self.complete else set()


def typing_protocol_bases(tree, filename):
    """AST identities only; flow closures never enter worker metadata/ASTs."""
    native_import = False
    protocol_reference = False
    for count, node in enumerate(ast.walk(tree)):
        if count >= 50000:
            return set()
        if isinstance(node, ast.ImportFrom) and node.module in _MODULES:
            native_import = True
            protocol_reference |= any(alias.name == "Protocol" for alias in node.names)
        elif isinstance(node, ast.Import):
            native_import |= any(alias.name in _MODULES for alias in node.names)
        elif isinstance(node, ast.Attribute) and node.attr == "Protocol":
            protocol_reference = True
    if not native_import or not protocol_reference:
        return set()
    try:
        return _ProtocolIndex(tree, filename).protocol_bases()
    except (OSError, RuntimeError, ValueError, RecursionError):
        return set()


@lru_cache(maxsize=64)
def _class_binding_facts(tree):
    """One bounded body index per cached source AST, never stored on the AST."""
    classes = []
    for count, node in enumerate(ast.walk(tree)):
        if count >= 50000:
            return {}
        if isinstance(node, ast.ClassDef):
            classes.append(node)
    result = {}
    work = 0
    for cls in classes:
        pending = list(cls.body)
        bindings = set()
        external = set()
        while pending:
            node = pending.pop()
            work += 1
            if work > 50000:
                return {}
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[("method", node.lineno, node.name)] = cls.lineno, cls.name
                for argument in [
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                    node.args.vararg,
                    node.args.kwarg,
                ]:
                    if argument is not None:
                        result[("parameter", argument.lineno, argument.arg)] = (
                            cls.lineno,
                            cls.name,
                        )
                continue
            if isinstance(
                node,
                (
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                continue
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                external.update(node.names)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bindings.add((node.id, node.lineno))
            pending.extend(ast.iter_child_nodes(node))
        result[cls.lineno] = (
            cls.name,
            frozenset(binding for binding in bindings if binding[0] not in external),
        )
    return result


def protocol_attribute_binding(definition):
    """Verify a binding in the actual class body, excluding nested scopes."""
    owner = getattr(definition, "python_class_owner", None)
    tree = parsed_python_source(str(definition.filename))
    if not owner or tree is None:
        return False
    name, bindings = _class_binding_facts(tree).get(owner[1], (None, frozenset()))
    return (
        str(owner[0]).rsplit(".", 1)[-1] == name
        and (definition.simple_name, definition.line) in bindings
    )


def protocol_member_declaration(definition, declarations):
    """Class/method/parameter exemptions belong to one source declaration."""
    if not declarations:
        return False
    tree = parsed_python_source(str(definition.filename))
    if tree is None:
        return False
    facts = _class_binding_facts(tree)
    if definition.type == "class":
        if (
            isinstance(definition.node, ast.ClassDef)
            and definition.node.lineno != definition.line
        ):
            return False
        return (definition.name, definition.line) in declarations
    if (
        definition.type == "method"
        and isinstance(definition.node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and definition.node.lineno != definition.line
    ):
        return False
    owner = facts.get((definition.type, definition.line, definition.simple_name))
    return bool(owner) and any(
        line == owner[0] and str(name).rsplit(".", 1)[-1] == owner[1]
        for name, line in declarations
    )
