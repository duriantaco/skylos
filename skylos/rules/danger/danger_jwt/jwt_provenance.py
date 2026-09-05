"""Track JWT import bindings without executing analyzed code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


def _imports(node: ast.Import | ast.ImportFrom):
    if isinstance(node, ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            yield local, alias.name if alias.asname else local
    else:
        for alias in node.names:
            if alias.name != "*":
                qualified = (
                    f"{node.module}.{alias.name}"
                    if node.level == 0 and node.module
                    else None
                )
                yield alias.asname or alias.name, qualified


def _arguments(node):
    return [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
        *([node.args.vararg] if node.args.vararg else []),
        *([node.args.kwarg] if node.args.kwarg else []),
    ]


class _LocalNames(ast.NodeVisitor):
    """Find lexical bindings without descending into nested scopes."""

    def __init__(self):
        self.names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(name for name, _ in _imports(node))

    visit_ImportFrom = visit_Import

    def visit_FunctionDef(self, node):
        self.names.add(node.name)
        for expression in [*node.decorator_list, *node.args.defaults]:
            self.visit(expression)
        for expression in node.args.kw_defaults:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)

    def visit_Lambda(self, node):
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_ListComp(self, node):
        # Comprehension targets are local to the comprehension. Assignment
        # expressions in its other expressions can bind in the outer scope.
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)

    def visit_Global(self, node):
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocal_names.update(node.names)


def _summary(statements):
    """Conservative final bindings for deferred function/closure lookup.

    This is not a call-order analysis: conditional assignments/imports are
    uncertain, and only direct imports establish a qualified binding.
    """
    bindings: dict[str, str | None] = {}
    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            bindings.update(_imports(statement))
        else:
            collector = _LocalNames()
            collector.visit(statement)
            bindings.update(dict.fromkeys(collector.names))
    return bindings


@dataclass
class _Scope:
    kind: str
    parent: _Scope | None = None
    bindings: dict[str, str | None] = field(default_factory=dict)
    deferred: dict[str, str | None] = field(default_factory=dict)
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)


class JWTImportVisitor(ast.NodeVisitor):
    """Visit Python evaluation scopes while keeping import identities local."""

    def __init__(self):
        self._scope = _Scope("module")

    def visit_Module(self, node):
        self._scope.deferred = _summary(node.body)
        self.generic_visit(node)

    def _lookup(self, name):
        scope = self._scope
        deferred = False
        while scope is not None:
            bindings = scope.deferred if deferred else scope.bindings
            if name in bindings:
                return bindings[name]
            deferred = deferred or scope.kind in {"function", "generator"}
            if name in scope.global_names:
                while scope.parent is not None:
                    scope = scope.parent
                    deferred = deferred or scope.kind in {"function", "generator"}
                bindings = scope.deferred if deferred else scope.bindings
                return bindings.get(name)
            if name in scope.nonlocal_names:
                scope = scope.parent
                while scope is not None:
                    if scope.kind == "function" and name in scope.deferred:
                        return scope.deferred[name]
                    scope = scope.parent
                return None
            scope = scope.parent
        return None

    def is_jwt_decode(self, node):
        func = node.func
        attributes = []
        while isinstance(func, ast.Attribute):
            attributes.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            return False
        binding = self._lookup(func.id)
        if binding is None:
            return False
        qualified = ".".join([binding, *reversed(attributes)])
        return qualified == "jose.jwt.decode" or (
            qualified.startswith("jwt.") and qualified.endswith(".decode")
        )

    def visit_Import(self, node):
        self._scope.bindings.update(_imports(node))

    visit_ImportFrom = visit_Import

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Del) and self._scope.kind == "class":
            self._scope.bindings.pop(node.id, None)
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            self._scope.bindings[node.id] = None

    def _visit_scope(self, node, kind, body):
        parent = self._scope
        while parent.kind == "class" and parent.parent is not None:
            parent = parent.parent
        child = _Scope(kind, parent)
        collector = _LocalNames()
        for statement in body:
            collector.visit(statement)
        child.global_names = collector.global_names
        child.nonlocal_names = collector.nonlocal_names
        if kind == "function":
            names = collector.names - collector.global_names - collector.nonlocal_names
            names.update(argument.arg for argument in _arguments(node))
            child.bindings = dict.fromkeys(names)
            child.deferred = {**child.bindings, **_summary(body)}
        previous = self._scope
        self._scope = child
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._scope = previous

    def _visit_arguments(self, node):
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)
        for argument in _arguments(node):
            if argument.annotation is not None:
                self.visit(argument.annotation)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_arguments(node)
        if node.returns is not None:
            self.visit(node.returns)
        self._scope.bindings[node.name] = None
        self._visit_scope(node, "function", node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)
        self._visit_scope(node, "class", node.body)
        self._scope.bindings[node.name] = None

    def visit_Lambda(self, node):
        self._visit_arguments(node)
        self._visit_scope(node, "function", [node.body])

    def visit_ListComp(self, node):
        self.visit(node.generators[0].iter)
        parent = self._scope
        while parent.kind == "class" and parent.parent is not None:
            parent = parent.parent
        previous = self._scope
        kind = "generator" if isinstance(node, ast.GeneratorExp) else "comprehension"
        self._scope = _Scope(kind, parent)
        target_names = {
            child.id
            for generator in node.generators
            for child in ast.walk(generator.target)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        }
        self._scope.bindings = dict.fromkeys(target_names)
        self._scope.deferred = dict.fromkeys(target_names)
        try:
            for index, generator in enumerate(node.generators):
                if index:
                    self.visit(generator.iter)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)
        finally:
            self._scope = previous

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node):
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self.visit(node.target)

    def visit_AugAssign(self, node):
        if not isinstance(node.target, ast.Name):
            self.visit(node.target)
        self.visit(node.value)
        self.visit(node.target)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        target_scope = self._scope
        while (
            target_scope.kind in {"comprehension", "generator"} and target_scope.parent
        ):
            target_scope = target_scope.parent
        target_scope.bindings[node.target.id] = None

    def _branch(self, statements, initial):
        self._scope.bindings = initial.copy()
        for statement in statements:
            self.visit(statement)
        return self._scope.bindings.copy()

    def _join(self, outcomes):
        names = set().union(*(outcome.keys() for outcome in outcomes))
        self._scope.bindings = {
            name: outcomes[0].get(name)
            if all(outcome.get(name) == outcomes[0].get(name) for outcome in outcomes)
            else None
            for name in names
        }

    def visit_If(self, node):
        self.visit(node.test)
        initial = self._scope.bindings.copy()
        self._join(
            [self._branch(node.body, initial), self._branch(node.orelse, initial)]
        )

    def visit_IfExp(self, node):
        self.visit(node.test)
        initial = self._scope.bindings.copy()
        self._join(
            [self._branch([node.body], initial), self._branch([node.orelse], initial)]
        )

    def visit_For(self, node):
        self.visit(node.iter)
        initial = self._scope.bindings.copy()
        self.visit(node.target)
        body = self._branch(node.body, self._scope.bindings)
        self._join([initial, body])
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        initial = self._scope.bindings.copy()
        self._join([initial, self._branch(node.body, initial)])
        for statement in node.orelse:
            self.visit(statement)

    def visit_Try(self, node):
        initial = self._scope.bindings.copy()
        body = self._branch(node.body, initial)
        normal = self._branch(node.orelse, body)
        # An exception may occur before any binding in the try body. Do not
        # carry its imports into a handler as proven identities.
        self._join([initial, body])
        uncertain = self._scope.bindings.copy()
        outcomes = [normal]
        for handler in node.handlers:
            outcomes.append(self._branch([handler], uncertain))
        self._join(outcomes)
        for statement in node.finalbody:
            self.visit(statement)

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        initial = self._scope.bindings.copy()
        outcomes = [initial]
        for case in node.cases:
            statements = [case.pattern]
            if case.guard is not None:
                statements.append(case.guard)
            outcomes.append(self._branch([*statements, *case.body], initial))
        self._join(outcomes)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node):
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._scope.bindings[node.name] = None
        for statement in node.body:
            self.visit(statement)

    def visit_MatchAs(self, node):
        self.generic_visit(node)
        if node.name:
            self._scope.bindings[node.name] = None

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        self.generic_visit(node)
        if node.rest:
            self._scope.bindings[node.rest] = None
