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
        self.deleted_names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)
        if isinstance(node.ctx, ast.Del):
            self.deleted_names.add(node.id)

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
            # Python clears the exception target when leaving its handler.
            self.deleted_names.add(node.name)
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


def _summary(statements, safe_parameters=()):
    """Reachable bindings for deferred lookup, without reporting or call order.

    A returned closure retains its enclosing return state. Imports following
    an exit cannot establish a binding, although they remain lexical locals.
    Nested function bodies are leaves in this non-reporting transfer pass.
    """
    visitor = JWTImportVisitor(summary_only=True)
    visitor._scope.safe_parameters = set(safe_parameters)
    flow = visitor._suite(statements, {})
    return (
        _merge_bindings(
            [
                state
                for kind, state in flow.states.items()
                if kind in {"normal", "return"}
            ]
        )
        or {}
    )


def _merge_bindings(states):
    if not states:
        return None
    names = set().union(*(state.keys() for state in states))
    return {
        name: states[0].get(name)
        if all(state.get(name) == states[0].get(name) for state in states)
        else None
        for name in names
    }


@dataclass
class _Flow:
    """Joined bindings per completion kind; absent normal means unreachable."""

    states: dict[str, dict[str, str | None]] = field(default_factory=dict)

    def add(self, kind, bindings):
        if bindings is not None:
            previous = self.states.get(kind)
            self.states[kind] = (
                bindings.copy()
                if previous is None
                else _merge_bindings([previous, bindings])
            )

    def extend(self, other, exclude=()):
        for kind, bindings in other.states.items():
            if kind not in exclude:
                self.add(kind, bindings)


@dataclass
class _Scope:
    kind: str
    parent: _Scope | None = None
    bindings: dict[str, str | None] = field(default_factory=dict)
    deferred: dict[str, str | None] = field(default_factory=dict)
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)
    safe_parameters: set[str] = field(default_factory=set)


class JWTImportVisitor(ast.NodeVisitor):
    """Visit Python evaluation scopes while keeping import identities local."""

    def __init__(self, summary_only=False):
        self._scope = _Scope("module")
        self._summary_only = summary_only

    def visit_Module(self, node):
        self._scope.deferred = _summary(node.body)
        return self._suite(node.body, self._scope.bindings)

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
            parameters = {argument.arg for argument in _arguments(node)}
            names.update(parameters)
            child.safe_parameters = parameters - collector.deleted_names
            child.bindings = dict.fromkeys(names)
            child.deferred = {
                **child.bindings,
                **_summary(body, child.safe_parameters),
            }
        previous = self._scope
        self._scope = child
        try:
            return self._suite(body, child.bindings)
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
        if not self._summary_only:
            # A function's exits belong to its invocation, not its definition.
            self._visit_scope(node, "function", node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)
        outer = self._scope.bindings.copy()
        body = self._visit_scope(node, "class", node.body)
        result = _Flow()
        for kind in body.states:
            bindings = outer.copy()
            if kind == "normal":
                bindings[node.name] = None
            result.add(kind, bindings)
        return result

    def visit_Lambda(self, node):
        self._visit_arguments(node)
        if not self._summary_only:
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

    def _finish(self, flow):
        normal = flow.states.get("normal")
        self._scope.bindings = normal.copy() if normal is not None else {}
        return flow

    def _suite(self, statements, initial):
        """Only normal completion reaches the next statement in a suite.

        Ordinary operations can raise before finishing. Retaining their
        before/after states also preserves intermediate exception bindings for
        enclosing handlers/finalizers, without interpreting called code.
        """
        result = _Flow()
        normal = initial.copy()
        for statement in statements:
            if normal is None:
                break
            self._scope.bindings = normal.copy()
            before = normal.copy()
            step = self.visit(statement)
            if not isinstance(step, _Flow):
                step = _Flow()
                step.add("normal", self._scope.bindings)
                if not isinstance(statement, (ast.Pass, ast.Global, ast.Nonlocal)):
                    step.add("raise", before)
                    step.add("raise", self._scope.bindings)
            result.extend(step, exclude=("normal",))
            normal = step.states.get("normal")
        result.add("normal", normal)
        return self._finish(result)

    def _exit(self, kind, expression=None):
        before = self._scope.bindings.copy()
        if expression is not None:
            self.visit(expression)
        result = _Flow()
        result.add(kind, self._scope.bindings)
        # Parameters exist on entry unless a lexical delete can unbind them.
        # Do not invent a suppressible NameError after an ordinary parameter
        # return; unknown names and compound operands remain conservative.
        safe_parameter = (
            isinstance(expression, ast.Name)
            and expression.id in self._scope.safe_parameters
        )
        if (
            expression is not None
            and not isinstance(expression, ast.Constant)
            and not safe_parameter
        ):
            result.add("raise", before)
        return self._finish(result)

    def visit_Return(self, node):
        return self._exit("return", node.value)

    def visit_Raise(self, node):
        before = self._scope.bindings.copy()
        if node.exc is not None:
            self.visit(node.exc)
        if node.cause is not None:
            self.visit(node.cause)
        result = _Flow()
        result.add("raise", before)
        result.add("raise", self._scope.bindings)
        return self._finish(result)

    def visit_Break(self, node):
        return self._exit("break")

    def visit_Continue(self, node):
        return self._exit("continue")

    def _conditional(self, test, body, orelse):
        before = self._scope.bindings.copy()
        self.visit(test)
        initial = self._scope.bindings.copy()
        result = _Flow()
        if isinstance(test, ast.Constant):
            selected = body if bool(test.value) else orelse
            result.extend(self._suite(selected, initial))
        else:
            result.extend(self._suite(body, initial))
            result.extend(self._suite(orelse, initial))
            result.add("raise", before)
        return self._finish(result)

    def visit_If(self, node):
        return self._conditional(node.test, node.body, node.orelse)

    def visit_IfExp(self, node):
        return self._conditional(node.test, [node.body], [node.orelse])

    def _loop_body(self, node, initial):
        # A non-reporting transfer finds loop-carried uncertainty first. The
        # real body is visited once, so callbacks/findings are never duplicated.
        header = initial.copy()
        if not self._summary_only:
            preview = JWTImportVisitor(summary_only=True)
            preview._scope.bindings = initial.copy()
            preview._scope.safe_parameters = self._scope.safe_parameters.copy()
            if isinstance(node, (ast.For, ast.AsyncFor)):
                preview.visit(node.target)
            transferred = preview._suite(node.body, preview._scope.bindings)
            header = _merge_bindings(
                [initial]
                + [
                    bindings
                    for kind, bindings in transferred.states.items()
                    if kind in {"normal", "continue"}
                ]
            )
        self._scope.bindings = header.copy()
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.visit(node.target)
        return self._suite(node.body, self._scope.bindings)

    def _complete_loop(self, node, initial, body, zero_iterations=True, exhausts=True):
        result = _Flow()
        result.extend(body, exclude=("normal", "break", "continue"))
        exhaustion = []
        if zero_iterations:
            exhaustion.append(initial)
        if exhausts:
            exhaustion.extend(
                bindings
                for kind, bindings in body.states.items()
                if kind in {"normal", "continue"}
            )
        exhausted = _merge_bindings(exhaustion)
        if exhausted is not None:
            result.extend(self._suite(node.orelse, exhausted))
        # A break bypasses else; its bindings join only after else completes.
        result.add("normal", body.states.get("break"))
        return self._finish(result)

    def visit_For(self, node):
        before = self._scope.bindings.copy()
        self.visit(node.iter)
        initial = self._scope.bindings.copy()
        literal = isinstance(node.iter, (ast.Tuple, ast.List, ast.Set)) and not any(
            isinstance(item, ast.Starred) for item in node.iter.elts
        )
        body = (
            _Flow()
            if literal and not node.iter.elts
            else self._loop_body(node, initial)
        )
        result = self._complete_loop(
            node, initial, body, zero_iterations=not literal or not node.iter.elts
        )
        result.add("raise", before)
        return self._finish(result)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        before = self._scope.bindings.copy()
        self.visit(node.test)
        initial = self._scope.bindings.copy()
        constant = (
            bool(node.test.value) if isinstance(node.test, ast.Constant) else None
        )
        body = _Flow() if constant is False else self._loop_body(node, initial)
        result = self._complete_loop(
            node,
            initial,
            body,
            zero_iterations=constant is not True,
            exhausts=constant is not True,
        )
        if not isinstance(node.test, ast.Constant):
            result.add("raise", before)
        return self._finish(result)

    def visit_Try(self, node):
        initial = self._scope.bindings.copy()
        body = self._suite(node.body, initial)
        pending = _Flow()
        pending.extend(body, exclude=("normal", "raise"))
        normal = body.states.get("normal")
        if normal is not None:
            # Else belongs only to normal try completion, never to a handler.
            pending.extend(self._suite(node.orelse, normal))
        exceptional = body.states.get("raise")
        if exceptional is not None:
            for handler in node.handlers:
                pending.extend(self._suite([handler], exceptional))
            # Typed handlers may not match; no exception types are executed or
            # inferred here. A bare handler is the one proven catch-all case.
            if not any(handler.type is None for handler in node.handlers):
                pending.add("raise", exceptional)
        if not node.finalbody or not pending.states:
            return self._finish(pending)

        # Visit the finalizer once with every reachable pending input joined.
        # Normal finalizer completion resumes the original completion kind;
        # an abrupt finalizer completion replaces it (including a prior return).
        incoming = _merge_bindings(list(pending.states.values()))
        finalizer = self._suite(node.finalbody, incoming)
        result = _Flow()
        for kind in pending.states:
            result.add(kind, finalizer.states.get("normal"))
        result.extend(finalizer, exclude=("normal",))
        return self._finish(result)

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        before = self._scope.bindings.copy()
        self.visit(node.subject)
        initial = self._scope.bindings.copy()
        result = _Flow()
        exhaustive = False
        for case in node.cases:
            statements = [case.pattern]
            if case.guard is not None:
                statements.append(case.guard)
            result.extend(self._suite([*statements, *case.body], initial))
            if case.guard is None and self._irrefutable(case.pattern):
                exhaustive = True
                break
        if not exhaustive:
            result.add("normal", initial)
        result.add("raise", before)
        return self._finish(result)

    @staticmethod
    def _irrefutable(pattern):
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is None or JWTImportVisitor._irrefutable(
                pattern.pattern
            )
        return isinstance(pattern, ast.MatchOr) and any(
            JWTImportVisitor._irrefutable(child) for child in pattern.patterns
        )

    def visit_With(self, node):
        before = self._scope.bindings.copy()
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        result = self._suite(node.body, self._scope.bindings)
        # __exit__ may suppress a body exception, but cannot suppress a return,
        # break or continue. Acquisition failures are not suppressible here.
        result.add("normal", result.states.get("raise"))
        result.add("raise", before)
        return self._finish(result)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node):
        before = self._scope.bindings.copy()
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._scope.bindings[node.name] = None
        result = self._suite(node.body, self._scope.bindings)
        if node.type is not None:
            result.add("raise", before)
        return self._finish(result)

    def visit_MatchAs(self, node):
        self.generic_visit(node)
        if node.name:
            self._scope.bindings[node.name] = None

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        self.generic_visit(node)
        if node.rest:
            self._scope.bindings[node.rest] = None
