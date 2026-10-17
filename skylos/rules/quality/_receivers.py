"""Attribute ownership for methods, including local aliases and nested scopes."""

import ast
from collections import Counter
from dataclasses import dataclass, field

from skylos.rules.quality._ast_visit import IterativeNodeVisitor


FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _builtin_decorator(node: ast.expr, name: str) -> bool:
    return (isinstance(node, ast.Name) and node.id == name) or (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "builtins"
        and node.attr == name
    )


def method_kind(node: ast.FunctionDef | ast.AsyncFunctionDef, *, kinds=None) -> str:
    if kinds is not None and node in kinds:
        return kinds[node]
    if any(_builtin_decorator(d, "staticmethod") for d in node.decorator_list):
        return "static"
    if any(_builtin_decorator(d, "classmethod") for d in node.decorator_list):
        return "class"
    return "instance"


def method_receiver(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    instance_only: bool = False,
    kinds=None,
) -> str | None:
    """Return the bound parameter; the caller must establish class ownership."""
    kind = method_kind(node, kinds=kinds)
    if kind in {"static", "unknown"} or (instance_only and kind == "class"):
        return None
    positional = [*node.args.posonlyargs, *node.args.args]
    return positional[0].arg if positional else None


def possible_method_receiver(
    node: ast.FunctionDef | ast.AsyncFunctionDef, *, kinds=None
):
    """Return a possible bound parameter without claiming unknown binding is proved.

    Callers must establish class ownership. Proven static methods have no
    implicit parameter; an unknown decorator leaves both interpretations open.
    """
    if method_kind(node, kinds=kinds) == "static":
        return None
    positional = [*node.args.posonlyargs, *node.args.args]
    return positional[0].arg if positional else None


def class_method_nodes(node: ast.ClassDef):
    """Yield function definitions whose nearest lexical scope is this class."""
    pending = list(reversed(node.body))
    while pending:
        child = pending.pop()
        if isinstance(child, FUNCTION_NODES):
            yield child
        elif not isinstance(child, (ast.ClassDef, ast.Lambda)):
            pending.extend(reversed(list(ast.iter_child_nodes(child))))


def _instance_descriptor(node, *, bindings=None, kinds=None):
    from skylos.rules.quality._receiver_descriptors import _instance_descriptor as prove

    return prove(node, bindings=bindings, kinds=kinds)


def resolve_method_kinds(
    node: ast.Module | ast.ClassDef,
    *,
    filename=None,
    project_root=None,
    source_reader=None,
    **internal,
):
    # Lazy import keeps receiver flow separate from descriptor source proofs.
    from skylos.rules.quality._receiver_decorators import (
        resolve_method_kinds as resolve,
    )

    return resolve(
        node,
        filename=filename,
        project_root=project_root,
        source_reader=source_reader,
        **internal,
    )


def context_method_kinds(node: ast.Module, context):
    """Share one bounded resolution across quality rules visiting this module."""
    cached = context.get("_receiver_method_kinds")
    if cached is None or cached[0] is not node:
        cached = (
            node,
            resolve_method_kinds(
                node,
                filename=context.get("filename"),
                project_root=context.get("project_root"),
                source_reader=context.get("receiver_source_reader"),
            ),
        )
        context["_receiver_method_kinds"] = cached
    return cached[1]


class _Bindings(IterativeNodeVisitor):
    """Bindings in one lexical scope; nested function bodies do not bind here."""

    def __init__(self):
        self.names: set[str] = set()
        self.nonlocals: set[str] = set()
        self.counts: Counter[str] = Counter()

    def _bind_name(self, name):
        self.names.add(name)
        self.counts[name] += 1

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind_name(node.id)

    def visit_FunctionDef(self, node):
        self._bind_name(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_Import(self, node):
        for alias in node.names:
            self._bind_name(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self._bind_name(alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._bind_name(node.name)
        self.generic_visit(node)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_Global(self, node):
        self.names.update(node.names)

    def visit_MatchAs(self, node):
        if node.name:
            self._bind_name(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self._bind_name(node.rest)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        # Comprehension iteration targets have a separate scope.
        writes = _ComprehensionWrites()
        writes.visit(node)
        for name in writes.names:
            self._bind_name(name)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


class _ComprehensionWrites(IterativeNodeVisitor):
    def __init__(self):
        self.names = set()

    def visit_NamedExpr(self, node):
        if isinstance(node.target, ast.Name):
            self.names.add(node.target.id)
        self.visit(node.value)

    def visit_Lambda(self, node):
        pass


def _scope_bindings(node):
    bindings = _Bindings()
    for statement in node.body:
        bindings.visit(statement)
    return bindings


def _parameters(node):
    args = node.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _bound_names(node):
    bindings = _scope_bindings(node)
    bindings.names.update(_parameters(node))
    return bindings.names - bindings.nonlocals


@dataclass
class ReceiverUsage:
    attributes: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)


class _ReceiverVisitor(IterativeNodeVisitor):
    def __init__(self, receiver, node):
        self.aliases = {receiver}
        self.usage = ReceiverUsage()
        self._unstable_captures = self._capture_mutations(node)
        self._class_closure_aliases = None
        self._class_nonlocals = set()

    def _enclosing_aliases(self):
        if self._class_closure_aliases is None:
            return self.aliases
        return (self._class_closure_aliases - self._class_nonlocals) | (
            self.aliases & self._class_nonlocals
        )

    @staticmethod
    def _capture_mutations(node):
        bindings = _scope_bindings(node)
        parameters = _parameters(node)
        return {
            name
            for name, count in bindings.counts.items()
            if count > 1 or name in parameters
        }

    def _body(self, statements, aliases):
        saved = self.aliases
        self.aliases = set(aliases)
        for statement in statements:
            self.visit(statement)
        result = self.aliases
        self.aliases = saved
        return result

    def _bind(self, target, receiver=False, value=None):
        if isinstance(target, ast.Name):
            self.aliases.discard(target.id)
            if receiver:
                self.aliases.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if (
                isinstance(value, (ast.Tuple, ast.List))
                and len(target.elts) == len(value.elts)
                and not any(isinstance(child, ast.Starred) for child in target.elts)
            ):
                # Evaluate identities before any target can overwrite a source.
                identities = [
                    (isinstance(expr, ast.Name) and expr.id in self.aliases, expr)
                    for expr in value.elts
                ]
                for child, (identity, expr) in zip(target.elts, identities):
                    self._bind(child, identity, expr)
            else:
                for child in target.elts:
                    self._bind(child)
        elif isinstance(target, ast.Starred):
            self._bind(target.value)
        else:
            self.visit(target)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id in self.aliases:
            self.usage.attributes.add(node.attr)
            if isinstance(node.ctx, ast.Store):
                self.usage.writes.add(node.attr)
        self.generic_visit(node)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.aliases
        ):
            self.usage.calls.add(node.func.attr)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self.visit(node.value)
        receiver = isinstance(node.value, ast.Name) and node.value.id in self.aliases
        for target in node.targets:
            self._bind(target, receiver, node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            receiver = (
                isinstance(node.value, ast.Name) and node.value.id in self.aliases
            )
            self._bind(node.target, receiver)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        receiver = isinstance(node.value, ast.Name) and node.value.id in self.aliases
        self._bind(node.target, receiver)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self._bind(node.target)

    def visit_Delete(self, node):
        for target in node.targets:
            self._bind(target)

    def visit_If(self, node):
        self.visit(node.test)
        before = set(self.aliases)
        self.aliases = self._body(node.body, before) & self._body(node.orelse, before)

    def visit_IfExp(self, node):
        self.visit(node.test)
        before = set(self.aliases)
        self.aliases = self._body([node.body], before) & self._body(
            [node.orelse], before
        )

    def visit_BoolOp(self, node):
        self.visit(node.values[0])
        for expression in node.values[1:]:
            before = set(self.aliases)
            self.visit(expression)
            self.aliases &= before

    def visit_For(self, node):
        self.visit(node.iter)
        before = set(self.aliases)
        self._bind(node.target)
        after = self._body(node.body, self.aliases)
        self.aliases = self._body(node.orelse, before & after)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        before = set(self.aliases)
        after = self._body(node.body, before)
        self.aliases = self._body(node.orelse, before & after)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._bind(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_Try(self, node):
        before = set(self.aliases)
        after = self._body(node.body, before)
        normal = self._body(node.orelse, after)
        # A handler can run before any particular body assignment completes.
        bindings = _Bindings()
        for statement in node.body:
            bindings.visit(statement)
        handlers = []
        for handler in node.handlers:
            aliases = before - bindings.names
            if handler.name:
                aliases.discard(handler.name)
            if handler.type:
                self.visit(handler.type)
            handlers.append(self._body(handler.body, aliases))
        joined = set.intersection(normal, *handlers) if handlers else normal
        self.aliases = self._body(node.finalbody, joined)

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        before = set(self.aliases)
        outcomes = [before]
        for case in node.cases:
            bindings = _Bindings()
            bindings.visit(case.pattern)
            self.aliases = before - bindings.names
            self.visit(case.pattern)
            if case.guard:
                self.visit(case.guard)
            outcomes.append(self._body(case.body, self.aliases))
        self.aliases = set.intersection(*outcomes)

    def visit_FunctionDef(self, node):
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for decorator in node.decorator_list:
            self.visit(decorator)
        enclosing = self._enclosing_aliases()
        captured = enclosing - _bound_names(node) - self._unstable_captures
        saved_mutations = self._unstable_captures
        saved_class_closure = self._class_closure_aliases
        saved_class_nonlocals = self._class_nonlocals
        self._unstable_captures = self._capture_mutations(node)
        self._class_closure_aliases = None
        self._class_nonlocals = set()
        self._body(node.body, captured)
        self._unstable_captures = saved_mutations
        self._class_closure_aliases = saved_class_closure
        self._class_nonlocals = saved_class_nonlocals
        self.aliases.discard(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        bindings = _Bindings()
        bindings.visit(node.body)
        enclosing = self._enclosing_aliases()
        captured = (
            enclosing - _parameters(node) - bindings.names - self._unstable_captures
        )
        saved_class_closure = self._class_closure_aliases
        saved_class_nonlocals = self._class_nonlocals
        self._class_closure_aliases = None
        self._class_nonlocals = set()
        self._body([node.body], captured)
        self._class_closure_aliases = saved_class_closure
        self._class_nonlocals = saved_class_nonlocals

    def visit_ClassDef(self, node):
        for expr in (*node.bases, *node.decorator_list):
            self.visit(expr)
        saved = self._class_closure_aliases
        saved_nonlocals = self._class_nonlocals
        # Class-body expressions see their namespace; method bodies skip it
        # and retain the enclosing function's unshadowed closure bindings.
        closure = self._enclosing_aliases()
        bindings = _Bindings()
        for statement in node.body:
            bindings.visit(statement)
        self._class_nonlocals = bindings.nonlocals
        self._class_closure_aliases = set(closure)
        after = self._body(node.body, closure)
        self._class_closure_aliases = saved
        self._class_nonlocals = saved_nonlocals
        # Nonlocal assignments execute eagerly during class construction.
        self.aliases.difference_update(bindings.nonlocals)
        self.aliases.update(after & bindings.nonlocals)
        self.aliases.discard(node.name)

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases.discard(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.aliases.discard(alias.asname or alias.name)

    def visit_ListComp(self, node):
        self.visit(node.generators[0].iter)
        before = set(self.aliases)
        saved_class_closure = self._class_closure_aliases
        if saved_class_closure is not None:
            self.aliases = set(self._enclosing_aliases())
        self._class_closure_aliases = None
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self._bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        writes = _ComprehensionWrites()
        writes.visit(node)
        self.aliases = before - (writes.names - self.aliases)
        self._class_closure_aliases = saved_class_closure

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_GeneratorExp(self, node):
        # Only the first iterable is evaluated when the generator is created.
        self.visit(node.generators[0].iter)
        before = set(self.aliases)
        saved_class_closure = self._class_closure_aliases
        if saved_class_closure is not None:
            self.aliases = set(self._enclosing_aliases())
        self._class_closure_aliases = None
        self.aliases -= self._unstable_captures
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self._bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        self.visit(node.elt)
        self.aliases = before
        self._class_closure_aliases = saved_class_closure


def receiver_usage(
    node: ast.FunctionDef | ast.AsyncFunctionDef, *, kinds=None
) -> ReceiverUsage:
    receiver = method_receiver(node, kinds=kinds)
    if receiver is None:
        return ReceiverUsage()
    visitor = _ReceiverVisitor(receiver, node)
    for statement in node.body:
        visitor.visit(statement)
    return visitor.usage
