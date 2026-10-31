from __future__ import annotations

import ast
from collections.abc import Iterable

_BUILTIN_MODULES = frozenset({"builtins", "__builtins__"})
_GLOBAL_NAMESPACES = frozenset({"globals", "vars"})
_NAMESPACE_WRITES = frozenset({"update", "setdefault", "__setitem__", "pop", "clear"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_DYNAMIC_CODE = frozenset({"exec", "eval"})


class _Scope:
    def __init__(self, kind: str, parent: _Scope | None) -> None:
        self.kind = kind
        self.parent = parent
        self.bound: set[str] = set()
        self.declared_global: set[str] = set()
        self.declared_nonlocal: set[str] = set()


class _ScopeBuilder:
    def __init__(
        self, names: frozenset[str], isolated_runners: frozenset[int] = frozenset()
    ) -> None:
        self.names = names
        self.isolated_runners = isolated_runners
        self.module = _Scope("module", None)
        self.loads: list[tuple[ast.Name, _Scope]] = []
        self.dynamic_globals = False
        self.dynamic_builtins = False
        self.rebound_attributes: set[str] = set()
        self.builtin_aliases: set[str] = set(_BUILTIN_MODULES)
        self.attribute_reads: set[int] = set()

    def visit(self, node: ast.AST, scope: _Scope) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function(node, scope)
        elif isinstance(node, ast.Lambda):
            self._lambda(node, scope)
        elif isinstance(node, ast.ClassDef):
            self._class(node, scope)
        elif isinstance(node, _COMPREHENSIONS):
            self._comprehension(node, scope)
        elif isinstance(node, ast.Name):
            self._name(node, scope)
        elif isinstance(node, ast.NamedExpr):
            self._named_expression(node, scope)
        elif isinstance(node, ast.Global):
            scope.declared_global.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.declared_nonlocal.update(node.names)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            self._import(node, scope)
        else:
            self._binding_node(node, scope)
            self._namespace_write(node)
            self._builtin_module_use(node)
            self.visit_all(ast.iter_child_nodes(node), scope)

    def visit_all(self, nodes: Iterable[ast.AST], scope: _Scope) -> None:
        for node in nodes:
            self.visit(node, scope)

    def bind(self, scope: _Scope, name: str) -> None:
        if name in scope.declared_global:
            self.module.bound.add(name)
        elif name not in scope.declared_nonlocal:
            scope.bound.add(name)

    def _function(self, node, scope: _Scope) -> None:
        self.bind(scope, node.name)
        self.visit_all(node.decorator_list, scope)
        self._signature(node.args, node.returns, scope)
        inner = _Scope("function", self._type_parameter_scope(node, scope))
        self._parameters(node.args, inner)
        self.visit_all(node.body, inner)

    def _lambda(self, node: ast.Lambda, scope: _Scope) -> None:
        self.visit_all(node.args.defaults, scope)
        self.visit_all([d for d in node.args.kw_defaults if d is not None], scope)
        inner = _Scope("function", scope)
        self._parameters(node.args, inner)
        self.visit(node.body, inner)

    def _class(self, node: ast.ClassDef, scope: _Scope) -> None:
        self.bind(scope, node.name)
        self.visit_all(node.decorator_list, scope)
        self.visit_all(node.bases, scope)
        self.visit_all(node.keywords, scope)
        inner = _Scope("class", self._type_parameter_scope(node, scope))
        self.visit_all(node.body, inner)

    def _type_parameter_scope(self, node: ast.AST, scope: _Scope) -> _Scope:
        parameters = getattr(node, "type_params", None) or []
        if not parameters:
            return scope
        annotations = _Scope("function", scope)
        for parameter in parameters:
            annotations.bound.add(parameter.name)
        return annotations

    def _signature(self, args: ast.arguments, returns, scope: _Scope) -> None:
        self.visit_all(args.defaults, scope)
        self.visit_all([d for d in args.kw_defaults if d is not None], scope)
        for argument in _arguments(args):
            if argument.annotation is not None:
                self.visit(argument.annotation, scope)
        if returns is not None:
            self.visit(returns, scope)

    def _parameters(self, args: ast.arguments, scope: _Scope) -> None:
        for argument in _arguments(args):
            scope.bound.add(argument.arg)

    def _comprehension(self, node, scope: _Scope) -> None:
        generators = node.generators
        self.visit(generators[0].iter, scope)
        inner = _Scope("comprehension", scope)
        for index, generator in enumerate(generators):
            if index:
                self.visit(generator.iter, inner)
            self.visit(generator.target, inner)
            self.visit_all(generator.ifs, inner)
        if isinstance(node, ast.DictComp):
            self.visit(node.key, inner)
            self.visit(node.value, inner)
        else:
            self.visit(node.elt, inner)

    def _name(self, node: ast.Name, scope: _Scope) -> None:
        if not isinstance(node.ctx, ast.Load):
            self.bind(scope, node.id)
            return
        if node.id in self.names:
            self.loads.append((node, scope))
        if node.id in _DYNAMIC_CODE and id(node) not in self.isolated_runners:
            self.dynamic_globals = True
        if node.id in self.builtin_aliases and id(node) not in self.attribute_reads:
            self.dynamic_builtins = True

    def _builtin_module_use(self, node: ast.AST) -> None:
        if isinstance(node, ast.Constant) and node.value in _BUILTIN_MODULES:
            self.dynamic_builtins = True
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr != "__dict__"
            and _is_name(node.value, self.builtin_aliases)
        ):
            self.attribute_reads.add(id(node.value))

    def _named_expression(self, node: ast.NamedExpr, scope: _Scope) -> None:
        owner = scope
        while owner.kind == "comprehension" and owner.parent is not None:
            owner = owner.parent
        self.bind(owner, node.target.id)
        self.visit(node.value, scope)

    def _import(self, node, scope: _Scope) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.dynamic_globals = True
                continue
            local = alias.asname or alias.name.split(".", 1)[0]
            self.bind(scope, local)
            if isinstance(node, ast.Import) and alias.name in _BUILTIN_MODULES:
                self.builtin_aliases.add(local)

    def _binding_node(self, node: ast.AST, scope: _Scope) -> None:
        if isinstance(node, ast.ExceptHandler) and node.name:
            self.bind(scope, node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            self.bind(scope, node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self.bind(scope, node.rest)
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and not isinstance(
            node.ctx, ast.Load
        ):
            if _is_name(node.value, _BUILTIN_MODULES):
                self.dynamic_builtins = True
            elif _is_namespace(node.value):
                self.dynamic_globals = True
            elif isinstance(node, ast.Attribute) and node.attr in self.names:
                self.rebound_attributes.add(node.attr)

    def _namespace_write(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _NAMESPACE_WRITES:
            if _is_namespace(func.value):
                self.dynamic_globals = True
            elif _is_name(func.value, _BUILTIN_MODULES):
                self.dynamic_builtins = True
        if _is_name(func, {"setattr", "delattr"}) and node.args:
            attribute = None
            if len(node.args) > 1:
                attribute = node.args[1]
            if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
                self.rebound_attributes.add(attribute.value)
            elif _is_name(node.args[0], _BUILTIN_MODULES):
                self.dynamic_builtins = True

    def resolves_to_builtin(self, name: str, scope: _Scope) -> bool:
        if self.dynamic_builtins or name in self.rebound_attributes:
            return False
        current = scope
        first = True
        while current.parent is not None:
            if name in current.declared_global:
                break
            if current.kind != "class" or first:
                if name in current.bound or name in current.declared_nonlocal:
                    return False
            first = False
            current = current.parent
        return not self.dynamic_globals and name not in self.module.bound


def _arguments(args: ast.arguments) -> list[ast.arg]:
    found = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg is not None:
        found.append(args.vararg)
    if args.kwarg is not None:
        found.append(args.kwarg)
    return found


def _is_name(node: ast.AST, names) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def _is_namespace(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return _is_name(node.func, _GLOBAL_NAMESPACES)
    return isinstance(node, ast.Attribute) and node.attr == "__dict__"


def builtin_references(
    tree: ast.AST,
    names: Iterable[str],
    *,
    isolated_code_calls: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Ids of ``Name`` loads of ``names`` that resolve to the builtins.

    ``isolated_code_calls`` are ids of ``exec``/``eval`` calls proved to run
    in a fresh namespace dict; they cannot bind this module's globals."""
    runners: frozenset[int] = frozenset()
    if isolated_code_calls:
        runners = frozenset(
            id(node.func)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and id(node) in isolated_code_calls
        )
    builder = _ScopeBuilder(frozenset(names), runners)
    try:
        if isinstance(tree, ast.Module):
            builder.visit_all(tree.body, builder.module)
        else:
            builder.visit(tree, builder.module)
    except RecursionError:
        return frozenset()
    return frozenset(
        id(node)
        for node, scope in builder.loads
        if builder.resolves_to_builtin(node.id, scope)
    )
