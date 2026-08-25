from __future__ import annotations

import ast
from dataclasses import dataclass


_SQLALCHEMY_ROOT = "sqlalchemy"


@dataclass(frozen=True)
class _ImportBinding:
    qualified_name: str


@dataclass
class _ScopeFrame:
    kind: str
    bindings: dict[str, _ImportBinding | None]
    lookup_parent: _ScopeFrame | None
    active_bindings: dict[str, _ImportBinding | None] | None = None


def _is_absolute_sqlalchemy_module(module: str | None, level: int = 0) -> bool:
    return bool(
        level == 0
        and module
        and (module == _SQLALCHEMY_ROOT or module.startswith(f"{_SQLALCHEMY_ROOT}."))
    )


def _import_bindings(
    node: ast.Import | ast.ImportFrom,
) -> list[tuple[str, _ImportBinding | None]]:
    bindings: list[tuple[str, _ImportBinding | None]] = []

    if isinstance(node, ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            if _is_absolute_sqlalchemy_module(alias.name):
                resolved = alias.name if alias.asname else local
                bindings.append((local, _ImportBinding(resolved)))
            else:
                bindings.append((local, None))
        return bindings

    module = node.module
    is_sqlalchemy = _is_absolute_sqlalchemy_module(module, node.level)
    for alias in node.names:
        if alias.name == "*":
            if is_sqlalchemy and module:
                bindings.append(("text", _ImportBinding(f"{module}.text")))
            continue

        local = alias.asname or alias.name
        if is_sqlalchemy and module:
            bindings.append((local, _ImportBinding(f"{module}.{alias.name}")))
        else:
            bindings.append((local, None))
    return bindings


class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect bindings in one lexical scope without entering child scopes."""

    def __init__(self) -> None:
        self.candidates: dict[str, list[_ImportBinding | None]] = {}
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def _record(self, name: str, binding: _ImportBinding | None) -> None:
        self.candidates.setdefault(name, []).append(binding)

    def visit_Import(self, node: ast.Import) -> None:
        for name, binding in _import_bindings(node):
            self._record(name, binding)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for name, binding in _import_bindings(node):
            self._record(name, binding)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._record(node.id, None)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record(node.name, None)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record(node.name, None)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record(node.name, None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def _visit_comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None:
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._record(node.name, None)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)


def _collect_scope(
    node: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> _ScopeBindingCollector:
    collector = _ScopeBindingCollector()
    for statement in node.body:
        collector.visit(statement)
    return collector


def _module_bindings(tree: ast.AST) -> dict[str, _ImportBinding | None]:
    if not isinstance(tree, ast.Module):
        return {}

    bindings: dict[str, _ImportBinding | None] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for name, binding in _import_bindings(statement):
                bindings[name] = binding
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            bindings[statement.name] = None
        else:
            collector = _ScopeBindingCollector()
            collector.visit(statement)
            for name in collector.candidates:
                bindings[name] = None
    return bindings


def _function_local_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    collector = _collect_scope(node)
    names = set(collector.candidates)
    arguments = [
        *getattr(node.args, "posonlyargs", []),
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if node.args.vararg:
        arguments.append(node.args.vararg)
    if node.args.kwarg:
        arguments.append(node.args.kwarg)
    names.update(argument.arg for argument in arguments)
    names.difference_update(collector.global_names)
    names.difference_update(collector.nonlocal_names)
    return names


class SQLAlchemyTextProvenance:
    """Resolve ``text`` calls only through proven absolute SQLAlchemy imports."""

    def __init__(self, tree: ast.AST) -> None:
        module = _ScopeFrame(
            kind="module",
            bindings=_module_bindings(tree),
            lookup_parent=None,
            active_bindings={},
        )
        self._module = module
        self._scope_stack = [module]

    @property
    def _current(self) -> _ScopeFrame:
        return self._scope_stack[-1]

    def enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        lookup_parent = self._current
        while lookup_parent.kind == "class" and lookup_parent.lookup_parent:
            lookup_parent = lookup_parent.lookup_parent
        bindings = {name: None for name in _function_local_names(node)}
        self._scope_stack.append(
            _ScopeFrame("function", bindings, lookup_parent=lookup_parent)
        )

    def enter_class(self, node: ast.ClassDef) -> None:
        collector = _collect_scope(node)
        bindings = {name: None for name in collector.candidates}
        self._scope_stack.append(
            _ScopeFrame("class", bindings, lookup_parent=self._current)
        )

    def enter_lambda(self, node: ast.Lambda) -> None:
        lookup_parent = self._current
        while lookup_parent.kind == "class" and lookup_parent.lookup_parent:
            lookup_parent = lookup_parent.lookup_parent
        arguments = [
            *getattr(node.args, "posonlyargs", []),
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg:
            arguments.append(node.args.vararg)
        if node.args.kwarg:
            arguments.append(node.args.kwarg)
        collector = _ScopeBindingCollector()
        collector.visit(node.body)
        names = set(collector.candidates)
        names.update(argument.arg for argument in arguments)
        bindings = {name: None for name in names}
        self._scope_stack.append(
            _ScopeFrame("function", bindings, lookup_parent=lookup_parent)
        )

    def enter_comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None:
        names: set[str] = set()
        for generator in node.generators:
            names.update(
                child.id
                for child in ast.walk(generator.target)
                if isinstance(child, ast.Name)
            )
        bindings = {name: None for name in names}
        self._scope_stack.append(
            _ScopeFrame("comprehension", bindings, lookup_parent=self._current)
        )

    def leave_scope(self) -> None:
        if len(self._scope_stack) > 1:
            self._scope_stack.pop()

    def record_import(self, node: ast.Import | ast.ImportFrom) -> None:
        target = self._current
        destination = (
            target.active_bindings if target.kind == "module" else target.bindings
        )
        if destination is None:
            return
        for name, binding in _import_bindings(node):
            destination[name] = binding

    def record_name_binding(self, name: str) -> None:
        target = self._current
        destination = (
            target.active_bindings if target.kind == "module" else target.bindings
        )
        if destination is not None:
            destination[name] = None

    def _lookup(self, name: str) -> _ImportBinding | None:
        use_precollected_module = any(
            scope.kind == "function" for scope in self._scope_stack
        )
        scope: _ScopeFrame | None = self._current
        while scope is not None:
            if scope.kind == "module" and not use_precollected_module:
                bindings = scope.active_bindings or {}
            else:
                bindings = scope.bindings
            if name in bindings:
                return bindings[name]
            scope = scope.lookup_parent
        return None

    def is_text_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        attributes: list[str] = []
        while isinstance(func, ast.Attribute):
            attributes.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            return False

        binding = self._lookup(func.id)
        if binding is None:
            return False

        attributes.reverse()
        qualified_name = ".".join([binding.qualified_name, *attributes])
        return qualified_name.startswith("sqlalchemy.") and qualified_name.endswith(
            ".text"
        )
