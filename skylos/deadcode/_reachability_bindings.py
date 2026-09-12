"""Lexical bindings used by the conservative Python reachability pass."""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

Binding = tuple[str, str]
Bindings = dict[str, Binding | None]
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
MODULE_BINDING = "module"
QUALIFIED_BINDING = "qualified"


def namespace_name(class_name: str, name: str) -> str:
    prefix = class_name.lstrip("_")
    if prefix and name.startswith("__") and not name.endswith("__"):
        return f"_{prefix}{name}"
    return name


class ScopeBindings(dict):
    """Bindings in a lexical scope, including Python's class-name mangling."""

    def __init__(self, values=(), *, class_name: str = "") -> None:
        super().__init__()
        self.class_name = class_name
        self.update(values)

    def __contains__(self, name):
        return super().__contains__(namespace_name(self.class_name, name))

    def __getitem__(self, name):
        return super().__getitem__(namespace_name(self.class_name, name))

    def __setitem__(self, name, value):
        super().__setitem__(namespace_name(self.class_name, name), value)

    def get(self, name, default=None):
        return super().get(namespace_name(self.class_name, name), default)

    def update(self, values):
        for name, value in dict(values).items():
            self[name] = value

    def copy(self):
        return ScopeBindings(self, class_name=self.class_name)


@dataclass
class ModuleInfo:
    path: Path
    tree: ast.Module
    names: set[str] = field(default_factory=set)
    bindings: Bindings = field(default_factory=dict)
    functions: dict[int, str] = field(default_factory=dict)


class BoundNames(ast.NodeVisitor):
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.scope_writes = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.counts[node.id] += 1

    def visit_FunctionDef(self, node: FunctionNode) -> None:
        self.counts[node.name] += 1
        for expression in [
            *node.decorator_list,
            *default_expressions(node.args),
            *(arg.annotation for arg in argument_nodes(node.args) if arg.annotation),
            *([node.returns] if node.returns else []),
        ]:
            self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.counts[node.name] += 1
        for expression in [
            *node.decorator_list,
            *node.bases,
            *(keyword.value for keyword in node.keywords),
        ]:
            self.visit(expression)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Defaults execute here; assignments in the deferred body do not.
        for expression in default_expressions(node.args):
            self.visit(expression)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.counts[alias.asname or alias.name.split(".")[0]] += 1

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.counts[alias.asname or alias.name] += 1

    def visit_Global(self, node: ast.Global | ast.Nonlocal) -> None:
        self.scope_writes = True
        self.counts.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.counts[node.name] += 1
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs | ast.MatchStar) -> None:
        if node.name:
            self.counts[node.name] += 1
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.counts[node.rest] += 1
        self.generic_visit(node)


def bound_names(nodes: Iterable[ast.AST], *, class_name: str = "") -> BoundNames:
    collector = BoundNames()
    for node in nodes:
        collector.visit(node)
    if class_name:
        counts: Counter[str] = Counter()
        for name, count in collector.counts.items():
            counts[namespace_name(class_name, name)] += count
        collector.counts = counts
    return collector


def _relative_parent(node: ast.ImportFrom, module: ModuleInfo) -> str | None:
    identities = {name for name in module.names if name}
    if len(identities) != 1:
        return None
    identity = next(iter(identities))
    package = (
        identity if module.path.name == "__init__.py" else identity.rpartition(".")[0]
    )
    parts = package.split(".") if package else []
    if node.level > len(parts):
        return None
    prefix = parts[: len(parts) - node.level + 1]
    if node.module:
        prefix.append(node.module)
    return ".".join(prefix)


def import_bindings(node: ast.Import | ast.ImportFrom, module: ModuleInfo) -> Bindings:
    if isinstance(node, ast.Import):
        return {_import_name(alias): _import_target(alias) for alias in node.names}
    parent = _relative_parent(node, module) if node.level else node.module or ""
    return _from_imports(node, parent)


def _from_imports(node: ast.ImportFrom, parent: str | None) -> Bindings:
    if parent is None:
        return {alias.asname or alias.name: None for alias in node.names}
    return {
        alias.asname or alias.name: (QUALIFIED_BINDING, f"{parent}.{alias.name}")
        for alias in node.names
        if alias.name != "*"
    }


def _import_name(alias: ast.alias) -> str:
    return alias.asname or alias.name.split(".")[0]


def _import_target(alias: ast.alias) -> Binding:
    return (MODULE_BINDING, alias.name if alias.asname else alias.name.split(".")[0])


def argument_nodes(arguments: ast.arguments) -> list[ast.arg]:
    named = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    return named + [
        arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None
    ]


def default_expressions(arguments: ast.arguments) -> list[ast.expr]:
    return [
        *arguments.defaults,
        *(value for value in arguments.kw_defaults if value is not None),
    ]


def function_bindings(
    node: FunctionNode, module: ModuleInfo, *, class_name: str = ""
) -> tuple[Bindings, bool]:
    names = bound_names(node.body, class_name=class_name)
    parameters = {
        namespace_name(class_name, arg.arg) for arg in argument_nodes(node.args)
    }
    local = ScopeBindings(
        dict.fromkeys(names.counts.keys() | parameters), class_name=class_name
    )
    for statement in node.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            local.update(
                _stable_imports(statement, module, names.counts, parameters, class_name)
            )
    return local, names.scope_writes


def _stable_imports(
    statement: ast.Import | ast.ImportFrom,
    module: ModuleInfo,
    counts: Counter[str],
    parameters: set[str],
    class_name: str = "",
) -> Bindings:
    return {
        name: value
        for name, value in import_bindings(statement, module).items()
        if counts[namespace_name(class_name, name)] == 1
        and namespace_name(class_name, name) not in parameters
    }
