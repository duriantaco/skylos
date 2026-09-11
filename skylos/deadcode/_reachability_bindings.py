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

    def visit_FunctionDef(self, node: FunctionNode | ast.ClassDef) -> None:
        self.counts[node.name] += 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit(self, node: ast.AST) -> None:
        """Skip lambda bodies, whose assignments have a separate scope."""
        if not isinstance(node, ast.Lambda):
            super().visit(node)

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


def bound_names(nodes: Iterable[ast.AST]) -> BoundNames:
    collector = BoundNames()
    for node in nodes:
        collector.visit(node)
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


def function_bindings(node: FunctionNode, module: ModuleInfo) -> tuple[Bindings, bool]:
    names = bound_names(node.body)
    parameters = {arg.arg for arg in argument_nodes(node.args)}
    local: Bindings = dict.fromkeys(names.counts.keys() | parameters)
    for statement in node.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            local.update(_stable_imports(statement, module, names.counts, parameters))
    return local, names.scope_writes


def _stable_imports(
    statement: ast.Import | ast.ImportFrom,
    module: ModuleInfo,
    counts: Counter[str],
    parameters: set[str],
) -> Bindings:
    return {
        name: value
        for name, value in import_bindings(statement, module).items()
        if counts[name] == 1 and name not in parameters
    }
