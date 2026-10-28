"""Source-owned reads of module-level type-checking import bindings.

The legacy symbol graph merges imports of the same provider in one file.
A read through a function-local import must not keep an unread outer import
alive. This proof only narrows that same-file credit; exports and references
from other modules still use the normal graph and verification paths.
"""

from __future__ import annotations

import ast

from skylos.deadcode._reachability_bindings import (
    BoundNames,
    argument_nodes,
    bound_names,
    namespace_name,
)
from skylos.rules.quality._protocols import type_checking_context


class _FunctionBindings(BoundNames):
    def visit_ListComp(self, node):
        # Iteration targets belong to the comprehension. Walrus assignments
        # in its expressions can still bind names in the containing function.
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


class _ModuleImportReads(ast.NodeVisitor):
    def __init__(self, names):
        self.names = names
        self.read = set()
        self.shadowed = set()
        self.class_name = ""

    def _name(self, name):
        return namespace_name(self.class_name, name)

    def visit_Name(self, node):
        name = self._name(node.id)
        if isinstance(node.ctx, ast.Load) and name not in self.shadowed:
            self.read.add(name)

    def visit_Constant(self, node):
        # Retain forward annotations, __all__ and possible dynamic string
        # lookups conservatively. Ordinary prose is not a Python expression.
        if not isinstance(node.value, str):
            return
        pending = [(node.value, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 8:
                self.read.update(self.names)
                return
            try:
                expression = ast.parse(value, mode="eval")
            except (SyntaxError, ValueError, RecursionError):
                continue
            for child in ast.walk(expression):
                if isinstance(child, ast.Name):
                    # Quoted annotations are not compiled identifiers. Keep
                    # both spellings when a class may resolve the annotation.
                    self.read.update(
                        {child.id, self._name(child.id)} - self.shadowed
                    )
                elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                    pending.append((child.value, depth + 1))

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in {
            "globals", "locals", "vars", "eval", "exec",
        }:
            self.read.update(self.names)
        self.generic_visit(node)

    def visit_Global(self, node):
        self.read.update(self._name(name) for name in node.names)

    visit_Nonlocal = visit_Global

    def visit_FunctionDef(self, node):
        # Signatures and defaults resolve in the enclosing scope, before the
        # body's local imports exist. Nested functions inherit local bindings.
        arguments = list(argument_nodes(node.args))
        for expression in [
            *node.decorator_list,
            *node.args.defaults,
            *(item for item in node.args.kw_defaults if item is not None),
            *(item.annotation for item in arguments if item.annotation),
            *([node.returns] if node.returns else []),
            *getattr(node, "type_params", ()),
        ]:
            self.visit(expression)
        previous = self.shadowed
        bindings = _FunctionBindings()
        for statement in node.body:
            bindings.visit(statement)
        self.shadowed = previous | {self._name(name) for name in bindings.counts} | {
            self._name(item.arg) for item in arguments
        }
        for statement in node.body:
            self.visit(statement)
        self.shadowed = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in [
            *node.decorator_list,
            *node.bases,
            *(item.value for item in node.keywords),
        ]:
            self.visit(expression)
        previous = self.class_name
        self.class_name = node.name
        for child in [*getattr(node, "type_params", ()), *node.body]:
            self.visit(child)
        self.class_name = previous

    def visit_Lambda(self, node):
        for expression in [
            *node.args.defaults,
            *(item for item in node.args.kw_defaults if item is not None),
        ]:
            self.visit(expression)
        previous = self.shadowed
        self.shadowed = previous | {
            self._name(item.arg) for item in argument_nodes(node.args)
        }
        self.visit(node.body)
        self.shadowed = previous


def unread_type_checking_imports(tree: ast.Module):
    """Map an unread outer import's line/provider leaf to its binding facts.

    Multiple module bindings and unsupported dynamic scope writes are retained
    conservatively. Class bodies do not introduce function-local shadowing:
    methods can still read a module binding even if the class binds its name.
    """
    _, guarded = type_checking_context(tree)
    if not guarded:
        return {}
    counts = bound_names(tree.body).counts
    imports = []

    def collect(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)) and id(node) in guarded:
            for alias in node.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                if alias.name != "*" and counts[name] == 1:
                    imports.append((node, alias, name))
        for child in ast.iter_child_nodes(node):
            collect(child)

    collect(tree)
    if not imports:
        return {}
    reads = _ModuleImportReads({name for _, _, name in imports})
    reads.visit(tree)
    result = {}
    ambiguous = set()
    for node, alias, name in imports:
        provider_leaf = (
            alias.name.rsplit(".", 1)[-1]
            if isinstance(node, ast.ImportFrom) or alias.asname
            else alias.name.split(".", 1)[0]
        )
        key = (alias.lineno, provider_leaf)
        if key in result or name in reads.read:
            ambiguous.add(key)
        result[key] = {
            "binding_name": name,
            "is_exported": alias.asname == alias.name,
            "suppression_lines": {alias.lineno, node.lineno, node.end_lineno},
        }
    return {key: value for key, value in result.items() if key not in ambiguous}
