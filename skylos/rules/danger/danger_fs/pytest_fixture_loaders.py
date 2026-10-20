"""Distinguish module metadata lookup from dynamic function dispatch."""

from __future__ import annotations

import ast
import copy

from skylos.rules.danger.danger_fs.closed_world import _Names, _computed_loader
from skylos.rules.danger.danger_fs.pytest_fixture_bindings import binding_escapes

_SPEC_METADATA = {
    "origin",
    "name",
    "parent",
    "cached",
    "has_location",
    "submodule_search_locations",
}


def has_unknown_fixture_loader(tree, source):
    """Keep unknown loading; a source-resolved metadata-only lookup is narrower.

    find_spec may import parent packages. This exception establishes only that
    the inspected code does not obtain/call a test function through the result.
    Project imports, explicit calls, provider overrides and other loaders are
    checked separately. An unknown finder or escaped ModuleSpec is not exempt.
    """
    try:
        if not _computed_loader(tree):
            return False
    except (RecursionError, MemoryError):
        return True
    names = _Names(tree)
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    replace = set()
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        if names.dotted(call.func) != "importlib.util.find_spec":
            continue
        root = call.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or binding_escapes(tree, root.id):
            continue
        parent = parents.get(call)
        if not isinstance(parent, ast.Assign) or len(parent.targets) != 1:
            continue
        target = parent.targets[0]
        if not isinstance(target, ast.Name):
            continue
        uses = []
        stores = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == target.id:
                if isinstance(node.ctx, ast.Load):
                    uses.append(node)
                elif isinstance(node.ctx, (ast.Store, ast.Del)):
                    stores.append(node)
        if len(stores) != 1 or not uses:
            continue
        metadata_only = True
        for use in uses:
            owner = parents.get(use)
            if (
                isinstance(owner, ast.Attribute)
                and owner.attr in _SPEC_METADATA
                and isinstance(owner.ctx, ast.Load)
            ):
                continue
            if isinstance(owner, ast.Compare):
                if len(owner.ops) == 1 and isinstance(
                    owner.ops[0], (ast.Is, ast.IsNot)
                ):
                    values = [owner.left, *owner.comparators]
                    has_none = False
                    for value in values:
                        if isinstance(value, ast.Constant) and value.value is None:
                            has_none = True
                    if has_none:
                        continue
            metadata_only = False
            break
        if metadata_only:
            replace.add((call.lineno, call.col_offset))
    if not replace:
        return True

    class WithoutMetadataQueries(ast.NodeTransformer):
        def visit_Call(self, node):
            if (node.lineno, node.col_offset) in replace:
                return ast.copy_location(ast.Constant(value=None), node)
            return self.generic_visit(node)

    remainder = WithoutMetadataQueries().visit(copy.deepcopy(tree))
    try:
        return _computed_loader(remainder)
    except (RecursionError, MemoryError):
        return True
