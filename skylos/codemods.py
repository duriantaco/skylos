from __future__ import annotations
import libcst as cst
from libcst.metadata import PositionProvider

def _bound_name_for_import_alias(alias: cst.ImportAlias):
    if alias.asname:
        return alias.asname.name.value
    node = alias.name
    while isinstance(node, cst.Attribute):
        node = node.value
    return node.value 

class _RemoveImportAtLine(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_name, target_line):
        self.target_name = target_name
        self.target_line = target_line
        self.changed = False

    def _is_target_line(self, node: cst.CSTNode):
        pos = self.get_metadata(PositionProvider, node, None)
        return bool(pos and pos.start.line == self.target_line)

    def _filter_aliases(self, aliases):
        kept = []
        for alias in aliases:
            bound = _bound_name_for_import_alias(alias)
            if bound == self.target_name:
                self.changed = True
                continue
            kept.append(alias)
        return kept

    def leave_Import(self, orig: cst.Import, updated: cst.Import):
        if not self._is_target_line(orig):
            return updated
        kept = self._filter_aliases(updated.names)
        if not kept:
            return cst.RemoveFromParent()
        return updated.with_changes(names=tuple(kept))

    def leave_ImportFrom(self, orig: cst.ImportFrom, updated: cst.ImportFrom):
        if not self._is_target_line(orig):
            return updated
        if isinstance(updated.names, cst.ImportStar):
            return updated 
        kept = self._filter_aliases(list(updated.names))
        if not kept:
            return cst.RemoveFromParent()

        return updated.with_changes(names=tuple(kept))

class _RemoveFunctionAtLine(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, func_name, target_line):
        self.func_name = func_name
        self.target_line = target_line
        self.changed = False

    def _is_target(self, node: cst.CSTNode):
        pos = self.get_metadata(PositionProvider, node, None)
        return bool(pos and pos.start.line == self.target_line)

    def leave_FunctionDef(self, orig: cst.FunctionDef, updated: cst.FunctionDef):
        if self._is_target(orig) and (orig.name.value in self.func_name):
            self.changed = True
            return cst.RemoveFromParent()
        return updated

    def leave_AsyncFunctionDef(self, orig: cst.AsyncFunctionDef, updated: cst.AsyncFunctionDef):
        if self._is_target(orig) and (orig.name.value in self.func_name):
            self.changed = True
            return cst.RemoveFromParent()

        return updated

def remove_unused_import_cst(code, import_name, line_number):
    wrapper = cst.MetadataWrapper(cst.parse_module(code))
    tx = _RemoveImportAtLine(import_name, line_number)
    new_mod = wrapper.visit(tx)
    return new_mod.code, tx.changed

def remove_unused_function_cst(code, func_name, line_number):
    wrapper = cst.MetadataWrapper(cst.parse_module(code))
    tx = _RemoveFunctionAtLine(func_name, line_number)
    new_mod = wrapper.visit(tx)
    return new_mod.code, tx.changed
