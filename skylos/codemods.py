from __future__ import annotations

import libcst as cst
from libcst.helpers import get_full_name_for_node
from libcst.metadata import PositionProvider

class _CommentOutBlock(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, module_code: str, marker: str = "SKYLOS DEADCODE"):
        self.module_code = module_code.splitlines(True)
        self.marker = marker

    def _comment_block(self, start_line, end_line):
        lines = self.module_code[start_line - 1 : end_line]
        out: list[cst.EmptyLine] = []

        out.append(
            cst.EmptyLine(
                comment=cst.Comment(
                    f"# {self.marker} START (lines {start_line}-{end_line})"
                )
            )
        )

        for raw in lines:
            out.append(cst.EmptyLine(comment=cst.Comment("# " + raw.rstrip("\n"))))

        out.append(cst.EmptyLine(comment=cst.Comment(f"# {self.marker} END")))
        return out

    def _replace_statement_with_comment_block(
        self, orig_stmt: cst.SimpleStatementLine
    ) -> cst.SimpleStatementLine:
      
        pos = self.get_metadata(PositionProvider, orig_stmt)
        leading = self._comment_block(pos.start.line, pos.end.line)

        return cst.SimpleStatementLine(
            body=[cst.Pass()],
            leading_lines=leading,
        )


class _CommentOutFunctionAtLine(_CommentOutBlock):
    def __init__(self, func_name, target_line, module_code, marker):
        super().__init__(module_code, marker)
        self.func_name = func_name
        self.target_line = target_line
        self.changed = False

    def _is_target(self, node: cst.CSTNode):
        pos = self.get_metadata(PositionProvider, node, None)
        return bool(pos and pos.start.line == self.target_line)

    def leave_FunctionDef(self, orig: cst.FunctionDef, updated: cst.FunctionDef):
        target = self.func_name.split(".")[-1]
        if self._is_target(orig) and orig.name.value == target:
            self.changed = True
            pos = self.get_metadata(PositionProvider, orig)
            leading = self._comment_block(pos.start.line, pos.end.line)
            return cst.SimpleStatementLine(body=[cst.Pass()], leading_lines=leading)
        return updated

    def leave_AsyncFunctionDef(
        self, orig: cst.AsyncFunctionDef, updated: cst.AsyncFunctionDef
    ):
        target = self.func_name.split(".")[-1]
        if self._is_target(orig) and orig.name.value == target:
            self.changed = True
            pos = self.get_metadata(PositionProvider, orig)
            leading = self._comment_block(pos.start.line, pos.end.line)
            return cst.SimpleStatementLine(body=[cst.Pass()], leading_lines=leading)
        return updated


class _CommentOutImportAtLine(_CommentOutBlock):
    def __init__(self, target_name, target_line, module_code, marker):
        super().__init__(module_code, marker)
        self.target_name = target_name
        self.target_line = target_line
        self.changed = False

    def _is_target_line(self, node: cst.CSTNode):
        pos = self.get_metadata(PositionProvider, node, None)
        return bool(pos and (pos.start.line <= self.target_line <= pos.end.line))

    def _name_code(self, node: cst.CSTNode):
        code = get_full_name_for_node(node) or ""
        if code:
            return code
        if hasattr(node, "value"):
            v = getattr(node, "value")
            if isinstance(v, str):
                return v
        return ""

    def _render_single_alias_text(self, head, alias: cst.ImportAlias, is_from):
        name_code = self._name_code(alias.name)
        alias_txt = name_code
        if alias.asname:
            alias_txt = f"{alias_txt} as {alias.asname.name.value}"

        if is_from:
            return f"from {head} import {alias_txt}"
        return f"import {alias_txt}"

    def _split_aliases(self, aliases, head, is_from):
        kept = []
        removed_for_comment: list[str] = []

        for alias in list(aliases):
            bound = _bound_name_for_import_alias(alias)

            if (not is_from) and _is_plain_dotted_import(alias):
                match_keys = {bound}
            else:
                name_code = self._name_code(alias.name)
                tail = name_code.split(".")[-1] if name_code else ""
                if tail:
                    match_keys = {bound, tail}
                else:
                    match_keys = {bound}

            if self.target_name in match_keys:
                self.changed = True
                removed_for_comment.append(self._render_single_alias_text(head, alias, is_from))
            else:
                kept.append(alias)

        return kept, removed_for_comment

    def _add_leading_comment_line(
        self, line: cst.SimpleStatementLine, text
    ) -> cst.SimpleStatementLine:
        comment = cst.EmptyLine(comment=cst.Comment(f"# {text}"))
        leading = list(line.leading_lines)
        leading.append(comment)
        return line.with_changes(leading_lines=leading)

    def leave_SimpleStatementLine(
        self, orig: cst.SimpleStatementLine, updated: cst.SimpleStatementLine
    ):
        if not self._is_target_line(orig):
            return updated

        if len(updated.body) != 1:
            return updated

        stmt = updated.body[0]

        if isinstance(stmt, cst.Import):
            kept, removed = self._split_aliases(stmt.names, head="", is_from=False)
            if not removed:
                return updated

            if not kept:
                return self._replace_statement_with_comment_block(orig)

            new_import = stmt.with_changes(names=tuple(kept))
            new_line = updated.with_changes(body=[new_import])

            removed_txt = "; ".join(removed)
            return self._add_leading_comment_line(new_line, f"{self.marker}: {removed_txt}")

        if isinstance(stmt, cst.ImportFrom):
            if isinstance(stmt.names, cst.ImportStar):
                return updated

            if stmt.relative:
                dots = "." * len(stmt.relative)
            else:
                dots = ""

            modname = ""
            if stmt.module is not None:
                modname = self._name_code(stmt.module)

            head = f"{dots}{modname}"

            kept, removed = self._split_aliases(list(stmt.names), head, is_from=True)
            if not removed:
                return updated

            if not kept:
                return self._replace_statement_with_comment_block(orig)

            new_from = stmt.with_changes(names=tuple(kept))
            new_line = updated.with_changes(body=[new_from])

            removed_txt = "; ".join(removed)
            return self._add_leading_comment_line(new_line, f"{self.marker}: {removed_txt}")

        return updated


def comment_out_unused_function_cst(code, func_name, line_number, marker = "SKYLOS DEADCODE"):
    wrapper = cst.MetadataWrapper(cst.parse_module(code))
    tx = _CommentOutFunctionAtLine(func_name, line_number, code, marker)
    new_mod = wrapper.visit(tx)
    return new_mod.code, tx.changed


def comment_out_unused_import_cst(code, import_name, line_number, marker = "SKYLOS DEADCODE"):
    wrapper = cst.MetadataWrapper(cst.parse_module(code))
    tx = _CommentOutImportAtLine(import_name, line_number, code, marker)
    new_mod = wrapper.visit(tx)
    return new_mod.code, tx.changed


def _bound_name_for_import_alias(alias: cst.ImportAlias):
    if alias.asname:
        return alias.asname.name.value
    node = alias.name
    while isinstance(node, cst.Attribute):
        node = node.value
    return node.value


def _is_plain_dotted_import(alias: cst.ImportAlias):
    return (alias.asname is None) and isinstance(alias.name, cst.Attribute)


class _RemoveImportAtLine(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_name: str, target_line: int):
        self.target_name = target_name
        self.target_line = target_line
        self.changed = False

    def _is_target_line(self, node: cst.CSTNode):
        pos = self.get_metadata(PositionProvider, node, None)
        return bool(pos and (pos.start.line <= self.target_line <= pos.end.line))

    def _filter_aliases(self, aliases):
        kept = []
        for alias in aliases:
            bound = _bound_name_for_import_alias(alias)

            if _is_plain_dotted_import(alias):
                match_keys = {bound}
            else:
                name_code = get_full_name_for_node(alias.name) or ""
                tail = name_code.split(".")[-1] if name_code else ""
                if tail:
                    match_keys = {bound, tail}
                else:
                    match_keys = {bound}

            if self.target_name in match_keys:
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
        target = self.func_name.split(".")[-1]
        if self._is_target(orig) and (orig.name.value == target):
            self.changed = True
            return cst.RemoveFromParent()
        return updated

    def leave_AsyncFunctionDef(
        self, orig: cst.AsyncFunctionDef, updated: cst.AsyncFunctionDef
    ):
        target = self.func_name.split(".")[-1]
        if self._is_target(orig) and (orig.name.value == target):
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
