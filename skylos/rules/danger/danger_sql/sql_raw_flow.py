from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger.danger_sql.sqlalchemy_provenance import (
    SQLAlchemyTextProvenance,
)


def _qualified_name(node: ast.Call):
    f = node.func
    parts = []

    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value

    if isinstance(f, ast.Name):
        parts.append(f.id)
        parts.reverse()
        return ".".join(parts)

    if isinstance(f, ast.Name):
        return f.id
    return None


def _is_static_string_expr(n: ast.AST) -> bool:
    if isinstance(n, ast.Constant):
        return isinstance(n.value, str)
    if isinstance(n, ast.JoinedStr):
        for value in n.values:
            if isinstance(value, ast.Constant):
                continue
            if isinstance(value, ast.FormattedValue) and isinstance(
                value.value, ast.Constant
            ):
                continue
            return False
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        return _is_static_string_expr(n.left) and _is_static_string_expr(n.right)
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
        if not _is_static_string_expr(n.left):
            return False
        if isinstance(n.right, ast.Tuple):
            return all(_is_static_string_expr(elt) for elt in n.right.elts)
        return _is_static_string_expr(n.right)
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "format"
    ):
        return (
            _is_static_string_expr(n.func.value)
            and all(_is_static_string_expr(arg) for arg in n.args)
            and all(_is_static_string_expr(k.value) for k in n.keywords)
        )
    return False


def _is_interpolated_string(n: ast.AST):
    if isinstance(n, (ast.JoinedStr, ast.BinOp)):
        return not _is_static_string_expr(n)
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "format"
    ):
        return not _is_static_string_expr(n)
    return False


class _SQLRawFlowChecker(TaintVisitor):
    def __init__(self, tree: ast.AST, file_path, findings):
        super().__init__(file_path, findings)
        self.sqlalchemy_text = SQLAlchemyTextProvenance(tree)

    def visit_Import(self, node: ast.Import) -> None:
        self.sqlalchemy_text.record_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.sqlalchemy_text.record_import(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_function(node)
        try:
            super().visit_FunctionDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_function(node)
        try:
            super().visit_AsyncFunctionDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_class(node)
        try:
            super().visit_ClassDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.sqlalchemy_text.record_name_binding(node.id)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.sqlalchemy_text.enter_lambda(node)
        try:
            self.generic_visit(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def _visit_scoped_comprehension(self, node) -> None:
        first, *remaining = node.generators
        self.visit(first.iter)
        self.sqlalchemy_text.enter_comprehension(node)
        try:
            self.visit(first.target)
            for condition in first.ifs:
                self.visit(condition)
            for generator in remaining:
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
            self.sqlalchemy_text.leave_scope()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_scoped_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_scoped_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_scoped_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_scoped_comprehension(node)

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return

        if self.sqlalchemy_text.is_text_call(node) and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self.findings.append(
                    {
                        "rule_id": "SKY-D217",
                        "severity": "CRITICAL",
                        "message": "Possible SQL injection: tainted SQL passed to sqlalchemy.text().",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        if (qn.endswith(".read_sql") or qn.endswith(".read_sql_query")) and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self.findings.append(
                    {
                        "rule_id": "SKY-D217",
                        "severity": "CRITICAL",
                        "message": "Possible SQL injection: tainted SQL passed to pandas.read_sql().",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        if qn.endswith(".objects.raw") and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self.findings.append(
                    {
                        "rule_id": "SKY-D217",
                        "severity": "CRITICAL",
                        "message": "Possible SQL injection: tainted SQL passed to Django .raw().",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)


def scan(tree: ast.AST, file_path, findings):
    try:
        checker = _SQLRawFlowChecker(tree, file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Raw SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
