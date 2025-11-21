from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


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


def _is_interpolated_string(n: ast.AST):
    if isinstance(n, ast.JoinedStr):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "format"
    ):
        return True
    return False


class _SQLRawFlowChecker(TaintVisitor):
    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return

        if qn.endswith(".text") and node.args:
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
                    }
                )

        self.generic_visit(node)


def scan(tree: ast.AST, file_path, findings):
    try:
        checker = _SQLRawFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Raw SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
