from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


def _qualified_name_from_call(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(func, ast.Name):
        return func.id
    return None


def _has_safe_base_url(node):
    if not node.values:
        return True

    first = node.values[0]

    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        val = first.value

        if "://" in val:
            parts = val.split("://", 1)
            if len(parts) > 1 and "/" in parts[1]:
                return True

    if isinstance(first, ast.FormattedValue):
        if isinstance(first.value, ast.Name) and first.value.id.isupper():
            return True

    return False


def _is_interpolated_string(node):
    if isinstance(node, ast.JoinedStr):
        if _has_safe_base_url(node):
            return False
        return True

    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


class _SSRFFlowChecker(TaintVisitor):
    HTTP_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)

        if qn and "." in qn:
            _, func = qn.split(".", 1)
            if func in self.HTTP_METHODS and node.args:
                url_arg = node.args[0]
                if _is_interpolated_string(url_arg) or self.is_tainted(url_arg):
                    self.findings.append(
                        {
                            "rule_id": "SKY-D216",
                            "severity": "CRITICAL",
                            "message": "Possible SSRF: tainted URL passed to HTTP client.",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if qn and qn.endswith(".urlopen") and node.args:
            url_arg = node.args[0]
            if _is_interpolated_string(url_arg) or self.is_tainted(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D216",
                        "severity": "CRITICAL",
                        "message": "Possible SSRF: tainted URL passed to HTTP client.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SSRFFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"SSRF flow analysis failed for {file_path}: {e}", file=sys.stderr)
