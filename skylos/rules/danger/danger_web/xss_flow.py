from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


def _qualified_name_from_call(node: ast.Call):
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


def _is_interpolated_string(node: ast.AST):
    if isinstance(node, ast.JoinedStr):
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


def _const_str_value(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_contains_html(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value
        return ("<" in s) and (">" in s)
    return False


class _XSSFlowChecker(TaintVisitor):
    SAFE_MARK_FUNCS = {"Markup", "mark_safe"}

    def _template_is_unsafe_literal(self, node: ast.AST):
        s = _const_str_value(node)
        if not s:
            return False
        low = s.lower()
        if "|safe" in low:
            return True
        if "{% autoescape false %}" in low:
            return True
        return False

    def _binop_has_html_const(self, node: ast.AST):
        if _const_contains_html(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._binop_has_html_const(node.left) or self._binop_has_html_const(
                node.right
            )
        return False

    def _html_built_with_taint(self, node: ast.AST):
        if isinstance(node, ast.JoinedStr):
            has_html = False
            for v in node.values:
                if isinstance(v, ast.Constant) and _const_contains_html(v):
                    has_html = True
                    break
            if not has_html:
                return False

            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self.is_tainted(v.value):
                    return True
            return False

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left_html = _const_contains_html(node.left)
            right_html = _const_contains_html(node.right)
            any_html = (
                left_html
                or right_html
                or self._binop_has_html_const(node.left)
                or self._binop_has_html_const(node.right)
            )

            if not any_html:
                return False
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            base = node.func.value
            if _const_contains_html(base):
                for a in node.args:
                    if self.is_tainted(a):
                        return True
            return False
        return False

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name_from_call(node)

        if qn and node.args:
            func_name = qn.split(".")[-1]
            if func_name in self.SAFE_MARK_FUNCS:
                arg0 = node.args[0]
                if _is_interpolated_string(arg0) or self.is_tainted(arg0):
                    self.findings.append(
                        {
                            "rule_id": "SKY-D226",
                            "severity": "CRITICAL",
                            "message": "Possible XSS: untrusted content marked safe",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if qn and qn.split(".")[-1] == "render_template_string" and node.args:
            tmpl = node.args[0]
            if self._template_is_unsafe_literal(tmpl):
                self.findings.append(
                    {
                        "rule_id": "SKY-D227",
                        "severity": "HIGH",
                        "message": "Possible XSS: unsafe inline template disables escaping",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value is not None:
            if self._html_built_with_taint(node.value):
                self.findings.append(
                    {
                        "rule_id": "SKY-D228",
                        "severity": "HIGH",
                        "message": "XSS (HTML built from unescaped user input)",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _XSSFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"XSS analysis failed for {file_path}: {e}", file=sys.stderr)
