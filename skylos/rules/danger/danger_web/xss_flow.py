from __future__ import annotations
import ast
import sys

"""
Common  XSS patterns the LLMs love to generate:

1) Marking untrusted HTML as safe

   from django.utils.safestring import mark_safe
   return HttpResponse(mark_safe(input()))         # -> XSS

2) Unsafe inline templates
   from flask import render_template_string
   render_template_string("<p>{{ body|safe }}</p>", body=request.args["body"])  # -> XSS
   render_template_string("{% autoescape false %}{{ x }}{% endautoescape %}", x=input())  # -> XSS

3) Returning string-built HTML directly with user input
   return "<div>" + request.args["q"] + "</div>"   # -> XSS
"""

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

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True

    return False

def _add_finding(findings, file_path, node, rule_id, severity, message):
    findings.append({
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": getattr(node, "lineno", 1),
        "col": getattr(node, "col_offset", 0),
    })

def _const_str_value(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None

def _const_contains_html(node: ast.AST):

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value
        return ("<" in s) and (">" in s)
    return False

class _XSSFlowChecker(ast.NodeVisitor):

    SAFE_MARK_FUNCS = {"Markup", "mark_safe"}

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = []

    def _push(self):
        self.env_stack.append({})

    def _pop(self):
        self.env_stack.pop()

    def _set(self, name, tainted):
        if not self.env_stack:
            self._push()
        self.env_stack[-1][name] = bool(tainted)

    def _get(self, name):
        for env in reversed(self.env_stack):
            if name in env:
                return env[name]
        return False

    def _tainted(self, node: ast.AST):
        if _is_interpolated_string(node):
            return True

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = node.value if isinstance(node, ast.Subscript) else node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == "request":
                return True

        if isinstance(node, ast.Name):
            return self._get(node.id)

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._tainted(node.value)

        if isinstance(node, ast.BinOp):
            return self._tainted(node.left) or self._tainted(node.right)

        if isinstance(node, ast.Call):
            for arg in node.args:
                if self._tainted(arg):
                    return True
            return False

        return False

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

    def _html_built_with_taint(self, node: ast.AST):
 
        if isinstance(node, ast.JoinedStr):
            has_html = False
            for v in node.values:
                if isinstance(v, ast.Constant):
                    if _const_contains_html(v):
                        has_html = True
                        break
            
            if not has_html:
                return False
            
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    if self._tainted(v.value):
                        return True
            
            return False

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left_html = _const_contains_html(node.left)
            right_html = _const_contains_html(node.right)
            any_html = left_html or right_html
            if not any_html:
                left_html = self._binop_has_html_const(node.left)
                right_html = self._binop_has_html_const(node.right)
                any_html = left_html or right_html
            if not any_html:
                return False
            # taint on either side?
            return self._tainted(node.left) or self._tainted(node.right)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = node.func.value
            if _const_contains_html(base):
                for a in node.args:
                    if self._tainted(a):
                        return True
            return False

        return False

    def _binop_has_html_const(self, node: ast.AST):
        if _const_contains_html(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._binop_has_html_const(node.left) or self._binop_has_html_const(node.right)
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_Assign(self, node: ast.Assign):
        t = self._tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            tainted = self._tainted(node.value)
        else:
            tainted = False
        
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, tainted)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        t = self._tainted(node.target) or self._tainted(node.value)
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, t)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name_from_call(node)

        if qn and node.args:
            func_name = qn.split(".")[-1]
            if func_name in self.SAFE_MARK_FUNCS:
                arg0 = node.args[0]
                is_interp = _is_interpolated_string(arg0)
                is_tainted = self._tainted(arg0)
                if is_interp or is_tainted:
                    _add_finding(
                        self.findings, self.file_path, node,
                        "SKY-D226", "CRITICAL",
                        "Possible XSS: untrusted content marked safe"
                    )

        if qn and qn.split(".")[-1] == "render_template_string" and node.args:
            tmpl = node.args[0]
            if self._template_is_unsafe_literal(tmpl):
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D227", "HIGH",
                    "Possible XSS: unsafe inline template disables escaping"
                )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
  
        if node.value is not None:
            if self._html_built_with_taint(node.value):
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D228", "HIGH",
                    "XSS (HTML built from unescaped user input)"
                )
        self.generic_visit(node)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

def scan(tree, file_path, findings):
    try:
        checker = _XSSFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"XSS analysis failed for {file_path}: {e}", file=sys.stderr)
