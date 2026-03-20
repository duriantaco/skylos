from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


REDIRECT_FUNCS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}

REQUEST_ARGS_ATTRS = {"args", "params", "query", "GET"}


def _is_request_args_get(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "get":
        return False
    val = func.value
    if (
        isinstance(val, ast.Attribute)
        and val.attr in REQUEST_ARGS_ATTRS
        and isinstance(val.value, ast.Name)
        and val.value.id == "request"
    ):
        return True
    return False


def _has_url_guard(func_body):
    for node in ast.walk(func_body):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "netloc"
            and isinstance(node.value, ast.Call)
        ):
            call_func = node.value.func
            name = None
            if isinstance(call_func, ast.Name):
                name = call_func.id
            elif isinstance(call_func, ast.Attribute):
                name = call_func.attr
            if name == "urlparse":
                return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "startswith"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "/"
        ):
            return True
    return False


class _RedirectFlowChecker(TaintVisitor):
    def __init__(self, file_path, findings):
        super().__init__(file_path, findings)
        self._func_node_stack = []

    def visit_FunctionDef(self, node):
        self._func_node_stack.append(node)
        super().visit_FunctionDef(node)
        self._func_node_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self._func_node_stack.append(node)
        super().visit_AsyncFunctionDef(node)
        self._func_node_stack.pop()

    def visit_Call(self, node):
        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name in REDIRECT_FUNCS and node.args:
            url_arg = node.args[0]

            if _is_request_args_get(url_arg):
                enclosing = self._func_node_stack[-1] if self._func_node_stack else None
                if enclosing is None or not _has_url_guard(enclosing):
                    self.findings.append(
                        {
                            "rule_id": "SKY-D230",
                            "severity": "HIGH",
                            "message": (
                                "Possible open redirect: request parameter passed to "
                                "redirect via .get() — default value does not prevent "
                                "attacker-supplied input."
                            ),
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                            "symbol": self._current_symbol(),
                        }
                    )
            elif self.is_tainted(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D230",
                        "severity": "HIGH",
                        "message": "Possible open redirect: user-controlled URL passed to redirect.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _RedirectFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Redirect flow analysis failed for {file_path}: {e}", file=sys.stderr)
