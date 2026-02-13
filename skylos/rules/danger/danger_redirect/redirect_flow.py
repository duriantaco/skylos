from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


REDIRECT_FUNCS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}


class _RedirectFlowChecker(TaintVisitor):
    def visit_Call(self, node):
        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name in REDIRECT_FUNCS and node.args:
            url_arg = node.args[0]
            if self.is_tainted(url_arg):
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
