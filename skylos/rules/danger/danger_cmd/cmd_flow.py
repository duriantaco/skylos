from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


def _qualified_name(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)

    return None


class _CmdFlowChecker(TaintVisitor):
    OS_SYSTEM = "os.system"
    SUBPROC_PREFIX = "subprocess."

    def visit_Call(self, node):
        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return

        if qn == self.OS_SYSTEM and node.args:
            if self.is_tainted(node.args[0]):
                self.findings.append(
                    {
                        "rule_id": "SKY-D212",
                        "severity": "CRITICAL",
                        "message": "Possible command injection (os.system): tainted input.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )

        if qn.startswith(self.SUBPROC_PREFIX):
            shell_true = False
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    shell_true = True

            if shell_true and self.is_tainted(node):
                self.findings.append(
                    {
                        "rule_id": "SKY-D212",
                        "severity": "CRITICAL",
                        "message": "Possible command injection (subprocess shell=True): tainted input.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _CmdFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"CMD flow failed for {file_path}: {e}", file=sys.stderr)
