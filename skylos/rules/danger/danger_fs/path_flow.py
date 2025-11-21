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
    if isinstance(func, ast.Name):
        return func.id
    return None


def _is_interpolated_string(node):
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


class _PathFlowChecker(TaintVisitor):
    FILE_OPEN_FUNCS = {"open"}
    OS_FILE_FUNCS = {"open", "unlink", "remove", "mkdir", "rmdir", "makedirs"}
    SHUTIL_FUNCS = {"copy", "copy2", "copytree", "move", "rmtree"}

    def _flag_if_tainted_path(self, node, path_expr):
        is_interp = _is_interpolated_string(path_expr)
        is_tainted = self.is_tainted(path_expr)

        if is_interp or is_tainted:
            self.findings.append(
                {
                    "rule_id": "SKY-D215",
                    "severity": "HIGH",
                    "message": "Possible path traversal: tainted filesystem path",
                    "file": str(self.file_path),
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)

        if qn and qn in self.FILE_OPEN_FUNCS and node.args:
            self._flag_if_tainted_path(node, node.args[0])

        if qn and "." in qn:
            mod, func = qn.split(".", 1)
            if mod == "os" and func in self.OS_FILE_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

            if mod == "shutil" and func in self.SHUTIL_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _PathFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
