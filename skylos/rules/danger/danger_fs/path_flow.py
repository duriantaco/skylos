from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor, PATH_SANITIZERS


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


def _expr_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _is_path_constructor_call(node):
    if not isinstance(node, ast.Call):
        return False
    name = _expr_name(node.func)
    return name in {
        "Path",
        "PurePath",
        "PosixPath",
        "WindowsPath",
        "pathlib.Path",
        "pathlib.PurePath",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
    }


def _is_path_name_projection(node):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "name"
        and _is_path_constructor_call(node.value)
    )


class _PathFlowChecker(TaintVisitor):
    FILE_OPEN_FUNCS = {"open"}
    OS_FILE_FUNCS = {"open", "unlink", "remove", "mkdir", "rmdir", "makedirs"}
    SHUTIL_FUNCS = {"copy", "copy2", "copytree", "move", "rmtree"}
    PATHLIB_SINK_METHODS = {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "unlink",
        "mkdir",
        "rmdir",
        "rename",
        "replace",
    }

    def __init__(self, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.path_like_stack = [{}]

    def _push(self):
        super()._push()
        self.path_like_stack.append({})

    def _pop(self):
        super()._pop()
        if self.path_like_stack:
            self.path_like_stack.pop()

    def _set_path_like(self, name, path_like):
        if not self.path_like_stack:
            self.path_like_stack.append({})
        self.path_like_stack[-1][name] = bool(path_like)

    def _get_path_like(self, name):
        for env in reversed(self.path_like_stack):
            if name in env:
                return env[name]
        return False

    def _taint_params(self, fn: ast.AST):
        super()._taint_params(fn)
        args = []
        if hasattr(fn, "args") and fn.args:
            args.extend(getattr(fn.args, "posonlyargs", []) or [])
            args.extend(getattr(fn.args, "args", []) or [])
            args.extend(getattr(fn.args, "kwonlyargs", []) or [])

            if fn.args.vararg:
                args.append(fn.args.vararg)
            if fn.args.kwarg:
                args.append(fn.args.kwarg)

        for arg in args:
            name = getattr(arg, "arg", None)
            if name and name not in {"self", "cls"}:
                self._set_path_like(name, False)

    def _is_path_like_expr(self, node):
        if _is_path_constructor_call(node):
            return True
        if isinstance(node, ast.Name):
            return self._get_path_like(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._is_path_like_expr(node.left) or self._is_path_like_expr(
                node.right
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {
                "absolute",
                "expanduser",
                "joinpath",
                "resolve",
                "with_name",
                "with_suffix",
            }:
                return self._is_path_like_expr(node.func.value)
        return False

    def is_tainted(self, node):
        if _is_path_name_projection(node):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        return super().is_tainted(node)

    def visit_Assign(self, node):
        t = self.is_tainted(node.value)
        path_like = self._is_path_like_expr(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
                self._set_path_like(tgt.id, path_like)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            t = self.is_tainted(node.value)
            path_like = self._is_path_like_expr(node.value)
            if isinstance(node.target, ast.Name):
                self._set(node.target.id, t)
                self._set_path_like(node.target.id, path_like)
        self.generic_visit(node)

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
                    "symbol": self._current_symbol(),
                }
            )

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self.PATHLIB_SINK_METHODS
            and self._is_path_like_expr(node.func.value)
        ):
            self._flag_if_tainted_path(node, node.func.value)

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
        checker = _PathFlowChecker(file_path, findings, sanitizers=PATH_SANITIZERS)
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
