from __future__ import annotations
import ast
import sys

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

def _is_interpolated_string(node):
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

class _PathFlowChecker(ast.NodeVisitor):

    FILE_OPEN_FUNCS = {"open"}
    OS_FILE_FUNCS = {"open", "unlink", "remove", "mkdir", "rmdir", "makedirs"}
    SHUTIL_FUNCS = {"copy", "copy2", "copytree", "move", "rmtree"}

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = [{}]

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

    def _tainted(self, node):
        if _is_interpolated_string(node):
            return True

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == "request":
                return True

        if isinstance(node, ast.Name):
            value = self._get(node.id)
            return value

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            inner = node.value
            result = self._tainted(inner)
            return result

        if isinstance(node, ast.BinOp):
            left = self._tainted(node.left)
            right = self._tainted(node.right)
            if left:
                return True
            if right:
                return True
            return False

        if isinstance(node, ast.Call):
            for arg in node.args:
                if self._tainted(arg):
                    return True
            return False

        return False
    
    def _traverse_children(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_FunctionDef(self, node):
        self._push()
        for arg in node.args.args:
            self._set(arg.arg, True)
        self._traverse_children(node)
        self._pop()

    def visit_AsyncFunctionDef(self, node):
        self._push()
        self._traverse_children(node)
        self._pop()

    def visit_Assign(self, node):
        t = self._tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
        self._traverse_children(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            t = self._tainted(node.value)
        else:
            t = False
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, t)
        self._traverse_children(node)

    def visit_AugAssign(self, node):
        t = self._tainted(node.target) or self._tainted(node.value)
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, t)
        self._traverse_children(node)

    def _flag_if_tainted_path(self, node, path_expr):
        is_interp = _is_interpolated_string(path_expr)
        is_tainted = self._tainted(path_expr)
        if is_interp or is_tainted:
            _add_finding(
                self.findings, self.file_path, node,
                "SKY-D215", "HIGH",
                "Possible path traversal: tainted filesystem path"
            )

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)

        if qn and qn in self.FILE_OPEN_FUNCS and node.args:
            self._flag_if_tainted_path(node, node.args[0])

        if qn and "." in qn:
            mod, func = qn.split(".", 1)
            if mod == "os" and func in self.OS_FILE_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

            if mod == "shutil" and func in self.SHUTIL_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

            if func == "open" and node.args:
                pass

        self._traverse_children(node)

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

def scan(tree, file_path, findings):
    try:
        checker = _PathFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
