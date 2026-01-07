import ast


class TaintVisitor(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = [{}]
        self.sources = {"input", "request"}
        self.request_obj = "request"

    def _push(self):
        self.env_stack.append({})

    def _pop(self):
        if self.env_stack:
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

    def _taint_params(self, fn: ast.AST):
        args = []
        if hasattr(fn, "args") and fn.args:
            args.extend(getattr(fn.args, "posonlyargs", []) or [])
            args.extend(getattr(fn.args, "args", []) or [])
            args.extend(getattr(fn.args, "kwonlyargs", []) or [])

            if fn.args.vararg:
                args.append(fn.args.vararg)
            if fn.args.kwarg:
                args.append(fn.args.kwarg)

        for a in args:
            name = getattr(a, "arg", None)
            if not name:
                continue
            if name in ("self", "cls"):
                continue
            self._set(name, True)

    def is_tainted(self, node):
        if node is None:
            return False

        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and self.is_tainted(v.value)
                for v in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return True

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in self.sources
        ):
            return True

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = node.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name) and base.id == self.request_obj:
                return True
            return self.is_tainted(node.value)

        if isinstance(node, ast.Name):
            return self._get(node.id)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if self.is_tainted(node.func.value):
                    return True

            if any(self.is_tainted(arg) for arg in node.args):
                return True

            if any(self.is_tainted(k.value) for k in node.keywords):
                return True

        return False

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_FunctionDef(self, node):
        self._push()
        self._taint_params(node)
        self.generic_visit(node)
        self._pop()

    def visit_AsyncFunctionDef(self, node):
        self._push()
        self._taint_params(node)
        self.generic_visit(node)
        self._pop()

    def visit_Assign(self, node):
        t = self.is_tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            t = self.is_tainted(node.value)
            if isinstance(node.target, ast.Name):
                self._set(node.target.id, t)
        self.generic_visit(node)
