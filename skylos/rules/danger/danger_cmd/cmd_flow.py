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

class _CmdFlowChecker(ast.NodeVisitor):
    OS_SYSTEM = "os.system"
    SUBPROC_PREFIX = "subprocess."

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = [{}]
        self.current_function = None

    def _push(self):
        self.env_stack.append({})
        
    def _pop(self):
        popped = self.env_stack.pop() # pragma: no skylos
        
    def _set(self, name, tainted):
        if not self.env_stack:
            self._push()
        self.env_stack[-1][name] = tainted
        
    def _get(self, name):
        for i, env in enumerate(reversed(self.env_stack)):
            if name in env:
                result = env[name]
                return result
        return False

    def _tainted(self, node):
        
        if _is_interpolated_string(node):
            if isinstance(node, ast.JoinedStr):
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        if self._tainted(value.value):
                            return True
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
            result = self._get(node.id)
            return result

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            target_value = node.value
            result = self._tainted(target_value)
            return result

        if isinstance(node, ast.BinOp):
            left = self._tainted(node.left)
            right = self._tainted(node.right)
            result = left or right
            return result

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
        self.current_function = node.name
        self._push()
        
        # for arg in node.args.args:
        #     self._set(arg.arg, True)
        
        self._traverse_children(node)
        self._pop()
        self.current_function = None

    def visit_AsyncFunctionDef(self, node):
        self.current_function = node.name
        self._push()
        
        for arg in node.args.args:
            self._set(arg.arg, True)
        
        self._traverse_children(node)
        self._pop()
        self.current_function = None

    def visit_Assign(self, node):
        taint = self._tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, taint)
        self._traverse_children(node)

    def visit_AnnAssign(self, node):
        taint = self._tainted(node.value) if node.value else False
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, taint)
        self._traverse_children(node)

    def visit_AugAssign(self, node):
        taint = self._tainted(node.target) or self._tainted(node.value)
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, taint)
        self._traverse_children(node)

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)

        if qn == self.OS_SYSTEM and node.args:
            arg0 = node.args[0]
            is_interp = _is_interpolated_string(arg0)
            is_taint = self._tainted(arg0)
          
            if is_interp or is_taint:
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D212", "CRITICAL",
                    "Possible command injection (RCE): string-built or tainted shell command."
                )

        if qn and qn.startswith(self.SUBPROC_PREFIX) and node.args:
            shell_true = False
            for kw in (node.keywords or []):
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True
                    break
                        
            if shell_true:
                arg0 = node.args[0]
                is_interp = _is_interpolated_string(arg0)
                is_taint = self._tainted(arg0)
        
                if is_interp or is_taint:
                    _add_finding(
                        self.findings, self.file_path, node,
                        "SKY-D212", "CRITICAL",
                        "Possible command injection (RCE): string-built or tainted command with shell=True."
                    )

        self._traverse_children(node)

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

        checker = _CmdFlowChecker(file_path, findings)
        checker.visit(tree)

    except Exception as e:
        print(f"CMD flow failed for {file_path}: {e}", file=sys.stderr)