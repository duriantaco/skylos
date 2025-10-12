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

class _SQLFlowChecker(ast.NodeVisitor):

    SQL_SINK_SUFFIXES = (".execute", ".executemany", ".executescript")

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

    def _tainted(self, node):
        if _is_interpolated_string(node):
            return True

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Subscript):
                base = node.value
            else:
                base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == "request":
                return True

        if isinstance(node, ast.Name):
            tainted = self._get(node.id)
            return tainted
        
        if isinstance(node, ast.BinOp):
            return self._tainted(node.left) or self._tainted(node.right)
            
        if isinstance(node, ast.Call):
            for arg in node.args:
                if self._tainted(arg):
                    return True
            return False
        return False

    def visit_FunctionDef(self, node):
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_AsyncFunctionDef(self, node):
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_Assign(self, node):
        taint = self._tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, taint)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):

        if node.value is not None:
            taint = self._tainted(node.value)
        else:
            taint = False

        if isinstance(node.target, ast.Name):
            self._set(node.target.id, taint)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        taint = self._tainted(node.target) or self._tainted(node.value)
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, taint)
        self.generic_visit(node)

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)
        
        if qn and qn.endswith(self.SQL_SINK_SUFFIXES) and node.args:
            arg0 = node.args[0]
            
            is_interp = _is_interpolated_string(arg0)
            is_tainted = self._tainted(arg0)

            if is_interp or is_tainted:
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D211", "CRITICAL",
                    "Possible SQL injection: string-built or tainted SQL. Use parameterized queries."
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
        checker = _SQLFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)