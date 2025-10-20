from __future__ import annotations
import ast

"""
raw sql injection flow analysis for sqlalchemy.text, pandas.read_sql, django .raw()
"""

def _is_interpolated_string(n: ast.AST):
    if isinstance(n, ast.JoinedStr):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return True
    return False

def _qualified_name_from_call(node: ast.Call):
    f = node.func
    parts = []

    while isinstance(f, ast.Attribute):
        parts.append(f.attr); f = f.value
        
    if isinstance(f, ast.Name):
        parts.append(f.id); parts.reverse()
        return ".".join(parts)
    
    if isinstance(f, ast.Name):
        return f.id
    return None

def _add_finding(findings, file_path, node: ast.AST, rule_id, severity, message):
    findings.append({
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": getattr(node, "lineno", 1),
        "col": getattr(node, "col_offset", 0),
    })

class _SQLRawFlowChecker(ast.NodeVisitor):

    # PANDAS_FUNCS = {"read_sql", "read_sql_query"}
    # SQLALCHEMY_TEXT = "sqlalchemy.text"

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = []

    def _push(self): 
        self.env_stack.append({})

    def _pop(self): 
        self.env_stack.pop()

    def _set(self, name, tainted):
        if not self.env_stack: self._push()
        self.env_stack[-1][name] = bool(tainted)

    def _get(self, name):
        for env in reversed(self.env_stack):
            if name in env: 
                return env[name]
        return False

    def _traverse_children(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def expr_is_tainted(self, n: ast.AST):
        if _is_interpolated_string(n):
            return True

        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input":
            return True

        if isinstance(n, (ast.Attribute, ast.Subscript)):
            base = n.value
            while isinstance(base, ast.Attribute):
                base = base.value
            
            if isinstance(base, ast.Name) and base.id == "request":
                return True

        if isinstance(n, ast.Name):
            return self._get(n.id)

        if isinstance(n, (ast.Attribute, ast.Subscript)):
            return self.expr_is_tainted(n.value)

        if isinstance(n, ast.Call):
            for arg in n.args:
                if self.expr_is_tainted(arg):
                    return True
            return False

        if isinstance(n, ast.BinOp):
            return self.expr_is_tainted(n.left) or self.expr_is_tainted(n.right)

        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._push()
        for arg in node.args.args:
            self._set(arg.arg, True)
        self._traverse_children(node)
        self._pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._push()
        for arg in node.args.args:
            self._set(arg.arg, True)
        self._traverse_children(node)
        self._pop()

    def visit_Assign(self, node: ast.Assign):
        tainted = self.expr_is_tainted(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, tainted)
        self._traverse_children(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.target, ast.Name):
            if node.value is not None:
                tainted = self.expr_is_tainted(node.value)
            else:
                tainted = False
            self._set(node.target.id, tainted)
        
        self._traverse_children(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        tainted = self.expr_is_tainted(node.target) or self.expr_is_tainted(node.value)
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, tainted)

        self._traverse_children(node)

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name_from_call(node)
        if not qn:
            return self._traverse_children(node)
        
        """
        import sqlalchemy as sa
        ip = input()  
        # attacker runs: "'; DROP TABLE logs; --"
        sa.text("DELETE FROM logs WHERE ip='" + ip + "'")  # tainted SQL

        """

        if qn.endswith(".text") and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.expr_is_tainted(sql):
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D217", "CRITICAL",
                    "Possible SQL injection: tainted SQL passed to sqlalchemy.text()."
                )

        """
        import pandas as pd
        name = input()  
        # attacker runs: "' OR 1=1; --"
        pd.read_sql(f"SELECT * FROM users WHERE name='{name}'", conn)  # tainted SQL
        """
        if (qn.endswith(".read_sql") or qn.endswith(".read_sql_query")) and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.expr_is_tainted(sql):
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D217", "CRITICAL",
                    "Possible SQL injection: tainted SQL passed to pandas.read_sql()."
                )

        """
        ## note this is for double quotation mark
        u = input()  
        # attacker: "'; DROP TABLE auth_user; --"
        User.objects.raw("SELECT * FROM auth_user WHERE username='" + u + "'")  # tainted SQL
        """

        if qn.endswith(".objects.raw") and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.expr_is_tainted(sql):
                _add_finding(
                    self.findings, self.file_path, node,
                    "SKY-D217", "CRITICAL",
                    "Possible SQL injection: tainted SQL passed to Django .raw()."
                )

        self._traverse_children(node)

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

def scan(tree: ast.AST, file_path, findings):
    _SQLRawFlowChecker(file_path, findings).visit(tree)
