from __future__ import annotations
import ast
import sys

"""
name = input()                                  
sql  = f"SELECT * FROM users WHERE name='{name}'"
 # attacker types: '; DROP TABLE users; --
cur.execute(sql) # adios amigos. table is gone
"""

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

def _is_passthrough_return(node: ast.AST, param_names):
    if isinstance(node, ast.Name) and node.id in param_names:
        return True
    
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id in param_names:
                return True
        return True
    
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    
    if isinstance(node, ast.BinOp):
        return True
    return False

def _func_name(node: ast.FunctionDef | ast.AsyncFunctionDef):
    return node.name

def get_query_expression(call: ast.Call, names=("sql", "query", "statement")):
    expression = None
    if call.args and len(call.args) > 0:
        expression = call.args[0]

    if expression is None:
        for keyword in (call.keywords or []):
            if keyword.arg in names and keyword.value is not None:
                expression = keyword.value
                break

    return expression

def is_parameterized_query(call: ast.Call, query_expr: ast.AST):
    """
    cosnidered parameterized if:
    - second positional arg exists; or
    - keyword arg "params" or "parameters" exists
    """
    if _is_interpolated_string(query_expr):
        return False

    has_params = False
    if len(call.args) >= 2:
        has_params = True
    else:
        for keyword in (call.keywords or []):
            if keyword.arg in {"params", "parameters"}:
                has_params = True
                break
    return has_params

def is_sqlalchemy_text(expr: ast.AST):
    if not isinstance(expr, ast.Call):
        return False

    func = expr.func
    if isinstance(func, ast.Attribute) and func.attr == "text":
        return True
    if isinstance(func, ast.Name) and func.id == "text":
        return True
    return False


class _SQLFlowChecker(ast.NodeVisitor):

    RULE_ID_SQLI = "SKY-D211"
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    DBAPI_SQL_SINK_SUFFIXES = (".execute", ".executemany", ".executescript")

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = [{}]
        self.current_function = None
        self.passthrough_functions = set()

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
        if node is None:
            return False

        if _is_interpolated_string(node):
            if isinstance(node, ast.JoinedStr):
                for val in node.values:
                    if isinstance(val, ast.FormattedValue) and self._tainted(val.value):
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
            return self._get(node.id)

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._tainted(node.value)

        if isinstance(node, ast.BinOp):
            return self._tainted(node.left) or self._tainted(node.right)

        if isinstance(node, ast.Call):
            for positional_arg in node.args:
                if self._tainted(positional_arg):
                    return True
                
            for keyword in (node.keywords or []):
                if self._tainted(keyword.value):
                    return True

            qual_name = _qualified_name_from_call(node)
            if qual_name and qual_name in getattr(self, "passthrough_functions", set()):
                for positional_arg in node.args:
                    if self._tainted(positional_arg):
                        return True
                for keyword in (node.keywords or []):
                    if self._tainted(keyword.value):
                        return True
                    
            return False

        return False

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self._push()

        param_names = {a.arg for a in node.args.args}
        for statement in node.body:
            if isinstance(statement, ast.Return) and statement.value is not None:
                if _is_passthrough_return(statement.value, param_names):
                    self.passthrough_functions.add(_func_name(node))
                    break

        self.generic_visit(node)
        self._pop()
        self.current_function = None

    def visit_AsyncFunctionDef(self, node):
        self.current_function = node.name
        self._push()

        param_names = {a.arg for a in node.args.args}
        for statement in node.body:
            if isinstance(statement, ast.Return) and statement.value is not None:
                if _is_passthrough_return(statement.value, param_names):
                    self.passthrough_functions.add(_func_name(node))
                    break

        self.generic_visit(node)
        self._pop()
        self.current_function = None

    def visit_Assign(self, node):
        taint = self._tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set(target.id, taint)
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
        qual_name = _qualified_name_from_call(node)

        if qual_name and qual_name.endswith(self.DBAPI_SQL_SINK_SUFFIXES):
            query_expr = get_query_expression(node, names=("sql", "query", "statement"))
            if query_expr is not None:
                if _is_interpolated_string(query_expr) or self._tainted(query_expr):
                    _add_finding(
                        self.findings, self.file_path, node,
                        self.RULE_ID_SQLI, self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted or string-built query. Use parameterized queries."
                    )
                else:
                    is_literal = isinstance(query_expr, ast.Constant) and isinstance(query_expr.value, str)

                    if not is_literal and not is_parameterized_query(node, query_expr):
                        _add_finding(
                            self.findings, self.file_path, node,
                            self.RULE_ID_SQLI, self.SEVERITY_HIGH,
                            "Likely unparameterized SQL execution. Prefer placeholders with bound parameters."
                        )
            self.generic_visit(node)
            return

        if qual_name and (qual_name.endswith(".read_sql") or qual_name.endswith(".read_sql_query")):
            query_expr = get_query_expression(node, names=("sql", "query"))
            if query_expr is not None and (_is_interpolated_string(query_expr) or self._tainted(query_expr)):
                _add_finding(
                    self.findings, self.file_path, node,
                    self.RULE_ID_SQLI, self.SEVERITY_CRITICAL,
                    "Possible SQL injection in read_sql: tainted or string-built query."
                )
            self.generic_visit(node)
            return

        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            statement_expression = get_query_expression(node, names=("statement", "sql", "query"))
            if statement_expression is not None:
                if _is_interpolated_string(statement_expression) or self._tainted(statement_expression):
                    _add_finding(
                        self.findings, self.file_path, node,
                        self.RULE_ID_SQLI, self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted statement passed to execute()."
                    )
                else:
                    is_literal = isinstance(statement_expression, ast.Constant) and isinstance(statement_expression.value, str)
                    if not is_literal and not is_parameterized_query(node, statement_expression):
                        _add_finding(
                            self.findings, self.file_path, node,
                            self.RULE_ID_SQLI, self.SEVERITY_HIGH,
                            "Likely unparameterized SQL execution. Bind parameters to execute()."
                        )
            self.generic_visit(node)
            return

        if is_sqlalchemy_text(node):
            for argument in node.args:
                if _is_interpolated_string(argument) or self._tainted(argument):
                    _add_finding(
                        self.findings, self.file_path, node,
                        self.RULE_ID_SQLI, self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted string used in sqlalchemy.text()."
                    )
                    break

        self.generic_visit(node)

    def generic_visit(self, node):
        for _, value in ast.iter_fields(node):
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