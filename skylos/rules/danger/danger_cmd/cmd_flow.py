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

def is_passthrough_return(node: ast.AST, parameter_names):
    """
    boolean checking if the return node is directly returning a parameter
    returns true/false
    """
    if isinstance(node, ast.Name):
        if node.id in parameter_names:
            return True

    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                if part.value.id in parameter_names:
                    return True

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True

    if isinstance(node, ast.BinOp):
        return True

    return False

def function_name(node: ast.FunctionDef | ast.AsyncFunctionDef):
    return node.name

class _CmdFlowChecker(ast.NodeVisitor):
    OS_SYSTEM = "os.system"
    SUBPROC_PREFIX = "subprocess."

    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.env_stack = [{}]
        self.current_function = None
        self.passthrough_functions = set()

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
                    if isinstance(value, ast.FormattedValue) and self._tainted(value.value):
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
            target_value = node.value
            return self._tainted(target_value)

        if isinstance(node, ast.BinOp):
            left = self._tainted(node.left)
            right = self._tainted(node.right)
            result = left or right
            return result

        if isinstance(node, ast.Call):
            for arg in node.args:
                if self._tainted(arg):
                    return True
            for keyword in (node.keywords or []):
                if self._tainted(keyword.value):
                    return True

            qual_name = _qualified_name_from_call(node)
            if qual_name and qual_name in self.passthrough_functions:
                for arg in node.args:
                    if self._tainted(arg):
                        return True
                for keyword in (node.keywords or []):
                    if self._tainted(keyword.value):
                        return True
            return False

        return False

    def _traverse_children(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self._push()
 
        parameter_names = set()
        for arg in node.args.args:
            parameter_names.add(arg.arg)

        for stmt in node.body:
            if isinstance(stmt, ast.Return):
                return_value = stmt.value
                if return_value is not None:
                    if is_passthrough_return(return_value, parameter_names):
                        fn_name = function_name(node)
                        self.passthrough_functions.add(fn_name)
                        break


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

    def iter_argv_elements(self, expr: ast.AST):
        if isinstance(expr, (ast.List, ast.Tuple)):
            for element in expr.elts:
                yield element
        else:
            yield expr

    def looks_shell_like(self, head_literals):
        shells = {"sh", "bash", "zsh", "ksh", "cmd", "powershell", "pwsh"}
        for value in head_literals[:2]:
            if value in shells:
                return True
        return False

    def visit_Call(self, node):
        qual_name = _qualified_name_from_call(node)

        if qual_name == self.OS_SYSTEM and node.args:
            arg0 = node.args[0]
            if _is_interpolated_string(arg0) or self._tainted(arg0):
                _add_finding(self.findings, self.file_path, node,
                            "SKY-D212", "CRITICAL",
                            "Possible command injection (RCE): string-built or tainted shell command.")
            self._traverse_children(node)
            return

        if qual_name and qual_name.startswith(self.SUBPROC_PREFIX):
            shell_true = False
            for kw in (node.keywords or []):
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True
                    break

            argv_expr = None
            if node.args:
                argv_expr = node.args[0]
            for kw in (node.keywords or []):
                if kw.arg == "args" and kw.value is not None:
                    argv_expr = kw.value
                    break

            tainted_elem = False
            shellish = False
            if argv_expr is not None:
                elements = list(self.iter_argv_elements(argv_expr))

                for element in elements:
                    if _is_interpolated_string(element):
                        tainted_elem = True
                        break
                    if self._tainted(element):
                        tainted_elem = True
                        break

                literal_heads: list[str] = []
                for element in elements[:2]:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        literal_heads.append(element.value.lower())

                shellish = self.looks_shell_like(literal_heads)

            if shell_true:
                if tainted_elem:
                    _add_finding(self.findings, self.file_path, node,
                                "SKY-D212", "CRITICAL",
                                "Possible command injection (RCE): tainted command with shell=True.")
            else:
                if tainted_elem or shellish:
                    _add_finding(self.findings, self.file_path, node,
                                "SKY-D212", "CRITICAL",
                                "Possible command injection (RCE): tainted argv element or shell-like list invocation.")

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