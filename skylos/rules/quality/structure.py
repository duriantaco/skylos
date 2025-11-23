import ast
from skylos.rules.base import SkylosRule
from pathlib import Path


class ArgCountRule(SkylosRule):
    rule_id = "SKY-C303"
    name = "Too Many Arguments"

    def __init__(self, max_args=5):
        self.max_args = max_args

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        args = node.args.args
        clean_args = []
        for a in args:
            if a.arg not in ("self", "cls"):
                clean_args.append(a)

        total_count = len(clean_args) + len(node.args.kwonlyargs)

        if total_count <= self.max_args:
            return None

        mod = context.get("mod", "")
        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": total_count,
                "threshold": self.max_args,
                "severity": "MEDIUM",
                "message": f"Function has {total_count} arguments (limit: {self.max_args}). Refactor.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


class FunctionLengthRule(SkylosRule):
    rule_id = "SKY-C304"
    name = "Function Too Long"

    def __init__(self, max_lines=50):
        self.max_lines = max_lines

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        physical_length = max(end - start + 1, 0)

        if physical_length <= self.max_lines:
            return None

        if physical_length < 100:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": physical_length,
                "threshold": self.max_lines,
                "severity": severity,
                "message": f"Function is {physical_length} lines long (limit: {self.max_lines}). It is too big.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
