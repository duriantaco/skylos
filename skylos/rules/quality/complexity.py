import ast
from pathlib import Path
from skylos.rules.base import SkylosRule

RULE_ID = "SKY-Q301"

_COMPLEX_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.IfExp,
)

def _func_complexity(fn_node: ast.AST) -> int:
    c = 1

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            return
        def visit_AsyncFunctionDef(self, node):
            return
        def visit_ClassDef(self, node):
            return
        def visit_Lambda(self, node):
            return

        def generic_visit(self, node):
            nonlocal c

            if isinstance(node, _COMPLEX_NODES):
                c += 1

            if isinstance(node, ast.BoolOp):
                c += max(len(node.values) - 1, 0)

            if isinstance(node, ast.Try):
                c += len(getattr(node, "handlers", []) or [])

            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                cases = getattr(node, "cases", []) or []
                c += max(len(cases) - 1, 0)

            if isinstance(node, ast.comprehension):
                c += 1
                c += len(node.ifs or [])

            super().generic_visit(node)

    Visitor().visit(fn_node)
    return c


def _func_length(node):
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)

    if start is None:
        return 0

    if end is None:
        end = start
        for child in ast.walk(node):
            ln = getattr(child, "lineno", None)
            if ln is not None and ln > end:
                end = ln

    return max(end - start + 1, 0)


class ComplexityRule(SkylosRule):
    rule_id = "SKY-Q301"
    name = "Cyclomatic Complexity"

    def __init__(self, threshold=10):
        self.threshold = threshold

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        complexity = _func_complexity(node)

        if complexity < self.threshold:
            return None

        if complexity < 15:
            severity = "WARN"
        elif complexity < 25:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        length = _func_length(node)
        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "complexity",
                "severity": severity,
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": complexity,
                "threshold": self.threshold,
                "length": length,
                "message": f"Function is complex (McCabe={complexity}). Consider splitting loops/branches.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
            }
        ]
