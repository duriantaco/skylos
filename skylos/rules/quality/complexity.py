import ast
from pathlib import Path
from skylos.rules.base import SkylosRule

RULE_ID = "SKY-Q301"
COGNITIVE_RULE_ID = "SKY-Q306"

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
        def visit_FunctionDef(self, _):
            return

        def visit_AsyncFunctionDef(self, _):
            return

        def visit_ClassDef(self, _):
            return

        def visit_Lambda(self, _):
            return

        def generic_visit(self, node):
            nonlocal c

            if isinstance(node, _COMPLEX_NODES):
                c += 1

            if isinstance(node, ast.BoolOp):
                c += max(len(node.values) - 1, 0)

            if isinstance(node, ast.Try):
                c += len(getattr(node, "handlers", []) or [])

            if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                c += len(getattr(node, "handlers", []) or [])

            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                cases = getattr(node, "cases", []) or []
                c += max(len(cases) - 1, 0)
                for case in cases:
                    if getattr(case, "guard", None) is not None:
                        c += 1

            if isinstance(node, ast.comprehension):
                c += 1
                c += len(node.ifs)

            for child in ast.iter_child_nodes(node):
                self.visit(child)

    v = Visitor()
    for stmt in fn_node.body:
        v.visit(stmt)
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

        if complexity <= self.threshold:
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
                "message": f"Cyclomatic complexity is {complexity} (threshold: {self.threshold}). Consider splitting branches.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
            }
        ]


def _cognitive_complexity(fn_node: ast.AST) -> int:

    total = 0

    def _process(node, nesting: int, is_elif: bool = False):
        nonlocal total

        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            for child in ast.iter_child_nodes(node):
                _process(child, 0)
            return

        if isinstance(node, ast.If):
            if is_elif:
                total += 1
            else:
                total += 1 + nesting

            inner_nesting = nesting + 1

            _process(node.test, inner_nesting)

            for body_child in node.body:
                _process(body_child, inner_nesting)

            if node.orelse:
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    _process(node.orelse[0], nesting, is_elif=True)
                else:
                    total += 1
                    for else_child in node.orelse:
                        _process(else_child, inner_nesting)
            return

        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            total += 1 + nesting
            if isinstance(node, ast.While):
                _process(node.test, nesting + 1)
            for body_child in node.body:
                _process(body_child, nesting + 1)
            if node.orelse:
                for else_child in node.orelse:
                    _process(else_child, nesting + 1)
            return

        if isinstance(node, ast.BoolOp):
            total += max(len(node.values) - 1, 0)
            for val in node.values:
                _process(val, nesting)
            return

        if isinstance(node, ast.IfExp):
            total += 1 + nesting
            _process(node.test, nesting)
            _process(node.body, nesting)
            _process(node.orelse, nesting)
            return

        if isinstance(node, ast.Try):
            for handler in getattr(node, "handlers", []) or []:
                total += 1 + nesting
                for h_child in handler.body:
                    _process(h_child, nesting + 1)
            for body_child in getattr(node, "body", []) or []:
                _process(body_child, nesting)
            for fb_child in getattr(node, "finalbody", []) or []:
                _process(fb_child, nesting)
            for else_child in getattr(node, "orelse", []) or []:
                _process(else_child, nesting)
            return

        if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
            for handler in getattr(node, "handlers", []) or []:
                total += 1 + nesting
                for h_child in handler.body:
                    _process(h_child, nesting + 1)
            for body_child in getattr(node, "body", []) or []:
                _process(body_child, nesting)
            for fb_child in getattr(node, "finalbody", []) or []:
                _process(fb_child, nesting)
            for else_child in getattr(node, "orelse", []) or []:
                _process(else_child, nesting)
            return

        if hasattr(ast, "Match") and isinstance(node, ast.Match):
            total += 1 + nesting
            for case in getattr(node, "cases", []) or []:
                for case_child in case.body:
                    _process(case_child, nesting + 1)
            return

        for child in ast.iter_child_nodes(node):
            _process(child, nesting)

    for stmt in fn_node.body:
        _process(stmt, 0)

    return total


class CognitiveComplexityRule(SkylosRule):
    rule_id = COGNITIVE_RULE_ID
    name = "Cognitive Complexity"

    def __init__(self, threshold=15):
        self.threshold = threshold

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        complexity = _cognitive_complexity(node)

        if complexity <= self.threshold:
            return None

        if complexity <= 30:
            severity = "MEDIUM"
        elif complexity <= 50:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

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
                "message": f"Cognitive complexity is {complexity} (threshold: {self.threshold}). Consider simplifying nested logic.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
            }
        ]
