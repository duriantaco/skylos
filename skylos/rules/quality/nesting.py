from __future__ import annotations
import ast
from pathlib import Path
from skylos.rules.base import SkylosRule

RULE_ID = "SKY-Q302"

NEST_NODES = (ast.If, ast.For, ast.While, ast.Try, ast.With)


def _max_depth(nodes, depth=0):
    max_depth = depth
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        if isinstance(node, NEST_NODES):
            branches = []
            if isinstance(node, ast.If):
                branches.append(node.body)
                if node.orelse:
                    branches.append(node.orelse)

            elif isinstance(node, (ast.For, ast.While)):
                branches.append(node.body)
                if node.orelse:
                    branches.append(node.orelse)

            elif isinstance(node, ast.With):
                branches.append(node.body)

            elif isinstance(node, ast.Try):
                branches.append(node.body)
                for handler in node.handlers:
                    branches.append(handler.body)
                if node.orelse:
                    branches.append(node.orelse)
                if node.finalbody:
                    branches.append(node.finalbody)

            for branch in branches:
                max_depth = max(max_depth, _max_depth(branch, depth + 1))

    return max_depth


def _physical_length(node):
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start)
    return max(end - start + 1, 0)


class NestingRule(SkylosRule):
    rule_id = "SKY-Q302"
    name = "Deep Nesting"

    def __init__(self, threshold=3):
        self.threshold = threshold

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        depth = _max_depth(node.body, 0)

        if depth <= self.threshold:
            return None

        if depth <= self.threshold + 2:
            severity = "MEDIUM"
        elif depth <= self.threshold + 5:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        physical_len = _physical_length(node)
        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "nesting",
                "severity": severity,
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "metric": "max_nesting",
                "value": depth,
                "threshold": self.threshold,
                "length": physical_len,
                "message": f"Nesting depth of {depth} exceeds threshold of {self.threshold}. Consider using early returns.",
            }
        ]
