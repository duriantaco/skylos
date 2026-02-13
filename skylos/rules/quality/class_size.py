import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


class GodClassRule(SkylosRule):
    rule_id = "SKY-Q501"
    name = "God Class"

    def __init__(self, max_methods=20, max_attributes=15):
        self.max_methods = max_methods
        self.max_attributes = max_attributes

    def visit_node(self, node, context):
        if not isinstance(node, ast.ClassDef):
            return None

        method_count = 0
        attributes = set()

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_count += 1

                for child in ast.walk(item):
                    if (
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id == "self"
                        and isinstance(child.ctx, ast.Store)
                    ):
                        attributes.add(child.attr)

        findings = []

        if method_count > self.max_methods:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": method_count,
                    "threshold": self.max_methods,
                    "message": f"Class '{node.name}' has {method_count} methods (limit: {self.max_methods}). Consider splitting into smaller classes.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        if len(attributes) > self.max_attributes:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": len(attributes),
                    "threshold": self.max_attributes,
                    "message": f"Class '{node.name}' has {len(attributes)} attributes (limit: {self.max_attributes}). Consider splitting into smaller classes.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        return findings if findings else None
