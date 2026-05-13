import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


def _count_code_lines(lines: list[str]) -> int:
    return sum(
        1 for line in lines if line.strip() and not line.lstrip().startswith("#")
    )


def _count_code_lines_from_source(source: str) -> int:
    return _count_code_lines(source.splitlines())


def _count_code_lines_from_file(filename: str) -> int | None:
    if not filename:
        return None

    try:
        lines = Path(filename).read_text(encoding="utf-8", errors="ignore").splitlines()  # skylos: ignore[SKY-D215] analyzer reads discovered source files
    except OSError:
        return None

    return _count_code_lines(lines)


def _count_ast_lines(node: ast.AST) -> int:
    max_line = 0
    for child in ast.walk(node):
        line = getattr(child, "end_lineno", None) or getattr(child, "lineno", None)
        if isinstance(line, int) and line > max_line:
            max_line = line
    return max_line


class GodFileRule(SkylosRule):
    rule_id = "SKY-Q502"
    name = "God File"

    def __init__(
        self,
        max_lines=500,
        max_definitions=40,
        max_top_level_definitions=25,
    ):
        self.max_lines = max_lines
        self.max_definitions = max_definitions
        self.max_top_level_definitions = max_top_level_definitions

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        source = context.get("source")
        if isinstance(source, str):
            code_lines = _count_code_lines_from_source(source)
        else:
            code_lines = _count_code_lines_from_file(filename)
        if code_lines is None:
            code_lines = _count_ast_lines(node)

        top_level_definitions = sum(
            1
            for item in node.body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        )
        class_count = sum(
            1 for item in ast.walk(node) if isinstance(item, ast.ClassDef)
        )
        function_count = sum(
            1
            for item in ast.walk(node)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        total_definitions = class_count + function_count

        metrics = [
            ("code_lines", code_lines, self.max_lines, "code lines"),
            (
                "total_definitions",
                total_definitions,
                self.max_definitions,
                "definitions",
            ),
            (
                "top_level_definitions",
                top_level_definitions,
                self.max_top_level_definitions,
                "top-level definitions",
            ),
        ]
        violations = [
            metric for metric in metrics if metric[2] > 0 and metric[1] > metric[2]
        ]
        if not violations:
            return None

        primary_metric, value, threshold, _label = max(
            violations,
            key=lambda metric: metric[1] / metric[2],
        )
        worst_ratio = value / threshold if threshold else 1.0
        severity = "HIGH" if worst_ratio >= 1.5 or len(violations) >= 2 else "MEDIUM"

        basename = Path(filename).name if filename else "<module>"
        module_name = context.get("mod") or basename
        violation_summary = ", ".join(
            f"{label}={actual} (limit: {limit})"
            for _metric, actual, limit, label in violations
        )

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "module",
                "name": module_name,
                "simple_name": basename,
                "value": value,
                "threshold": threshold,
                "metric": primary_metric,
                "code_lines": code_lines,
                "total_definitions": total_definitions,
                "top_level_definitions": top_level_definitions,
                "class_count": class_count,
                "function_count": function_count,
                "message": (
                    f"File '{basename}' is a god file candidate: {violation_summary}. "
                    "Consider splitting it by responsibility."
                ),
                "file": filename,
                "basename": basename,
                "line": 1,
                "col": 0,
            }
        ]


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
