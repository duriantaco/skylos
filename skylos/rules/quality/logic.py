import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


class MutableDefaultRule(SkylosRule):
    rule_id = "SKY-L001"
    name = "Mutable Default Argument"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        findings = []

        kw_defaults_filtered = []
        for d in node.args.kw_defaults:
            if d:
                kw_defaults_filtered.append(d)

        for default in node.args.defaults + kw_defaults_filtered:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "function",
                        "name": node.name,
                        "simple_name": node.name,
                        "value": "mutable",
                        "threshold": 0,
                        "message": "Mutable default argument detected (List/Dict/Set). This causes state leaks.",
                        "file": context.get("filename"),
                        "basename": Path(context.get("filename", "")).name,
                        "line": default.lineno,
                        "col": default.col_offset,
                    }
                )
        if findings:
            return findings
        else:
            return None


class BareExceptRule(SkylosRule):
    rule_id = "SKY-L002"
    name = "Bare Except Block"

    def visit_node(self, node, context):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "block",
                    "name": "except",
                    "simple_name": "except",
                    "value": "bare",
                    "threshold": 0,
                    "message": "Bare 'except:' block swallows SystemExit and other critical errors.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


class DangerousComparisonRule(SkylosRule):
    rule_id = "SKY-L003"
    name = "Dangerous Comparison"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Compare):
            return None

        findings = []
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(comparator, ast.Constant):
                    val = comparator.value
                    if val is True or val is False or val is None:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "LOW",
                                "type": "comparison",
                                "name": "==",
                                "simple_name": "==",
                                "value": str(comparator.value),
                                "threshold": 0,
                                "message": f"Comparison to {comparator.value} should use 'is' or 'is not'.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )
        if findings:
            return findings
        else:
            return None


class TryBlockPatternsRule(SkylosRule):
    rule_id = "SKY-L004"
    name = "Anti-Pattern Try Block"

    def __init__(self, max_lines=15, max_control_flow=3):
        self.max_lines = max_lines
        self.max_control_flow = max_control_flow

    def visit_node(self, node, context):
        if not isinstance(node, ast.Try):
            return None

        findings = []

        if node.body:
            start = node.body[0].lineno
            end = getattr(node.body[-1], "end_lineno", start)
            length = end - start + 1

            if length > self.max_lines:
                findings.append(
                    self._create_finding(
                        node,
                        context,
                        severity="LOW",
                        value=length,
                        msg=f"Try block covers {length} lines (limit: {self.max_lines}). Reduce scope to the risky operation only.",
                    )
                )

        control_flow_count = 0
        has_nested_try = False

        for stmt in node.body:
            for child in ast.walk(stmt):
                if isinstance(child, ast.Try):
                    has_nested_try = True

                if isinstance(child, (ast.If, ast.For, ast.While)):
                    control_flow_count += 1

        if has_nested_try:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="MEDIUM",
                    value="nested",
                    msg="Nested 'try' block detected. Flatten logic or move inner try to a helper function.",
                )
            )

        if control_flow_count > self.max_control_flow:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="HIGH",
                    value=control_flow_count,
                    msg=f"Try block contains {control_flow_count} control flow statements. Don't wrap complex logic in error handling.",
                )
            )

        if findings:
            return findings
        else:
            return None

    def _create_finding(self, node, context, severity, value, msg):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": severity,
            "type": "block",
            "name": "try",
            "simple_name": "try",
            "value": value,
            "threshold": 0,
            "message": msg,
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }
