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
                findings.append({
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
                    "col": default.col_offset
                })
        if findings:
            return findings
        else:
            return None

class BareExceptRule(SkylosRule):
    rule_id = "SKY-L002"
    name = "Bare Except Block"

    def visit_node(self, node, context):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            return [{
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
                "col": node.col_offset
            }]
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
                        findings.append({
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
                        "col": node.col_offset
                    })
        if findings:
            return findings
        else:
            return None