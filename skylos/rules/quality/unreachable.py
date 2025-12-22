import ast
from pathlib import Path
from skylos.rules.base import SkylosRule
from skylos.control_flow import evaluate_static_condition

class UnreachableCodeRule(SkylosRule):
    rule_id = "SKY-U001"
    name = "Unreachable Code"

    def visit_node(self, node, context):
        findings = []
        
        if isinstance(node, ast.If):
            condition = evaluate_static_condition(node.test)
            
            if condition is False and node.body:
                findings.append({
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "dead_branch",
                    "name": "unreachable",
                    "simple_name": "unreachable",
                    "value": "if_false",
                    "threshold": 0,
                    "message": "Dead code: condition is always False",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                })
            elif condition is True and node.orelse:
                findings.append({
                    "rule_id": self.rule_id,
                    "kind": "quality", 
                    "severity": "MEDIUM",
                    "type": "dead_branch",
                    "name": "unreachable",
                    "simple_name": "unreachable",
                    "value": "else_after_true",
                    "threshold": 0,
                    "message": "Dead code: else branch after condition that is always True",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.orelse[0].lineno,
                    "col": node.orelse[0].col_offset,
                })

        if not hasattr(node, "body") or not isinstance(node.body, list):
            if findings:
                return findings
            else:
                return None

        def block_terminates(stmts):
            for s in stmts:
                if isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    return True
                
                if isinstance(s, ast.If):
                    if s.orelse and block_terminates(s.body) and block_terminates(s.orelse):
                        return True
                    
            return False

        terminated = False
        
        for stmt in node.body:
            if terminated:
                findings.append({
                    "rule_id": "SKY-U002",
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "statement",
                    "name": "unreachable",
                    "simple_name": "unreachable",
                    "value": "dead_logic",
                    "threshold": 0,
                    "message": "Unreachable code: statement follows return/raise/break",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": stmt.lineno,
                    "col": stmt.col_offset,
                })
                break

            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True
            elif isinstance(stmt, ast.If):
                if stmt.orelse and block_terminates(stmt.body) and block_terminates(stmt.orelse):
                    terminated = True

        if findings:
            return findings
        else:
            return None
