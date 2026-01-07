import ast
from pathlib import Path
from skylos.rules.base import SkylosRule
from skylos.control_flow import evaluate_static_condition


class UnreachableCodeRule(SkylosRule):
    rule_id = "SKY-UC001"
    name = "Unreachable Code"

    def visit_node(self, node, context):
        findings = []

        filename = context.get("filename", "")
        if filename:
            basename = Path(filename).name
        else:
            basename = ""

        if isinstance(node, ast.If):
            cond = evaluate_static_condition(node.test)

            if cond is False and node.body:
                first = node.body[0]
                findings.append(
                    self._mk(
                        filename,
                        basename,
                        line=getattr(first, "lineno", node.lineno),
                        col=getattr(first, "col_offset", node.col_offset),
                        msg="Dead code: condition is always False",
                        value="if_false",
                        kind="dead_branch",
                    )
                )
                return findings

            if cond is True and node.orelse:
                first = node.orelse[0]
                findings.append(
                    self._mk(
                        filename,
                        basename,
                        line=getattr(first, "lineno", node.lineno),
                        col=getattr(first, "col_offset", node.col_offset),
                        msg="Dead code: else branch after condition that is always True",
                        value="else_after_true",
                        kind="dead_branch",
                    )
                )
                return findings

        body = getattr(node, "body", None)
        if not isinstance(body, list):
            return findings

        finding = self._first_unreachable_in_block(body, filename, basename)
        if finding:
            findings.append(finding)

        return findings

    def _mk(self, filename, basename, line, col, msg, value, kind="unreachable"):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": "MEDIUM",
            "type": kind,
            "name": "unreachable",
            "simple_name": "unreachable",
            "value": value,
            "threshold": 0,
            "message": msg,
            "file": filename,
            "basename": basename,
            "line": int(line) if line is not None else 1,
            "col": int(col) if col is not None else 0,
        }

    def _first_unreachable_in_block(self, stmts, filename, basename):
        terminated_by = None

        for stmt in stmts:
            if terminated_by is not None:
                return self._mk(
                    filename,
                    basename,
                    line=getattr(stmt, "lineno", 1),
                    col=getattr(stmt, "col_offset", 0),
                    msg=f"Unreachable code: statement follows a {terminated_by}",
                    value=terminated_by,
                    kind="unreachable",
                )

            if self._stmt_terminates_block(stmt):
                terminated_by = self._terminator_kind(stmt)

        return None

    def _stmt_terminates_block(self, stmt):
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True

        if isinstance(stmt, ast.If) and stmt.orelse:
            return self._block_terminates(stmt.body) and self._block_terminates(
                stmt.orelse
            )

        return False

    def _block_terminates(self, stmts):
        if not stmts:
            return False
        last = stmts[-1]
        return self._stmt_terminates_block(last)

    def _terminator_kind(self, stmt):
        if isinstance(stmt, ast.Return):
            return "return"
        if isinstance(stmt, ast.Raise):
            return "raise"
        if isinstance(stmt, ast.Break):
            return "break"
        if isinstance(stmt, ast.Continue):
            return "continue"
        if isinstance(stmt, ast.If):
            return "return"
        return "return"
