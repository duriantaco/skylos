import ast
from skylos.rules.base import SkylosRule
from skylos.analysis.control_flow import evaluate_static_condition


_BODY_NODE_TYPES = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    getattr(ast, "TryStar", ast.Try),
)


def _static_bool(value):
    if value is None:
        return None
    return bool(value)


def _iter_is_statically_empty(node):
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return len(node.elts) == 0
    if isinstance(node, ast.Dict):
        return len(node.keys) == 0
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return len(node.value) == 0
    return False


class UnreachableCodeRule(SkylosRule):
    rule_id = "SKY-UC001"
    name = "Unreachable Code"

    def visit_node(self, node, context):
        if not isinstance(node, _BODY_NODE_TYPES):
            return None

        findings = []

        filename = context.get("filename", "")
        if filename:
            basename = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
        else:
            basename = ""

        if isinstance(node, ast.If):
            cond = evaluate_static_condition(node.test, file_path=filename)

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

        if isinstance(node, ast.While):
            cond = _static_bool(
                evaluate_static_condition(node.test, file_path=filename)
            )

            if cond is False and node.body:
                first = node.body[0]
                findings.append(
                    self._mk(
                        filename,
                        basename,
                        line=getattr(first, "lineno", node.lineno),
                        col=getattr(first, "col_offset", node.col_offset),
                        msg="Dead code: loop body never runs because condition is always False",
                        value="while_false",
                        kind="dead_branch",
                    )
                )
                return findings

        if isinstance(node, ast.For):
            if _iter_is_statically_empty(node.iter) and node.body:
                first = node.body[0]
                findings.append(
                    self._mk(
                        filename,
                        basename,
                        line=getattr(first, "lineno", node.lineno),
                        col=getattr(first, "col_offset", node.col_offset),
                        msg=(
                            "Dead code: loop body never runs because iterable is "
                            "statically empty"
                        ),
                        value="for_empty_iterable",
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

        if isinstance(stmt, ast.While):
            cond = _static_bool(evaluate_static_condition(stmt.test))
            return cond is True and not self._has_current_loop_break(stmt.body)

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
        if isinstance(stmt, ast.While):
            return "loop that cannot fall through"
        return "return"

    def _has_current_loop_break(self, stmts):
        stack = list(reversed(stmts))
        boundary_nodes = (
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.Lambda,
        )

        while stack:
            node = stack.pop()
            if isinstance(node, ast.Break):
                return True
            if isinstance(node, boundary_nodes):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(node))))

        return False
