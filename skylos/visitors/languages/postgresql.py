"""Static checks for standalone PostgreSQL source. SQL is never executed."""

from __future__ import annotations

import re
from array import array
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass

try:
    from pglast import ast, enums
    from pglast.parser import ParseError
except ImportError:
    ast = None
else:
    from .postgresql_migrations import scan_migrations
    from .postgresql_privileges import check_privileges
    from .postgresql_queries import check_query_node


# PostgreSQL boolean settings accept unambiguous prefixes. "o" is ambiguous.
_TRUE_GUC_VALUES = frozenset({"1", "on", "y", "ye", "yes", "t", "tr", "tru", "true"})


@dataclass(frozen=True)
class _Scope:
    """A nonrecursive CTE can see only earlier siblings."""

    declarations: dict[str, tuple[int, int]]
    visible: int
    parent: _Scope | None

    def resolve(self, name):
        scope = self
        while scope is not None:
            hit = scope.declarations.get(name)
            if hit is not None and hit[0] < scope.visible:
                return hit[1]
            scope = scope.parent
        return None


def _literal_null_list(expr):
    left = expr.lexpr
    if isinstance(left, ast.ColumnRef):
        if not all(isinstance(field, ast.String) for field in left.fields):
            return False
    elif not isinstance(left, ast.A_Const) or left.isnull:
        return False
    values = expr.rexpr
    return (
        isinstance(values, tuple)
        and all(isinstance(item, ast.A_Const) for item in values)
        and any(item.isnull for item in values)
    )


def _check_filter(expr, report, null_equals_enabled):
    """Inspect boolean predicates. A nested SELECT owns its own filter."""
    pending = [(expr, True)]
    while pending:
        node, required = pending.pop()
        if isinstance(node, ast.BoolExpr):
            required = required and node.boolop == enums.BoolExprType.AND_EXPR
            pending.extend((arg, required) for arg in node.args or ())
            continue
        if not isinstance(node, ast.A_Expr) or len(node.name or ()) != 1:
            continue
        operator = node.name[0].sval
        if (
            node.kind == enums.A_Expr_Kind.AEXPR_IN
            and operator == "<>"
            and required
            and _literal_null_list(node)
        ):
            report(
                node.location,
                "SKY-Q505",
                "MEDIUM",
                "Literal NULL in a NOT IN filter. With ordinary equality, even "
                "unmatched values cannot satisfy this condition. Check how missing "
                "values should be handled.",
            )
        elif (
            node.kind == enums.A_Expr_Kind.AEXPR_OP
            and operator in {"=", "<>"}
            and not (operator == "=" and null_equals_enabled)
            and any(
                isinstance(side, ast.A_Const) and side.isnull
                for side in (node.lexpr, node.rexpr)
            )
        ):
            replacement = "IS NULL" if operator == "=" else "IS NOT NULL"
            report(
                node.location,
                "SKY-Q504",
                "MEDIUM",
                f"Ordinary comparison with NULL in a filter. Use {replacement} to test for null.",
            )


def _definer_option(stmt):
    # CREATE starts with no routine-local settings. ALTER preserves any
    # existing settings unless this statement explicitly removes them.
    creating = isinstance(stmt, ast.CreateFunctionStmt)
    path_known_missing = creating
    options = stmt.options if creating else stmt.actions
    security = None
    for option in options or ():
        if option.defname == "security":
            if security is not None:
                return None  # PostgreSQL rejects duplicate SECURITY clauses.
            security = option
        elif option.defname == "set":
            # PostgreSQL applies routine settings from left to right.
            setting = option.arg
            if setting.kind == enums.VariableSetKind.VAR_RESET_ALL:
                path_known_missing = True
            elif setting.name and setting.name.lower() == "search_path":
                path_known_missing = setting.kind in {
                    enums.VariableSetKind.VAR_SET_DEFAULT,
                    enums.VariableSetKind.VAR_RESET,
                }
    if security is not None and security.arg.boolval and path_known_missing:
        return security
    return None


def _scan_statement(stmt, report, null_equals_enabled):
    pending = [(stmt, None, None)]
    definitions = {}
    dependencies = defaultdict(set)
    roots = {None}  # The outer statement always consumes its inputs.
    while pending:
        node, scope, owner = pending.pop()
        if isinstance(node, tuple):
            pending.extend((child, scope, owner) for child in node)
            continue
        if not isinstance(node, ast.Node):
            continue
        check_query_node(node, report)
        if isinstance(node, ast.RangeVar) and scope and not node.schemaname:
            referenced = scope.resolve(node.relname)
            if referenced is not None and referenced != owner:
                dependencies[owner].add(referenced)
        if owner is not None and isinstance(
            node, (ast.FuncCall, ast.LockingClause, ast.IntoClause)
        ):
            # Function volatility and user-defined side effects need a database catalog.
            roots.add(owner)
        if isinstance(node, (ast.CreateFunctionStmt, ast.AlterFunctionStmt)):
            option = _definer_option(node)
            if option:
                report(
                    option.location,
                    "SKY-D417",
                    "MEDIUM",
                    "This statement leaves a SECURITY DEFINER routine without a fixed search_path. "
                    "Set the path to trusted schemas and put pg_temp last.",
                )
        with_clause = getattr(node, "withClause", None)
        if with_clause:
            ctes = with_clause.ctes
            declarations = {c.ctename: (i, c.location) for i, c in enumerate(ctes)}
            full_scope = _Scope(declarations, len(ctes), scope)
            for i, cte in enumerate(ctes):
                body_scope = (
                    full_scope
                    if with_clause.recursive
                    else _Scope(declarations, i, scope)
                )
                if isinstance(cte.ctequery, ast.SelectStmt):
                    definitions[cte.location] = cte.ctename
                else:
                    roots.add(
                        cte.location
                    )  # A data-modifying CTE can run even if unread.
                pending.append((cte.ctequery, body_scope, cte.location))
            scope = full_scope
        for field in node:
            if field == "withClause":
                continue
            if field == "relation" and isinstance(
                node, (ast.UpdateStmt, ast.DeleteStmt, ast.InsertStmt, ast.MergeStmt)
            ):
                # DML always targets an actual relation, even when a CTE shares its name.
                continue
            if (field == "lockedRels" and isinstance(node, ast.LockingClause)) or (
                field == "rel" and isinstance(node, ast.IntoClause)
            ):
                # Lock targets name FROM aliases. INTO names a destination table.
                continue
            value = getattr(node, field)
            if isinstance(value, (ast.Node, tuple)):
                pending.append((value, scope, owner))
            if (
                field in {"whereClause", "havingClause", "agg_filter", "joinCondition"}
                or (field == "quals" and isinstance(node, ast.JoinExpr))
                or (field == "condition" and isinstance(node, ast.MergeWhenClause))
            ):
                _check_filter(value, report, null_equals_enabled)
    live = set(roots)
    pending = list(roots)
    while pending:
        for dependency in dependencies.get(pending.pop(), ()):
            if dependency not in live:
                live.add(dependency)
                pending.append(dependency)
    for location, name in definitions.items():
        if location not in live:
            report(
                location,
                "SKY-Q503",
                "LOW",
                f"Read-only CTE '{name}' does not feed the statement or a potentially effectful CTE.",
            )


def scan_postgresql(source: str, filename: str) -> tuple[list[dict], str | None]:
    """Return source findings and a reason if the file could not be parsed."""
    if ast is None:
        return [], "PostgreSQL parser unavailable. Install skylos[postgres]."
    if "\x00" in source:
        return [], "PostgreSQL source contains a NUL character."
    from .postgresql_script import PsqlScriptError, parse_script

    try:
        source, sessions = parse_script(source)
    except PsqlScriptError as exc:
        return [], str(exc)
    except (ParseError, RecursionError) as exc:
        return [], f"PostgreSQL parse error: {exc}"

    # pglast's Python AST translates PostgreSQL byte positions to character offsets.
    newlines = array("I", (m.end() - 1 for m in re.finditer(r"\r\n?|\n", source)))
    findings = []

    def report(offset, rule_id, severity, message):
        findings.append(
            {
                "file": str(filename),
                "line": 1 + bisect_right(newlines, session_offset + offset),
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
            }
        )

    for session_offset, statements in sessions:
        scan_migrations(statements, report)
        may_rewrite_null_equals = False
        for raw in statements:
            stmt = raw.stmt
            if (
                isinstance(stmt, ast.VariableSetStmt)
                and stmt.name
                and stmt.name.lower() == "transform_null_equals"
            ):
                args = stmt.args or ()
                value = (
                    args[0].val
                    if len(args) == 1 and isinstance(args[0], ast.A_Const)
                    else None
                )
                # A transaction rollback or savepoint can restore a previous setting.
                # Stay conservative once the script enables nonstandard NULL equality.
                may_rewrite_null_equals |= (
                    stmt.kind == enums.VariableSetKind.VAR_SET_CURRENT
                    or (
                        isinstance(value, ast.String)
                        and value.sval.lower() in _TRUE_GUC_VALUES
                    )
                    or (isinstance(value, ast.Integer) and value.ival == 1)
                )
            check_privileges(stmt, report)
            _scan_statement(stmt, report, may_rewrite_null_equals)
    findings.sort(key=lambda finding: (finding["line"], finding["rule_id"]))
    return findings, None
