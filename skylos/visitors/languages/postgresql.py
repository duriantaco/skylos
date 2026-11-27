"""Static checks for standalone PostgreSQL source. SQL is never executed."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

try:
    from pglast import ast, enums, parse_sql
    from pglast.parser import ParseError
except ImportError:
    ast = None


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


def _filter_comparisons(expr):
    """Only inspect predicates, without mistaking a subquery's output for a filter."""
    pending = [expr]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.BoolExpr):
            pending.extend(node.args or ())
        elif (
            isinstance(node, ast.A_Expr)
            and node.kind == enums.A_Expr_Kind.AEXPR_OP
            and len(node.name) == 1
            and node.name[0].sval in {"=", "<>"}
            and any(
                isinstance(side, ast.A_Const) and side.isnull
                for side in (node.lexpr, node.rexpr)
            )
        ):
            yield node


def _definer_option(stmt):
    if stmt.is_procedure:
        return None
    security = None
    for option in stmt.options or ():
        if option.defname == "security" and option.arg.boolval:
            security = option
        if (
            option.defname == "set"
            and option.arg.name == "search_path"
            and option.arg.kind
            in {
                enums.VariableSetKind.VAR_SET_VALUE,
                enums.VariableSetKind.VAR_SET_CURRENT,
            }
        ):
            # FROM CURRENT captures a fixed value when the function is created.
            return None
    return security


def _scan_statement(stmt, report, null_equals_enabled):
    pending = [(stmt, None, None)]
    definitions = {}
    used = set()
    has_effect = set()
    while pending:
        node, scope, owner = pending.pop()
        if isinstance(node, tuple):
            pending.extend((child, scope, owner) for child in node)
            continue
        if not isinstance(node, ast.Node):
            continue
        if isinstance(node, ast.RangeVar) and scope and not node.schemaname:
            referenced = scope.resolve(node.relname)
            if referenced is not None and referenced != owner:
                used.add(referenced)
        if owner is not None and isinstance(
            node, (ast.FuncCall, ast.LockingClause, ast.IntoClause)
        ):
            # Function volatility and user-defined side effects need a database catalog.
            has_effect.add(owner)
        if isinstance(node, ast.CreateFunctionStmt):
            option = _definer_option(node)
            if option:
                report(
                    option.location,
                    "SKY-D417",
                    "MEDIUM",
                    "SECURITY DEFINER function has no fixed search_path in its declaration. "
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
            value = getattr(node, field)
            if isinstance(value, (ast.Node, tuple)):
                pending.append((value, scope, owner))
            if (
                field in {"whereClause", "havingClause", "agg_filter", "joinCondition"}
                or (field == "quals" and isinstance(node, ast.JoinExpr))
                or (field == "condition" and isinstance(node, ast.MergeWhenClause))
            ):
                for comparison in _filter_comparisons(value):
                    equality = comparison.name[0].sval == "="
                    if equality and null_equals_enabled:
                        continue
                    replacement = "IS NULL" if equality else "IS NOT NULL"
                    report(
                        comparison.location,
                        "SKY-Q504",
                        "MEDIUM",
                        f"Ordinary comparison with NULL in a filter. Use {replacement} to test for null.",
                    )
    for location, name in definitions.items():
        if location not in used and location not in has_effect:
            report(
                location,
                "SKY-Q503",
                "LOW",
                f"Read-only CTE '{name}' is never referenced.",
            )


def scan_postgresql(source: str, filename: str) -> tuple[list[dict], str | None]:
    """Return source findings and a reason if the file could not be parsed."""
    if ast is None:
        return [], "PostgreSQL parser unavailable. Install skylos[postgres]."
    if "\x00" in source:
        return [], "PostgreSQL source contains a NUL character."
    try:
        source_bytes = len(source.encode("utf-8"))
    except UnicodeEncodeError:
        return [], "PostgreSQL source is not valid UTF-8."
    if source_bytes > 4_000_000:
        return [], "PostgreSQL file exceeds the 4 MB parse limit."
    try:
        statements = parse_sql(source)
    except (ParseError, RecursionError) as exc:
        return [], f"PostgreSQL parse error: {exc}"

    # pglast's Python AST translates PostgreSQL byte positions to character offsets.
    newlines = [i for i, char in enumerate(source) if char == "\n"]
    findings = []

    def report(offset, rule_id, severity, message):
        findings.append(
            {
                "file": str(filename),
                "line": 1 + bisect_right(newlines, offset),
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
            }
        )

    may_rewrite_null_equals = False
    for raw in statements:
        stmt = raw.stmt
        if (
            isinstance(stmt, ast.VariableSetStmt)
            and stmt.name == "transform_null_equals"
        ):
            args = stmt.args or ()
            value = args[0].val if args else None
            # A transaction rollback or savepoint can restore a previous setting.
            # Stay conservative once the script enables nonstandard NULL equality.
            may_rewrite_null_equals |= (
                stmt.kind == enums.VariableSetKind.VAR_SET_CURRENT
                or (
                    isinstance(value, ast.String)
                    and value.sval.lower() in {"on", "yes", "true", "1"}
                )
                or (isinstance(value, ast.Integer) and value.ival == 1)
            )
        _scan_statement(stmt, report, may_rewrite_null_equals)
    findings.sort(key=lambda finding: (finding["line"], finding["rule_id"]))
    return findings, None
