"""Reviews for CASE branches and conditional counts in parsed PostgreSQL."""

from pglast import ast


def _selector_type(selector):
    if isinstance(selector, ast.A_Const) and isinstance(
        selector.val, (ast.Boolean, ast.Integer)
    ):
        return type(selector.val)
    if isinstance(selector, ast.TypeCast):
        target = selector.typeName
        names = tuple(part.sval for part in target.names or ())
        if target.arrayBounds or target.pct_type or target.setof:
            return None
        if names in {
            ("pg_catalog", "int2"),
            ("pg_catalog", "int4"),
            ("pg_catalog", "int8"),
        }:
            return ast.Integer
        if names == ("pg_catalog", "bool"):
            return ast.Boolean
    return None


def _check_case(node, report):
    # A raw column has no resolved type. Its equality operator may be custom.
    simple_type = _selector_type(node.arg)
    seen = set()
    after_true = False
    for arm in node.args or ():
        expr = arm.expr
        if after_true:
            report(
                arm.location,
                "SKY-Q509",
                "LOW",
                "This CASE arm follows WHEN TRUE and can never supply the result.",
            )
            continue
        key = None
        if node.arg is None:
            if isinstance(expr, ast.A_Const) and isinstance(expr.val, ast.Boolean):
                after_true = expr.val.boolval
            elif isinstance(expr, ast.NullTest) and isinstance(expr.arg, ast.ColumnRef):
                fields = expr.arg.fields
                # A qualified name can call a volatile composite-field function.
                if len(fields) == 1 and isinstance(fields[0], ast.String):
                    key = (expr.nulltesttype, fields[0].sval)
        elif isinstance(expr, ast.A_Const):
            if simple_type is ast.Boolean and isinstance(expr.val, ast.Boolean):
                key = expr.val.boolval
            elif simple_type is ast.Integer and isinstance(expr.val, ast.Integer):
                key = expr.val.ival
        if key is not None:
            if key in seen:
                report(
                    arm.location,
                    "SKY-Q509",
                    "LOW",
                    "An earlier CASE arm already tests this value or condition. "
                    "This arm cannot supply a different result.",
                )
            seen.add(key)


def _check_count(node, report):
    if (
        len(node.args or ()) != 1
        or not isinstance(node.args[0], ast.CaseExpr)
        or node.agg_distinct
        or node.agg_order
        or node.agg_within_group
        or node.func_variadic
    ):
        return
    name = tuple(part.sval for part in node.funcname)
    if name not in {("count",), ("pg_catalog", "count")}:
        return
    case = node.args[0]
    fallback = case.defresult
    if not isinstance(fallback, ast.A_Const) or not isinstance(
        fallback.val, (ast.Integer, ast.Float, ast.String, ast.Boolean)
    ):
        return
    if all(
        isinstance(arm.result, ast.A_Const)
        and type(arm.result.val) is type(fallback.val)
        for arm in case.args
    ):
        report(
            node.location,
            "SKY-Q510",
            "MEDIUM",
            "Every result of this CASE is non-null, so PostgreSQL's built-in "
            "COUNT includes every input row. Use a FILTER to count matching rows.",
        )


def check_query_node(node, report):
    if isinstance(node, ast.CaseExpr):
        _check_case(node, report)
    elif isinstance(node, ast.FuncCall):
        _check_count(node, report)
