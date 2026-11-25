"""Shared lexical and SQLite call checks for SQL provenance."""

import ast
from inspect import Parameter, Signature

_METHOD = (ast.FunctionDef, ast.AsyncFunctionDef)
_CONNECT_OPTIONS = (
    "database",
    "timeout",
    "detect_types",
    "isolation_level",
    "check_same_thread",
)


def _valid_call(function, call, *, bound=False):
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return False
    keywords = {kw.arg: kw.value for kw in call.keywords}
    if None in keywords or len(keywords) != len(call.keywords):
        return False
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = [Parameter.empty] * (
        len(positional) - len(args.defaults)
    ) + args.defaults
    parameters = [
        Parameter(
            arg.arg,
            Parameter.POSITIONAL_ONLY
            if i < len(args.posonlyargs)
            else Parameter.POSITIONAL_OR_KEYWORD,
            default=default,
        )
        for i, (arg, default) in enumerate(zip(positional, defaults, strict=True))
    ]
    if args.vararg:
        parameters.append(Parameter(args.vararg.arg, Parameter.VAR_POSITIONAL))
    parameters.extend(
        Parameter(
            arg.arg,
            Parameter.KEYWORD_ONLY,
            default=Parameter.empty if default is None else default,
        )
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
    )
    if args.kwarg:
        parameters.append(Parameter(args.kwarg.arg, Parameter.VAR_KEYWORD))
    try:
        Signature(parameters).bind(*([None] if bound else []), *call.args, **keywords)
    except (TypeError, ValueError):
        return False
    return True


def _prior(unit, at, function):
    """Statements on the lexical path to an expression, innermost first."""
    child = at
    for parent in unit.ancestors(at):
        if isinstance(parent, (ast.BoolOp, ast.comprehension, ast.Lambda)):
            return
        for attr in ("body", "orelse"):
            statements = getattr(parent, attr, None)
            if isinstance(statements, list) and child in statements:
                yield from reversed(statements[: statements.index(child)])
        if parent is function:
            return
        child = parent


def _terminates(stmt):
    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Constant):
        return any(
            _terminates(part)
            for part in (stmt.body if stmt.test.value else stmt.orelse)
        )
    return False


def _reachable(unit, at, function):
    child = at
    for parent in unit.ancestors(at):
        if parent is function:
            return not any(_terminates(stmt) for stmt in _prior(unit, at, function))
        if (
            isinstance(parent, ast.If)
            and isinstance(parent.test, ast.Constant)
            and (
                child in parent.body
                and not parent.test.value
                or child in parent.orelse
                and parent.test.value
            )
        ):
            return False
        if isinstance(
            parent,
            (ast.Lambda, ast.comprehension, ast.IfExp, ast.BoolOp, ast.ExceptHandler),
        ):
            return False
        child = parent
    return False


def _one(values):
    return next(iter(values)) if values and len(values) == 1 else None


def _load(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _first(fn):
    args = [*fn.args.posonlyargs, *fn.args.args]
    return args[0].arg if args else None


def _own_nodes(block):
    for node in block:
        if isinstance(node, (*_METHOD, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        yield from _own_nodes(ast.iter_child_nodes(node))


def _native_connect_arguments(expression):
    keywords = {kw.arg for kw in expression.keywords}
    return (
        (bool(expression.args) or "database" in keywords)
        and not any(isinstance(arg, ast.Starred) for arg in expression.args)
        and len(expression.args) <= len(_CONNECT_OPTIONS)
        and len(keywords) == len(expression.keywords)
        and keywords
        <= set(_CONNECT_OPTIONS[len(expression.args) :])
        | {"cached_statements", "uri", "autocommit"}
    )
