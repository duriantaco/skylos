"""Additional conservative reachability facts for test-quality subjects.

This is separate from Done's assertion inventory. Abrupt effects are kept
distinct until a loop consumes its own jumps or finally overrides them.
Unknown exceptions and context-manager suppression keep possible paths live.
"""

from __future__ import annotations

import ast

from skylos.done.inventory import _constant_truth

_NORMAL = "normal"
_RAISE = "raise"
_RETURN = "return"
_BREAK = "break"
_CONTINUE = "continue"
_TRY = (ast.Try, getattr(ast, "TryStar", ast.Try))


def unreachable_test_nodes(function) -> frozenset[int]:
    """Return IDs proved unreachable within this directly declared test body."""
    dead = set()

    def bury(statements):
        dead.update(
            id(node) for statement in statements for node in ast.walk(statement)
        )

    def truth(expression):
        try:
            return _constant_truth(expression)
        except RecursionError:
            return None

    def block(statements):
        effects = {_NORMAL}
        for index, statement in enumerate(statements):
            if _NORMAL not in effects:
                bury(statements[index:])
                break
            effects = (effects - {_NORMAL}) | visit(statement)
        return effects

    def visit(statement):
        if isinstance(statement, ast.Return):
            # Returning a name/call can raise before the return happens; an
            # enclosing context manager may suppress that exception.
            return (
                {_RETURN}
                if statement.value is None or isinstance(statement.value, ast.Constant)
                else {_RETURN, _RAISE}
            )
        if isinstance(statement, ast.Raise):
            return {_RAISE}
        if isinstance(statement, ast.Break):
            return {_BREAK}
        if isinstance(statement, ast.Continue):
            return {_CONTINUE}
        if isinstance(statement, ast.If):
            condition = truth(statement.test)
            if condition is True:
                bury(statement.orelse)
                return block(statement.body)
            if condition is False:
                bury(statement.body)
                return block(statement.orelse)
            return block(statement.body) | block(statement.orelse) | {_RAISE}
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            condition = (
                truth(statement.test) if isinstance(statement, ast.While) else None
            )
            empty = (
                isinstance(statement, (ast.For, ast.AsyncFor))
                and isinstance(statement.iter, (ast.Tuple, ast.List))
                and not statement.iter.elts
            )
            if condition is False or empty:
                bury(statement.body)
                return block(statement.orelse)
            body = block(statement.body)
            effects = body - {_NORMAL, _BREAK, _CONTINUE}
            if _BREAK in body:
                effects.add(_NORMAL)  # break bypasses the loop's else clause.
            if condition is not True:
                effects |= block(statement.orelse) | {_RAISE}
            else:
                bury(statement.orelse)
            return effects
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            body = block(statement.body)
            effects = body | {_RAISE}  # entry/exit can fail.
            if _RAISE in body or len(statement.items) > 1:
                # A raise can be suppressed. With multiple managers an outer
                # exit can also suppress an inner exit failure during return.
                effects.add(_NORMAL)
            return effects
        if isinstance(statement, _TRY):
            body = block(statement.body)
            effects = body - {_NORMAL}
            if _NORMAL in body:
                effects |= block(statement.orelse)
            else:
                bury(statement.orelse)
            for handler in statement.handlers:
                if _RAISE in body:
                    effects |= block(handler.body)
                else:
                    bury(handler.body)
            final = block(statement.finalbody)
            return (effects if _NORMAL in final else set()) | (final - {_NORMAL})
        if isinstance(statement, ast.Match):
            # Pattern/guard semantics are deliberately unknown here; an
            # unmatched case remains a possible normal path.
            effects = {_NORMAL, _RAISE}
            for case in statement.cases:
                effects |= block(case.body)
            return effects
        if isinstance(statement, ast.Pass) or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
        ):
            return {_NORMAL}
        # Includes nested definitions: their bodies do not run in this scope,
        # but decorators/defaults, and ordinary statements, can raise.
        return {_NORMAL, _RAISE}

    block(function.body)
    return frozenset(dead)
