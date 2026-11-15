"""A whole-value regular-expression match that admits filename characters only.

``PATTERN.fullmatch(value)``, or ``PATTERN.match(value)`` when the pattern ends
with ``$`` or ``\\Z``, proves ``value`` holds no separator, dot or drive colon
when every character the pattern can match is a letter, digit, ``-`` or ``_``.
A prefix match or a search proves nothing about the rest of the value.
"""

from __future__ import annotations

import ast
import re

try:
    from re import _constants as _codes
    from re import _parser as _syntax
except ImportError:
    import sre_constants as _codes
    import sre_parse as _syntax

_TEXT_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "casefold"})


def _ends_at_end(text):
    try:
        items = list(_syntax.parse(text, 0))
    except (re.error, OverflowError, RecursionError, ValueError, TypeError):
        return False
    if not items:
        return False
    op, value = items[-1]
    return op is _codes.AT and value in {_codes.AT_END, _codes.AT_END_STRING}


def filename_match_subject(call, binding, canonical):
    """The expression ``call`` proves to be filename characters, or None."""
    from skylos.rules.danger.danger_fs.path_provenance import _filename_pattern

    func = call.func
    if (
        not isinstance(func, ast.Attribute)
        or func.attr not in {"fullmatch", "match"}
        or call.keywords
    ):
        return None
    if canonical(func) in {"re.fullmatch", "re.match"}:
        if len(call.args) != 2:
            return None
        pattern, subject = call.args
    else:
        if not isinstance(func.value, ast.Name) or len(call.args) != 1:
            return None
        compiled = binding(func.value.id)
        if (
            not isinstance(compiled, ast.Call)
            or canonical(compiled.func) != "re.compile"
            or len(compiled.args) != 1
            or compiled.keywords
        ):
            return None
        pattern, subject = compiled.args[0], call.args[0]
    if not isinstance(pattern, ast.Constant) or not isinstance(pattern.value, str):
        return None
    if not _filename_pattern(pattern.value, 0):
        return None
    if func.attr == "match" and not _ends_at_end(pattern.value):
        return None
    return subject


def names_when(test, holds, call_names):
    """Names ``call_names`` vouches for when ``test`` evaluates to ``holds``,
    through ``not``, ``and``/``or`` and ``is None``/``is not None``."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return names_when(test.operand, not holds, call_names)
    if isinstance(test, ast.BoolOp):
        parts = [names_when(value, holds, call_names) for value in test.values]
        if isinstance(test.op, ast.And) == holds:
            return set().union(*parts)
        return set.intersection(*parts)
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.left, ast.Call)
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    ):
        if isinstance(test.ops[0], ast.IsNot):
            return names_when(test.left, holds, call_names)
        if isinstance(test.ops[0], ast.Is):
            return names_when(test.left, not holds, call_names)
        return set()
    if isinstance(test, ast.Call) and holds:
        return set(call_names(test))
    return set()


def native_text_name(name, function, binding):
    """``name`` is a ``str`` parameter of ``function``, or its one binding is
    a built-in text method of such a parameter."""
    if function is None or isinstance(function, ast.Lambda):
        return False
    arguments = function.args
    parameters = {
        argument.arg: argument
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        )
    }

    def annotated(parameter):
        annotation = parameter.annotation
        return isinstance(annotation, ast.Name) and annotation.id == "str"

    if name in parameters:
        return annotated(parameters[name])
    value = binding(name)
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr in _TEXT_METHODS
        and not value.keywords
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id in parameters
        and annotated(parameters[value.func.value.id])
    )


def rejecting_guards(function, proven_names, terminates):
    """Names each top-level ``if`` of ``function`` proves before the code
    after it runs, in statement order: ``[(statement index, names)]``."""
    found = []
    for index, statement in enumerate(function.body):
        if isinstance(statement, ast.If) and not statement.orelse:
            names = proven_names(statement.test)
            if names and terminates(statement.body):
                found.append((index, names))
    return found


def validated_return(function, proven_names, terminates):
    """True when every value ``function`` returns is a name one of its
    top-level guards proved, and nothing rebinds that name afterwards."""
    if not isinstance(function, ast.FunctionDef) or function.decorator_list:
        return False
    guards = rejecting_guards(function, proven_names, terminates)
    if not guards:
        return False
    returned = False
    for index, statement in enumerate(function.body):
        active = set()
        for position, names in guards:
            if position < index:
                active |= names
        for node in ast.walk(statement):
            if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Lambda)):
                return False
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return False
            if (
                isinstance(node, ast.Return)
                and node is not statement
                and not isinstance(node.value, ast.Constant)
            ):
                return False
        if isinstance(statement, ast.Return):
            if not isinstance(statement.value, ast.Name):
                return False
            if statement.value.id not in active:
                return False
            returned = True
    if not returned:
        return False
    proven = set().union(*(names for _, names in guards))
    first = {name: min(p for p, names in guards if name in names) for name in proven}
    for index, statement in enumerate(function.body):
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id in proven
                and index > first[node.id]
            ):
                return False
    return True
