"""Finite formatting operations which preserve a proven filename component."""

from __future__ import annotations

import ast
import re
import string

_NUMERIC_SPEC = re.compile(
    r"(?:[ <>=^])?[+ -]?(?:z)?#?0?\d*(?:[_,])?(?:\.\d+)?[bdeEfFgGosxX%]?"
)
_PERCENT_FIELD = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[diouxXeEfFgGs%]")


def literal_spec_preserves_component(node):
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(_NUMERIC_SPEC.fullmatch(node.value))
    )


def format_call_preserves_component(node):
    """Only literal templates and specs, without attribute/protocol dispatch."""
    if not isinstance(node.func, ast.Attribute):
        # builtin format(value, specification)
        return len(node.args) <= 1 or (
            len(node.args) == 2 and literal_spec_preserves_component(node.args[1])
        )
    template = node.func.value
    if not isinstance(template, ast.Constant) or not isinstance(template.value, str):
        return False
    try:
        fields = string.Formatter().parse(template.value)
        return all(
            name is None
            or (
                (not name or name.isidentifier() or name.isdecimal())
                and conversion in {None, "s"}
                and bool(_NUMERIC_SPEC.fullmatch(spec))
            )
            for _literal, name, spec, conversion in fields
        )
    except ValueError:
        return False


def percent_preserves_component(template):
    if not isinstance(template, ast.Constant) or not isinstance(template.value, str):
        return False
    cursor = 0
    while (cursor := template.value.find("%", cursor)) >= 0:
        match = _PERCENT_FIELD.match(template.value, cursor)
        if match is None:
            return False
        cursor = match.end()
    return True


def fstring_preserves_component(node):
    # repr/ascii may introduce backslashes even if the original component has
    # none. Arbitrary __format__ behavior is not granted a shape proof here.
    if node.conversion not in {-1, ord("s")}:
        return False
    spec = node.format_spec
    if spec is None:
        return True
    if not isinstance(spec, ast.JoinedStr) or not all(
        isinstance(part, ast.Constant) and isinstance(part.value, str)
        for part in spec.values
    ):
        return False
    text = "".join(part.value for part in spec.values)
    # In particular, c may turn an integer into '/', n depends on locale,
    # and an explicit fill character may itself be a pathname delimiter.
    return bool(_NUMERIC_SPEC.fullmatch(text))
