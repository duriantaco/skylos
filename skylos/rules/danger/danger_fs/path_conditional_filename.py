"""Filename choices whose membership test constrains the selected operand."""

import ast

from skylos.security.http_input_declaration import declared_flask_query_value

from .path_http_filename_input import HTTPFilenameInput
from .path_provenance import (
    _filename_allowlist_value,
    _HttpFilenameGuardStep,
    _step,
)


def finite_filename_choice(tracer, unit, scope, expr, env):
    """Prove both arms, or retain the guarded trace for an ordinary Flask query."""
    test = expr.test
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.In, ast.NotIn))
        and isinstance(test.left, ast.Name)
        and isinstance(test.comparators[0], (ast.List, ast.Tuple, ast.Set))
        and scope.kind == "function"
        and tracer.project.complete
        and not tracer.project.truncated
    ):
        return None
    checked, fallback = expr.body, expr.orelse
    if isinstance(test.ops[0], ast.NotIn):
        checked, fallback = fallback, checked
    if not (
        isinstance(checked, ast.Name)
        and checked.id == test.left.id
        and test.comparators[0].elts
        and all(
            isinstance(member, ast.Constant) and _filename_allowlist_value(member.value)
            for member in [fallback, *test.comparators[0].elts]
        )
        and tracer._filename_runtime_is_stable((unit,))
    ):
        return None

    found = unit.lookup(scope, checked.id)
    if not found or found[0] is not scope:
        return None
    if not tracer._local_writes(unit, scope, checked.id, found[1]).empty():
        return None
    step = _step(
        unit,
        expr,
        "membership selects this local from a finite set of literal filenames",
    )
    # Preserve source identity so a post-check decode, replacement or other
    # path transformation can restore the unguarded input to the alert list.
    contract = HTTPFilenameInput(tracer)
    if not (contract.matches(unit, scope, checked, env) and contract.http_seen):
        visible = tracer._visible_binds(unit, scope, found[1], checked)
        if not (
            len(visible) == 1
            and visible[0].kind == "assign"
            and declared_flask_query_value(
                unit.tree,
                scope.node,
                visible[0].value,
                filename=unit.path,
                project_root=tracer.project.root,
            )
        ):
            return None
    note = _HttpFilenameGuardStep(step + " under standard HTTP string decoding")
    return tracer.trace(unit, scope, checked, env).then(note)
