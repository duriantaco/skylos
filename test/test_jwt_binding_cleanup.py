"""Binding cleanup and guard reachability over inert Python source."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.danger.danger_jwt.jwt_provenance import JWTImportVisitor


def _analyze_source(source):
    filename = "label_binding_cleanup.py"
    tree = ast.parse(dedent(source).lstrip(), filename=filename)
    # Check contextual syntax without executing the compiled source.
    compile(tree, filename, "exec")

    class ResolvedCalls(JWTImportVisitor):
        def __init__(self):
            super().__init__()
            self.locations = []
            self.handler_states = []

        def visit_Call(self, node):
            if self.is_jwt_decode(node):
                self.locations.append((filename, node.lineno))
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            result = super().visit_ExceptHandler(node)
            self.handler_states.append(
                {kind: bindings.copy() for kind, bindings in result.states.items()}
            )
            return result

    visitor = ResolvedCalls()
    flow = visitor.visit(tree)
    return visitor, flow


def _recognized_calls(source):
    visitor, _ = _analyze_source(source)
    return visitor.locations


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(
            """
            from labels import decode
            try:
                raise LookupError()
            except LookupError as decode:
                from jwt import decode
                decode(data)
            decode(data)
            """,
            [6],
            id="module-handler-target-is-cleared",
        ),
        pytest.param(
            """
            from jwt import decode
            def render(data):
                try:
                    raise LookupError()
                except LookupError as decode:
                    from jwt import decode
                    decode(data)
                decode(data)
            """,
            [7],
            id="cleared-function-local-still-masks-module-import",
        ),
        pytest.param(
            """
            from jwt import decode
            class Formatter:
                try:
                    raise LookupError()
                except LookupError as decode:
                    pass
                decode(data)
            """,
            [7],
            id="cleared-class-local-reveals-module-import",
        ),
        pytest.param(
            """
            from labels import decode
            class Formatter:
                try:
                    raise LookupError()
                except LookupError as decode:
                    from jwt import decode
                    decode(data)
                decode(data)
            """,
            [7],
            id="cleared-class-local-restores-unrelated-module-import",
        ),
        pytest.param(
            """
            from jwt import decode
            class Formatter:
                global decode
                try:
                    raise LookupError()
                except LookupError as decode:
                    from jwt import decode
                    decode(data)
                decode(data)
            """,
            [8],
            id="class-global-target-does-not-reveal-deleted-import",
        ),
        pytest.param(
            """
            def outer(data):
                from jwt import decode
                class Formatter:
                    nonlocal decode
                    try:
                        raise LookupError()
                    except LookupError as decode:
                        from jwt import decode
                        decode(data)
                    decode(data)
                return Formatter
            """,
            [9],
            id="class-nonlocal-target-does-not-reveal-deleted-import",
        ),
    ],
)
def test_except_target_cleanup_respects_scope(source, lines):
    assert _recognized_calls(source) == [
        ("label_binding_cleanup.py", line) for line in lines
    ]


@pytest.mark.parametrize(
    "completion",
    ["return data", "raise LookupError()", "break", "continue"],
    ids=["return", "raise", "break", "continue"],
)
def test_except_target_is_cleared_before_finally_on_abrupt_completion(completion):
    source = f"""
        def render(data):
            from jwt import decode
            for item in [1]:
                try:
                    raise LookupError()
                except LookupError as decode:
                    from jwt import decode
                    decode(data)
                    {completion}
                finally:
                    decode(data)
        """

    assert _recognized_calls(source) == [("label_binding_cleanup.py", 8)]


@pytest.mark.parametrize(
    ("guard", "lines"),
    [
        pytest.param("False", [7], id="false-guard-skips-body-and-runs-next-case"),
        pytest.param("0", [7], id="zero-guard-skips-body-and-runs-next-case"),
        pytest.param("True", [4, 7], id="true-guard-retains-possible-pattern-match"),
        pytest.param("ready", [4, 7], id="dynamic-guard-retains-both-case-paths"),
    ],
)
def test_match_guard_reachability_preserves_later_cases(guard, lines):
    source = f"""
        match data:
            case str() if {guard}:
                from jwt import decode
                decode(data)
            case _:
                from jwt import decode as read_data
                read_data(data)
        """

    assert _recognized_calls(source) == [
        ("label_binding_cleanup.py", line) for line in lines
    ]


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(
            """
            from jwt import decode
            match data:
                case decode if False:
                    pass
                case _:
                    decode(data)
            decode(data)
            """,
            [],
            id="false-irrefutable-guard-retains-capture-in-fallthrough",
        ),
        pytest.param(
            """
            from jwt import decode
            match data:
                case {"label": decode} if False:
                    pass
                case _:
                    decode(data)
            decode(data)
            """,
            [],
            id="false-refutable-guard-joins-unmatched-and-captured-paths",
        ),
        pytest.param(
            """
            from jwt import decode
            match data:
                case _ if (decode := False):
                    pass
                case _:
                    decode(data)
            decode(data)
            """,
            [],
            id="guard-named-expression-binding-survives-fallthrough",
        ),
        pytest.param(
            """
            match data:
                case _ if True:
                    from jwt import decode
                    decode(data)
                case _:
                    from jwt import decode as read_data
                    read_data(data)
            """,
            [4],
            id="true-irrefutable-guard-consumes-later-cases",
        ),
    ],
)
def test_match_guard_preserves_binding_effects_and_consumed_paths(source, lines):
    assert _recognized_calls(source) == [
        ("label_binding_cleanup.py", line) for line in lines
    ]


def test_false_case_import_does_not_reach_following_statements():
    source = """
        from labels import decode
        match data:
            case _ if False:
                from jwt import decode
            case _:
                pass
        decode(data)
        """

    visitor, flow = _analyze_source(source)

    assert visitor.locations == []
    assert flow.states["normal"]["decode"] == "labels.decode"


@pytest.mark.parametrize(
    ("completion", "kind"),
    [
        pytest.param("pass", "normal", id="normal"),
        pytest.param("return data", "return", id="return"),
        pytest.param("raise LookupError()", "raise", id="raise"),
        pytest.param("break", "break", id="break"),
        pytest.param("continue", "continue", id="continue"),
    ],
)
def test_function_handler_outgoing_state_keeps_cleared_local_mask(completion, kind):
    source = f"""
        def render(data):
            for item in [1]:
                try:
                    raise LookupError()
                except LookupError as decode:
                    from jwt import decode
                    {completion}
        """

    visitor, _ = _analyze_source(source)

    assert len(visitor.handler_states) == 1
    assert kind in visitor.handler_states[0]
    assert visitor.handler_states[0][kind]["decode"] is None
