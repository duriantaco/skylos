"""Import-provenance checks over inert, syntactically valid Python source."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.danger.danger_jwt.jwt_provenance import JWTImportVisitor


def _recognized_calls(source):
    filename = "label_control_flow.py"
    tree = ast.parse(dedent(source).lstrip(), filename=filename)
    # Validate contextual syntax (return/break/nonlocal) without running code.
    compile(tree, filename, "exec")

    class ResolvedCalls(JWTImportVisitor):
        def __init__(self):
            super().__init__()
            self.locations = []

        def visit_Call(self, node):
            if self.is_jwt_decode(node):
                self.locations.append((filename, node.lineno))
            self.generic_visit(node)

    visitor = ResolvedCalls()
    visitor.visit(tree)
    return visitor.locations


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(
            """
            from labels import decode
            for item in items:
                break
            else:
                from jwt import decode
            decode(data)
            """,
            [],
            id="for-break-skips-else-import",
        ),
        pytest.param(
            """
            from labels import decode
            while more_items:
                break
            else:
                from jwt import decode
            decode(data)
            """,
            [],
            id="while-break-skips-else-import",
        ),
        pytest.param(
            """
            def render(data):
                return data
                from jwt import decode
                decode(data)
            """,
            [],
            id="return-stops-following-import-and-call",
        ),
        pytest.param(
            """
            def render(data):
                raise LookupError()
                from jwt import decode
                decode(data)
            """,
            [],
            id="raise-stops-following-import-and-call",
        ),
        pytest.param(
            """
            def render(data):
                from labels import decode
                try:
                    return data
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-sees-return-state-not-unreachable-import",
        ),
        pytest.param(
            """
            def render(data):
                from labels import decode
                try:
                    raise LookupError()
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-sees-raise-state-not-unreachable-import",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                try:
                    break
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-sees-break-state-not-unreachable-import",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                try:
                    continue
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-sees-continue-state-not-unreachable-import",
        ),
        pytest.param(
            """
            def render(data):
                if skip_rendering:
                    return data
                else:
                    from jwt import decode
                return decode(data)
            """,
            [6],
            id="conditional-return-leaves-normal-import-arm",
        ),
        pytest.param(
            """
            def render(data):
                if use_token_codec:
                    from jwt import decode
                else:
                    raise LookupError()
                return decode(data)
            """,
            [6],
            id="conditional-raise-leaves-normal-import-arm",
        ),
        pytest.param(
            """
            def render(data):
                from labels import decode
                try:
                    if skip_rendering:
                        return data
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-joins-conditional-return-and-normal-states",
        ),
        pytest.param(
            """
            for item in items:
                break
                from jwt import decode
                decode(data)
            """,
            [],
            id="break-stops-following-body-import-and-call",
        ),
        pytest.param(
            """
            for item in items:
                continue
                from jwt import decode
                decode(data)
            """,
            [],
            id="continue-stops-following-body-import-and-call",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                pass
            else:
                from jwt import decode
            decode(data)
            """,
            [6],
            id="for-exhaustion-or-zero-iterations-runs-else",
        ),
        pytest.param(
            """
            from labels import decode
            while more_items:
                pass
            else:
                from jwt import decode
            decode(data)
            """,
            [6],
            id="while-exhaustion-or-zero-iterations-runs-else",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                from jwt import decode
                break
            else:
                from jwt import decode
            decode(data)
            """,
            [7],
            id="break-and-exhaustion-both-establish-same-import",
        ),
        pytest.param(
            """
            from labels import decode
            for group in groups:
                for item in group:
                    break
            else:
                from jwt import decode
            decode(data)
            """,
            [7],
            id="inner-loop-break-does-not-skip-outer-else",
        ),
        pytest.param(
            """
            from labels import decode
            for group in groups:
                for item in group:
                    pass
                break
            else:
                from jwt import decode
            decode(data)
            """,
            [],
            id="outer-loop-break-still-skips-outer-else",
        ),
        pytest.param(
            """
            def render(data):
                from labels import decode
                try:
                    prepare_label(data)
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-includes-implicit-exception-before-import",
        ),
        pytest.param(
            """
            def render(data):
                try:
                    return data
                finally:
                    from jwt import decode
                    decode(data)
            """,
            [6],
            id="finally-can-establish-import-after-pending-return",
        ),
        pytest.param(
            """
            def render(data):
                try:
                    raise LookupError()
                finally:
                    return data
                from jwt import decode
                decode(data)
            """,
            [],
            id="finally-return-overrides-raise-and-stops-following-code",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                try:
                    continue
                finally:
                    break
            else:
                from jwt import decode
            decode(data)
            """,
            [],
            id="finally-break-overrides-continue-and-skips-else",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                try:
                    break
                finally:
                    continue
            else:
                from jwt import decode
            decode(data)
            """,
            [9],
            id="finally-continue-overrides-break-and-keeps-exhaustion",
        ),
        pytest.param(
            """
            def stop():
                return
                from jwt import decode as ignored
            import jwt as codec
            codec.decode(data)
            """,
            [5],
            id="function-exit-does-not-stop-module-alias-scan",
        ),
        pytest.param(
            """
            def outer():
                from labels import decode
                def render(data):
                    return decode(data)
                return render
                from jwt import decode
            """,
            [],
            id="returned-closure-excludes-unreachable-later-import",
        ),
        pytest.param(
            """
            def render(data):
                with label_context():
                    return data
                    from jwt import decode
                    decode(data)
            """,
            [],
            id="with-return-stops-following-suite-import-and-call",
        ),
        pytest.param(
            """
            async def render(data):
                async with label_context():
                    return data
                    from jwt import decode
                    decode(data)
            """,
            [],
            id="async-with-return-stops-following-suite-import-and-call",
        ),
        pytest.param(
            """
            def render(data):
                try:
                    prepare_label(data)
                except LookupError:
                    return data
                    from jwt import decode
                    decode(data)
            """,
            [],
            id="handler-return-stops-following-suite-import-and-call",
        ),
        pytest.param(
            """
            def render(data):
                match data:
                    case str():
                        return data
                        from jwt import decode
                        decode(data)
            """,
            [],
            id="match-return-stops-following-case-import-and-call",
        ),
        pytest.param(
            """
            class Formatter:
                raise LookupError()
                from jwt import decode
                decode(data)
            """,
            [],
            id="class-raise-stops-following-body-import-and-call",
        ),
        pytest.param(
            """
            def render(data):
                try:
                    if skip_rendering:
                        return data
                    if missing_label:
                        raise LookupError()
                    prepare_label(data)
                finally:
                    from jwt import decode as read_data
                    read_data(data)
            """,
            [10],
            id="finally-alias-reported-once-for-multiple-pending-exits",
        ),
        pytest.param(
            """
            def render(data):
                from labels import decode
                try:
                    return data
                except LookupError:
                    return data
                else:
                    from jwt import decode
                    decode(data)
                finally:
                    decode(data)
            """,
            [],
            id="try-else-import-is-skipped-on-return-before-finally",
        ),
        pytest.param(
            """
            def render(data):
                from jwt import decode
                try:
                    from labels import decode
                    prepare_label(data)
                    from jwt import decode
                finally:
                    decode(data)
            """,
            [],
            id="finally-includes-intermediate-exception-binding",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                try:
                    try:
                        continue
                    finally:
                        break
                finally:
                    from jwt import decode as read_data
                    read_data(data)
            else:
                from jwt import decode
            decode(data)
            """,
            [10],
            id="nested-finally-forwards-break-and-visits-outer-once",
        ),
        pytest.param(
            """
            def render(data):
                if True:
                    return data
                else:
                    from jwt import decode
                    decode(data)
                from jwt import decode
                decode(data)
            """,
            [],
            id="constant-if-return-stops-unreachable-arms-and-continuation",
        ),
        pytest.param(
            """
            while 0:
                from jwt import decode
                decode(data)
            """,
            [],
            id="false-literal-while-skips-body",
        ),
        pytest.param(
            """
            while 1:
                break
            else:
                from jwt import decode
                decode(data)
            """,
            [],
            id="true-literal-while-break-skips-else",
        ),
        pytest.param(
            """
            def render(data):
                with label_context():
                    return data
                from jwt import decode
                decode(data)
            """,
            [],
            id="with-cannot-suppress-return-of-parameter",
        ),
        pytest.param(
            """
            def render(data):
                del data
                with label_context():
                    return data
                from jwt import decode
                decode(payload)
            """,
            [6],
            id="deleted-parameter-can-raise-and-be-suppressed",
        ),
        pytest.param(
            """
            def render(data):
                try:
                    read_label()
                except LookupError as data:
                    pass
                with label_context():
                    return data
                from jwt import decode
                decode(payload)
            """,
            [9],
            id="handler-target-can-unbind-parameter-before-return",
        ),
    ],
)
def test_jwt_control_flow_preserves_reachable_imports(source, lines):
    assert _recognized_calls(source) == [
        ("label_control_flow.py", line) for line in lines
    ]
