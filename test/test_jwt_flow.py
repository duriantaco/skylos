import ast
from textwrap import dedent

import pytest

from skylos.rules.danger.danger_jwt.jwt_flow import scan
from skylos.rules.danger.danger_jwt.jwt_provenance import JWTImportVisitor


def _scan_code(code, filename="app.py"):
    tree = ast.parse(code)
    findings = []
    scan(tree, filename, findings)
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_jwt_algorithm_none():
    code = "import jwt\ndecoded = jwt.decode(token, 'secret', algorithms=['none'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_verify_false():
    code = (
        "import jwt\ndecoded = jwt.decode(token, options={'verify_signature': False})\n"
    )
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_verify_false_legacy():
    code = "import jwt\ndecoded = jwt.decode(token, verify=False)\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_safe_decode():
    code = "import jwt\ndecoded = jwt.decode(token, 'secret', algorithms=['HS256'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" not in _rule_ids(findings)


def test_jwt_safe_decode_rs256():
    code = "import jwt\ndecoded = jwt.decode(token, public_key, algorithms=['RS256'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" not in _rule_ids(findings)


def test_jwt_algorithm_none_import_alias():
    """Regression: `import jwt as j` alias must still be detected."""
    code = "import jwt as j\ndecoded = j.decode(token, 'secret', algorithms=['none'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_verify_false_from_import():
    """Regression: `from jwt import decode` must still be detected."""
    code = "from jwt import decode\ndecoded = decode(token, verify=False)\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(
            "from jwt import encode as format_label\n"
            "format_label(label, verify=False)\n",
            id="non-decode-member",
        ),
        pytest.param(
            "from jwt import get_unverified_header as format_label\n"
            "format_label(label, verify=False)\n",
            id="non-decode-header-member",
        ),
        pytest.param(
            "from .jwt import decode as format_label\n"
            "format_label(label, verify=False)\n",
            id="relative-import",
        ),
        pytest.param(
            """
            from labels import format_label
            def load_decoder():
                from jwt import decode as format_label
                return format_label
            def render(label):
                return format_label(label, verify=False)
            """,
            id="sibling-function-direct-import",
        ),
        pytest.param(
            """
            from labels import formatter
            def load_decoder():
                import jwt as formatter
                return formatter
            def render(label):
                return formatter.decode(label, verify=False)
            """,
            id="sibling-function-module-import",
        ),
        pytest.param(
            """
            from jwt import decode as format_label
            def render(format_label, label):
                return format_label(label, verify=False)
            """,
            id="parameter-shadows-direct-import",
        ),
        pytest.param(
            """
            import jwt
            def render(jwt, label):
                return jwt.decode(label, verify=False)
            """,
            id="parameter-shadows-module-import",
        ),
        pytest.param(
            "from jwt import decode as format_label\n"
            "format_label = label_formatter\n"
            "format_label(label, verify=False)\n",
            id="assignment-shadows-direct-import",
        ),
        pytest.param(
            "import jwt as formatter\n"
            "formatter = label_codec\n"
            "formatter.decode(label, verify=False)\n",
            id="assignment-shadows-module-import",
        ),
        pytest.param(
            "from jwt import decode as format_label\n"
            "from labels import format_label\n"
            "format_label(label, verify=False)\n",
            id="later-import-shadows-direct-import",
        ),
        pytest.param(
            "import jwt as formatter\n"
            "import labels as formatter\n"
            "formatter.decode(label, verify=False)\n",
            id="later-import-shadows-module-import",
        ),
        pytest.param(
            """
            from jwt import decode as format_label
            def render(label):
                result = format_label(label, verify=False)
                from labels import format_label
                return result
            """,
            id="later-local-import-binds-whole-function",
        ),
        pytest.param(
            """
            from labels import format_label
            class Formatter:
                from jwt import decode as format_label
                def render(self, label):
                    return format_label(label, verify=False)
            """,
            id="method-does-not-inherit-class-import",
        ),
        pytest.param(
            """
            from labels import format_label
            class Outer:
                from jwt import decode as format_label
                class Inner:
                    rendered = format_label(label, verify=False)
            """,
            id="nested-class-does-not-inherit-class-import",
        ),
        pytest.param(
            "from jwt import decode as format_label\n"
            "render = lambda format_label: format_label(label, verify=False)\n",
            id="lambda-parameter-shadows-import",
        ),
        pytest.param(
            "from jwt import decode as format_label\n"
            "rendered = [format_label(label, verify=False) "
            "for format_label in label_formatters]\n",
            id="comprehension-target-shadows-import",
        ),
    ],
)
def test_unrelated_calls_are_not_jwt_decodes(code):
    """Only parse the fixtures: imported and rebound label helpers never run."""
    assert _scan_code(dedent(code).lstrip(), filename="labels.py") == []


@pytest.mark.parametrize(
    ("code", "expected_lines"),
    [
        pytest.param(
            "from jwt import decode as read_token\n"
            "decoded = read_token(token, verify=False)\n",
            [2],
            id="direct-import-alias",
        ),
        pytest.param(
            "import jwt as j\n"
            "decoded = j.decode(token, verify=False)\n"
            "decoded_again = j.decode(token, verify=False)\n",
            [2, 3],
            id="module-alias-exact-count",
        ),
        pytest.param(
            """
            import jwt as j
            class Formatter:
                j = label_codec
                def parse(self, token):
                    return j.decode(token, verify=False)
            """,
            [5],
            id="method-resolves-module-import-not-class-attribute",
        ),
    ],
)
def test_resolved_jwt_alias_findings_have_exact_locations(code, expected_lines):
    findings = _scan_code(dedent(code).lstrip(), filename="tokens.py")
    assert [
        (finding["rule_id"], finding["file"], finding["line"]) for finding in findings
    ] == [("SKY-D232", "tokens.py", line) for line in expected_lines]


def _jwt_decode_lines(code):
    class ResolvedCalls(JWTImportVisitor):
        def __init__(self):
            super().__init__()
            self.lines = []

        def visit_Call(self, node):
            if self.is_jwt_decode(node):
                self.lines.append(node.lineno)
            self.generic_visit(node)

    visitor = ResolvedCalls()
    visitor.visit(ast.parse(dedent(code).lstrip()))
    return visitor.lines


@pytest.mark.parametrize(
    ("code", "expected_lines"),
    [
        pytest.param(
            "import jwt.api_jwt as codec\ncodec.decode(data)\n",
            [2],
            id="pyjwt-nested-module-alias",
        ),
        pytest.param(
            "from jwt.api_jwt import decode as read_data\nread_data(data)\n",
            [2],
            id="pyjwt-nested-direct-alias",
        ),
        pytest.param(
            "from jwt import api_jwt as codec\ncodec.decode(data)\n",
            [2],
            id="pyjwt-imported-nested-module",
        ),
        pytest.param(
            "import jose.jwt\njose.jwt.decode(data)\n",
            [2],
            id="jose-qualified-module",
        ),
        pytest.param(
            "from jose import jwt as codec\ncodec.decode(data)\n",
            [2],
            id="jose-module-alias",
        ),
        pytest.param(
            "from jose.jwt import decode as read_data\nread_data(data)\n",
            [2],
            id="jose-direct-alias",
        ),
        pytest.param(
            """
            from jwt import decode
            @decorate(decode(data))
            def render(decode=decode(data)):
                return decode(data)
            """,
            [2, 3],
            id="decorator-and-default-use-enclosing-scope",
        ),
        pytest.param(
            """
            from jwt import decode
            class Formatter:
                first = decode(data)
                decode = label_formatter
                second = decode(data)
                def render(self):
                    return decode(data)
            """,
            [3, 7],
            id="class-body-sequential-method-skips-class-bindings",
        ),
        pytest.param(
            "from jwt import decode\ndecode = decode(data)\ndecode(data)\n",
            [2],
            id="assignment-rhs-before-rebinding",
        ),
        pytest.param(
            """
            def render(data):
                return decode(data)
            from jwt import decode
            """,
            [2],
            id="deferred-function-sees-later-module-import",
        ),
        pytest.param(
            """
            from jwt import decode
            def render(data):
                return decode(data)
            decode = label_formatter
            """,
            [],
            id="deferred-function-sees-module-rebinding",
        ),
        pytest.param(
            """
            def outer():
                def render(data):
                    return decode(data)
                from jwt import decode
                return render
            """,
            [3],
            id="deferred-closure-sees-later-enclosing-import",
        ),
        pytest.param(
            """
            def outer():
                from jwt import decode
                def render(data):
                    return decode(data)
                decode = label_formatter
                return render
            """,
            [],
            id="deferred-closure-sees-enclosing-rebinding",
        ),
        pytest.param(
            """
            from jwt import decode
            values = [decode(data)
                      for decode in decode(data)]
            """,
            [3],
            id="comprehension-first-iterable-uses-enclosing-scope",
        ),
        pytest.param(
            """
            from jwt import decode
            values = [data
                      for item in items if decode(data)
                      for decode in label_formatters]
            """,
            [],
            id="comprehension-all-targets-are-local",
        ),
        pytest.param(
            """
            if use_token_codec:
                from jwt import decode
            else:
                from labels import decode
            decode(data)
            """,
            [],
            id="conditional-import-unrelated-else-is-uncertain",
        ),
        pytest.param(
            """
            if use_label_codec:
                from labels import decode
            else:
                from jwt import decode
            decode(data)
            """,
            [],
            id="conditional-import-jwt-else-is-uncertain",
        ),
        pytest.param(
            """
            if use_token_codec:
                from jwt import decode
            else:
                from jwt import decode
            decode(data)
            """,
            [5],
            id="conditional-import-same-binding-on-both-paths",
        ),
    ],
)
def test_jwt_import_resolution_respects_python_scopes(code, expected_lines):
    """Trace import identities only; the inert calls have no JWT options."""
    assert _jwt_decode_lines(code) == expected_lines


@pytest.mark.parametrize(
    ("code", "expected_lines"),
    [
        pytest.param(
            "from jwt import decode\n"
            "callbacks = [lambda: decode(data) "
            "for decode in label_formatters]\n",
            [],
            id="comprehension-lambda-captures-local-target",
        ),
        pytest.param(
            """
            from labels import decode
            def outer():
                from jwt import decode
                def render(data):
                    global decode
                    return decode(data)
                return render
            """,
            [],
            id="nested-global-skips-enclosing-function-import",
        ),
        pytest.param(
            """
            from jwt import decode
            values = (decode(data)
                      for item in decode(data))
            decode = label_formatter
            """,
            [3],
            id="generator-first-iterable-immediate-body-deferred",
        ),
        pytest.param(
            """
            if use_token_codec:
                from jwt import decode
            else:
                decode(data)
            """,
            [],
            id="opposite-if-arm-does-not-inherit-import",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                from jwt import decode
            decode(data)
            """,
            [],
            id="loop-import-not-proven-after-zero-iterations",
        ),
        pytest.param(
            """
            from labels import decode
            for item in items:
                from jwt import decode
            else:
                decode(data)
            """,
            [],
            id="loop-else-can-follow-zero-iterations",
        ),
        pytest.param(
            """
            from labels import decode
            try:
                from jwt import decode
            except ImportError:
                decode(data)
            """,
            [],
            id="exception-handler-cannot-assume-import-succeeded",
        ),
        pytest.param(
            """
            def outer():
                from jwt import decode
                class Formatter:
                    from labels import decode
                    def render(self, data):
                        nonlocal decode
                        return decode(data)
                return Formatter
            """,
            [7],
            id="method-nonlocal-resolves-enclosing-function-not-class",
        ),
    ],
)
def test_jwt_import_resolution_keeps_deferred_and_branch_scopes_separate(
    code, expected_lines
):
    assert _jwt_decode_lines(code) == expected_lines
