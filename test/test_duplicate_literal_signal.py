import ast
import json
import textwrap

import pytest

from skylos.audit.redaction import REDACTION
from skylos.rules.quality.logic_maintainability import (
    DuplicateStringLiteralRule,
    _duplicate_string_occurrence_role,
)


def _findings(source, threshold=3):
    return (
        DuplicateStringLiteralRule(threshold=threshold).visit_node(
            ast.parse(textwrap.dedent(source)), {"filename": "app.py"}
        )
        or []
    )


def _repeated(value, *, count=3):
    return _findings(
        "def render():\n" + "\n".join(f"    consume({value!r})" for _ in range(count))
    )


@pytest.mark.parametrize(
    "sentence",
    [
        "Timeout in seconds waiting for reply.",
        "Use json as output format.",
        "Unable to read the selected input file.",
        "Use\tjson\tas\toutput\tformat.",
    ],
)
def test_ordinary_sentences_are_not_redacted_by_whole_sentence_entropy(sentence):
    finding = _repeated(sentence)[0]
    assert finding["name"] == sentence
    assert REDACTION not in finding["message"]
    assert finding["literal_context"]["identifier_like"] is False


@pytest.mark.parametrize(
    "credential",
    [
        "ghp_" + "1234567890abcdefABCDEF1234567890abcd",
        " bearer abc def ghi ",
        "password: 'a long pass phrase with spaces'",
        "-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n",
        "AbCdEf1234_5678.XyZ9012-abcdefgh",
        " AbCdEf1234_5678.XyZ9012-abcdefgh ",
        "prefix\tAbCdEf1234_5678.XyZ9012-abcdefgh\nsuffix",
        "prefix ghp_1234567890abcdefABCDEF1234567890abcd suffix",
    ],
)
def test_known_and_opaque_credentials_remain_redacted_with_whitespace(credential):
    finding = _repeated(credential)[0]
    assert finding["name"] == REDACTION
    assert finding["simple_name"] == REDACTION
    assert credential not in json.dumps(finding)
    assert set(finding["literal_context"]) == {
        "version",
        "scope_complete",
        "occurrence_count",
        "distinct_function_count",
        "non_function_occurrences",
        "identifier_like",
        "all_occurrences_contract_tokens",
        "role_counts",
    }
    # Even opaque tokens and secret-bearing symbols must not enter evidence.
    assert "AbCdEf" not in json.dumps(finding["literal_context"])
    assert "ghp_" not in json.dumps(finding["literal_context"])


@pytest.mark.parametrize("count,severity", [(3, "LOW"), (5, "LOW"), (6, "MEDIUM")])
def test_context_is_additive_and_preserves_raw_counts_thresholds_and_severity(
    count, severity
):
    finding = _repeated("store_true", count=count)[0]
    context = finding.pop("literal_context")
    assert finding == {
        "rule_id": "SKY-L027",
        "kind": "quality",
        "severity": severity,
        "type": "string",
        "name": "store_true",
        "simple_name": "store_true",
        "value": count,
        "threshold": 3,
        "message": f"String literal 'store_true' repeated {count} times (threshold: 3).",
        "file": "app.py",
        "basename": "app.py",
        "line": 2,
        "col": 12,
    }
    assert context == {
        "version": 1,
        "scope_complete": True,
        "occurrence_count": count,
        "distinct_function_count": 1,
        "non_function_occurrences": 0,
        "identifier_like": True,
        "all_occurrences_contract_tokens": True,
        "role_counts": {"call_argument": count},
    }


def test_configured_threshold_remains_effective():
    source = "\n".join('consume("store_true")' for _ in range(3))
    assert _findings(source, threshold=4) == []
    assert _findings(source, threshold=2)[0]["value"] == 3


@pytest.mark.parametrize(
    "source,functions,non_function",
    [
        (
            """
            class First:
                def render(self):
                    consume("store_true")
                    consume("store_true")
            class Second:
                async def render(self):
                    consume("store_true")
            """,
            2,
            0,
        ),
        (
            """
            def outer():
                consume("store_true")
                def inner():
                    consume("store_true")
                async def another():
                    consume("store_true")
            """,
            3,
            0,
        ),
        (
            """
            @decorate("store_true")
            async def render(value="store_true"):
                consume("store_true")
            """,
            1,
            2,
        ),
        (
            """
            def outer():
                @decorate("store_true")
                def inner(value="store_true"):
                    consume("store_true")
            """,
            2,
            0,
        ),
        (
            """
            def outer():
                @decorate("store_true")
                class Inner(base("store_true")):
                    label = "store_true"
            """,
            1,
            1,
        ),
        (
            """
            first = lambda value="store_true": consume("store_true")
            second = lambda: consume("store_true")
            """,
            2,
            1,
        ),
        (
            """
            label = "store_true"
            class First:
                label = "store_true"
            class Second:
                label = "store_true"
            """,
            0,
            3,
        ),
    ],
)
def test_exact_function_body_scopes_handle_nested_async_decorated_and_named_methods(
    source, functions, non_function
):
    context = _findings(source)[0]["literal_context"]
    assert context["occurrence_count"] == 3
    assert context["distinct_function_count"] == functions
    assert context["non_function_occurrences"] == non_function
    assert context["scope_complete"] is True


def test_argument_roles_include_keywords_without_serializing_api_names():
    finding = _findings(
        """
        def private_credential_handler():
            parser.add_argument("--read", action="custom_action")
            parser.add_argument("--copy", action="custom_action")
            consume("custom_action")
        """
    )[0]
    context = finding["literal_context"]
    assert context["all_occurrences_contract_tokens"] is True
    assert context["role_counts"] == {"call_keyword": 2, "call_argument": 1}
    assert "private_credential_handler" not in json.dumps(finding)
    assert "parser" not in json.dumps(context)


@pytest.mark.parametrize(
    "statement,role",
    [
        ('label = "store_true"', "assignment_value"),
        ('return "store_true"', "return_value"),
        ('consume(value == "store_true")', "comparison"),
        ('consume({"input": "store_true"})', "dict_value"),
        ('consume(["store_true"])', "other"),
    ],
)
def test_mixed_roles_are_not_labelled_as_all_contract_tokens(statement, role):
    finding = _findings(
        'def render(value):\n    consume("store_true")\n'
        '    consume("store_true")\n    ' + statement
    )[0]
    context = finding["literal_context"]
    assert context["identifier_like"] is True
    assert context["all_occurrences_contract_tokens"] is False
    assert context["role_counts"] == {"call_argument": 2, role: 1}


def test_meaningful_messages_in_multiple_functions_keep_complete_context():
    finding = _findings(
        """
        def first():
            raise RuntimeError("Unable to read the input file.")
        def second():
            raise RuntimeError("Unable to read the input file.")
        async def third():
            raise RuntimeError("Unable to read the input file.")
        """
    )[0]
    context = finding["literal_context"]
    assert context["distinct_function_count"] == 3
    assert context["non_function_occurrences"] == 0
    assert context["identifier_like"] is False
    assert context["all_occurrences_contract_tokens"] is False


def test_existing_structural_and_annotation_exclusions_do_not_inflate_counts():
    finding = _findings(
        """
        def render(value: "store_true"):
            data = {"store_true": 1}
            consume(data["store_true"])
            consume("store_true")
            consume("store_true")
            consume("store_true")
        """
    )[0]
    assert finding["value"] == 3
    assert finding["literal_context"]["occurrence_count"] == 3
    assert finding["literal_context"]["role_counts"] == {"call_argument": 3}


class _NoLinearMembership(list):
    """Fail deterministically if metadata performs a repeated list scan."""

    def __contains__(self, item):
        raise AssertionError("L027 occurrence metadata must not scan sibling lists")


def test_large_call_uses_cached_identity_membership_for_literal_context():
    count = 8_000
    tree = ast.parse(
        "def render():\n    consume(" + ",".join(['"store_true"'] * count) + ")\n"
    )
    call = tree.body[0].body[0].value
    call.args = _NoLinearMembership(call.args)
    finding = DuplicateStringLiteralRule().visit_node(tree, {"filename": "app.py"})[0]
    assert finding["value"] == count
    assert finding["literal_context"]["role_counts"] == {"call_argument": count}
    assert finding["literal_context"]["distinct_function_count"] == 1


def test_mapping_roles_use_cached_identity_membership_without_rescanning_lists():
    mapping = (
        ast.parse('{"first_key": "first_value", "second_key": "second_value"}')
        .body[0]
        .value
    )
    mapping.keys = _NoLinearMembership(mapping.keys)
    mapping.values = _NoLinearMembership(mapping.values)
    cache = {}
    for node in mapping.keys:
        assert (
            _duplicate_string_occurrence_role(node, {id(node): mapping}, cache)
            == "dict_key"
        )
    for node in mapping.values:
        assert (
            _duplicate_string_occurrence_role(node, {id(node): mapping}, cache)
            == "dict_value"
        )
    assert len(cache) == 1
