"""A strict boolean comparison is not a variable-length secret comparison."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.visitors.languages.typescript import scan_typescript_file
from test.fixture_paths import write_fixture


def findings(tmp_path, expression):
    path = write_fixture(
        tmp_path, "check.ts", "export const check = " + expression + ";\n"
    )
    return [f for f in scan_typescript_file(str(path))[7] if f["rule_id"] == "SKY-D253"]


@pytest.mark.parametrize(
    "expression",
    [
        "withXSRFToken !== false",
        "withXSRFToken === true",
        "false === config.apiToken",
        "true !== auth.secret",
        "((password)) === ((false))",
        "((token)) !== (true as const)",
        "token === <boolean>false",
        "apiKey !== (false satisfies boolean)",
    ],
)
def test_boolean_literal_comparisons_have_no_secret_content_oracle(
    tmp_path, expression
):
    assert findings(tmp_path, expression) == []


@pytest.mark.parametrize(
    "expression",
    [
        "token === expectedToken",
        "secret !== request.body.secret",
        "password == supplied",
        "signature != expectedSignature",
        "token === 'false'",
        'secret !== "true"',
        "token == false",
        "token != true",
        "false == password",
        "true != apiKey",
        "token === Boolean(value)",
        "signature === (value as boolean)",
        "token !== falseValue",
        "token === (supplied as false)",
        'token === ("false" as unknown as boolean)',
    ],
)
def test_real_or_unproved_secret_comparisons_still_report(tmp_path, expression):
    result = findings(tmp_path, expression)
    assert len(result) == 1
    assert result[0]["line"] == 1
    assert result[0]["severity"] == "MEDIUM"


def test_outer_boolean_comparison_keeps_nested_secret_comparison(tmp_path):
    result = findings(tmp_path, "((token === expectedToken) === true)")
    assert len(result) == 1
    assert "token" in result[0]["message"]


def test_boolean_flag_does_not_hide_following_secret_comparison(tmp_path):
    path = write_fixture(
        tmp_path,
        "check.ts",
        "export function check(withXSRFToken, secretToken, req) {\n"
        " if (withXSRFToken !== false) {\n"
        "   return secretToken === req.body.token;\n"
        " }\n return false;\n}\n",
    )
    result = [
        f for f in scan_typescript_file(str(path))[7] if f["rule_id"] == "SKY-D253"
    ]
    assert [f["line"] for f in result] == [3]


@pytest.mark.parametrize(
    "expression, expected",
    [("withXSRFToken !== false", 0), ("token === suppliedToken", 1)],
)
def test_actual_json_listing_and_security_gate_agree(tmp_path, expression, expected):
    write_fixture(tmp_path, "check.ts", "export const check = " + expression + ";\n")
    report = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    matched = [f for f in report.get("danger", []) if f["rule_id"] == "SKY-D253"]
    assert len(matched) == expected
    assert all(f.get("listing", {}).get("listed", True) for f in matched)
    gate = check_gate(report, {"gate": {"max_security": 0}})
    assert gate[0] is (expected == 0)
