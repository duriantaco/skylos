"""Independent postfix/short-circuit regressions for D309 expression flow.

GitHub's runner Index.EvaluateCore returns null for scalar dereferences:
https://github.com/actions/runner/blob/main/src/Sdk/DTExpressions2/Expressions2/Sdk/Operators/Index.cs
"""

import pytest

from skylos.rules.config.cicd.secret_value_flow import secret_value_names
from test.test_workflow_secret_value_flow import _workflow_findings


SCALAR_FALLBACKS = [
    "${{ (true).missing || secrets.DEPLOY_KEY }}",
    "${{ ('public').missing || secrets.DEPLOY_KEY }}",
    "${{ (123).missing || secrets.DEPLOY_KEY }}",
    "${{ ('public')[0] || secrets.DEPLOY_KEY }}",
    "${{ (always()).missing || secrets.DEPLOY_KEY }}",
    "${{ secrets[('GITHUB_TOKEN').missing || 'DEPLOY_KEY'] }}",
]


@pytest.mark.parametrize("expression", SCALAR_FALLBACKS)
def test_scalar_postfix_cannot_hide_the_exposed_fallback(expression):
    names = secret_value_names(expression)
    exposed = []
    for name in names:
        if name.upper() != "GITHUB_TOKEN":
            exposed.append(name)
    assert exposed


@pytest.mark.parametrize("scope", ["workflow", "job"])
@pytest.mark.parametrize("expression", SCALAR_FALLBACKS)
def test_yaml_scalar_postfix_does_not_bypass_broad_secret_rule(
    tmp_path, scope, expression
):
    findings = _workflow_findings(tmp_path, {"TOKEN": expression}, scope=scope)
    rows = []
    for finding in findings:
        if finding["rule_id"] == "SKY-D309":
            rows.append(finding)
    assert len(rows) == 1


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("${{ secrets.FIRST == 'yes' || secrets.SECOND }}", ["SECOND"]),
        ("${{ secrets.FIRST < 1 && secrets.SECOND }}", ["SECOND"]),
        ("${{ (secrets.FIRST != '') == true }}", []),
        ("${{ toJSON(secrets.FIRST != '') }}", []),
        ("${{ toJSON(secrets.FIRST) }}", ["FIRST"]),
        ("${{ format('}} {0}', secrets.FIRST) }}", ["FIRST"]),
        ("${{ format('}}', secrets.FIRST", ["FIRST"]),
        ("${{ github.event.secrets.FIRST }}", []),
    ],
)
def test_independent_comparison_serialization_and_fallback_controls(
    expression, expected
):
    assert secret_value_names(expression) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "${{ (github.ref && secrets).GITHUB_TOKEN }}",
        "${{ (secrets && secrets)['GITHUB_TOKEN'] }}",
    ],
)
def test_operand_context_keeps_github_token_exemption(tmp_path, expression):
    findings = _workflow_findings(tmp_path, {"TOKEN": expression})
    for finding in findings:
        assert finding["rule_id"] != "SKY-D309"
