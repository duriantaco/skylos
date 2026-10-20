"""D309 follows expression results, with source-independent safety controls."""

import pytest
import yaml

from skylos.rules.config.cicd.github_actions import scan_github_actions
from skylos.rules.config.cicd.secret_value_flow import (
    MAX_DEPTH,
    MAX_EXPRESSION_CHARS,
    MAX_TOKENS,
    secret_value_names,
)
from test.fixture_paths import write_fixture


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("${{ secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ SeCrEtS.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ (secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ secrets['DEPLOY_KEY'] }}", ["DEPLOY_KEY"]),
        ("${{ secrets[('DEPLOY_KEY')] }}", ["DEPLOY_KEY"]),
        ("${{ (secrets)['DEPLOY_KEY'] }}", ["DEPLOY_KEY"]),
        ("${{ secrets[matrix.key] }}", ["[dynamic]"]),
        ("${{ secrets }}", ["*"]),
        ("${{ secrets.* }}", ["*"]),
        ("${{ secrets.DEPLOY_KEY != '' }}", []),
        ("${{ secrets.DEPLOY_KEY == 'yes' }}", []),
        ("${{ secrets.DEPLOY_KEY > 0 }}", []),
        ("${{ secrets.DEPLOY_KEY >= 0 }}", []),
        ("${{ secrets.DEPLOY_KEY < 0 }}", []),
        ("${{ secrets.DEPLOY_KEY <= 0 }}", []),
        ("${{ !secrets.DEPLOY_KEY }}", []),
        ("${{ !!secrets.DEPLOY_KEY }}", []),
        ("${{ secrets['DEPLOY_KEY'] != '' }}", []),
        ("${{ secrets[matrix.key] != '' }}", []),
        ("${{ contains(secrets.DEPLOY_KEY, 'x') }}", []),
        ("${{ startsWith(secrets.DEPLOY_KEY, 'x') }}", []),
        ("${{ endsWith(secrets.DEPLOY_KEY, 'x') }}", []),
        ("${{ secrets.DEPLOY_KEY != '' && true }}", []),
        ("${{ secrets.DEPLOY_KEY && 'enabled' }}", []),
        ("${{ secrets.DEPLOY_KEY && 'enabled' || 'disabled' }}", []),
        ("${{ false && secrets.DEPLOY_KEY }}", []),
        ("${{ null && secrets.DEPLOY_KEY }}", []),
        ("${{ 0 && secrets.DEPLOY_KEY }}", []),
        ("${{ -0.0 && secrets.DEPLOY_KEY }}", []),
        ("${{ 0x0 && secrets.DEPLOY_KEY }}", []),
        ("${{ true || secrets.DEPLOY_KEY }}", []),
        ("${{ 'yes' || secrets.DEPLOY_KEY }}", []),
        ("${{ always() || secrets.DEPLOY_KEY }}", []),
        ("${{ true && secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ false || secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ 0 || secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ 0x10 && secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ !false && secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ github.ref == 'main' && secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ secrets.DEPLOY_KEY || 'fallback' }}", ["DEPLOY_KEY"]),
        ("${{ secrets.FIRST && secrets.SECOND }}", ["SECOND"]),
        ("${{ secrets.FIRST || secrets.SECOND }}", ["FIRST", "SECOND"]),
        (
            "${{ secrets.FIRST != '' && secrets.SECOND || secrets.THIRD }}",
            ["SECOND", "THIRD"],
        ),
        ("${{ format('{0}', secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ format('{{{0}}}', secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ format('{0}', secrets.DEPLOY_KEY != '') }}", []),
        ("${{ toJSON(secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ toJSON(secrets) }}", ["*"]),
        ("${{ toJSON(secrets.DEPLOY_KEY != '') }}", []),
        ("${{ fromJSON(secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ join(secrets.DEPLOY_KEY, ',') }}", ["DEPLOY_KEY"]),
        ("${{ unsupported(secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ contains(secrets.DEPLOY_KEY) }}", ["DEPLOY_KEY"]),
        ("${{ 'secrets.DEPLOY_KEY' }}", []),
        ("${{ 'it''s secrets.DEPLOY_KEY' }}", []),
        ("${{ '}} secrets.DEPLOY_KEY' }}", []),
        ("${{ format('secrets.DEPLOY_KEY {0}', 'plain') }}", []),
        ("${{ github.event.secrets.DEPLOY_KEY }}", []),
        ("plain text secrets.DEPLOY_KEY", []),
        ("", []),
        ("prefix-${{ secrets.DEPLOY_KEY }}-suffix", ["DEPLOY_KEY"]),
        ("${{ secrets.FIRST != '' }}:${{ secrets.SECOND }}", ["SECOND"]),
        ("${{ secrets.FIRST }}:${{ secrets.SECOND != '' }}", ["FIRST"]),
        ("${{ secrets.FIRST }}:${{ secrets.FIRST }}", ["FIRST"]),
        ("${{ secrets.DEPLOY_KEY != ''", ["DEPLOY_KEY"]),
        ("${{ secrets.DEPLOY_KEY ? 'yes' : 'no' }}", ["DEPLOY_KEY"]),
        ("${{ secrets.DEPLOY_KEY != }}", ["DEPLOY_KEY"]),
        ("${{ secrets.DEPLOY_KEY != 'unterminated }}", ["DEPLOY_KEY"]),
        ("${{ unsupported('secrets.DEPLOY_KEY', ) }}", []),
        ("${{ unsupported(secrets['DEPLOY_KEY'], ) }}", ["DEPLOY_KEY"]),
        ("${{ unsupported(secrets[matrix.key], ) }}", ["[dynamic]"]),
        ("${{ unsupported(secrets, ) }}", ["*"]),
        ("${{ 'public' '||' secrets.DEPLOY_KEY }}", ["DEPLOY_KEY"]),
        ("${{ contains '(' secrets.DEPLOY_KEY ',' 'x' ')' }}", ["DEPLOY_KEY"]),
    ],
)
def test_expression_output_value_matrix(expression, expected):
    assert secret_value_names(expression) == expected


@pytest.mark.parametrize("limit", ["characters", "tokens", "depth"])
def test_parser_limits_preserve_unknown_secret_values(limit):
    expression = "secrets.DEPLOY_KEY != ''"
    if limit == "characters":
        expression += " " * MAX_EXPRESSION_CHARS
    elif limit == "tokens":
        expression += " && true" * MAX_TOKENS
    else:
        expression = "(" * MAX_DEPTH + expression + ")" * MAX_DEPTH
    assert secret_value_names("${{ " + expression + " }}") == ["DEPLOY_KEY"]


def test_limit_fallback_does_not_turn_literal_text_into_secret_reference():
    expression = "'secrets.NOT_A_REFERENCE'" + " " * MAX_EXPRESSION_CHARS
    assert secret_value_names("${{ " + expression + " }}") == []


def _workflow_findings(tmp_path, environment, *, scope="job"):
    job = {
        "runs-on": "ubuntu-latest",
        "steps": [{"run": "echo ready"}],
    }
    workflow = {"name": "CI", "on": "push", "jobs": {"build": job}}
    if scope == "workflow":
        workflow["env"] = environment
    elif scope == "step":
        job["steps"][0]["env"] = environment
    else:
        job["env"] = environment
    source = yaml.safe_dump(workflow, sort_keys=False)
    write_fixture(tmp_path, ".github/workflows/ci.yml", source)
    return scan_github_actions(tmp_path)


@pytest.mark.parametrize("scope", ["workflow", "job"])
def test_yaml_keeps_raw_secret_and_removes_boolean_check(tmp_path, scope):
    findings = _workflow_findings(
        tmp_path,
        {
            "HAS_DEPLOY_KEY": "${{ secrets.DEPLOY_KEY != '' }}",
            "DEPLOY_KEY": "${{ format('{0}', secrets.DEPLOY_KEY) }}",
            "LOOKALIKE": "${{ unsupported(secrets.OTHER_KEY) }}",
        },
        scope=scope,
    )
    rows = []
    for finding in findings:
        if finding["rule_id"] == "SKY-D309":
            rows.append(finding)
    assert len(rows) == 2
    messages = []
    for row in rows:
        messages.append(row["message"])
    messages = "\n".join(messages)
    assert "HAS_DEPLOY_KEY" not in messages
    assert "environment variable DEPLOY_KEY exposes secret DEPLOY_KEY" in messages
    assert "environment variable LOOKALIKE exposes secret OTHER_KEY" in messages
    for row in rows:
        if scope == "workflow":
            assert row["severity"] == "HIGH"
        else:
            assert row["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "expression, description",
    [
        ("${{ secrets['DEPLOY_KEY'] }}", "secret DEPLOY_KEY"),
        ("${{ secrets[matrix.key] }}", "a dynamically selected secret"),
        ("${{ toJSON(secrets) }}", "the secrets context"),
        ("${{ secrets.GITHUB_TOKEN }}:${{ secrets.OTHER_KEY }}", "secret OTHER_KEY"),
    ],
)
def test_yaml_reports_bracket_context_and_mixed_exposure(
    tmp_path, expression, description
):
    findings = _workflow_findings(tmp_path, {"VALUE": expression})
    rows = []
    for finding in findings:
        if finding["rule_id"] == "SKY-D309":
            rows.append(finding)
    assert len(rows) == 1
    assert "exposes " + description + " to every nested step" in rows[0]["message"]


@pytest.mark.parametrize(
    "expression, scope",
    [
        ("${{ secrets.GITHUB_TOKEN }}", "job"),
        ("${{ secrets['GITHUB_TOKEN'] }}", "job"),
        ("${{ secrets.DEPLOY_KEY }}", "step"),
        ("${{ secrets.DEPLOY_KEY != '' }}", "workflow"),
        ("${{ 'secrets.DEPLOY_KEY' }}", "job"),
    ],
)
def test_yaml_preserves_rule_scope_and_non_exposure_controls(
    tmp_path, expression, scope
):
    findings = _workflow_findings(tmp_path, {"VALUE": expression}, scope=scope)
    for finding in findings:
        assert finding["rule_id"] != "SKY-D309"


def test_other_secret_rules_are_not_suppressed_by_boolean_output(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        {"HAS_KEY": "${{ secrets.DEPLOY_KEY != '' }}"},
    )
    ids = set()
    for finding in findings:
        ids.add(finding["rule_id"])
    assert "SKY-D309" not in ids
    assert "SKY-D299" in ids
