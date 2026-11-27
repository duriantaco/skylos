import pytest

from skylos.agents.center import normalize_findings
from skylos.cicd.review import _flatten_findings, _review_only_lines
from skylos.cli import _apply_precommit_gate_policy
from skylos.core.gatekeeper import check_gate
from skylos.reporting.github_annotations import _github_annotation_items


def _rows():
    location = {"file": "db/sample.sql", "line": 3}
    return {
        "danger": [
            {
                **location,
                "rule_id": "SKY-D417",
                "severity": "MEDIUM",
                "review_item": {"kind": "postgresql_search_path", "blocking": False},
            }
        ],
        "quality": [
            {**location, "rule_id": rule, "severity": "LOW"}
            for rule in ("SKY-Q503", "SKY-Q504")
        ],
    }


@pytest.mark.parametrize("strict", [False, True])
def test_frozen_postgresql_advisories_stay_visible_and_pass_gate(strict):
    result = _rows()
    config = {"gate": {"max_quality": 0, "rules": ["SKY-Q503", "SKY-Q504"]}}
    assert check_gate(result, config, strict=strict)[0]
    findings = _flatten_findings(result)
    assert len(findings) == 3
    assert findings[0]["_review_only_kind"] == "postgresql_search_path"
    summary = _review_only_lines(
        {("SKY-D417", findings[0]["_review_only_kind"]): findings[:1]}
    )
    assert "PostgreSQL search path" in summary[-1]
    annotations = _github_annotation_items(result)
    assert len(annotations) == 3
    assert any("review only" in item["title"] for item in annotations)


def test_precommit_uses_normalized_advisories_and_preserves_other_security(tmp_path):
    result = _rows()
    result["danger"].append(
        {**result["danger"][0], "rule_id": "SKY-D211", "severity": "HIGH"}
    )
    findings = normalize_findings(
        result, tmp_path, include_dead_code=False, use_debt_baseline=False
    )
    blocking, suppressed = _apply_precommit_gate_policy(
        [finding for finding in findings if finding["category"] != "debt"]
    )
    assert [r["rule_id"] for r in blocking] == ["SKY-D211"]
    assert suppressed == 3
    assert not check_gate(result, {}, strict=True)[0]


def test_custom_rule_with_colliding_advisory_id_still_blocks():
    result = _rows()
    result["custom_rules"] = [dict(result["quality"][0])]
    assert not check_gate(result, {"gate": {"max_quality": 0}})[0]
