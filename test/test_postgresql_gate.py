import pytest

from skylos.agents.center import normalize_findings
from skylos.cicd.review import _flatten_findings, _review_only_lines
from skylos.cli import _apply_precommit_gate_policy
from skylos.core.gatekeeper import check_gate
from skylos.reporting.github_annotations import _github_annotation_items
from skylos.reporting.listing import github_feedback_result, is_gate_exempt_review


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
            {**location, "rule_id": rule, "severity": severity}
            for rule, severity in (
                ("SKY-Q503", "LOW"),
                ("SKY-Q504", "MEDIUM"),
                ("SKY-Q505", "MEDIUM"),
            )
        ],
    }


@pytest.mark.parametrize("strict", [False, True])
def test_frozen_postgresql_advisories_stay_visible_and_pass_gate(strict):
    result = _rows()
    config = {"gate": {"max_quality": 0, "rules": ["SKY-Q503", "SKY-Q504", "SKY-Q505"]}}
    assert check_gate(result, config, strict=strict)[0]
    view = github_feedback_result(result)
    assert len(result["quality"]) == 3
    findings = _flatten_findings(view)
    assert len(findings) == 1
    assert findings[0]["_review_only_kind"] == "postgresql_search_path"
    summary = _review_only_lines(
        {("SKY-D417", findings[0]["_review_only_kind"]): findings[:1]}
    )
    assert "PostgreSQL search path" in "\n".join(summary)
    annotations = _github_annotation_items(view)
    assert len(annotations) == 1
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
    assert suppressed == 4
    assert not check_gate(result, {}, strict=True)[0]


def test_custom_rule_with_colliding_advisory_id_still_blocks():
    result = _rows()
    result["custom_rules"] = [dict(result["quality"][0])]
    assert not check_gate(result, {"gate": {"max_quality": 0}})[0]


def test_deeper_postgresql_reviews_do_not_exempt_unrelated_rules(tmp_path):
    quality_rules = [f"SKY-Q{i}" for i in range(506, 511)]
    location = {"file": "db/change.sql", "line": 2, "severity": "MEDIUM"}
    kinds = {
        "SKY-D418": "postgresql_public_grant",
        "SKY-D419": "postgresql_login_bypassrls",
        "SKY-D420": "postgresql_public_grant",
    }
    report = {
        "danger": [
            dict(location, rule_id=rule, review_item={"kind": kind, "blocking": False})
            for rule, kind in kinds.items()
        ],
        "quality": [dict(location, rule_id=rule) for rule in quality_rules],
    }
    config = {"gate": {"max_quality": 0, "rules": quality_rules}}
    for strict in (False, True):
        assert check_gate(report, config, strict=strict)[0]
    seen = _flatten_findings(report)
    assert {
        r["rule_id"]: r["_review_only_kind"] for r in seen if r.get("_review_only_kind")
    } == kinds
    findings = normalize_findings(
        report, tmp_path, include_dead_code=False, use_debt_baseline=False
    )
    assert _apply_precommit_gate_policy(
        [f for f in findings if f["category"] != "debt"]
    ) == ([], 8)
    report["danger"].append(
        dict(
            location,
            rule_id="SKY-D211",
            severity="HIGH",
            review_item={"kind": "postgresql_public_grant", "blocking": False},
        )
    )
    assert not check_gate(report, config, strict=True)[0]


@pytest.mark.parametrize("value", [[], {}, None])
def test_malformed_rule_ids_cannot_exempt_a_finding(value):
    assert not is_gate_exempt_review(
        {
            "rule_id": value,
            "review_item": {"kind": "postgresql_public_grant", "blocking": False},
        }
    )
