from __future__ import annotations

import copy
import json

import pytest

import skylos.api as api
from skylos.api._scan_coverage import (
    architecture_advisory_summary,
    quality_rule_classification,
    scan_coverage_receipt,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS


def _full_result() -> dict:
    return {
        "analysis_summary": {
            "comparison_scope": {
                "kind": "repository_root",
                "complete_repository": True,
                "changed_files_only": False,
                "excluded_folders": [],
            },
            "grade_categories": ["quality"],
            "analysis_error_count": 0,
            "resolution_scope_limited": False,
        },
        "analysis_errors": [],
        "suppressed": [],
        "grade": {"overall": "A"},
        "quality": [],
        "architecture_metrics": {
            "iad_enforced": False,
            "advisories": [],
            "advisory_count": 0,
            "advisory_signal_count": 0,
        },
    }


def _receipt(result: dict, *, analyzer_owned: bool = True, analysis_mode: str = "static") -> dict:
    receipt = scan_coverage_receipt(
        result, analyzer_owned=analyzer_owned, analysis_mode=analysis_mode
    )
    assert receipt is not None
    return receipt


def test_full_static_scan_can_attest_covered_checks():
    receipt = _receipt(_full_result())
    assert receipt == {
        "version": 1,
        "scope": "full_repository",
        "complete": True,
        "selected_rules": [],
        "resolution_covered_checks": ["quality"],
        "reasons": [],
    }


@pytest.mark.parametrize(
    ("change", "expected_reason"),
    [
        (lambda r: r["analysis_summary"].update(selected_rules=["SKY-Q301"]), "selected_rules"),
        (lambda r: r["analysis_summary"]["comparison_scope"].update(changed_files_only=True), "partial_repository"),
        (lambda r: r["analysis_summary"]["comparison_scope"].update(kind="file"), "partial_repository"),
        (lambda r: r["analysis_summary"]["comparison_scope"].update(kind="repository_root_with_exclusions", complete_repository=False, excluded_folders=["generated"]), "partial_repository"),
        (lambda r: r.pop("grade"), "filtered_findings"),
        (lambda r: r["analysis_errors"].append({"file": "bad.ts"}), "analysis_incomplete"),
        (lambda r: r["analysis_summary"].update(incomplete_languages=["typescript"]), "analysis_incomplete"),
        (lambda r: r["analysis_summary"].update(selected_rules="SKY-Q301"), "selected_rules"),
        (lambda r: r["analysis_summary"].update(resolution_scope_limited=True), "configured_suppression"),
        (lambda r: r["suppressed"].append({"rule_id": "SKY-Q301"}), "suppressed_findings"),
    ],
)
def test_partial_or_filtered_scans_cannot_claim_complete_coverage(change, expected_reason):
    result = _full_result()
    change(result)
    receipt = _receipt(result)
    assert receipt["complete"] is False
    assert receipt["scope"] == "partial"
    assert expected_reason in receipt["reasons"]
    assert receipt["resolution_covered_checks"] == []


def test_standard_default_exclusions_are_full_scope_but_custom_exclusions_are_not():
    result = _full_result()
    result["analysis_summary"]["comparison_scope"].update(
        kind="repository_root_with_exclusions",
        complete_repository=False,
        excluded_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
    )
    assert _receipt(result)["complete"] is True
    result["analysis_summary"]["comparison_scope"]["excluded_folders"].append("src")
    assert "partial_repository" in _receipt(result)["reasons"]


def test_partial_sca_only_removes_dependency_resolution_coverage():
    result = _full_result()
    result["analysis_summary"]["grade_categories"] = ["quality", "dependencies"]
    result["analysis_summary"]["sca_coverage"] = {
        "status": "complete_with_unresolved_versions",
        "complete": True,
        "category_complete": False,
        "unresolved_dependency_count": 28,
    }
    receipt = _receipt(result)
    assert receipt["complete"] is True
    assert receipt["resolution_covered_checks"] == ["quality"]
    result["analysis_summary"]["sca_coverage"] = {
        "status": "incomplete",
        "complete": False,
        "category_complete": False,
    }
    receipt = _receipt(result)
    assert receipt["complete"] is True
    assert receipt["resolution_covered_checks"] == ["quality"]
    result["analysis_summary"]["sca_coverage"] = {
        "status": "complete",
        "complete": True,
        "category_complete": True,
        "unresolved_dependency_count": 0,
        "query": {"complete": True},
    }
    assert _receipt(result)["resolution_covered_checks"] == [
        "quality",
        "dependencies",
    ]


def test_disabled_check_and_missing_architecture_evidence_are_not_covered():
    result = _full_result()
    result["analysis_summary"]["grade_categories"] = ["quality", "dead_code"]
    result["analysis_summary"]["grep_verify"] = {"enabled": False}
    assert _receipt(result)["resolution_covered_checks"] == ["quality"]
    result["architecture_metrics"].pop("iad_enforced")
    assert _receipt(result)["resolution_covered_checks"] == []


def test_unmeasured_architecture_module_does_not_attest_quality_absence():
    result = _full_result()
    result["architecture_metrics"]["iad_enforced"] = True
    result["architecture_metrics"]["abstractness_unavailable_modules"] = [
        "src.unmeasured"
    ]
    receipt = _receipt(result)
    assert receipt["complete"] is True
    assert receipt["resolution_covered_checks"] == []
    result["architecture_metrics"]["abstractness_unavailable_modules"] = []
    assert _receipt(result)["resolution_covered_checks"] == ["quality"]


def test_selected_rules_are_preserved_but_cannot_resolve_other_rules():
    result = _full_result()
    result["analysis_summary"]["selected_rules"] = ["sky-q301"]
    assert _receipt(result)["selected_rules"] == ["SKY-Q301"]


def test_non_analyzer_and_non_static_uploads_are_partial():
    result = _full_result()
    assert "unverified_origin" in _receipt(result, analyzer_owned=False)["reasons"]
    assert "unverified_origin" in _receipt(result, analysis_mode="hybrid")["reasons"]


def test_missing_summary_emits_no_coverage_claim():
    assert scan_coverage_receipt({}, analyzer_owned=True, analysis_mode="static") is None


def test_ignored_quality_rule_does_not_resolve_other_quality_issues(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        '[tool.skylos]\nignore = ["SKY-Q301"]\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        "def main():\n    return 1\n", encoding="utf-8"
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_quality=True,
            grep_verify=False,
            include_review_context=True,
        )
    )
    assert result["analysis_summary"]["resolution_scope_limited"] is True
    receipt = _receipt(result)
    assert receipt["complete"] is False
    assert receipt["resolution_covered_checks"] == []
    assert "configured_suppression" in receipt["reasons"]


def test_nested_file_config_ignore_limits_resolution_scope(tmp_path):
    from skylos.analyzer import analyze

    source = tmp_path / "src"
    source.mkdir()
    (source / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        '[tool.skylos]\nignore = ["SKY-Q301"]\n', encoding="utf-8"
    )
    (source / "app.py").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        "def main():\n    return 1\n", encoding="utf-8"
    )
    result = json.loads(
        analyze(str(tmp_path), enable_quality=True, include_review_context=True)
    )
    assert result["analysis_summary"]["resolution_scope_limited"] is True


@pytest.mark.parametrize(("filename", "source"), [("app.py", "VALUE = 1\n"), ("app.ts", "export const value = 1;\n")])
def test_uploaded_analyzer_covers_standard_default_exclusions(
    tmp_path, filename, source
):
    from skylos.analyzer import analyze

    (tmp_path / filename).write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        source, encoding="utf-8"
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_quality=True,
            exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
            include_review_context=True,
        )
    )
    assert result["analysis_summary"]["resolution_scope_limited"] is False
    assert _receipt(result)["resolution_covered_checks"] == ["quality", "dead_code"]


def test_architecture_policy_is_explicit_even_when_there_are_no_signals():
    result = _full_result()
    assert quality_rule_classification(result) == {
        "version": 1,
        "architecture_iad": "advisory",
    }
    result["architecture_metrics"]["iad_enforced"] = True
    assert quality_rule_classification(result)["architecture_iad"] == "enforced"
    result["architecture_metrics"].pop("iad_enforced")
    assert quality_rule_classification(result)["architecture_iad"] == "unknown"


def test_conflicting_actionable_iad_finding_is_not_labeled_advisory():
    result = _full_result()
    result["quality"] = [{"rule_id": "SKY-Q802", "advisory": False}]
    assert quality_rule_classification(result)["architecture_iad"] == "unknown"


@pytest.mark.parametrize("enforce", [False, True])
def test_analyzer_records_iad_policy_with_zero_signals(tmp_path, enforce):
    from skylos.analyzer import analyze

    (tmp_path / "app.py").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
        "VALUE = 1\n", encoding="utf-8"
    )
    if enforce:
        (tmp_path / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] pytest-owned tmp_path fixture
            "[tool.skylos.architecture]\nenforce_iad = true\n",
            encoding="utf-8",
        )
    result = json.loads(analyze(str(tmp_path), enable_quality=True, grep_verify=False))
    assert result["architecture_metrics"]["iad_enforced"] is enforce
    assert quality_rule_classification(result)["architecture_iad"] == (
        "enforced" if enforce else "advisory"
    )


def test_architecture_advisory_upload_is_count_only_and_bounded():
    result = _full_result()
    result["architecture_metrics"]["advisories"] = [
        {
            "file": "private/path.py",
            "name": "private.module",
            "advisory": True,
            "signals": [
                {"rule_id": "SKY-Q802", "advisory": True, "message": "private message"},
                {"rule_id": "SKY-Q803", "advisory": True},
                {"rule_id": "SKY-Q802", "advisory": True},
            ],
        },
        {
            "file": "other.py",
            "advisory": True,
            "signals": [{"rule_id": "SKY-Q802", "advisory": True}],
        },
    ]
    assert architecture_advisory_summary(result) == {
        "version": 1,
        "module_count": 2,
        "signal_count": 3,
        "by_rule": {"SKY-Q802": 2, "SKY-Q803": 1},
    }


def test_upload_payloads_carry_coverage_and_classification_without_advisory_sources(
    monkeypatch,
):
    result = _full_result()
    result["architecture_metrics"]["advisories"] = [
        {
            "file": "private/path.py",
            "name": "private.module",
            "advisory": True,
            "signals": [{"rule_id": "SKY-Q802", "advisory": True}],
        }
    ]
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    prepared = api._prepare_report_upload(copy.deepcopy(result), analyzer_owned=True)

    for payload in (
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
        prepared.metadata,
    ):
        assert payload["scan_coverage"]["complete"] is True
        assert payload["quality_rule_classification"]["architecture_iad"] == "advisory"
        assert payload["architecture_advisories"]["signal_count"] == 1
        assert "private.module" not in json.dumps(payload)
        assert "private/path.py" not in json.dumps(payload)
    assert prepared.core_payload["runs"][0]["results"] == []
    assert prepared.compatibility_payload["findings"] == []
