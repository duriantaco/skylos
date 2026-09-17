"""Managed comment reconciliation requires complete, unfiltered scan evidence."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

import skylos.api as api
from skylos.cloud.gitlab import cli_full_scan, managed_report_paths, scan_receipt


def _complete():
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "analysis_error_count": 0,
            "sca_coverage": {"status": "complete", "complete": True},
            "grep_verify": {"enabled": False},
        },
        "provenance": None,
    }


def test_managed_finding_paths_use_original_analyzer_file_without_mutating_result(
    tmp_path,
):
    checkout = tmp_path / "checkout"
    project = checkout / "apps" / "api"
    original = {
        "quality": [
            {
                "file_path": "github/workspace/app.py",
                "file": str(project / "github/workspace/app.py"),
            },
            {"file": str(project), "kind": "repo_policy", "rule_id": "SKY-R104"},
        ],
        "reviewed_findings": [{"file_path": "app.py", "file": str(project / "app.py")}],
        "analysis_summary": {"analysis_error_count": 0},
    }
    before = deepcopy(original)
    anchored = managed_report_paths(original, checkout, "apps/api")
    assert anchored["quality"][0]["file_path"] == str(
        project / "github/workspace/app.py"
    )
    assert anchored["quality"][1]["file_path"] == str(project)
    assert anchored["reviewed_findings"][0]["file_path"] == str(project / "app.py")
    assert original == before
    assert anchored["analysis_summary"] is original["analysis_summary"]


def test_managed_relative_only_paths_use_scanned_subproject_not_process_cwd(
    tmp_path, monkeypatch
):
    checkout = tmp_path / "checkout"
    monkeypatch.chdir(tmp_path)
    original = {"danger": [{"file_path": "home/runner/work/a/b/app.py"}, {}]}
    anchored = managed_report_paths(original, checkout, "apps/api")
    assert anchored["danger"][0]["file_path"] == str(
        checkout / "apps/api/home/runner/work/a/b/app.py"
    )
    assert anchored["danger"][1] == {}, "a missing location must not be fabricated"


def test_managed_path_copy_keeps_outside_absolute_location_outside(tmp_path):
    checkout = tmp_path / "checkout"
    outside = tmp_path / "outside.py"
    result = {"danger": [{"file_path": "inside.py", "file": str(outside)}]}
    anchored = managed_report_paths(result, checkout, "")
    assert anchored["danger"][0]["file_path"] == str(outside)
    assert managed_report_paths(result, None, "") is result


def test_receipt_requires_analyzer_owned_evidence_and_explicit_full_scope():
    result = _complete()
    result["gitlab_scan_receipt"] = {"complete": True, "full_scan": True}
    assert scan_receipt(result, full_scan=True) == {
        "complete": False,
        "full_scan": False,
    }
    assert scan_receipt(result, analyzer_owned=True) == {
        "complete": True,
        "full_scan": False,
    }
    assert scan_receipt(result, analyzer_owned=True, full_scan=True) == {
        "complete": True,
        "full_scan": True,
    }


@pytest.mark.parametrize(
    "change",
    [
        {"analysis_errors": [{"message": "fixture analysis unavailable"}]},
        {"analysis_summary": None},
        {"analysis_summary": {"analysis_error_count": 1}},
        {"analysis_summary": {"analysis_error_count": "0"}},
        {"analysis_summary": {"incomplete_languages": ["go"]}},
        {"analysis_summary": {"language_engines": {"go": {"status": "partial"}}}},
        {"analysis_summary": {"grep_verify": {"enabled": True, "complete": False}}},
        {
            "analysis_summary": {
                "sca_coverage": {"status": "incomplete", "complete": False}
            }
        },
        {
            "analysis_summary": {
                "sca_coverage": {"status": "complete", "complete": False}
            }
        },
        {"analysis_summary": {"sca_coverage": {"status": [], "complete": True}}},
        {"analysis_summary": {"sca_coverage": "invalid"}},
        {
            "analysis_summary": {
                "sca_coverage": {
                    "status": "complete",
                    "complete": True,
                    "parse_error_count": 1,
                }
            }
        },
        {
            "analysis_summary": {
                "sca_coverage": {
                    "status": "complete",
                    "complete": True,
                    "query": {"complete": False},
                }
            }
        },
        {"analysis_summary": {"grep_verify": {"enabled": False, "complete": False}}},
    ],
)
def test_incomplete_or_inconsistent_receipts_never_resolve_comments(change):
    result = _complete()
    result.update(change)
    result["is_forced"] = True
    result["gitlab_scan_receipt"] = {"complete": True, "full_scan": True}
    assert scan_receipt(result, analyzer_owned=True, full_scan=True) == {
        "complete": False,
        "full_scan": False,
    }


def test_available_language_engine_is_not_marked_incomplete():
    result = _complete()
    result["analysis_summary"]["language_engines"] = {"go": {"status": "available"}}
    assert scan_receipt(result, analyzer_owned=True, full_scan=True)["complete"] is True


@pytest.mark.parametrize(
    "coverage",
    [None, {"status": "complete_with_unresolved_versions", "complete": True}],
)
def test_missing_or_unresolved_dependency_receipt_cannot_resolve_old_findings(coverage):
    result = _complete()
    if coverage is None:
        result["analysis_summary"].pop("sca_coverage")
    else:
        result["analysis_summary"]["sca_coverage"] = coverage
    assert scan_receipt(result, analyzer_owned=True, full_scan=True) == {
        "complete": True,
        "full_scan": False,
    }


@pytest.fixture
def full_invocation(tmp_path, monkeypatch):
    monkeypatch.delenv("SKYLOS_PROJECT_ROOT", raising=False)
    (tmp_path / ".git").mkdir()
    args = SimpleNamespace(
        path=[str(tmp_path)],
        danger=True,
        secrets=True,
        quality=True,
        ai_defects=True,
        sca=True,
        confidence=60,
    )
    return args, {}, tmp_path


def test_unfiltered_all_category_directory_scan_is_full(full_invocation):
    assert cli_full_scan(*full_invocation) is True


@pytest.mark.parametrize(
    "key,value",
    [
        ("baseline", True),
        ("baseline_ref", "origin/main"),
        ("diff", "origin/main"),
        ("diff_base", "origin/main"),
        ("select", ["SKY-D201"]),
        ("severity", "HIGH"),
        ("category", "security"),
        ("file_filter", "app.py"),
        ("exclude_folders", ["generated"]),
        ("include_folders", ["generated"]),
        ("limit", 10),
        ("confidence", 80),
        ("sca", False),
        ("danger", False),
        ("secrets", False),
        ("quality", False),
        ("ai_defects", False),
    ],
)
def test_cli_narrowing_is_not_full(full_invocation, key, value):
    setattr(full_invocation[0], key, value)
    assert cli_full_scan(*full_invocation) is False


@pytest.mark.parametrize(
    "key", ["ignore", "exclude", "whitelist", "lower_confidence", "overrides"]
)
def test_config_narrowing_is_not_full(full_invocation, key):
    full_invocation[1][key] = ["fixture"]
    assert cli_full_scan(*full_invocation) is False


def test_changed_files_and_mismatched_monorepo_binding_are_not_full(
    full_invocation, monkeypatch
):
    assert cli_full_scan(*full_invocation, changed_files=set()) is False
    monkeypatch.setenv("SKYLOS_PROJECT_ROOT", "apps/api")
    assert cli_full_scan(*full_invocation) is False


def test_force_does_not_change_full_scope(full_invocation):
    full_invocation[0].force = True
    assert cli_full_scan(*full_invocation) is True
    full_invocation[0].baseline = True
    assert cli_full_scan(*full_invocation) is False


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("owned", [False, True])
def test_receipt_survives_all_upload_protocol_payloads(monkeypatch, managed, owned):
    monkeypatch.setattr(
        api,
        "get_git_info",
        lambda: ("a" * 40, "main", "fixture", {"provider": "gitlab"}),
    )
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda root: {})
    monkeypatch.setattr(api, "_load_repo_link", lambda root: {})
    result = _complete()
    result["project_root"] = ""
    result["danger"] = [
        {
            "rule_id": "SKY-D201",
            "file": "app.py",
            "line": 1,
            "message": "fixture finding",
            "severity": "HIGH",
        }
    ]
    original = deepcopy(result)
    prepared = api._prepare_report_upload(
        result,
        is_forced=True,
        analyzer_owned=owned,
        gitlab_managed=managed,
        gitlab_full_scan=True,
    )
    initialized = api._build_report_init_payload(prepared, {})
    for payload in (
        prepared.metadata,
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
        initialized,
    ):
        if managed:
            assert payload["gitlab_scan_receipt"] == {
                "complete": owned,
                "full_scan": owned,
            }
        else:
            assert "gitlab_scan_receipt" not in payload
    assert prepared.core_payload["runs"][0]["results"]
    assert result == original
