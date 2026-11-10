"""Explicit upload preparation adds sanitized persisted observations only."""

from copy import deepcopy
import json

import pytest

import skylos.api as api
from skylos.cleanup_receipts import make_cleanup_receipt, store_cleanup_receipt
from skylos.cleanup_state import STATE_PATH, mutate_cleanup_workspace


def _receipt(root, *, target=None):
    scope = {
        "target": str(target or root),
        "project_root": str(root),
        "scanner_version": "5.4.0",
        "config_digest": "4" * 64,
    }
    task = {"id": "1" * 64, "rule_id": "SKY-L038", "file": "app.py"}
    execution = {
        "task_id": task["id"],
        "source_sha256": "a" * 64,
        "applied_sha256": "b" * 64,
        "status": "applied_unverified",
        "applied": True,
        "rolled_back": False,
        "tests": {"status": "skipped"},
        "rescan": {
            "status": "passed",
            "new_findings": [],
            "original_present": False,
            "checked_categories": ["quality", "ai_defects", "dead_code"],
        },
    }
    receipt = make_cleanup_receipt(
        task,
        scope,
        execution,
        project_root=root,
        source_revision={"head": "c" * 40, "dirty": False},
    )
    return scope, receipt


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "get_git_info", lambda: ("d" * 40, "main", "test", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda *_a: {"detected": False})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_a: None)
    monkeypatch.setattr(api, "_load_repo_link", lambda *_a: {})
    monkeypatch.setattr(api, "_new_upload_client_session_id", lambda: "fixed-session")
    monkeypatch.setattr(api, "_cli_version", lambda: "5.4.0")
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_a, **_kw: pytest.fail("preparation must not upload"),
    )
    monkeypatch.setattr(api, "source_revision_state", lambda *_a, **_kw: "clean")

    def prepare(**extra):
        return api._prepare_report_upload(
            {"definitions": {}, "quality": [], "provenance": {}, **extra}
        )

    return prepare


def test_no_receipts_preserves_existing_metadata_shape_and_ignores_report_injection(
    tmp_path, prepared
):
    baseline = prepared()
    _, receipt = _receipt(tmp_path)
    injected = prepared(cleanup_receipts=[receipt])
    assert "cleanup_receipts" not in baseline.metadata
    assert injected.metadata == baseline.metadata
    assert injected.core_payload == baseline.core_payload
    assert injected.compatibility_payload == baseline.compatibility_payload


def test_persisted_receipts_are_additive_in_each_existing_payload_without_rebinding(
    tmp_path, prepared
):
    baseline = prepared()
    scope, receipt = _receipt(tmp_path)
    store_cleanup_receipt(tmp_path, scope, receipt)
    original = (tmp_path / STATE_PATH).read_bytes()
    result = prepared()
    assert result.metadata["cleanup_receipts"] == [receipt]
    assert {
        key: value
        for key, value in result.metadata.items()
        if key != "cleanup_receipts"
    } == baseline.metadata
    for payload in (
        result.core_payload,
        result.legacy_payload,
        result.compatibility_payload,
    ):
        assert payload["cleanup_receipts"] == [receipt]
    assert result.metadata["cleanup_receipts"][0]["outcome_revision"] == {
        "head": None,
        "dirty": True,
    }
    assert result.metadata["commit_hash"] == "d" * 40
    assert (tmp_path / STATE_PATH).read_bytes() == original


def test_upload_sanitizes_persisted_private_fields_without_changing_findings(
    tmp_path, prepared
):
    scope, receipt = _receipt(tmp_path)
    injected = deepcopy(receipt)
    injected["command"] = "private-command"
    injected["source"] = "private-source"
    injected["binding"] = {"status": "trusted"}
    injected["checks"]["tests"]["output"] = "private-output"
    mutate_cleanup_workspace(
        tmp_path, scope, lambda bucket: bucket.update(cleanup_receipts=[injected])
    )
    result = prepared()
    encoded = json.dumps(result.metadata["cleanup_receipts"])
    assert "private-" not in encoded and "binding" not in encoded
    assert result.metadata["cleanup_receipts"] == [receipt]
    assert result.compatibility_payload["findings"] == []


def test_malformed_or_symlink_history_does_not_reject_normal_upload(tmp_path, prepared):
    baseline = prepared()
    cache = tmp_path / STATE_PATH
    cache.parent.mkdir(parents=True)
    cache.write_text("not JSON", encoding="utf-8")
    assert prepared().metadata == baseline.metadata
    cache.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("private-data", encoding="utf-8")
    cache.symlink_to(outside)
    assert prepared().metadata == baseline.metadata
    assert outside.read_text() == "private-data"


def test_root_and_scan_subdirectory_receipts_are_loaded_and_deduplicated(
    tmp_path, prepared
):
    # A Git marker anchors logical paths; no source or target code is executed.
    (tmp_path / ".git").mkdir()
    project = tmp_path / "services" / "tool"
    project.mkdir(parents=True)
    scope, receipt = _receipt(project)
    store_cleanup_receipt(project, scope, receipt)
    duplicate_scope, _ = _receipt(tmp_path)
    mutate_cleanup_workspace(
        tmp_path,
        duplicate_scope,
        lambda bucket: bucket.update(cleanup_receipts=[receipt]),
    )
    result = prepared(project_root="services/tool")
    assert result.metadata["cleanup_receipts"] == [receipt]
    assert receipt["file"] == "services/tool/app.py"
    assert receipt["scope"]["target"] == "services/tool"


def test_upload_cannot_read_receipts_through_external_or_symlink_scan_root(
    tmp_path, monkeypatch
):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    scope, receipt = _receipt(outside)
    store_cleanup_receipt(outside, scope, receipt)
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    assert api._cleanup_receipts_for_upload(tmp_path, outside) == []
    assert api._cleanup_receipts_for_upload(tmp_path, tmp_path / "linked") == []


def test_metadata_builder_discards_invalid_receipts_and_raw_unknown_fields(tmp_path):
    _, receipt = _receipt(tmp_path)
    receipt["command"] = "private-command"
    result = api._build_report_metadata(
        commit_hash=None,
        branch=None,
        actor=None,
        cleanup_receipts=[{"file": "/outside"}, receipt],
    )
    assert len(result["cleanup_receipts"]) == 1
    assert "command" not in result["cleanup_receipts"][0]
    assert "cleanup_receipts" not in api._build_report_metadata(
        commit_hash=None, branch=None, actor=None, cleanup_receipts=[{"status": []}]
    )


def test_receipt_claim_cannot_replace_security_findings_or_failed_grade(
    tmp_path, prepared
):
    (tmp_path / "app.py").write_text("unsafe_path = True\n", encoding="utf-8")
    raw = {
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(tmp_path / "app.py"),
                "line": 1,
                "severity": "HIGH",
                "message": "unsafe filesystem path",
            }
        ],
        "grade": {"passed": False, "score": 12},
    }
    baseline = prepared(**raw)
    scope, receipt = _receipt(tmp_path)
    receipt["runs"] = []
    receipt["grade"] = {"passed": True, "score": 100}
    mutate_cleanup_workspace(
        tmp_path, scope, lambda bucket: bucket.update(cleanup_receipts=[receipt])
    )
    result = prepared(**raw)
    assert (
        result.core_payload["runs"][0]["results"]
        == baseline.core_payload["runs"][0]["results"]
    )
    assert result.metadata["grade"] == baseline.metadata["grade"] == raw["grade"]
    assert len(result.core_payload["runs"][0]["results"]) == 1
    assert "grade" not in result.metadata["cleanup_receipts"][0]
