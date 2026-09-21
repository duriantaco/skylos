from __future__ import annotations

import gzip
import json
from types import SimpleNamespace

import pytest
import requests

import skylos.api as api
import skylos.cloud.control_registry as control_registry
from skylos.cloud.control_registry import (
    capture_scan_controls,
    format_control_registry_status,
    import_scan_controls,
)


SCAN_ID = "10000000-0000-4000-8000-000000000001"


def _scan_result(tmp_path):
    (tmp_path / "app.py").write_text(
        """
from fastapi import FastAPI, Depends
app = FastAPI()
@app.get("/admin", dependencies=[Depends(require_admin)])
def admin():
    return "ok"
""",
        encoding="utf-8",
    )
    return {
        "analysis_summary": {
            "comparison_scope": {
                "kind": "repository_root",
                "scan_path": str(tmp_path),
                "repository_root": str(tmp_path),
                "complete_repository": True,
                "changed_files_only": False,
                "excluded_folders": [],
            }
        }
    }


def test_report_payload_carries_scope_in_inline_and_artifact_protocols(
    tmp_path, monkeypatch
):
    result = _scan_result(tmp_path)
    result["provenance"] = None
    monkeypatch.setattr(api, "get_git_info", lambda: ("abc123", "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda _root: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda _root: {})

    prepared = api._prepare_report_upload(result)
    expected = result["analysis_summary"]["comparison_scope"]

    assert prepared.core_payload["comparison_scope"] == expected
    assert prepared.legacy_payload["comparison_scope"] == expected
    assert "comparison_scope" not in prepared.metadata

    artifacts = api._build_report_artifacts(prepared)
    try:
        with gzip.open(
            artifacts["scan_report"].file_path, "rt", encoding="utf-8"
        ) as stream:
            uploaded_report = json.load(stream)
        assert uploaded_report["comparison_scope"] == expected
    finally:
        for artifact in artifacts.values():
            artifact.cleanup()


def test_invalid_scope_cannot_be_uploaded_as_a_complete_claim(tmp_path, monkeypatch):
    result = _scan_result(tmp_path)
    result["provenance"] = None
    result["analysis_summary"]["comparison_scope"]["excluded_folders"] = [42]
    monkeypatch.setattr(api, "get_git_info", lambda: ("abc123", "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda _root: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda _root: {})

    prepared = api._prepare_report_upload(result)

    assert "comparison_scope" not in prepared.core_payload
    assert "comparison_scope" not in prepared.legacy_payload


def test_imports_discovered_controls_with_scan_and_monorepo_identity(
    tmp_path, monkeypatch
):
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "imported_controls": 1,
                "stored_controls": 1,
                "skipped_controls": 0,
                "missing_controls": 2,
                "authoritative": True,
                "snapshot_complete": True,
                "registry_updated": True,
                "lifecycle_updated": True,
            },
        )

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", fake_post)

    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture", "X-Skylos-Auth": "oidc"},
        project_root="services/api",
    )

    assert status == {
        "status": "imported",
        "discovered_controls": 1,
        "imported_controls": 1,
        "skipped_controls": 0,
        "truncated": False,
        "missing_controls": 2,
        "registry_updated": True,
        "snapshot_complete": True,
        "reported_snapshot_complete": True,
        "authoritative": True,
        "lifecycle_updated": True,
        "idempotent_replay": False,
    }
    assert captured["url"] == "https://skylos.dev/api/control-registry/import"
    assert captured["headers"]["X-Skylos-Project-Root"] == "services/api"
    assert captured["json"]["source"] == "skylos"
    assert captured["json"]["scan_id"] == SCAN_ID
    assert captured["json"]["commit_hash"] == "abc123"
    assert captured["json"]["branch"] == "main"
    assert captured["json"]["snapshot_complete"] is True
    control = captured["json"]["controls"][0]
    assert control["route"] == {"method": "GET", "path": "/admin"}
    assert control["guard_name"] == "require_admin"
    assert format_control_registry_status(status) == (
        "Control Registry: stored 1 FastAPI control from this trusted "
        "default-branch CI scan. Marked 2 previously seen controls as missing."
    )


def test_incomplete_nonempty_snapshot_cannot_retire_unseen_controls(
    tmp_path, monkeypatch
):
    result = _scan_result(tmp_path)
    result["analysis_summary"]["comparison_scope"]["complete_repository"] = False
    result["analysis_summary"]["comparison_scope"]["kind"] = (
        "repository_root_with_exclusions"
    )
    result["analysis_summary"]["comparison_scope"]["excluded_folders"] = ["generated"]
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "imported_controls": 1,
                "stored_controls": 0,
                "skipped_controls": 0,
                "authoritative": False,
                "snapshot_complete": False,
                "registry_updated": False,
                "lifecycle_updated": False,
                "noop_reason": "incomplete_project_scope",
            },
        )

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", fake_post)

    status = import_scan_controls(
        result,
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] == "recorded"
    assert status["truncated"] is False
    assert status["snapshot_complete"] is False
    assert status["reported_snapshot_complete"] is False
    assert captured["json"]["snapshot_complete"] is False
    assert format_control_registry_status(status) == (
        "Control Registry: found 1 FastAPI control; scan receipt recorded. The "
        "shared registry is unchanged because this upload did not cover the "
        "complete project (partial snapshot; existing entries retained)."
    )


@pytest.mark.parametrize(
    "status_code,data,expected",
    [
        (
            403,
            {"code": "PLAN_REQUIRED", "required_plan": "pro"},
            "plan_required",
        ),
        (409, {"code": "REPLAY_CHANGED"}, "rejected"),
        (503, {}, "unavailable"),
    ],
)
def test_registry_failures_do_not_change_scan_upload_outcome(
    tmp_path, monkeypatch, status_code, data, expected
):
    monkeypatch.setattr(
        "skylos.cloud.control_registry.requests.post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=status_code,
            json=lambda: data,
        ),
    )

    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] == expected
    assert status["discovered_controls"] == 1


def test_complete_empty_snapshot_is_posted_to_retire_missing_controls(
    tmp_path, monkeypatch
):
    result = _scan_result(tmp_path)
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "imported_controls": 0,
                "stored_controls": 0,
                "skipped_controls": 0,
                "missing_controls": 2,
                "authoritative": True,
                "snapshot_complete": True,
                "registry_updated": True,
                "lifecycle_updated": True,
            },
        )

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", fake_post)

    status = import_scan_controls(
        result,
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status == {
        "status": "not_detected",
        "discovered_controls": 0,
        "imported_controls": 0,
        "skipped_controls": 0,
        "truncated": False,
        "missing_controls": 2,
        "registry_updated": True,
        "snapshot_complete": True,
        "reported_snapshot_complete": True,
        "authoritative": True,
        "lifecycle_updated": True,
        "idempotent_replay": False,
    }
    assert captured["json"]["controls"] == []
    assert captured["json"]["snapshot_complete"] is True
    assert format_control_registry_status(status) == (
        "Control Registry: no FastAPI access controls found in this trusted "
        "complete scan; registry snapshot recorded. Marked 2 previously seen "
        "controls as missing."
    )


@pytest.mark.parametrize(
    "discovery",
    [
        {
            "controls": [],
            "status": "discovered",
            "complete": False,
            "truncated": True,
        },
        {
            "controls": [],
            "status": "skipped",
            "reason": "unsupported_partial_scope",
        },
    ],
)
def test_incomplete_or_partial_empty_snapshot_is_not_posted(
    tmp_path, monkeypatch, discovery
):
    monkeypatch.setattr(
        "skylos.cloud.control_registry.discover_fastapi_controls_for_scan",
        lambda _result: discovery,
    )

    def must_not_post(*args, **kwargs):
        raise AssertionError("an incomplete empty snapshot must not be imported")

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", must_not_post)

    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] in {"not_detected", "skipped"}
    if status["status"] == "not_detected":
        assert status["registry_updated"] is False
        assert status["snapshot_complete"] is False
        assert format_control_registry_status(status) == (
            "Control Registry: no FastAPI access controls found in this "
            "partial scan; registry unchanged."
        )


def test_body_bounding_marks_snapshot_incomplete(monkeypatch):
    monkeypatch.setattr(control_registry, "_MAX_IMPORT_BODY_BYTES", 1_500)

    payload, truncated = control_registry._bounded_payload(
        controls=[{"value": "a" * 900}, {"value": "b" * 900}],
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        snapshot_complete=True,
    )

    assert truncated is True
    assert len(payload["controls"]) == 1
    assert payload["snapshot_complete"] is False


def test_registry_transport_error_is_bounded_and_nonfatal(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("fixture token must not be surfaced")

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", fail)
    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] == "unavailable"
    assert status["reason"] == "request_failed"
    assert "token" not in str(status)


def test_captured_snapshot_does_not_reread_files_after_upload(tmp_path, monkeypatch):
    result = _scan_result(tmp_path)
    snapshot = capture_scan_controls(result)
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured["json"] = json
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "imported_controls": 1,
                "stored_controls": 1,
                "skipped_controls": 0,
                "authoritative": True,
                "snapshot_complete": True,
                "registry_updated": True,
                "lifecycle_updated": True,
            },
        )

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", fake_post)
    status = import_scan_controls(
        result,
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
        discovery_snapshot=snapshot,
    )

    assert status["status"] == "imported"
    assert captured["json"]["snapshot_complete"] is True
    assert captured["json"]["controls"][0]["guard_name"] == "require_admin"


def test_registry_skips_without_server_scan_or_git_identity(tmp_path, monkeypatch):
    def must_not_post(*args, **kwargs):
        raise AssertionError("registry request must not run")

    monkeypatch.setattr("skylos.cloud.control_registry.requests.post", must_not_post)
    result = _scan_result(tmp_path)

    assert (
        import_scan_controls(
            result,
            scan_id="not-a-scan",
            commit_hash="abc",
            branch="main",
            base_url="https://skylos.dev",
            auth_headers={},
        )["reason"]
        == "missing_or_invalid_scan_id"
    )
    assert (
        import_scan_controls(
            result,
            scan_id=SCAN_ID,
            commit_hash=None,
            branch="main",
            base_url="https://skylos.dev",
            auth_headers={},
        )["reason"]
        == "missing_git_identity"
    )


def test_post_upload_hook_runs_before_strict_gate_exit():
    events = []
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {
            "scan_id": SCAN_ID,
            "plan": "pro",
            "quality_gate": {"passed": False},
        },
    )

    with pytest.raises(SystemExit) as caught:
        api._finalize_report_upload(
            response,
            grade_data=None,
            quiet=True,
            strict=True,
            post_success=lambda result: (
                events.append(result["scan_id"])
                or {"control_registry": {"status": "imported"}}
            ),
        )

    assert caught.value.code == 1
    assert events == [SCAN_ID]


def test_post_upload_hook_failure_is_visible_but_nonfatal():
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {
            "scan_id": SCAN_ID,
            "quality_gate": {"passed": True},
        },
    )

    def fail(_result):
        raise RuntimeError("private failure detail")

    result = api._finalize_report_upload(
        response,
        grade_data=None,
        quiet=True,
        post_success=fail,
    )

    assert result["success"] is True
    assert result["control_registry"] == {
        "status": "unavailable",
        "discovered_controls": 0,
        "imported_controls": 0,
        "skipped_controls": 0,
        "truncated": False,
        "reason": "post_upload_failed",
    }
    assert "private failure detail" not in str(result)


def test_status_copy_explains_discovery_without_claiming_verification():
    message = format_control_registry_status(
        {
            "status": "imported",
            "discovered_controls": 2,
            "imported_controls": 2,
            "authoritative": True,
            "truncated": False,
        }
    )
    assert message == (
        "Control Registry: stored 2 FastAPI controls from this trusted "
        "default-branch CI scan."
    )
    assert "verified" not in message.lower()


def test_untrusted_success_is_described_as_receipt_only(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "skylos.cloud.control_registry.requests.post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "observed_controls": 1,
                "stored_controls": 0,
                "skipped_controls": 0,
                "missing_controls": 0,
                "authoritative": False,
                "snapshot_complete": False,
                "registry_updated": False,
                "lifecycle_updated": False,
                "noop_reason": "not_trusted_default_branch",
            },
        ),
    )

    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="feature/example",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] == "recorded"
    assert status["imported_controls"] == 0
    assert status["registry_updated"] is False
    assert format_control_registry_status(status) == (
        "Control Registry: found 1 FastAPI control; scan receipt recorded. The "
        "shared registry is unchanged because only trusted default-branch CI "
        "scans can update it."
    )


def test_idempotent_replay_does_not_claim_an_import(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "skylos.cloud.control_registry.requests.post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "stored_controls": 0,
                "skipped_controls": 0,
                "missing_controls": 0,
                "authoritative": True,
                "snapshot_complete": True,
                "registry_updated": False,
                "lifecycle_updated": False,
                "noop_reason": "idempotent_replay",
                "idempotent_replay": True,
            },
        ),
    )

    status = import_scan_controls(
        _scan_result(tmp_path),
        scan_id=SCAN_ID,
        commit_hash="abc123",
        branch="main",
        base_url="https://skylos.dev",
        auth_headers={"Authorization": "Bearer fixture"},
    )

    assert status["status"] == "unchanged"
    assert status["imported_controls"] == 0
    assert format_control_registry_status(status) == (
        "Control Registry: this scan receipt was already processed; the shared "
        "registry is unchanged."
    )
