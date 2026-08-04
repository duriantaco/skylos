from __future__ import annotations

import json

from skylos.cloud.shadow_upload import (
    MAX_SHADOW_CLOUD_UPLOAD_BYTES,
    _cloud_web_base_url,
    _shadow_reports_url,
    prepare_shadow_report_for_cloud,
    upload_shadow_report,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_shadow_cloud_upload_limit_matches_cloud_envelope_contract():
    assert MAX_SHADOW_CLOUD_UPLOAD_BYTES == 4_000_000


def test_shadow_reports_url_handles_api_base():
    assert _shadow_reports_url("https://skylos.dev") == (
        "https://skylos.dev/api/shadow/reports"
    )
    assert _shadow_reports_url("https://skylos.dev/api") == (
        "https://skylos.dev/api/shadow/reports"
    )
    assert _cloud_web_base_url("https://skylos.dev/api") == "https://skylos.dev"


def test_shadow_upload_uses_project_auth_and_context(monkeypatch, tmp_path):
    import skylos.api as api

    captured = {}

    def fake_post(url, headers, payload, **kwargs):
        captured.update(url=url, headers=headers, payload=payload, kwargs=kwargs)
        return (
            _Response(
                201,
                {
                    "success": True,
                    "id": "receipt-1",
                    "view_url": "/dashboard/projects/project-1/scanner-proof",
                },
            ),
            None,
        )

    monkeypatch.setattr(api, "BASE_URL", "https://cloud.example/api")
    monkeypatch.setattr(api, "get_project_token", lambda: "token")
    monkeypatch.setattr(api, "get_git_root", lambda: tmp_path)
    monkeypatch.setattr(api, "_cli_version", lambda: "4.2.0")
    monkeypatch.setattr(api, "_new_upload_client_session_id", lambda: "session-1")
    monkeypatch.setattr(api, "_post_json_with_retries", fake_post)

    result = upload_shadow_report({"schema_version": 1}, project_path=tmp_path)

    assert result["success"] is True
    assert result["view_url"] == (
        "https://cloud.example/dashboard/projects/project-1/scanner-proof"
    )
    assert captured["url"] == "https://cloud.example/api/shadow/reports"
    assert captured["headers"] == {
        "Authorization": "Bearer token",
        "X-Skylos-Project-Root": ".",
    }
    assert captured["payload"]["project_root"] == ""
    assert captured["payload"]["cli_version"] == "4.2.0"
    assert captured["payload"]["upload_client_session_id"] == "session-1"
    assert 402 in captured["kwargs"]["accepted_statuses"]


def test_shadow_upload_requires_token(monkeypatch):
    import skylos.api as api

    monkeypatch.setattr(api, "get_project_token", lambda: None)

    result = upload_shadow_report({"schema_version": 1})

    assert result["success"] is False
    assert result["code"] == "NO_TOKEN"


def test_shadow_upload_rejects_oversized_payload_before_network(monkeypatch):
    import skylos.api as api

    monkeypatch.setattr(api, "get_project_token", lambda: "token")
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "_cli_version", lambda: "4.2.0")
    monkeypatch.setattr(api, "_new_upload_client_session_id", lambda: "session-1")
    monkeypatch.setattr(
        api,
        "_post_json_with_retries",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network called")),
    )

    result = upload_shadow_report(
        {"external": {"tools": ["x" * MAX_SHADOW_CLOUD_UPLOAD_BYTES]}}
    )

    assert result["success"] is False
    assert result["code"] == "PAYLOAD_TOO_LARGE"
    assert "4,000,000 bytes" in result["error"]


def test_shadow_upload_surfaces_structured_server_error(monkeypatch):
    import skylos.api as api

    monkeypatch.setattr(api, "get_project_token", lambda: "token")
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "_cli_version", lambda: None)
    monkeypatch.setattr(api, "_new_upload_client_session_id", lambda: "session-1")
    monkeypatch.setattr(
        api,
        "_post_json_with_retries",
        lambda *args, **kwargs: (
            _Response(
                409,
                {
                    "error": "Repository mismatch",
                    "code": "SHADOW_PROVENANCE_MISMATCH",
                },
            ),
            None,
        ),
    )

    result = upload_shadow_report(json.loads('{"schema_version": 1}'))

    assert result == {
        "success": False,
        "error": "Repository mismatch",
        "code": "SHADOW_PROVENANCE_MISMATCH",
    }


def test_shadow_upload_preserves_safe_upgrade_link_without_retry(monkeypatch):
    import skylos.api as api

    captured = {}

    def fake_post(*args, **kwargs):
        captured["accepted_statuses"] = kwargs["accepted_statuses"]
        return (
            _Response(
                402,
                {
                    "error": "Three free proofs used",
                    "code": "SCANNER_PROOF_UPGRADE_REQUIRED",
                    "upgrade_url": "/dashboard/billing?return_to=%2Fdashboard%2Fprojects%2F1%2Fscanner-proof",
                },
            ),
            None,
        )

    monkeypatch.setattr(api, "BASE_URL", "https://cloud.example/api")
    monkeypatch.setattr(api, "get_project_token", lambda: "token")
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "_cli_version", lambda: None)
    monkeypatch.setattr(api, "_new_upload_client_session_id", lambda: "session-1")
    monkeypatch.setattr(api, "_post_json_with_retries", fake_post)

    result = upload_shadow_report({"schema_version": 1})

    assert 402 in captured["accepted_statuses"]
    assert result == {
        "success": False,
        "error": "Three free proofs used",
        "code": "SCANNER_PROOF_UPGRADE_REQUIRED",
        "upgrade_url": "https://cloud.example/dashboard/billing?return_to=%2Fdashboard%2Fprojects%2F1%2Fscanner-proof",
    }


def test_cloud_projection_rejects_absolute_path_outside_repository():
    report = {
        "scope": {"skylos": {"repository_root": "/work/repo"}},
        "external_findings": [{"file_path": "/private/secret.py"}],
        "skylos_only_findings": [],
    }

    try:
        prepare_shadow_report_for_cloud(report)
    except ValueError as exc:
        assert "outside the analyzed repository" in str(exc)
    else:
        raise AssertionError("unsafe absolute path was accepted")


def test_cloud_projection_normalizes_windows_file_uri_inside_repository():
    report = {
        "scope": {"skylos": {"repository_root": r"C:\Work\Repo"}},
        "external_findings": [
            {
                "file_path": "file:///c:/work/repo/src/App.py",
                "shadow": {
                    "reachability": {
                        "state": "live",
                        "file_path": "file:///C:/WORK/REPO/src/App.py",
                    }
                },
            }
        ],
        "skylos_only_findings": [],
    }

    projected = prepare_shadow_report_for_cloud(report)

    assert projected["external_findings"][0]["file_path"] == "src/App.py"
    assert (
        projected["external_findings"][0]["shadow"]["reachability"]["file_path"]
        == "src/App.py"
    )


def test_cloud_projection_rejects_local_repository_identities():
    local_identities = (
        "/Users/alice/work/repo",
        "file:///Users/alice/work/repo",
        r"C:\Users\alice\work\repo",
        "../repo",
    )

    for identity in local_identities:
        report = {
            "scope": {
                "skylos": {
                    "repository_root": "/Users/alice/work/repo",
                    "repository_identities": [identity],
                },
                "incumbent": {"repository_identities": [identity]},
            },
            "external_findings": [],
            "skylos_only_findings": [],
        }
        try:
            prepare_shadow_report_for_cloud(report)
        except ValueError as exc:
            assert "repository identity" in str(exc)
        else:
            raise AssertionError(f"local repository identity was accepted: {identity}")


def test_cloud_projection_canonicalizes_network_repository_identity():
    report = {
        "scope": {
            "skylos": {
                "repository_identities": ["https://token@example.com:443/Acme/Repo.git"]
            },
            "incumbent": {"repository_identities": ["git@example.com:Acme/Repo.git"]},
        },
        "external_findings": [],
        "skylos_only_findings": [],
    }

    projected = prepare_shadow_report_for_cloud(report)

    assert projected["scope"]["skylos"]["repository_identities"] == [
        "example.com/Acme/Repo"
    ]
    assert projected["scope"]["incumbent"]["repository_identities"] == [
        "example.com/Acme/Repo"
    ]
    assert "token" not in json.dumps(projected)
