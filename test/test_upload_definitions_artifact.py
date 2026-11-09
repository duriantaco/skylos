from __future__ import annotations

import gzip
import json

import pytest

import skylos.api as api

CLOUD_ACCEPTED_ARTIFACTS = {"scan_report"}


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.headers = {"ETag": "e"}
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


class CloudInitRule:
    def __init__(self):
        self.inits = []
        self.puts = []
        self.completes = []

    def post(self, url, **kwargs):
        body = kwargs.get("json")
        if body is None:
            body = json.loads(kwargs["data"])
        if url == api.REPORT_INIT_URL:
            names = sorted(body["artifacts"])
            self.inits.append(names)
            for name in names:
                if name not in CLOUD_ACCEPTED_ARTIFACTS:
                    return Resp(
                        400,
                        {
                            "error": f"Unsupported artifact '{name}'.",
                            "code": "INVALID_ARTIFACT_MANIFEST",
                        },
                    )
            artifacts = {}
            for name in names:
                artifacts[name] = {
                    "artifact_id": name,
                    "key": name,
                    "upload": {
                        "method": "PUT",
                        "url": f"https://uploads.skylos.dev/{name}",
                    },
                }
            return Resp(
                200, {"scan_id": "s1", "upload_id": "u1", "artifacts": artifacts}
            )
        if url == api.REPORT_COMPLETE_URL:
            self.completes.append(body)
            return Resp(200, {"scanId": "s1", "quality_gate": {"passed": True}})
        raise AssertionError(f"unexpected POST {url}")

    def put(self, url, data=None, headers=None, timeout=None, **kwargs):
        self.puts.append((url, json.loads(gzip.decompress(data.read()))))
        return Resp(200)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def main():\n    return 1\n")
    monkeypatch.setattr(api, "get_project_token", lambda: "sk_test_token")
    monkeypatch.setattr(api, "get_git_root", lambda: str(root))
    monkeypatch.setattr(api, "get_git_info", lambda: ("0" * 40, "main", "tester", None))
    monkeypatch.setattr(api, "detect_ai_code", lambda *a, **k: {"detected": False})
    monkeypatch.setattr(api, "get_project_info", lambda token: None)
    monkeypatch.setenv("SKYLOS_PENDING_UPLOAD_DIR", str(tmp_path / "pending"))
    monkeypatch.setenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "10")
    return root


def _result(root):
    return {
        "provenance": None,
        "project_root": "",
        "analysis_summary": {"project_root": ""},
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "file": str(root / "src" / "app.py"),
                "line": 1,
                "severity": "MEDIUM",
                "message": "Too complex.",
            }
        ],
        "definitions": {
            "src.app.main": {"file": str(root / "src" / "app.py"), "line": 1}
        },
    }


def test_large_upload_sends_only_the_artifact_cloud_accepts(repo, monkeypatch):
    cloud = CloudInitRule()
    monkeypatch.setattr(api.requests, "post", cloud.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", cloud.put)

    result = api.upload_report(_result(repo), quiet=True)

    assert result["success"] is True
    assert cloud.inits == [["scan_report"]]
    assert [url for url, _ in cloud.puts] == ["https://uploads.skylos.dev/scan_report"]
    assert "definitions" not in cloud.puts[0][1]
    assert len(cloud.completes) == 1
    assert not cloud.completes[0].get("skipped_artifacts")


def test_prepared_report_has_no_definitions_artifact(repo):
    prepared = api._prepare_report_upload(_result(repo))

    assert prepared.definitions_payload is None
    assert prepared.scan_summary["definitions_count"] == 1
    assert prepared.legacy_payload["definitions"]["src.app.main"]["file"] == (
        "src/app.py"
    )
    artifacts = api._build_report_artifacts(prepared)
    try:
        assert set(artifacts) == {"scan_report"}
    finally:
        for artifact in artifacts.values():
            artifact.cleanup()
