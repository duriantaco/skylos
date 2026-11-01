import hashlib
import json
import subprocess

import pytest

from skylos import api
from skylos.cicd import context_packet


@pytest.mark.parametrize(
    "owned,state,expected",
    [
        (True, "clean", True),
        (False, "clean", False),
        (True, "dirty", False),
        (True, "unknown", False),
    ],
)
def test_upload_builds_optional_context_only_from_owned_clean_source(
    tmp_path, monkeypatch, owned, state, expected
):
    calls = []
    generated = {"version": 1, "head_sha": "a" * 40, "snapshot_id": "b" * 64}
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda _: {"detected": False})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_: None)
    monkeypatch.setattr(api, "source_revision_state", lambda *_: state)

    def collect(root, findings, head):
        calls.append((root, findings, head))
        return generated

    monkeypatch.setattr(context_packet, "build_upload_context", collect)
    (tmp_path / "app.py").write_text("value = 1\n")
    result = {
        "danger": [
            {
                "file": str(tmp_path / "app.py"),
                "line": 1,
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "message": "review",
            }
        ],
        "pr_context": {"forged": True},
        "provenance": {},
    }
    prepared = api._prepare_report_upload(result, analyzer_owned=owned)
    for payload in (
        prepared.metadata,
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
    ):
        assert ("pr_context" in payload) == expected
        if expected:
            assert payload["pr_context"] == generated
    assert len(calls) == int(expected)
    if calls:
        assert calls[0] == (str(tmp_path), [{"file": "app.py", "line": 1}], "a" * 40)


def test_upload_packet_is_redacted_bounded_and_hashed_after_sanitization(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    token = "gh" + "p_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4zA6"
    (tmp_path / "app.py").write_text(
        f"def f(value):\n    API_TOKEN = '{token}'\n    return eval(value)\n"
    )
    git("add", "app.py")
    git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "base")
    (tmp_path / "untracked.py").write_text("def never_upload():\n    return 1\n")
    packet = context_packet.build_upload_context(
        tmp_path, [{"file": "app.py", "line": 3}], git("rev-parse", "HEAD")
    )
    assert packet["path_base"] == "repository"
    assert packet["file_digests"].keys() == {"app.py"}
    serialized = json.dumps(packet)
    assert token not in serialized
    assert len(serialized.encode()) < 24_576
    snapshot = packet.pop("snapshot_id")
    assert (
        snapshot
        == hashlib.sha256(
            json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert packet["checks"] == []


def test_optional_context_error_does_not_discard_uploaded_findings(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda _: {"detected": False})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_: None)
    monkeypatch.setattr(api, "source_revision_state", lambda *_: "clean")

    def unavailable(*_):
        raise RecursionError("bounded graph unavailable")

    monkeypatch.setattr(context_packet, "build_upload_context", unavailable)
    (tmp_path / "app.py").write_text("value = 1\n")
    result = {
        "danger": [
            {
                "file": str(tmp_path / "app.py"),
                "line": 1,
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "message": "review",
            }
        ],
        "provenance": {},
    }
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert "pr_context" not in prepared.metadata
    assert prepared.compatibility_payload["findings"][0]["rule_id"] == "SKY-D201"
