"""Descriptive labels and real credentials through the static CLI and gate."""

import json
import os
import sys

import pytest

from skylos import cli
from skylos.core.safe_cache_io import write_text_no_symlink


LABEL = "upstream model prefill / first-token"
OPAQUE_TOKEN = "9xQ2mK7pL4vR8tW1zN6bY3cH5jD0fG2sA"


@pytest.fixture
def local_project(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith(("GIT_", "GITHUB_", "GITLAB_", "SKYLOS_", "BITBUCKET_")):
            monkeypatch.delenv(name)
    for name in (
        "CI",
        "TF_BUILD",
        "SYSTEM_PULLREQUEST_TARGETBRANCH",
        "SYSTEM_PULLREQUEST_PULLREQUESTID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)
    monkeypatch.setattr(
        cli, "upload_report", lambda *_args, **_kwargs: pytest.fail("Must not upload")
    )
    project = tmp_path.resolve() / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return project


@pytest.mark.parametrize("mode", ["concise", "json", "llm"])
@pytest.mark.parametrize(
    "key,value,secret",
    [
        ("upstream_prefill_first_token", LABEL, False),
        ("api_token", LABEL, True),
        ("upstream_prefill_first_token", OPAQUE_TOKEN, True),
    ],
    ids=["descriptive-label", "credential-context", "opaque-token"],
)
def test_static_cli_keeps_credentials_blocking_without_flagging_labels(
    local_project, monkeypatch, capsys, mode, key, value, secret
):
    source = (
        "PHASES = {\n    "
        + json.dumps(key)
        + ": "
        + json.dumps(value)
        + ",\n}\n\ndef main():\n    return PHASES\n\n"
        'if __name__ == "__main__":\n    main()\n'
    )
    assert write_text_no_symlink(local_project / "app.py", source)
    flags = ["--llm"] if mode == "llm" else ["--format", mode]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(local_project),
            "--secrets",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--gate",
            "--strict",
            *flags,
        ],
    )
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    assert code == int(secret)
    if mode == "json":
        payload = json.loads(captured.out)
        findings = payload.get("secrets", [])
        assert any(item["rule_id"] == "SKY-S101" for item in findings) is secret
        assert payload["gate"]["passed"] is not secret
        assert payload.get("analysis_errors", []) == []
    else:
        assert ("SKY-S101" in captured.out) is secret
    if secret:
        assert value not in captured.out
