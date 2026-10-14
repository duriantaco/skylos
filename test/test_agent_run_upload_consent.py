"""Agent run summaries reach Skylos Cloud only with an explicit --upload.

A saved login, SKYLOS_TOKEN or a CI OIDC token is not consent. Without the
flag, `agent scan`, `agent remediate` (both modes) and `agent verify` must not
look a token up or open a socket.
"""

from __future__ import annotations

import socket
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

import skylos.api as api
from skylos import cli
from skylos.commands import agent_verify_cmd
from skylos.core.safe_cache_io import write_text_no_symlink


@pytest.fixture
def no_network(monkeypatch):
    """Record (and refuse) every outbound socket connection."""
    attempts = []

    def refuse_connect(self, address):
        attempts.append(address)
        raise OSError("network disabled in test")

    def refuse_create_connection(address, *args, **kwargs):
        attempts.append(address)
        raise OSError("network disabled in test")

    monkeypatch.setattr(socket.socket, "connect", refuse_connect)
    monkeypatch.setattr(socket, "create_connection", refuse_create_connection)
    return attempts


@pytest.fixture
def cloud(monkeypatch):
    """A token is present; requests.post and token lookup are observed."""
    monkeypatch.setenv("SKYLOS_TOKEN", "t0d-test-token")
    post = Mock(return_value=Mock(status_code=200))
    token = Mock(wraps=api.get_project_token)
    monkeypatch.setattr(api.requests, "post", post)
    monkeypatch.setattr(api, "get_project_token", token)
    return SimpleNamespace(post=post, token=token)


def _agent_runs_posts(post: Mock) -> list:
    return [c for c in post.call_args_list if c.args and c.args[0] == api.AGENT_RUNS_URL]


def test_upload_agent_run_is_off_unless_requested(cloud, no_network):
    api.upload_agent_run("scan", {"total": 1})
    api.upload_agent_run("scan", {"total": 1}, requested=False)
    api.upload_agent_run("scan", {"total": 1}, requested="yes")

    cloud.token.assert_not_called()
    cloud.post.assert_not_called()
    assert no_network == []


def test_upload_agent_run_posts_once_when_requested(cloud, no_network):
    api.upload_agent_run("scan", {"total": 1}, requested=True, model="m")

    posts = _agent_runs_posts(cloud.post)
    assert len(posts) == 1
    assert posts[0].kwargs["json"]["command"] == "scan"
    assert posts[0].kwargs["headers"]["Authorization"] == "Bearer t0d-test-token"


def test_cli_helper_requires_an_explicit_request(cloud, no_network):
    with patch.object(api, "upload_agent_run") as upload:
        cli._upload_agent_run_best_effort("scan", {}, requested=False)
    upload.assert_not_called()

    with pytest.raises(TypeError):
        cli._upload_agent_run_best_effort("scan", {})  # requested is required


def _run_agent_cli(argv: list[str]) -> int:
    with (
        patch.object(sys, "argv", ["skylos", "agent", *argv]),
        patch("skylos.cli.Console", return_value=MagicMock()),
        patch("skylos.cli._ensure_llm_support", return_value=True),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "", "http://127.0.0.1:9/v1", True),
        ),
    ):
        with pytest.raises(SystemExit) as exit_info:
            cli.main()
    return exit_info.value.code


def _scan_argv(tmp_path):
    assert write_text_no_symlink(tmp_path / "app.py", "print(1)\n")
    return ["scan", str(tmp_path), "--format", "json", "-o", str(tmp_path / "o.json")]


def _remediate_agent(summary: dict) -> Mock:
    agent = Mock()
    agent.return_value.run.return_value = summary
    return agent


@pytest.mark.parametrize("upload", [False, True])
def test_agent_scan_sends_run_summary_only_with_upload(
    tmp_path, cloud, no_network, upload
):
    argv = _scan_argv(tmp_path) + (["--upload"] if upload else [])
    with patch("skylos.cli.run_pipeline", return_value=[]):
        assert _run_agent_cli(argv) == 0

    posts = _agent_runs_posts(cloud.post)
    if upload:
        assert len(posts) == 1
        assert posts[0].kwargs["json"]["command"] == "scan"
        assert cloud.post.call_count == 1  # 0 findings: no report upload
    else:
        assert posts == []
        cloud.post.assert_not_called()
        cloud.token.assert_not_called()
    assert no_network == []


@pytest.mark.parametrize("upload", [False, True])
def test_agent_remediate_sends_run_summary_only_with_upload(
    tmp_path, cloud, no_network, upload
):
    agent = _remediate_agent({"total_findings": 0, "fixed": 0})
    argv = ["remediate", str(tmp_path), "--dry-run"] + (["--upload"] if upload else [])
    with patch("skylos.llm.orchestrator.RemediationAgent", agent):
        assert _run_agent_cli(argv) == 0

    posts = _agent_runs_posts(cloud.post)
    assert [p.kwargs["json"]["command"] for p in posts] == (
        ["remediate"] if upload else []
    )
    if not upload:
        cloud.token.assert_not_called()
    assert no_network == []


@pytest.mark.parametrize("upload", [False, True])
def test_agent_cleanup_sends_run_summary_only_with_upload(
    tmp_path, cloud, no_network, upload
):
    orchestrator = _remediate_agent({"total_items": 0, "applied": 0})
    argv = ["remediate", str(tmp_path), "--dry-run", "--standards"] + (
        ["--upload"] if upload else []
    )
    with patch("skylos.llm.cleanup_orchestrator.CleanupOrchestrator", orchestrator):
        assert _run_agent_cli(argv) == 0

    posts = _agent_runs_posts(cloud.post)
    assert [p.kwargs["json"]["command"] for p in posts] == (
        ["cleanup"] if upload else []
    )
    if not upload:
        cloud.token.assert_not_called()
    assert no_network == []


@pytest.mark.parametrize("upload", [False, True])
def test_agent_verify_sends_run_summary_only_with_upload(
    tmp_path, cloud, no_network, upload
):
    source = tmp_path / "app.py"
    assert write_text_no_symlink(source, "def unused():\n    return 1\n")
    finding = {
        "name": "unused",
        "full_name": "app.unused",
        "file": str(source),
        "line": 1,
        "confidence": 100,
    }
    static = {
        "unused_functions": [finding],
        "definitions": {"app.unused": {"file": str(source), "line": 1, "type": "function"}},
    }

    def harness(_args, _path, **_kwargs):
        return {
            "verified_findings": [finding],
            "new_dead_code": [],
            "entry_points": [],
            "stats": {
                "total_findings": 1,
                "verified_true_positive": 1,
                "verified_false_positive": 0,
                "uncertain": 0,
                "entry_points_discovered": 0,
                "survivors_challenged": 0,
                "survivors_reclassified_dead": 0,
                "llm_calls": 1,
                "elapsed_seconds": 0.1,
            },
        }

    args = SimpleNamespace(
        path=str(tmp_path), conf=60, format="table", fix=False, upload=upload
    )
    with (
        patch.object(agent_verify_cmd, "_run_static_dead_code_scan", return_value=static),
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(False, False),
        ),
        patch(
            "skylos.core.review_decisions.apply_trusted_review_decisions",
            side_effect=lambda result, _root: result,
        ),
        patch.object(agent_verify_cmd, "_run_verification_harness", harness),
    ):
        code = agent_verify_cmd.run_agent_verify_command(
            args,
            MagicMock(),
            model="m",
            api_key=None,
            provider="openai",
            base_url=None,
            exclude_folders=[],
            upload_agent_run=cli._upload_agent_run_best_effort,
        )

    assert code == 0
    posts = _agent_runs_posts(cloud.post)
    assert [p.kwargs["json"]["command"] for p in posts] == (["verify"] if upload else [])
    if not upload:
        cloud.token.assert_not_called()
    assert no_network == []


@pytest.mark.parametrize("command", ["remediate", "verify"])
def test_agent_upload_flag_is_documented(command, capsys):
    with pytest.raises(SystemExit):
        cli._build_agent_parser().parse_args([command, "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--upload" in help_text
    assert "Skylos Cloud" in help_text
    assert "Off by default" in help_text


# --- actor: git author or null, never the OS user name ----------------------


@pytest.fixture
def no_ci(monkeypatch):
    monkeypatch.delenv("SKYLOS_ACTOR", raising=False)
    monkeypatch.setattr(api, "_detect_ci", lambda: (None, {}))
    monkeypatch.setenv("USER", "t0d-os-user")
    monkeypatch.setenv("LOGNAME", "t0d-os-user")


def _git_repo(path, author):
    import subprocess

    path.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path / "a.py", "x = 1\n")
    for args in (
        ["init", "-q"],
        ["add", "."],
        ["-c", f"user.name={author}", "-c", "user.email=a@example.invalid",
         "commit", "-qm", "init"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


def _sent_actor(cloud):
    posts = _agent_runs_posts(cloud.post)
    assert len(posts) == 1
    payload = posts[0].kwargs["json"]
    assert "t0d-os-user" not in repr(payload)
    return payload["actor"]


def test_agent_run_actor_is_null_without_git_author(
    tmp_path, monkeypatch, cloud, no_ci
):
    monkeypatch.chdir(tmp_path)  # not a git repository
    api.upload_agent_run("scan", {}, requested=True)
    assert _sent_actor(cloud) is None


def test_agent_run_actor_is_the_head_commit_author(
    tmp_path, monkeypatch, cloud, no_ci
):
    monkeypatch.chdir(_git_repo(tmp_path / "repo", "Jane Author"))
    api.upload_agent_run("scan", {}, requested=True)
    assert _sent_actor(cloud) == "Jane Author"


def test_agent_run_actor_prefers_skylos_actor_then_ci_actor(
    tmp_path, monkeypatch, cloud, no_ci
):
    monkeypatch.chdir(_git_repo(tmp_path / "repo", "Jane Author"))
    monkeypatch.setenv("SKYLOS_ACTOR", "release-bot")
    api.upload_agent_run("scan", {}, requested=True)
    assert _sent_actor(cloud) == "release-bot"

    cloud.post.reset_mock()
    monkeypatch.delenv("SKYLOS_ACTOR")
    monkeypatch.setattr(api, "_detect_ci", lambda: ("github_actions", {"actor": "octocat"}))
    api.upload_agent_run("scan", {}, requested=True)
    assert _sent_actor(cloud) == "octocat"


def test_report_actor_never_falls_back_to_the_os_user(tmp_path, monkeypatch, no_ci):
    monkeypatch.chdir(tmp_path)
    assert api.get_git_info()[2] == "unknown"

    monkeypatch.chdir(_git_repo(tmp_path / "repo", "Jane Author"))
    assert api.get_git_info()[2] == "Jane Author"


# --- skylos . --upload --no-upload never uploads ------------------------------


@pytest.mark.parametrize("output_format", ["json", "rich"])
@pytest.mark.parametrize("gate", [False, True])
def test_no_upload_beats_upload_with_or_without_gate(
    monkeypatch, tmp_path, output_format, gate
):
    from test.test_cli_report_serialization import _configure

    _configure(monkeypatch, tmp_path, output_format, upload=True)
    argv = [*cli.sys.argv, "--no-upload"] + (["--gate"] if gate else [])
    monkeypatch.setattr(cli.sys, "argv", argv)
    upload = Mock(return_value={"success": True, "scan_id": "x"})
    monkeypatch.setattr(cli, "upload_report", upload)
    monkeypatch.setattr(api, "upload_report", upload)

    try:
        cli.main()
    except SystemExit:
        pass

    upload.assert_not_called()
