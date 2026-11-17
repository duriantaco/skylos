"""Main scan uploads bind Cloud operations to the target without moving outputs."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos import api, cli
from skylos.cloud import login, sync
from skylos.cloud.upload_destination import resolve_upload_destination
from skylos.commands import cloud_cmd, scan_cmd
from skylos.reporting import provenance


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fixture_repo(root):
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("VALUE = 1\n")
    _git(root, "add", "app.py")
    _git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )


def _report():
    return {
        "definitions": {},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "analysis_errors": [],
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
    }


@pytest.fixture
def scan_repos(monkeypatch, tmp_path):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    for root in (caller, target):
        _fixture_repo(root)
        (root / ".skylos").mkdir()
        (root / ".skylos/link.json").write_text(json.dumps({"project_id": root.name}))
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "token": "caller-token",
                "project_id": "caller",
                "tokens": {
                    "caller": {"token": "caller-token"},
                    "target": {"token": "target-token"},
                },
            }
        )
    )
    monkeypatch.chdir(caller)
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(api, "GLOBAL_CREDS_FILE", credentials)
    monkeypatch.setattr(sync, "GLOBAL_CREDS_DIR", tmp_path)
    monkeypatch.setattr(sync, "GLOBAL_CREDS_FILE", credentials)
    monkeypatch.setattr(api, "get_key", lambda _name: None)
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: None)
    monkeypatch.setattr(api, "_try_gitlab_oidc_token", lambda: None)
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    monkeypatch.setattr(cli, "_is_tty", lambda: False)
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {})
    monkeypatch.setattr(cli, "print_badge", lambda *_a, **_k: None)
    monkeypatch.setattr(scan_cmd, "_start_update_check", lambda: None)
    monkeypatch.setattr(scan_cmd, "_print_upgrade_notice", lambda *_a: None)
    monkeypatch.setattr(
        sync, "load_custom_rules", lambda: {"status": "complete", "rules": []}
    )
    monkeypatch.setattr(
        api,
        "get_project_info",
        lambda token: {
            "ok": True,
            "project": {
                "id": token.removesuffix("-token"),
                "name": token.removesuffix("-token"),
            },
        },
    )

    def no_network(*_args, **_kwargs):
        pytest.fail("scan context regression tests must not use the network")

    monkeypatch.setattr(api.requests, "request", no_network)
    monkeypatch.setattr(api.requests, "get", no_network)
    monkeypatch.setattr(api.requests, "post", no_network)
    events = []

    def analyze(path, **kwargs):
        events.append(("analyze", Path.cwd(), path))
        return json.dumps(_report())

    monkeypatch.setattr(cli, "run_analyze", analyze)
    monkeypatch.setattr(
        provenance,
        "analyze_provenance",
        lambda *_a, **_k: SimpleNamespace(
            summary={},
            to_dict=dict,
        ),
    )
    return SimpleNamespace(
        caller=caller, target=target, credentials=credentials, events=events
    )


def _upload_response():
    return {
        "success": True,
        "scan_id": "saved-scan",
        "upload_trust": "unverified",
        "quality_gate_reported": True,
        "quality_gate_passed": True,
        "destination": {"project_id": "target", "branch": "main"},
    }


@pytest.mark.parametrize("output_format", ["json", "pretty", "rich"])
def test_main_upload_uses_target_project_and_keeps_analysis_and_output_in_caller(
    scan_repos, monkeypatch, output_format
):
    repos = scan_repos
    original_print = cli._print_upload_destination

    def destination(project_root):
        resolved = resolve_upload_destination(project_root)
        repos.events.append(("destination", Path.cwd(), resolved.project_id))
        return resolved

    def print_destination(*args, **kwargs):
        repos.events.append(("print-destination", Path.cwd()))
        return original_print(*args, **kwargs)

    def upload(result, **kwargs):
        repos.events.append(
            ("upload", Path.cwd(), api.get_project_token(), api.get_git_root())
        )
        return _upload_response()

    monkeypatch.setattr(cli, "_resolve_upload_destination", destination)
    monkeypatch.setattr(cli, "_print_upload_destination", print_destination)
    monkeypatch.setattr(cli, "upload_report", upload)

    scan_cmd.run_scan_command(
        [
            str(repos.target),
            "--format",
            output_format,
            "--upload",
            "--no-provenance",
            "--no-clipboard",
            "--output",
            "report.txt",
        ],
        cli_module=cli,
    )

    assert ("analyze", repos.caller, str(repos.target)) in repos.events
    assert ("destination", repos.target, "target") in repos.events
    assert ("upload", repos.target, "target-token", str(repos.target)) in repos.events
    if output_format == "rich":
        assert ("print-destination", repos.target) in repos.events
    assert Path.cwd() == repos.caller
    assert (repos.caller / "report.txt").is_file()
    assert not (repos.target / "report.txt").exists()
    assert api.get_project_token() == "caller-token"


def test_provenance_and_verification_use_target_repo_from_another_directory(
    scan_repos, monkeypatch
):
    repos = scan_repos
    original_git_root = api.get_git_root

    def git_root():
        root = original_git_root()
        repos.events.append(("git-root", Path.cwd(), root))
        return root

    def analyze_provenance(root, **kwargs):
        repos.events.append(("provenance", root))
        return SimpleNamespace(summary={}, to_dict=dict)

    def verify(result, **kwargs):
        repos.events.append(("verify", Path.cwd(), api.get_project_token()))
        return {"success": True}

    monkeypatch.setattr(api, "get_git_root", git_root)
    monkeypatch.setattr(api, "verify_report", verify)
    monkeypatch.setattr(provenance, "analyze_provenance", analyze_provenance)

    scan_cmd.run_scan_command(
        [
            str(repos.target),
            "--format",
            "rich",
            "--no-upload",
            "--verify",
            "--no-clipboard",
        ],
        cli_module=cli,
    )

    assert ("verify", repos.target, "target-token") in repos.events
    assert ("git-root", repos.target, str(repos.target)) in repos.events
    assert ("provenance", str(repos.target)) in repos.events
    assert Path.cwd() == repos.caller


@pytest.mark.parametrize("failure", [RuntimeError("transport failed"), SystemExit(4)])
def test_main_upload_restores_caller_directory_when_transport_exits(
    scan_repos, monkeypatch, failure
):
    repos = scan_repos

    def upload(*args, **kwargs):
        assert Path.cwd() == repos.target
        raise failure

    monkeypatch.setattr(cli, "upload_report", upload)

    with pytest.raises(type(failure)):
        scan_cmd.run_scan_command(
            [str(repos.target), "--upload", "--no-provenance", "--no-clipboard"],
            cli_module=cli,
        )

    assert Path.cwd() == repos.caller
    assert api.get_project_token() == "caller-token"


def test_explicit_human_upload_connects_target_before_analysis(scan_repos, monkeypatch):
    repos = scan_repos
    monkeypatch.setattr(cli, "_is_tty", lambda: True)

    def connect(cli_module, project_root, **kwargs):
        repos.events.append(("connect", Path.cwd(), project_root))
        return True

    monkeypatch.setattr(cloud_cmd, "_ensure_connected", connect)
    monkeypatch.setattr(cli, "upload_report", lambda *_a, **_k: _upload_response())

    scan_cmd.run_scan_command(
        [str(repos.target), "--upload", "--no-provenance", "--no-clipboard"],
        cli_module=cli,
    )

    assert repos.events[:2] == [
        ("connect", repos.target, repos.target),
        ("analyze", repos.caller, str(repos.target)),
    ]
    assert Path.cwd() == repos.caller


def test_cancelled_main_sign_in_stops_before_analysis_and_restores_caller(
    scan_repos, monkeypatch
):
    repos = scan_repos
    monkeypatch.setattr(cli, "_is_tty", lambda: True)

    def connect(cli_module, project_root, **kwargs):
        repos.events.append(("connect", Path.cwd(), project_root))
        return False

    monkeypatch.setattr(cloud_cmd, "_ensure_connected", connect)

    with pytest.raises(SystemExit) as stopped:
        scan_cmd.run_scan_command(
            [str(repos.target), "--upload", "--no-provenance", "--no-clipboard"],
            cli_module=cli,
        )

    assert stopped.value.code == 1
    assert repos.events == [("connect", repos.target, repos.target)]
    assert Path.cwd() == repos.caller


def test_no_upload_never_starts_authentication_even_when_upload_was_also_given(
    scan_repos, monkeypatch
):
    repos = scan_repos

    def unexpected_auth(*_args, **_kwargs):
        pytest.fail("--no-upload must not start Cloud authentication or upload")

    monkeypatch.setattr(cloud_cmd, "_ensure_connected", unexpected_auth)
    monkeypatch.setattr(login, "run_login", unexpected_auth)
    monkeypatch.setattr(login, "manual_token_fallback", unexpected_auth)
    monkeypatch.setattr(cli, "upload_report", unexpected_auth)
    monkeypatch.setattr(cli, "_resolve_upload_destination", unexpected_auth)

    scan_cmd.run_scan_command(
        [
            str(repos.target),
            "--format=json",
            "--upload",
            "--no-upload",
            "--no-provenance",
            "--no-clipboard",
            "--output",
            "local.json",
        ],
        cli_module=cli,
    )

    assert repos.events == [("analyze", repos.caller, str(repos.target))]
    assert (repos.caller / "local.json").is_file()
    assert not (repos.target / "local.json").exists()
    assert Path.cwd() == repos.caller


@pytest.mark.parametrize("target_linked", [False, True], ids=["unlinked", "stale-link"])
@pytest.mark.parametrize("format_args", [["--format=json"], ["--json"]])
def test_main_json_upload_rejects_unrelated_saved_token_before_analysis(
    scan_repos, monkeypatch, capsys, target_linked, format_args
):
    repos = scan_repos
    credentials = json.loads(repos.credentials.read_text())
    del credentials["tokens"]["target"]
    repos.credentials.write_text(json.dumps(credentials))
    if not target_linked:
        (repos.target / ".skylos/link.json").unlink()
    # A TTY must not make a machine-output invocation open browser sign-in.
    monkeypatch.setattr(cli, "_is_tty", lambda: True)

    def unexpected_work(*_args, **_kwargs):
        pytest.fail("missing target credentials must stop before login, analysis or upload")

    monkeypatch.setattr(login, "run_login", unexpected_work)
    monkeypatch.setattr(login, "manual_token_fallback", unexpected_work)
    monkeypatch.setattr(cli, "run_analyze", unexpected_work)
    monkeypatch.setattr(cli, "upload_report", unexpected_work)
    monkeypatch.setattr(cli, "_resolve_upload_destination", unexpected_work)
    monkeypatch.setattr(sync, "load_custom_rules", unexpected_work)

    with pytest.raises(SystemExit) as stopped:
        scan_cmd.run_scan_command(
            [
                str(repos.target),
                "--upload",
                *format_args,
                "--no-provenance",
                "--no-clipboard",
            ],
            cli_module=cli,
        )

    assert stopped.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert cloud_cmd.NOT_CONNECTED in captured.err
    assert "sign in in your browser" in captured.err
    assert repos.events == []
    assert Path.cwd() == repos.caller
    assert api.get_project_token() == "caller-token"
