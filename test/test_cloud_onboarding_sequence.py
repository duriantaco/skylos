"""Each Cloud onboarding step names the next one."""

import io
from argparse import Namespace

from rich.console import Console

from skylos.cicd.init_setup import DoneSetup, print_init_next_steps
from skylos.cloud.upload_status import (
    BLOCK_PULL_REQUESTS_NEXT,
    CI_BLOCKS_PULL_REQUESTS,
    local_scan_next_step,
)
from skylos.commands import cicd_cmd


def _console():
    buffer = io.StringIO()
    return Console(file=buffer, width=200, color_system=None), buffer


def _next_steps(*, upload, app_setup_url):
    console, buffer = _console()
    print_init_next_steps(
        console,
        output_path=".github/workflows/skylos.yml",
        triggers=["pull_request", "push"],
        upload=upload,
        done_requested=False,
        done_setup=DoneSetup(enabled=False, reason="no tests found", install_commands=()),
        push_branches=("main",),
        branch_detected=True,
        app_setup_url=app_setup_url,
    )
    return buffer.getvalue()


def test_local_upload_points_at_the_ci_workflow_until_it_exists():
    assert local_scan_next_step(ci_configured=False) == BLOCK_PULL_REQUESTS_NEXT
    assert "skylos cicd init" in BLOCK_PULL_REQUESTS_NEXT
    assert local_scan_next_step(ci_configured=True) == CI_BLOCKS_PULL_REQUESTS


def test_cicd_init_with_upload_lists_the_github_app_before_the_merge():
    url = "https://skylos.dev/dashboard/projects/p-1/settings#merge-blocking"
    output = _next_steps(upload=True, app_setup_url=url)

    assert "2. Before you merge, install the Skylos GitHub App" in output
    assert url in output
    assert "3. Wait for:" in output
    assert "4. After the merge, run skylos setup" in output


def test_cicd_init_without_upload_has_no_app_step():
    output = _next_steps(upload=False, app_setup_url=None)

    assert "GitHub App on this" not in output
    assert "2. Wait for:" in output


def test_upload_without_sign_in_off_a_terminal_keeps_the_job_and_says_why(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.setattr(cicd_cmd, "_cloud_login_found", lambda root: False)
    monkeypatch.setattr(cicd_cmd.sys.stdin, "isatty", lambda: False, raising=False)
    console, _ = _console()

    use_upload, note = cicd_cmd._init_upload_choice(
        Namespace(upload=True), tmp_path, console
    )

    assert use_upload is True
    assert note == cicd_cmd.UPLOAD_SIGN_IN_SKIPPED


def test_no_upload_choice_without_sign_in_names_the_one_command(tmp_path, monkeypatch):
    monkeypatch.setattr(cicd_cmd, "_cloud_login_found", lambda root: False)

    use_upload, note = cicd_cmd._init_upload_choice(Namespace(upload=None), tmp_path)

    assert use_upload is False
    assert "skylos cicd init --upload" in note


def test_ci_job_without_a_credential_says_what_is_missing(monkeypatch):
    import skylos.cli as cli

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    console, buffer = _console()

    cli._render_upload_failure(
        console, {"error": "No token found. Run 'skylos login', or set SKYLOS_TOKEN."}
    )

    output = buffer.getvalue()
    assert "Not uploaded" in output
    assert "Skylos GitHub App" in output
    assert "id-token: write" in output
