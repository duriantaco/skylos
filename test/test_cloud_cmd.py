"""`skylos cloud`: one command that scans with every check, uploads and shows the gate."""

import pytest

import skylos.api as api
import skylos.cli as cli
from skylos.cloud.cloud_receipt import (
    CI_NEXT_STEP,
    FAILED_NEXT_STEP,
    cloud_receipt_lines,
    local_next_steps,
)
from skylos.cloud.upload_destination import UploadDestination
from skylos.commands import cloud_cmd
from skylos.commands.cloud_cmd import cloud_scan_argv, run_cloud_command
from test.test_cli_report_serialization import _configure

BASE = "https://skylos.dev"
PREVIOUS = {
    "scan_id": "scan-0",
    "created_at": "2026-10-24T15:38:00+00:00",
    "commit": "1ba9895aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "passed": False,
    "overridden": False,
}


def _response(passed, *, branch="feat/add-endpoint", default="main", **extra):
    message = "Quality Gate Passed."
    if not passed:
        message = "Quality Gate Failed! 1 critical security issue."
    response = {
        "success": True,
        "scan_id": "scan-1",
        "quality_gate_passed": passed,
        "quality_gate_reported": True,
        "quality_gate": {
            "passed": passed,
            "new_violations": 5,
            "message": message,
        },
        "destination": {
            "project_id": "proj-1",
            "branch": branch,
            "default_branch": default,
            "default_branch_source": "repository",
        },
        "previous_gate": dict(PREVIOUS),
    }
    response.update(extra)
    return response


def _dest(**extra):
    values = {"key_source": "env", "project_id": "proj-1", "project_name": "demo"}
    values.update(extra)
    return UploadDestination(**values)


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], [".", "-a", "--upload"]),
        (["src"], ["src", "-a", "--upload"]),
        (["--gate"], [".", "-a", "--upload"]),
        (["src", "-a", "--upload"], ["src", "-a", "--upload"]),
        (["--all"], [".", "--all", "--upload"]),
        (["--danger", "--secrets"], [".", "--danger", "--secrets", "--upload"]),
        (["src", "--security", "--gate"], ["src", "--security", "--upload"]),
    ],
)
def test_cloud_scan_argv_adds_every_check_unless_named_and_the_upload_once(
    argv, expected
):
    assert cloud_scan_argv(argv) == expected


def test_failed_gate_receipt_is_the_gate_one_link_and_the_next_step():
    lines = cloud_receipt_lines(_dest(), _response(False), BASE, ci_configured=False)

    assert lines == [
        "✗ Quality gate on feat/add-endpoint: FAILED (same as last run on "
        "24 Oct 15:38 UTC, 1ba9895) · 1 critical security issue",
        "  Open: https://skylos.dev/dashboard/projects/proj-1?branch=feat%2Fadd-endpoint",
        FAILED_NEXT_STEP,
    ]


def test_passed_gate_on_main_points_to_ci_setup_until_a_workflow_exists():
    response = _response(True, branch="main")

    without_ci = cloud_receipt_lines(_dest(), response, BASE, ci_configured=False)
    with_ci = cloud_receipt_lines(_dest(), response, BASE, ci_configured=True)

    assert without_ci == [
        "✓ Quality gate on main: PASSED (was FAILED on 24 Oct 15:38 UTC, 1ba9895)",
        "  Open: https://skylos.dev/dashboard/projects/proj-1",
        CI_NEXT_STEP,
    ]
    assert with_ci == without_ci[:2]


def test_unverified_default_branch_upload_says_it_does_not_mark_issues_fixed():
    response = _response(True, branch="main", upload_trust="unverified")

    lines = cloud_receipt_lines(
        _dest(key_source="saved"), response, BASE, ci_configured=True
    )

    assert lines[2] == (
        "  This is main, but a login-token upload is unverified: it does not "
        "set the project verdict or mark issues fixed."
    )
    assert len(lines) == 3


def test_feature_branch_and_assumed_default_add_no_extra_notes():
    response = _response(False)
    response["destination"]["default_branch_source"] = "assumed"

    lines = cloud_receipt_lines(_dest(), response, BASE, ci_configured=True)

    assert len(lines) == 3
    assert not any("This is not main" in line for line in lines)
    assert not any("assumed" in line for line in lines)


def test_failed_gate_without_reasons_names_the_new_issue_count():
    response = _response(False)
    response["quality_gate"]["message"] = "Quality Gate Failed!"
    response["new_issue_baseline"] = {"mode": "baseline", "branch": "main"}

    lines = cloud_receipt_lines(_dest(), response, BASE, ci_configured=True)

    assert lines[0].endswith("· 5 new issues (not in the last passing scan of main)")


def test_server_without_a_gate_result_still_gives_the_link():
    response = _response(True)
    response["quality_gate_reported"] = False

    lines = cloud_receipt_lines(_dest(), response, BASE, ci_configured=False)

    assert lines == [
        "✓ Uploaded to Skylos Cloud (no quality gate result was reported)",
        "  Open: https://skylos.dev/dashboard/projects/proj-1?branch=feat%2Fadd-endpoint",
    ]


def test_without_a_project_id_the_link_is_the_scan_page():
    response = _response(False)
    response["destination"].pop("project_id")

    lines = cloud_receipt_lines(None, response, BASE, ci_configured=True)

    assert lines[1] == "  Open: https://skylos.dev/dashboard/scans/scan-1"


def test_hostile_server_strings_never_reach_the_terminal():
    response = _response(False, branch="feat/\x1b[31mred")
    response["quality_gate"]["message"] = "Quality Gate Failed! \x1b]8;;evil\x07bad."

    lines = cloud_receipt_lines(_dest(), response, BASE, ci_configured=True)

    assert not any("\x1b" in line or "\x07" in line for line in lines)


def test_local_next_steps_drop_ci_setup_once_a_workflow_exists():
    assert [command for command, _ in local_next_steps(ci_configured=False)] == [
        "skylos cloud",
        "skylos cicd init",
    ]
    assert [command for command, _ in local_next_steps(ci_configured=True)] == [
        "skylos cloud"
    ]


def _no_scan(*_args, **_kwargs):
    raise AssertionError("the scan must not start")


def test_help_prints_usage_and_never_scans(monkeypatch, capsys):
    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", _no_scan)

    assert run_cloud_command(["--help"], cli_module=cli) == 0

    out = capsys.readouterr().out
    assert out.startswith("Usage: skylos cloud [PATH] [scan flags]")
    assert "Not your repository." in out
    assert "--gate" in out
    assert "skylos upload --retry" in out


def test_help_is_reached_from_the_top_level_command(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "cloud", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("Usage: skylos cloud")


def test_no_upload_is_refused(monkeypatch, capsys):
    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", _no_scan)

    assert run_cloud_command(["--no-upload"], cli_module=cli) == 2
    assert "skylos cloud always uploads" in capsys.readouterr().err


def _not_connected(monkeypatch, *, tty, ci=False):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.setattr(cli, "_detect_link_file", lambda _root: None)
    monkeypatch.setattr(api, "get_project_token", lambda: None)
    monkeypatch.setattr(cli, "_is_tty", lambda: tty)
    monkeypatch.setattr(cli, "_is_ci", lambda: ci)


def test_not_connected_without_a_terminal_stops_before_scanning(
    monkeypatch, capsys, tmp_path
):
    _not_connected(monkeypatch, tty=False)
    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", _no_scan)
    monkeypatch.setattr("skylos.cloud.login.run_login", _no_scan)

    assert run_cloud_command([str(tmp_path)], cli_module=cli) == 1
    assert cloud_cmd.NOT_CONNECTED in capsys.readouterr().out


def test_not_connected_in_a_terminal_logs_in_first(monkeypatch, capsys, tmp_path):
    _not_connected(monkeypatch, tty=True)
    calls = []
    monkeypatch.setattr(
        "skylos.cloud.login.run_login",
        lambda console=None: calls.append("login") or None,
    )
    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", _no_scan)

    assert run_cloud_command([str(tmp_path)], cli_module=cli) == 1

    out = capsys.readouterr().out
    assert calls == ["login"]
    assert cloud_cmd.OPENING_LOGIN in out
    assert cloud_cmd.LOGIN_CANCELLED in out


def test_ci_without_a_token_leaves_the_identity_check_to_the_upload(
    monkeypatch, tmp_path
):
    _not_connected(monkeypatch, tty=False, ci=True)
    seen = []
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda argv, *, cli_module, cloud, cloud_gate: seen.append(
            (argv, cloud, cloud_gate)
        ),
    )

    assert run_cloud_command([str(tmp_path)], cli_module=cli) == 0
    assert seen == [([str(tmp_path), "-a", "--upload"], True, False)]


def test_connected_runs_the_scan_in_cloud_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("SKYLOS_TOKEN", "local-test-key")
    seen = []
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda argv, *, cli_module, cloud, cloud_gate: seen.append(
            (argv, cloud, cloud_gate)
        ),
    )

    assert run_cloud_command([str(tmp_path), "--gate"], cli_module=cli) == 0
    assert seen == [([str(tmp_path), "-a", "--upload"], True, True)]


def _cloud_scan(monkeypatch, tmp_path, response, *, command):
    _configure(monkeypatch, tmp_path, "rich", upload=True)
    monkeypatch.setenv("SKYLOS_TOKEN", "local-test-key")
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", *command, str(tmp_path), "--no-clipboard"]
    )
    destination = _dest(branch="feat/add-endpoint")
    monkeypatch.setattr(cli, "_resolve_upload_destination", lambda _root: destination)
    monkeypatch.setattr(api, "_print_pending_upload_reminder", lambda: None)
    calls = []

    def upload(result, **kwargs):
        calls.append(kwargs)
        return response

    monkeypatch.setattr(cli, "upload_report", upload)
    return calls


def _main_exit():
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


def test_cloud_scan_prints_the_short_receipt_only(monkeypatch, capsys, tmp_path):
    calls = _cloud_scan(monkeypatch, tmp_path, _response(False), command=["cloud"])

    assert _main_exit() == 0

    out = capsys.readouterr().out
    assert calls and calls[0]["quiet"] is True
    assert "Uploading findings to Skylos Cloud" in out
    assert "✗ Quality gate on feat/add-endpoint: FAILED" in out
    assert (
        "Open: https://skylos.dev/dashboard/projects/proj-1?branch=feat%2Fadd-endpoint"
        in out
    )
    assert FAILED_NEXT_STEP.strip() in out
    assert "· Overview:" not in out
    assert "View details" not in out
    assert "Uploading 1 cloud scan." not in out
    assert "does not change this command's exit code" not in out
    assert "new issues" not in out
    assert "Unused function: unused" in out.split("Uploading findings")[0]


def test_cloud_scan_in_ci_does_not_suggest_ci_setup(monkeypatch, capsys, tmp_path):
    _cloud_scan(monkeypatch, tmp_path, _response(True), command=["cloud"])
    monkeypatch.setattr(cli, "_is_ci", lambda: True)

    assert _main_exit() == 0

    out = capsys.readouterr().out
    assert "✓ Quality gate on feat/add-endpoint: PASSED" in out
    assert "skylos cicd init" not in out


def test_cloud_scan_with_gate_exits_one_on_a_failed_gate(monkeypatch, capsys, tmp_path):
    _cloud_scan(monkeypatch, tmp_path, _response(False), command=["cloud", "--gate"])
    monkeypatch.setattr(cli, "run_gate_interaction", _no_scan)

    assert _main_exit() == 1

    out = capsys.readouterr().out
    assert "✗ Quality gate on feat/add-endpoint: FAILED" in out
    assert (
        "Exiting with code 1 because the Skylos Cloud quality gate failed (--gate)."
        in out
    )
    assert "reasons above" not in out
    assert "app.py" in out


def test_cloud_scan_with_gate_and_a_passed_gate_never_runs_the_local_gate(
    monkeypatch, capsys, tmp_path
):
    _cloud_scan(monkeypatch, tmp_path, _response(True), command=["cloud", "--gate"])
    monkeypatch.setattr(cli, "run_gate_interaction", _no_scan)

    assert _main_exit() == 0
    assert "✓ Quality gate on feat/add-endpoint: PASSED" in capsys.readouterr().out


def test_plain_upload_keeps_todays_receipt(monkeypatch, capsys, tmp_path):
    calls = _cloud_scan(monkeypatch, tmp_path, _response(False), command=[])
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", str(tmp_path), "--upload", "--no-clipboard"]
    )

    assert _main_exit() == 0

    out = capsys.readouterr().out
    assert calls and calls[0].get("quiet", False) is False
    assert "· Overview: https://skylos.dev/dashboard/projects/proj-1?branch=" in out
    assert "Uploading 1 cloud scan." in out
    assert "Uploading findings to Skylos Cloud" not in out
    assert "Open: " not in out


def test_local_scan_with_findings_ends_with_one_next_block(
    monkeypatch, capsys, tmp_path
):
    _configure(monkeypatch, tmp_path, "rich")
    monkeypatch.setattr(cli, "_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_is_ci", lambda: False)

    assert _main_exit() == 0

    out = capsys.readouterr().out
    assert "Next: skylos cloud" in out
    assert "skylos cicd init  check every pull request in CI" in out
    assert "skylos . --upload" not in out
    assert "Set up CI/CD" not in out
    assert "Not uploaded: this scan stayed on your machine." not in out
