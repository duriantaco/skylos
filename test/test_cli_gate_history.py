"""After an upload the gate line names the branch and how it moved since the last run."""

import json
import os
import time
from unittest.mock import Mock

import pytest

import skylos.api as api
import skylos.cli as cli
from skylos.cloud.gate_status import (
    clean_previous_gate,
    details_url,
    format_gate_time,
    formatted_gate_line,
    gate_context,
)
from skylos.commands.scan_cmd import _public_upload_receipt
from test.test_cli_report_serialization import _configure, _report

BASE = "https://skylos.dev"
COMMIT = "abc1234def5678901234567890abcdef12345678"
PREVIOUS_TIME = "2026-10-21T14:05:00.123456+00:00"
DESTINATION = {
    "project_id": "proj-1",
    "branch": "main",
    "default_branch": "main",
    "default_branch_source": "repository",
    "pr_number": None,
}
PROJECT_SCAN_URL = f"{BASE}/dashboard/projects/proj-1/scans/scan-1"


@pytest.fixture(autouse=True)
def cloud_base(monkeypatch):
    monkeypatch.setattr(api, "BASE_URL", BASE)


@pytest.fixture
def machine_zone_not_utc():
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is unavailable on this platform")
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "Asia/Singapore"
    time.tzset()
    yield
    if saved is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = saved
    time.tzset()


def _previous(passed, overridden=False, created_at=PREVIOUS_TIME, commit=COMMIT):
    return {
        "scan_id": "scan-0",
        "created_at": created_at,
        "commit": commit,
        "passed": passed,
        "overridden": overridden,
    }


def _body(gate, **extra):
    return {"scanId": "scan-1", "plan": "pro", "quality_gate": gate, **extra}


def _finalize(capsys, body, **kwargs):
    response = Mock(status_code=200, headers={})
    response.json.return_value = body
    result = api._finalize_report_upload(response, grade_data=None, **kwargs)
    return result, capsys.readouterr().out


PASS = {"passed": True, "new_violations": 0, "message": "Quality Gate Passed."}
FAIL = {
    "passed": False,
    "new_violations": 2,
    "message": "Quality Gate Failed! 1 critical security issue; 1 new exposed secret.",
}


@pytest.mark.parametrize(
    "gate,previous,expected",
    [
        (
            PASS,
            _previous(False),
            "✅ PASS Quality gate on main: PASSED (was FAILED on 21 Oct 14:05 UTC, abc1234)",
        ),
        (
            FAIL,
            _previous(True),
            "❌ FAIL Quality gate on main: FAILED (was PASSED on 21 Oct 14:05 UTC, abc1234) because of",
        ),
        (
            PASS,
            _previous(True),
            "✅ PASS Quality gate on main: PASSED (same as last run on 21 Oct 14:05 UTC, abc1234)",
        ),
        (
            {"passed": False, "new_violations": 2},
            _previous(False),
            "❌ FAIL Quality gate on main: FAILED (2 new issues; same as last run on 21 Oct 14:05 UTC, abc1234)",
        ),
        (
            PASS,
            None,
            "✅ PASS Quality gate on main: PASSED (first result on this branch)",
        ),
        (
            FAIL,
            _previous(False, overridden=True),
            "❌ FAIL Quality gate on main: FAILED (was OVERRIDDEN on 21 Oct 14:05 UTC, abc1234) because of",
        ),
        (PASS, _previous(None), "✅ PASS Quality gate on main: PASSED\n"),
        (PASS, "not-a-dict", "✅ PASS Quality gate on main: PASSED\n"),
    ],
)
def test_rich_gate_line_says_how_the_gate_moved(
    capsys, machine_zone_not_utc, gate, previous, expected
):
    result, out = _finalize(
        capsys, _body(gate, destination=DESTINATION, previous_gate=previous)
    )
    assert expected in out
    assert f"🔗 View details: {PROJECT_SCAN_URL}\n" in out
    assert out.count("/scans/scan-1") == 1
    assert "View the scan" not in out
    assert result["quality_gate_passed"] is gate["passed"]


def test_failed_gate_keeps_its_reason_bullets(capsys, machine_zone_not_utc):
    _result, out = _finalize(
        capsys, _body(FAIL, destination=DESTINATION, previous_gate=_previous(True))
    )
    assert (
        "because of\n   - 1 critical security issue\n   - 1 new exposed secret\n" in out
    )


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"destination": DESTINATION},
        {"destination": "bad", "url": "https://untrusted.example/x"},
    ],
)
def test_old_cloud_without_previous_gate_prints_exactly_todays_lines(capsys, extra):
    _result, out = _finalize(capsys, _body(PASS, **extra))
    assert "✅ PASS Quality gate: PASSED\n" in out
    assert f"🔗 View the scan: {BASE}/dashboard/scans/scan-1\n" in out
    assert "was " not in out and "first result" not in out
    assert "View details" not in out and "untrusted.example" not in out


def test_old_cloud_failed_gate_lines_are_unchanged(capsys):
    _result, out = _finalize(capsys, _body({"passed": False, "new_violations": 2}))
    assert "❌ FAIL Quality gate: FAILED (2 new issues)\n" in out


def test_missing_branch_keeps_todays_gate_line_with_a_workspace_link(
    capsys, machine_zone_not_utc
):
    _result, out = _finalize(capsys, _body(PASS, previous_gate=_previous(False)))
    assert "✅ PASS Quality gate: PASSED\n" in out
    assert f"🔗 View details: {BASE}/dashboard/scans/scan-1\n" in out


def test_pull_request_scan_names_the_pr(capsys, machine_zone_not_utc):
    _result, out = _finalize(
        capsys,
        _body(
            FAIL,
            destination={**DESTINATION, "branch": "feat/x", "pr_number": 12},
            previous_gate=_previous(True),
        ),
    )
    assert "❌ FAIL Quality gate on feat/x (PR #12): FAILED (was PASSED" in out


def test_hostile_server_strings_never_reach_the_terminal(capsys):
    _result, out = _finalize(
        capsys,
        _body(
            PASS,
            destination={
                "project_id": "../../evil",
                "branch": "main\x1b[31m\nFAKE",
                "pr_number": True,
            },
            previous_gate={
                "scan_id": "x/../y",
                "created_at": "2026-10-21T14:05:00Z\n\x1b[2J",
                "commit": "abc1234\x1b[0m\nevil",
                "passed": False,
                "overridden": "yes",
            },
            url="https://untrusted.example/x",
        ),
    )
    assert "\x1b" not in out
    assert "✅ PASS Quality gate on main[31mFAKE: PASSED (was FAILED)\n" in out
    assert f"🔗 View details: {BASE}/dashboard/scans/scan-1\n" in out
    assert "evil" not in out and "untrusted.example" not in out and "PR #" not in out


def test_free_plan_advisory_lines_stay(capsys, machine_zone_not_utc):
    body = _body(
        {"passed": False, "new_violations": 1},
        destination=DESTINATION,
        previous_gate=_previous(True),
    )
    body["plan"] = "free"
    _result, out = _finalize(capsys, body)
    assert "⚠️  Quality gate failed but continuing (Free plan)" in out
    assert "💡 The Workspace plan blocks commits and CI on a failed gate" in out


@pytest.mark.parametrize("previous", [_previous(True), None])
def test_strict_gate_exit_is_unchanged(capsys, previous):
    with pytest.raises(SystemExit) as exc:
        _finalize(
            capsys,
            _body(FAIL, destination=DESTINATION, previous_gate=previous),
            strict=True,
        )
    assert exc.value.code == 1
    assert "Commit blocked by quality gate" in capsys.readouterr().out


def test_quiet_upload_prints_nothing_and_keeps_a_clean_previous_gate(capsys):
    result, out = _finalize(
        capsys,
        _body(
            PASS,
            destination={**DESTINATION, "pr_number": 7},
            previous_gate={**_previous(False), "extra": "dropped", "commit": "zzz"},
        ),
        quiet=True,
    )
    assert out == ""
    assert result["previous_gate"] == {
        "scan_id": "scan-0",
        "created_at": PREVIOUS_TIME,
        "commit": None,
        "passed": False,
        "overridden": False,
    }
    assert result["destination"]["pr_number"] == 7


def test_result_has_no_previous_gate_when_cloud_does_not_send_it(capsys):
    result, _out = _finalize(capsys, _body(PASS), quiet=True)
    assert "previous_gate" not in result
    assert "pr_number" not in result.get("destination", {})


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-21T14:05:00",
        "2026-10-21 14:05:00Z",
        "2026-10-21T14:05:00.12+00:00",
        "2026-10-21T22:05+08:00",
        "2026-10-21T09:05:00-05:00",
    ],
)
def test_iso_times_print_in_utc_whatever_the_machine_zone(machine_zone_not_utc, value):
    assert format_gate_time(value) == "21 Oct 14:05 UTC"


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        "",
        "yesterday",
        "2026-13-01T00:00:00Z",
        "2026-10-21T14:05:00+99:00",
        "２０２６-10-21T14:05:00Z",
        "2026-10-21T14:05:00Z" + " " * 60,
    ],
)
def test_unparseable_times_are_dropped(value):
    assert format_gate_time(value) is None
    assert clean_previous_gate({"created_at": value})["created_at"] is None


@pytest.mark.parametrize(
    "commit,kept",
    [
        (COMMIT, COMMIT),
        ("abc1234", "abc1234"),
        ("abc123", None),
        ("g" * 40, None),
        ("a" * 65, None),
        (12345678, None),
    ],
)
def test_only_hex_commits_are_kept(commit, kept):
    assert clean_previous_gate({"commit": commit})["commit"] == kept


def test_details_link_uses_validated_ids_only():
    assert details_url(BASE + "/", "proj-1", "scan-1") == PROJECT_SCAN_URL
    assert details_url(BASE, "../x", "scan-1") == f"{BASE}/dashboard/scans/scan-1"
    assert details_url(BASE, "proj-1", "a/../b") is None
    assert details_url(BASE, None, None) is None


def test_formatted_line_needs_a_reported_gate_and_previous_gate(machine_zone_not_utc):
    result = {
        "success": True,
        "scan_id": "scan-1",
        "quality_gate_passed": False,
        "quality_gate_reported": True,
        "destination": DESTINATION,
        "previous_gate": _previous(True),
    }
    assert formatted_gate_line(result, BASE) == (
        "Quality gate on main: FAILED (was PASSED on 21 Oct 14:05 UTC, abc1234)"
        f" — View details: {PROJECT_SCAN_URL}"
    )
    assert formatted_gate_line({**result, "quality_gate_reported": False}, BASE) is None
    assert formatted_gate_line({**result, "quality_gate_passed": None}, BASE) is None
    without = dict(result)
    without.pop("previous_gate")
    assert formatted_gate_line(without, BASE) is None
    assert gate_context(without, BASE) is None


def test_public_receipt_copies_a_clean_previous_gate_only_when_sent():
    response = {
        "success": True,
        "scan_id": "scan-1",
        "quality_gate_passed": True,
        "previous_gate": {**_previous(False), "scan_id": "../x", "token": "secret"},
    }
    receipt = _public_upload_receipt(response)
    assert receipt["previous_gate"] == {**_previous(False), "scan_id": None}
    assert (
        _public_upload_receipt({**response, "previous_gate": None})["previous_gate"]
        is None
    )
    response.pop("previous_gate")
    assert "previous_gate" not in _public_upload_receipt(response)
    assert "previous_gate" not in _public_upload_receipt(
        {"success": False, "previous_gate": _previous(True)}
    )


def _formatted_gate_scan(monkeypatch, tmp_path, *, gate=True):
    _configure(monkeypatch, tmp_path, "json", upload=True)
    if gate:
        monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--gate"])
    result = _report()
    result["unused_functions"] = []
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))


def _run_exit():
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


@pytest.mark.parametrize("passed,exit_code", [(True, 0), (False, 1)])
def test_json_upload_prints_gate_history_on_stderr_and_keeps_stdout_json(
    monkeypatch, capsys, tmp_path, machine_zone_not_utc, passed, exit_code
):
    _formatted_gate_scan(monkeypatch, tmp_path)
    response = {
        "success": True,
        "scan_id": "scan-1",
        "quality_gate_passed": passed,
        "quality_gate_reported": True,
        "quality_gate": {"passed": passed},
        "destination": DESTINATION,
        "previous_gate": _previous(not passed),
        "url": "https://untrusted.example/ignored",
    }
    monkeypatch.setattr(cli, "upload_report", Mock(return_value=response))

    assert _run_exit() == exit_code
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    word = "FAILED"
    was = "PASSED"
    if passed:
        word = "PASSED"
        was = "FAILED"
    assert (
        f"Quality gate on main: {word} (was {was} on 21 Oct 14:05 UTC, abc1234)"
        f" — View details: {PROJECT_SCAN_URL}\n"
    ) in captured.err
    assert captured.err.count("/scans/scan-1") == 1
    assert "View Cloud gate and results" not in captured.err
    assert payload["upload"]["previous_gate"]["passed"] is (not passed)
    assert payload["upload"]["url"] == f"{BASE}/dashboard/scans/scan-1"
    assert "untrusted.example" not in captured.out + captured.err
    if not passed:
        assert "Quality Gate: FAILED\n" in captured.err


def test_json_upload_from_old_cloud_keeps_the_existing_link_line(
    monkeypatch, capsys, tmp_path
):
    _formatted_gate_scan(monkeypatch, tmp_path, gate=False)
    response = {"success": True, "scan_id": "scan-1", "quality_gate_passed": True}
    monkeypatch.setattr(cli, "upload_report", Mock(return_value=response))

    assert _run_exit() == 0
    captured = capsys.readouterr()
    assert captured.err.splitlines()[0] == (
        f"View Cloud gate and results: {BASE}/dashboard/scans/scan-1"
    )
    assert "previous_gate" not in json.loads(captured.out)["upload"]
    assert "Quality gate on" not in captured.err


@pytest.mark.parametrize(
    "trusted,suffix",
    [(False, ", unverified upload"), (True, ""), (None, ""), ("false", ""), (0, "")],
)
def test_unverified_previous_run_is_named_in_the_history(
    capsys, machine_zone_not_utc, trusted, suffix
):
    previous = _previous(True)
    if trusted is not None:
        previous["trusted"] = trusted
    result, out = _finalize(
        capsys, _body(FAIL, destination=DESTINATION, previous_gate=previous)
    )
    assert (
        "❌ FAIL Quality gate on main: FAILED "
        f"(was PASSED on 21 Oct 14:05 UTC, abc1234{suffix}) because of\n"
    ) in out
    if isinstance(trusted, bool):
        assert result["previous_gate"]["trusted"] is trusted
    else:
        assert "trusted" not in result["previous_gate"]


def test_unverified_previous_run_is_named_for_every_history_state(machine_zone_not_utc):
    from skylos.cloud.gate_status import history_text

    base = {
        "scan_id": "scan-0",
        "created_at": PREVIOUS_TIME,
        "commit": None,
        "trusted": False,
    }
    assert (
        history_text(True, {**base, "passed": True, "overridden": False})
        == "same as last run on 21 Oct 14:05 UTC, unverified upload"
    )
    assert (
        history_text(True, {**base, "passed": False, "overridden": True})
        == "was OVERRIDDEN on 21 Oct 14:05 UTC, unverified upload"
    )
    assert history_text(True, {**base, "passed": None, "overridden": False}) is None


def test_public_receipt_keeps_only_a_boolean_trusted_flag():
    response = {"success": True, "scan_id": "scan-1", "quality_gate_passed": True}
    for trusted, expected in ((False, False), (True, True)):
        receipt = _public_upload_receipt(
            {**response, "previous_gate": {**_previous(True), "trusted": trusted}}
        )
        assert receipt["previous_gate"]["trusted"] is expected
    for value in ("false", 1, None):
        receipt = _public_upload_receipt(
            {**response, "previous_gate": {**_previous(True), "trusted": value}}
        )
        assert "trusted" not in receipt["previous_gate"]


def _upload_destination_text(monkeypatch, tmp_path, destination):
    from rich.console import Console

    monkeypatch.setenv("SKYLOS_TOKEN", "local-test-key")
    console = Console(record=True, width=400, theme=cli._skylos_console_theme())
    cli._print_upload_destination(console, tmp_path, destination)
    return console.export_text()


def test_upload_contents_line_follows_the_destination_block(monkeypatch, tmp_path):
    from skylos.cloud.upload_destination import UploadDestination

    destination = UploadDestination(
        key_source="env", project_id="proj-1", project_name="demo", branch="main"
    )
    text = _upload_destination_text(monkeypatch, tmp_path, destination)

    assert text.count("Sends:") == 1
    assert text.index("Branch:") < text.index("Sends:")
    assert "(none for secrets)" in text
    assert "git author email of each flagged line" in text
    assert "Not your repository." in text


def test_upload_contents_line_without_a_resolved_destination(monkeypatch, tmp_path):
    text = _upload_destination_text(monkeypatch, tmp_path, None)

    assert "Auto-uploading: SKYLOS_TOKEN" in text
    assert text.count("Sends:") == 1
    assert "Not your repository." in text
