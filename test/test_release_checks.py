import json
import sys

import pytest

from tools.release.check_release_checks import (
    REQUIRED_CHECKS,
    check_release_checks,
    main,
)


def _run(name, run_id, status="completed", conclusion="success", app="github-actions"):
    return {
        "id": run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "app": {"slug": app},
    }


def test_release_checks_require_every_current_github_actions_job():
    runs = [_run(name, index) for index, name in enumerate(REQUIRED_CHECKS, 1)]

    assert check_release_checks({"check_runs": runs}) == ([], [])
    assert check_release_checks({"check_runs": runs[1:]}) == ([], ["test: missing"])


def test_release_checks_wait_for_current_test_rerun_instead_of_old_success():
    runs = [_run(name, index) for index, name in enumerate(REQUIRED_CHECKS, 1)]
    runs.append(_run("test", 100, status="in_progress", conclusion=None))

    assert check_release_checks({"check_runs": runs}) == ([], ["test: in_progress"])

    runs[-1] = _run("test", 100, conclusion="failure")
    assert check_release_checks({"check_runs": runs}) == (["test: failure"], [])


def test_release_checks_ignore_third_party_success_with_same_name():
    runs = [_run(name, index) for index, name in enumerate(REQUIRED_CHECKS, 1)]
    runs[0] = _run("test", 100, app="third-party")

    assert check_release_checks({"check_runs": runs}) == ([], ["test: missing"])


@pytest.mark.parametrize(
    ("test_status", "test_conclusion", "expected_code"),
    [
        ("completed", "success", 0),
        ("in_progress", None, 2),
        ("completed", "failure", 1),
    ],
)
def test_release_check_cli_exit_codes(
    tmp_path, monkeypatch, test_status, test_conclusion, expected_code
):
    runs = [_run(name, index) for index, name in enumerate(REQUIRED_CHECKS, 1)]
    runs[0] = _run("test", 100, test_status, test_conclusion)
    response = tmp_path / "check-runs.json"
    response.write_text(json.dumps({"check_runs": runs}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_release_checks.py", str(response)])

    assert main() == expected_code


def test_release_checks_fail_closed_on_invalid_api_response(tmp_path, monkeypatch, capsys):
    response = tmp_path / "check-runs.json"
    response.write_text(json.dumps({"check_runs": "invalid"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_release_checks.py", str(response)])

    assert main() == 3
    assert "Invalid release check data" in capsys.readouterr().err
