"""The post-edit hook runs the project's type checker only when the base
commit's ``[tool.skylos.done]`` asks for it, inside a hard budget, and never
turns a check that could not finish into a pass."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from skylos.commands.hook_cmd import HookDeps, run_hook_command, run_recheck


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
            "HOME": str(root),
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
    )


def _repo(tmp_path: Path, done_table: str) -> Path:
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".skylos/\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(done_table, encoding="utf-8")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "other.py").write_text("other = 2\n", encoding="utf-8")
    _git(tmp_path, "add", ".gitignore", "pyproject.toml", "app.py", "lib/other.py")
    _git(tmp_path, "commit", "-qm", "initial")
    (tmp_path / "app.py").write_text(
        "value = 1\nresult: str = value\n", encoding="utf-8"
    )
    return tmp_path


class FakeTypeCheck:
    def __init__(self, report=None, error=None):
        self.report = report
        self.error = error
        self.calls = []

    def __call__(self, root, **kwargs):
        self.calls.append((root, kwargs))
        if self.error is not None:
            raise self.error
        return self.report


def _report(*diagnostics, complete=True, summary="Type check passed"):
    status = "complete"
    if not complete:
        status = "incomplete"
    return {
        "complete": complete,
        "status": "fail" if diagnostics else "pass",
        "checker": "mypy",
        "summary": summary,
        "seconds": 0.4,
        "comparison": {"status": status},
        "diagnostics": list(diagnostics),
    }


def _diag(file, line, origin, code="assignment", message="Incompatible types", **extra):
    return {
        "file": file,
        "line": line,
        "column": 1,
        "code": code,
        "message": message,
        "severity": "error",
        "origin": origin,
        **extra,
    }


def _post_edit(root: Path, type_check):
    payload = {
        "cwd": str(root),
        "session_id": "session-1",
        "tool_name": "Write",
        "tool_input": {"file_path": str(root / "app.py")},
    }
    deps = HookDeps(
        verify=lambda target, **kwargs: {"status": "pass", "findings": []},
        type_check=type_check,
    )
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    code = run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    return code, json.loads(text) if text else None


def _context(out) -> str:
    return out["hookSpecificOutput"]["additionalContext"]


BLOCK = '[tool.skylos.done]\n[tool.skylos.done.checks]\ntype_check = "block"\n'
ADVISE = '[tool.skylos.done]\n[tool.skylos.done.checks]\ntype_check = "advise"\n'


def test_type_check_off_never_runs_the_checker(tmp_path):
    root = _repo(tmp_path, "[tool.skylos.done]\nmax_stop_blocks = 2\n")
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    code, out = _post_edit(root, fake)

    assert (code, out) == (0, None)
    assert fake.calls == []


def test_introduced_error_blocks_with_the_checker_line(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    code, out = _post_edit(root, fake)

    assert code == 0
    assert out["decision"] == "block"
    assert "Skylos found 1 issue(s)" in out["reason"]
    assert (
        "app.py:2 type-check:assignment [introduced] Incompatible types"
        in out["reason"]
    )
    assert "hook recheck app.py" in out["reason"]
    assert "--type-check" not in out["reason"]
    _, kwargs = fake.calls[0]
    assert kwargs["timeout_seconds"] == 60
    assert kwargs["checker"] == "auto"
    assert kwargs["target_files"] == [str((root / "app.py").resolve())]


def test_preexisting_errors_are_notes_not_blocks(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("lib/other.py", 1, "preexisting")))

    code, out = _post_edit(root, fake)

    assert code == 0
    assert "decision" not in out
    assert "[preexisting] Incompatible types" in _context(out)


def test_incomplete_check_is_a_visible_note_never_a_pass(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(complete=False, summary="mypy is not installed"))

    code, out = _post_edit(root, fake)

    assert code == 0
    assert "decision" not in out
    assert "Type check incomplete (mypy is not installed)" in _context(out)
    assert "runs again when you stop" in _context(out)


def test_advise_mode_reports_introduced_errors_as_notes(tmp_path):
    root = _repo(tmp_path, ADVISE)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    code, out = _post_edit(root, fake)

    assert code == 0
    assert "decision" not in out
    assert "[introduced] Incompatible types" in _context(out)


def test_broken_unchanged_caller_blocks_and_is_named(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(
        _report(
            _diag(
                "lib/other.py",
                7,
                "introduced",
                code="arg-type",
                scope="dependency_impact",
            )
        )
    )

    _, out = _post_edit(root, fake)

    assert out["decision"] == "block"
    assert "lib/other.py:7 type-check:arg-type [introduced]" in out["reason"]
    assert "(in a file this edit affects)" in out["reason"]


def test_unclassified_errors_block_in_block_mode(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "unclassified")))

    _, out = _post_edit(root, fake)

    assert out["decision"] == "block"
    assert "[unclassified]" in out["reason"]


def test_checker_failure_is_a_note_and_never_blocks(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(error=RuntimeError("boom"))

    code, out = _post_edit(root, fake)

    assert code == 0
    assert "decision" not in out
    assert "could not run (RuntimeError)" in _context(out)
    assert "boom" not in _context(out)


def test_configured_timeout_lower_than_the_post_edit_budget_wins(tmp_path):
    root = _repo(
        tmp_path,
        "[tool.skylos.done]\ntype_check_timeout_seconds = 20\n"
        '[tool.skylos.done.checks]\ntype_check = "block"\n',
    )
    fake = FakeTypeCheck(_report())

    _post_edit(root, fake)

    assert fake.calls[0][1]["timeout_seconds"] == 20


def test_warnings_do_not_block(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced", severity="warning")))

    code, out = _post_edit(root, fake)

    assert (code, out) == (0, None)


@pytest.mark.parametrize("table", ["[tool.skylos.done]\n", BLOCK])
def test_type_check_result_is_recorded_in_the_hook_log(tmp_path, table):
    root = _repo(tmp_path, table)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    _post_edit(root, fake)

    entries = [
        json.loads(line)
        for line in (root / ".skylos" / "hook.log").read_text().splitlines()
    ]
    recorded = entries[-1].get("type_check")
    if table == BLOCK:
        assert recorded["mode"] == "block"
        assert recorded["introduced"] == 1
    else:
        assert recorded is None


def _recheck(root: Path, type_check, *arguments: str, monkeypatch):
    monkeypatch.chdir(root)
    deps = HookDeps(
        verify=lambda target, **kwargs: {"status": "pass", "findings": []},
        type_check=type_check,
    )
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    code = run_recheck(list(arguments), stdout=stdout, deps=deps)
    return code, stdout.getvalue()


def test_recheck_reports_an_open_type_error_instead_of_an_all_clear(
    tmp_path, monkeypatch
):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))
    _post_edit(root, fake)

    code, text = _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert code == 1
    assert "app.py:2 type-check:assignment [introduced]" in text
    assert "will not block" not in text


def test_recheck_is_clean_once_the_type_error_is_fixed(tmp_path, monkeypatch):
    root = _repo(tmp_path, BLOCK)
    _post_edit(root, FakeTypeCheck(_report(_diag("app.py", 2, "introduced"))))

    code, text = _recheck(
        root, FakeTypeCheck(_report()), "app.py", monkeypatch=monkeypatch
    )

    assert code == 0
    assert "no blocking issues in 1 file(s)" in text
    assert "will not block" in text


def test_recheck_never_calls_an_unfinished_check_clean(tmp_path, monkeypatch):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(complete=False, summary="mypy is not installed"))

    code, text = _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert code == 0
    assert "Type check incomplete (mypy is not installed)" in text
    assert "will not block" not in text


def test_recheck_with_type_check_off_never_runs_the_checker(tmp_path, monkeypatch):
    root = _repo(tmp_path, "[tool.skylos.done]\nmax_stop_blocks = 2\n")
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    code, text = _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert code == 0
    assert fake.calls == []
    assert "will not block" in text


def test_recheck_range_limits_type_findings(tmp_path, monkeypatch):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    outside = _recheck(root, fake, "app.py", "--range", "5:6", monkeypatch=monkeypatch)
    inside = _recheck(root, fake, "app.py", "--range", "2:2", monkeypatch=monkeypatch)

    assert outside[0] == 0
    assert inside[0] == 1


def test_recheck_session_checks_the_whole_project_with_no_recorded_files(
    tmp_path, monkeypatch
):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("lib/other.py", 1, "introduced")))

    code, text = _recheck(root, fake, "--session", monkeypatch=monkeypatch)

    assert code == 1
    assert "lib/other.py:1 type-check:assignment" in text
    assert fake.calls[0][1]["target_files"] is None


def test_recheck_compares_against_the_session_baseline_not_a_later_commit(
    tmp_path, monkeypatch
):
    root = _repo(tmp_path, BLOCK)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _post_edit(root, FakeTypeCheck(_report()))
    _git(root, "add", "app.py")
    _git(root, "commit", "-qm", "agent commit")
    fake = FakeTypeCheck(_report())

    _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert fake.calls[0][1]["comparison"].base_sha == base


def test_block_from_an_unchanged_caller_does_not_claim_the_lines_were_changed(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(
        _report(_diag("lib/other.py", 7, "introduced", scope="dependency_impact"))
    )

    _, out = _post_edit(root, fake)

    assert "lines you just changed" not in out["reason"]
    assert "from this edit" in out["reason"]
    assert "hook recheck lib/other.py" in out["reason"]


def test_a_bare_any_warning_reaches_the_agent_as_a_note(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(
        _report(
            _diag(
                "app.py",
                2,
                "introduced",
                code="type-widening",
                message="New bare Any annotation",
                severity="warning",
                source="suppression_guard",
            )
        )
    )

    _, out = _post_edit(root, fake)

    assert "decision" not in out
    assert "New bare Any annotation" in _context(out)


def test_a_checker_warning_still_stays_out_of_the_agent_notes(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced", severity="warning")))

    assert _post_edit(root, fake) == (0, None)


def _slow(*diagnostics, seconds=20.0):
    report = _report(*diagnostics)
    report["seconds"] = seconds
    return report


def test_a_slow_check_still_reports_then_moves_to_stop_for_the_session(tmp_path):
    root = _repo(tmp_path, BLOCK)
    first = FakeTypeCheck(_slow(_diag("app.py", 2, "introduced")))

    _, out = _post_edit(root, first)

    assert out["decision"] == "block"
    assert "runs when you stop" in out["reason"]

    second = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))
    code, again = _post_edit(root, second)

    assert (code, again) == (0, None)
    assert second.calls == []


def test_a_timed_out_check_moves_to_stop_and_says_so_once(tmp_path):
    root = _repo(tmp_path, BLOCK)
    first = FakeTypeCheck(_slow(seconds=60.0))
    first.report.update(complete=False, summary="mypy exceeded its time budget")
    first.report["comparison"] = {"status": "incomplete"}

    _, out = _post_edit(root, first)

    assert "exceeded its time budget" in _context(out)
    assert "runs when you stop" in _context(out)
    assert _post_edit(root, FakeTypeCheck(_report())) == (0, None)


def test_a_fast_check_keeps_running_on_every_edit(tmp_path):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_slow(seconds=14.9))

    _post_edit(root, fake)
    _post_edit(root, fake)

    assert len(fake.calls) == 2


def test_recheck_still_runs_the_checker_after_the_session_moved_it_to_stop(
    tmp_path, monkeypatch
):
    root = _repo(tmp_path, BLOCK)
    _post_edit(root, FakeTypeCheck(_slow()))
    fake = FakeTypeCheck(_report(_diag("app.py", 2, "introduced")))

    code, _ = _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert code == 1
    assert len(fake.calls) == 1


def test_per_edit_checks_may_reuse_the_baseline(tmp_path, monkeypatch):
    root = _repo(tmp_path, BLOCK)
    fake = FakeTypeCheck(_report())

    _post_edit(root, fake)
    _recheck(root, fake, "app.py", monkeypatch=monkeypatch)

    assert [call[1]["baseline_cache"] for call in fake.calls] == [True, True]
