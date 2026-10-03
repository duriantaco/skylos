"""Full-session baselines preserve user work and cannot silently lose coverage."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import engine, receipt, session
from skylos.done.base import DoneError
from skylos.done.checks import CheckContext, CheckResult, check_gate_tampering
from skylos.done.config import parse_done_config

CONFIG = """[tool.skylos.done]
test_command = ["python", "-m", "pytest"]
[tool.skylos.done.checks]
unknown_imports = "off"
"""


def _git(root: Path, *args: str) -> str:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "commit.gpgSign=false",
            *args,
        ],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()


def _write(root: Path, name: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / name
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


@pytest.fixture
def repo(tmp_path):
    tmp_path = tmp_path / "repo"
    tmp_path.mkdir()
    _git(tmp_path, "init", "--template=", "-q")
    _write(tmp_path, "pyproject.toml", CONFIG)
    _write(tmp_path, "app.py", "VALUE = 1\n")
    _write(tmp_path, "tests/test_app.py", "def test_app():\n    assert True\n")
    _git(tmp_path, "add", "pyproject.toml", "app.py", "tests/test_app.py")
    _git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def _context(repo):
    comparison = session.open_session_comparison(repo, "qa")
    config = parse_done_config(
        comparison.base_text("pyproject.toml", sha=comparison.config_sha)
    )
    return CheckContext(comparison, config, run_tests=False)


def test_snapshot_preserves_staged_unstaged_and_agent_commits(repo):
    original_head = _git(repo, "rev-parse", "HEAD")
    _write(repo, "app.py", "VALUE = 2\n")
    _git(repo, "add", "app.py")
    _write(repo, "app.py", "VALUE = 3\n")
    index = (repo / ".git/index").read_bytes()
    first = session.capture_session(repo, "qa")
    assert (repo / ".git/index").read_bytes() == index
    assert _git(repo, "rev-parse", "HEAD") == original_head
    comparison = _context(repo).comparison
    assert comparison.base_text("app.py") == "VALUE = 3\n"
    assert not comparison.changed
    _write(repo, "app.py", "VALUE = 4\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "agent change")
    assert session.capture_session(repo, "qa") == first
    comparison = _context(repo).comparison
    assert comparison.config_sha == original_head
    diff = comparison.file_diff(comparison.changed[0])
    assert "-VALUE = 3" in diff and "+VALUE = 4" in diff


@pytest.mark.parametrize("action", ["unchanged", "modified", "deleted"])
def test_initial_untracked_tests_remain_in_both_inventories(repo, action):
    name = "tests/test_untracked.py"
    _write(repo, name, "def test_new():\n    assert True\n")
    session.capture_session(repo, "qa")
    if action == "modified":
        _write(repo, name, "def test_new():\n    assert False\n")
    elif action == "deleted":
        (repo / name).unlink()
    context = _context(repo)
    before, after = context.tests()
    assert len(before) == 2
    assert len(after) == (1 if action == "deleted" else 2)
    found = [change for change in context.comparison.changed if change.path == name]
    if action == "unchanged":
        assert not found
    else:
        assert len(found) == 1 and found[0].status == action
        if action == "modified":
            diff = context.comparison.file_diff(found[0])
            assert "-    assert True" in diff and "+    assert False" in diff


def test_staged_deletion_with_ignored_remaining_test_keeps_actual_inventory(repo):
    _git(repo, "rm", "--cached", "tests/test_app.py")
    _write(repo, ".gitignore", "/tests/test_app.py\n/ignored.txt\n")
    _write(repo, "ignored.txt", "not part of the snapshot\n")
    index = (repo / ".git/index").read_bytes()
    record = session.capture_session(repo, "qa")
    context = _context(repo)
    before, after = context.tests()
    assert len(before) == len(after) == 1
    assert not context.comparison.changed
    assert context.comparison.base_text("ignored.txt") is None
    assert (repo / ".git/index").read_bytes() == index
    assert record["source"] == "session"


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_snapshot_detects_hidden_git_edits_and_preserved_mtime(repo, flag):
    session.capture_session(repo, "qa")
    target = repo / "app.py"
    status = target.stat()
    _git(repo, "update-index", flag, "app.py")
    _write(repo, "app.py", "VALUE = 9\n")
    os.utime(target, ns=(status.st_atime_ns, status.st_mtime_ns))
    assert not _git(repo, "diff", "--name-status", "HEAD", "--", "app.py")
    comparison = _context(repo).comparison
    assert comparison.head_dirty
    assert [change.path for change in comparison.changed] == ["app.py"]
    assert "+VALUE = 9" in comparison.file_diff(comparison.changed[0])


def test_committed_policy_weakening_uses_initial_policy(repo):
    record = session.capture_session(repo, "qa")
    _write(repo, "pyproject.toml", CONFIG + 'tests_pass = "off"\n')
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "weaken policy")
    assert session.capture_session(repo, "qa") == record
    context = _context(repo)
    assert context.config.mode("tests_pass") == "block"
    assert check_gate_tampering(context).status == "fail"


def test_only_committed_policy_opts_in(repo):
    _write(repo, "pyproject.toml", '[project]\nname = "demo"\n')
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "no done policy")
    _write(repo, "pyproject.toml", CONFIG)
    assert session.capture_session(repo, "qa") is None
    assert not (repo / session.SESSION_PATH).exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("base_sha", "f" * 40),
        ("config_digest", "sha256:" + "0" * 64),
        ("tree_digest", "sha256:" + "0" * 64),
        ("repository", "/outside"),
        ("source", "unknown"),
    ],
)
def test_invalid_baseline_cannot_be_silently_recaptured(repo, key, value):
    session.capture_session(repo, "qa")
    state = json.loads((repo / session.SESSION_PATH).read_text())
    state["sessions"]["qa"]["done_base"][key] = value
    _write(repo, session.SESSION_PATH.as_posix(), json.dumps(state))
    with pytest.raises(DoneError):
        session.capture_session(repo, "qa")
    with pytest.raises(DoneError):
        session.open_session_comparison(repo, "qa")


def test_capture_failure_survives_later_successful_reads(repo, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(session, "MAX_TREE_FILES", 1)
        with pytest.raises(DoneError, match="exceeds"):
            session.capture_session(repo, "qa")
    with pytest.raises(DoneError, match="initial session capture failed"):
        session.capture_session(repo, "qa")


def test_late_capture_cannot_pass_even_with_required_checks_disabled(repo):
    _write(repo, "pyproject.toml", CONFIG + 'tests_pass = "off"\n')
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "disable tests by owner")
    session.capture_session(repo, "qa", before_edit=False)
    result = engine.run(repo, session_id="qa", run_tests=False)
    assert result.verdict == "incomplete"
    outcome = next(item for item in result.checks if item.result.id == "tests_pass")
    assert outcome.mode == "block"
    assert outcome.result.evidence["session_base"] == "head_fallback"


def test_snapshot_reads_symlink_itself_and_never_its_target(repo, tmp_path):
    outside = tmp_path / "outside.txt"
    _write(tmp_path, "outside.txt", "PRIVATE OUTSIDE BYTES\n")
    (repo / "link.txt").symlink_to(outside)
    record = session.capture_session(repo, "qa")
    assert _git(repo, "show", f"{record['base_sha']}:link.txt") == str(outside)
    assert "PRIVATE" not in _git(repo, "show", f"{record['base_sha']}:link.txt")


def test_symlink_parent_is_rejected(repo, tmp_path):
    session.capture_session(repo, "qa")
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "test_app.py", "OUTSIDE = True\n")
    (repo / "tests").rename(repo / "original_tests")
    (repo / "tests").symlink_to(outside, target_is_directory=True)
    with pytest.raises(DoneError, match="safely snapshot"):
        session.open_session_comparison(repo, "qa")
    assert (outside / "test_app.py").read_text() == "OUTSIDE = True\n"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_fifo_cannot_stall_session_verification(repo):
    session.capture_session(repo, "qa")
    (repo / "app.py").unlink()
    os.mkfifo(repo / "app.py")
    started = time.monotonic()
    with pytest.raises(DoneError, match="safely snapshot"):
        session.open_session_comparison(repo, "qa")
    assert time.monotonic() - started < 3


def test_changed_source_during_checks_refuses_a_verdict(repo, monkeypatch):
    session.capture_session(repo, "qa")

    def check(check_id, ctx):
        _write(repo, "app.py", "VALUE = 2\n")
        return CheckResult(check_id, None, "pass", "checked")

    monkeypatch.setattr(engine, "run_check", check)
    with pytest.raises(DoneError, match="changed during verification"):
        engine.run(repo, session_id="qa")


def test_required_static_failure_skips_expensive_checks(repo, monkeypatch):
    calls = []

    def check(check_id, ctx):
        calls.append(check_id)
        status = "fail" if check_id == "gate_tampering" else "pass"
        return CheckResult(check_id, None, status, "checked")

    monkeypatch.setattr(engine, "run_check", check)
    result = engine.run(repo)
    assert result.verdict == "fail"
    assert "tests_pass" not in calls
    assert "changed_lines_checked" not in calls


def test_non_pytest_command_without_junit_cannot_claim_tests_ran(repo, monkeypatch):
    _write(
        repo,
        "pyproject.toml",
        CONFIG.replace('["python", "-m", "pytest"]', '["python", "-c", "pass"]'),
    )
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "non pytest tests")
    calls = []

    def check(check_id, ctx):
        calls.append(check_id)
        return CheckResult(check_id, None, "pass", "checked")

    monkeypatch.setattr(engine, "run_check", check)
    result = engine.run(repo)
    assert result.verdict == "incomplete"
    assert "tests_pass" not in calls
    assert "junit_xml" in next(
        outcome.result.summary
        for outcome in result.checks
        if outcome.result.id == "tests_pass"
    )


def test_receipt_requires_latest_publication(repo, monkeypatch):
    value = receipt.build_receipt(engine.run(repo, run_tests=False))
    monkeypatch.setattr(receipt, "save_project_json_cache", lambda *args: False)
    assert receipt.write_receipt(repo, value) is None
    assert not (repo / ".skylos/receipts/latest.json").exists()


def test_unavailable_verification_invalidates_read_only_latest_keeps_history(repo):
    value = receipt.build_receipt(engine.run(repo, run_tests=False))
    named = receipt.write_receipt(repo, value)
    assert named is not None
    latest = repo / ".skylos/receipts/latest.json"
    latest.chmod(0o400)
    assert session.invalidate_latest_receipt(repo)
    assert receipt.read_receipt(latest) is None
    assert receipt.read_receipt(named) == value


def test_session_command_rechecks_whole_session_and_refuses_mixed_base(repo, capsys):
    from skylos.commands.done_cmd import run_done_command

    session.capture_session(repo, "qa")
    assert (
        run_done_command(
            [str(repo), "--session", "qa", "--no-tests", "--format", "json"]
        )
        == 1
    )
    value = json.loads(capsys.readouterr().out)
    assert value["base"]["source"] == "session"
    assert value["agent"]["session_id"] == "qa"
    with pytest.raises(SystemExit) as exc:
        run_done_command([str(repo), "--session", "qa", "--base", "HEAD"])
    assert exc.value.code == 2
