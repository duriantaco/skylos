"""Manual Done failures cannot expose a stale success as the latest receipt."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from skylos.commands import done_cmd
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import DoneError, open_comparison
from skylos.done.checks import CheckResult
from skylos.done.config import DoneConfig
from skylos.done.engine import CheckOutcome, DoneResult
from skylos.done.receipt import build_receipt, read_receipt, write_receipt


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Receipt test",
            "-c",
            "user.email=test@example.com",
            *arguments,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _write(root: Path, relative: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / relative
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


def _result(root: Path, *, status="pass") -> DoneResult:
    check = CheckResult(
        id="tests_pass",
        rule="SKY-A113",
        status=status,
        summary="Test verification result",
        evidence={"summary": "Test verification result"},
    )
    return DoneResult(
        open_comparison(root),
        DoneConfig(),
        [CheckOutcome("block", check)],
        status,
        0.0,
    )


@pytest.fixture
def prior_pass(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, ".gitignore", ".skylos/\n")
    _write(root, "app.py", "value = 1\n")
    _write(root, "nested/module.py", "value = 1\n")
    _git(root, "add", ".gitignore", "app.py", "nested/module.py")
    _git(root, "commit", "-qm", "initial")
    receipt = build_receipt(_result(root))
    historical = write_receipt(root, receipt)
    assert historical is not None
    latest = root / ".skylos/receipts/latest.json"
    assert read_receipt(latest)["verdict"] == "pass"
    return root, latest, historical, historical.read_bytes()


def _assert_invalidated(prior_pass):
    _root, latest, historical, history_bytes = prior_pass
    assert read_receipt(latest) is None
    assert historical.read_bytes() == history_bytes


@pytest.mark.parametrize("nested", [False, True])
def test_invalid_base_clears_real_prior_pass_at_repository_root(
    prior_pass, capsys, nested
):
    root, *_ = prior_pass
    target = root / "nested" if nested else root
    assert (
        done_cmd.run_done_command(
            [str(target), "--base", "nonexistent-test-base", "--format", "json"]
        )
        == 2
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert "cannot find base" in output.err
    _assert_invalidated(prior_pass)
    assert done_cmd.run_done_command(["receipt", str(root), "--format", "json"]) == 2
    assert capsys.readouterr().out == ""


def test_missing_session_baseline_invalidates_prior_pass(prior_pass, capsys):
    root, *_ = prior_pass
    assert done_cmd.run_done_command([str(root), "--session", "missing-session"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "session baseline" in output.err
    _assert_invalidated(prior_pass)


@pytest.mark.parametrize("output_format", ["text", "json", "markdown"])
def test_unpublished_pass_is_not_printed_or_added_to_ci_summary(
    prior_pass, monkeypatch, capsys, output_format
):
    root, *_ = prior_pass
    result = _result(root)
    monkeypatch.setattr("skylos.done.engine.run", lambda *args, **kwargs: result)
    monkeypatch.setattr("skylos.done.receipt.write_receipt", lambda *args: None)
    summaries = []
    monkeypatch.setattr(done_cmd, "_write_step_summary", summaries.append)
    assert done_cmd.run_done_command([str(root), "--format", output_format]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "verification is unfinished" in output.err
    assert "receipt could not be saved" in output.err
    assert summaries == []
    _assert_invalidated(prior_pass)


def test_unpublished_failing_result_reports_publication_error(prior_pass, monkeypatch):
    root, *_ = prior_pass
    result = _result(root, status="fail")
    monkeypatch.setattr("skylos.done.engine.run", lambda *args, **kwargs: result)
    monkeypatch.setattr("skylos.done.receipt.write_receipt", lambda *args: None)
    assert done_cmd.run_done_command([str(root)]) == 2
    _assert_invalidated(prior_pass)


@pytest.mark.parametrize("raises", [False, True])
def test_invalidation_failure_is_explicit_and_keeps_error_exit(
    prior_pass, monkeypatch, capsys, raises
):
    root, latest, *_ = prior_pass

    def unavailable(*args, **kwargs):
        raise DoneError("Git verification is unavailable")

    def cannot_invalidate(*args):
        if raises:
            raise OSError("receipt directory is unavailable")
        return False

    monkeypatch.setattr("skylos.done.engine.run", unavailable)
    monkeypatch.setattr(
        "skylos.done.session.invalidate_latest_receipt", cannot_invalidate
    )
    assert done_cmd.run_done_command([str(root), "--format", "json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Git verification is unavailable" in output.err
    assert "could not invalidate the latest receipt" in output.err
    assert "earlier receipts do not verify this attempt" in " ".join(output.err.split())
    assert read_receipt(latest)["verdict"] == "pass"


@pytest.mark.parametrize("output_format", ["text", "json", "markdown"])
def test_successful_publication_preserves_pass_exit_and_receipt(
    prior_pass, monkeypatch, capsys, output_format
):
    root, latest, *_ = prior_pass
    result = _result(root)
    monkeypatch.setattr("skylos.done.engine.run", lambda *args, **kwargs: result)
    assert done_cmd.run_done_command([str(root), "--format", output_format]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    if output_format == "json":
        assert json.loads(output.out)["verdict"] == "pass"
    else:
        assert "PASS" in output.out
    assert read_receipt(latest)["verdict"] == "pass"


@pytest.mark.parametrize(
    "stage", ["run", "build_receipt", "validate_receipt", "write_receipt"]
)
def test_unexpected_execution_or_publication_error_invalidates_without_printing_pass(
    prior_pass, monkeypatch, capsys, stage
):
    root, *_ = prior_pass
    result = _result(root)
    monkeypatch.setattr("skylos.done.engine.run", lambda *args, **kwargs: result)
    summaries = []
    monkeypatch.setattr(done_cmd, "_write_step_summary", summaries.append)

    def unavailable(*args, **kwargs):
        raise OSError("disk full at private-test-location")

    namespace = "engine" if stage == "run" else "receipt"
    monkeypatch.setattr(f"skylos.done.{namespace}.{stage}", unavailable)
    assert done_cmd.run_done_command([str(root), "--format", "json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "verification could not complete" in output.err
    assert "private-test-location" not in output.err
    assert "Traceback" not in output.err
    assert summaries == []
    _assert_invalidated(prior_pass)


def test_invalid_receipt_contract_is_rejected_before_publication(
    prior_pass, monkeypatch, capsys
):
    root, *_ = prior_pass
    result = _result(root)
    monkeypatch.setattr("skylos.done.engine.run", lambda *args, **kwargs: result)
    malformed = build_receipt(result)
    malformed["head"]["sha"] = "invalid-head"
    monkeypatch.setattr(
        "skylos.done.receipt.build_receipt", lambda *args, **kwargs: malformed
    )
    writes = []
    summaries = []
    monkeypatch.setattr(
        "skylos.done.receipt.write_receipt", lambda *args: writes.append(args)
    )
    monkeypatch.setattr(done_cmd, "_write_step_summary", summaries.append)
    assert done_cmd.run_done_command([str(root), "--format", "json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "receipt failed validation" in output.err
    assert writes == []
    assert summaries == []
    _assert_invalidated(prior_pass)
