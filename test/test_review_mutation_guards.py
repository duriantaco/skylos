from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

import pytest

import skylos.cli as cli
from skylos.commands import clean_cmd, review_cmd


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _reviewed_dead_code_repo(tmp_path: Path, monkeypatch) -> tuple[Path, Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    source = repo / "app.py"
    original = "def reviewed_orphan():\n    return 1\n"
    source.write_text(original, encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(
        repo,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )

    cloud_cache = tmp_path / "reviewed-findings"
    local_cache = tmp_path / "local-review-decisions"
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else cloud_cache
        ),
    )
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "_local_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else local_cache
        ),
    )
    for key in (
        "CI",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB",
        "CI_PIPELINE_ID",
        "BUILD_BUILDID",
        "CIRCLE_WORKFLOW_ID",
        "BUILD_TAG",
    ):
        monkeypatch.delenv(key, raising=False)

    def choose_dead(_console, findings, _input_fn):
        return next(
            finding
            for finding in findings
            if finding.get("_review_category") == "DEAD_CODE"
            and finding.get("symbol") == "reviewed_orphan"
        )

    monkeypatch.setattr(review_cmd, "_choose_finding", choose_dead)
    answers = iter(["1", "registered runtime callback"])
    assert (
        review_cmd.run_review_command(
            [str(repo)],
            input_fn=lambda _prompt: next(answers),
            environ={},
        )
        == 0
    )
    return repo, source, original


@pytest.mark.parametrize("comment_out", [False, True])
def test_clean_never_edits_a_reviewed_dead_finding(
    tmp_path,
    monkeypatch,
    comment_out,
):
    repo, source, original = _reviewed_dead_code_repo(tmp_path, monkeypatch)
    analyze_calls = []
    real_analyze = clean_cmd.run_analyze

    def capture_analyze(*args, **kwargs):
        analyze_calls.append(kwargs)
        return real_analyze(*args, **kwargs)

    monkeypatch.setattr(clean_cmd, "run_analyze", capture_analyze)
    args = [str(repo), "--apply", "--confidence", "60"]
    if comment_out:
        args.append("--comment-out")

    with (
        patch(
            "skylos.commands.clean_cmd.remove_unused_function_cst",
            side_effect=AssertionError("reviewed function must not be removed"),
        ),
        patch(
            "skylos.commands.clean_cmd.comment_out_unused_function_cst",
            side_effect=AssertionError("reviewed function must not be commented"),
        ),
    ):
        assert clean_cmd.run_clean_command(args) == 0

    assert analyze_calls[0]["include_review_proofs"] is True
    assert source.read_text(encoding="utf-8") == original
    assert _git(repo, "status", "--porcelain") == ""


@pytest.mark.parametrize("mutation_flag", ["--apply", "--pr"])
def test_agent_verify_never_edits_or_commits_a_reviewed_dead_finding(
    tmp_path,
    monkeypatch,
    mutation_flag,
):
    repo, source, original = _reviewed_dead_code_repo(tmp_path, monkeypatch)
    before_head = _git(repo, "rev-parse", "HEAD")
    before_branch = _git(repo, "branch", "--show-current")

    from skylos.analyzer import analyze as real_analyze

    analyze_calls = []

    def capture_analyze(*args, **kwargs):
        analyze_calls.append(kwargs)
        return real_analyze(*args, **kwargs)

    monkeypatch.setattr("skylos.analyzer.analyze", capture_analyze)
    monkeypatch.setattr(
        cli,
        "resolve_llm_runtime",
        lambda **_kwargs: ("openai", "fake-key", None, False),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            "agent",
            "verify",
            str(repo),
            "--fix",
            mutation_flag,
        ],
    )

    with patch(
        "skylos.llm.harness.run_verification_harness",
        side_effect=AssertionError("reviewed finding must not reach verification"),
    ):
        with pytest.raises(SystemExit) as exc:
            cli.main()

    assert exc.value.code == 0
    assert analyze_calls[0]["include_review_proofs"] is True
    assert source.read_text(encoding="utf-8") == original
    assert _git(repo, "rev-parse", "HEAD") == before_head
    assert _git(repo, "branch", "--show-current") == before_branch
    assert _git(repo, "status", "--porcelain") == ""


def test_agent_verify_cannot_rediscover_a_reviewed_definition_for_a_fix(
    tmp_path,
    monkeypatch,
):
    from skylos.commands import agent_verify_cmd

    reviewed_file = tmp_path / "reviewed.py"
    active_file = tmp_path / "active.py"
    reviewed_file.write_text("def reviewed():\n    return 1\n", encoding="utf-8")
    active_file.write_text("def active():\n    return 2\n", encoding="utf-8")
    reviewed = {
        "name": "reviewed",
        "full_name": "reviewed.reviewed",
        "file": str(reviewed_file),
        "line": 1,
        "category": "DEAD_CODE",
        "_llm_verdict": "TRUE_POSITIVE",
    }
    active = {
        "name": "active",
        "full_name": "active.active",
        "file": str(active_file),
        "line": 1,
        "confidence": 100,
        "_llm_verdict": "TRUE_POSITIVE",
    }
    projected = {
        "unused_functions": [active],
        "reviewed_findings": [reviewed],
        "definitions": {
            "reviewed.reviewed": {
                "file": str(reviewed_file),
                "line": 1,
                "type": "function",
                "heuristic_refs": {"callback": 0.5},
            },
            "active.active": {
                "file": str(active_file),
                "line": 1,
                "type": "function",
            },
        },
    }
    seen_defs = {}

    def verify(_args, _path, *, findings, defs_map, **_kwargs):
        assert findings == [active]
        seen_defs.update(defs_map)
        return {
            "verified_findings": [reviewed, active],
            "new_dead_code": [],
            "entry_points": [],
            "stats": {
                "total_findings": 2,
                "verified_true_positive": 2,
                "verified_false_positive": 0,
                "uncertain": 0,
                "entry_points_discovered": 0,
                "survivors_challenged": 0,
                "survivors_reclassified_dead": 0,
                "llm_calls": 1,
                "elapsed_seconds": 0.1,
            },
        }

    generated = []

    def generate(_args, _defs_map, findings, _project_root):
        generated.extend(findings)
        return []

    args = SimpleNamespace(
        path=str(tmp_path),
        conf=60,
        format="table",
        fix=True,
        apply=True,
        pr=False,
    )
    with (
        patch.object(
            agent_verify_cmd,
            "_run_static_dead_code_scan",
            return_value={"unused_functions": [active]},
        ) as scan,
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(True, True),
        ),
        patch(
            "skylos.core.review_decisions.apply_trusted_review_decisions",
            return_value=projected,
        ),
        patch.object(agent_verify_cmd, "_run_verification_harness", verify),
        patch.object(agent_verify_cmd, "_generate_verify_patches", generate),
    ):
        assert (
            agent_verify_cmd.run_agent_verify_command(
                args,
                Mock(),
                model="test-model",
                api_key=None,
                provider=None,
                base_url=None,
                exclude_folders=[],
                upload_agent_run=Mock(),
            )
            == 0
        )

    assert scan.call_args.kwargs["include_review_proofs"] is True
    assert "reviewed.reviewed" not in seen_defs
    assert "active.active" in seen_defs
    assert generated == [active]
