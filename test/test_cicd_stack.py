from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from skylos import __version__
from skylos.cicd.stack import Stack, plan_stack
from skylos.commands.done_cmd import run_done_command
from skylos.commands.stack_cmd import run_stack_command
from skylos.done.config import CHECK_IDS
from skylos.done.receipt import SCHEMA


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "--no-pager", *args],
        cwd=root,
        text=True,
    ).strip()


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


def _write(path: Path, text: str) -> None:
    path.write_text(  # skylos: ignore[SKY-D324] fixture files inside pytest's own tmp_path
        text, encoding="utf-8"
    )


def _create_stack(
    root: Path, *, broken_lower: bool = False, tests_mode: str = "block"
) -> tuple[str, str, str, str]:
    root.mkdir()
    _git(root, "init", "-q", "--template=")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "config", "user.name", "Fixture")
    _write(
        root / "pyproject.toml",
        "[tool.skylos.done]\n"
        f'test_command = [{json.dumps(sys.executable)}, "-m", "pytest"]\n'
        "verify_preexisting = false\n"
        "[tool.skylos.done.checks]\n"
        f'tests_pass = "{tests_mode}"\n'
        'unknown_imports = "off"\n'
        'branch_orphans = "off"\n'
        'changed_lines_checked = "off"\n',
    )
    _write(root / "values.py", "value = 1\n")
    _write(
        root / "test_values.py",
        "from values import value\n\ndef test_value():\n    assert value > 0\n",
    )
    base = _commit(root, "base")
    _write(root / "values.py", "value = 0\n" if broken_lower else "value = 2\n")
    first = _commit(root, "first layer")
    _git(root, "branch", "first-layer", first)
    _write(root / "values.py", "value = 3\n")
    tip = _commit(root, "second layer")
    original = _git(
        root, "commit-tree", f"{tip}^{{tree}}", "-p", base, "-m", "original"
    )
    return base, first, tip, original


def _plan_args(base: str, first: str, tip: str, *extra: str) -> list[str]:
    return ["plan", "--base", base, "--layer", first, "--layer", tip, *extra]


def _invoke(capsys, repo: Path, *args: str) -> tuple[int, dict]:
    code = run_stack_command([*args, "--path", str(repo), "--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def _verify(capsys, repo: Path, manifest: Path, receipts: Path) -> tuple[int, dict]:
    return _invoke(
        capsys,
        repo,
        "verify",
        "--manifest",
        str(manifest),
        "--receipts-dir",
        str(receipts),
    )


@pytest.mark.parametrize("broken_lower", [False, True])
def test_verifies_exact_commits_using_real_done_runs(tmp_path, capsys, broken_lower):
    repo = tmp_path / "repo"
    base, first, tip, original = _create_stack(repo, broken_lower=broken_lower)
    code, plan = _invoke(
        capsys, repo, *_plan_args(base, "first-layer", tip, "--original", original)
    )
    assert code == 0, plan
    assert plan["original"]["sha"] != tip
    manifest, receipts = tmp_path / "stack.json", tmp_path / "receipts"
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    receipts.mkdir()
    _git(repo, "branch", "-f", "first-layer", tip)
    for index, sha in enumerate((first, tip)):
        checkout = tmp_path / f"job-{index}"
        _git(repo, "worktree", "add", "--quiet", "--detach", str(checkout), sha)
        code = run_done_command([str(checkout), "--base", base, "--format", "json"])
        receipt = capsys.readouterr().out
        assert code == int(index == 0 and broken_lower), receipt
        (receipts / f"{sha}.json").write_text(receipt, encoding="utf-8")
    code, result = _verify(capsys, repo, manifest, receipts)
    assert code == int(broken_lower), result
    assert result["outcome"] == ("NOT_VERIFIED" if broken_lower else "VERIFIED")
    assert result["final_tree_matches_original"] is True
    assert result["layers"][0]["status"] == (
        "not_verified" if broken_lower else "passed"
    )
    assert result["layers"][1]["tests_passed"] == 1
    assert _git(repo, "rev-parse", "HEAD") == tip


def test_rejects_diverged_order_or_nonmatching_original(tmp_path, capsys):
    repo = tmp_path / "repo"
    base, first, tip, original = _create_stack(repo)
    for lower, upper, extras, reason in (
        (tip, first, [], "strictly descend"),
        (first, first, [], "strictly descend"),
        (first, original, [], "strictly descend"),
        (first, tip, ["--original", first], "differs"),
    ):
        code, result = _invoke(capsys, repo, *_plan_args(base, lower, upper, *extras))
        assert code == 2 and reason in result["message"], result


def test_base_policy_must_require_passing_tests(tmp_path, capsys):
    repo = tmp_path / "repo"
    base, first, tip, _ = _create_stack(repo, tests_mode="advise")
    code, result = _invoke(capsys, repo, *_plan_args(base, first, tip))
    assert code == 2 and "must require passing tests" in result["message"], result


def _passing_receipt(stack: Stack, commit: str) -> dict:
    checks = [
        {"id": name, "mode": stack.config.mode(name), "status": "pass", "evidence": {}}
        for name in CHECK_IDS
    ]
    tests = next(check for check in checks if check["id"] == "tests_pass")
    tests["evidence"] = {
        "run": 1,
        "passed": 1,
        "skipped": 0,
        "failed": 0,
        "flaky": 0,
        "not_run": 0,
        "unknown_case_totals": 0,
    }
    return {
        "schema": SCHEMA,
        "skylos_version": __version__,
        "head": {"sha": commit, "dirty": False},
        "base": {"sha": stack.base.sha, "source": "merge_base"},
        "agent": {"client": "unknown"},
        "config_digest": stack.config.digest(),
        "verdict": "pass",
        "checks": checks,
    }


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("missing", "missing"),
        ("other_head", "exact clean layer"),
        ("dirty", "exact clean layer"),
        ("other_base", "pinned stack base"),
        ("digest", "pinned base policy"),
        ("omitted_check", "complete set of checks"),
        ("advisory_tests", "changed the policy"),
        ("skipped", "completed passing test run"),
        ("flaky", "failed, flaky or missing"),
        ("invalid_count", "valid test counts"),
        ("malformed_check", "Invalid Done receipt"),
        ("duplicate_key", "not valid JSON"),
    ],
)
def test_does_not_accept_missing_or_mismatched_receipts(
    tmp_path, capsys, mutation, reason
):
    repo = tmp_path / "repo"
    base, first, tip, _ = _create_stack(repo)
    stack = plan_stack(repo, base, [first, tip], None)
    manifest, receipts = tmp_path / "stack.json", tmp_path / "receipts"
    manifest.write_text(json.dumps(stack.manifest()), encoding="utf-8")
    receipts.mkdir()
    (receipts / f"{tip}.json").write_text(
        json.dumps(_passing_receipt(stack, tip)), encoding="utf-8"
    )
    receipt = _passing_receipt(stack, first)
    tests = next(check for check in receipt["checks"] if check["id"] == "tests_pass")
    match mutation:
        case "other_head":
            receipt["head"]["sha"] = tip
        case "dirty":
            receipt["head"]["dirty"] = True
        case "other_base":
            receipt["base"]["sha"] = first
        case "digest":
            receipt["config_digest"] = "sha256:" + "0" * 64
        case "omitted_check":
            receipt["checks"].pop()
        case "advisory_tests":
            tests["mode"] = "advise"
        case "skipped":
            tests["evidence"].update(passed=0, skipped=1)
        case "flaky":
            tests["evidence"]["flaky"] = 1
        case "invalid_count":
            tests["evidence"]["passed"] = True
        case "malformed_check":
            tests["id"] = {"invalid": [1]}
    if mutation != "missing":
        text = json.dumps(receipt)
        if mutation == "duplicate_key":
            text = '{"verdict":"fail",' + text[1:]
        (receipts / f"{first}.json").write_text(text, encoding="utf-8")
    code, result = _verify(capsys, repo, manifest, receipts)
    assert code == 1 and result["outcome"] == "NOT_VERIFIED", result
    assert reason in result["layers"][0]["reason"], result
    assert result["final_tree_matches_original"] is None
    assert result["layers"][1]["status"] == "passed"


def test_rechecks_manifest_objects_and_base_policy(tmp_path, capsys):
    repo = tmp_path / "repo"
    base, first, tip, _ = _create_stack(repo)
    stack = plan_stack(repo, base, [first, tip], None)
    manifest = stack.manifest()
    manifest["layers"][0]["tree"] = manifest["base"]["tree"]
    file = tmp_path / "stack.json"
    file.write_text(json.dumps(manifest), encoding="utf-8")
    code, result = _verify(capsys, repo, file, tmp_path)
    assert code == 2 and "pinned Git objects" in result["message"], result
