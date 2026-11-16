"""The action's pull request diff scope and its upload skip, run as real bash
against real git repositories with a local CLI stub (no scan, no network)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest
import yaml

from test.fixture_paths import write_fixture


ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"
GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "init.defaultBranch=main"]


@pytest.fixture
def action():
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


def _git(cwd, *args):
    return subprocess.run(
        [*GIT, *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def _pr_checkout(tmp_path, *, shallow):
    """origin has main; the checkout is a PR branch one commit ahead of it."""
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-q")
    write_fixture(tmp_path, "seed/app.py", "x = 1\n")
    _git(seed, "add", ".")
    _git(seed, "commit", "-q", "-m", "base")
    origin = tmp_path / "origin.git"
    _git(tmp_path, "clone", "-q", "--bare", str(seed), str(origin))
    work = tmp_path / "work"
    clone = ["clone", "-q"]
    if shallow:
        clone += ["--depth", "1", "--no-local"]
    _git(tmp_path, *clone, f"file://{origin}" if shallow else str(origin), str(work))
    _git(work, "checkout", "-q", "-b", "feature")
    write_fixture(tmp_path, "work/app.py", "x = 1\ny = 2\n", overwrite=True)
    _git(work, "commit", "-q", "-am", "change")
    # Like actions/checkout: only the checked-out ref, no remote-tracking main.
    subprocess.run([*GIT, "update-ref", "-d", "refs/remotes/origin/main"], cwd=work)
    return work


def _run(action, step_name, cwd, tmp_path, **env_overrides):
    step = next(s for s in action["runs"]["steps"] if s["name"] == step_name)
    calls = write_fixture(tmp_path, "cli-calls.jsonl", "", overwrite=True)
    stub = write_fixture(
        tmp_path,
        "stub_python.py",
        textwrap.dedent(
            """\
            import json, os, sys
            from pathlib import Path
            args = sys.argv[1:]
            if args[:2] == ["-m", "skylos.cli"]:
                with Path(os.environ["SKYLOS_TEST_CALLS"]).open("a") as stream:
                    stream.write(json.dumps(
                        {"args": args, "policy_base": os.environ.get("SKYLOS_POLICY_BASE")}
                    ) + "\\n")
                print("{}")
            elif args[:1] == ["-c"]:
                print(0)
            else:
                raise SystemExit("Unexpected Python invocation: " + repr(args))
            """
        ),
        overwrite=True,
    )
    outputs = tmp_path / "outputs"
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "SKYLOS_PATH": ".",
        "SKYLOS_ANALYSIS": "dead-code security",
        "SKYLOS_CONFIDENCE": "60",
        "SKYLOS_TOKEN": "",
        "SKYLOS_DIFF_MODE": "auto",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_BASE_REF": "main",
        "GITHUB_OUTPUT": str(outputs),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "SKYLOS_TEST_PYTHON": sys.executable,
        "SKYLOS_TEST_STUB": str(stub),
        "SKYLOS_TEST_CALLS": str(calls),
        **env_overrides,
    }
    script = (
        'python() { command "$SKYLOS_TEST_PYTHON" "$SKYLOS_TEST_STUB" "$@"; }\n'
        + step["run"]
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    invocations = [json.loads(line) for line in calls.read_text().splitlines()]
    out = dict(
        line.split("=", 1)
        for line in (outputs.read_text().splitlines() if outputs.exists() else [])
    )
    return invocations, out, result.stdout


@pytest.mark.parametrize("shallow", [False, True])
def test_pull_request_scan_covers_only_the_changed_lines(action, tmp_path, shallow):
    work = _pr_checkout(tmp_path, shallow=shallow)
    calls, out, _ = _run(action, "Run Skylos Scan", work, tmp_path)
    assert len(calls) == 1
    args = calls[0]["args"]
    assert args[-5:] == ["--diff-base", "origin/main", "--diff", "origin/main", "--json"]
    assert calls[0]["policy_base"] == _git(work, "merge-base", "origin/main", "HEAD")
    assert out["diff_base"] == "origin/main"


def test_diff_false_scans_the_whole_repository(action, tmp_path):
    work = _pr_checkout(tmp_path, shallow=False)
    calls, out, _ = _run(action, "Run Skylos Scan", work, tmp_path, SKYLOS_DIFF_MODE="false")
    assert "--diff" not in calls[0]["args"]
    assert "diff_base" not in out


def test_push_scans_the_whole_repository(action, tmp_path):
    work = _pr_checkout(tmp_path, shallow=False)
    calls, out, _ = _run(action, "Run Skylos Scan", work, tmp_path, GITHUB_EVENT_NAME="push")
    assert "--diff" not in calls[0]["args"]
    assert "diff_base" not in out


def test_pull_request_without_common_history_falls_back_with_a_notice(action, tmp_path):
    lonely = tmp_path / "lonely"
    lonely.mkdir()
    _git(lonely, "init", "-q")
    _git(lonely, "commit", "-q", "--allow-empty", "-m", "only")
    calls, out, stdout = _run(action, "Run Skylos Scan", lonely, tmp_path)
    assert "--diff" not in calls[0]["args"]
    assert "diff_base" not in out
    assert "::notice::Skylos scanned the whole repository" in stdout


@pytest.mark.parametrize("base_ref", ["main;touch pwned", "$(touch pwned)", "a b"])
def test_unexpected_base_ref_is_not_used(action, tmp_path, base_ref):
    work = _pr_checkout(tmp_path, shallow=False)
    calls, out, _ = _run(action, "Run Skylos Scan", work, tmp_path, GITHUB_BASE_REF=base_ref)
    assert "--diff" not in calls[0]["args"]
    assert not (work / "pwned").exists()


def test_gate_uses_the_scan_base(action, tmp_path):
    calls, _, _ = _run(
        action, "Quality Gate", tmp_path, tmp_path,
        SKYLOS_DIFF_BASE_REF="origin/main", SKYLOS_PATH="project dir",
    )
    assert calls[0]["args"] == [
        "-m", "skylos.cli", "cicd", "gate", "project dir",
        "--diff-base", "origin/main", "--input", "skylos-report.json", "--summary",
    ]


def test_gate_without_scan_base_is_unchanged(action, tmp_path):
    calls, _, _ = _run(action, "Quality Gate", tmp_path, tmp_path, SKYLOS_DIFF_BASE_REF="")
    assert calls[0]["args"] == [
        "-m", "skylos.cli", "cicd", "gate", "--input", "skylos-report.json", "--summary",
    ]


def test_upload_is_skipped_without_token_or_oidc(action, tmp_path):
    calls, _, stdout = _run(action, "Upload to Skylos Dashboard", tmp_path, tmp_path)
    assert calls == []
    assert "::notice::Skylos Cloud upload skipped" in stdout


@pytest.mark.parametrize(
    "env",
    [{"SKYLOS_TOKEN": "sk_test"}, {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example"}],
)
def test_upload_runs_with_a_token_or_oidc(action, tmp_path, env):
    calls, _, _ = _run(action, "Upload to Skylos Dashboard", tmp_path, tmp_path, **env)
    assert len(calls) == 1
    assert calls[0]["args"][-1] == "--upload"
