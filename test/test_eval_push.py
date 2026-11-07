"""Pre-push checks grade committed analyzers against separately approved data."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from skylos.benchmarks import eval_push as push


ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
ZERO = "0" * 40


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=push.git_environment(),
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        f"(delete) {ZERO} refs/heads/old {SHA}\n",
        f"refs/heads/main {SHA} refs/heads/main {SHA}\n",
    ],
)
def test_empty_deleted_or_unchanged_refs_need_no_checks(text):
    assert push.parse_updates(text) == []


@pytest.mark.parametrize("size", [40, 64])
def test_full_sha_formats_are_accepted(size):
    sha = "a" * size
    result = push.parse_updates(f"refs/heads/main {sha} refs/heads/main {'0' * size}\n")
    assert result[0]["local_oid"] == sha


@pytest.mark.parametrize(
    "text",
    [
        "one two three",
        "one two three four five",
        f"main {'g' * 40} main {ZERO}",
        f"main {'a' * 39} main {ZERO}",
        f"bad\x00ref {SHA} main {ZERO}",
    ],
)
def test_malformed_native_input_fails_instead_of_skipping(text):
    with pytest.raises(ValueError):
        push.parse_updates(text)


def test_hook_local_git_environment_is_scrubbed(monkeypatch, tmp_path):
    # Git publishes the repository-local variables its hooks must clear before
    # invoking Git in another repository. Keep this list complete for this Git.
    local_names = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert set(local_names) <= push._GIT_LOCAL
    for name in (
        *local_names,
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ):
        monkeypatch.setenv(name, str(tmp_path / "wrong-repository"))
    env = push.git_environment()
    assert not (set(env) & push._GIT_LOCAL)
    assert "GIT_CONFIG_KEY_0" not in env and "GIT_CONFIG_VALUE_0" not in env
    assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"]
    assert "GIT_DIR" in __import__("os").environ


@pytest.fixture
def project(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "core.hooksPath", "/dev/null")
    _git(repo, "config", "user.name", "Eval Push Tests")
    _git(repo, "config", "user.email", "eval@example.invalid")
    shutil.copytree(
        ROOT / "skylos",
        repo / "skylos",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".skylos"),
    )
    # Model a legacy commit without the new runner or benchmark metadata. The
    # analyzer remains real; the independently pinned harness owns all fixtures.
    shutil.rmtree(repo / "skylos/benchmarks")
    (repo / "skylos/benchmarks").mkdir()
    (repo / "skylos/benchmarks/__init__.py").write_text("")
    (repo / ".gitignore").write_text(".skylos/\n__pycache__/\n*.pyc\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "legacy analyzer without eval tooling")
    return repo


def _revision(repo):
    oid = _git(repo, "rev-parse", "HEAD")
    return push.resolve_updates(
        repo, push.parse_updates(f"refs/heads/main {oid} refs/heads/main {ZERO}\n")
    )[0]


def _fault(repo):
    path = repo / "skylos/rules/danger/danger_net/ssrf_flow.py"
    original = path.read_bytes()
    needle = b"def scan(tree, file_path, findings):\n"
    assert original.count(needle) == 1
    path.write_bytes(
        original.replace(
            needle,
            needle + b"    return  # Deliberate test-only detector failure.\n",
            1,
        )
    )
    return path, original


def test_annotated_tag_and_duplicate_refs_check_one_commit(project):
    oid = _git(project, "rev-parse", "HEAD")
    _git(project, "tag", "-a", "sample", "-m", "same commit")
    tag_oid = _git(project, "rev-parse", "refs/tags/sample")
    text = (
        f"refs/heads/main {oid} refs/heads/main {ZERO}\n"
        f"refs/tags/sample {tag_oid} refs/tags/sample {ZERO}\n"
    )
    resolved = push.resolve_updates(project, push.parse_updates(text))
    assert len(resolved) == 1
    assert resolved[0]["commit"] == oid
    assert len(resolved[0]["refs"]) == 2


def test_legacy_committed_analyzer_passes_despite_dirty_uncommitted_break(
    project, tmp_path
):
    revision = _revision(project)
    path, _ = _fault(project)
    dirty = path.read_bytes()
    assert not (project / "scripts/eval_check.py").exists()
    assert not (project / "benchmarks").exists()
    report = push.check_commit(project, revision, tmp_path / "proof")
    assert report["passed"], report
    assert report["commit"] == revision["commit"]
    assert report["tree"] == _git(project, "rev-parse", "HEAD^{tree}")
    assert path.read_bytes() == dirty
    assert Path(report["worker"]["analyzer_path"]).name == "analyzer.py"
    for suite in push.SMOKE_CASES:
        result = report["worker"]["cases"][suite]
        assert result["passed"] and not result["errors"]
        assert len(result["results"]) == len(push.SMOKE_CASES[suite])
    assert report["artifacts"]["checks/security/dataset.json"]


def test_committed_detector_break_fails_even_with_weak_candidate_labels_and_dirty_fix(
    project, tmp_path
):
    path, original = _fault(project)
    # These deliberately weakened candidate answers must not be used by the gate.
    candidate_data = project / "benchmarks/security"
    candidate_data.mkdir(parents=True)
    (candidate_data / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "ssrf-tainted-host",
                        "path": "safe.py",
                        "expect": {"absent": {"danger": ["SKY-D216"]}},
                    }
                ],
            }
        )
    )
    (candidate_data / "safe.py").write_text(
        "print('this cannot replace approved cases')\n"
    )
    _git(project, "add", ".")
    _git(
        project, "commit", "-qm", "deliberate detector break and weakened local answers"
    )
    revision = _revision(project)
    path.write_bytes(original)
    report = push.check_commit(project, revision, tmp_path / "proof")
    assert not report["passed"]
    security = report["worker"]["cases"]["security"]
    assert not security["passed"]
    assert report["worker"]["cases"]["dead-code"]["passed"]
    failures = [f for case in security["results"] for f in case["failures"]]
    assert any(
        f.get("expected") == "SKY-D216" and f.get("mode") == "present" for f in failures
    )
    assert path.read_bytes() == original
    dataset = json.loads((tmp_path / "proof/checks/security/dataset.json").read_text())
    positive = next(
        case["case"]
        for case in dataset["cases"]
        if case["case"]["id"] == "ssrf-tainted-host"
    )
    assert positive["expect"]["present"]["danger"] == ["SKY-D216"]


def test_committed_source_symlink_is_rejected_before_outside_import(project, tmp_path):
    helper = project / "skylos/rules/danger/danger_net/ssrf_flow.py"
    original = helper.read_bytes()
    outside = tmp_path / "outside-helper.py"
    marker = tmp_path / "outside-imported.txt"
    outside.write_bytes(
        original
        + f"\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n".encode()
    )
    helper.unlink()
    helper.symlink_to(outside)
    _git(project, "add", ".")
    _git(project, "commit", "-qm", "source helper points outside committed snapshot")
    revision = _revision(project)

    # The very same commit must be rejected before any external helper executes,
    # regardless of whether those uncommitted external bytes look safe or broken.
    for number, source in enumerate(
        (outside.read_bytes(), b"raise RuntimeError('broken')\n")
    ):
        outside.write_bytes(source)
        report = push.check_commit(project, revision, tmp_path / f"proof-{number}")
        assert not report["passed"]
        assert report["commit"] == revision["commit"]
        assert report["tree"] == revision["tree"]
        assert report["worker_exit_code"] == 2
        stderr = (tmp_path / f"proof-{number}/stderr.txt").read_text()
        assert "committed Skylos source contains a symbolic link" in stderr
        assert "skylos/rules/danger/danger_net/ssrf_flow.py" in stderr
        assert "worker" not in report
        assert not marker.exists()


def test_controller_reads_native_delimiter_and_deduplicates_before_check(
    project, monkeypatch
):
    oid = _git(project, "rev-parse", "HEAD")
    text = f"main {oid} refs/heads/main {ZERO}\nother {oid} refs/heads/other {ZERO}\n"
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    called = []

    def fake_check(repo, revision, output):
        called.append(revision["commit"])
        return {**revision, "passed": True}

    monkeypatch.setattr(push, "check_commit", fake_check)
    assert (
        push.main(
            [
                "--repo",
                str(project),
                "--",
                "origin",
                "https://user:secret@example.invalid/repository",
            ]
        )
        == 0
    )
    assert called == [oid]
    receipt = next((project / ".skylos/evals/pre-push/runs").rglob("push-receipt.json"))
    assert "secret" not in receipt.read_text()


def test_missing_pinned_case_fails_clearly_before_scanning(monkeypatch, tmp_path):
    harness = tmp_path / "harness"
    (harness / "scripts").mkdir(parents=True)
    (harness / "scripts/eval_pre_push.py").write_text("pass\n")
    for directory in ("security", "dead_code"):
        target = harness / "benchmarks" / directory
        target.mkdir(parents=True)
        (target / "manifest.json").write_text('{"version":1,"cases":[]}')
    monkeypatch.setattr(push, "HARNESS_ROOT", harness)
    with pytest.raises(ValueError, match="missing required smoke"):
        push.harness_identity()


def test_fixture_changes_alter_pinned_harness_identity(tmp_path, monkeypatch):
    harness = tmp_path / "harness"
    (harness / "scripts").mkdir(parents=True)
    (harness / "scripts/eval_pre_push.py").write_text("pass\n")
    for suite, ids in push.SMOKE_CASES.items():
        directory = (
            harness
            / "benchmarks"
            / ("security" if suite == "security" else "dead_code")
        )
        (directory / "fixtures").mkdir(parents=True)
        cases = []
        for case_id in ids:
            path = "fixtures/" + case_id + ".py"
            (directory / path).write_text("value = 1\n")
            cases.append({"id": case_id, "path": path})
        (directory / "manifest.json").write_text(json.dumps({"cases": cases}))
    monkeypatch.setattr(push, "HARNESS_ROOT", harness)
    before = push.harness_identity()
    fixture = harness / "benchmarks/security/fixtures/ssrf-tainted-host.py"
    fixture.write_text("value = 2\n")
    assert push.harness_identity()["sha256"] != before["sha256"]
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        in push.harness_identity()["files"].values()
    )
