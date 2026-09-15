import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.core import baseline_source
from skylos.core.git_safety import read_only_git_environment
from skylos.core.safe_cache_io import write_text_no_symlink


def _baseline(label="approved"):
    return {
        "fingerprints": [],
        "dependency_baseline": {
            "version": 1,
            "fingerprints": [hashlib.sha256(label.encode()).hexdigest()],
            "captured_count": 1,
            "unmatched_count": 0,
        },
    }


def _write_baseline(root, baseline=None):
    path = root / ".skylos" / "baseline.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(
        path, json.dumps(_baseline() if baseline is None else baseline)
    )
    return path


def _git(root, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=skylos-test@example.invalid",
            *args,
        ],
        cwd=root,
        env=read_only_git_environment(),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo with spaces"
    root.mkdir()
    _git(root, "init", "-q")
    _write_baseline(root)
    _git(root, "add", ".skylos/baseline.json")
    _git(root, "commit", "-qm", "approved baseline")
    return root


def test_loads_local_baseline(tmp_path):
    _write_baseline(tmp_path)
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline == _baseline()
    assert receipt == {"source": "working_tree", "status": "loaded"}


def test_local_baseline_without_dependency_section_is_valid(tmp_path):
    _write_baseline(tmp_path, {"fingerprints": ["legacy"]})
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline == {"fingerprints": ["legacy"]}
    assert receipt["status"] == "loaded"


@pytest.mark.parametrize(
    "environ",
    [
        {"CI": "true"},
        {"CI": "1"},
        {"CI": "yes"},
        {"GITHUB_RUN_ID": "123"},
        {"CI_PIPELINE_ID": "123"},
        {"BUILD_BUILDID": "123"},
    ],
)
def test_ci_never_reads_worktree_without_explicit_ref(tmp_path, monkeypatch, environ):
    _write_baseline(tmp_path)

    def unexpected_read(*args, **kwargs):
        pytest.fail("CI without a selected base must not read the worktree baseline")

    monkeypatch.setattr(
        baseline_source, "read_project_text_no_symlink", unexpected_read
    )
    baseline, receipt = baseline_source.load_dependency_baseline(
        tmp_path, environ=environ
    )
    assert baseline is None
    assert receipt == {"source": "working_tree", "status": "ci_ref_required"}


def test_missing_local_baseline_retains_findings(tmp_path):
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt == {
        "source": "working_tree",
        "status": "unavailable",
        "error": "baseline_unavailable",
    }


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "null",
        "1",
        "not json",
        '{"dependency_baseline": []}',
        '{"dependency_baseline": null}',
        '{"dependency_baseline": {}, "dependency_baseline": {}}',
    ],
)
def test_rejects_invalid_local_baseline_shape(tmp_path, text):
    _write_baseline(tmp_path).write_text(text)
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["error"] == "invalid_baseline"


def test_rejects_deeply_nested_json(tmp_path):
    _write_baseline(tmp_path).write_text(
        '{"nested":' + "[" * 1500 + "0" + "]" * 1500 + "}"
    )
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["error"] == "invalid_baseline"


def test_rejects_json_above_node_limit(tmp_path, monkeypatch):
    _write_baseline(tmp_path, {"values": list(range(100))})
    monkeypatch.setattr(baseline_source, "_MAX_JSON_NODES", 10)
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["error"] == "invalid_baseline"


def test_rejects_json_above_depth_limit(tmp_path):
    _write_baseline(tmp_path).write_text('{"nested":' + "[" * 33 + "0" + "]" * 33 + "}")
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["error"] == "invalid_baseline"


def test_rejects_invalid_utf8(tmp_path):
    _write_baseline(tmp_path).write_bytes(b"\xff")
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["status"] == "unavailable"


def test_rejects_local_baseline_above_byte_limit(tmp_path, monkeypatch):
    _write_baseline(tmp_path)
    monkeypatch.setattr(baseline_source, "MAX_DEPENDENCY_BASELINE_BYTES", 8)
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, environ={})
    assert baseline is None
    assert receipt["status"] == "unavailable"


@pytest.mark.parametrize("target", ["file", "directory", "root"])
def test_rejects_symlinked_local_baseline_components(tmp_path, target):
    actual = tmp_path / "actual"
    actual.mkdir()
    actual_file = _write_baseline(actual)
    root = tmp_path / "project"
    if target == "root":
        root.symlink_to(actual, target_is_directory=True)
    else:
        root.mkdir()
        if target == "directory":
            (root / ".skylos").symlink_to(actual / ".skylos", target_is_directory=True)
        else:
            (root / ".skylos").mkdir()
            (root / ".skylos" / "baseline.json").symlink_to(actual_file)
    baseline, receipt = baseline_source.load_dependency_baseline(root, environ={})
    assert baseline is None
    assert receipt["status"] == "unavailable"


def test_ref_reads_committed_baseline_not_changed_worktree(repo):
    commit = _git(repo, "rev-parse", "HEAD")
    _write_baseline(repo, _baseline("working-tree-change"))
    baseline, receipt = baseline_source.load_dependency_baseline(
        repo, ref=commit, environ={"CI": "true"}
    )
    assert baseline == _baseline()
    assert receipt == {"source": "git_ref", "commit": commit, "status": "loaded"}


def test_ref_reads_immutable_revision_not_latest_commit(repo):
    commit = _git(repo, "rev-parse", "HEAD")
    _write_baseline(repo, _baseline("later-commit"))
    _git(repo, "add", ".skylos/baseline.json")
    _git(repo, "commit", "-qm", "later baseline")
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref=commit)
    assert baseline == _baseline()
    assert receipt["commit"] == commit


def test_ref_ignores_worktree_baseline_symlink(repo, tmp_path):
    path = repo / ".skylos" / "baseline.json"
    path.unlink()
    other = tmp_path / "unrelated.json"
    other.write_text(json.dumps(_baseline("unrelated")))
    path.symlink_to(other)
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref="HEAD")
    assert baseline == _baseline()
    assert receipt["status"] == "loaded"


def test_ref_reads_subproject_scope(repo):
    subproject = repo / "packages" / "demo"
    _write_baseline(subproject, _baseline("subproject"))
    _git(repo, "add", "packages/demo/.skylos/baseline.json")
    _git(repo, "commit", "-qm", "subproject baseline")
    baseline, receipt = baseline_source.load_dependency_baseline(subproject, ref="HEAD")
    assert baseline == _baseline("subproject")
    assert receipt["status"] == "loaded"


@pytest.mark.parametrize("ref", ["", " ", "-invalid", "bad\nref", "x" * 513])
def test_invalid_ref_does_not_fall_back_to_local(repo, ref):
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref=ref)
    assert baseline is None
    assert receipt == {
        "source": "git_ref",
        "status": "unavailable",
        "error": "invalid_ref",
    }


def test_missing_ref_does_not_fall_back_to_local(repo):
    baseline, receipt = baseline_source.load_dependency_baseline(
        repo, ref="missing-base"
    )
    assert baseline is None
    assert receipt["error"] == "ref_unavailable"
    assert "missing-base" not in json.dumps(receipt)


def test_no_git_repo_does_not_fall_back_to_local(tmp_path):
    _write_baseline(tmp_path)
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, ref="HEAD")
    assert baseline is None
    assert receipt["error"] == "ref_unavailable"


def test_ref_missing_baseline_does_not_use_worktree(repo):
    subproject = repo / "new-package"
    _write_baseline(subproject, _baseline("new"))
    baseline, receipt = baseline_source.load_dependency_baseline(subproject, ref="HEAD")
    assert baseline is None
    assert receipt["error"] == "baseline_unavailable"


def test_ref_rejects_symlink_blob(repo):
    path = repo / ".skylos" / "baseline.json"
    path.unlink()
    path.symlink_to("../other.json")
    _git(repo, "add", ".skylos/baseline.json")
    _git(repo, "commit", "-qm", "symlink fixture")
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref="HEAD")
    assert baseline is None
    assert receipt["error"] == "nonregular_baseline"


def test_ref_rejects_blob_above_byte_limit(repo, monkeypatch):
    monkeypatch.setattr(baseline_source, "MAX_DEPENDENCY_BASELINE_BYTES", 8)
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref="HEAD")
    assert baseline is None
    assert receipt["error"] == "baseline_too_large"


def test_ref_rejects_invalid_baseline_json(repo):
    _write_baseline(repo, [])
    _git(repo, "add", ".skylos/baseline.json")
    _git(repo, "commit", "-qm", "invalid fixture")
    baseline, receipt = baseline_source.load_dependency_baseline(repo, ref="HEAD")
    assert baseline is None
    assert receipt["error"] == "invalid_baseline"


@pytest.mark.parametrize(
    "failure",
    [
        OSError("secret-path"),
        subprocess.TimeoutExpired("secret-ref", 10),
        UnicodeError("secret-data"),
    ],
)
def test_git_errors_have_sanitized_receipts(repo, monkeypatch, failure):
    def fail(*args):
        raise failure

    monkeypatch.setattr(baseline_source.GitContext, "from_path", fail)
    baseline, receipt = baseline_source.load_dependency_baseline(
        repo, ref="private-ref"
    )
    assert baseline is None
    assert receipt == {
        "source": "git_ref",
        "status": "unavailable",
        "error": "source_unavailable",
    }


def test_ref_reads_validated_blob_by_object_id(monkeypatch, tmp_path):
    commit = "a" * 40
    object_id = "b" * 40
    content = json.dumps(_baseline())
    calls = []

    def run(*args):
        calls.append(args)
        if args[0] == "rev-parse":
            output = commit + "\n"
        elif args[0] == "ls-tree":
            output = f"100644 blob {object_id} {len(content)}\t.skylos/baseline.json\0"
        else:
            output = content
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(
        baseline_source.GitContext,
        "from_path",
        lambda root: SimpleNamespace(root=Path(root), run=run),
    )
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, ref="stable")
    assert baseline == _baseline()
    assert calls == [
        ("rev-parse", "--verify", "--end-of-options", "stable^{commit}"),
        ("ls-tree", "-l", "-z", commit, "--", ":(literal).skylos/baseline.json"),
        ("cat-file", "blob", object_id),
    ]
    assert receipt["commit"] == commit


@pytest.mark.parametrize(
    "entry,error",
    [
        ("", "baseline_unavailable"),
        ("missing-metadata\t.skylos/baseline.json\0", "invalid_git_entry"),
        ("100644 blob {object_id} 10\twrong.json\0", "invalid_git_entry"),
        (
            "100644 blob invalid-object 10\t.skylos/baseline.json\0",
            "nonregular_baseline",
        ),
        ("040000 tree {object_id} -\t.skylos/baseline.json\0", "nonregular_baseline"),
        (
            "100644 blob {object_id} 2000001\t.skylos/baseline.json\0",
            "baseline_too_large",
        ),
    ],
)
def test_invalid_git_metadata_is_rejected_before_blob_read(
    tmp_path, monkeypatch, entry, error
):
    def run(*args):
        if args[0] == "rev-parse":
            output = "a" * 40
        elif args[0] == "ls-tree":
            output = entry.format(object_id="b" * 40)
        else:
            pytest.fail("invalid Git metadata must prevent reading the blob")
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(
        baseline_source.GitContext,
        "from_path",
        lambda root: SimpleNamespace(root=Path(root), run=run),
    )
    baseline, receipt = baseline_source.load_dependency_baseline(tmp_path, ref="stable")
    assert baseline is None
    assert receipt["error"] == error
