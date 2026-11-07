import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from skylos.benchmarks import eval_identity


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    )


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Eval Tests")
    _git(root, "config", "user.email", "eval@example.invalid")
    (root / ".gitignore").write_text(".skylos/\n*.native\n")
    (root / "skylos").mkdir()
    (root / "skylos" / "analyzer.py").write_text("value = 1\n")
    _git(root, "add", ".gitignore", "skylos/analyzer.py")
    _git(root, "commit", "-qm", "fixture")
    return root


def test_tracked_and_untracked_edits_change_identity_without_a_new_commit(checkout):
    before = eval_identity.source_identity(checkout)
    (checkout / "skylos" / "analyzer.py").write_text("value = 2\n")
    edited = eval_identity.source_identity(checkout)
    assert edited["revision"] == before["revision"]
    assert edited["snapshot_sha256"] != before["snapshot_sha256"]
    assert edited["dirty_paths"] == ["skylos/analyzer.py"]

    (checkout / "new_rule.py").write_text("new = True\n")
    added = eval_identity.source_identity(checkout)
    assert "new_rule.py" in added["files"]
    assert added["snapshot_sha256"] != edited["snapshot_sha256"]


def test_ignored_artifacts_stay_out_but_effective_native_inputs_participate(checkout):
    before = eval_identity.source_identity(checkout)
    artifacts = checkout / ".skylos" / "internal-regressions"
    artifacts.mkdir(parents=True)
    (artifacts / "private.json").write_text('"private-value"')
    cache = checkout / "skylos" / "__pycache__"
    cache.mkdir()
    (cache / "analyzer.pyc").write_bytes(b"bytecode")
    (checkout / "unrelated.native").write_bytes(b"ignored nonruntime input")
    assert (
        eval_identity.source_identity(checkout)["snapshot_sha256"]
        == before["snapshot_sha256"]
    )

    binary = checkout / "skylos" / "engine.native"
    binary.write_bytes(b"effective native engine")
    after = eval_identity.source_identity(checkout)
    assert "skylos/engine.native" in after["files"]
    assert after["snapshot_sha256"] != before["snapshot_sha256"]


def test_missing_tracked_file_is_explicit(checkout):
    before = eval_identity.source_identity(checkout)
    (checkout / "skylos" / "analyzer.py").unlink()
    after = eval_identity.source_identity(checkout)
    assert after["files"]["skylos/analyzer.py"] == {
        "sha256": None,
        "mode": None,
        "missing": True,
    }
    assert after["snapshot_sha256"] != before["snapshot_sha256"]


def test_marketing_media_is_excluded_but_fixture_assets_stay_inputs(checkout):
    baseline = eval_identity.source_identity(checkout)
    media = checkout / "editors/vscode/media/demo.gif"
    media.parent.mkdir(parents=True)
    media.write_bytes(b"marketing animation")
    (checkout / "assets").mkdir()
    (checkout / "assets/screenshot.png").write_bytes(b"marketing screenshot")
    assert (
        eval_identity.source_identity(checkout)["snapshot_sha256"]
        == baseline["snapshot_sha256"]
    )
    fixture = checkout / "benchmarks/fixtures/assets/model.dll"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"native fixture metadata")
    after = eval_identity.source_identity(checkout)
    assert "benchmarks/fixtures/assets/model.dll" in after["files"]
    assert after["snapshot_sha256"] != baseline["snapshot_sha256"]
    archive_path = checkout / ".skylos/source.tar.gz"
    eval_identity.write_source_snapshot(checkout, archive_path, after)
    with tarfile.open(archive_path, "r:gz") as archive:
        assert "benchmarks/fixtures/assets/model.dll" in archive.getnames()
        assert not any(
            name.startswith(("assets/", "editors/vscode/media/"))
            for name in archive.getnames()
        )


def test_submodule_gitlink_and_checked_out_bytes_are_preserved(checkout):
    revision = _git(checkout, "rev-parse", "HEAD").stdout.strip()
    _git(checkout, "update-index", "--add", "--cacheinfo", f"160000,{revision},demo")
    (checkout / "demo").mkdir()
    before = eval_identity.source_identity(checkout)
    assert before["files"]["demo"]["gitlink"] == revision
    (checkout / "demo" / "app.py").write_text("value = 1\n")
    after = eval_identity.source_identity(checkout)
    assert after["snapshot_sha256"] != before["snapshot_sha256"]
    assert "demo/app.py" in after["files"]
    destination = checkout / ".skylos" / "snapshot.tar.gz"
    eval_identity.write_source_snapshot(checkout, destination, after)
    with tarfile.open(destination, "r:gz") as archive:
        assert archive.getmember("demo").isdir()
        assert archive.extractfile("demo/app.py").read() == b"value = 1\n"


def test_demo_gitlink_keeps_pin_without_archiving_generated_application(
    checkout, tmp_path
):
    revision = _git(checkout, "rev-parse", "HEAD").stdout.strip()
    _git(
        checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{revision},skylos-demo",
    )
    demo = checkout / "skylos-demo"
    demo.mkdir()
    (demo / "app.py").write_text("demo_value = 1\n")
    generated = demo / "real_life_examples"
    generated.mkdir()
    outside = tmp_path / "external-demo-certificates"
    outside.mkdir()
    (outside / "certificate.pem").write_text("not an analyzer input")
    (generated / "certificates").symlink_to(outside, target_is_directory=True)

    baseline = eval_identity.source_identity(checkout)
    assert baseline["files"]["skylos-demo"]["gitlink"] == revision
    assert not any(name.startswith("skylos-demo/") for name in baseline["files"])
    (demo / "app.py").write_text("demo_value = 2\n")
    assert (
        eval_identity.source_identity(checkout)["snapshot_sha256"]
        == baseline["snapshot_sha256"]
    )

    destination = checkout / ".skylos" / "demo-scope.tar.gz"
    eval_identity.write_source_snapshot(checkout, destination, baseline)
    with tarfile.open(destination, "r:gz") as archive:
        assert archive.getmember("skylos-demo").isdir()
        assert not any(name.startswith("skylos-demo/") for name in archive.getnames())

    (checkout / "skylos/analyzer.py").write_text("value = 99\n")
    changed = eval_identity.source_identity(checkout)
    assert changed["snapshot_sha256"] != baseline["snapshot_sha256"]
    (checkout / "skylos/engine.native").write_bytes(b"changed native analyzer input")
    assert (
        eval_identity.source_identity(checkout)["snapshot_sha256"]
        != changed["snapshot_sha256"]
    )


@pytest.mark.parametrize("directory", [False, True])
def test_escaping_symlinks_are_rejected_before_reading(checkout, tmp_path, directory):
    outside = tmp_path / "outside"
    if directory:
        outside.mkdir()
        (outside / "private.py").write_text("secret = True\n")
    else:
        outside.write_text("secret = True\n")
    (checkout / "skylos" / "external").symlink_to(
        outside, target_is_directory=directory
    )
    with pytest.raises(ValueError, match="escapes checkout"):
        eval_identity.source_identity(checkout)


def test_unsupported_special_file_cannot_yield_a_partial_identity(checkout):
    os.mkfifo(checkout / "skylos" / "input.pipe")
    with pytest.raises(ValueError, match="not a regular file"):
        eval_identity.source_identity(checkout)


def test_snapshot_is_deterministic_and_contains_actual_dirty_source_only(checkout):
    source = checkout / "skylos" / "analyzer.py"
    source.write_text("value = 3\n")
    (checkout / "new_rule.py").write_text("new = True\n")
    private = checkout / ".skylos"
    private.mkdir()
    (private / "private.json").write_text("private")
    identity = eval_identity.source_identity(checkout)
    first = private / "evals" / "first.tar.gz"
    second = private / "evals" / "second.tar.gz"
    eval_identity.write_source_snapshot(checkout, first, identity)
    eval_identity.write_source_snapshot(checkout, second, identity)
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:gz") as archive:
        assert archive.getnames() == [
            ".gitignore",
            "new_rule.py",
            "skylos/analyzer.py",
        ]
        assert archive.extractfile("skylos/analyzer.py").read() == b"value = 3\n"


def test_snapshot_retains_relative_internal_file_symlink_and_its_target(checkout):
    (checkout / "skylos" / "linked.py").symlink_to("analyzer.py")
    identity = eval_identity.source_identity(checkout)
    destination = checkout / ".skylos" / "snapshot.tar.gz"
    eval_identity.write_source_snapshot(checkout, destination, identity)
    with tarfile.open(destination, "r:gz") as archive:
        member = archive.getmember("skylos/linked.py")
        assert member.issym()
        assert member.linkname == "analyzer.py"
        assert archive.extractfile(member).read() == b"value = 1\n"


def test_stale_snapshot_identity_is_rejected_without_creating_an_archive(checkout):
    identity = eval_identity.source_identity(checkout)
    (checkout / "skylos" / "analyzer.py").write_text("value = 4\n")
    destination = checkout / ".skylos" / "snapshot.tar.gz"
    with pytest.raises(ValueError, match="changed before"):
        eval_identity.write_source_snapshot(checkout, destination, identity)
    assert not destination.exists()


def test_source_changes_during_capture_remove_the_incomplete_archive(
    checkout, monkeypatch
):
    identity = eval_identity.source_identity(checkout)
    real_identity = eval_identity.source_identity
    calls = 0

    def concurrent_identity(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            (checkout / "new_rule.py").write_text("late = True\n")
        return real_identity(root)

    monkeypatch.setattr(eval_identity, "source_identity", concurrent_identity)
    destination = checkout / ".skylos" / "snapshot.tar.gz"
    with pytest.raises(ValueError, match="changed during"):
        eval_identity.write_source_snapshot(checkout, destination, identity)
    assert not destination.exists()


def test_snapshot_refuses_to_overwrite_receipt_or_include_itself(checkout):
    identity = eval_identity.source_identity(checkout)
    existing = checkout / ".skylos" / "snapshot.tar.gz"
    existing.parent.mkdir()
    existing.write_bytes(b"previous evidence")
    with pytest.raises(FileExistsError):
        eval_identity.write_source_snapshot(checkout, existing, identity)
    assert existing.read_bytes() == b"previous evidence"
    with pytest.raises(ValueError, match="outside the source inventory"):
        eval_identity.write_source_snapshot(
            checkout, checkout / "snapshot.tar.gz", identity
        )


def test_environment_config_changes_identity_without_exposing_values(monkeypatch):
    monkeypatch.setenv("SKYLOS_GREP_BUDGET", "100")
    before = eval_identity.environment_identity()
    monkeypatch.setenv("SKYLOS_GREP_BUDGET", "200")
    after = eval_identity.environment_identity()
    assert before["sha256"] != after["sha256"]
    assert "SKYLOS_GREP_BUDGET" not in json.dumps(after)


def test_environment_ignores_credentials_and_transient_shell_paths(monkeypatch):
    monkeypatch.setenv("SKYLOS_API_KEY", "first-secret-value")
    before = eval_identity.environment_identity()
    monkeypatch.setenv("SKYLOS_API_KEY", "second-secret-value")
    monkeypatch.setenv("SKYLOS_ACCESS_TOKEN", "a-token-that-must-not-be-recorded")
    monkeypatch.setenv("PWD", "/some/other/place")
    monkeypatch.setenv("HOME", "/another/home")
    after = eval_identity.environment_identity()
    assert before == after
    assert "secret-value" not in json.dumps(after)
    assert "a-token-that-must-not-be-recorded" not in json.dumps(after)


def test_environment_records_dependencies_and_executable(monkeypatch):
    class Distribution:
        metadata = {"Name": "example-eval-package"}
        version = "1.2.3"

    monkeypatch.setattr(
        eval_identity.importlib.metadata, "distributions", lambda: [Distribution()]
    )
    identity = eval_identity.environment_identity()
    assert identity["facts"]["distributions"] == [["example-eval-package", "1.2.3"]]
    assert len(identity["facts"]["python_executable_sha256"]) == 64
    assert Path(identity["facts"]["python_executable"]).is_file()
