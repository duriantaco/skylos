"""Comparable type diagnostics require stable source, configuration and environment."""

import copy
import subprocess
import types
from pathlib import Path

import pytest

from skylos.done.base import open_comparison
from skylos.typecheck import adapters, comparison


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def project(tmp_path, monkeypatch):
    for variable in ("PYTHONPATH", "MYPYPATH", "NODE_PATH"):
        monkeypatch.delenv(variable, raising=False)
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".gitignore").write_text(".venv/\n")
    (tmp_path / "mypy.ini").write_text("[mypy]\nfiles = app.py\n")
    (tmp_path / "app.py").write_text("value: int = 'base'\n")
    (tmp_path / "consumer.py").write_text("value: int = 'consumer'\n")
    executable = tmp_path / ".venv" / "bin" / "mypy"
    executable.parent.mkdir(parents=True)
    # Only discovery/fingerprinting reads this sentinel. Every checker run is
    # replaced below; the fixture is deliberately not an executable program.
    executable.write_bytes(b"test-only checker sentinel\n")
    executable.chmod(0o755)
    _git(tmp_path, "add", ".gitignore", "mypy.ini", "app.py", "consumer.py")
    _git(tmp_path, "commit", "-qm", "base")
    monkeypatch.setattr(adapters.shutil, "which", lambda name: str(executable))
    return tmp_path, executable


def _diagnostic(*, file="app.py", column=1):
    return {
        "file": file,
        "line": 1,
        "column": column,
        "code": "assignment",
        "message": "Incompatible assignment",
        "severity": "error",
    }


def _checker(monkeypatch, root, executable, *, head=None, base=None, mutate=None):
    calls = []

    def run(path, *, checker="mypy", timeout_seconds=120, **kwargs):
        path = Path(path)
        is_head = path == root
        calls.append({"head": is_head, "timeout": timeout_seconds})
        if mutate is not None:
            mutate(is_head)
        plan = adapters.discover_checker(path, "mypy")
        diagnostics = copy.deepcopy((head if is_head else base) or [])
        return {
            **plan,
            "status": "fail" if diagnostics else "pass",
            "complete": True,
            "checker": "mypy",
            "diagnostics": diagnostics,
            "summary": "mypy completed",
            "executable": str(executable),
            "executable_fingerprint": adapters._executable_fingerprint(str(executable)),
        }

    monkeypatch.setattr(comparison, "run_project_checker", run)
    return calls


def _run(root, **kwargs):
    return comparison.run_type_check(
        root, checker="mypy", comparison=open_comparison(root, None), **kwargs
    )


def test_stable_matching_error_remains_preexisting(project, monkeypatch):
    root, executable = project
    _checker(monkeypatch, root, executable, head=[_diagnostic()], base=[_diagnostic()])

    report = _run(root)

    assert report["status"] == "pass"
    assert report["complete"]
    assert report["diagnostics"][0]["origin"] == "preexisting"


@pytest.mark.parametrize("phase", ["head", "base"])
def test_configuration_mutation_during_checker_cannot_produce_a_pass(
    project, monkeypatch, phase
):
    root, executable = project

    def mutate(is_head):
        if is_head == (phase == "head"):
            (root / "mypy.ini").write_text(
                "[mypy]\nfiles = app.py\nignore_errors = True\n"
            )

    _checker(
        monkeypatch,
        root,
        executable,
        head=[_diagnostic()],
        base=[_diagnostic()],
        mutate=mutate,
    )

    report = _run(root)

    assert report["status"] == "incomplete"
    assert report["comparison"]["status"] == "incomplete"
    assert not report["complete"]
    assert all(d["origin"] != "preexisting" for d in report["diagnostics"])


def test_current_source_mutation_cannot_forgive_an_old_diagnostic(project, monkeypatch):
    root, executable = project
    (root / "app.py").write_text("value: int = 'edited'\n")

    def mutate(is_head):
        if is_head:
            (root / "app.py").write_text("value: int = 'base'\n")

    _checker(
        monkeypatch,
        root,
        executable,
        head=[_diagnostic()],
        base=[_diagnostic()],
        mutate=mutate,
    )

    report = _run(root)

    assert report["status"] != "pass"
    assert all(d["origin"] != "preexisting" for d in report["diagnostics"])


@pytest.mark.parametrize("variable", ["PYTHONPATH", "MYPYPATH"])
def test_baseline_refuses_environment_paths_to_current_sources(
    project, monkeypatch, variable
):
    root, executable = project
    monkeypatch.setenv(variable, str(root))
    _checker(monkeypatch, root, executable, head=[_diagnostic()], base=[_diagnostic()])

    report = _run(root)

    assert report["status"] == "incomplete"
    assert report["comparison"]["status"] == "incomplete"


def test_baseline_refuses_absolute_config_paths_to_current_sources(
    project, monkeypatch
):
    root, executable = project
    (root / "mypy.ini").write_text(f"[mypy]\nfiles = app.py\nmypy_path = {root}\n")
    _git(root, "add", "mypy.ini")
    _git(root, "commit", "-qm", "absolute source path")
    _checker(monkeypatch, root, executable, head=[_diagnostic()], base=[_diagnostic()])

    report = _run(root)

    assert report["status"] == "incomplete"
    assert report["comparison"]["status"] == "incomplete"


def test_baseline_refuses_symlink_alias_config_paths_to_current_sources(
    project, monkeypatch
):
    root, executable = project
    alias = root.parent / "source-alias"
    alias.symlink_to(root, target_is_directory=True)
    (root / "mypy.ini").write_text(f"[mypy]\nfiles = app.py\nmypy_path = {alias}\n")
    _git(root, "add", "mypy.ini")
    _git(root, "commit", "-qm", "aliased absolute source path")
    _checker(monkeypatch, root, executable, head=[_diagnostic()], base=[_diagnostic()])

    report = _run(root)

    assert report["status"] == "incomplete"
    assert report["comparison"]["status"] == "incomplete"


def test_baseline_has_only_the_remaining_shared_budget(project, monkeypatch):
    root, executable = project
    clock = [0.0]
    monkeypatch.setattr(
        comparison, "time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )

    def advance(is_head):
        if is_head:
            clock[0] += 7.0

    calls = _checker(
        monkeypatch,
        root,
        executable,
        head=[_diagnostic()],
        base=[_diagnostic()],
        mutate=advance,
    )

    report = _run(root, timeout_seconds=10)

    assert report["status"] == "pass"
    assert len(calls) == 2
    assert 0 < calls[1]["timeout"] <= 3


def test_different_column_is_not_confirmed_preexisting(project, monkeypatch):
    root, executable = project
    _checker(
        monkeypatch,
        root,
        executable,
        head=[_diagnostic(column=9)],
        base=[_diagnostic(column=1)],
    )

    report = _run(root)

    assert report["status"] == "fail"
    assert report["diagnostics"][0]["origin"] == "unclassified"


def test_selected_provider_keeps_new_error_in_an_unchanged_consumer(
    project, monkeypatch
):
    root, executable = project
    _checker(
        monkeypatch, root, executable, head=[_diagnostic(file="consumer.py")], base=[]
    )

    report = _run(root, target_files=[root / "app.py"])

    assert report["status"] == "fail"
    assert report["diagnostics"][0]["file"] == "consumer.py"
    assert report["diagnostics"][0]["origin"] == "introduced"
    assert report["diagnostics"][0]["scope"] == "dependency_impact"


def test_nested_checker_cannot_ignore_a_sibling_source_mutation(project, monkeypatch):
    root, executable = project
    nested = root / "pkg"
    nested.mkdir()
    (nested / "mypy.ini").write_text("[mypy]\nfiles = app.py\nmypy_path = ../shared\n")
    (nested / "app.py").write_text("import shared\n")
    shared = root / "shared"
    shared.mkdir()
    (shared / "types.py").write_text("value: int = 1\n")
    _git(root, "add", "pkg", "shared")
    _git(root, "commit", "-qm", "nested project")

    def mutate(is_head):
        if is_head:
            (shared / "types.py").write_text("value: str = 'changed'\n")

    _checker(
        monkeypatch,
        nested,
        executable,
        head=[_diagnostic()],
        base=[_diagnostic()],
        mutate=mutate,
    )

    report = comparison.run_type_check(
        nested, checker="mypy", comparison=open_comparison(root, None)
    )

    assert report["status"] == "incomplete"
    assert report["comparison"]["status"] == "incomplete"
