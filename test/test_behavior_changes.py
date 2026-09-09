"""Automatic behavior comparison observes Git sources, never fixture execution."""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
import shutil
import subprocess
from unittest.mock import Mock

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.verification.changes import compare_working_changes


_IDENTITY = "def run(value):\n    return value\n"


def _git(repo: Path, *args: str) -> str:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _write(repo: Path, name: str, source: str) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    _git(
        repo,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        message,
    )


def _register_local_submodule(repo: Path) -> Path:
    """Register an existing local nested repository without clone or transport."""
    dependency = repo / "dependency"
    dependency.mkdir()
    _git(dependency, "init", "-q")
    _write(dependency, "module.py", _IDENTITY)
    _git(dependency, "add", "--", "module.py")
    _commit(dependency, "dependency baseline")
    _write(
        repo,
        ".gitmodules",
        '[submodule "dependency"]\n\tpath = dependency\n\turl = ./dependency\n',
    )
    _git(repo, "add", "--", ".gitmodules", "dependency")
    _commit(repo, "register local dependency")
    return dependency


@pytest.fixture
def change_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is required")

    def create(files: dict[str, str]) -> tuple[Path, str]:
        repo = tmp_path / "automatic comparison project"
        repo.mkdir()
        _git(repo, "init", "-q")
        for name, source in files.items():
            _write(repo, name, source)
        _git(repo, "add", "--", *files)
        _commit(repo, "baseline")
        return repo, _git(repo, "rev-parse", "HEAD")

    return create


def _comparisons(result):
    return {(item["file"], item["symbol"]): item for item in result["comparisons"]}


def test_git_adapter_reuses_shared_service_once_and_preserves_byte_evidence(
    change_repo, monkeypatch
):
    import skylos.verification.changes as changes

    original = "# coding: latin-1\ndef run(value):\n    return value\n"
    repo, commit = change_repo({"app.py": original})
    changed_bytes = (
        "# coding: latin-1\ndef run(value):\n    return 'caf\u00e9'\n".encode("latin-1")
    )
    (repo / "app.py").write_bytes(changed_bytes)
    base_loader = Mock(wraps=changes._base_sources)
    current_loader = Mock(wraps=changes._current_sources)
    compare = changes.compare_source_changes
    recorded = []

    def record_comparison(*args, **kwargs):
        result = compare(*args, **kwargs)
        recorded.append(result)
        return result

    service = Mock(side_effect=record_comparison)
    monkeypatch.setattr(changes, "_base_sources", base_loader)
    monkeypatch.setattr(changes, "_current_sources", current_loader)
    monkeypatch.setattr(changes, "compare_source_changes", service)

    result = compare_working_changes(repo / "app.py")

    base_loader.assert_called_once()
    current_loader.assert_called_once()
    service.assert_called_once()
    before, after = service.call_args.args
    assert before.sources["app.py"] == original
    assert "caf\u00e9" in after.sources["app.py"]
    assert after.hashes["app.py"] == hashlib.sha256(changed_bytes).hexdigest()
    assert result["base"] == {
        "ref": "HEAD",
        "commit": commit,
        "source_hashes": {"app.py": hashlib.sha256(original.encode()).hexdigest()},
    }
    assert result["current"]["source_hashes"] == dict(after.hashes)
    for key, value in recorded[0].items():
        if key != "assumptions":
            assert result[key] == value
    assert result["status"] == "different"
    assert len(result["assumptions"]) == 4
    assert len(recorded[0]["assumptions"]) == 1
    assert result["assumptions"][:1] == recorded[0]["assumptions"]


@pytest.mark.parametrize("file_scope", [False, True], ids=["directory", "file"])
def test_changed_function_is_discovered_without_symbol_or_base(change_repo, file_scope):
    repo, commit = change_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", "def run(value):\n    return 'changed'\n")

    result = compare_working_changes(repo / "app.py" if file_scope else repo)

    assert result["status"] == "different"
    assert result["base"]["commit"] == commit
    assert _comparisons(result)[("app.py", "run")]["status"] == "different"


@pytest.mark.parametrize("file_scope", [False, True], ids=["directory", "file"])
def test_changed_imported_helper_includes_unchanged_caller(change_repo, file_scope):
    app = (
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n"
    )
    repo, _ = change_repo(
        {"app.py": app, "helpers.py": "def identity(value):\n    return value\n"}
    )
    _write(repo, "helpers.py", "def identity(value):\n    return 'changed'\n")

    result = compare_working_changes(repo / "app.py" if file_scope else repo)

    assert result["status"] == "different"
    assert _comparisons(result)[("app.py", "run")]["status"] == "different"


@pytest.mark.parametrize(
    "separate_file", [False, True], ids=["local", "untracked-module"]
)
def test_extracted_helper_is_covered_by_existing_function(change_repo, separate_file):
    repo, _ = change_repo({"app.py": _IDENTITY})
    helper = "def identity(value):\n    return value\n"
    if separate_file:
        _write(repo, "helpers.py", helper)
        prefix = "from helpers import identity\n\n"
    else:
        prefix = helper + "\n"
    _write(repo, "app.py", prefix + "def run(value):\n    return identity(value)\n")

    result = compare_working_changes(repo)

    assert result["status"] == "equivalent"
    assert _comparisons(result)[("app.py", "run")]["status"] == "equivalent"
    assert all(item["status"] == "equivalent" for item in result["comparisons"])


def test_new_helper_selected_alone_has_no_compared_caller_baseline(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY})
    _write(
        repo,
        "app.py",
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n",
    )
    _write(repo, "helpers.py", "def identity(value):\n    return value\n")

    result = compare_working_changes(repo / "helpers.py")

    assert result["status"] == "unknown"
    assert ("app.py", "run") not in _comparisons(result)
    assert _comparisons(result)[("helpers.py", "identity")]["status"] == "unknown"


def test_deleted_public_function_is_not_silently_ignored(change_repo):
    repo, _ = change_repo(
        {"app.py": _IDENTITY + "\ndef previously_available(value):\n    return value\n"}
    )
    _write(repo, "app.py", _IDENTITY)

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"
    assert result["reasons"] or any(
        item["status"] == "unknown" for item in result["comparisons"]
    )


def test_new_independent_function_has_no_baseline(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", _IDENTITY + "\ndef new_entry(value):\n    return value\n")

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"
    assert result["reasons"] or any(
        item["status"] == "unknown" for item in result["comparisons"]
    )


def test_clean_working_tree_needs_no_behavior_obligation(change_repo):
    repo, commit = change_repo({"app.py": _IDENTITY})

    result = compare_working_changes(repo)

    assert result["status"] == "unchanged"
    assert result["base"]["commit"] == commit
    assert result["comparisons"] == []


def test_non_git_project_reports_baseline_unavailable(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(_IDENTITY, encoding="utf-8")

    result = compare_working_changes(tmp_path)

    assert result["status"] == "unavailable"
    assert result["reasons"]


def test_changed_module_state_cannot_report_unchanged(change_repo):
    repo, _ = change_repo({"app.py": "MODE = 'before'\n\n" + _IDENTITY})
    _write(repo, "app.py", "MODE = 'after'\n\n" + _IDENTITY)

    result = compare_working_changes(repo)

    assert result["status"] in {"different", "unknown"}


def test_import_binding_change_cannot_hide_behind_unchanged_function_ast(change_repo):
    function = "\ndef run(value):\n    return emit(value)\n"
    repo, _ = change_repo({"app.py": "from old_fixture_api import emit\n" + function})
    _write(repo, "app.py", "from new_fixture_api import emit\n" + function)

    result = compare_working_changes(repo)

    assert result["status"] in {"different", "unknown"}
    assert ("app.py", "run") in _comparisons(result)


def test_dependency_change_with_unchanged_python_requires_qualification(change_repo):
    repo, _ = change_repo(
        {"app.py": _IDENTITY, "requirements.txt": "fixture-dependency==1.0\n"}
    )
    _write(repo, "requirements.txt", "fixture-dependency==2.0\n")

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"
    assert result["reasons"]


def test_line_range_limits_obligations_to_selected_function(change_repo):
    before = (
        "def first(value):\n    return value\n\ndef second(value):\n    return value\n"
    )
    after = "def first(value):\n    return 'changed'\n\ndef second(value):\n    return value\n"
    repo, _ = change_repo({"app.py": before})
    _write(repo, "app.py", after)

    result = compare_working_changes(repo / "app.py", line_range="4:5")

    assert result["status"] in {"unchanged", "equivalent"}
    assert ("app.py", "first") not in _comparisons(result)


def test_directory_file_scope_rejects_parent_escape(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY, "pkg/app.py": _IDENTITY})

    with pytest.raises(ValueError):
        compare_working_changes(repo / "pkg", file="../app.py")


def test_selected_subdirectory_uses_repository_relative_file_identity(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY, "pkg/app.py": _IDENTITY})
    _write(repo, "pkg/app.py", "def run(value):\n    return 'changed'\n")

    result = compare_working_changes(repo / "pkg", file="app.py")

    assert result["status"] == "different"
    assert ("pkg/app.py", "run") in _comparisons(result)
    assert ("app.py", "run") not in _comparisons(result)


def test_module_source_is_never_executed(change_repo, tmp_path):
    repo, _ = change_repo({"app.py": _IDENTITY})
    marker = tmp_path / "fixture must not run"
    _write(repo, "app.py", f"open({str(marker)!r}, 'w').write('ran')\n\n" + _IDENTITY)

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"
    assert not marker.exists()


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "class Worker:\n    def run(self, value):\n        return value\n",
            "class Worker:\n    def run(self, value):\n        return 'changed'\n",
        ),
        (
            "async def run(value):\n    return value\n",
            "async def run(value):\n    return 'changed'\n",
        ),
    ],
    ids=["method", "async-function"],
)
def test_changed_unsupported_function_shape_is_not_ignored(change_repo, before, after):
    repo, _ = change_repo({"app.py": before})
    _write(repo, "app.py", after)

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"


def test_deleted_python_module_is_not_ignored(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY, "removed.py": _IDENTITY})
    (repo / "removed.py").unlink()

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"


def test_comments_and_formatting_do_not_create_a_behavior_difference(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY})
    _write(
        repo,
        "app.py",
        "# Explanation\n\ndef run(value):\n    return (value)  # Same result\n",
    )

    result = compare_working_changes(repo)

    assert result["status"] in {"equivalent", "unchanged"}


def test_reordered_effectful_function_headers_are_not_treated_as_formatting(
    change_repo,
):
    first = "def first(value=record('first')):\n    return value\n"
    second = "def second(value=record('second')):\n    return value\n"
    repo, _ = change_repo({"app.py": first + "\n" + second})
    _write(repo, "app.py", second + "\n" + first)

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"


def test_line_scoped_caller_includes_changed_same_module_helper(change_repo):
    before = (
        "def helper(value):\n    return value\n\n"
        "def run(value):\n    callback = helper\n    return callback(value)\n"
    )
    after = before.replace("return value", "return 'changed'", 1)
    repo, _ = change_repo({"app.py": before})
    _write(repo, "app.py", after)

    result = compare_working_changes(repo / "app.py", line_range="4:6")

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {("app.py", "run")}


def test_unsupported_global_alias_cannot_hide_changed_helper_from_scoped_caller(
    change_repo,
):
    before = (
        "def helper(value):\n    return value\n\n"
        "callback = helper\n\n"
        "def run(value):\n    return callback(value)\n"
    )
    after = before.replace("return value", "return 'changed'", 1)
    repo, _ = change_repo({"app.py": before})
    _write(repo, "app.py", after)

    result = compare_working_changes(repo / "app.py", line_range="6:7")

    assert result["status"] == "unknown"


def test_unchanged_registered_submodule_allows_application_comparison(change_repo):
    repo, _ = change_repo({"app.py": _IDENTITY})
    _register_local_submodule(repo)
    _write(repo, "app.py", "def run(value):\n    return 'changed'\n")

    result = compare_working_changes(repo)

    assert result["status"] == "different"
    assert _comparisons(result)[("app.py", "run")]["status"] == "different"
    assert "dependency/module.py" not in result["base"]["source_hashes"]
    assert any("submodule" in assumption for assumption in result["assumptions"])


@pytest.mark.parametrize(
    "commit_dependency", [False, True], ids=["dirty", "new-commit"]
)
def test_changed_registered_submodule_requires_qualification(
    change_repo, commit_dependency
):
    repo, _ = change_repo({"app.py": _IDENTITY})
    dependency = _register_local_submodule(repo)
    _write(dependency, "module.py", "def run(value):\n    return 'changed'\n")
    if commit_dependency:
        _git(dependency, "add", "--", "module.py")
        _commit(dependency, "dependency behavior changed")

    result = compare_working_changes(repo)

    assert result["status"] == "unknown"
    assert any("submodule" in reason for reason in result["reasons"])
