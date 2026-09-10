"""Compare Git snapshots without importing or executing fixture applications."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from skylos.commands.verify_cmd import run_verify_command
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.verification import refactor
from skylos.verification.refactor import verify_refactor
from skylos.verify_change import verify_change_path


_GIT_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
)
_IDENTITY = "def run(value):\n    return value\n"


def _git(repo: Path, *args: str) -> str:
    env = dict(os.environ)
    for key in _GIT_ENV:
        env.pop(key, None)
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


@pytest.fixture
def make_repo(tmp_path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git is required")
    for key in _GIT_ENV:
        monkeypatch.delenv(key, raising=False)

    def create(files: dict[str, str]) -> tuple[Path, str]:
        repo = tmp_path / "refactor project"
        repo.mkdir()
        _git(repo, "init", "-q")
        for name, source in files.items():
            _write(repo, name, source)
        _git(repo, "add", "--", *files)
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
            "baseline",
        )
        return repo, _git(repo, "rev-parse", "HEAD")

    return create


def test_unchanged_symbol_records_snapshot_identity(make_repo):
    repo, commit = make_repo({"app.py": _IDENTITY})

    result = verify_refactor(repo, base="HEAD", file="app.py", symbol="run")

    assert result["tool"] == "verify_behavior"
    assert result["status"] == "pass"
    assert result["comparison"]["status"] == "equivalent"
    assert result["base"]["commit"] == commit
    digest = hashlib.sha256(_IDENTITY.encode()).hexdigest()
    assert result["base"]["source_hashes"]["app.py"] == digest
    assert result["current"]["source_hashes"]["app.py"] == digest
    assert result["findings"] == []
    assert result["summary"]
    assert result["coverage"]


def test_extracting_local_helper_preserves_behavior(make_repo):
    repo, commit = make_repo({"app.py": _IDENTITY})
    _write(
        repo,
        "app.py",
        "def identity(value):\n    return value\n\n"
        "def run(value):\n    return identity(value)\n",
    )

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "pass"
    assert result["comparison"]["status"] == "equivalent"
    assert result["base"]["source_hashes"] != result["current"]["source_hashes"]


@pytest.mark.parametrize(
    "current_body",
    ["    return emit('different')\n", "    emit(value)\n"],
    ids=["changed-call-argument", "dropped-return-value"],
)
def test_changed_external_effect_or_return_fails(make_repo, current_body):
    imports = "from unavailable_fixture_library import emit\n\n"
    repo, commit = make_repo(
        {"app.py": imports + "def run(value):\n    return emit(value)\n"}
    )
    _write(repo, "app.py", imports + "def run(value):\n" + current_body)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "fail"
    assert result["comparison"]["status"] == "different"
    assert result["findings"]


def test_imported_helper_change_is_detected_without_entry_file_change(make_repo):
    app = (
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n"
    )
    repo, commit = make_repo(
        {"app.py": app, "helpers.py": "def identity(value):\n    return value\n"}
    )
    _write(repo, "helpers.py", "def identity(value):\n    return 'different'\n")

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "fail"
    assert result["comparison"]["status"] == "different"
    before = result["base"]["source_hashes"]
    after = result["current"]["source_hashes"]
    assert before["app.py"] == after["app.py"]
    assert before["helpers.py"] != after["helpers.py"]


@pytest.mark.parametrize(
    "manifest,before,after",
    [
        ("requirements.txt", "example-library==1.0\n", "example-library==2.0\n"),
        ("requirements/base.txt", "example-library==1.0\n", "example-library==2.0\n"),
        (
            "pyproject.toml",
            '[project]\nname = "fixture"\ndependencies = ["example-library==1.0"]\n',
            '[project]\nname = "fixture"\ndependencies = ["example-library==2.0"]\n',
        ),
    ],
)
def test_changed_dependency_environment_prevents_equivalence(
    make_repo, manifest, before, after
):
    repo, commit = make_repo({"app.py": _IDENTITY, manifest: before})
    _write(repo, manifest, after)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert result["comparison"]["status"] == "unknown"
    assert result["base"]["source_hashes"] == result["current"]["source_hashes"]
    assert (
        result["base"]["environment_hashes"] != result["current"]["environment_hashes"]
    )


def test_extraction_into_untracked_helper_is_included(make_repo):
    repo, commit = make_repo({"app.py": _IDENTITY})
    _write(
        repo,
        "app.py",
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n",
    )
    _write(repo, "helpers.py", "def identity(value):\n    return value\n")
    assert _git(repo, "ls-files", "--", "helpers.py") == ""

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "pass"
    assert result["comparison"]["status"] == "equivalent"
    assert "helpers.py" not in result["base"]["source_hashes"]
    assert "helpers.py" in result["current"]["source_hashes"]


@pytest.mark.parametrize(
    "overrides",
    [{"base": "missing-revision"}, {"base": "--help"}, {"file": "app.ts"}],
    ids=["missing-base", "option-like-base", "unsupported-file-type"],
)
def test_invalid_snapshot_inputs_are_rejected(make_repo, overrides):
    repo, commit = make_repo({"app.py": _IDENTITY})
    options = {"base": commit, "file": "app.py", "symbol": "run", **overrides}

    with pytest.raises(ValueError):
        verify_refactor(repo, **options)


@pytest.mark.parametrize("file,symbol", [("app.py", "missing"), ("missing.py", "run")])
def test_missing_obligation_target_is_incomplete(make_repo, file, symbol):
    repo, commit = make_repo({"app.py": _IDENTITY})

    result = verify_refactor(repo, base=commit, file=file, symbol=symbol)

    assert result["status"] == "incomplete"
    assert result["comparison"]["status"] == "unknown"


def test_symlinked_import_is_not_used_as_source(make_repo, tmp_path):
    repo, commit = make_repo(
        {
            "app.py": "from helpers import identity\n\ndef run(value):\n    return identity(value)\n",
            "helpers.py": "def identity(value):\n    return value\n",
        }
    )
    outside = tmp_path / "external helper.py"
    outside.write_text("def identity(value):\n    return value\n", encoding="utf-8")
    (repo / "helpers.py").unlink()
    (repo / "helpers.py").symlink_to(outside)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert result["comparison"]["status"] == "unknown"
    assert "helpers.py" not in result["current"]["source_hashes"]


def test_working_snapshot_preserves_encoded_bytes_and_line_endings(make_repo):
    repo, _ = make_repo({"app.py": _IDENTITY})
    source = "# coding: latin-1\r\ndef run(value):\r\n    return 'caf\xe9'\r\n"
    assert write_text_no_symlink(repo / "app.py", source, encoding="latin-1")

    sources, hashes = refactor._current_sources(repo)

    assert sources["app.py"] == source
    assert hashes["app.py"] == hashlib.sha256(source.encode("latin-1")).hexdigest()


@pytest.mark.parametrize("multiple_files", [False, True])
def test_explicit_ignored_files_share_one_working_snapshot(
    make_repo, monkeypatch, multiple_files
):
    repo, _ = make_repo({"app.py": _IDENTITY, ".gitignore": "generated/\n"})
    ignored = {
        "generated/first.py": _IDENTITY,
        "generated/second.py": "def run(value):\n    return None\n",
        "generated/unselected.py": _IDENTITY,
    }
    for name, source in ignored.items():
        _write(repo, name, source)
    assert set(_git(repo, "check-ignore", "--", *ignored).splitlines()) == set(ignored)
    selected = (
        ("generated/first.py", "generated/second.py", "generated/first.py")
        if multiple_files
        else "generated/first.py"
    )
    reader = Mock(wraps=refactor._read_working_source)
    monkeypatch.setattr(refactor, "_read_working_source", reader)

    sources, hashes = refactor._current_sources(repo, selected)

    expected = {"app.py": _IDENTITY, "generated/first.py": _IDENTITY}
    if multiple_files:
        expected["generated/second.py"] = ignored["generated/second.py"]
    assert sources == expected
    assert hashes == {
        name: hashlib.sha256(source.encode()).hexdigest()
        for name, source in expected.items()
    }
    assert sorted(call.args[1] for call in reader.call_args_list) == sorted(expected)


@pytest.mark.parametrize("name", ["../app.py", "/app.py", ".", "\0"])
def test_explicit_file_tuple_rejects_unsafe_member(make_repo, name):
    repo, _ = make_repo({"app.py": _IDENTITY})

    with pytest.raises(ValueError, match="Unsafe path"):
        refactor._current_sources(repo, ("app.py", name))


def test_explicit_ignored_files_count_toward_snapshot_limit(make_repo, monkeypatch):
    repo, _ = make_repo({"app.py": _IDENTITY, ".gitignore": "generated/\n"})
    selected = ("generated/first.py", "generated/second.py")
    for name in selected:
        _write(repo, name, _IDENTITY)
    monkeypatch.setattr(refactor, "_MAX_FILES", 2)

    with pytest.raises(ValueError, match="verification file limit"):
        refactor._current_sources(repo, selected)


def test_deleted_working_source_is_absent_from_snapshot(make_repo):
    repo, _ = make_repo({"app.py": _IDENTITY, "pkg/helper.py": _IDENTITY})
    (repo / "pkg/helper.py").unlink()
    (repo / "pkg").rmdir()

    sources, hashes = refactor._current_sources(repo)

    assert sources == {"app.py": _IDENTITY}
    assert set(hashes) == {"app.py"}


def test_symlinked_source_directory_is_rejected_even_within_repository(make_repo):
    repo, commit = make_repo({"app.py": _IDENTITY, "pkg/helper.py": _IDENTITY})
    (repo / "pkg").rename(repo / "saved")
    (repo / "pkg").symlink_to(repo / "saved", target_is_directory=True)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert (
        "Cannot read working source: pkg/helper.py" in result["comparison"]["reasons"]
    )
    assert not result["current"]["source_hashes"]


def test_working_snapshot_rejects_symlinked_root(make_repo, tmp_path):
    repo, _ = make_repo({"app.py": _IDENTITY})
    alias = tmp_path / "repository alias"
    alias.symlink_to(repo, target_is_directory=True)

    with pytest.raises(ValueError, match="Cannot open working source snapshot root"):
        refactor._current_sources(alias)


def test_unreadable_working_source_is_incomplete_instead_of_deleted(
    make_repo, monkeypatch
):
    repo, commit = make_repo({"app.py": _IDENTITY})
    real_open = os.open

    def unreadable_source(path, flags, *args, **kwargs):
        if path == "app.py" and kwargs.get("dir_fd") is not None:
            raise PermissionError("fixture denied")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", unreadable_source)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, unreadable_source})

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert "Cannot read working source: app.py" in result["comparison"]["reasons"]


def test_working_source_descriptor_allocation_failure_is_incomplete(
    make_repo, monkeypatch
):
    repo, commit = make_repo({"app.py": _IDENTITY})

    def exhausted_descriptors(fd):
        raise OSError("fixture descriptor allocation failed")

    monkeypatch.setattr(os, "dup", exhausted_descriptors)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert result["comparison"]["reasons"] == ["Cannot read working source: app.py"]
    assert not result["current"]["source_hashes"]


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_nonregular_working_source_is_rejected(make_repo, kind):
    if kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are unavailable")
    repo, commit = make_repo({"app.py": _IDENTITY, "helper.py": _IDENTITY})
    helper = repo / "helper.py"
    helper.unlink()
    if kind == "directory":
        helper.mkdir()
    else:
        os.mkfifo(helper)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert (
        "Working source is not a regular file: helper.py"
        in result["comparison"]["reasons"]
    )


@pytest.mark.parametrize("limit", ["_MAX_FILE_BYTES", "_MAX_SOURCE_BYTES"])
def test_working_snapshot_read_limits_are_preserved(make_repo, monkeypatch, limit):
    repo, _ = make_repo({"app.py": _IDENTITY})
    monkeypatch.setattr(refactor, limit, len(_IDENTITY.encode()) - 1)

    with pytest.raises(ValueError, match="verification size limit"):
        refactor._current_sources(repo)


def test_working_snapshot_detects_changed_metadata(make_repo, monkeypatch):
    repo, _ = make_repo({"app.py": _IDENTITY})
    real_fstat = os.fstat
    observed = 0

    def changed_metadata(fd):
        nonlocal observed
        result = real_fstat(fd)
        observed += 1
        return SimpleNamespace(
            st_mode=result.st_mode,
            st_size=result.st_size,
            st_mtime_ns=result.st_mtime_ns,
            st_ctime_ns=result.st_ctime_ns + (observed > 1),
        )

    monkeypatch.setattr(os, "fstat", changed_metadata)

    with pytest.raises(ValueError, match="Working source changed while being read"):
        refactor._current_sources(repo)


def test_working_snapshot_requires_descriptor_relative_no_follow_support(
    make_repo, monkeypatch
):
    repo, commit = make_repo({"app.py": _IDENTITY})
    monkeypatch.setattr(os, "supports_dir_fd", set())

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert (
        "Platform does not support safe working source snapshot reads"
        in result["comparison"]["reasons"]
    )


@pytest.mark.parametrize("name", ["../app.py", "/app.py", ".", "\0"])
def test_working_source_rejects_unsafe_relative_names_before_opening(name):
    with pytest.raises(ValueError, match="Unsafe path"):
        refactor._read_working_source(-1, name)


def test_subdirectory_scope_selects_its_file_and_rejects_parent_escape(make_repo):
    repo, commit = make_repo({"app.py": _IDENTITY, "pkg/app.py": _IDENTITY})
    _write(repo, "pkg/app.py", "def run(value):\n    return 'different'\n")

    result = verify_refactor(repo / "pkg", base=commit, file="app.py", symbol="run")

    assert result["status"] == "fail"
    assert result["comparison"]["status"] == "different"
    assert result["target"]["file"] == "pkg/app.py"
    assert "pkg/app.py" in result["current"]["source_hashes"]
    with pytest.raises(ValueError):
        verify_refactor(repo / "pkg", base=commit, file="../app.py", symbol="run")


@pytest.mark.parametrize(
    "source",
    [
        "def run(value):\n    for item in value:\n        print(item)\n    return value\n",
        "def run(value):\n    return (\n",
    ],
    ids=["unsupported-loop", "invalid-syntax"],
)
def test_unmodeled_or_invalid_source_is_incomplete(make_repo, source):
    repo, commit = make_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", source)

    result = verify_refactor(repo, base=commit, file="app.py", symbol="run")

    assert result["status"] == "incomplete"
    assert result["comparison"]["status"] == "unknown"


@pytest.mark.parametrize("has_ai_finding", [False, True])
@pytest.mark.parametrize("target_mode", ["file", "directory"])
def test_verify_change_adds_behavior_comparison_to_analyzer_result(
    make_repo, has_ai_finding, target_mode
):
    repo, _ = make_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", "def run(value):\n    return 'different'\n")
    target = repo / "app.py" if target_mode == "file" else repo
    calls = []

    def analyzer(path, **kwargs):
        calls.append(path)
        if not has_ai_finding:
            return {}
        return {
            "ai_defects": [
                {
                    "rule_id": "SKY-L012",
                    "file": str(repo / "app.py"),
                    "line": 2,
                    "message": "Missing call target.",
                    "severity": "HIGH",
                }
            ]
        }

    result = verify_change_path(
        target,
        analyze_func=analyzer,
    )

    assert calls == [str(target)]
    assert result["schema_version"] == 2
    assert result["tool"] == "verify_change"
    assert result["status"] == ("fail" if has_ai_finding else "incomplete")
    assert result["behavior"]["status"] == "different"
    assert result["behavior"]["comparisons"]
    assert bool(result["findings"]) is has_ai_finding


@pytest.mark.parametrize(
    "source,behavior_status,no_fail,expected_exit",
    [
        ("def run(value):\n    return 'different'\n", "different", False, 2),
        ("def run(value):\n    return 'different'\n", "different", True, 0),
        ("def run(value):\n    while value:\n        pass\n", "unknown", False, 2),
        ("def run(value):\n    while value:\n        pass\n", "unknown", True, 0),
    ],
)
def test_normal_verify_cli_compares_behavior_and_applies_exit_policy(
    make_repo, capsys, source, behavior_status, no_fail, expected_exit
):
    repo, _ = make_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", source)

    exit_code = run_verify_command(
        [
            str(repo / "app.py"),
            *(["--no-fail"] if no_fail else []),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert exit_code == expected_exit
    assert result["tool"] == "verify_change"
    assert result["status"] == "incomplete"
    assert result["behavior"]["status"] == behavior_status
    assert result["behavior"]["comparisons"]


def test_cli_entry_point_infers_behavior_comparison_without_flags(make_repo):
    repo, _ = make_repo({"app.py": _IDENTITY})
    _write(repo, "app.py", "def run(value):\n    return 'different'\n")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from skylos.cli import main; main()",
            "verify",
            str(repo / "app.py"),
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2, completed.stderr
    result = json.loads(completed.stdout)
    assert result["tool"] == "verify_change"
    assert result["status"] == "incomplete"
    assert result["behavior"]["status"] == "different"
    assert result["behavior"]["comparisons"]
