"""Shared behavior facts use supplied source snapshots without command or Git IO."""

from dataclasses import FrozenInstanceError
import hashlib
import io
from pathlib import Path
import subprocess

import pytest

from skylos.verification.comparison import (
    ComparisonScope,
    SourceSnapshot,
    compare_source_changes,
)


_IDENTITY = "def run(value):\n    return value\n"
_CHANGED = "def run(value):\n    return None\n"


def _snapshot(sources, *, hashes=None):
    if hashes is None:
        hashes = {
            name: hashlib.sha256(source.encode()).hexdigest()
            for name, source in sources.items()
        }
    return SourceSnapshot(sources=sources, hashes=hashes)


def _comparisons(result):
    return {(item["file"], item["symbol"]): item for item in result["comparisons"]}


def test_return_loss_preserves_explanation_as_behavior_facts():
    before = _snapshot(
        {"app.py": "def run(callback, value):\n    return callback(value)\n"}
    )
    after = _snapshot(
        {"app.py": "def run(callback, value):\n    callback(value)\n    return None\n"}
    )

    result = compare_source_changes(before, after)

    assert result["status"] == "different"
    assert result["changed_files"] == ["app.py"]
    comparison = _comparisons(result)[("app.py", "run")]
    assert comparison["status"] == "different"
    explanation = comparison["differences"][0]["explanation"]
    assert explanation["title"] == "Callback result discarded"
    assert "callback(value)" in explanation["before"]
    assert "None" in explanation["after"]
    assert result["runtime_witness"] is False
    assert {"base", "current", "exit_code", "tool"}.isdisjoint(result)
    assert not any("git" in text.lower() for text in result["assumptions"])


def test_extracted_helper_is_compared_through_existing_caller():
    before = _snapshot({"app.py": _IDENTITY})
    after = _snapshot(
        {
            "app.py": (
                "from helpers import identity\n\n"
                "def run(value):\n    return identity(value)\n"
            ),
            "helpers.py": "def identity(value):\n    return value\n",
        }
    )

    result = compare_source_changes(before, after)

    assert result["status"] == "equivalent"
    assert set(_comparisons(result)) == {("app.py", "run")}


@pytest.mark.parametrize("hash_mode", ["missing", "stale"])
def test_changed_helper_selects_unchanged_caller_even_without_reliable_hashes(
    hash_mode,
):
    app = (
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n"
    )
    before_sources = {
        "app.py": app,
        "helpers.py": "def identity(value):\n    return value\n",
    }
    after_sources = {
        "app.py": app,
        "helpers.py": "def identity(value):\n    return None\n",
    }
    hashes = (
        {} if hash_mode == "missing" else {name: "stale" for name in before_sources}
    )

    result = compare_source_changes(
        _snapshot(before_sources, hashes=hashes),
        _snapshot(after_sources, hashes=hashes),
        scope=ComparisonScope(selected="app.py", directory=False),
    )

    assert result["status"] == "different"
    assert result["changed_files"] == ["helpers.py"]
    assert set(_comparisons(result)) == {("app.py", "run")}
    assert _comparisons(result)[("app.py", "run")]["status"] == "different"


def test_python_hash_difference_alone_does_not_create_a_source_edit():
    sources = {"app.py": _IDENTITY}

    result = compare_source_changes(
        _snapshot(sources, hashes={"app.py": "original-encoded-bytes"}),
        _snapshot(sources, hashes={"app.py": "different-encoded-bytes"}),
    )

    assert result["status"] == "unchanged"
    assert result["changed_files"] == []
    assert result["comparisons"] == []


def test_snapshot_copies_inputs_and_preserves_supplied_byte_hashes():
    sources = {"app.py": _IDENTITY}
    hashes = {"app.py": "hash-of-original-bytes"}
    before = SourceSnapshot(sources=sources, hashes=hashes)
    after = _snapshot({"app.py": _CHANGED})
    sources["app.py"] = _CHANGED
    hashes["app.py"] = "mutated-by-caller"

    assert before.sources["app.py"] == _IDENTITY
    assert before.hashes["app.py"] == "hash-of-original-bytes"
    with pytest.raises(TypeError):
        before.sources["app.py"] = _CHANGED
    with pytest.raises(TypeError):
        before.hashes["app.py"] = "mutated"
    with pytest.raises(FrozenInstanceError):
        before.sources = {}

    result = compare_source_changes(before, after)
    assert result["status"] == "different"
    assert compare_source_changes(before, after) == result
    assert before.hashes["app.py"] == "hash-of-original-bytes"


def test_subdirectory_scope_excludes_generated_functions():
    names = ("app.py", "pkg/app.py", "pkg/generated/app.py")
    before = _snapshot({name: _IDENTITY for name in names})
    after = _snapshot({name: _CHANGED for name in names})
    excluded = {"generated"}
    scope = ComparisonScope(selected="pkg", exclude_folders=excluded)
    excluded.clear()

    result = compare_source_changes(before, after, scope=scope)

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {("pkg/app.py", "run")}
    assert scope.exclude_folders == frozenset({"generated"})


@pytest.mark.parametrize("parameter", ["value", "value: str"])
def test_excluded_selected_file_has_no_comparisons_even_with_unsupported_syntax(
    parameter,
):
    result = compare_source_changes(
        _snapshot({"generated/app.py": f"def run({parameter}):\n    return value\n"}),
        _snapshot({"generated/app.py": f"def run({parameter}):\n    return None\n"}),
        scope=ComparisonScope(
            selected="generated/app.py",
            directory=False,
            exclude_folders=frozenset({"generated"}),
        ),
    )

    assert result["status"] == "unchanged"
    assert result["comparisons"] == []
    assert result["reasons"] == []


def test_line_scope_selects_only_intersecting_changed_function():
    before = _snapshot(
        {
            "app.py": "def first(value):\n    return value\n\ndef second(value):\n    return value\n"
        }
    )
    after = _snapshot(
        {
            "app.py": "def first(value):\n    return None\n\ndef second(value):\n    return None\n"
        }
    )

    result = compare_source_changes(
        before,
        after,
        scope=ComparisonScope(selected="app.py", directory=False, line_range=(4, 5)),
    )

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {("app.py", "second")}


def test_environment_hash_change_qualifies_unchanged_python():
    sources = {"app.py": _IDENTITY}
    before = _snapshot(sources, hashes={"pyproject.toml": "old-environment-bytes"})
    after = _snapshot(sources, hashes={"pyproject.toml": "new-environment-bytes"})

    result = compare_source_changes(before, after)

    assert result["status"] == "unknown"
    assert any("pyproject.toml" in reason for reason in result["reasons"])
    assert result["changed_files"] == []
    assert _comparisons(result)[("app.py", "run")]["status"] == "equivalent"


def test_deleted_symbol_is_unknown_without_requiring_a_current_file():
    result = compare_source_changes(
        _snapshot({"removed.py": _IDENTITY}),
        _snapshot({}),
        scope=ComparisonScope(selected="removed.py", directory=False),
    )

    assert result["status"] == "unknown"
    assert result["changed_files"] == ["removed.py"]
    assert _comparisons(result)[("removed.py", "run")]["status"] == "unknown"


def test_function_budget_reports_unassessed_work_instead_of_completeness():
    before_source = "\n".join(
        f"def function_{index}(value):\n    return value\n" for index in range(129)
    )
    after_source = "\n".join(
        f"def function_{index}(value):\n    return None\n" for index in range(129)
    )

    result = compare_source_changes(
        _snapshot({"app.py": before_source}),
        _snapshot({"app.py": after_source}),
    )

    assert result["status"] == "unknown"
    assert len(result["comparisons"]) == 128
    assert all(item["status"] == "different" for item in result["comparisons"])
    assert any("budget exhausted" in reason.lower() for reason in result["reasons"])


def test_comparison_uses_no_filesystem_process_or_analyzer_io(monkeypatch):
    import skylos
    import skylos.analyzer

    before = _snapshot({"app.py": _IDENTITY})
    after = _snapshot({"app.py": _CHANGED})

    def unexpected_io(*args, **kwargs):
        raise AssertionError("Shared comparison must only inspect supplied source data")

    with monkeypatch.context() as blocked:
        blocked.setattr("builtins.open", unexpected_io)
        blocked.setattr(io, "open", unexpected_io)
        blocked.setattr(Path, "stat", unexpected_io)
        blocked.setattr(subprocess, "run", unexpected_io)
        blocked.setattr(subprocess, "Popen", unexpected_io)
        blocked.setattr(skylos, "analyze", unexpected_io)
        blocked.setattr(skylos.analyzer, "analyze", unexpected_io)
        result = compare_source_changes(before, after)

    assert result["status"] == "different"
