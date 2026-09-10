"""Shared behavior facts use supplied source snapshots without command or Git IO."""

from dataclasses import FrozenInstanceError
import hashlib
import io
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

from skylos.verification import comparison
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


def test_overlapping_scopes_compare_each_function_once(monkeypatch):
    names = ("pkg/app.py", "pkg/other.py")
    compare = Mock(wraps=comparison.compare_python_behavior)
    monkeypatch.setattr(comparison, "compare_python_behavior", compare)
    monkeypatch.setattr(comparison, "_MAX_COMPARISONS", 2)
    file_scope = ComparisonScope(selected="pkg/app.py", directory=False)

    result = compare_source_changes(
        _snapshot({name: _IDENTITY for name in names}),
        _snapshot({name: _CHANGED for name in names}),
        scopes=[ComparisonScope(selected="pkg"), file_scope, file_scope],
    )

    assert result["status"] == "different"
    assert result["reasons"] == []
    assert set(_comparisons(result)) == {(name, "run") for name in names}
    assert len(result["comparisons"]) == compare.call_count == 2


def test_disjoint_scopes_share_source_indexing(monkeypatch):
    names = ("first/app.py", "second/app.py", "unselected.py")
    index = Mock(wraps=comparison._index)
    monkeypatch.setattr(comparison, "_index", index)

    result = compare_source_changes(
        _snapshot({name: _IDENTITY for name in names}),
        _snapshot({name: _CHANGED for name in names}),
        scopes=[ComparisonScope(selected="first"), ComparisonScope(selected="second")],
    )

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {
        ("first/app.py", "run"),
        ("second/app.py", "run"),
    }
    calls = [call.args for call in index.call_args_list]
    for name in names:
        assert calls.count((name, _IDENTITY)) == 1
        assert calls.count((name, _CHANGED)) == 1


def test_each_scope_keeps_its_own_line_range_and_exclusions():
    before_source = (
        "def first(value):\n    return value\n\n"
        "def second(value):\n    return value\n\n"
        "def third(value):\n    return value\n"
    )
    after_source = before_source.replace("return value", "return None")
    names = ("pkg/app.py", "pkg/generated/app.py", "pkg/private/app.py")

    result = compare_source_changes(
        _snapshot({name: before_source for name in names}),
        _snapshot({name: after_source for name in names}),
        scopes=[
            ComparisonScope(
                selected="pkg",
                line_range=(1, 2),
                exclude_folders=frozenset({"generated"}),
            ),
            ComparisonScope(
                selected="pkg/generated/app.py",
                directory=False,
                line_range=(4, 5),
            ),
            ComparisonScope(
                selected="pkg",
                line_range=(7, 8),
                exclude_folders=frozenset({"generated", "private"}),
            ),
        ],
    )

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {
        ("pkg/app.py", "first"),
        ("pkg/app.py", "third"),
        ("pkg/generated/app.py", "second"),
        ("pkg/private/app.py", "first"),
    }


def test_multiple_scopes_include_unchanged_callers_of_changed_unselected_helper():
    caller = (
        "from helpers import identity\n\ndef run(value):\n    return identity(value)\n"
    )
    callers = {"first.py": caller, "second.py": caller, "unselected.py": caller}

    result = compare_source_changes(
        _snapshot(
            {**callers, "helpers.py": "def identity(value):\n    return value\n"}
        ),
        _snapshot({**callers, "helpers.py": "def identity(value):\n    return None\n"}),
        scopes=[
            ComparisonScope(selected="first.py", directory=False),
            ComparisonScope(selected="second.py", directory=False),
        ],
    )

    assert result["status"] == "different"
    assert result["changed_files"] == ["helpers.py"]
    assert set(_comparisons(result)) == {("first.py", "run"), ("second.py", "run")}
    assert all(item["status"] == "different" for item in result["comparisons"])


def test_helper_selected_by_another_scope_is_covered_by_existing_caller():
    result = compare_source_changes(
        _snapshot({"app.py": _IDENTITY}),
        _snapshot(
            {
                "app.py": (
                    "from helpers import identity\n\n"
                    "def run(value):\n    return identity(value)\n"
                ),
                "helpers.py": "def identity(value):\n    return value\n",
            }
        ),
        scopes=[
            ComparisonScope(selected="app.py", directory=False),
            ComparisonScope(selected="helpers.py", directory=False),
        ],
    )

    assert result["status"] == "equivalent"
    assert set(_comparisons(result)) == {("app.py", "run")}


def test_multiple_scopes_share_one_function_budget(monkeypatch):
    before_source = "\n".join(
        f"def function_{index}(value):\n    return value\n" for index in range(3)
    )
    after_source = before_source.replace("return value", "return None")
    names = ("first.py", "second.py")
    monkeypatch.setattr(comparison, "_MAX_COMPARISONS", 4)

    result = compare_source_changes(
        _snapshot({name: before_source for name in names}),
        _snapshot({name: after_source for name in names}),
        scopes=[ComparisonScope(selected=name, directory=False) for name in names],
    )

    assert result["status"] == "unknown"
    assert len(result["comparisons"]) == len(_comparisons(result)) == 4
    assert result["limits"]["functions"] == 4
    assert result["reasons"] == ["Affected function budget exhausted (limit 4)"]


def test_environment_change_qualifies_every_selected_scope_once():
    sources = {name: _IDENTITY for name in ("first.py", "second.py", "unselected.py")}

    result = compare_source_changes(
        _snapshot(sources, hashes={"pyproject.toml": "before"}),
        _snapshot(sources, hashes={"pyproject.toml": "after"}),
        scopes=[
            ComparisonScope(selected="first.py", directory=False),
            ComparisonScope(selected="second.py", directory=False),
        ],
    )

    assert result["status"] == "unknown"
    assert set(_comparisons(result)) == {("first.py", "run"), ("second.py", "run")}
    assert result["reasons"] == [
        "Dependency or Python environment files changed: pyproject.toml"
    ]


@pytest.mark.parametrize("use_scopes", [False, True])
def test_single_scope_preserves_unsupported_file_fastpath(monkeypatch, use_scopes):
    index = Mock(wraps=comparison._index)
    monkeypatch.setattr(comparison, "_index", index)
    selected = ComparisonScope(selected="app.py", directory=False)

    result = compare_source_changes(
        _snapshot(
            {
                "app.py": "def run(value: str):\n    return value\n",
                "other.py": _IDENTITY,
            }
        ),
        _snapshot(
            {"app.py": "def run(value: str):\n    return None\n", "other.py": _CHANGED}
        ),
        **({"scopes": [selected]} if use_scopes else {"scope": selected}),
    )

    assert result["status"] == "unknown"
    assert set(_comparisons(result)) == {("app.py", "run")}
    assert [call.args[0] for call in index.call_args_list] == ["app.py", "app.py"]


def test_scope_and_scopes_cannot_be_supplied_together():
    snapshot = _snapshot({"app.py": _IDENTITY})

    with pytest.raises(ValueError, match="either scope or scopes"):
        compare_source_changes(
            snapshot, snapshot, scope=ComparisonScope(), scopes=[ComparisonScope()]
        )


def test_empty_scopes_do_not_default_to_whole_repository():
    with pytest.raises(ValueError, match="At least one comparison scope"):
        compare_source_changes(
            _snapshot({"app.py": _IDENTITY}),
            _snapshot({"app.py": _CHANGED}),
            scopes=[],
        )


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


@pytest.mark.parametrize("multiple_scopes", [False, True])
def test_comparison_uses_no_filesystem_process_or_analyzer_io(
    monkeypatch, multiple_scopes
):
    import skylos
    import skylos.analyzer

    before = _snapshot({"app.py": _IDENTITY, "pkg/app.py": _IDENTITY})
    after = _snapshot({"app.py": _CHANGED, "pkg/app.py": _CHANGED})
    scopes = (
        [
            ComparisonScope(selected="app.py", directory=False),
            ComparisonScope(selected="pkg"),
        ]
        if multiple_scopes
        else None
    )

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
        result = compare_source_changes(before, after, scopes=scopes)

    assert result["status"] == "different"
    assert set(_comparisons(result)) == {("app.py", "run"), ("pkg/app.py", "run")}
