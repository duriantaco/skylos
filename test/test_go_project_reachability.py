"""General source contracts distilled from real Go repository comparisons."""

import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.analysis.penalties import _check_non_library_path
from skylos.engines.go_runner import GoEngineError, run_go_engine_for_module
from skylos.visitors.base import Definition
from skylos.visitors.languages.go import clear_go_cache


FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks/dead_code/fixtures"
CASES = {
    "go_project_import_graph": {
        "unused": {"worker.alpha", "worker.beta", "worker.orphan"},
        "used": {"provider.Touch", "worker.Factory", "worker.callback"},
    },
    "go_private_test_helpers": {
        "unused": {"unusedProduction", "alpha", "beta", "stale"},
        "used": {"core", "liveTestHelper", "testLeaf"},
    },
}


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("grep_verify", [False, True])
def test_go_project_import_and_private_test_helper_reachability(
    tmp_path, monkeypatch, case_id, grep_verify
):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    path = tmp_path / case_id
    shutil.copytree(FIXTURES / case_id, path)
    try:
        native = run_go_engine_for_module(path)
    except GoEngineError as exc:
        if "missing/invalid" in str(exc):
            raise
        pytest.skip(f"requires the source-built Go engine: {exc}")
    states = {
        item["name"]: item.get("reachability") for item in native["symbols"]["defs"]
    }
    expected = CASES[case_id]
    assert {name: states.get(name) for name in expected["unused"]} == {
        name: "unreachable" for name in expected["unused"]
    }
    assert {name: states.get(name) for name in expected["used"]} == {
        name: "reachable" for name in expected["used"]
    }
    clear_go_cache()
    report = json.loads(
        analyze(
            str(path),
            conf=60,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    assert {
        item["full_name"] for item in report.get("unused_functions", [])
    } == expected["unused"]
    assert all(item["listing"]["listed"] for item in report["unused_functions"])


@pytest.mark.parametrize(
    "relative, proven, kind, exported, config, reported",
    [
        ("helper_test.go", True, "function", False, {}, True),
        ("tests/helper_test.go", True, "function", False, {}, True),
        ("helper_test.go", False, "function", False, {}, False),
        ("helper_test.go", True, "method", False, {}, False),
        ("helper_test.go", True, "function", True, {}, False),
        ("test_helper.py", True, "function", False, {}, False),
        ("tests/examples/helper_test.go", True, "function", False, {}, False),
        ("docs/helper_test.go", True, "function", False, {}, False),
        (
            "custom/helper_test.go",
            True,
            "function",
            False,
            {"non_library_dirs": {"custom": "test"}},
            False,
        ),
        (
            "custom/helper_test.go",
            True,
            "function",
            False,
            {"non_library_dirs": {"Custom": "test"}},
            False,
        ),
    ],
)
def test_only_proven_go_helpers_bypass_default_test_path_suppression(
    tmp_path, relative, proven, kind, exported, config, reported
):
    definition = Definition("helper", kind, tmp_path / relative, 1)
    definition.go_proven_unused_test_helper = proven
    definition.is_exported = exported
    result = _check_non_library_path(
        definition, SimpleNamespace(_project_root=tmp_path), config
    )
    assert (result is None) is reported


def test_other_definitions_default_to_no_go_test_helper_attestation(tmp_path):
    definition = Definition("helper", "function", tmp_path / "helper_test.go", 1)
    assert definition.go_proven_unused_test_helper is False
