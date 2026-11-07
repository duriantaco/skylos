"""Source-only Go reachability contracts through the actual native engine."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.engines.go_runner import GoEngineError, run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache


FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks/dead_code/fixtures"
CASES = {
    "go_dead_call_graph": {
        "used": {
            "Public": 3,
            "rooted": 4,
            "callback": 5,
            "init": 6,
            "initialized": 7,
            "startupHook": 9,
            "testOnly": 15,
            "generatedOnly": 16,
        },
        "unused": {
            "staleA": 10,
            "staleB": 11,
            "self": 12,
            "unusedOwner": 13,
            "deadValue": 14,
        },
    },
    "go_scope_identity": {
        "used": {"main": 4, "selected": 16},
        "unused": {"stale": 13, "retired": 14, "parameterOnly": 15},
    },
}


@pytest.mark.parametrize(
    "source, names",
    [
        (
            'package demo\nimport "strings"\n'
            "func Clean(value string) string { return strings.TrimSpace(value) }\n",
            ["Clean"],
        ),
        ("package demo\n", []),
    ],
)
def test_go_native_empty_symbol_arrays_keep_the_strict_protocol(
    tmp_path, source, names
):
    (tmp_path / "go.mod").write_text("module example.com/emptyrefs\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text(source)
    try:
        native = run_go_engine_for_module(tmp_path)
    except GoEngineError as exc:
        # Availability is optional; an engine that returned invalid JSON symbols
        # is a protocol failure, not an unavailable optional dependency.
        if "missing/invalid" in str(exc):
            raise
        pytest.skip(f"requires the source-built Go engine: {exc}")
    assert [item["name"] for item in native["symbols"]["defs"]] == names
    assert native["symbols"]["refs"] == []
    assert native["symbols"]["call_pairs"] == []


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("grep_verify", [False, True])
def test_go_deadcode_uses_rooted_objects_and_reports_exact_source(
    case_id, grep_verify, monkeypatch, tmp_path
):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    path = tmp_path / case_id
    shutil.copytree(FIXTURES / case_id, path)
    try:
        native = run_go_engine_for_module(path)
    except GoEngineError as exc:
        pytest.skip(f"requires the source-built Go engine: {exc}")
    expected = CASES[case_id]
    definitions = {
        item["name"]: item
        for item in native["symbols"]["defs"]
        if item["file"] == str(path / "main.go")
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
    assert report["analysis_summary"]["languages"] == {
        "Go": 3 if case_id == "go_dead_call_graph" else 1
    }
    findings = report.get("unused_functions", [])
    assert {(item["full_name"], item["line"]) for item in findings} == set(
        expected["unused"].items()
    )
    assert all(item["file"] == str(path / "main.go") for item in findings)
    assert all(item["listing"]["listed"] for item in findings)
    for state, symbols in expected.items():
        for symbol, line in symbols.items():
            assert definitions[symbol]["line"] == line
            assert definitions[symbol].get("reachability") == (
                "reachable" if state == "used" else "unreachable"
            )


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX host-tool guard")
def test_go_standard_library_proof_does_not_build_a_cold_cache(tmp_path, monkeypatch):
    go_bin = shutil.which("go")
    if not go_bin:
        pytest.skip("requires the installed host Go standard library")
    host_env = {
        **os.environ,
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOPROXY": "off",
        "GOSUMDB": "off",
    }
    goroot = subprocess.run(
        [go_bin, "env", "GOROOT"],
        cwd=tmp_path,
        env=host_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    # The trusted host source is readable, but any attempt to compile it or
    # discover cached exports through the Go command is a deterministic failure.
    host = tmp_path / "host"
    host.mkdir()
    (host / "src").symlink_to(Path(goroot) / "src", target_is_directory=True)
    (host / "bin").mkdir()
    go_guard = host / "bin" / "go"
    go_guard.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$SKYLOS_TEST_GO_CALL_LOG"\nexit 73\n'
    )
    go_guard.chmod(0o755)
    cache = tmp_path / "cold-cache"
    calls = tmp_path / "go-calls"
    monkeypatch.setenv("GOROOT", str(host))
    monkeypatch.setenv("GOCACHE", str(cache))
    monkeypatch.setenv("GOPATH", str(tmp_path / "empty-gopath"))
    monkeypatch.setenv("SKYLOS_TEST_GO_CALL_LOG", str(calls))
    path = tmp_path / "source"
    shutil.copytree(FIXTURES / "go_service", path)
    try:
        native = run_go_engine_for_module(path)
    except GoEngineError as exc:
        pytest.skip(f"requires the source-built Go engine: {exc}")
    assert not calls.exists(), "static type imports must not run go list/build/cgo"
    assert not cache.exists(), "static type imports must not populate a build cache"
    assert {
        item["name"]: item.get("reachability") for item in native["symbols"]["defs"]
    } == {
        "main": "reachable",
        "healthHandler": "reachable",
        "formatStatus": "reachable",
        "unusedReconciler": "unreachable",
    }
