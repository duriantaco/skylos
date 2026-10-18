"""Architecture measurements must describe the file used by the graph."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import Skylos, analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.architecture_result import (
    _architecture_metric_sources,
    _build_circular_rule,
)


@pytest.mark.parametrize("stub_first", [False, True])
def test_runtime_metrics_keep_graph_identity_in_either_worker_order(stub_first):
    runtime = Path("src/api.py")
    stub = Path("src/api.pyi")
    files = [stub, runtime] if stub_first else [runtime, stub]
    modmap = dict.fromkeys(files, "api")

    sources = _architecture_metric_sources(files, modmap)
    graph_files = _build_circular_rule(files, modmap, {})._analyzer.modules

    assert sources == {"api": runtime}
    assert str(sources["api"]) == graph_files["api"]


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_runtime_modules_follow_the_existing_graph_winner(reverse):
    first = Path("src/api.py")
    second = Path("lib/api.py")
    stub = Path("src/api.pyi")
    files = [first, stub, second]
    if reverse:
        files.reverse()
    modmap = dict.fromkeys(files, "api")

    sources = _architecture_metric_sources(files, modmap)
    graph_files = _build_circular_rule(files, modmap, {})._analyzer.modules

    assert str(sources["api"]) == graph_files["api"]
    assert sources["api"] == (first if reverse else second)


def test_stub_only_metadata_is_retained_without_combining_different_modules():
    first = Path("api.pyi")
    second = Path("models.pyi")
    assert _architecture_metric_sources(
        [first, second], {first: "api", second: "models"}
    ) == {"api": first, "models": second}


def test_unrelated_languages_cannot_supply_python_architecture_metadata():
    python = Path("api.py")
    stub = Path("api.pyi")
    typescript = Path("api.ts")
    unknown = Path("api.unknown")
    files = [python, stub, typescript, unknown]
    assert _architecture_metric_sources(files, dict.fromkeys(files, "api")) == {
        "api": python
    }
    assert (
        _architecture_metric_sources(
            [typescript, unknown], {typescript: "api", unknown: "api"}
        )
        == {}
    )


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _signals(result):
    return [
        signal
        for advisory in result["architecture_metrics"]["advisories"]
        for signal in advisory["signals"]
    ]


@pytest.mark.parametrize("stub_first", [False, True])
@pytest.mark.parametrize("runtime_main_guard", [False, True])
def test_analyzer_uses_runtime_abstractness_loc_and_main_guard(
    tmp_path, monkeypatch, stub_first, runtime_main_guard
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    runtime_source = (
        "from typing import Protocol\n"
        "import downstream\n"
        "class Contract(Protocol): pass\n"
        "def first(): return downstream.VALUE\n"
        "def second(): return 2\n"
        "def third(): return 3\n"
    )
    if runtime_main_guard:
        runtime_source += 'if __name__ == "__main__":\n    first()\n'
    # The opposite guard deliberately catches borrowing a stub's entrypoint
    # status as well as its A=0 and different line count.
    stub_source = (
        "def first() -> int: ...\ndef second() -> int: ...\ndef third() -> int: ...\n"
    )
    if not runtime_main_guard:
        stub_source += 'if __name__ == "__main__":\n    first()\n'
    _write(tmp_path, "api.py", runtime_source)
    _write(tmp_path, "api.pyi", stub_source)
    _write(tmp_path, "downstream.py", "VALUE = 1\n")
    for name in ("one", "two", "three"):
        _write(tmp_path, f"{name}.py", "import api\n")

    discover = Skylos._discover_files

    def ordered_discovery(self, path, exclude_folders):
        files, root = discover(self, path, exclude_folders)
        return sorted(
            files,
            key=lambda file: (
                file.suffix != (".pyi" if stub_first else ".py"),
                str(file),
            ),
        ), root

    monkeypatch.setattr(Skylos, "_discover_files", ordered_discovery)
    result = json.loads(
        analyze(str(tmp_path), enable_quality=True, grep_verify=False, trace_file=False)
    )

    architecture = result["architecture_metrics"]
    metrics = architecture["module_metrics"]["api"]
    assert metrics["ca"] == 3
    assert metrics["ce"] == 1
    assert metrics["abstractness"] == 0.25
    assert metrics["distance"] == 0.5
    assert architecture["system_metrics"]["total_modules"] == 5
    assert (
        architecture["system_metrics"]["total_loc"]
        == len(runtime_source.splitlines()) + 4
    )
    api_rules = {row["rule_id"] for row in _signals(result) if row["name"] == "api"}
    assert "SKY-Q802" not in api_rules
    assert ("SKY-Q803" in api_rules) is (not runtime_main_guard)
    assert any(row["name"] == "downstream" for row in _signals(result))
    assert result.get("analysis_errors", []) == []


def test_stub_only_api_still_receives_quality_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    stub = _write(tmp_path, "api.pyi", "def wide(a, b, c, d, e, f): ...\n")
    result = json.loads(
        analyze(str(tmp_path), enable_quality=True, grep_verify=False, trace_file=False)
    )
    assert any(
        row["rule_id"] == "SKY-C303" and row["file"] == str(stub)
        for row in result.get("quality", [])
    )
    assert result.get("analysis_errors", []) == []
