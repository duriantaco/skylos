"""Local Go module metadata can prove reachability only for indexed source."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.engines.go_runner import run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache


def _project(path, *, target="./local/provider", required=True, method_value=False):
    path.mkdir()
    requirement = "require example.com/provider v0.0.0\n" if required else ""
    (path / "go.mod").write_text(
        "module example.com/application\n\ngo 1.22\n"
        + requirement
        + f"replace example.com/provider => {target}\n"
    )
    invocation = "bridge.Invoke(callback)"
    if method_value:
        invocation = (
            "var value bridge.Box[int]; invoke := value.Invoke; invoke(callback)"
        )
    (path / "main.go").write_text(
        'package main\nimport bridge "example.com/provider/bridge"\n'
        f"func main() {{ {invocation} }}\n"
        "func callback() {}\n"
        "func alpha() { beta() }\n"
        "func beta() { alpha() }\n"
        "func orphan() {}\n"
    )
    provider = path / "local/provider"
    (provider / "bridge").mkdir(parents=True)
    (provider / "go.mod").write_text("module example.com/provider\n\ngo 1.22\n")
    api = "func Invoke(callback func()) { callback() }"
    if method_value:
        api = "type Box[T any] struct{}\nfunc (Box[T]) Invoke(callback func()) { callback() }"
    (provider / "bridge/api.go").write_text(f"package differentName\n{api}\n")
    return path


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("method_value", [False, True])
def test_local_replacement_exposes_dead_cycle_and_preserves_callback(
    tmp_path, monkeypatch, grep_verify, method_value
):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("GOWORK", "off")
    root = _project(tmp_path / "project", method_value=method_value)
    native = run_go_engine_for_module(root)
    states = {
        d["name"]: d.get("reachability")
        for d in native["symbols"]["defs"]
        if Path(d["file"]) == root / "main.go"
    }
    assert states == {
        "main": "reachable",
        "callback": "reachable",
        "alpha": "unreachable",
        "beta": "unreachable",
        "orphan": "unreachable",
    }
    clear_go_cache()
    report = json.loads(
        analyze(
            str(root),
            conf=60,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    assert {
        (Path(f["file"]).relative_to(root).as_posix(), f["name"], f["line"])
        for f in report.get("unused_functions", [])
    } == {("main.go", "alpha", 5), ("main.go", "beta", 6), ("main.go", "orphan", 7)}
    assert all(f["listing"]["listed"] for f in report["unused_functions"])


@pytest.mark.parametrize(
    "target,required",
    [("./testdata/provider", True), ("./local/provider", False)],
)
def test_unresolved_replacements_do_not_create_native_dead_cycle_proof(
    tmp_path, monkeypatch, target, required
):
    monkeypatch.setenv("GOWORK", "off")
    root = _project(tmp_path / "project", target=target, required=required)
    native = run_go_engine_for_module(root)
    states = {
        d["name"]: d.get("reachability")
        for d in native["symbols"]["defs"]
        if Path(d["file"]) == root / "main.go"
    }
    assert set(states) == {"main", "callback", "alpha", "beta", "orphan"}
    assert set(states.values()) == {None}
