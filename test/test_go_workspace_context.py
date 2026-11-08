"""Workspace type proof follows the selected source inventory, never siblings outside it."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.engines.go_runner import GoEngineError, run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache
from skylos.visitors.languages.go.go import scan_go_file


def _workspace(root, *, live_cycle=False, method_value=False):
    root.mkdir()
    (root / "go.work").write_text("go 1.22\nuse (\n ./application\n ./provider\n)\n")
    app, provider = root / "application", root / "provider"
    app.mkdir()
    (provider / "bridge").mkdir(parents=True)
    (app / "go.mod").write_text("module example.com/application\n\ngo 1.22\n")
    (provider / "go.mod").write_text("module example.com/provider\n\ngo 1.22\n")
    call = "bridge.Invoke(callback)"
    api = "func Invoke(callback func()) { callback() }"
    if method_value:
        call = "var value bridge.Box[int]; invoke := value.Invoke; invoke(callback)"
        api = "type Box[T any] struct{}\nfunc (Box[T]) Invoke(callback func()) { callback() }"
    body = "alpha()" if live_cycle else ""
    (app / "main.go").write_text(
        'package main\nimport bridge "example.com/provider/bridge"\n'
        f"func main() {{ {call} }}\nfunc callback() {{ {body} }}\n"
        "func alpha() { beta() }\nfunc beta() { alpha() }\nfunc orphan() {}\n"
    )
    (provider / "bridge/api.go").write_text(f"package differentName\n{api}\n")
    return root


def _scan(root, grep_verify=True, **options):
    result = json.loads(
        analyze(
            str(root),
            conf=60,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_dependency_hallucinations=False,
            **options,
        )
    )
    assert not result.get("analysis_errors")
    return result


def _unused(result, root):
    return {
        (
            Path(item["file"]).relative_to(root).as_posix(),
            item["name"].rsplit(".", 1)[-1],
            item["line"],
        )
        for item in result.get("unused_functions", [])
    }


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("method_value", [False, True])
@pytest.mark.parametrize("live_cycle", [False, True])
def test_workspace_dead_cycle_and_used_callbacks(
    tmp_path, monkeypatch, grep_verify, method_value, live_cycle
):
    monkeypatch.setenv("GOWORK", "")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    root = _workspace(
        tmp_path / "workspace", live_cycle=live_cycle, method_value=method_value
    )
    result = _scan(root, grep_verify)
    expected = {("application/main.go", "orphan", 7)}
    if not live_cycle:
        expected |= {
            ("application/main.go", "alpha", 5),
            ("application/main.go", "beta", 6),
        }
    assert _unused(result, root) == expected
    assert all(row["listing"]["listed"] for row in result["unused_functions"])


def test_workspace_excluded_provider_does_not_prove_private_cycle(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    result = _scan(root, exclude_folders=["provider"])
    assert _unused(result, root) == {("application/main.go", "orphan", 7)}


def test_workspace_scan_of_one_module_never_reads_outside_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    result = _scan(root / "application")
    assert _unused(result, root) == {("application/main.go", "orphan", 7)}


def test_omitted_package_member_preserves_unknown_consumers(tmp_path, monkeypatch):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    consumer = root / "application/consumer.go"
    consumer.write_text("package main\nfunc init() { alpha() }\n")
    selected = (str(root / "application/main.go"), str(root / "provider/bridge/api.go"))
    native = run_go_engine_for_module(root, source_files=selected)
    states = {
        definition["name"]: definition.get("reachability")
        for definition in native["symbols"]["defs"]
        if Path(definition["file"]) == root / "application/main.go"
    }
    assert set(states.values()) == {None}
    assert str(consumer) not in {item["file"] for item in native["symbols"]["defs"]}


def test_native_scope_does_not_read_omitted_security_source(tmp_path, monkeypatch):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    omitted = root / "provider/bridge/unsafe.go"
    omitted.write_text(
        'package differentName\nimport "os/exec"\nfunc Run(input string) { exec.Command(input).Run() }\n'
    )
    selected = (str(root / "application/main.go"), str(root / "provider/bridge/api.go"))
    native = run_go_engine_for_module(root, source_files=selected)
    assert not native["findings"]
    assert str(omitted) not in {item["file"] for item in native["symbols"]["defs"]}


def test_go_source_scope_cache_keeps_full_and_partial_inventories_separate(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    main, api = root / "application/main.go", root / "provider/bridge/api.go"
    clear_go_cache()
    full = scan_go_file(main, {}, go_scan_scope=(str(root), (str(main), str(api))))
    partial = scan_go_file(main, {}, go_scan_scope=(str(root), (str(main),)))
    full_defs, partial_defs = (
        {d.name: d for d in full[0]},
        {d.name: d for d in partial[0]},
    )
    assert full_defs["application.callback"].references > 0
    assert partial_defs["application.callback"].references == 0


@pytest.mark.parametrize("kind", ["outside", "relative", "symlink", "unlisted"])
def test_go_source_scope_rejects_invalid_inventory(tmp_path, monkeypatch, kind):
    monkeypatch.setenv("GOWORK", "")
    root = _workspace(tmp_path / "workspace")
    main = root / "application/main.go"
    selected = [str(main), str(root / "provider/bridge/api.go")]
    if kind == "outside":
        outside = tmp_path / "outside.go"
        outside.write_text("package main\n")
        selected.append(str(outside))
    elif kind == "relative":
        selected.append("provider/bridge/api.go")
    elif kind == "symlink":
        link = root / "link.go"
        link.symlink_to(main)
        selected.append(str(link))
    else:
        selected.remove(str(main))
    with pytest.raises(GoEngineError, match="Invalid admitted Go source scope"):
        scan_go_file(main, {}, go_scan_scope=(str(root), tuple(selected)))
