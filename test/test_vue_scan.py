"""Vue fixtures are static input only; no component or package code executes."""

import json

import pytest

import skylos.analyzer as analyzer_module
from skylos.analysis.file_processing import NON_PYTHON_SCANNERS
from skylos.analyzer import PYTHON_SIGNATURE_SUFFIXES, Skylos
from skylos.core.safe_cache_io import write_text_no_symlink


VUE_COMPONENTS = [
    "<template><p>Hello</p></template><script>export default {};</script>",
    '<script lang="ts">export default { name: "App" };</script>',
    '<script setup lang="ts">const count: number = 0;</script>',
    "<template><p>No script</p></template><style>p { color: red; }</style>",
]


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _scan(target, **kwargs):
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(
            target,
            thr=0,
            enable_danger=True,
            enable_quality=True,
            enable_secrets=True,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
            **kwargs,
        )
    )
    return analyzer, result


@pytest.fixture(autouse=True)
def python_discovery(monkeypatch):
    monkeypatch.setattr(analyzer_module, "_fast_discover", None)


@pytest.mark.parametrize("source", VUE_COMPONENTS)
@pytest.mark.parametrize("suffix", [".vue", ".VUE"])
def test_explicit_vue_is_skipped_without_worker_error(tmp_path, source, suffix):
    component = _write(tmp_path, f"App{suffix}", source)

    analyzer, result = _scan(str(component))

    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["analysis_error_count"] == 0
    assert result["analysis_summary"]["total_files"] == 0
    assert analyzer.defs == {}


@pytest.mark.parametrize("input_kind", ["directory", "list", "tuple", "overlap"])
@pytest.mark.parametrize("changed", [False, True])
def test_mixed_vue_scan_still_analyzes_python_and_typescript(
    tmp_path, monkeypatch, input_kind, changed
):
    component = _write(tmp_path, "App.vue", VUE_COMPONENTS[2])
    python = _write(tmp_path, "app.py", "def unused_python():\n    return 41\n")
    typescript = _write(
        tmp_path, "helper.ts", "export function helper(): number { return 42; }\n"
    )
    files = [str(component), str(python), str(typescript)]
    target = {
        "directory": str(tmp_path),
        "list": files,
        "tuple": tuple(files),
        "overlap": [str(component), str(tmp_path), str(python)],
    }[input_kind]
    dispatched = []
    run_workers = analyzer_module.run_proc_file_parallel

    def record_workers(source_files, *args, **kwargs):
        dispatched.extend(source_files)
        return run_workers(source_files, *args, **kwargs)

    monkeypatch.setattr(analyzer_module, "run_proc_file_parallel", record_workers)
    analyzer, result = _scan(
        target, changed_files={str(component)} if changed else None
    )

    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["total_files"] == 2
    assert result["analysis_summary"]["languages"] == {"Python": 1, "TypeScript": 1}
    assert dispatched == [python, typescript]
    assert "app.unused_python" in analyzer.defs
    assert any(
        definition.simple_name == "helper" and definition.filename == typescript
        for definition in analyzer.defs.values()
    )
    if not changed:
        assert "app.unused_python" in {
            item["full_name"] for item in result.get("unused_functions", [])
        }


@pytest.mark.parametrize("as_list", [False, True])
def test_vue_only_directory_and_file_list_have_no_analyzed_sources(tmp_path, as_list):
    first = _write(tmp_path, "One.vue", VUE_COMPONENTS[0])
    second = _write(tmp_path, "Two.vue", VUE_COMPONENTS[2])
    target = [str(first), str(second)] if as_list else str(tmp_path)

    _, result = _scan(target)

    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["total_files"] == 0


@pytest.mark.parametrize(
    "suffix",
    sorted(
        {
            *PYTHON_SIGNATURE_SUFFIXES,
            *(suffix for suffixes, _ in NON_PYTHON_SCANNERS for suffix in suffixes),
        }
    ),
)
def test_all_registered_source_and_config_suffixes_remain_accepted(tmp_path, suffix):
    source = _write(tmp_path, f"source{suffix}", "")

    files, root = Skylos()._get_python_files(source)

    assert files == [source]
    assert root == tmp_path


@pytest.mark.parametrize("name", ["App.vue.ts", "App.vue.js", "App.vue.py"])
def test_vue_in_basename_does_not_hide_supported_source(tmp_path, name):
    source = _write(tmp_path, name, "")

    files, _ = Skylos()._get_python_files(source)

    assert files == [source]


def test_vue_does_not_hide_a_python_syntax_error(tmp_path):
    component = _write(tmp_path, "App.vue", VUE_COMPONENTS[0])
    broken = _write(tmp_path, "broken.py", "def broken(:\n    pass\n")

    _, result = _scan([str(component), str(broken)])

    assert len(result["analysis_errors"]) == 1
    error = result["analysis_errors"][0]
    assert error["kind"] == "syntax_error"
    assert error["file"] == str(broken)
    assert "grade" not in result


def test_vue_does_not_hide_a_missing_supported_worker_result(tmp_path, monkeypatch):
    component = _write(tmp_path, "App.vue", VUE_COMPONENTS[0])
    source = _write(tmp_path, "app.py", "value = 1\n")
    monkeypatch.setattr(
        analyzer_module,
        "run_proc_file_parallel",
        lambda files, *_a, **_k: [None] * len(files),
    )

    _, result = _scan([str(component), str(source)])

    assert len(result["analysis_errors"]) == 1
    error = result["analysis_errors"][0]
    assert error["kind"] == "worker_error"
    assert error["file"] == str(source)
    assert "grade" not in result


@pytest.mark.parametrize("fast_fails", [False, True])
def test_fast_discovery_cannot_send_vue_to_a_static_worker(
    tmp_path, monkeypatch, fast_fails
):
    component = _write(tmp_path, "App.vue", VUE_COMPONENTS[0])
    source = _write(tmp_path, "app.py", "value = 1\n")

    def fast_discover(_root, extensions, _excludes):
        assert "vue" not in extensions
        if fast_fails:
            raise RuntimeError("discovery unavailable")
        return [str(component), str(source)]

    monkeypatch.setattr(analyzer_module, "_fast_discover", fast_discover)
    _, result = _scan(str(tmp_path))

    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["total_files"] == 1


@pytest.mark.parametrize("input_mode", ["directory", "explicit_list"])
@pytest.mark.parametrize("module_script", [False, True])
def test_vue_still_supplies_browser_script_and_named_handler_refs(
    tmp_path, input_mode, module_script
):
    from skylos.deadcode import browser_refs

    widget = _write(
        tmp_path,
        "widget.js",
        "function greet() { return 'hello'; }\nfunction unused() {}\n",
    )
    other = _write(tmp_path, "other.js", "function greet() { return 'other'; }\n")
    script_type = ' type="module"' if module_script else ""
    component = _write(
        tmp_path,
        "components/Page.vue",
        '<template><button onclick="greet()">Go</button></template>\n'
        f'<script{script_type} src="/widget.js"></script>\n',
    )
    target = tmp_path if input_mode == "directory" else [component, widget, other]

    files, root = Skylos()._discover_files(target, None)
    entries = browser_refs.collect_browser_script_entry_files(root, files)
    refs = browser_refs.collect_browser_event_handler_refs(root, files)

    assert set(files) == {widget, other}
    assert entries == {widget}
    assert (("greet", str(widget)) in refs) is not module_script
    assert ("greet", str(other)) not in refs
    assert not any(name == "unused" for name, _ in refs)


def test_excluded_vue_template_does_not_supply_browser_references(tmp_path):
    from skylos.deadcode import browser_refs

    widget = _write(tmp_path, "widget.js", "function greet() {}\n")
    _write(
        tmp_path,
        "templates/Page.vue",
        '<template><button onclick="greet()">Go</button></template>\n'
        '<script src="/widget.js"></script>\n',
    )

    files, root = Skylos()._discover_files(tmp_path, ["templates"])

    assert files == [widget]
    assert (
        browser_refs.collect_browser_script_entry_files(
            root, files, exclude_folders=["templates"]
        )
        == set()
    )
    assert (
        browser_refs.collect_browser_event_handler_refs(
            root, files, exclude_folders=["templates"]
        )
        == []
    )


@pytest.mark.parametrize(
    "suffix,source",
    [
        (".json", '{"label": "ordinary fixture"}\n'),
        (".yaml", "label: ordinary fixture\n"),
        (".toml", 'label = "ordinary fixture"\n'),
        (".lock", 'label = "ordinary fixture"\n'),
    ],
)
def test_explicit_config_still_reaches_config_and_secret_checks(
    tmp_path, monkeypatch, suffix, source
):
    selected = _write(tmp_path, "selected" + suffix, source)
    _write(tmp_path, "sibling" + suffix, source)
    secret_scans = []
    config_scans = []

    def record_secret_scan(context):
        secret_scans.append(context["relpath"])
        return []

    def record_config_scan(target, **kwargs):
        config_scans.append(target)
        return []

    monkeypatch.setattr(analyzer_module, "_secrets_scan_ctx", record_secret_scan)
    monkeypatch.setattr("skylos.rules.config.scan_config_files", record_config_scan)

    _, result = _scan(str(selected))

    assert result["analysis_errors"] == []
    assert result["analysis_summary"]["total_files"] == 1
    assert secret_scans == [selected.name]
    assert config_scans == [selected]
