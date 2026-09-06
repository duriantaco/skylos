"""Template loading proves file reachability, not consumption of every export."""

import json
from pathlib import Path

import pytest

from skylos.deadcode import browser_refs
from skylos.visitors.base import Definition
from skylos.visitors.languages.typescript.analysis import (
    demote_unconsumed_ts_exports,
    find_dead_ts_files,
)


def _sources(root: Path, sources: dict[str, str]) -> list[Path]:
    files = []
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(source)
        if path.suffix in {".js", ".mjs"}:
            files.append(path)
    return files


def _entries(root: Path, files: list[Path], **kwargs) -> set[Path]:
    return browser_refs.collect_browser_script_entry_files(root, files, **kwargs)


@pytest.mark.parametrize(
    "asset", ["static/widget.js", "app/static/widget.js", "app/static/app/widget.js"]
)
@pytest.mark.parametrize("script_type", ["", ' type="module"'])
def test_literal_static_script_is_a_file_entrypoint(tmp_path, asset, script_type):
    static_path = asset.split("static/", 1)[1]
    files = _sources(
        tmp_path,
        {
            asset: "export function greet() { return 'ok'; }\n",
            "templates/page.html": f"<script{script_type} src=\"{{% static '{static_path}' %}}\"></script>",
            "unloaded.js": "function unused() {}\n",
        },
    )

    entries = _entries(tmp_path, files)

    assert entries == {tmp_path / asset}
    findings = find_dead_ts_files(
        files, [], {}, {}, project_root=str(tmp_path), browser_entry_points=entries
    )
    assert {Path(item["file"]).name for item in findings} == {"unloaded.js"}


@pytest.mark.parametrize("script_type", ["", ' type="module"'])
def test_loading_script_does_not_consume_unused_export(tmp_path, script_type):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "export function greet() { return 'ok'; }\n",
            "templates/page.html": f"<script{script_type} src=\"{{% static 'widget.js' %}}\"></script>",
        },
    )
    definition = Definition("greet", "function", files[0], 1)
    definition.is_exported = True

    assert _entries(tmp_path, files) == {files[0]}
    demoted = demote_unconsumed_ts_exports({"greet": definition}, {})

    assert demoted == [definition]
    assert definition.references == 0
    assert definition.is_exported is False
    assert browser_refs.collect_browser_event_handler_refs(tmp_path, files) == []


def test_named_handler_reaches_only_called_function_in_loaded_classic_script(tmp_path):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "function greet() { return 'ok'; }\nfunction unused() {}\n",
            "other/widget.js": "function greet() { return 'other'; }\n",
            "templates/page.html": '<script src="{% static \'widget.js\' %}"></script><button onclick="greet()">Go</button>',
        },
    )

    refs = browser_refs.collect_browser_event_handler_refs(tmp_path, files)

    assert ("greet", str(tmp_path / "static/widget.js")) in refs
    assert ("greet", str(tmp_path / "other/widget.js")) not in refs
    assert not any(name == "unused" for name, _ in refs)


@pytest.mark.parametrize("script_type", [' type="module"', " type=module"])
def test_module_exports_are_not_global_inline_handlers(tmp_path, script_type):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "export function greet() {}\n",
            "templates/page.html": f'<script{script_type} src="{{% static \'widget.js\' %}}"></script><button onclick="greet()">Go</button>',
        },
    )

    refs = browser_refs.collect_browser_event_handler_refs(tmp_path, files)

    assert ("greet", str(files[0])) not in refs


def test_export_declaration_is_not_a_classic_script_global(tmp_path):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "export function greet() {}\n",
            "templates/page.html": '<script src="{% static \'widget.js\' %}"></script><button onclick="greet()">Go</button>',
        },
    )

    refs = browser_refs.collect_browser_event_handler_refs(tmp_path, files)

    assert ("greet", str(files[0])) not in refs


def test_template_handler_is_not_assigned_to_another_pages_script(tmp_path):
    files = _sources(
        tmp_path,
        {
            "first/static/first.js": "function greet() {}\n",
            "second/static/second.js": "function greet() {}\n",
            "templates/first.html": '<script src="{% static \'first.js\' %}"></script><button onclick="greet()">Go</button>',
            "templates/second.html": "<script src=\"{% static 'second.js' %}\"></script>",
        },
    )

    refs = browser_refs.collect_browser_event_handler_refs(tmp_path, files)

    assert ("greet", str(files[0])) in refs
    assert ("greet", str(files[1])) not in refs


def test_commented_handler_does_not_consume_a_loaded_scripts_function(tmp_path):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "function greet() {}\n",
            "templates/page.html": '<script src="{% static \'widget.js\' %}"></script><!-- <button onclick="greet()">Go</button> -->',
        },
    )

    assert browser_refs.collect_browser_event_handler_refs(tmp_path, files) == []


def test_static_directory_can_itself_be_the_scan_root(tmp_path):
    root = tmp_path / "static"
    root.mkdir()
    files = _sources(
        root,
        {
            "widget.js": "function greet() {}\n",
            "page.html": "<script src=\"{% static 'widget.js' %}\"></script>",
        },
    )

    assert _entries(root, files) == {files[0]}


@pytest.mark.parametrize(
    "markup",
    [
        "<script data-src=\"{% static 'widget.js' %}\"></script>",
        '<script src="{% static asset_name %}"></script>',
        "<script src=\"{% static 'missing.js' %}\"></script>",
        '<script type="application/json" src="{% static \'widget.js\' %}"></script>',
        "<!-- <script src=\"{% static 'widget.js' %}\"></script> -->",
        "{# <script src=\"{% static 'widget.js' %}\"></script> #}",
        "{% comment %}<script src=\"{% static 'widget.js' %}\"></script>{% endcomment %}",
    ],
)
def test_nonloading_template_lookalikes_do_not_create_entrypoints(tmp_path, markup):
    files = _sources(
        tmp_path,
        {"static/widget.js": "function greet() {}\n", "templates/page.html": markup},
    )

    assert _entries(tmp_path, files) == set()


def test_ambiguous_static_asset_is_not_guessed(tmp_path):
    files = _sources(
        tmp_path,
        {
            "first/static/widget.js": "function greet() {}\n",
            "second/static/widget.js": "function greet() {}\n",
            "templates/page.html": '<script src="{% static \'widget.js\' %}"></script><button onclick="greet()">Go</button>',
        },
    )

    assert _entries(tmp_path, files) == set()
    refs = browser_refs.collect_browser_event_handler_refs(tmp_path, files)
    assert not any(Path(filename).suffix == ".js" for _, filename in refs)


def test_only_scanned_assets_and_included_templates_create_entrypoints(tmp_path):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "function greet() {}\n",
            "templates/page.html": "<script src=\"{% static 'widget.js' %}\"></script>",
        },
    )

    assert _entries(tmp_path, []) == set()
    assert _entries(tmp_path, files, exclude_folders=["templates"]) == set()


@pytest.mark.parametrize(
    "script_type", ["", ' type="text/javascript"', ' type="application/x-javascript"']
)
def test_regular_browser_script_url_remains_supported(tmp_path, script_type):
    files = _sources(
        tmp_path,
        {
            "widget.js": "function greet() {}\n",
            "templates/page.html": f'<script{script_type} src="/widget.js?v=1#loaded"></script><button onclick="greet()">Go</button>',
        },
    )

    assert _entries(tmp_path, files) == {files[0]}
    assert ("greet", str(files[0])) in browser_refs.collect_browser_event_handler_refs(
        tmp_path, files
    )


def test_loaded_module_keeps_its_imported_dependency_file_reachable(tmp_path):
    files = _sources(
        tmp_path,
        {
            "static/widget.js": "import { greet } from './helpers.js';\ngreet();\n",
            "static/helpers.js": "export function greet() {}\n",
            "templates/page.html": '<script type="module" src="{% static \'widget.js\' %}"></script>',
        },
    )
    entries = _entries(tmp_path, files)
    importers = {str(files[1]): {str(files[0])}}

    assert (
        find_dead_ts_files(
            files,
            [],
            importers,
            {},
            project_root=str(tmp_path),
            browser_entry_points=entries,
        )
        == []
    )


def test_analyzer_preserves_called_handler_and_reports_unused_helper(tmp_path):
    from skylos.analyzer import analyze

    files = _sources(
        tmp_path,
        {
            "static/widget.js": "function greet() { return 'ok'; }\nfunction unusedHelper() { return 'unused'; }\n",
            "templates/page.html": '<script src="{% static \'widget.js\' %}"></script><button onclick="greet()">Go</button>',
        },
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {item["name"] for item in result.get("unused_functions", [])}
    unused_files = {Path(item["file"]) for item in result.get("unused_files", [])}

    assert "greet" not in unused
    assert "unusedHelper" in unused
    assert files[0] not in unused_files


@pytest.mark.parametrize("script_type", ["", ' type="module"'])
def test_analyzer_keeps_uncalled_export_unused_in_loaded_file(tmp_path, script_type):
    from skylos.analyzer import analyze

    files = _sources(
        tmp_path,
        {
            "static/widget.js": "export function greet() { return 'ok'; }\n",
            "templates/page.html": f"<script{script_type} src=\"{{% static 'widget.js' %}}\"></script>",
        },
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {item["name"] for item in result.get("unused_functions", [])}
    unused_files = {Path(item["file"]) for item in result.get("unused_files", [])}

    assert "greet" in unused
    assert files[0] not in unused_files
