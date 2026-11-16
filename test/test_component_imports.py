"""Component fixtures are parsed as data; no compiler or target code runs."""

from pathlib import Path
import json

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.deadcode import component_imports
from skylos.deadcode.component_imports import expand_component_imports
from skylos.visitors.languages.typescript.analysis import build_ts_import_graph
from skylos.visitors.languages.typescript.core import TypeScriptCore


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)
    return path


def _expand(root, source="./Panel.vue", *, excludes=None):
    entry = _write(root, "src/main.ts", "export {};\n")
    return expand_component_imports(
        root,
        [entry],
        {entry: [{"source": source, "names": ["Panel"], "line": 1}]},
        exclude_folders=excludes,
    )


@pytest.mark.parametrize(
    "filename, source",
    [
        ("Panel.vue", '<script setup lang="ts">import { format as display } from "./helpers"; const value = display();</script><template>{{ value }}</template>'),
        ("Panel.svelte", '<script lang="ts">import { format as display } from "./helpers"; const value = display();</script><p>{value}</p>'),
        ("Panel.astro", '---\nimport { format as display } from "./helpers";\nconst value = display();\n---\n<p>{value}</p>'),
    ],
)
def test_component_import_keeps_exact_aliased_binding_and_loader_identity(tmp_path, filename, source):
    component = _write(tmp_path, "src/" + filename, source)
    helper = _write(tmp_path, "src/helpers.ts", 'export function format() { return "ok"; }\nexport function retired() { return "old"; }\n')
    extras, receipt = _expand(tmp_path, "./" + filename)
    entry = tmp_path / "src/main.ts"
    assert set(extras) == {entry}
    row, = extras[entry]
    assert row["source"] == "./helpers.ts"
    assert row["names"] == ["format as display"]
    assert row["component_file"] == str(component)
    assert row["is_component_import"] is True
    assert receipt["status"] == "complete"
    assert receipt["component_count"] == 1
    assert receipt["scope"] == "component_import_graph"
    core = TypeScriptCore(str(helper), helper.read_bytes())
    core.scan()
    definitions = {f"{helper}:{definition.name}": definition for definition in core.defs}
    consumed, _, importers = build_ts_import_graph(extras, definitions)
    assert consumed[str(helper)] == {"format"}
    assert importers[str(helper)] == {str(entry)}
    assert definitions[f"{helper}:retired"].references == 0


def test_nested_components_forward_paths_relative_to_actual_loading_source(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script setup>import Child from "./parts/Child.svelte";</script><template><Child /></template>')
    child = _write(tmp_path, "src/parts/Child.svelte", '<script>import { format } from "../helpers"; format();</script>')
    _write(tmp_path, "src/helpers.ts", "export const format = () => 1;\n")
    extras, receipt = _expand(tmp_path)
    row, = extras[tmp_path / "src/main.ts"]
    assert row["source"] == "./helpers.ts"
    assert row["component_file"] == str(child)
    assert receipt["component_count"] == 2
    assert receipt["languages"] == {"svelte": 1, "vue": 1}


def test_multiline_script_tag_preserves_original_import_line(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script\n  setup\n  lang="ts">\nimport { format } from "./helpers";\n</script>')
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    extras, _ = _expand(tmp_path)
    row, = extras[tmp_path / "src/main.ts"]
    assert row["component_line"] == 4


def test_unloaded_component_is_not_an_external_root(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script setup>import { format } from "./helpers";</script>')
    _write(tmp_path, "src/Orphan.vue", '<script setup>import { retired } from "./retired";</script>')
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    _write(tmp_path, "src/retired.ts", "export const retired = 1;\n")
    extras, receipt = _expand(tmp_path)
    assert [row["source"] for rows in extras.values() for row in rows] == ["./helpers.ts"]
    assert receipt["component_count"] == 1


def test_unselected_js_source_cannot_supply_component_edges(tmp_path):
    component = _write(tmp_path, "Panel.vue", '<script>import { format } from "./helpers";</script>')
    loader = tmp_path / "outside.ts"
    extras, receipt = expand_component_imports(tmp_path, [], {loader: [{"source": "./Panel.vue", "names": ["Panel"]}]})
    assert not extras
    assert receipt["status"] == "not_applicable"
    assert component.exists()


def test_comments_data_and_template_scripts_do_not_load_modules(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<!-- <script>import { wrong } from "./wrong";</script> -->\n<script type="application/json">{"example": "import example from ./data"}</script>\n<template><script>import { inert } from "./inert";</script></template>')
    extras, receipt = _expand(tmp_path)
    assert not extras
    assert receipt["status"] == "complete"


@pytest.mark.parametrize("suffix", ["vue", "svelte", "astro"])
def test_script_namespace_reads_remain_selective(tmp_path, suffix):
    script = 'import * as tools from "./helpers"; tools.format();'
    source = '---\n' + script + '\n---\n<p>hello</p>' if suffix == "astro" else '<script>' + script + '</script><p>hello</p>'
    _write(tmp_path, f"src/Panel.{suffix}", source)
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\nexport const retired = 2;\n")
    extras, _ = _expand(tmp_path, f"./Panel.{suffix}")
    row, = extras[tmp_path / "src/main.ts"]
    assert row["names"] == ["format"]
    assert not row.get("consume_all_exports")


def test_namespace_read_from_template_preserves_uncertain_members(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script setup>import * as tools from "./helpers";</script><template>{{ tools[selected]() }}</template>')
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    extras, _ = _expand(tmp_path)
    row, = extras[tmp_path / "src/main.ts"]
    assert row["consume_all_exports"] is True


@pytest.mark.parametrize("forwarding, names, all_exports", [
    ('export { format as display } from "./helpers";', ["format as display"], False),
    ('export * from "./helpers";', ["*"], True),
    ('export * as tools from "./helpers";', ["* as tools"], True),
])
def test_component_reexports_are_not_misattributed_to_loading_module(tmp_path, forwarding, names, all_exports):
    _write(tmp_path, "src/Panel.svelte", "<script context=\"module\">" + forwarding + "</script>")
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    extras, _ = _expand(tmp_path, "./Panel.svelte")
    row, = extras[tmp_path / "src/main.ts"]
    assert row["names"] == names
    assert not row.get("is_reexport")
    assert bool(row.get("consume_all_exports")) is all_exports


def test_src_script_and_component_cycles_are_bounded(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script src="./controller.ts"></script><script setup>import Child from "./Child.vue";</script>')
    _write(tmp_path, "src/Child.vue", '<script setup>import Panel from "./Panel.vue";</script>')
    _write(tmp_path, "src/controller.ts", "export const model = 1;\n")
    extras, receipt = _expand(tmp_path)
    row, = extras[tmp_path / "src/main.ts"]
    assert row["source"] == "./controller.ts"
    assert row["consume_all_exports"] is True
    assert receipt["component_count"] == 2
    assert receipt["complete"] is True


@pytest.mark.parametrize("source, reason", [
    ('<script lang="coffee">import thing from "./helpers";</script>', "unsupported_script_language"),
    ('<script setup>import { format } from "./helpers"; const = ;</script>', "script_parse_error"),
    ('<script setup>import { format } from "./helpers";', "unclosed_component_script"),
])
def test_unsupported_and_invalid_scripts_cannot_claim_complete_coverage(tmp_path, source, reason):
    _write(tmp_path, "src/Panel.vue", source)
    _, receipt = _expand(tmp_path)
    assert receipt["complete"] is False
    assert reason in {issue["reason"] for issue in receipt["issues"]}


def test_symlink_component_is_not_followed(tmp_path):
    outside = _write(tmp_path, "outside.vue", '<script>import { format } from "./helpers";</script>')
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Panel.vue").symlink_to(outside)
    extras, receipt = _expand(tmp_path)
    assert not extras
    assert receipt["complete"] is False


def test_excluded_component_is_not_read(tmp_path):
    _write(tmp_path, "src/hidden/Panel.vue", '<script>import { format } from "../helpers";</script>')
    extras, receipt = _expand(tmp_path, "./hidden/Panel.vue", excludes=["src/hidden"])
    assert not extras
    assert receipt["complete"] is False


def test_component_limit_is_explicit(tmp_path, monkeypatch):
    _write(tmp_path, "src/Panel.vue", '<script>import Child from "./Child.vue";</script>')
    _write(tmp_path, "src/Child.vue", "<script>export {};</script>")
    monkeypatch.setattr(component_imports, "MAX_COMPONENTS", 1)
    _, receipt = _expand(tmp_path)
    assert receipt["complete"] is False
    assert "component_limit" in {issue["reason"] for issue in receipt["issues"]}


def test_shared_child_is_expanded_once_per_loader(tmp_path):
    _write(tmp_path, "src/Panel.vue", '<script>import Left from "./Left.vue"; import Right from "./Right.vue";</script>')
    for name in ["Left", "Right"]:
        _write(tmp_path, f"src/{name}.vue", '<script>import Shared from "./Shared.vue";</script>')
    _write(tmp_path, "src/Shared.vue", '<script>import { format } from "./helpers";</script>')
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    extras, receipt = _expand(tmp_path)
    assert len(extras[tmp_path / "src/main.ts"]) == 1
    assert receipt["component_count"] == 4
    assert receipt["import_edges"] == 1


def test_component_alias_uses_loading_sources_tsconfig(tmp_path):
    from skylos.visitors.languages.typescript.resolve import MonorepoResolver

    _write(tmp_path, "tsconfig.json", '{"compilerOptions":{"baseUrl":".","paths":{"@views/*":["src/views/*"]}}}')
    entry = _write(tmp_path, "src/main.ts", "export {};\n")
    _write(tmp_path, "src/views/Panel.vue", '<script setup>import { format } from "../helpers";</script>')
    _write(tmp_path, "src/helpers.ts", "export const format = 1;\n")
    extras, receipt = expand_component_imports(
        tmp_path, [entry],
        {entry: [{"source": "@views/Panel.vue", "names": ["Panel"], "line": 1}]},
        resolver=MonorepoResolver(str(tmp_path)),
    )
    row, = extras[entry]
    assert row["source"] == "./helpers.ts"
    assert receipt["complete"] is True


def test_generated_routes_are_explicitly_outside_complete_component_graph(tmp_path):
    _write(tmp_path, "src/Panel.vue", "<template>hello</template>")
    entry = _write(tmp_path, "src/main.ts", "export {};\n")
    _, receipt = expand_component_imports(tmp_path, [entry], {entry: [
        {"source": "./Panel.vue", "names": ["Panel"]},
        {"source": "vue-router/auto-routes", "names": ["routes"]},
    ]})
    assert receipt["complete"] is False
    assert "unresolved_generated_route_provider" in {issue["reason"] for issue in receipt["issues"]}


def test_type_provider_reference_is_not_a_runtime_generated_router(tmp_path):
    types = _write(tmp_path, "types.d.ts", "export {};\n")
    _, receipt = expand_component_imports(tmp_path, [types], {types: [{"source": "vue-router/auto-routes", "names": ["RouteMap"]}]})
    assert receipt["status"] == "not_applicable"


@pytest.mark.parametrize("plugin, source, options, expected", [
    ("AutoImport", "unplugin-auto-import/vite", "{ dirs: ['./src/composables'], vueTemplate: true }", "unresolved_auto_import_provider"),
    ("AutoImport", "unplugin-auto-import/vite", "runtimeOptions", "unresolved_auto_import_provider"),
    ("AutoImport", "unplugin-auto-import/vite", "{ ...runtimeOptions }", "unresolved_auto_import_provider"),
    ("Components", "unplugin-vue-components/vite", "{}", "unresolved_auto_component_provider"),
])
def test_actual_auto_provider_calls_record_unknown_consumers(tmp_path, plugin, source, options, expected):
    config = _write(tmp_path, "vite.config.ts", f"import {{defineConfig}} from 'vite';\nimport {plugin} from '{source}';\nexport default defineConfig({{plugins:[{plugin}({options})]}});\n")
    _, receipt = expand_component_imports(tmp_path, [config], {})
    assert receipt["complete"] is False
    assert expected in {issue["reason"] for issue in receipt["issues"]}


@pytest.mark.parametrize("config", [
    "import Components from 'unplugin-vue-components/vite'; export default {plugins: []};",
    "function Components() {} export default {plugins:[Components()]};",
    "import Components from './factory'; export default {plugins:[Components()]};",
    "import AutoImport from 'unplugin-auto-import/vite'; export default {plugins:[AutoImport({imports:['vue']})]};",
])
def test_unproven_or_external_only_auto_providers_do_not_invent_local_roots(tmp_path, config):
    config = _write(tmp_path, "vite.config.ts", config)
    extras, receipt = expand_component_imports(tmp_path, [config], {})
    assert not extras
    assert receipt["status"] == "not_applicable"


def test_component_bridges_keep_used_helpers_and_report_unused_siblings(tmp_path):
    from skylos.analyzer import Skylos

    _write(tmp_path, "package.json", '{"name":"component-fixture","private":true,"scripts":{"start":"node src/main.ts"}}')
    _write(tmp_path, "src/main.ts", "import Panel from './Panel.vue';\nconsole.log(Panel);\n")
    _write(tmp_path, "src/Panel.vue", '<script setup>import { format as display } from "./helpers"; const value = display();</script><template>{{value}}</template>')
    helper = _write(tmp_path, "src/helpers.ts", 'export function format() { return "ok"; }\nexport function expanded() { return "expanded"; }\n')
    _write(tmp_path, "src/Orphan.vue", '<script>import { summarize } from "./table";</script>')
    table = _write(tmp_path, "src/table.ts", 'export function summarize() { return "rows"; }\n')
    report = json.loads(Skylos().analyze(
        str(tmp_path), thr=0, grep_verify=False, grep_cache=False,
        enable_dependency_hallucinations=False, enable_sca=False,
        trace_file=False,
    ))
    functions = {(Path(row["file"]), row["simple_name"]) for row in report.get("unused_functions", [])}
    assert (helper, "format") not in functions
    assert (helper, "expanded") in functions
    assert (table, "summarize") in functions
    files = {Path(row["file"]) for row in report.get("unused_files", [])}
    assert helper not in files
    assert table in files
