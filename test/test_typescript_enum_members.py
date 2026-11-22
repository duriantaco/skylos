"""Member demand for local enums, with public and opaque boundaries."""

import pytest

from skylos.visitors.languages.typescript.unused_enum_members import find_unused_ts_enum_members


def _scan(root, body, **kwargs):
    path = root / "app.ts"
    path.write_text(body, encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path, fixed filename
    return find_unused_ts_enum_members([path], project_root=root, **kwargs)


@pytest.mark.parametrize("read", ["Status.Ready", "Status['Ready']", "Status[\"Ready\"]", "Alias.Ready"])
def test_literal_member_read_reports_only_unused_sibling(tmp_path, read):
    found = _scan(tmp_path, 'export {};\nenum Status {\n Ready="ready",\n Spare="spare"\n}\nconst Alias = Status;\nconsole.log(' + read + ');')
    assert [(item["full_name"], item["line"]) for item in found] == [("Status.Spare", 4)]
    assert found[0]["rule_id"] == "SKY-U007"
    assert found[0]["type"] == "enum_member"


@pytest.mark.parametrize("use", ["consume(Status)", "Object.keys(Status)", "Status[key]", "Status[0]", "Status.Ready = other", "const copy = {...Status}", "export {Status}", "let alias=Status; consume(alias)", "eval(text)"])
def test_opaque_escaped_or_mutated_enum_retains_all_members(tmp_path, use):
    assert _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready); ' + use + ';') == []


def test_exported_enum_is_a_public_surface(tmp_path):
    assert _scan(tmp_path, 'export enum Status {Ready, Spare}; console.log(Status.Ready);') == []


def test_classic_script_may_have_cross_file_consumers(tmp_path):
    assert _scan(tmp_path, 'enum Status {Ready, Spare}; console.log(Status.Ready);') == []


def test_ambient_declaration_enum_has_no_removable_implementation(tmp_path):
    assert _scan(tmp_path, 'export {}; declare enum Status {Ready, Spare}; console.log(Status.Ready);') == []


def test_shadowed_receiver_does_not_credit_unrelated_member(tmp_path):
    found = _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready); function local(Status: any){return Status.Spare;}')
    assert [item["full_name"] for item in found] == ["Status.Spare"]


def test_enum_member_used_by_other_initializer_stays_live(tmp_path):
    found = _scan(tmp_path, 'export {}; enum Status {Ready=1, Selected=Ready+1, Spare=9}; console.log(Status.Selected);')
    assert [item["full_name"] for item in found] == ["Status.Spare"]


def test_effectful_initializer_declines_member_absence(tmp_path):
    assert _scan(tmp_path, 'export {}; enum Status {Ready=1, Spare=compute()}; console.log(Status.Ready);') == []


def test_entire_unused_enum_is_left_to_existing_owner_finding(tmp_path):
    assert _scan(tmp_path, 'export {}; enum Status {Ready, Spare};') == []


def test_enum_declaration_merging_is_not_narrowed(tmp_path):
    assert _scan(tmp_path, 'export {}; enum Status {Ready}; enum Status {Spare=1}; console.log(Status.Ready);') == []


def test_invalid_parse_declines_member_absence(tmp_path):
    assert _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready); function (') == []


def test_coverage_records_public_and_opaque_boundaries(tmp_path):
    coverage = {}
    assert _scan(tmp_path, 'export enum Public {Ready, Spare}; enum Local {Ready, Spare}; consume(Local);', coverage=coverage) == []
    assert coverage["scope"] == "local_and_internal_module_enums"
    assert coverage["complete"] is False
    assert coverage["status"] == "bounded"
    assert {item["reason"] for item in coverage["abstained_enums"]} == {"public_module_enum", "opaque_enum_use"}


def test_coverage_does_not_mark_parser_failure_complete(tmp_path):
    coverage = {}
    assert _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; function (', coverage=coverage) == []
    assert coverage["complete"] is False
    assert coverage["status"] == "incomplete"
    assert coverage["reasons"][0]["kind"] == "source_parse_error"


def test_budget_failure_clears_partial_enum_findings(tmp_path, monkeypatch):
    from skylos.visitors.languages.typescript import unused_enum_members

    monkeypatch.setattr(unused_enum_members, "MAX_TOTAL_BYTES", 2)
    coverage = {}
    assert _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready);', coverage=coverage) == []
    assert coverage["complete"] is False
    assert coverage["reasons"][0]["kind"] == "source_byte_budget"


def test_complete_local_enum_proof_is_recorded(tmp_path):
    coverage = {}
    assert len(_scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready);', coverage=coverage)) == 1
    assert coverage["status"] == "complete"
    assert coverage["complete"] is True
    assert coverage["checked_enums"] == 1


def _analyse(root):
    import json
    from skylos.analyzer import analyze

    return json.loads(analyze(str(root), conf=0, grep_verify=False, enable_quality=False,
        enable_danger=False, enable_secrets=False, enable_ai_defects=False,
        enable_dependency_hallucinations=False, enable_sca=False))


def test_analysis_reports_enum_member_as_dead_code_without_quality_flag(tmp_path):
    _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready);')
    # An entry file: members of an unused file fold into its SKY-E003 finding.
    (tmp_path / "package.json").write_text('{"main": "app.ts"}', encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path, fixed filename
    result = _analyse(tmp_path)
    found = [item for item in result.get("unused_variables", []) if item.get("rule_id") == "SKY-U007"]
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert result["analysis_summary"]["enum_member_analysis"]["complete"] is True


def test_analysis_honours_enum_member_inline_ignore(tmp_path):
    _scan(tmp_path, 'export {};\nenum Status {\nReady,\nSpare // skylos: ignore[SKY-U007]\n}; console.log(Status.Ready);')
    result = _analyse(tmp_path)
    assert not any(item.get("rule_id") == "SKY-U007" for item in result.get("unused_variables", []))
    assert any(item.get("rule_id") == "SKY-U007" for item in result.get("suppressed", []))


def test_analysis_honours_enum_member_project_ignore(tmp_path):
    _scan(tmp_path, 'export {}; enum Status {Ready, Spare}; console.log(Status.Ready);')
    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.skylos]\nignore=["SKY-U007"]\n', encoding="utf-8")
    result = _analyse(tmp_path)
    assert not any(item.get("rule_id") == "SKY-U007" for item in result.get("unused_variables", []))


def _cross_file(root, consumer, *, private=True, provider=None, extra=None, selected=None, package=None):
    import json

    sources = {
        "package.json": json.dumps(package or {"name":"app", "private":private, "main":"app.ts"}),
        "status.ts": provider or 'export enum Status {Ready="ready", Spare="spare"};',
        "app.ts": consumer,
        **(extra or {}),
    }
    files = []
    for relative, source in sources.items():
        path = root / relative
        path.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324] all callers use fresh pytest tmp_path, literal fixture names
        if path.suffix in {".ts", ".js"} and (selected is None or relative in selected):
            files.append(path)
    coverage = {}
    return find_unused_ts_enum_members(files, project_root=root, coverage=coverage), coverage


@pytest.mark.parametrize("consumer", [
    'import {Status} from "./status"; console.log(Status.Ready);',
    'import {Status as Mode} from "./status.js"; console.log(Mode.Ready);',
    'import {Status as Mode} from "./status"; const Stable=Mode; console.log(Stable["Ready"]);',
])
def test_closed_private_named_import_reports_unused_member(tmp_path, consumer):
    found, coverage = _cross_file(tmp_path, consumer)
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["complete"] is True


def test_unrelated_provider_and_shadowed_alias_do_not_credit_member(tmp_path):
    found, _ = _cross_file(tmp_path, 'import {Status as Mode} from "./status"; import {Status as Other} from "./other"; console.log(Mode.Ready, Other.Spare); function local(Mode:any){return Mode.Spare;}', extra={"other.ts":'export enum Status {Ready, Spare};'})
    assert {(item["file"].rsplit("/",1)[-1],item["full_name"]) for item in found} == {("status.ts","Status.Spare"),("other.ts","Status.Ready")}


@pytest.mark.parametrize("consumer", [
    'import {Status} from "./status"; console.log(Status[key]);',
    'import {Status} from "./status"; consume(Status);',
    'import * as provider from "./status"; console.log(provider.Status.Ready);',
    'export {Status} from "./status";',
    'const provider = require("./status"); console.log(provider.Status.Ready);',
    'const load = require; const provider=load("./status"); console.log(provider.Status.Ready);',
])
def test_private_enum_opaque_consumers_decline_member_absence(tmp_path, consumer):
    found, coverage = _cross_file(tmp_path, consumer)
    assert found == []
    assert coverage["complete"] is False


def test_internal_module_of_public_package_reports_unused_member(tmp_path):
    # The package is published, but status.ts is no entry: only app.ts reads it.
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', private=False)
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["complete"] is True


@pytest.mark.parametrize("package", [
    {"name": "lib", "main": "status.ts"},
    {"name": "lib", "exports": {".": "./app.ts", "./status": "./status.ts"}},
    {"name": "lib", "types": "status.ts", "main": "app.ts"},
])
def test_package_entry_enum_stays_public_despite_internal_read(tmp_path, package):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', package=package)
    assert found == []
    assert coverage["abstained_enums"][0]["reason"] == "public_module_enum"


def test_public_tagged_enum_and_member_stay_live(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', provider='/** @public */\nexport enum Status {Ready="ready", Spare="spare"};')
    assert found == []
    assert coverage["abstained_enums"][0]["reason"] == "public_api_tag"
    found, _ = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', provider='export enum Status {\nReady="ready",\n/** @beta */\nSpare="spare",\nOld="old"\n};')
    assert [item["full_name"] for item in found] == ["Status.Old"]


def test_internal_tag_gives_no_protection(tmp_path):
    found, _ = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', provider='/** @internal */\nexport enum Status {Ready="ready", Spare="spare"};')
    assert [item["full_name"] for item in found] == ["Status.Spare"]


def test_unselected_source_cannot_close_private_enum_graph(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"not_selected.ts":'import {Status} from "./status"; console.log(Status.Spare);'}, selected={"status.ts","app.ts"})
    assert found == []
    assert any(item["kind"] == "unselected_source" for item in coverage["exported_scope_reasons"])


def test_component_importing_the_enum_is_an_opaque_consumer(tmp_path):
    # A template can read ``Status.Spare`` without the script naming it.
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"View.vue":'<script setup>import {Status} from "./status";</script><template>{{ Status.Spare }}</template>'})
    assert found == []
    assert coverage["exported_scope_reasons"] == []
    assert coverage["abstained_enums"][0]["reason"] == "opaque_or_indirect_enum_import"


def test_component_importing_other_modules_keeps_the_enum_graph_closed(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"View.vue":'<script setup>import {used} from "./other";</script>', "other.ts": "export const used = 1;"})
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["exported_scope_reasons"] == []



def test_importing_a_readable_component_keeps_the_enum_graph_closed(tmp_path):
    # app.ts imports View.vue; the component's own imports are already read,
    # so the import cannot hide a read of Status.Spare.
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; import View from "./View.vue"; console.log(Status.Ready, View);', extra={"View.vue":'<script setup>import {used} from "./other";</script><template>{{ used }}</template>', "other.ts": "export const used = 1;"})
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["exported_scope_reasons"] == []


def test_importing_a_component_that_imports_the_enum_keeps_it_opaque(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; import View from "./View.vue"; console.log(Status.Ready, View);', extra={"View.vue":'<script setup>import {Status} from "./status";</script><template>{{ Status.Spare }}</template>'})
    assert found == []
    assert coverage["abstained_enums"][0]["reason"] == "opaque_or_indirect_enum_import"

def test_unparsed_component_holds_back_the_modules_its_text_names(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"View.vue":'<script lang="coffee">\nimport {Status} from "./status"\n</script>'})
    assert found == []
    # The export surface treats the named module as wholly used.
    assert coverage["abstained_enums"][0]["reason"] == "public_module_enum"


def test_missing_relative_import_cannot_consume_an_existing_enum(tmp_path):
    # "./generated" matches no file, so it cannot load status.ts.
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; import "./generated"; import missing from "./missing"; console.log(Status.Ready, missing);')
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["exported_scope_reasons"] == []
    assert {item["specifier"] for item in coverage["unresolved_imports"]} == {"./generated", "./missing"}


@pytest.mark.parametrize("unresolved", [
    'import raw from "./status.js?raw";',
    'const load = () => import("./status.mjs?worker");',
])
def test_unresolved_import_naming_the_enum_module_holds_it_back(tmp_path, unresolved):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; ' + unresolved + ' console.log(Status.Ready);')
    assert found == []
    assert coverage["abstained_enums"][0]["reason"] == "unresolved_import_may_reach_module"


def test_unresolved_path_alias_holds_back_only_the_module_it_names(tmp_path):
    import json

    (tmp_path / "tsconfig.json").write_text(json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}), encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path, literal name
    found, coverage = _cross_file(
        tmp_path,
        'import {Status} from "./status"; import {Mode} from "./mode"; import {gone} from "@/lib/status"; console.log(Status.Ready, Mode.On, gone);',
        extra={"mode.ts": 'export enum Mode {On="on", Off="off"};'},
    )
    assert [item["full_name"] for item in found] == ["Mode.Off"]
    assert coverage["abstained_enums"] == [{"file": str(tmp_path / "status.ts"), "name": "Status", "reason": "unresolved_import_may_reach_module"}]


def test_effectful_exported_enum_initializer_is_retained(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', provider='export enum Status {Ready=1, Spare=compute()};')
    assert found == []
    assert coverage["complete"] is False


def test_analysis_counts_cross_file_private_enum_members(tmp_path):
    _cross_file(tmp_path, 'import {Status as Mode} from "./status"; console.log(Mode.Ready);')
    result = _analyse(tmp_path)
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    found = [item for item in result.get("unused_variables", []) if item.get("rule_id") == "SKY-U007"]
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert result["analysis_summary"]["enum_member_analysis"]["complete"] is True
    assert any(row.get("rules", {}).get("SKY-U007") == 1 for row in result["analysis_summary"]["by_directory"])


def test_import_free_mdx_document_does_not_open_the_private_enum_graph(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"post.mdx": "# Post\n\n```ts\nimport {Status} from './status';\nconsole.log(Status.Spare);\n```\n"})
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"post.mdx": "import {Status} from './status';\n\n{Status.Spare}\n"})
    assert found == []
    assert coverage["exported_scope_reasons"] == []
    assert coverage["abstained_enums"][0]["reason"] == "opaque_or_indirect_enum_import"


def test_html_pages_without_module_imports_keep_the_enum_graph_closed(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"index.html": "<html><body><script>window.x = 1;</script></body></html>"})
    assert [item["full_name"] for item in found] == ["Status.Spare"]
    assert coverage["exported_scope_reasons"] == []
