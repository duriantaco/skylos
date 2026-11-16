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
    assert coverage["scope"] == "local_and_closed_private_enums"
    assert coverage["complete"] is False
    assert coverage["status"] == "bounded"
    assert {item["reason"] for item in coverage["abstained_enums"]} == {"public_package_enum", "opaque_enum_use"}


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


def _cross_file(root, consumer, *, private=True, provider=None, extra=None, selected=None):
    import json

    sources = {
        "package.json": json.dumps({"name":"app", "private":private, "main":"app.ts"}),
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


def test_library_enum_stays_public_despite_selected_internal_read(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', private=False)
    assert found == []
    assert coverage["abstained_enums"][0]["reason"] == "public_package_enum"


def test_unselected_source_cannot_close_private_enum_graph(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"not_selected.ts":'import {Status} from "./status"; console.log(Status.Spare);'}, selected={"status.ts","app.ts"})
    assert found == []
    assert any(item["kind"] == "unselected_source" for item in coverage["exported_scope_reasons"])


def test_unparsed_component_cannot_close_private_enum_graph(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; console.log(Status.Ready);', extra={"View.vue":'<script setup>import {Status} from "./status"; console.log(Status.Spare)</script>'})
    assert found == []
    assert any(item["kind"] == "unparsed_component_consumer" for item in coverage["exported_scope_reasons"])


def test_missing_local_import_cannot_close_private_enum_graph(tmp_path):
    found, coverage = _cross_file(tmp_path, 'import {Status} from "./status"; import "./generated"; console.log(Status.Ready);')
    assert found == []
    assert any(item["kind"] == "unresolved_local_import" for item in coverage["exported_scope_reasons"])


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
