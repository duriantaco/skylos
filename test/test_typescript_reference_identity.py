"""Real-repository gap contracts, with used and unrelated-name controls."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def _scan(root, files, *, grep_verify=True, enable_quality=False):
    files = {
        "package.json": '{"private":true,"type":"module","main":"index.ts"}',
        **files,
    }
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    report = json.loads(
        analyze(
            str(root),
            conf=0,
            enable_quality=enable_quality,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    return report


def _identities(report, category):
    return {
        (Path(row["file"]).name, row.get("simple_name", row.get("name")))
        for row in report.get(category, [])
    }


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "local",
    [
        "const measure = 1; console.log(measure);",
        "let measure = 1; measure++; console.log(measure);",
        "const {measure} = {measure: 1}; console.log(measure);",
        "const [measure] = [1]; console.log(measure);",
        "try { throw 1; } catch (measure) { console.log(measure); }",
        "for (const measure of [1]) { console.log(measure); }",
        "function show(measure: number) { return measure; } console.log(show(1));",
        "const show = (measure: number) => measure; console.log(show(1));",
        "function show({measure}: {measure: number}) { return measure; } console.log(show({measure:1}));",
    ],
)
def test_local_values_do_not_rescue_an_unrelated_module_function(
    tmp_path, local, grep_verify
):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import {format} from './helpers';\nfunction start() { "
            + local
            + " format(); }\nstart();\n",
            "helpers.ts": "export function format() { return 1; }\nexport function measure() { return 2; }\n",
        },
        grep_verify=grep_verify,
    )
    assert ("helpers.ts", "measure") in _identities(report, "unused_functions")
    assert ("helpers.ts", "measure") not in _identities(report, "unused_exports")
    assert ("helpers.ts", "format") not in _identities(report, "unused_functions")
    assert ("index.ts", "start") not in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "body",
    [
        "measure();",
        "const callback = measure; callback();",
        "const object = {run: measure}; object.run();",
        "function invoke(measure: () => void) { measure(); } invoke(measure);",
        "{ const measure = 1; console.log(measure); } measure();",
        "const callback = () => measure(); callback();",
    ],
)
def test_real_function_values_and_outer_calls_still_reference_the_provider(
    tmp_path, body
):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import {measure} from './helpers';\n" + body,
            "helpers.ts": "export function measure() { return 1; }\nexport function spare() {}\n",
        },
    )
    assert ("helpers.ts", "measure") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


def test_local_arrow_definition_is_kept_by_its_own_reads(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "function start() { const callback = () => 1; return callback(); } start();"
        },
    )
    assert ("index.ts", "callback") not in _identities(report, "unused_functions")


def test_value_parameter_does_not_hide_type_uses(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import type {Measure} from './helpers';\nfunction show(Measure: number, value: Measure) { console.log(Measure,value); }\nshow(1, {value:2});",
            "helpers.ts": "export interface Measure { value: number }\n",
        },
    )
    assert ("helpers.ts", "Measure") not in _identities(report, "unused_classes")


@pytest.mark.parametrize("grep_verify", [False, True])
def test_unreachable_consumer_does_not_rescue_imported_functions_or_data(
    tmp_path, grep_verify
):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import {format} from './helpers'; console.log(format());",
            "helpers.ts": "export function format() { return 1; }\nexport function calculate() { return 2; }\nexport const modes = [1,2];",
            "orphan.ts": "import {calculate,modes} from './helpers'; export function prepare() { return calculate()+modes[0]; }",
        },
        grep_verify=grep_verify,
    )
    assert ("helpers.ts", "calculate") in _identities(report, "unused_functions")
    assert ("helpers.ts", "modes") in _identities(report, "unused_variables")
    assert ("orphan.ts", "prepare") in _identities(report, "unused_functions")
    assert ("orphan.ts", "calculate") not in _identities(report, "unused_imports")
    assert ("orphan.ts", "modes") not in _identities(report, "unused_imports")
    assert ("helpers.ts", "format") not in _identities(report, "unused_functions")
    assert any(
        Path(row["file"]).name == "orphan.ts" for row in report.get("unused_files", [])
    )


@pytest.mark.parametrize(
    "entry",
    [
        "import './consumer';",
        "import('./consumer');",
        "import {prepare} from './consumer'; prepare();",
    ],
)
def test_reachable_side_effect_dynamic_and_named_consumers_keep_their_dependencies(
    tmp_path, entry
):
    report = _scan(
        tmp_path,
        {
            "index.ts": entry,
            "consumer.ts": "import {calculate,modes} from './helpers'; export function prepare() { return calculate()+modes[0]; }\nprepare();",
            "helpers.ts": "export function calculate() { return 2; }\nexport const modes = [1,2];\nexport function spare() {}",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "modes") not in _identities(report, "unused_variables")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


def test_test_entry_consumer_remains_live_in_the_full_scan(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "console.log('application');",
            "consumer.ts": "import {calculate} from './helpers'; export function prepare() { return calculate(); }",
            "helpers.ts": "export function calculate() { return 2; }\nexport function spare() {}",
            "consumer.test.ts": "import {prepare} from './consumer'; prepare();",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("consumer.ts", "prepare") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


def test_html_entry_consumer_remains_live(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "console.log('application');",
            "page.html": '<script type="module" src="./consumer.ts"></script>',
            "consumer.ts": "import {calculate} from './helpers'; console.log(calculate());",
            "helpers.ts": "export function calculate() { return 2; }\nexport function spare() {}",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


def test_public_package_exports_remain_api_even_without_source_consumers(tmp_path):
    report = _scan(
        tmp_path,
        {
            "package.json": '{"type":"module","exports":"./api.ts"}',
            "index.ts": "console.log('application');",
            "api.ts": "export {calculate} from './helpers';",
            "helpers.ts": "export function calculate() { return 2; }\nexport function spare() {}",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "boundary",
    [
        "import './missing';",
        "import 'unknown-package';",
        "const key = request(); import(key);",
        "eval(source);",
    ],
)
def test_opaque_or_unresolved_consumers_do_not_supply_a_deadness_proof(
    tmp_path, boundary
):
    from skylos.visitors.languages.typescript import scan_typescript_file
    from skylos.visitors.languages.typescript.analysis import (
        build_ts_import_graph,
        prune_dead_ts_import_consumers,
    )

    _scan(
        tmp_path,
        {
            "index.ts": "console.log('application');",
            "orphan.ts": boundary
            + "\nimport {calculate} from './helpers'; export function prepare(){ return calculate(); }",
            "helpers.ts": "export function calculate() { return 1; }",
        },
    )
    files = list(tmp_path.glob("*.ts"))
    raw = {str(path): scan_typescript_file(str(path))[12] for path in files}
    definitions = {
        f"{path}:{d.name}": d
        for path in files
        for d in scan_typescript_file(str(path))[0]
    }
    _, wildcard, importers = build_ts_import_graph(
        raw, definitions, credit_references=False
    )
    effective, dead = prune_dead_ts_import_consumers(
        raw, definitions, files, importers, wildcard, project_root=str(tmp_path)
    )
    assert str((tmp_path / "orphan.ts").resolve()) not in dead
    assert str(tmp_path / "orphan.ts") in effective


def test_unresolved_incoming_alias_does_not_erase_a_possible_consumer(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import '@app/orphan';",
            "orphan.ts": "import {calculate} from './helpers'; console.log(calculate());",
            "helpers.ts": "export function calculate() { return 1; }",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")


def test_pure_graph_pass_does_not_credit_or_erase_references(tmp_path, monkeypatch):
    import skylos.visitors.languages.typescript.analysis as graph
    from skylos.visitors.base import Definition

    path = tmp_path / "helpers.ts"
    path.write_text("export function calculate() {}")
    definition = Definition("calculate", "function", str(path), 1)
    definition.references = 3
    definitions = {f"{path}:calculate": definition}
    raw = {
        str(tmp_path / "index.ts"): [
            {"source": "./helpers", "names": ["calculate"], "line": 1}
        ]
    }
    consumed, _, _ = graph.build_ts_import_graph(
        raw, definitions, credit_references=False
    )
    assert consumed[str(path)] == {"calculate"}
    assert definition.references == 3

    def broken(*args):
        definition.references += 1
        raise ValueError("unavailable graph")

    monkeypatch.setattr(graph, "_build_ts_import_graph", broken)
    with pytest.raises(ValueError, match="unavailable graph"):
        graph.build_ts_import_graph(raw, definitions, credit_references=False)
    assert definition.references == 3


@pytest.mark.parametrize("boundary", ["incomplete", "unanalysed-dependency", "classic"])
def test_partial_or_classic_program_evidence_does_not_remove_consumer_demand(
    tmp_path, boundary
):
    from skylos.visitors.languages.typescript import scan_typescript_file
    from skylos.visitors.languages.typescript.analysis import (
        build_ts_import_graph,
        prune_dead_ts_import_consumers,
    )

    sources = {
        "package.json": '{"private":true,"type":"module","main":"index.ts"}',
        "index.ts": "console.log('application');",
        "helpers.ts": "export function calculate(){ return 1; }",
        "orphan.ts": (
            "const calculate = require('./helpers').calculate; console.log(calculate());"
            if boundary == "classic"
            else "import {calculate} from './helpers'; export function prepare(){ return calculate(); }"
        ),
    }
    for name, source in sources.items():
        (tmp_path / name).write_text(source)
    files = [
        path
        for path in tmp_path.glob("*.ts")
        if boundary != "unanalysed-dependency" or path.name != "helpers.ts"
    ]
    scans = {str(path): scan_typescript_file(str(path)) for path in files}
    raw = {path: scan[12] for path, scan in scans.items()}
    definitions = {
        f"{path}:{d.name}": d for path, scan in scans.items() for d in scan[0]
    }
    _, wildcard, importers = build_ts_import_graph(
        raw, definitions, credit_references=False
    )
    effective, dead = prune_dead_ts_import_consumers(
        raw,
        definitions,
        files,
        importers,
        wildcard,
        project_root=str(tmp_path),
        analysis_errors=[{"kind": "source_read_error"}]
        if boundary == "incomplete"
        else None,
    )
    assert str((tmp_path / "orphan.ts").resolve()) not in dead
    assert str(tmp_path / "orphan.ts") in effective


@pytest.mark.parametrize(
    "loader",
    [
        "import(process.argv[2]);",
        "require(process.argv[2]);",
        "eval(process.argv[2]);",
        "new Function(process.argv[2])();",
        "import.meta.glob(process.argv[2]);",
    ],
)
def test_incoming_opaque_loader_keeps_possible_consumer_dependencies(tmp_path, loader):
    report = _scan(
        tmp_path,
        {
            "index.ts": loader
            + " import {format} from './helpers'; console.log(format());",
            "helpers.ts": "export function format(){return 1;} export function calculate(){return 2;} export function spare(){return 3;}",
            "consumer.ts": "import {calculate} from './helpers'; export function prepare(){return calculate();} prepare();",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("consumer.ts", "prepare") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "loader",
    [
        "globalThis.eval(process.argv[2]);",
        "const evaluate=eval; evaluate(process.argv[2]);",
        "const make=Function; make(process.argv[2])();",
        "import {createRequire} from 'node:module'; const load=createRequire(import.meta.url); load(process.argv[2]);",
        "const evaluate=globalThis.eval; evaluate(process.argv[2]);",
        "const runtime=globalThis; runtime.eval(process.argv[2]);",
        "globalThis[process.argv[3]](process.argv[2]);",
        "globalThis['eval'](process.argv[2]);",
        "const {eval:evaluate}=globalThis; evaluate(process.argv[2]);",
        "import {createRequire as build} from 'node:module'; const load=build(import.meta.url); load(process.argv[2]);",
        "import * as runtime from 'node:module'; const load=runtime.createRequire(import.meta.url); load(process.argv[2]);",
        "const make=()=>Function; make()(process.argv[2])();",
        "const load=require; load(process.argv[2]);",
        "const runtime=require('node:module'); runtime.createRequire(import.meta.url)(process.argv[2]);",
        "const make=globalThis['Function']; make(process.argv[2])();",
        r"const evaluate=e\u0076al; evaluate(process.argv[2]);",
        "(()=>{}).constructor(process.argv[2])();",
        "const holder={load:eval}; holder.load(process.argv[2]);",
        "let load=console.log; load=eval; load(process.argv[2]);",
        "window.eval(process.argv[2]);",
        "self.eval(process.argv[2]);",
        "global.eval(process.argv[2]);",
        "const {load}={load:require}; load(process.argv[2]);",
        "import runtime from 'module'; const load=runtime.createRequire(import.meta.url); load(process.argv[2]);",
    ],
)
def test_escaped_runtime_loading_capabilities_prevent_a_deadness_proof(
    tmp_path, loader
):
    report = _scan(
        tmp_path,
        {
            "index.ts": loader
            + " import {format} from './helpers'; console.log(format());",
            "helpers.ts": "export function format(){return 1;} export function calculate(){return 2;} export function spare(){return 3;}",
            "consumer.ts": "import {calculate} from './helpers'; export function prepare(){return calculate();} prepare();",
        },
    )
    assert ("helpers.ts", "calculate") not in _identities(report, "unused_functions")
    assert ("consumer.ts", "prepare") not in _identities(report, "unused_functions")
    assert ("helpers.ts", "spare") in _identities(report, "unused_functions")


def test_static_literal_loader_does_not_disable_closed_module_demand(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "const {format}=require('./active'); console.log(format());",
            "active.ts": "export function format(){return 1;}",
            "helpers.ts": "export function calculate(){return 2;} export const modes=[1];",
            "consumer.ts": "import {calculate,modes} from './helpers'; export function prepare(){return calculate()+modes[0];} prepare();",
        },
    )
    assert ("helpers.ts", "calculate") in _identities(report, "unused_functions")
    assert ("helpers.ts", "modes") in _identities(report, "unused_variables")
    assert ("active.ts", "format") not in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "non_runtime_reference",
    [
        "// eval Function require createRequire globalThis\n",
        "const message='eval Function require createRequire globalThis'; console.log(message);",
        "type Function = {value:number}; const value:Function={value:1}; console.log(value);",
        "type Callable = typeof Function;",
        "import type {Module} from 'node:module'; let value:Module;",
        "import {type Module} from 'node:module'; let value:Module;",
    ],
)
def test_comment_string_and_type_names_are_not_runtime_loader_exposure(
    tmp_path, non_runtime_reference
):
    report = _scan(
        tmp_path,
        {
            "index.ts": non_runtime_reference
            + "\nimport {format} from './active'; console.log(format());",
            "active.ts": "export function format(){return 1;}",
            "helpers.ts": "export function calculate(){return 2;} export const modes=[1];",
            "consumer.ts": "import {calculate,modes} from './helpers'; export function prepare(){return calculate()+modes[0];} prepare();",
        },
    )
    assert ("helpers.ts", "calculate") in _identities(report, "unused_functions")
    assert ("helpers.ts", "modes") in _identities(report, "unused_variables")
    assert ("active.ts", "format") not in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "loader",
    [
        "import {Worker} from 'node:worker_threads'; new Worker(process.argv[2]);",
        "import {Worker as Thread} from 'node:worker_threads'; new Thread(process.argv[2]);",
        "import * as threads from 'node:worker_threads'; new threads.Worker(process.argv[2]);",
        "const threads=require('node:worker_threads'); new threads.Worker(process.argv[2]);",
        "const threads=await import('node:worker_threads'); new threads.Worker(process.argv[2]);",
        "new Worker(process.argv[2], {type:'module'});",
        "const BackgroundWorker=Worker; new BackgroundWorker(process.argv[2], {type:'module'});",
        "new globalThis.Worker(process.argv[2], {type:'module'});",
        "const {Worker:BackgroundWorker}=globalThis; new BackgroundWorker(process.argv[2], {type:'module'});",
        "new SharedWorker(process.argv[2], {type:'module'});",
        "navigator.serviceWorker.register(process.argv[2], {type:'module'});",
    ],
)
def test_runtime_worker_entries_keep_possible_module_dependencies(tmp_path, loader):
    report = _scan(
        tmp_path,
        {
            "package.json": '{"private":true,"type":"module","main":"index.js"}',
            "index.js": loader
            + " import {format} from './helpers.js'; console.log(format());",
            "helpers.js": "export function format(){return 1;} export function calculate(){return 2;} export function spare(){return 3;}",
            "consumer.js": "import {calculate} from './helpers.js'; export function prepare(){return calculate();} prepare();",
        },
    )
    assert ("helpers.js", "calculate") not in _identities(report, "unused_functions")
    assert ("consumer.js", "prepare") not in _identities(report, "unused_functions")
    assert ("helpers.js", "spare") in _identities(report, "unused_functions")


@pytest.mark.parametrize(
    "loader",
    [
        "import {fork} from 'node:child_process'; fork(process.argv[2]);",
        "import * as child from 'child_process'; child.fork(process.argv[2]);",
        "const child=require('node:child_process'); child.fork(process.argv[2]);",
        "import * as vm from 'node:vm'; vm.runInThisContext(process.argv[2]);",
    ],
)
def test_runtime_node_execution_providers_prevent_a_deadness_proof(tmp_path, loader):
    report = _scan(
        tmp_path,
        {
            "package.json": '{"private":true,"type":"module","main":"index.js"}',
            "index.js": loader
            + " import {format} from './helpers.js'; console.log(format());",
            "helpers.js": "export function format(){return 1;} export function calculate(){return 2;} export function spare(){return 3;}",
            "consumer.js": "import {calculate} from './helpers.js'; export function prepare(){return calculate();} prepare();",
        },
    )
    assert ("helpers.js", "calculate") not in _identities(report, "unused_functions")
    assert ("consumer.js", "prepare") not in _identities(report, "unused_functions")
    assert ("helpers.js", "spare") in _identities(report, "unused_functions")


def test_dead_consumer_demand_keeps_file_evidence_and_architecture_edges(tmp_path):
    report = _scan(
        tmp_path,
        {
            "index.ts": "import {format} from './active'; console.log(format());",
            "active.ts": "export function format(){return 1;}",
            "helpers.ts": "export function calculate(){return 2;} export const modes=[1];",
            "orphan.ts": "import {calculate,modes} from './helpers'; export function prepare(){return calculate()+modes[0];} prepare();",
        },
        enable_quality=True,
    )
    assert ("helpers.ts", "calculate") in _identities(report, "unused_functions")
    assert ("helpers.ts", "modes") in _identities(report, "unused_variables")
    assert ("active.ts", "format") not in _identities(report, "unused_functions")
    files = {Path(row["file"]).name: row for row in report.get("unused_files", [])}
    assert files["orphan.ts"]["confidence"] == 80
    assert files["helpers.ts"]["confidence"] == 65
    assert (
        "only imported by files that are themselves unused"
        in files["helpers.ts"]["message"]
    )
    metrics = report["architecture_metrics"]["module_metrics"]
    assert metrics["orphan"]["ce"] == 1
    assert metrics["helpers"]["ca"] == 1
