"""Node argv APIs become shell sinks only when their options enable a shell."""

from __future__ import annotations

import json

import pytest

from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.danger import scan_danger


def _scan(statement: str, imports: str = "import * as cp from 'node:child_process';"):
    source = (
        imports
        + "\nimport express from 'express';\nconst app = express();\n"
        + "app.post('/run', (req, res) => {\n"
        + statement
        + "\nres.end();\n});\n"
    ).encode()
    core = TypeScriptCore("src/routes/process.ts", source)
    assert core.root_node is not None and not core.root_node.has_error
    findings = scan_danger(core.root_node, core.file_path, core.lang, source)
    return [finding for finding in findings if finding["rule_id"] == "SKY-D212"]


@pytest.mark.parametrize("method", ["spawn", "spawnSync", "execFile", "execFileSync"])
@pytest.mark.parametrize("shell", ["true", "'/bin/sh'"])
def test_request_argument_reaches_enabled_shell(method, shell):
    hits = _scan(f"cp.{method}('printf', [req.body.value], {{shell: {shell}}});")
    assert len(hits) == 1
    assert hits[0]["severity"] == "CRITICAL"
    assert hits[0]["line"] == 5
    assert "req" in hits[0]["security_evidence"]["source"]
    assert method in hits[0]["message"]


@pytest.mark.parametrize(
    ("imports", "statement"),
    [
        (
            "import {spawn as launch} from 'child_process';",
            "launch('printf', [req.body.value], {shell:true});",
        ),
        (
            "import cp from 'child_process';",
            "const launch=cp.spawn; launch('printf', [req.body.value], {shell:true});",
        ),
        (
            "const cp=require('node:child_process');",
            "const {spawn: launch}=cp; launch('printf', [req.body.value], {shell:true});",
        ),
        (
            "const {execFile: launch}=require('child_process');",
            "launch('printf', [req.body.value], {shell:true}, () => {});",
        ),
        (
            "",
            "require('child_process').spawn('printf', [req.body.value], {shell:true});",
        ),
        (
            "import * as cp from 'child_process';",
            "const module=cp; module['spawn']('printf', [req.body.value], {shell:true});",
        ),
        (
            "import * as cp from 'child_process';",
            "const first=cp.spawn; const launch=first; launch('printf', [req.body.value], {shell:true});",
        ),
    ],
)
def test_shell_sinks_keep_import_and_function_value_identity(imports, statement):
    assert len(_scan(statement, imports)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "cp.spawn(req.body.command, {shell:true});",
        "cp.execFile(req.body.command, {shell:true}, () => {});",
        "cp.execFile('printf', [req.body.value], {shell:true}, () => {});",
        "const options={shell:true}; cp.spawn('printf', [req.body.value], options);",
        "let options={shell:false}; options={shell:true}; cp.spawn('printf', [req.body.value], options);",
        "const base={shell:false}; cp.spawn('printf', [req.body.value], {...base,shell:true});",
        "const base={shell:true}; cp.spawn('printf', [req.body.value], {shell:false,...base});",
        "const options={shell:true}; const alias=options; cp.spawn('printf', [req.body.value], alias);",
        "cp.spawn('printf', [req.body.value], {shell:false,shell:true});",
        "cp.spawn(...['printf', [req.body.value], {shell:true}]);",
        "const args=['printf', [req.body.value], {shell:true}]; cp.spawn(...args);",
        "const launch=cp.spawn; { const launch=()=>{}; launch(); } launch('printf', [req.body.value], {shell:true});",
        "const options={shell:true}; { const options={shell:false}; } cp.spawn('printf', [req.body.value], options);",
        "const options={shell:false}; options.shell=true; cp.spawn('printf', [req.body.value], options);",
        "const options={shell:false}; const alias=options; alias.shell=true; cp.spawn('printf', [req.body.value], options);",
        "const options={shell:false}; const alias=options; options.shell=true; cp.spawn('printf', [req.body.value], alias);",
        "const options={shell:true}; cp.spawn('printf', [req.body.value], {shell:true,...req.body.options});",
        "const launch=cp.spawn; cp.spawn=()=>{}; launch('printf', [req.body.value], {shell:true});",
        "cp.spawn=cp.spawn; cp.spawn('printf', [req.body.value], {shell:true});",
        "const options={shell:true}; options.shell ||= false; cp.spawn('printf',[req.body.value],options);",
        "const options={shell:false}; options.shell ||= true; cp.spawn('printf',[req.body.value],options);",
        "const options={shell:true}; options.shell &&= true; cp.spawn('printf',[req.body.value],options);",
    ],
)
def test_shell_options_overloads_aliases_and_property_order(statement):
    assert len(_scan(statement)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "cp.spawn('printf', [req.body.value]);",
        "cp.spawn('printf', [req.body.value], {shell:false});",
        "cp.execFile('printf', [req.body.value], () => {});",
        "cp.execFileSync('printf', [req.body.value]);",
        "cp.spawn('printf', ['fixed'], {shell:true});",
        "const base={shell:true}; cp.spawn('printf', [req.body.value], {...base,shell:false});",
        "const base={shell:false}; cp.spawn('printf', [req.body.value], {shell:true,...base});",
        "cp.spawn('printf', [req.body.value], {shell:true,shell:false});",
        "const options={shell:true}; const options2={...options,shell:false}; cp.spawn('printf', [req.body.value], options2);",
        "const cp={spawn:()=>{}}; cp.spawn('printf', [req.body.value], {shell:true});",
        "const launch=()=>{}; launch('printf', [req.body.value], {shell:true});",
        "let launch=cp.spawn; launch=()=>{}; launch('printf', [req.body.value], {shell:true});",
        "const launch=cp.spawn; function nested(launch) { launch('printf', [req.body.value], {shell:true}); }",
        "function nested(cp) { cp.spawn('printf', [req.body.value], {shell:true}); }",
        "const options={shell:false}; cp.spawn('printf', [req.body.value], options);",
        "let options={shell:true}; options={shell:false}; cp.spawn('printf', [req.body.value], options);",
        "const options={shell:true}; { const options={shell:false}; cp.spawn('printf', [req.body.value], options); }",
        "cp.spawn('printf', [req.body.value], {['shell']:false});",
        "cp.spawn=()=>{}; cp.spawn('printf', [req.body.value], {shell:true});",
        "cp['spawn']=()=>{}; cp.spawn('printf', [req.body.value], {shell:true});",
        "const options={shell:true}; options.shell=false; cp.spawn('printf', [req.body.value], options);",
        "const options={shell:true}; const alias=options; options.shell=false; cp.spawn('printf', [req.body.value], alias);",
        "cp.spawn('printf', [req.body.value], {...req.body.options,shell:false});",
        "const options={shell:false}; options.shell &&= true; cp.spawn('printf',[req.body.value],options);",
        "const options={shell:true}; delete options.shell; cp.spawn('printf',[req.body.value],options);",
        "const options={shell:true}; const alias=options; delete alias.shell; cp.spawn('printf',[req.body.value],options);",
    ],
)
def test_default_argv_disabled_shell_and_local_lookalikes_stay_quiet(statement):
    assert _scan(statement) == []


def test_shell_sink_reaches_analyzer_output(tmp_path):
    import skylos

    path = tmp_path / "routes" / "app.ts"
    path.parent.mkdir()
    path.write_text(
        "import {spawn} from 'node:child_process';\n"
        "import express from 'express';\n"
        "const app=express();\n"
        "app.post('/run', (req,res) => {spawn('printf',[req.body.value],{shell:true});res.end();});\n"
    )
    result = json.loads(
        skylos.analyze(str(tmp_path), enable_danger=True, grep_verify=False)
    )
    hits = [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D212"]
    assert len(hits) == 1
    assert hits[0]["file"] == str(path)
    assert hits[0]["line"] == 4


def test_query_budget_is_reset_for_each_call(monkeypatch):
    from skylos.visitors.languages.typescript import child_process_shell

    monkeypatch.setattr(child_process_shell, "_QUERY_LIMIT", 12)
    statements = "\n".join(
        "cp.spawn('printf', ['fixed'], {shell:true});" for _ in range(30)
    )
    hits = _scan(statements + "\ncp.spawn('printf', [req.body.value], {shell:true});")
    assert len(hits) == 1


def test_exhausted_query_does_not_disable_later_simple_candidate(monkeypatch):
    from skylos.visitors.languages.typescript import child_process_shell

    monkeypatch.setattr(child_process_shell, "_QUERY_LIMIT", 5)
    hits = _scan(
        "const a=cp;const b=a;const c=b;const d=c;"
        "d.spawn('printf',[req.body.value],{shell:true});"
        "cp.spawn('printf',[req.body.value],{shell:true});"
    )
    assert len(hits) == 1


@pytest.mark.parametrize("limit", ["_COLLECTION_LIMIT", "_QUERY_LIMIT", "depth"])
def test_exhausted_proof_budget_is_visible(monkeypatch, limit):
    from skylos.visitors.languages.typescript import child_process_shell

    aliases = ""
    provider = "cp"
    if limit == "depth":
        for index in range(20):
            aliases += f"const alias{index}={provider};"
            provider = f"alias{index}"
    else:
        monkeypatch.setattr(child_process_shell, limit, 1)
    source = (
        "import * as cp from 'child_process';\n"
        "import express from 'express';\n"
        "const app=express();\n"
        f"app.post('/run',(req,res)=>{{{aliases}{provider}.spawn('printf',[req.body.value],{{shell:true}});res.end();}});"
    ).encode()
    core = TypeScriptCore("src/routes/process.ts", source)
    findings = scan_danger(core.root_node, core.file_path, core.lang, source)
    incomplete = [f for f in findings if f["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"]
    assert len(incomplete) == 1
    assert incomplete[0]["kind"] == "processing_error"
