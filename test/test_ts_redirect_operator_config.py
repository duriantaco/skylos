"""Operator config redirects need provenance; request-shaped env lookalikes do not."""

from __future__ import annotations

import json

import pytest

from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.danger import scan_danger


def _scan(statement):
    source = (
        "import express from 'express';\nconst app=express();\n"
        "app.get('/profile',(req,res)=>{\n" + statement + "\n});\n"
    ).encode()
    core = TypeScriptCore("src/routes/profile.ts", source)
    assert core.root_node is not None and not core.root_node.has_error
    return [
        finding
        for finding in scan_danger(core.root_node, core.file_path, core.lang, source)
        if finding["rule_id"] == "SKY-D230"
    ]


@pytest.mark.parametrize(
    "statement",
    [
        "res.redirect(process.env.BASE_PATH + '/profile');",
        "res.redirect(process.env['BASE_PATH'] + '/profile');",
        "const destination=process.env.BASE_PATH + '/profile';res.redirect(destination);",
        "res.redirect((process.env.BASE_PATH ?? '') + '/profile');",
        "res.redirect((process.env.BASE_PATH || '/') + 'profile');",
        "const destination=process.env.BASE_PATH;res.redirect(destination + '/profile');",
        "if (req.body.imageUrl) { fetch(req.body.imageUrl); } res.redirect(process.env.BASE_PATH + '/profile');",
    ],
)
def test_redirect_uses_only_unchanged_operator_config_and_literals(statement):
    assert _scan(statement) == []


@pytest.mark.parametrize(
    "statement",
    [
        "res.redirect(req.query.next);",
        "res.redirect(process.env.BASE_PATH + req.query.next);",
        "res.redirect(process.env[req.query.key] + '/profile');",
        "res.redirect((process.env.BASE_PATH ?? req.query.next) + '/profile');",
        "const process={env:req.body};res.redirect(process.env.BASE_PATH + '/profile');",
        "let destination=process.env.BASE_PATH;destination=req.query.next;res.redirect(destination);",
        "let destination=process.env.BASE_PATH;if(req.query.change){destination=req.query.next;}res.redirect(destination);",
        "const destination=req.query.change ? process.env.BASE_PATH : req.query.next;res.redirect(destination);",
        "process.env.BASE_PATH=req.query.next;res.redirect(process.env.BASE_PATH + '/profile');",
        "if(req.query.change){process.env.BASE_PATH=req.query.next;}res.redirect(process.env.BASE_PATH + '/profile');",
        "const environment=process.env;environment.BASE_PATH=req.query.next;res.redirect(process.env.BASE_PATH + '/profile');",
        "Object.assign(process.env,req.body);res.redirect(process.env.BASE_PATH + '/profile');",
        "globalThis.process.env.BASE_PATH=req.query.next;res.redirect(process.env.BASE_PATH + '/profile');",
        "globalThis['process'].env.BASE_PATH=req.query.next;res.redirect(process.env.BASE_PATH + '/profile');",
        "Object.defineProperty(globalThis,'process',{value:{env:req.body}});res.redirect(process.env.BASE_PATH + '/profile');",
        "const globals=globalThis;globals.process={env:req.body};res.redirect(process.env.BASE_PATH + '/profile');",
        "globalThis[req.query.provider]={env:req.body};res.redirect(process.env.BASE_PATH + '/profile');",
        "process.env=req.body;res.redirect(process.env.BASE_PATH + '/profile');",
        "res.redirect(unknownConfig.BASE_PATH + '/profile');",
    ],
)
def test_request_input_and_mutated_or_shadowed_config_remain_findings(statement):
    assert _scan(statement)


def test_operator_config_redirect_is_quiet_in_analyzer_output(tmp_path):
    import skylos

    path = tmp_path / "routes" / "profile.ts"
    path.parent.mkdir()
    path.write_text(
        "import express from 'express';\nconst app=express();\n"
        "app.get('/profile',(req,res)=>{if(req.body.imageUrl){fetch(req.body.imageUrl);}"
        "res.redirect(process.env.BASE_PATH+'/profile');});\n"
    )
    result = json.loads(
        skylos.analyze(str(tmp_path), enable_danger=True, grep_verify=False)
    )
    assert not [
        finding
        for finding in result.get("danger", [])
        if finding["rule_id"] == "SKY-D230"
    ]
    assert [
        finding
        for finding in result.get("danger", [])
        if finding["rule_id"] == "SKY-D216"
    ]
