"""TS/JS security flow: library sinks, Angular sanitizer bypass, NoSQL
without a driver import, express-session cookies, path guards and the
constant-input shapes. Each shape has a reported and a quiet variant."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _findings(tmp_path: Path, code: str, name: str = "src/app.ts", extra=None):
    for extra_name, text in (extra or {}).items():
        _write(tmp_path, extra_name, text)
    path = _write(tmp_path, name, code)
    return scan_typescript_file(str(path))[7]


def _lines(findings, rule_id: str) -> list[int]:
    return sorted(f["line"] for f in findings if f["rule_id"] == rule_id)


def _severity(findings, rule_id: str) -> list[str]:
    return [f["severity"] for f in findings if f["rule_id"] == rule_id]


EXPRESS = "const express = require('express');\nconst app = express();\n"


# ---------------------------------------------------------------- command


def test_member_require_of_exec_is_a_command_sink(tmp_path):
    code = (
        "const exec = require('child_process').exec;\n"
        + EXPRESS
        + "app.post('/ping', (req, res) => {\n"
        "  exec('ping -c 2 ' + req.body.address, () => res.end());\n"
        "});\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D212") == [5]


def test_member_require_of_a_local_module_exec_is_not_child_process(tmp_path):
    code = (
        "const exec = require('./runner').exec;\n"
        + EXPRESS
        + "app.post('/ping', (req, res) => {\n"
        "  exec('ping -c 2 ' + req.body.address, () => res.end());\n"
        "});\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D212") == []


# ---------------------------------------------------------- library sinks


def test_mathjs_eval_of_request_data_is_code_injection(tmp_path):
    code = (
        "const mathjs = require('mathjs');\n"
        + EXPRESS
        + "app.post('/calc', (req, res) => res.json(mathjs.eval(req.body.eqn)));\n"
        "app.post('/fixed', (req, res) => res.json(mathjs.eval('1 + 2')));\n"
    )
    findings = _findings(tmp_path, code)
    assert _lines(findings, "SKY-D201") == [4]
    assert _severity(findings, "SKY-D201") == ["CRITICAL"]


def test_node_serialize_unserialize(tmp_path):
    code = (
        "const serialize = require('node-serialize');\n"
        + EXPRESS
        + "app.post('/bulk', (req, res) => {\n"
        "  const products = serialize.unserialize(req.files.products.data.toString('utf8'));\n"
        "  res.json(products);\n"
        "});\n"
        "export function load(text: string) { return serialize.unserialize(text); }\n"
        "export const fixed = serialize.unserialize('{}');\n"
    )
    findings = _findings(tmp_path, code)
    by_line = {f["line"]: f["severity"] for f in findings if f["rule_id"] == "SKY-D233"}
    assert by_line == {5: "CRITICAL", 8: "HIGH"}


@pytest.mark.parametrize("version, expected", [("^3.14.0", [5]), ("^4.1.0", [])])
def test_js_yaml_load_is_unsafe_only_before_version_4(tmp_path, version, expected):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"js-yaml": version}})
    )
    code = (
        "import yaml from 'js-yaml';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function upload(req: Request, res: Response) {\n"
        "  const text = req.body.document;\n"
        "  res.json(yaml.load(text));\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D233") == expected


def test_vm_runs_request_code(tmp_path):
    code = (
        "import vm from 'node:vm';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function run(req: Request, res: Response) {\n"
        "  res.json(vm.runInNewContext(req.body.code, {}));\n"
        "  res.json(new vm.Script(req.query.script as string));\n"
        "  res.json(vm.runInNewContext('1 + 1', {}));\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D202") == [4, 5]


def test_vm_sandbox_code_that_evaluates_sandbox_data(tmp_path):
    code = (
        "import vm from 'node:vm';\n"
        "import { eval as safeEval } from 'notevil';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function order({ body }: Request, res: Response) {\n"
        "  const orderLines = body.orderLinesData || '';\n"
        "  const sandbox = { safeEval, orderLines };\n"
        "  vm.createContext(sandbox);\n"
        "  vm.runInContext('safeEval(orderLines)', sandbox, { timeout: 2000 });\n"
        "  const fixed = { safeEval, orderLines: '1+1' };\n"
        "  vm.runInContext('safeEval(orderLines)', fixed, { timeout: 2000 });\n"
        "  res.end();\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D201") == [8]


def test_libxmljs_noent_is_xxe(tmp_path):
    code = (
        "const libxmljs = require('libxmljs');\n"
        "const fs = require('fs');\n" + EXPRESS + "app.post('/xml', (req, res) => {\n"
        "  const doc = libxmljs.parseXmlString(req.body.xml, { noent: true });\n"
        "  const safe = libxmljs.parseXmlString(req.body.xml, { noblanks: true });\n"
        "  res.end();\n"
        "});\n"
        "export const local = libxmljs.parseXml(fs.readFileSync('a.xml', 'utf8'), { noent: true });\n"
    )
    findings = _findings(tmp_path, code)
    by_line = {f["line"]: f["severity"] for f in findings if f["rule_id"] == "SKY-D236"}
    assert by_line == {6: "CRITICAL", 10: "HIGH"}


def test_libxml2_noent_parse_option(tmp_path):
    code = (
        "const libxml2 = await import('libxml2-wasm');\n"
        "export const unsafe = libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_NOBLANKS;\n"
        "export const cleared = options & ~libxml2.ParseOption.XML_PARSE_NOENT;\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D236") == [2]


# ------------------------------------------------------- Angular sanitizer


ANGULAR = """import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer } from '@angular/platform-browser';

@Component({ selector: 'app-x', template: '' })
export class SearchComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly sanitizer = inject(DomSanitizer);
  value: any;

  search() {
    let query: string = this.route.snapshot.queryParams.q;
    query = query.trim();
    this.value = this.sanitizer.bypassSecurityTrustHtml(query);
  }

  show(rows: any[]) {
    for (const row of rows) {
      row.description = this.sanitizer.bypassSecurityTrustHtml(row.description);
    }
  }

  fixed() {
    this.value = this.sanitizer.bypassSecurityTrustHtml('<b>hello</b>');
    this.value = this.sanitizer.bypassSecurityTrustResourceUrl('https://www.youtube.com/embed/' + this.id);
  }
}
"""


def test_angular_bypass_security_trust(tmp_path):
    findings = _findings(tmp_path, ANGULAR, "src/app/search.component.ts")
    by_line = {f["line"]: f["severity"] for f in findings if f["rule_id"] == "SKY-D226"}
    assert by_line == {14: "HIGH", 19: "MEDIUM"}


def test_bypass_named_method_without_angular_import_is_not_reported(tmp_path):
    code = ANGULAR.replace(
        "import { DomSanitizer } from '@angular/platform-browser';\n", ""
    )
    findings = _findings(tmp_path, code, "src/app/search.component.ts")
    assert _lines(findings, "SKY-D226") == []


# ------------------------------------------------------------------ NoSQL


def test_where_built_from_request_data_without_a_driver_import(tmp_path):
    code = (
        "import * as db from '../data/store';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function track(req: Request, res: Response) {\n"
        "  const id = req.params.id;\n"
        "  db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((o: any) => res.json(o));\n"
        "  db.ordersCollection.find({ $where: 'this.orderId === ' + Number(id) });\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D238") == [5]


def test_collection_receiver_takes_operator_injection(tmp_path):
    code = (
        "import * as db from '../data/store';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function update(req: Request, res: Response) {\n"
        "  db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } });\n"
        "  reviewService.find({ _id: req.body.id });\n"
        "  res.end();\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D238") == [4]


def test_where_built_from_a_dao_parameter(tmp_path):
    code = (
        "function AllocationsDAO(db) {\n"
        "  const col = db.collection('allocations');\n"
        "  this.get = (userId, threshold, callback) => {\n"
        "    const parsedUserId = parseInt(userId);\n"
        "    const criteria = () => ({\n"
        "      $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`\n"
        "    });\n"
        "    const numeric = () => ({ $where: `this.userId == ${parsedUserId}` });\n"
        "    col.find(criteria()).toArray(callback);\n"
        "  };\n"
        "}\n"
        "module.exports = { AllocationsDAO };\n"
    )
    assert _lines(
        _findings(tmp_path, code, "app/data/allocations-dao.js"), "SKY-D238"
    ) == [6]


UTILS = """export const trunc = function (str: string, length: number) {
  str = str.replace(/(\\r\\n|\\n|\\r)/gm, '')
  return (str.length > length) ? str.substr(0, length - 1) + '...' : str
}
export function lookup (key: string) {
  return table[key]
}
"""


@pytest.mark.parametrize("helper, expected", [("trunc", [6]), ("lookup", [])])
def test_taint_through_a_project_helper_that_returns_its_argument(
    tmp_path, helper, expected
):
    (tmp_path / "package.json").write_text("{}")
    code = (
        "import * as utils from '../lib/utils';\n"
        "import * as db from '../data/store';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function reviews(req: Request, res: Response) {\n"
        f"  const id = utils.{helper}(req.params.id, 40);\n"
        "  db.reviewsCollection.find({ $where: 'this.product == ' + id });\n"
        "  res.end();\n"
        "}\n"
    )
    findings = _findings(
        tmp_path, code, "routes/reviews.ts", extra={"lib/utils.ts": UTILS}
    )
    assert _lines(findings, "SKY-D238") == expected


# --------------------------------------------------------- express-session


@pytest.mark.parametrize(
    "options, expected",
    [
        ("{ secret: process.env.S, resave: false }", [3]),
        ("{ secret: process.env.S, cookie: { secure: false } }", [3]),
        ("{ secret: process.env.S, cookie: { secure: true, httpOnly: false } }", [3]),
        ("{ secret: process.env.S, cookie: { secure: true } }", []),
        (
            "{ secret: process.env.S, cookie: { secure: process.env.NODE_ENV === 'production' } }",
            [],
        ),
        ("{ secret: process.env.S, cookie: { secure: 'auto' } }", []),
    ],
)
def test_express_session_cookie_flags(tmp_path, options, expected):
    code = (
        "const session = require('express-session');\n"
        + "const app = require('express')();\n"
        + f"app.use(session({options}));\n"
    )
    assert _lines(_findings(tmp_path, code, "server.js"), "SKY-D252") == expected


def test_express_session_in_a_development_branch_is_not_reported(tmp_path):
    code = (
        "const session = require('express-session');\n"
        "const app = require('express')();\n"
        "if (app.get('env') === 'development') {\n"
        "  app.use(session({ secret: 'dev' }));\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code, "server.js"), "SKY-D252") == []


# ------------------------------------------------------------ path guards


def test_ternary_extension_allowlist_is_a_path_guard(tmp_path):
    code = (
        "import fs from 'fs';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function save(req: Request, res: Response) {\n"
        "  const url = req.body.imageUrl;\n"
        "  const ext = ['jpg', 'png'].includes(url.split('.').slice(-1)[0]) ? url.split('.').slice(-1)[0] : 'jpg';\n"
        "  fs.createWriteStream(`uploads/avatar.${ext}`);\n"
        "  const raw = url.split('.').slice(-1)[0];\n"
        "  fs.createWriteStream(`uploads/avatar.${raw}`);\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D215") == [8]


LOOKUP = """import fs from 'node:fs/promises';
import {{ type Request, type Response }} from 'express';
const known = new Map(Object.entries(loadChallenges()));
export const retrieve = async (challengeKey: string) => {{
  if ({check}) {{
    return known.get(challengeKey) ?? null;
  }}
  return null;
}};
export const verdict = async (req: Request, res: Response) => {{
  const key = req.body.key;
  let data;
  try {{
    data = await retrieve(key);
    if (data == null) {{
      res.status(404).end();
      return;
    }}
  }} catch (error) {{
    res.status(500).end();
    return;
  }}
  res.send(await fs.readFile('./data/fixes/' + key + '.yml', 'utf8'));
}};
"""


@pytest.mark.parametrize(
    "check, expected",
    [("known.has(challengeKey)", []), ("challengeKey.length > 0", [23])],
)
def test_membership_lookup_in_a_helper_that_404s(tmp_path, check, expected):
    code = LOOKUP.format(check=check)
    assert _lines(_findings(tmp_path, code), "SKY-D215") == expected


@pytest.mark.parametrize(
    "inner, expected",
    [
        ("path.normalize(req.path).replace(/^[\\\\/]+/, '')", []),
        ("path.normalize(req.params.name)", [7]),
    ],
)
def test_rooted_normalize_with_a_prefix_check_without_separator(
    tmp_path, inner, expected
):
    code = (
        "import fs from 'fs';\n"
        "import path from 'path';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function serve(req: Request, res: Response) {\n"
        f"  const filePath = path.resolve('infrastructure', {inner});\n"
        "  if (!filePath.startsWith(path.resolve('infrastructure'))) return res.status(403).end();\n"
        "  fs.readFile(filePath, 'utf8', (err, data) => res.send(data));\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D215") == expected


@pytest.mark.parametrize(
    "target, expected",
    [("path.resolve('encryptionkeys/', file)", []), ("path.resolve(file)", [6])],
)
def test_value_without_slash_is_one_segment_under_a_directory(
    tmp_path, target, expected
):
    code = (
        "import path from 'path';\n"
        "import { type Request, type Response } from 'express';\n"
        "export function keys({ params }: Request, res: Response) {\n"
        "  const file = params.file;\n"
        "  if (!file.includes('/')) {\n"
        f"    res.sendFile({target});\n"
        "  }\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D215") == expected


# ------------------------------------------------- constant-input shapes


def test_eval_of_math_random_arithmetic_is_not_code_injection(tmp_path):
    code = (
        "export function captcha() {\n"
        "  const operators = ['*', '+', '-'];\n"
        "  const first = Math.floor((Math.random() * 10) + 1);\n"
        "  const op = operators[Math.floor(Math.random() * 3)];\n"
        "  const expression = first.toString() + op + '3';\n"
        "  return eval(expression);\n"
        "}\n"
        "export function run(code: string) { return eval(code); }\n"
        "export const loader = new Function('specifier', 'return import(specifier)');\n"
        "export const built = (body: string) => new Function('a', body);\n"
    )
    findings = _findings(tmp_path, code)
    assert _lines(findings, "SKY-D201") == [8]
    assert _lines(findings, "SKY-D202") == [10]


def test_redirect_between_literal_paths_is_same_origin(tmp_path):
    code = (
        EXPRESS
        + "app.get('/home', (req, res) => res.redirect(req.user.isAdmin ? '/benefits' : '/dashboard'));\n"
        "app.get('/next', (req, res) => res.redirect(req.query.admin ? '/benefits' : req.query.url));\n"
    )
    assert _lines(_findings(tmp_path, code, "routes.js"), "SKY-D230") == [4]


def test_localhost_parse_base_is_not_an_internal_url(tmp_path):
    code = (
        "export const path = (value: string) => new URL(value, 'https://localhost').pathname;\n"
        "export function current(url: string, hostname?: string) {\n"
        "  const base = hostname ? `https://${hostname}` : 'https://localhost';\n"
        "  return new URL(url, base);\n"
        "}\n"
        "export const api = 'http://localhost:3000/api/v1';\n"
    )
    assert _lines(_findings(tmp_path, code), "SKY-D248") == [6]


def test_math_random_in_seed_data_and_nested_helpers(tmp_path):
    seed = "export const variance = () => 0.8 + Math.random() * 0.4;\n"
    assert (
        _lines(_findings(tmp_path, seed, "scripts/seed/temporal.ts"), "SKY-D250") == []
    )
    nested = (
        "function SessionHandler(db) {\n"
        "  const prepare = (user) => {\n"
        "    const stocks = Math.floor(Math.random() * 40);\n"
        "    return stocks;\n"
        "  };\n"
        "  const sessionToken = Math.random().toString(36);\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, nested, "routes/session.js"), "SKY-D250") == [6]


@pytest.mark.parametrize(
    "constant, expected",
    [("'https://api.example.com/v1/updates'", []), ("'/v1/updates'", [])],
)
def test_fetch_of_an_imported_project_constant(tmp_path, constant, expected):
    (tmp_path / "package.json").write_text("{}")
    _write(
        tmp_path, "src/lib/constants.ts", f"export const UPDATES_URL = {constant};\n"
    )
    code = (
        "import { UPDATES_URL } from './lib/constants';\n"
        "export async function check(current: string) {\n"
        "  return fetch(`${UPDATES_URL}?v=${current}`);\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code, "src/version.ts"), "SKY-D216") == expected


def test_fetch_of_an_unresolved_import_still_reports(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    _write(
        tmp_path,
        "src/lib/constants.ts",
        "export const UPDATES_URL = process.env.URL;\n",
    )
    code = (
        "import { UPDATES_URL } from './lib/constants';\n"
        "export async function check(current: string) {\n"
        "  return fetch(`${UPDATES_URL}?v=${current}`);\n"
        "}\n"
    )
    assert _lines(_findings(tmp_path, code, "src/version.ts"), "SKY-D216") == [3]


# ------------------------------------------------------------- res.render


def test_request_body_spread_into_render_locals(tmp_path):
    code = (
        EXPRESS + "app.post('/erase', (req, res) => {\n"
        "  res.render('result', { ...req.body, title: 'Done' });\n"
        "  res.render('result', { email: req.body.email, title: 'Done' });\n"
        "  res.render(req.query.page, {});\n"
        "  res.render('result', { layout: req.body.layout });\n"
        "  res.render('result', { ...defaults });\n"
        "  const { userName, email } = req.body;\n"
        "  const errors = { userName, email };\n"
        "  res.render('signup', { ...errors });\n"
        "});\n"
    )
    assert _lines(_findings(tmp_path, code, "routes.js"), "SKY-D215") == [4, 6, 7]


def test_md5_package_for_a_reset_token_but_not_a_checksum(tmp_path):
    code = (
        "const md5 = require('md5');\n"
        + EXPRESS
        + "app.get('/reset', (req, res) => {\n"
        "  if (req.query.token == md5(req.query.login)) res.send('ok');\n"
        "  const etag = md5(JSON.stringify(res.locals.page));\n"
        "});\n"
    )
    assert _lines(_findings(tmp_path, code, "auth.js"), "SKY-D207") == [5]
