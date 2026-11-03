"""Request data reaching TS/JS sinks in Express, Koa, Fastify, Hapi, NestJS
and Next.js handlers.

Express ``res.send(string)`` answers with ``Content-Type: text/html`` unless
the handler sets another type, so reflected request text is XSS even without
a literal tag."""

import textwrap

import pytest

from skylos.visitors.languages.typescript.danger import scan_danger

try:
    from tree_sitter import Language, Parser
    import tree_sitter_typescript

    TS_LANG = Language(tree_sitter_typescript.language_typescript())
except Exception:  # pragma: no cover - optional dependency
    TS_LANG = None

pytestmark = pytest.mark.skipif(TS_LANG is None, reason="tree-sitter-typescript missing")

HEADER = """
import { exec, execFile } from 'child_process';
import express, { NextFunction, Request, Response, Router } from 'express';
import * as path from 'path';
import prisma from './prisma-client';
const router = Router();
const app = express();
"""


def _scan(body: str, file_path: str = "src/routes/app.ts") -> list[dict]:
    source = (HEADER + textwrap.dedent(body)).encode()
    tree = Parser(TS_LANG).parse(source)
    return scan_danger(tree.root_node, file_path, TS_LANG, source)


def _hits(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


POSITIVES = {
    "exec_template": (
        "SKY-D212",
        """
        router.post('/thumb', (req: Request, res: Response) => {
          const image = req.body.image;
          exec(`convert uploads/${image} -resize 128x128 out.png`, () => res.end());
        });
        """,
    ),
    "exec_concat_destructured": (
        "SKY-D212",
        """
        app.get('/ping', (req, res) => {
          const { host } = req.query;
          exec('ping -c 1 ' + host, () => res.end());
        });
        """,
    ),
    "send_html": (
        "SKY-D228",
        """
        router.get('/card/:username', async (req: Request, res: Response) => {
          res.send(`<div class="card"><h1>${req.params.username}</h1></div>`);
        });
        """,
    ),
    "send_file_join": (
        "SKY-D215",
        """
        app.get('/images/:name', (req: express.Request, res: express.Response) => {
          res.sendFile(path.join(__dirname, 'assets', 'images', req.params.name));
        });
        """,
    ),
    "prisma_raw_unsafe": (
        "SKY-D211",
        """
        router.get('/search', async (req: Request, res: Response, next: NextFunction) => {
          const term = String(req.query.q || '');
          const rows = await prisma.$queryRawUnsafe(
            `SELECT slug FROM "Article" WHERE title ILIKE '%${term}%'`,
          );
          res.json({ rows });
        });
        """,
    ),
    "prisma_execute_raw_unsafe": (
        "SKY-D211",
        """
        router.post('/rename', async (req, res) => {
          await prisma.$executeRawUnsafe("UPDATE t SET name = '" + req.body.name + "'");
          res.sendStatus(204);
        });
        """,
    ),
    "send_plain_text_is_html": (
        "SKY-D228",
        """
        router.get('/echo/:name', (req, res) => {
          res.send(`hello ${req.params.name}`);
        });
        """,
    ),
}


@pytest.mark.parametrize("rule_id,body", POSITIVES.values(), ids=POSITIVES.keys())
def test_request_data_reaches_sink(rule_id, body):
    hits = _hits(_scan(body), rule_id)
    assert len(hits) == 1, hits
    evidence = hits[0].get("security_evidence")
    assert evidence and "req" in evidence["source"]


NEGATIVES = {
    "exec_constant": (
        "SKY-D212",
        """
        router.post('/thumb', (req, res) => {
          exec(`convert uploads/logo.png out.png`, () => res.end());
        });
        """,
    ),
    "execfile_args": (
        "SKY-D212",
        """
        router.post('/thumb', (req, res) => {
          execFile('convert', [req.body.image, 'out.png'], () => res.end());
        });
        """,
    ),
    "send_json": (
        "SKY-D228",
        """
        router.get('/card/:username', (req, res) => {
          res.json({ html: `<h1>${req.params.username}</h1>` });
        });
        """,
    ),
    "send_escaped": (
        "SKY-D228",
        """
        router.get('/card/:username', (req, res) => {
          res.send(`<h1>${escapeHtml(req.params.username)}</h1>`);
        });
        """,
    ),
    "send_text_plain_type": (
        "SKY-D228",
        """
        router.get('/echo/:name', (req, res) => {
          res.type('text/plain').send(`hello ${req.params.name}`);
        });
        """,
    ),
    "send_file_root_option": (
        "SKY-D215",
        """
        app.get('/images/:name', (req, res) => {
          res.sendFile(req.params.name, { root: path.join(__dirname, 'assets') });
        });
        """,
    ),
    "send_file_basename": (
        "SKY-D215",
        """
        app.get('/images/:name', (req, res) => {
          res.sendFile(path.join(__dirname, 'assets', path.basename(req.params.name)));
        });
        """,
    ),
    "send_file_prefix_guard": (
        "SKY-D215",
        """
        app.get('/images/:name', (req, res) => {
          const root = path.join(__dirname, 'assets');
          const target = path.resolve(root, req.params.name);
          if (!target.startsWith(root + path.sep)) {
            return res.sendStatus(400);
          }
          res.sendFile(target);
        });
        """,
    ),
    "prisma_tagged_template": (
        "SKY-D211",
        """
        router.get('/search', async (req, res) => {
          const rows = await prisma.$queryRaw`SELECT slug FROM "Article" WHERE title = ${req.query.q}`;
          res.json(rows);
        });
        """,
    ),
    "prisma_unsafe_with_params": (
        "SKY-D211",
        """
        router.get('/search', async (req, res) => {
          const rows = await prisma.$queryRawUnsafe('SELECT slug FROM "Article" WHERE title = $1', req.query.q);
          res.json(rows);
        });
        """,
    ),
}


@pytest.mark.parametrize("rule_id,body", NEGATIVES.values(), ids=NEGATIVES.keys())
def test_safe_forms_not_reported(rule_id, body):
    hits = [
        f for f in _hits(_scan(body), rule_id) if f.get("security_evidence") is not None
    ]
    assert hits == []


@pytest.mark.parametrize(
    "stmt",
    [
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
        "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';",
    ],
)
def test_node_tls_reject_unauthorized_disabled(stmt):
    assert len(_hits(_scan(stmt), "SKY-D210")) == 1


def test_node_tls_reject_unauthorized_enabled_is_safe():
    assert _hits(_scan("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';"), "SKY-D210") == []


# rejectUnauthorized: false (D210), not reported in test files
# (get_non_library_dir_kind(...) == "test"), like D346 in Python.
_AGENT = "const agent = new https.Agent({ rejectUnauthorized: false });"


@pytest.mark.parametrize(
    ("file_path", "body", "expected"),
    [
        ("src/api.ts", _AGENT, 1),
        ("src/db.ts", "const pool = new Pool({ ssl: { rejectUnauthorized: false } });", 1),
        ("src/api.ts", "const opts = { 'rejectUnauthorized': false };", 1),
        ("src/api.test.ts", _AGENT, 0),
        ("src/__tests__/api.ts", _AGENT, 0),
        ("src/api.ts", "const agent = new https.Agent({ rejectUnauthorized: true });", 0),
        ("src/env.spec.ts", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", 0),
    ],
)
def test_reject_unauthorized_false_follows_the_test_path_rule(file_path, body, expected):
    assert len(_hits(_scan(body, file_path), "SKY-D210")) == expected


def _scan_src(src: str, file_path: str = "src/routes/app.ts") -> list[dict]:
    source = textwrap.dedent(src).encode()
    tree = Parser(TS_LANG).parse(source)
    return scan_danger(tree.root_node, file_path, TS_LANG, source)


def _proven(findings, rule_id):
    return [f for f in _hits(findings, rule_id) if f.get("security_evidence")]


EXPRESS = """
import express from 'express';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { Pool } from 'pg';
const router = express.Router();
const pool = new Pool();
const ROOT = path.join(__dirname, 'files');
const HOSTS = ['api.github.com'];
"""

MONGO = """
import express from 'express';
import mongoose from 'mongoose';
import User from './user.model';
const router = express.Router();
"""

SOURCE_CASES = {
    "express_concat_sql": (
        "SKY-D211",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/u/:id', async (req, res) => {
  res.json(await pool.query('SELECT * FROM users WHERE id = ' + req.params.id));
});
""",
    ),
    "express_prebuilt_sql": (
        "SKY-D211",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/s', async (req, res) => {
  const sql = "SELECT * FROM t WHERE name = '" + req.query.q + "'";
  res.json(await pool.query(sql));
});
""",
    ),
    "express_fs_join": (
        "SKY-D215",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/f/:name', (req, res) => {
  fs.readFile(path.join(ROOT, req.params.name), () => res.end());
});
""",
    ),
    "express_ssrf": (
        "SKY-D216",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/proxy', async (req, res) => {
  res.json((await axios.get(req.query.url)).data);
});
""",
    ),
    "express_redirect_status": (
        "SKY-D230",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/go', (req, res) => {
  res.redirect(302, req.query.to);
});
""",
    ),
    "koa_raw_sql": (
        "SKY-D211",
        "src/router.ts",
        """
import Router from '@koa/router';
import knex from './db';
const router = new Router();
router.get('/r', async (ctx) => {
  ctx.body = await knex.raw(`select * from r where owner = '${ctx.query.owner}'`);
});
""",
    ),
    "koa_redirect": (
        "SKY-D230",
        "src/router.ts",
        """
import Router from '@koa/router';
const router = new Router();
router.get('/out', async (ctx) => {
  ctx.redirect(ctx.query.returnTo as string);
});
""",
    ),
    "koa_html_body": (
        "SKY-D228",
        "src/router.ts",
        """
import Router from '@koa/router';
const router = new Router();
router.get('/hi', async (ctx) => {
  ctx.body = `<h1>${ctx.query.name}</h1>`;
});
""",
    ),
    "fastify_fs": (
        "SKY-D215",
        "src/server.ts",
        """
import Fastify from 'fastify';
import fs from 'node:fs';
const app = Fastify();
app.get('/logs/:file', async (request, reply) => {
  return fs.readFileSync(`/var/log/${request.params.file}`, 'utf8');
});
""",
    ),
    "hapi_payload_sql": (
        "SKY-D211",
        "src/routes.js",
        """
const { Sequelize } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:');
server.route({ method: 'POST', path: '/x', handler: async (request, h) => {
  return sequelize.query("SELECT * FROM u WHERE name = '" + request.payload.name + "'");
} });
""",
    ),
    "nest_query_sql": (
        "SKY-D211",
        "src/users.controller.ts",
        """
import { Controller, Get, Query } from '@nestjs/common';
import { DataSource } from 'typeorm';
@Controller('users')
export class UsersController {
  constructor(private readonly dataSource: DataSource) {}
  @Get('search')
  search(@Query('name') name: string) {
    return this.dataSource.query(`SELECT * FROM users WHERE name = '${name}'`);
  }
}
""",
    ),
    "nest_param_typed_number_is_still_text": (
        "SKY-D211",
        "src/users.controller.ts",
        """
import { Controller, Get, Param } from '@nestjs/common';
import { DataSource } from 'typeorm';
@Controller('users')
export class UsersController {
  constructor(private readonly dataSource: DataSource) {}
  @Get(':id')
  find(@Param('id') id: number) {
    return this.dataSource.query('SELECT * FROM users WHERE id = ' + id);
  }
}
""",
    ),
    "next_route_json_sql": (
        "SKY-D211",
        "app/api/items/route.ts",
        """
import { Pool } from 'pg';
const pool = new Pool();
export async function POST(request: Request) {
  const { name } = await request.json();
  return Response.json(await pool.query("SELECT * FROM t WHERE name = '" + name + "'"));
}
""",
    ),
    "next_route_params_fs": (
        "SKY-D215",
        "app/files/[name]/route.ts",
        """
import { readFile } from 'node:fs/promises';
import path from 'node:path';
export async function GET(request: Request, { params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  return new Response(await readFile(path.join(process.cwd(), 'files', name)));
}
""",
    ),
    "next_route_redirect": (
        "SKY-D230",
        "app/auth/route.ts",
        """
import { NextRequest, NextResponse } from 'next/server';
export async function GET(request: NextRequest) {
  const next = request.nextUrl.searchParams.get('next') ?? '/';
  return NextResponse.redirect(new URL(next, request.url));
}
""",
    ),
    "mongo_body_fields": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.post('/login', async (req, res) => {
  res.json(await User.findOne({ username: req.body.username, password: req.body.password }));
});
""",
    ),
    "mongo_whole_query": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.get('/list', async (req, res) => {
  const filter = req.query;
  res.json(await User.find(filter));
});
""",
    ),
    "mongo_where_string": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.post('/older', async (req, res) => {
  res.json(await User.find({ $where: `this.age > ${req.body.age}` }));
});
""",
    ),
    "mongo_typeof_on_other_field": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.post('/t', async (req, res) => {
  const { email, token } = req.body;
  if (typeof token !== 'string') {
    return res.status(400).end();
  }
  res.json(await User.findOne({ email }));
});
""",
    ),
    "proto_nested_write": (
        "SKY-D510",
        "src/routes/settings.ts",
        EXPRESS
        + """
const settings = {};
router.post('/p/:section', (req, res) => {
  settings[req.params.section][req.body.key] = req.body.value;
  res.end();
});
""",
    ),
    "proto_recursive_merge": (
        "SKY-D510",
        "src/routes/settings.ts",
        EXPRESS
        + """
const settings = {};
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key] = target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
router.post('/s', (req, res) => {
  merge(settings, req.body);
  res.end();
});
""",
    ),
}


@pytest.mark.parametrize(
    "rule_id,file_path,src", SOURCE_CASES.values(), ids=SOURCE_CASES.keys()
)
def test_framework_request_data_reaches_sink(rule_id, file_path, src):
    assert len(_proven(_scan_src(src, file_path), rule_id)) == 1


SAFE_CASES = {
    "placeholder_sql": (
        "SKY-D211",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/u/:id', async (req, res) => {
  res.json(await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]));
});
""",
    ),
    "strong_reassign_with_parseint": (
        "SKY-D211",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/page', async (req, res) => {
  let { page } = req.query;
  page = parseInt(page, 10) || 1;
  res.json(await pool.query('SELECT * FROM posts OFFSET ' + page * 20));
});
""",
    ),
    "nest_parse_int_pipe": (
        "SKY-D211",
        "src/users.controller.ts",
        """
import { Controller, Get, Param, ParseIntPipe } from '@nestjs/common';
import { DataSource } from 'typeorm';
@Controller('users')
export class UsersController {
  constructor(private readonly dataSource: DataSource) {}
  @Get(':id')
  find(@Param('id', ParseIntPipe) id: number) {
    return this.dataSource.query('SELECT * FROM users WHERE id = ' + id);
  }
}
""",
    ),
    "path_basename": (
        "SKY-D215",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/f/:name', (req, res) => {
  fs.readFile(path.join(ROOT, path.basename(req.params.name)), () => res.end());
});
""",
    ),
    "resolved_prefix_check_that_rejects": (
        "SKY-D215",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/doc', (req, res) => {
  const target = path.resolve(ROOT, req.query.name);
  if (!target.startsWith(ROOT + path.sep)) {
    return res.status(403).end();
  }
  fs.createReadStream(target).pipe(res);
});
""",
    ),
    "fixed_host_url": (
        "SKY-D216",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/repos/:owner', async (req, res) => {
  res.json(await fetch(`https://api.github.com/users/${req.params.owner}/repos`));
});
""",
    ),
    "hostname_allowlist_that_rejects": (
        "SKY-D216",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/fetch', async (req, res) => {
  const url = new URL(req.query.url);
  if (!HOSTS.includes(url.hostname)) {
    return res.status(400).end();
  }
  res.json((await axios.get(url.toString())).data);
});
""",
    ),
    "relative_redirect_check": (
        "SKY-D230",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/return', (req, res) => {
  const next = req.query.next || '/';
  if (!next.startsWith('/') || next.startsWith('//')) {
    return res.redirect('/');
  }
  res.redirect(next);
});
""",
    ),
    "relative_redirect_prefix": (
        "SKY-D230",
        "src/routes/app.ts",
        EXPRESS
        + """
router.get('/profile', (req, res) => {
  res.redirect('/users/' + req.query.id);
});
""",
    ),
    "next_same_origin_redirect": (
        "SKY-D230",
        "app/auth/route.ts",
        """
import { NextRequest, NextResponse } from 'next/server';
export async function POST(request: NextRequest) {
  return NextResponse.redirect(new URL('/login', request.url));
}
""",
    ),
    "mongo_string_coercion": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.get('/n', async (req, res) => {
  res.json(await User.find({ name: String(req.query.name) }));
});
""",
    ),
    "mongo_typeof_guard": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.post('/t', async (req, res) => {
  const { email } = req.body;
  if (typeof email !== 'string') {
    return res.status(400).end();
  }
  res.json(await User.findOne({ email }));
});
""",
    ),
    "mongo_route_param_is_text": (
        "SKY-D238",
        "src/routes/auth.ts",
        MONGO
        + """
router.get('/u/:id', async (req, res) => {
  res.json(await User.findOne({ _id: req.params.id }));
});
""",
    ),
    "nest_dto_body_for_mongo": (
        "SKY-D238",
        "src/users.controller.ts",
        """
import { Body, Controller, Post } from '@nestjs/common';
import { Model } from 'mongoose';
@Controller('users')
export class UsersController {
  constructor(private readonly userModel: Model<User>) {}
  @Post()
  find(@Body() dto: FindUserDto) {
    return this.userModel.findOne({ email: dto.email });
  }
}
""",
    ),
    "proto_single_level_write": (
        "SKY-D510",
        "src/routes/settings.ts",
        EXPRESS
        + """
const settings = { theme: {} };
router.post('/p', (req, res) => {
  settings.theme[req.body.key] = req.body.value;
  res.end();
});
""",
    ),
    "proto_guarded_merge": (
        "SKY-D510",
        "src/routes/settings.ts",
        EXPRESS
        + """
const settings = {};
function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor') continue;
    if (typeof source[key] === 'object') {
      merge(target[key] = target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
router.post('/s', (req, res) => {
  merge(settings, req.body);
  res.end();
});
""",
    ),
}


@pytest.mark.parametrize(
    "rule_id,file_path,src", SAFE_CASES.values(), ids=SAFE_CASES.keys()
)
def test_framework_safe_forms_not_reported(rule_id, file_path, src):
    assert _hits(_scan_src(src, file_path), rule_id) == []


ADVERSARIAL_CASES = {
    "parse_int_result_unused": (
        "SKY-D211",
        EXPRESS
        + """
router.get('/c/:id', async (req, res) => {
  const id = req.params.id;
  parseInt(id, 10);
  res.json(await pool.query('SELECT * FROM orders WHERE user_id = ' + id));
});
""",
    ),
    "prefix_check_that_only_logs": (
        "SKY-D215",
        EXPRESS
        + """
router.get('/doc', (req, res) => {
  const target = path.resolve(ROOT, req.query.name);
  if (!target.startsWith(ROOT)) {
    console.warn('suspicious path', target);
  }
  fs.createReadStream(target).pipe(res);
});
""",
    ),
    "guard_on_a_different_variable": (
        "SKY-D215",
        EXPRESS
        + """
router.delete('/f', (req, res) => {
  const name = req.body.name;
  const other = req.body.other;
  if (other.includes('..')) {
    return res.sendStatus(400);
  }
  fs.unlink(path.join(ROOT, name), () => res.end());
});
""",
    ),
    "unnormalized_prefix_check": (
        "SKY-D215",
        EXPRESS
        + """
router.get('/raw', (req, res) => {
  const f = req.query.f;
  if (!f.startsWith('uploads/')) {
    return res.sendStatus(403);
  }
  fs.readFile(f, () => res.end());
});
""",
    ),
    "dotdot_check_before_resolve": (
        "SKY-D215",
        EXPRESS
        + """
router.get('/r', (req, res) => {
  const name = req.query.name;
  if (name.includes('..')) {
    return res.sendStatus(400);
  }
  fs.readFile(path.resolve(ROOT, name), () => res.end());
});
""",
    ),
    "guard_then_reassigned": (
        "SKY-D215",
        EXPRESS
        + """
router.get('/re', (req, res) => {
  let p = path.resolve(ROOT, req.query.f);
  if (!p.startsWith(ROOT)) {
    return res.sendStatus(403);
  }
  p = req.query.g;
  fs.readFile(p, () => res.end());
});
""",
    ),
    "local_basename_lookalike": (
        "SKY-D215",
        EXPRESS
        + """
const fake = { basename: (p) => p };
router.get('/f', (req, res) => {
  fs.readFile(path.join(ROOT, fake.basename(req.query.name)), () => res.end());
});
""",
    ),
    "allowlist_checked_after_request": (
        "SKY-D216",
        EXPRESS
        + """
router.get('/late', async (req, res) => {
  const url = new URL(req.query.url);
  const r = await axios.get(url.toString());
  if (!HOSTS.includes(url.hostname)) {
    return res.status(400).end();
  }
  res.json(r.data);
});
""",
    ),
    "allowlist_from_environment": (
        "SKY-D216",
        EXPRESS
        + """
const FROM_ENV = process.env.HOSTS.split(',');
router.get('/env', async (req, res) => {
  const url = new URL(req.query.url);
  if (!FROM_ENV.includes(url.hostname)) {
    return res.status(400).end();
  }
  res.json((await axios.get(url.href)).data);
});
""",
    ),
    "redirect_slash_only_check": (
        "SKY-D230",
        EXPRESS
        + """
router.get('/weak', (req, res) => {
  const next = req.query.next || '/';
  if (!next.startsWith('/')) {
    return res.redirect('/');
  }
  res.redirect(next);
});
""",
    ),
    "local_escape_lookalike": (
        "SKY-D228",
        EXPRESS
        + """
function escapeHtml(s) {
  return s;
}
router.get('/e', (req, res) => {
  res.send(`<p>${escapeHtml(req.query.q)}</p>`);
});
""",
    ),
    "local_quote_lookalike": (
        "SKY-D212",
        """
import express from 'express';
import { exec } from 'child_process';
const router = express.Router();
router.post('/run', (req, res) => {
  const quote = (s) => s;
  exec('convert ' + quote(req.body.file), () => res.end());
});
""",
    ),
}


@pytest.mark.parametrize(
    "rule_id,src", ADVERSARIAL_CASES.values(), ids=ADVERSARIAL_CASES.keys()
)
def test_fake_or_misplaced_proofs_still_report(rule_id, src):
    assert len(_proven(_scan_src(src), rule_id)) == 1


def test_local_html_escaper_clears_xss_unless_it_restores_markup():
    src = (
        EXPRESS
        + """
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function undo(s) {
  return escapeHtml(s).replace(/&lt;/g, '<');
}
router.get('/a', (req, res) => {
  res.send(`<p>${escapeHtml(req.query.q)}</p>`);
});
router.get('/b', (req, res) => {
  res.send(`<p>${undo(req.query.q)}</p>`);
});
"""
    )
    lines = [f["line"] for f in _proven(_scan_src(src), "SKY-D228")]
    assert len(lines) == 1
    assert "undo(" in textwrap.dedent(src).splitlines()[lines[0] - 1]


def test_mongo_sanitize_middleware_in_the_file_clears_nosql():
    src = (
        MONGO
        + """
import mongoSanitize from 'express-mongo-sanitize';
const app = express();
app.use(mongoSanitize());
router.post('/login', async (req, res) => {
  res.json(await User.findOne({ username: req.body.username }));
});
"""
    )
    assert _hits(_scan_src(src, "src/routes/auth.ts"), "SKY-D238") == []


LONE_REQUEST_CASES = {
    "untyped_any_req_exec_both_lines": (
        "SKY-D212",
        """
import { exec } from "child_process";
export function run(req: any) {
  exec("ls " + req.query.dir);
  exec("rm " + req.query.path);
}
""",
        [4, 5],
    ),
    "lone_req_body_into_sql": (
        "SKY-D211",
        """
import { Pool } from 'pg';
const pool = new Pool();
export function find(req) {
  return pool.query("SELECT * FROM t WHERE name = '" + req.body.name + "'");
}
""",
        [5],
    ),
    "lone_req_header_accessor_into_exec": (
        "SKY-D212",
        """
import { exec } from "child_process";
export function run(req) {
  exec("convert " + req.get("x-file"));
}
""",
        [4],
    ),
    "lone_req_path_property_is_not_a_source": (
        "SKY-D215",
        """
const fs = require("fs");
const unzipper = require("unzipper");
function writeReq(req) {
  fs.writeFileSync(req.path, "x");
}
""",
        [],
    ),
    "lone_request_url_is_not_a_source": (
        "SKY-D216",
        """
export async function forward(request) {
  return fetch(request.url);
}
""",
        [],
    ),
}


@pytest.mark.parametrize(
    "rule_id,src,lines", LONE_REQUEST_CASES.values(), ids=LONE_REQUEST_CASES.keys()
)
def test_lone_request_parameter_uses_only_request_data_members(rule_id, src, lines):
    found = _proven(_scan_src(src, "src/lib/run.ts"), rule_id)
    assert sorted(f["line"] for f in found) == lines
    assert all(f["severity"] == "CRITICAL" for f in found if rule_id in {"SKY-D211", "SKY-D212"})


def test_proven_ssrf_upgrades_the_pattern_finding():
    src = (
        EXPRESS
        + """
router.get('/p', async (req, res) => {
  res.json((await axios.get(req.query.url)).data);
});
"""
    )
    hits = _hits(_scan_src(src), "SKY-D216")
    assert [(f["severity"], bool(f.get("security_evidence"))) for f in hits] == [
        ("HIGH", True)
    ]
