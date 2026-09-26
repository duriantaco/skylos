"""Express request data reaching TS/JS sinks (agent-code benchmark misses)."""

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
    "send_plain_text": (
        "SKY-D228",
        """
        router.get('/echo/:name', (req, res) => {
          res.send(`hello ${req.params.name}`);
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
