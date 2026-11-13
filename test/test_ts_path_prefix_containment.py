"""TS/JS: a startsWith check proves containment only when the prefix ends at
a separator. ``'/srv/files2/x'.startsWith('/srv/files')`` is true."""

import textwrap

import pytest

from skylos.visitors.languages.typescript.danger import scan_danger

try:
    from tree_sitter import Language, Parser
    import tree_sitter_typescript

    TS_LANG = Language(tree_sitter_typescript.language_typescript())
except Exception:  # pragma: no cover - optional dependency
    TS_LANG = None

pytestmark = pytest.mark.skipif(
    TS_LANG is None, reason="tree-sitter-typescript missing"
)

EXPRESS = """
import express from 'express';
import fs from 'fs';
import path from 'path';
const router = express.Router();
const ROOT = path.join(__dirname, 'files');
const FIXED = '/srv/files';
const FIXED_PREFIX = '/srv/files/';
const PREFIX = ROOT + path.sep;
"""


def route(check, setup="  const target = path.resolve(ROOT, req.query.name);\n"):
    return (
        EXPRESS
        + "\nrouter.get('/doc', (req, res) => {\n"
        + setup
        + f"  if (!{check}) {{\n"
        + "    return res.status(403).end();\n"
        + "  }\n"
        + "  fs.createReadStream(target).pipe(res);\n"
        + "});\n"
    )


def traversals(src, file_path="src/routes/app.ts"):
    source = textwrap.dedent(src).encode()
    tree = Parser(TS_LANG).parse(source)
    findings = scan_danger(tree.root_node, file_path, TS_LANG, source)
    return [f for f in findings if f["rule_id"] == "SKY-D215"]


@pytest.mark.parametrize(
    ("check", "setup"),
    [
        ("target.startsWith(ROOT)", None),
        (
            "target.startsWith(FIXED)",
            "  const target = path.resolve(FIXED, req.query.name);\n",
        ),
        ("target.startsWith(path.resolve(ROOT))", None),
        (
            "target.startsWith(root)",
            "  const root = loadRoot();\n  const target = path.resolve(root, req.query.name);\n",
        ),
        ("target.startsWith(path.join(ROOT, 'public'))", None),
    ],
)
def test_prefix_without_a_separator_is_reported(check, setup):
    if setup is None:
        setup = "  const target = path.resolve(ROOT, req.query.name);\n"

    found = traversals(route(check, setup))

    assert len(found) == 1
    assert found[0].get("security_evidence")


@pytest.mark.parametrize(
    "check",
    [
        "target.startsWith(ROOT + path.sep)",
        "target.startsWith(ROOT + '/')",
        "target.startsWith(`${ROOT}/`)",
        "target.startsWith(FIXED_PREFIX)",
        "target.startsWith('/srv/files/')",
        "target.startsWith(PREFIX)",
        "target.startsWith(path.join(ROOT, 'public/'))",
    ],
)
def test_prefix_ending_at_a_separator_stays_quiet(check):
    assert traversals(route(check)) == []


def test_sibling_prefix_in_a_positive_branch_is_reported():
    src = (
        EXPRESS
        + "\nrouter.get('/doc', (req, res) => {\n"
        + "  const target = path.resolve(ROOT, req.query.name);\n"
        + "  if (target.startsWith(ROOT)) {\n"
        + "    fs.createReadStream(target).pipe(res);\n"
        + "  }\n"
        + "});\n"
    )

    assert len(traversals(src)) == 1


@pytest.mark.parametrize(
    "check", ["target.startsWith('/')", "target.startsWith(path.sep)"]
)
def test_root_prefix_alone_is_not_containment(check):
    assert len(traversals(route(check))) == 1


def test_prefix_variable_reassigned_is_not_proven():
    src = route(
        "target.startsWith(prefix)",
        "  let prefix = ROOT + path.sep;\n  prefix = ROOT;\n"
        "  const target = path.resolve(ROOT, req.query.name);\n",
    )

    assert len(traversals(src)) == 1
