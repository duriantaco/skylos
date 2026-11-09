"""Gaps the hook-loop replay exposed. Every new block sits next to a control
that must stay quiet: a helper with a plain parameter is still only a note."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.commands.hook_policy import classify_findings, finding_touches_ranges


def _finding(line, rule, category="security", **extra):
    return {"line": line, "rule_id": rule, "category": category, **extra}


def _blocks(source, line, rule, name="app.ts", **extra):
    finding = _finding(line, rule, **extra)
    classify_findings([finding], Path(name), source)
    return finding["blocking"]


@pytest.mark.parametrize(
    "source, line, rule",
    [
        (
            "router.get('/s', async (req: Request, res: Response) => {\n"
            "  const term = String(req.query.q || '');\n"
            "  await prisma.$queryRawUnsafe(\n"
            "    `SELECT * FROM a WHERE t = '${term}'`,\n"
            "  );\n"
            "});\n",
            3,
            "SKY-D211",
        ),
        (
            "router.post('/t', (req, res) => {\n"
            "  const image = req.body.image;\n"
            "  exec(`convert ${image}`, (error) => {\n"
            "    res.end();\n"
            "  });\n"
            "});\n",
            3,
            "SKY-D212",
        ),
        (
            "app.get('/i/:name', (req, res) => {\n"
            "  res.sendFile(path.join(root, req.params.name));\n"
            "});\n",
            2,
            "SKY-D215",
        ),
        (
            "app.post('/d', (req, res) => {\n"
            "  const { target } = req.body;\n"
            "  res.redirect(target);\n"
            "});\n",
            3,
            "SKY-D230",
        ),
        (
            "fastify.get('/f', async (request, reply) => {\n"
            "  const name = request.query.name;\n"
            "  return readFile(name);\n"
            "});\n",
            3,
            "SKY-D215",
        ),
        (
            "router.get('/k', async (ctx) => {\n"
            "  const url = ctx.query.url;\n"
            "  ctx.body = await fetch(url);\n"
            "});\n",
            3,
            "SKY-D216",
        ),
        (
            "app.get('/h', async (c) => {\n"
            "  const sql = c.req.query('sql');\n"
            "  return c.json(await db.unsafe(sql));\n"
            "});\n",
            3,
            "SKY-D211",
        ),
        (
            "@Controller('users')\n"
            "export class UsersController {\n"
            "  @Get(':id')\n"
            "  find(@Param('id') id: string) {\n"
            "    return this.db.query(`SELECT * FROM u WHERE id = ${id}`);\n"
            "  }\n"
            "}\n",
            5,
            "SKY-D211",
        ),
        (
            "export async function GET(request: NextRequest) {\n"
            "  const file = request.nextUrl.searchParams.get('file');\n"
            "  return readFile(file);\n"
            "}\n",
            3,
            "SKY-D215",
        ),
        (
            "router.get('/n', (req, res) => {\n"
            "  const q = req.query.q;\n"
            "  run(() => {\n"
            "    exec(q);\n"
            "  });\n"
            "});\n",
            4,
            "SKY-D212",
        ),
        (
            "const target = process.argv[2];\nreadFileSync(target);\n",
            2,
            "SKY-D215",
        ),
    ],
)
def test_javascript_source_reaching_a_sink_blocks(source, line, rule):
    assert _blocks(source, line, rule)


@pytest.mark.parametrize(
    "source, line, rule",
    [
        ("function load(p) {\n  return readFileSync(p);\n}\n", 2, "SKY-D215"),
        (
            "router.get('/', (req, res) => {\n"
            "  const q = req.query.q;\n"
            "  res.sendFile(path.join(root, 'index.html'));\n"
            "});\n",
            3,
            "SKY-D215",
        ),
        ("const query = 'SELECT 1';\ndb.query(query);\n", 2, "SKY-D211"),
        (
            "const params = { a: 1 };\nconst body = 'x';\nfetch(url, params, body);\n",
            3,
            "SKY-D216",
        ),
        (
            "router.get('/', (req, res) => {\n"
            "  const { name } = config;\n"
            "  readFile(user.name);\n"
            "});\n",
            3,
            "SKY-D215",
        ),
        (
            "export class A {\n  find(id: string) {\n    return run(id);\n  }\n}\n",
            3,
            "SKY-D212",
        ),
    ],
)
def test_javascript_without_a_real_source_stays_a_note(source, line, rule):
    assert not _blocks(source, line, rule)


def test_the_reported_column_picks_the_sink_on_a_line_with_a_callback():
    callback = (
        "router.get('/', (req, res) => {\n"
        "  readFile(name, () => res.send(req.query.q));\n"
        "});\n"
    )
    one_liner = "app.get('/x', (req, res) => res.sendFile(req.query.p));\n"
    assert not _blocks(callback, 2, "SKY-D215", col=2)
    assert _blocks(one_liner, 1, "SKY-D215", col=28)


@pytest.mark.parametrize(
    "source, blocking",
    [
        ("const f = eval('(' + String(x) + ')');\n", True),
        ("const f = req.query.f ? eval(req.query.f) : null;\n", True),
        ("new Function(code)();\n", True),
        ("eval('1 + 1');\n", False),
        ("eval(`1 + 1`);\n", False),
    ],
)
def test_javascript_eval_blocks_unless_every_argument_is_constant(source, blocking):
    assert _blocks(source, 1, "SKY-D201") is blocking


def test_invalid_javascript_never_blocks_on_taint():
    assert not _blocks("router.get('/', (req => {\n  exec(req.query.q\n", 2, "SKY-D212")


@pytest.mark.parametrize(
    "rule, category",
    [
        ("SKY-D349", "security"),
        ("SKY-L011", "ai_defect"),
        ("SKY-L014", "quality"),
        ("SKY-L021", "quality"),
    ],
)
def test_rules_that_are_unsafe_whatever_the_input_block(rule, category):
    assert _blocks("x = 1\n", 1, rule, name="app.py", category=category)


@pytest.mark.parametrize("rule", ["SKY-D207", "SKY-D250", "SKY-D231"])
def test_rules_held_as_notes_stay_notes(rule):
    assert not _blocks("x = 1\n", 1, rule, name="app.py")


def test_xss_blocks_with_a_source_and_stays_a_note_for_a_helper():
    route = "app.get('/x', (req, res) => {\n  res.send(`<b>${req.query.q}</b>`);\n});\n"
    helper = "function page(q) {\n  return res.send(`<b>${q}</b>`);\n}\n"
    assert _blocks(route, 2, "SKY-D228")
    assert not _blocks(helper, 2, "SKY-D228")


@pytest.mark.parametrize(
    "line, blocking",
    [
        ("q = form.search.data", True),
        ("q = g.search_form.q.data", True),
        ("q = form.cleaned_data['q']", True),
        ("q = response.data", False),
        ("q = transform.value.data", False),
    ],
)
def test_python_form_fields_are_sources(line, blocking):
    source = (
        "@bp.route('/search')\n"
        "def search():\n"
        f"    {line}\n"
        '    return db.session.execute(sa.text(f"SELECT {q}"))\n'
    )
    assert _blocks(source, 4, "SKY-D211", name="routes.py") is blocking


def _touches(
    source, finding_line, ranges, rule="SKY-D232", category="security", name="deps.py"
):
    return finding_touches_ranges(
        _finding(finding_line, rule, category=category), ranges, Path(name), source
    )


MULTILINE = (
    "def get(token):\n"
    "    payload = jwt.decode(\n"
    "        token,\n"
    "        options={'verify_signature': False},\n"
    "    )\n"
    "    return payload\n"
)


def test_sink_on_a_multiline_call_is_in_scope_when_an_inner_line_changed():
    assert _touches(MULTILINE, 2, [(4, 4)])


def test_multiline_scope_does_not_reach_other_statements():
    assert not _touches(MULTILINE, 2, [(6, 6)])
    assert not _touches(MULTILINE, 6, [(4, 4)])


def test_multiline_scope_does_not_cover_secrets_in_an_edited_literal():
    source = "CONFIG = {\n    'key': 'value',\n    'other': 1,\n}\n"
    assert not _touches(source, 1, [(3, 3)], rule="SKY-S101", category="secret")
    assert not _touches(source, 2, [(3, 3)], rule="SKY-S101", category="secret")


def test_multiline_scope_stops_at_a_function_header_body():
    source = "def f(\n    a,\n):\n    return a\n"
    assert not _touches(source, 1, [(4, 4)])


def test_multiline_scope_in_typescript_stops_at_a_nested_callback():
    source = "router.get(\n  '/x',\n  (req, res) => {\n    res.end();\n  },\n);\n"
    assert _touches(source, 1, [(2, 2)], name="app.ts")
    assert not _touches(source, 1, [(4, 4)], name="app.ts")


def test_whole_file_and_empty_ranges_keep_their_meaning():
    assert _touches(MULTILINE, 6, None)
    assert not _touches(MULTILINE, 2, [])


ROUTE = (
    "from fastapi import APIRouter, Depends, HTTPException\n"
    "\n"
    "router = APIRouter()\n"
    "\n"
    "\n"
    "@router.put('/items/{item_id}')\n"
    "def update_item(item_id: int, user=Depends(current_user)):\n"
    "    item = load(item_id)\n"
    "    print('updating')\n"
    "    if item.owner_id != user.id:\n"
    "        raise HTTPException(status_code=403)\n"
    "    return save(item)\n"
    "\n"
    "\n"
    "def current_user():\n"
    "    return None\n"
    "\n"
    "\n"
    "def load(item_id):\n"
    "    return item_id\n"
    "\n"
    "\n"
    "def save(item):\n"
    "    return item\n"
)
OWNERSHIP = (
    "    if item.owner_id != user.id:\n        raise HTTPException(status_code=403)\n"
)


def _git_project(tmp_path: Path, source: str) -> Path:
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
    (tmp_path / ".gitignore").write_text(".skylos/\n")
    (tmp_path / "app.py").write_text(source)
    for command in (
        ["init", "-q"],
        ["add", "-A"],
        [*identity, "commit", "-qm", "base"],
    ):
        subprocess.run(
            ["git", *command], cwd=tmp_path, check=True, capture_output=True, env=env
        )
    return tmp_path


def _deletion_edit(root: Path, removed: str):
    before = (root / "app.py").read_text()
    assert removed in before
    start = before[: before.index(removed)].count("\n") + 1
    (root / "app.py").write_text(before.replace(removed, ""))
    lines = [f"-{line}" for line in removed.splitlines()]
    payload = {
        "session_id": "del",
        "cwd": str(root),
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(root / "app.py"),
            "old_string": removed,
            "new_string": "",
        },
        "tool_response": {
            "structuredPatch": [
                {
                    "oldStart": start,
                    "oldLines": len(lines),
                    "newStart": start,
                    "newLines": 0,
                    "lines": lines,
                }
            ]
        },
    }
    deps = HookDeps()
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    if not text:
        return {}
    return json.loads(text)


def test_an_edit_that_only_deletes_an_ownership_check_blocks(tmp_path):
    root = _git_project(tmp_path, ROUTE)

    out = _deletion_edit(root, OWNERSHIP)

    assert out.get("decision") == "block"
    assert "SKY-L021" in out["reason"]


def test_an_edit_that_only_deletes_unrelated_code_does_not_block(tmp_path):
    root = _git_project(tmp_path, ROUTE)

    out = _deletion_edit(root, "    print('updating')\n")

    assert out.get("decision") != "block"


def test_a_hard_coded_password_reaches_the_agent_and_blocks(tmp_path):
    root = _git_project(tmp_path, "value = 1\n")
    (root / "app.py").write_text(
        "import os\n\nPASSWORD = os.environ.get('MAIL_PASSWORD') or 'Mb!2024-smtp-Pa55w0rd'\n"
    )
    payload = {
        "session_id": "pw",
        "cwd": str(root),
        "tool_name": "Write",
        "tool_input": {"file_path": str(root / "app.py")},
    }
    deps = HookDeps()
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    out = json.loads(stdout.getvalue())
    assert out["decision"] == "block"
    assert "SKY-L014" in out["reason"]
    assert "Pa55w0rd" not in out["reason"]


def _manifest_edit(root: Path, name: str, text: str, verify):
    (root / name).write_text(text)
    payload = {
        "session_id": "manifest",
        "cwd": str(root),
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(root / name),
            "old_string": "x",
            "new_string": text.splitlines()[-1],
        },
    }
    deps = HookDeps(verify=verify)
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    if not text:
        return {}
    return json.loads(text)


def _verify_reporting(*findings):
    calls = []

    def verify(target, **kwargs):
        calls.append(target)
        return {
            "status": "fail",
            "findings": [
                {
                    "rule_id": rule,
                    "severity": "HIGH",
                    "category": "ai_defect",
                    "message": f"{rule} message",
                    "range": {"file": Path(target).name, "start_line": line},
                }
                for rule, line in findings
            ],
        }

    verify.calls = calls
    return verify


def test_a_fake_dependency_added_to_a_manifest_blocks(tmp_path):
    root = _git_project(tmp_path, "value = 1\n")
    verify = _verify_reporting(("SKY-D222", 2))

    out = _manifest_edit(
        root, "requirements.txt", "requests==2.32.3\nfake-pkg==9.9\n", verify
    )

    assert out["decision"] == "block"
    assert "requirements.txt:2 SKY-D222" in out["reason"]


def test_an_old_bad_dependency_on_an_unchanged_manifest_line_does_not_block(tmp_path):
    root = _git_project(tmp_path, "value = 1\n")
    verify = _verify_reporting(("SKY-D222", 1))

    out = _manifest_edit(
        root, "requirements.txt", "fake-pkg==9.9\nrequests==2.32.3\n", verify
    )

    assert out.get("decision") != "block"


def test_only_dependency_rules_are_taken_from_a_manifest(tmp_path):
    root = _git_project(tmp_path, "value = 1\n")
    verify = _verify_reporting(("SKY-L030", 1))

    out = _manifest_edit(root, "requirements.txt", "requests==2.32.3\n", verify)

    assert out == {}


def test_a_file_that_is_not_a_manifest_is_not_verified(tmp_path):
    root = _git_project(tmp_path, "value = 1\n")
    verify = _verify_reporting(("SKY-D222", 1))

    out = _manifest_edit(root, "notes.yaml", "a: 1\n", verify)

    assert out.get("decision") != "block"
    assert verify.calls == []


def test_flask_debug_blocks():
    assert _blocks("x = 1\n", 1, "SKY-D346", name="app.py")


@pytest.mark.parametrize(
    "message, blocking",
    [
        ("CORS misconfiguration: wildcard origin with allow_credentials=True", True),
        ("CORS misconfiguration: wildcard origin with supports_credentials=True", True),
        ("CORS misconfiguration: CORS_ALLOW_ALL_ORIGINS = True", False),
        ("CORS misconfiguration: Access-Control-Allow-Origin set to '*'", False),
    ],
)
def test_cors_blocks_only_with_credentials(message, blocking):
    assert _blocks("x = 1\n", 1, "SKY-D231", name="app.py", message=message) is blocking


@pytest.mark.parametrize(
    "source, line",
    [
        ('def find(term: str):\n    return text(f"SELECT {term}")\n', 2),
        ('def find(term):\n    return cursor.execute("SELECT " + term)\n', 2),
        ('def find(term):\n    return cursor.execute("SELECT %s" % term)\n', 2),
        ('def find(term):\n    return cursor.execute("SELECT {}".format(term))\n', 2),
        (
            'def find(term):\n    sql = f"SELECT {term}"\n    return cursor.execute(sql)\n',
            3,
        ),
        (
            "def find(term):\n"
            "    cleaned = term.strip()\n"
            '    return cursor.execute(f"SELECT {cleaned}")\n',
            3,
        ),
    ],
)
def test_python_sql_built_from_a_parameter_blocks(source, line):
    assert _blocks(source, line, "SKY-D211", name="crud.py")


@pytest.mark.parametrize(
    "source, line",
    [
        ('TABLE = "users"\ndef find():\n    return text(f"SELECT {TABLE}")\n', 3),
        ('def find():\n    table = "users"\n    return text(f"SELECT {table}")\n', 3),
        ("def run(sql, params):\n    return cursor.execute(sql, params)\n", 2),
        ('def find(term):\n    return cursor.execute("SELECT %s", (term,))\n', 2),
        ('def find(limit: int):\n    return text(f"SELECT LIMIT {limit}")\n', 2),
        ('def find(on: bool):\n    return text(f"SELECT {on}")\n', 2),
        (
            'class R:\n    def find(self):\n        return text(f"SELECT {self.table}")\n',
            3,
        ),
        ('text(f"SELECT {TABLE}")\n', 1),
    ],
)
def test_python_sql_controls_stay_notes(source, line):
    assert not _blocks(source, line, "SKY-D211", name="crud.py")


def test_parameter_interpolation_only_applies_to_sql_rules():
    source = 'def show(name):\n    return open(f"/tmp/{name}")\n'
    assert not _blocks(source, 2, "SKY-D215", name="crud.py")
    assert not _blocks(source, 2, "SKY-D228", name="crud.py")


@pytest.mark.parametrize(
    "source, line",
    [
        (
            "export function helper(term: string) {\n"
            "  return prisma.$queryRawUnsafe(`SELECT ${term}`);\n"
            "}\n",
            2,
        ),
        ("function find(term) {\n  return db.query('SELECT ' + term);\n}\n", 2),
        (
            "const find = (term) => {\n"
            "  const sql = `SELECT ${term}`;\n"
            "  return db.query(sql);\n"
            "};\n",
            3,
        ),
    ],
)
def test_javascript_sql_built_from_a_parameter_blocks(source, line):
    assert _blocks(source, line, "SKY-D211")


@pytest.mark.parametrize(
    "source, line",
    [
        ("const T = 'u';\nfunction f() {\n  return db.query(`SELECT ${T}`);\n}\n", 3),
        ("function run(sql, params) {\n  return db.query(sql, params);\n}\n", 2),
        ("function f(id) {\n  return db.query('SELECT $1', [id]);\n}\n", 2),
        ("function f(n: number) {\n  return db.query(`LIMIT ${n}`);\n}\n", 2),
        ("function f(id) {\n  return sql`SELECT ${id}`;\n}\n", 2),
    ],
)
def test_javascript_sql_controls_stay_notes(source, line):
    assert not _blocks(source, line, "SKY-D211")


GUARDED = (
    "COLUMNS = ('id', 'qty')\n"
    "def rows(conn, sort, direction):\n"
    "    if sort not in COLUMNS:\n"
    "        raise ValueError(sort)\n"
    "    if direction not in ('asc', 'desc'):\n"
    "        raise ValueError(direction)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort} {direction}")\n'
)


def test_an_allowlisted_identifier_is_not_interpolated_sql():
    assert not _blocks(GUARDED, 7, "SKY-D211", name="db.py")


@pytest.mark.parametrize(
    "source",
    [
        "def rows(conn, sort):\n"
        "    if sort not in COLUMNS:\n"
        "        print(sort)\n"
        '    return conn.execute(f"SELECT {sort}")\n',
        "def rows(conn, sort, other):\n"
        "    if other not in COLUMNS:\n"
        "        raise ValueError(other)\n"
        '    return conn.execute(f"SELECT {sort}")\n',
        "def rows(conn, sort, flag):\n"
        "    if flag:\n"
        "        if sort not in COLUMNS:\n"
        "            raise ValueError(sort)\n"
        '    return conn.execute(f"SELECT {sort}")\n',
        "def rows(conn, sort):\n"
        '    conn.execute(f"SELECT {sort}")\n'
        "    if sort not in COLUMNS:\n"
        "        raise ValueError(sort)\n"
        "    return 1\n",
        "def rows(conn, sort, allowed):\n"
        "    if sort not in allowed:\n"
        "        raise ValueError(sort)\n"
        '    return conn.execute(f"SELECT {sort}")\n',
    ],
)
def test_a_guard_that_proves_nothing_still_blocks(source):
    line = next(
        number
        for number, text in enumerate(source.splitlines(), 1)
        if "execute" in text
    )
    assert _blocks(source, line, "SKY-D211", name="db.py")


def test_a_lookup_in_a_constant_map_is_not_interpolated_sql():
    source = (
        "ORDERS = {'asc': 'ASC', 'desc': 'DESC'}\n"
        "def rows(conn, direction):\n"
        "    order = ORDERS[direction]\n"
        '    return conn.execute(f"SELECT 1 ORDER BY id {order}")\n'
    )
    assert not _blocks(source, 4, "SKY-D211", name="db.py")


def test_a_route_with_an_allowlisted_sort_does_not_block_but_without_one_does():
    guarded = (
        "@bp.get('/items')\n"
        "def items():\n"
        "    sort = request.args.get('sort')\n"
        "    if sort not in COLUMNS:\n"
        "        abort(400)\n"
        '    return db.execute(f"SELECT 1 ORDER BY {sort}")\n'
    )
    open_route = guarded.replace(
        "    if sort not in COLUMNS:\n        abort(400)\n", ""
    )
    assert not _blocks(guarded, 6, "SKY-D211", name="routes.py")
    assert _blocks(open_route, 4, "SKY-D211", name="routes.py")


def test_an_allowlist_does_not_excuse_other_sinks_on_the_same_value():
    source = (
        "@bp.get('/f')\n"
        "def f():\n"
        "    name = request.args.get('name')\n"
        "    if name not in NAMES:\n"
        "        abort(400)\n"
        "    return open(name)\n"
    )
    assert _blocks(source, 6, "SKY-D215", name="routes.py")


@pytest.mark.parametrize(
    "guard",
    [
        "if (!COLUMNS.includes(sort)) throw new Error('x');",
        "if (!COLUMNS.has(sort)) { return null; }",
        "if (COLUMNS.indexOf(sort) === -1) { throw new Error('x'); }",
    ],
)
def test_javascript_allowlist_is_not_interpolated_sql(guard):
    source = (
        "function rows(sort) {\n"
        f"  {guard}\n"
        "  return db.query(`SELECT 1 ORDER BY ${sort}`);\n"
        "}\n"
    )
    assert not _blocks(source, 3, "SKY-D211")


@pytest.mark.parametrize(
    "guard",
    [
        "if (!COLUMNS.includes(other)) throw new Error('x');",
        "if (!COLUMNS.includes(sort)) console.log(sort);",
        "if (!allowed.includes(sort)) throw new Error('x');",
    ],
)
def test_javascript_guard_that_proves_nothing_still_blocks(guard):
    source = (
        "function rows(sort, other, allowed) {\n"
        f"  {guard}\n"
        "  return db.query(`SELECT 1 ORDER BY ${sort}`);\n"
        "}\n"
    )
    assert _blocks(source, 3, "SKY-D211")
