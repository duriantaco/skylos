"""Chained-call SQL injection and file-serving path traversal (Python).

Covers SKY-D211 on ``<db call>().execute(...)`` receivers, SKY-D215 on
Starlette/FastAPI ``FileResponse`` and Flask ``send_file`` /
``send_from_directory``, and the ``security_evidence`` source packet these
findings carry for SARIF codeFlows and the agent hook.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.commands import hook_policy
from skylos.reporting.sarif import SarifExporter
from skylos.rules.danger import untrusted_sources
from skylos.rules.danger.danger import scan_ctx


def _scan(tmp_path: Path, code: str, name: str = "app.py") -> list[dict]:
    path = tmp_path / name
    path.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return scan_ctx(tmp_path, [path])


def _hits(findings, rule):
    return sorted(f["line"] for f in findings if f["rule_id"] == rule)


def _evidence(finding):
    return (finding.get("metadata") or {}).get("security_evidence")


# --------------------------------------------------------------------------
# SQL injection through chained connection / cursor calls
# --------------------------------------------------------------------------

SQL_POSITIVE = """
import os
import sqlite3
import sys

from fastapi import FastAPI
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine("sqlite://")


@app.get("/a/{uid}")
def chained(uid: str):
    return sqlite3.connect("x").execute("SELECT * FROM t WHERE id = " + uid).fetchall()


@app.get("/b/{x}")
def cursor_chain(x: str):
    conn = sqlite3.connect("x")
    return conn.cursor().execute(f"SELECT * FROM t WHERE id = {x}").fetchall()


@app.get("/c/{x}")
def engine_chain(x: str):
    return engine.connect().execute(text(f"SELECT * FROM t WHERE id = {x}"))


@app.get("/d/{x}")
def session_text(x: str, session=None):
    return session.execute(text("SELECT * FROM t WHERE id = " + x))


@app.get("/e/{x}")
def db_mod(x: str, db=None):
    return db.execute("SELECT * FROM t WHERE id = %s" % x)


def get_db():
    return sqlite3.connect("x")


@app.post("/f")
async def factory(request):
    body = await request.json()
    return get_db().executescript("DELETE FROM t WHERE id = " + body["id"])


def cli():
    sqlite3.connect("x").cursor().execute("SELECT * FROM t WHERE n = '%s'" % sys.argv[1])
"""


def test_chained_sql_sinks_flagged_with_rule_and_line(tmp_path):
    findings = _scan(tmp_path, SQL_POSITIVE)
    assert _hits(findings, "SKY-D211") == [14, 20, 25, 30, 30, 35, 45, 49]
    chained = [f for f in findings if f["rule_id"] == "SKY-D211" and f["line"] == 14]
    assert chained[0]["severity"] == "CRITICAL"
    assert chained[0]["symbol"] == "chained"


def test_chained_sql_findings_carry_source_evidence(tmp_path):
    findings = _scan(tmp_path, SQL_POSITIVE)
    by_line = {f["line"]: f for f in findings if f["rule_id"] == "SKY-D211"}

    route = _evidence(by_line[14])
    assert route["source"] == "route parameter `uid` of `chained` (@app.get)"
    assert route["sink"] == "SQL text passed to .execute()"
    assert route["guards_missing"] == ["parameterized SQL binding"]
    assert route["path"] == [
        "untrusted `uid` from route parameter `uid` of `chained` (@app.get)",
        "reaches SQL text passed to .execute()",
    ]
    # No paths or line numbers: review-decision context hashes include the
    # packet, so it must survive line shifts and snapshot checkouts.
    assert str(tmp_path) not in json.dumps(route)

    assert _evidence(by_line[45])["source"] == "request data `request.json`"
    assert _evidence(by_line[49])["source"] == "`sys.argv`"


SQL_NEGATIVE = """
import sqlite3

from fastapi import FastAPI
from sqlalchemy import create_engine, text
from sqlmodel import Session, delete, select

app = FastAPI()
engine = create_engine("sqlite://")
TABLE = "t"


@app.get("/a/{uid}")
def parameterized(uid: str):
    return sqlite3.connect("x").execute("SELECT * FROM t WHERE id = ?", (uid,)).fetchall()


@app.get("/b/{uid}")
def bound_text(uid: str):
    return engine.connect().execute(text("SELECT * FROM t WHERE id = :id"), {"id": uid})


@app.get("/c")
def constant_fstring():
    return sqlite3.connect("x").cursor().execute(f"SELECT * FROM {TABLE}").fetchall()


@app.get("/d/{rows}")
def executemany(rows: list):
    sqlite3.connect("x").executemany("INSERT INTO t VALUES (?)", rows)


@app.get("/e")
def static_text():
    with engine.begin() as conn:
        conn.execute(text("SELECT 1"))


@app.get("/f/{user_id}")
def orm_constructs(user_id: int, session: Session):
    session.execute(select(User).where(User.id == user_id))
    session.execute(delete(Item))


def helper(query):
    # A plain helper parameter is not an untrusted source for chained calls.
    return sqlite3.connect("x").execute(query)


def not_a_database(q):
    return make_client().execute(q)
"""


def test_chained_sql_negatives_stay_clean(tmp_path):
    findings = _scan(tmp_path, SQL_NEGATIVE)
    assert [f for f in findings if f["rule_id"] in {"SKY-D211", "SKY-D217"}] == []


# --------------------------------------------------------------------------
# Path traversal through file-serving helpers
# --------------------------------------------------------------------------

PATH_POSITIVE = """
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from flask import request, send_file, send_from_directory
from starlette.responses import FileResponse as StarletteFile

app = FastAPI()
BASE = "/srv/files"


def upload_root() -> Path:
    return Path("/srv/uploads")


@app.get("/a/{name}")
def download(name: str):
    return FileResponse(upload_root() / name)


@app.get("/b")
async def download_join(name: str):
    return FileResponse(os.path.join(BASE, name))


@app.get("/c/{name}")
def starlette_alias(name: str):
    target = Path(BASE) / name
    return StarletteFile(path=target)


@app.route("/d/<filename>")
def flask_send_file(filename):
    return send_file(os.path.join(BASE, filename))


@app.route("/e")
def flask_query():
    return send_file(request.args.get("p"))


@app.route("/f")
def flask_directory():
    return send_from_directory(request.args["dir"], "report.txt")


@app.get("/g/{name}")
def guard_does_not_stop(name: str):
    target = (Path(BASE) / name).resolve()
    if not target.is_relative_to(BASE):
        print("outside base")
    return FileResponse(target)


@app.get("/h/{name}")
def unnormalized_prefix_check(name: str):
    target = os.path.join(BASE, name)
    if not target.startswith(BASE):
        raise ValueError(name)
    return FileResponse(target)


@app.get("/i/{name}")
def only_the_base_is_normalized(name: str):
    base = Path(BASE).resolve()
    if not (base / name).is_relative_to(base):
        raise ValueError(name)
    return FileResponse(base / name)
"""


def test_file_serving_sinks_flagged_with_rule_and_line(tmp_path):
    findings = _scan(tmp_path, PATH_POSITIVE)
    assert _hits(findings, "SKY-D215") == [19, 24, 30, 35, 40, 45, 53, 61, 69]
    first = [f for f in findings if f["rule_id"] == "SKY-D215" and f["line"] == 19]
    assert first[0]["severity"] == "HIGH"
    assert "FileResponse()" in first[0]["message"]
    evidence = _evidence(first[0])
    assert evidence["source"] == "route parameter `name` of `download` (@app.get)"
    assert evidence["sink"] == "filesystem path served by FileResponse()"


PATH_NEGATIVE = """
import io
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from flask import send_file, send_from_directory
from werkzeug.utils import safe_join

app = FastAPI()
BASE = Path("/srv/files")
UPLOAD = "/srv/uploads"
ALLOWED = {"a.txt": "a.txt", "b.txt": "b.txt"}


@app.get("/a/{name}")
def resolved_is_relative_to(name: str):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE.resolve()):
        raise HTTPException(404)
    return FileResponse(target)


@app.get("/b/{name}")
def realpath_commonpath(name: str):
    target = os.path.realpath(os.path.join(UPLOAD, name))
    if os.path.commonpath([target, UPLOAD]) != UPLOAD:
        raise HTTPException(404)
    return FileResponse(target)


@app.get("/c/{name}")
def allowlist_lookup(name: str):
    if name not in ALLOWED:
        raise HTTPException(404)
    return FileResponse(BASE / ALLOWED[name])


@app.get("/d/{name}")
def allowlist_membership(name: str):
    if name not in ALLOWED:
        raise HTTPException(404)
    return FileResponse(BASE / name)


@app.get("/e")
def constant_path():
    return FileResponse(BASE / "index.html")


@app.get("/f/{name}")
def positive_branch(name: str):
    target = (BASE / name).resolve()
    if target.is_relative_to(BASE):
        return FileResponse(target)
    raise HTTPException(404)


@app.get("/g/{name}")
def relative_to_raises(name: str):
    target = (BASE / name).resolve()
    try:
        target.relative_to(BASE)
    except ValueError:
        raise HTTPException(404)
    return FileResponse(target)


@app.route("/h/<filename>")
def flask_safe_directory(filename):
    return send_from_directory(UPLOAD, filename)


@app.route("/i/<filename>")
def flask_safe_join(filename):
    return send_file(safe_join(UPLOAD, filename))


@app.route("/j/<filename>")
def flask_basename(filename):
    return send_file(os.path.join(UPLOAD, os.path.basename(filename)))


@app.route("/k/<text>")
def flask_buffer(text):
    return send_file(io.BytesIO(text.encode()), download_name="x.txt")


def forwarding_wrapper(directory, path):
    # A library wrapper forwarding its own parameters has no untrusted source.
    return send_from_directory(directory, path)
"""


def test_file_serving_negatives_stay_clean(tmp_path):
    findings = _scan(tmp_path, PATH_NEGATIVE)
    assert [f for f in findings if f["rule_id"] == "SKY-D215"] == []


def test_django_file_response_is_not_treated_as_a_path_sink(tmp_path):
    code = """
    from django.http import FileResponse

    def view(request, name):
        return FileResponse(open("/srv/static/logo.png", "rb"))
    """
    findings = _scan(tmp_path, code)
    assert _hits(findings, "SKY-D215") == []


# --------------------------------------------------------------------------
# End to end: analyzer, SARIF codeFlows, hook policy
# --------------------------------------------------------------------------

FASTAPI_APP = """
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()
UPLOADS = Path("/srv/uploads")


@app.get("/users/{uid}")
def read_user(uid: str):
    return sqlite3.connect("app.db").execute("SELECT * FROM users WHERE id = " + uid).fetchall()


@app.get("/files/{name}")
def read_file(name: str):
    return FileResponse(UPLOADS / name)


@app.get("/safe/{uid}")
def read_user_safe(uid: str):
    return sqlite3.connect("app.db").execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()


@app.get("/safe-files/{name}")
def read_file_safe(name: str):
    target = (UPLOADS / name).resolve()
    if not target.is_relative_to(UPLOADS.resolve()):
        raise ValueError(name)
    return FileResponse(target)
"""


def _analyze_danger(tmp_path: Path) -> list[dict]:
    project = tmp_path / "svc"
    project.mkdir()
    (project / "main.py").write_text(FASTAPI_APP.lstrip("\n"), encoding="utf-8")
    result = json.loads(
        analyze(
            str(project),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    return result.get("danger") or []


def test_fastapi_sample_end_to_end_through_analyzer(tmp_path):
    danger = _analyze_danger(tmp_path)
    hits = sorted(
        (f["rule_id"], f["line"])
        for f in danger
        if f["rule_id"] in {"SKY-D211", "SKY-D215"}
    )
    assert hits == [("SKY-D211", 13), ("SKY-D215", 18)]
    for finding in danger:
        if (finding["rule_id"], finding["line"]) in hits:
            assert _evidence(finding)["source"].startswith("route parameter")

    sarif = SarifExporter(
        [f for f in danger if f["rule_id"] == "SKY-D211"], analyzer_owned=True
    ).generate()
    flow = sarif["runs"][0]["results"][0]["codeFlows"][0]
    steps = flow["threadFlows"][0]["locations"]
    lines = [s["location"]["physicalLocation"]["region"]["startLine"] for s in steps]
    assert lines == [13, 13]  # textual steps anchored at the sink
    assert "route parameter" in steps[0]["location"]["message"]["text"]
    assert flow["message"]["text"].startswith("Flow from route parameter")


@pytest.mark.parametrize("line, rule", [(13, "SKY-D211"), (18, "SKY-D215")])
def test_hook_policy_blocks_the_new_positives(line, rule):
    finding = {
        "rule_id": rule,
        "category": "security",
        "severity": "HIGH",
        "line": line,
    }
    hook_policy.classify_findings([finding], Path("main.py"), FASTAPI_APP.lstrip("\n"))
    assert finding["blocking"] is True
    assert finding["why"] == "untrusted-source"


def test_source_vocabulary_matches_hook_policy():
    assert untrusted_sources.ROUTE_DECORATOR_NAMES == hook_policy.ROUTE_DECORATOR_NAMES
    assert untrusted_sources.REQUEST_ANNOTATIONS == hook_policy.REQUEST_ANNOTATIONS
    assert untrusted_sources.REQUEST_NAMES == hook_policy.REQUEST_NAMES
    assert untrusted_sources.SOURCE_CALLS == hook_policy._SOURCE_CALLS
    assert untrusted_sources.SOURCE_ATTRS == hook_policy._SOURCE_ATTRS


def test_post_edit_hook_blocks_the_new_positives_only(tmp_path):
    import io

    from skylos.commands.hook_cmd import HookDeps, run_hook_command

    (tmp_path / ".git").mkdir()
    app = tmp_path / "main.py"
    app.write_text(FASTAPI_APP.lstrip("\n"), encoding="utf-8")
    payload = {
        "session_id": "flows",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app)},
        "tool_response": {"type": "create"},
    }
    deps = HookDeps()
    deps.env = {"CLAUDE_PROJECT_DIR": str(tmp_path)}
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    out = json.loads(stdout.getvalue())
    assert out["decision"] == "block"
    blocked = {
        int(line.split(":")[1].split()[0])
        for line in out["reason"].split("Check again")[0].splitlines()
        if line.startswith("- main.py:")
    }
    assert blocked == {13, 18}
