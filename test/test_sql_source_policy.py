import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate


def _analyze(tmp_path, files, *, single_file=False):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return json.loads(
        analyze(
            str(tmp_path / next(iter(files))) if single_file else str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )


def _sql_rows(result, section="danger"):
    return [row for row in result.get(section, []) if row.get("rule_id") == "SKY-D211"]


@pytest.mark.parametrize(
    "source",
    [
        "def lookup(cursor, query):\n    cursor.execute(query)\n",
        "def lookup(cursor, table):\n    cursor.execute(f'SELECT * FROM {table}')\n",
        "def lookup(cursor):\n    row = cursor.execute('SELECT digest FROM cache').fetchone()\n    cursor.execute(f\"DELETE FROM cache WHERE digest = '{row[0]}'\")\n",
    ],
)
@pytest.mark.parametrize("single_file", [False, True])
def test_unknown_query_sources_are_diagnostics_not_injection_claims(
    tmp_path, source, single_file
):
    result = _analyze(tmp_path, {"database.py": source}, single_file=single_file)
    assert _sql_rows(result) == []
    rows = _sql_rows(result, "suppressed")
    assert len(rows) == 1
    assert rows[0]["metadata"]["sql_provenance"]["status"] == "unknown"
    assert "not proof" in rows[0]["reason"]
    assert check_gate(result, {"gate": {"max_critical": 0, "max_high": 0}})[0]


@pytest.mark.parametrize("transform", ["value", "os.path.basename(value)"])
def test_cross_module_route_source_keeps_sql_evidence_and_gate_failure(
    tmp_path, transform
):
    result = _analyze(
        tmp_path,
        {
            "web.py": "import os\nfrom flask import Flask, request\nfrom service import search\napp = Flask(__name__)\n@app.get('/search')\ndef route():\n    value = request.args['name']\n    return search("
            + transform
            + ")\n",
            "service.py": "from database import lookup\ndef search(name):\n    return lookup(name)\n",
            "database.py": "def lookup(name):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        },
    )
    rows = _sql_rows(result)
    assert len(rows) == 1
    metadata = rows[0]["metadata"]
    assert metadata["sql_provenance"]["status"] == "untrusted"
    assert metadata["security_evidence"]["source"]
    assert metadata["source_status"] == "untrusted"
    assert not metadata.get("audit_only")
    assert rows[0].get("listing", {}).get("listed", True)
    assert not check_gate(result, {"gate": {"max_critical": 0, "max_high": 0}})[0]


def test_path_containment_does_not_sanitize_a_sql_query(tmp_path):
    result = _analyze(
        tmp_path,
        {
            "web.py": "from pathlib import Path\nfrom flask import Flask, request\nfrom database import lookup\napp = Flask(__name__)\n@app.get('/search')\ndef route():\n    value = str(Path('/data', request.args['name']).resolve())\n    if not Path(value).is_relative_to('/data'):\n        return None\n    return lookup(value)\n",
            "database.py": "def lookup(name):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        },
    )
    assert len(_sql_rows(result)) == 1


def test_an_incomplete_sql_source_index_is_not_a_safety_proof(tmp_path, monkeypatch):
    from skylos.rules.danger import project_source

    monkeypatch.setattr(project_source, "_MAX_FILES", 1)
    result = _analyze(
        tmp_path,
        {
            "database.py": "def lookup(cursor, query):\n    cursor.execute(query)\n",
            "other.py": "pass\n",
        },
    )
    rows = _sql_rows(result)
    assert len(rows) == 1
    assert rows[0]["metadata"]["sql_provenance"]["status"] == "incomplete"


def test_direct_input_source_keeps_existing_injection_claim(tmp_path):
    result = _analyze(
        tmp_path, {"database.py": "cursor.execute('SELECT ' + input())\n"}
    )
    rows = _sql_rows(result)
    assert len(rows) == 1
    assert rows[0]["metadata"]["security_evidence"]["source"]


def test_input_source_through_a_helper_stays_reported(tmp_path):
    result = _analyze(
        tmp_path,
        {
            "database.py": "def lookup(query):\n    cursor.execute(query)\n",
            "caller.py": "from database import lookup\nlookup('SELECT ' + input())\n",
        },
    )
    rows = _sql_rows(result)
    assert len(rows) == 1
    assert rows[0]["metadata"]["sql_provenance"]["status"] == "untrusted"


def test_changed_source_does_not_borrow_an_unknown_source_result(tmp_path):
    import ast

    from skylos.rules.danger.danger_sql.sql_flow import scan
    from skylos.rules.danger.danger_sql.sql_source_policy import (
        resolve_sql_source_findings,
    )

    path = tmp_path / "database.py"
    original = "def lookup(query):\n    cursor.execute(query)\n"
    path.write_text(original)
    findings = []
    scan(ast.parse(original), path, findings, project_root=tmp_path)
    path.write_text("def lookup(query):\n    cursor.execute('SELECT 1')\n")
    unknown = []
    kept = resolve_sql_source_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=unknown
    )
    assert len(kept) == 1
    assert kept[0]["metadata"]["sql_provenance"]["status"] == "incomplete"
    assert unknown == []
