"""Reported and uploaded evidence never carries the scanning machine's paths.

The analyzer runs on a real fixture (never imported). Receiver proofs and
evidence traces use the security_trace convention: a path relative to the
scan root, or ``<external>/<basename>`` for a file outside it.
"""

import copy
import json
import os
import textwrap
from unittest.mock import patch

import pytest

from skylos.analyzer import analyze
from skylos.api._payloads import _compact_upload_finding
from skylos.reporting.metadata_paths import (
    relativize_contract_traces,
    relativize_definitions,
    relativize_evidence_paths,
    relativize_receiver_paths,
    relativize_upload_finding,
    scan_relative_location,
    scan_relative_path,
)
from skylos.reporting.sarif import SarifExporter
from test.fixture_paths import write_fixture

DB_SOURCE = """\
    import sqlite3


    class Database:
        def __init__(self):
            self.conn = sqlite3.connect("app.db")

        def execute(self, sql):
            return self.conn.execute(sql)


    def run_query(term):
        conn = sqlite3.connect("app.db")
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM items WHERE name = '{term}'")
        return cur.fetchall()
"""

ROUTES_SOURCE = """\
    from flask import Flask, request

    from app.db import Database, run_query

    app = Flask(__name__)
    db = Database()


    @app.route("/search")
    def search():
        term = request.args.get("q")
        return str(run_query(term))


    @app.route("/raw")
    def raw():
        name = request.args.get("name")
        return str(db.execute(f"SELECT * FROM t WHERE n = '{name}'"))
"""


def _write_project(tmp_path):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname = "fixture"\n')
    write_fixture(tmp_path, "app/__init__.py", "")
    write_fixture(tmp_path, "app/db.py", textwrap.dedent(DB_SOURCE))
    write_fixture(tmp_path, "app/routes.py", textwrap.dedent(ROUTES_SOURCE))


def _analyze(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    return json.loads(
        analyze(
            str(tmp_path),
            exclude_folders=[],
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )


def _machine_roots(tmp_path):
    return {str(tmp_path), os.path.realpath(tmp_path)}


def _strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)
    elif isinstance(node, str):
        yield node


def _leaks(node, roots):
    return sorted({text for text in _strings(node) for root in roots if root in text})


def _sql_rows(result):
    rows = {}
    for row in result.get("danger", []):
        if row["rule_id"] == "SKY-D211":
            rows[(os.path.basename(row["file"]), row["line"])] = row
    return rows


@pytest.fixture
def analyzed(tmp_path, monkeypatch):
    _write_project(tmp_path)
    return _analyze(tmp_path, monkeypatch)


def test_analyzer_receiver_proof_paths_are_scan_relative(tmp_path, analyzed):
    rows = _sql_rows(analyzed)
    assert set(rows) == {("db.py", 9), ("db.py", 15), ("routes.py", 18)}
    proof = rows[("routes.py", 18)]["metadata"]["receiver_resolution"]
    assert proof["status"] == "resolved"
    assert proof["kind"] == "imported_method"
    assert proof["qualified_name"].endswith("Database.execute")
    assert proof["file"] == "app/db.py"
    assert proof["line"] == 8
    assert [(s["kind"], s["file"], s["line"]) for s in proof["steps"]] == [
        ("source_binding", "app/db.py", 8)
    ]
    local = rows[("db.py", 15)]["metadata"]["receiver_resolution"]
    assert [(s["kind"], s["file"], s["line"]) for s in local["steps"]] == [
        ("source_binding", "app/db.py", 15),
        ("standard_library_contract", "app/db.py", 15),
    ]
    for row in rows.values():
        assert _leaks(row["metadata"], _machine_roots(tmp_path)) == []


def test_security_trace_still_resolves_and_matches_the_receiver_proof(analyzed):
    row = _sql_rows(analyzed)[("routes.py", 18)]
    trace = row["metadata"]["security_trace"]
    located = [(s["kind"], s["file"], s["line"]) for s in trace["steps"]]
    assert ("receiver", "app/db.py", 8) in located
    assert ("source", "app/routes.py", 17) in located
    assert ("sink", "app/routes.py", 18) in located
    assert all(not os.path.isabs(step["file"]) for step in trace["steps"])
    assert row["file"].endswith(os.path.join("app", "routes.py"))
    assert os.path.isabs(row["file"])


def _prepare_upload(result, tmp_path, *, git_root=None):
    import skylos.api as api
    from skylos.cli import _attach_upload_project_context

    with (
        patch.object(api, "get_git_info", return_value=("c", "main", "actor", {})),
        patch.object(api, "get_git_root", return_value=str(git_root or tmp_path)),
        patch.object(api, "detect_ai_code", return_value={"detected": False}),
        patch.object(api, "_annotate_findings_with_blame"),
        patch.object(api, "_load_repo_link", return_value={}),
    ):
        _attach_upload_project_context(result, tmp_path)
        before = copy.deepcopy(result)
        prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert result == before
    return prepared


def test_every_upload_shape_is_free_of_machine_paths(tmp_path, analyzed):
    prepared = _prepare_upload(analyzed, tmp_path)
    roots = _machine_roots(tmp_path)
    assert prepared.definitions_payload
    for payload in (
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
        prepared.definitions_payload,
    ):
        assert _leaks(payload, roots) == []

    sarif = {
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        ): r
        for r in prepared.core_payload["runs"][0]["results"]
        if r["ruleId"] == "SKY-D211"
    }
    assert set(sarif) == {("app/db.py", 9), ("app/db.py", 15), ("app/routes.py", 18)}
    properties = sarif[("app/routes.py", 18)]["properties"]
    proof = properties["skylos_metadata"]["receiver_resolution"]
    assert proof["file"] == "app/db.py"
    assert proof["steps"][0]["file"] == "app/db.py"
    assert proof["steps"][0]["line"] == 8
    assert "app/routes.py:18" in properties["skylos_evidence_contract"]["traces"]

    compact = {
        (f["file_path"], f["line_number"]): f
        for f in prepared.compatibility_payload["findings"]
        if f["rule_id"] == "SKY-D211"
    }
    assert set(compact) == set(sarif)
    metadata = compact[("app/routes.py", 18)]["metadata"]
    assert metadata["receiver_resolution"]["file"] == "app/db.py"
    original = _sql_rows(analyzed)[("routes.py", 18)]["metadata"]
    assert metadata["security_trace"] == original["security_trace"]
    assert metadata["receiver_resolution"] == original["receiver_resolution"]


def test_nested_scan_keeps_evidence_relative_to_the_scanned_project(
    tmp_path, monkeypatch
):
    project = tmp_path / "apps" / "server"
    project.mkdir(parents=True)
    _write_project(project)
    analyzed = _analyze(project, monkeypatch)
    prepared = _prepare_upload(analyzed, project, git_root=tmp_path)
    assert prepared.core_payload["project_root"] == "apps/server"
    for payload in (
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
        prepared.definitions_payload,
    ):
        assert _leaks(payload, _machine_roots(tmp_path)) == []
    row = next(
        finding
        for finding in prepared.compatibility_payload["findings"]
        if finding["file_path"] == "apps/server/app/routes.py"
        and finding["line_number"] == 18
        and finding["rule_id"] == "SKY-D211"
    )
    assert row["metadata"]["receiver_resolution"]["file"] == "app/db.py"
    assert prepared.definitions_payload["definitions"]["app.db.Database"]["file"] == (
        "app/db.py"
    )


def test_receiver_rewrite_preserves_the_resolvers_shared_proof(tmp_path):
    proof = {
        "status": "resolved",
        "file": str(tmp_path / "app.py"),
        "steps": [{"file": str(tmp_path / "app.py"), "line": 4}],
    }
    before = copy.deepcopy(proof)
    metadata = {"receiver_resolution": proof, "unrelated": {"keep": True}}
    findings = [{"metadata": metadata}, {"metadata": metadata}]
    relativize_receiver_paths(findings, tmp_path)
    assert proof == before
    assert metadata["receiver_resolution"] is proof
    for finding in findings:
        assert finding["metadata"]["receiver_resolution"] == {
            "status": "resolved",
            "file": "app.py",
            "steps": [{"file": "app.py", "line": 4}],
        }
        assert finding["metadata"]["unrelated"] is metadata["unrelated"]


def test_local_sarif_evidence_traces_follow_the_location_path(
    tmp_path, analyzed, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    rows = [{**row, "category": "SECURITY"} for row in analyzed["danger"]]
    workflow = tmp_path / ".github" / "workflows" / "tests.yaml"
    rows.append(
        {
            "rule_id": "SKY-D295",
            "category": "SECURITY",
            "severity": "HIGH",
            "file": str(workflow),
            "line": 15,
            "message": "Self-hosted runner",
            "evidence_contract": {
                "schema_version": 1,
                "proof_state": "candidate",
                "traces": [f"{workflow}:15"],
            },
        }
    )
    report = SarifExporter(rows, tool_name="Skylos", analyzer_owned=True).generate()
    assert _leaks(report, _machine_roots(tmp_path)) == []
    for result in report["runs"][0]["results"]:
        location = result["locations"][0]["physicalLocation"]
        own = f"{location['artifactLocation']['uri']}:{location['region']['startLine']}"
        traces = result["properties"]["skylos_evidence_contract"]["traces"]
        assert traces[0] == own
        assert traces.count(own) == 1
    baked = report["runs"][0]["results"][-1]["properties"]["skylos_evidence_contract"]
    assert baked["traces"] == [".github/workflows/tests.yaml:15"]


def test_upload_names_a_file_outside_the_scan_root_only_by_basename(tmp_path):
    root = tmp_path / "project"
    outside = tmp_path / "shared" / "lib" / "store.py"
    finding = {
        "rule_id": "SKY-D211",
        "file_path": "app.py",
        "metadata": {
            "receiver_resolution": {
                "status": "resolved",
                "file": str(outside),
                "line": 8,
                "steps": [{"kind": "source_binding", "file": str(outside), "line": 8}],
            },
            "security_trace": {"steps": [{"file": "app.py", "line": 3}]},
        },
    }
    original = copy.deepcopy(finding)
    shared_metadata = finding["metadata"]
    relativize_upload_finding(finding, str(root))
    assert shared_metadata == original["metadata"]
    proof = finding["metadata"]["receiver_resolution"]
    assert proof["file"] == "<external>/store.py"
    assert proof["steps"] == [
        {"kind": "source_binding", "file": "<external>/store.py", "line": 8}
    ]
    assert (
        finding["metadata"]["security_trace"] == original["metadata"]["security_trace"]
    )
    compact = _compact_upload_finding(finding, include_snippet=False)
    assert _leaks(compact, {str(tmp_path), os.path.realpath(tmp_path)}) == []
    assert compact["metadata"]["receiver_resolution"]["line"] == 8


def test_relative_evidence_is_returned_untouched(tmp_path):
    metadata = {
        "receiver_resolution": {"file": "app/db.py", "steps": [{"file": "app/db.py"}]},
        "security_trace": {"steps": [{"file": "../vendored/x.py", "line": 2}]},
        "evidence_contract": {"traces": ["app/db.py:9", "request data reaches SQL"]},
    }
    assert relativize_evidence_paths(metadata, str(tmp_path)) is metadata
    finding = {"metadata": metadata, "evidence_contract": metadata["evidence_contract"]}
    relativize_upload_finding(finding, str(tmp_path))
    assert finding["metadata"] is metadata
    assert finding["evidence_contract"] is metadata["evidence_contract"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("{root}/app/db.py", "app/db.py"),
        ("{root}", "."),
        ("{root}/../elsewhere/x.py", "<external>/x.py"),
        ("/etc/passwd", "<external>/passwd"),
        ("C:\\Users\\me\\project\\a.py", "<external>/a.py"),
        ("app/db.py", "app/db.py"),
        ("", ""),
        (None, None),
        (7, 7),
    ],
)
def test_scan_relative_path(tmp_path, value, expected):
    if isinstance(value, str):
        value = value.replace("{root}", str(tmp_path))
    assert scan_relative_path(value, str(tmp_path)) == expected


def test_symlinked_root_spelling_still_counts_as_inside(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    assert scan_relative_path(str(link / "app.py"), str(real)) == "app.py"
    assert scan_relative_path(str(real / "app.py"), str(link)) == "app.py"


def test_unknown_root_never_returns_an_absolute_path(tmp_path):
    assert scan_relative_path(str(tmp_path / "a.py"), None) == "<external>/a.py"


def test_location_strings_keep_their_line_or_symbol(tmp_path):
    root = str(tmp_path)
    assert scan_relative_location(f"{root}/a/b.py:12", root) == "a/b.py:12"
    assert scan_relative_location(f"{root}/ui.js:docReady", root) == "ui.js:docReady"
    assert scan_relative_location("/opt/x/c.py:3", root) == "<external>/c.py:3"
    assert scan_relative_location("dependency_truth_state:unknown", root) == (
        "dependency_truth_state:unknown"
    )
    contract = {"traces": [f"{root}/a.py:1", "a.py:1", "prose"], "sources": []}
    assert relativize_contract_traces(contract, root) == {
        "traces": ["a.py:1", "prose"],
        "sources": [],
    }


def test_definitions_lose_machine_paths_in_keys_and_values(tmp_path):
    root = str(tmp_path)
    definitions = {
        "pkg.mod.fn": {"name": "fn", "file": f"{root}/pkg/mod.py", "line": 3},
        f"{root}/static/ui.js:docReady": {"file": f"{root}/static/ui.js", "line": 9},
    }
    before = copy.deepcopy(definitions)
    updated = relativize_definitions(definitions, root)
    assert definitions == before
    assert updated == {
        "pkg.mod.fn": {"name": "fn", "file": "pkg/mod.py", "line": 3},
        "static/ui.js:docReady": {"file": "static/ui.js", "line": 9},
    }
