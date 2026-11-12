"""Reported findings carry the code and the checked facts behind them."""

import copy
import json
import textwrap
from pathlib import Path

from skylos.analyzer import analyze
from skylos.api._payloads import _compact_upload_finding
from skylos.reporting.sarif import SarifExporter
from skylos.security.static_trace import attach_security_traces
from test.fixture_paths import write_fixture


CONTRACT = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "skylos"
        / "api"
        / "upload_contract"
        / "v1.json"
    ).read_text(encoding="utf-8")
)


def _write(root, relative, body):
    return write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _scan(root):
    return json.loads(analyze(str(root), conf=0))


def _named(items, name):
    return [item for item in items if item.get("simple_name") == name]


def _events(item):
    return {event["kind"]: event for event in item["dead_code_evidence"]}


def test_unused_import_records_what_was_checked(tmp_path):
    _write(
        tmp_path,
        "mod.py",
        """
        import json
        import os


        def main():
            return json.dumps(1)


        main()
        """,
    )

    result = _scan(tmp_path)
    unused = result.get("unused_imports", [])

    assert _named(unused, "json") == []
    [finding] = _named(unused, "os")
    assert finding["dead_code_classification"] == "likely_dead"
    assert finding["dead_code_disposition"] == "reported"
    assert finding["dead_code_reason_tags"] == [
        "no_refs",
        "not_exported",
        "confidence_ge_threshold",
    ]
    events = _events(finding)
    assert list(events) == ["no_static_references", "not_exported", "confidence_gate"]
    searched = events["no_static_references"]
    assert searched["role"] == "supports_dead"
    assert "`os`" in searched["reason"]
    assert searched["details"] == {
        "references": 0,
        "searched_name": "os",
        "files_searched": 1,
        "imported_target": "os",
        "in_package_init": False,
    }
    assert events["not_exported"]["details"] == {"module_declares_all": False}
    assert "__all__" in events["not_exported"]["reason"]


def test_import_listed_in_all_stays_unreported_and_unlisted_one_says_so(tmp_path):
    _write(
        tmp_path,
        "mod.py",
        """
        import json
        import os

        __all__ = ["json", "main"]


        def main():
            return 1


        main()
        """,
    )

    unused = _scan(tmp_path).get("unused_imports", [])

    assert _named(unused, "json") == []
    [finding] = _named(unused, "os")
    not_exported = _events(finding)["not_exported"]
    assert not_exported["details"] == {"module_declares_all": True}
    assert not_exported["reason"] == "`os` is not listed in the module's `__all__`"


def test_dead_function_events_name_the_search_and_stay_bounded(tmp_path):
    for module in ("a", "b", "c", "d", "e"):
        _write(tmp_path, f"{module}.py", "def helper():\n    return 1\n")

    result = _scan(tmp_path)
    reported = [
        item
        for item in _named(result.get("unused_functions", []), "helper")
        if item["file"].endswith("a.py")
    ]

    [finding] = reported
    details = _events(finding)["no_static_references"]["details"]
    assert details["references"] == 0
    assert details["searched_name"] == "helper"
    assert details["files_searched"] == 5
    assert details["same_name_definition_count"] == 4
    assert [text.split(" ")[0] for text in details["same_name_definitions"]] == [
        "b.py:1",
        "c.py:1",
        "d.py:1",
    ]
    assert len(finding["dead_code_evidence"]) <= 8
    compact = _compact_upload_finding(
        {**finding, "rule_id": "SKY-U001", "category": "DEAD_CODE"},
        include_snippet=False,
    )
    assert len(compact["metadata"]["dead_code_evidence"]["events"]) <= 8
    assert len(json.dumps(compact["metadata"]["dead_code_evidence"])) < 8192


CALLER = """
from aiohttp import web

from dao import Student


async def create(request):
    data = await request.post()
    await Student.create(request.app["db"], data["name"])
    return web.Response()
"""

DAO = """
class Student:
    @staticmethod
    async def create(conn, name):
        q = "INSERT INTO students (name) VALUES ('%s')" % name
        await conn.execute(q)
"""

PROVENANCE = {
    "version": 1,
    "status": "untrusted",
    "function": "create",
    "complete_project": True,
    "safety_proven": False,
    "untrusted": [
        [
            "views.py:7 request data `request.post()`",
            "views.py:7 `data` = Await",
            "views.py:8 call `Student.create(...)` binds `name`",
            "dao.py:4 `q` = <literal> % `name`",
        ]
    ],
}


def _sql_finding(root, *, provenance=True):
    metadata = {}
    if provenance:
        metadata["sql_provenance"] = copy.deepcopy(PROVENANCE)
    return {
        "rule_id": "SKY-D211",
        "file": str(root / "dao.py"),
        "line": 5,
        "col": 14,
        "severity": "HIGH",
        "category": "SECURITY",
        "message": "Possible SQL injection: identified input reaches SQL query text.",
        "metadata": metadata,
    }


def _cross_function_trace(tmp_path, **options):
    paths = [_write(tmp_path, "views.py", CALLER), _write(tmp_path, "dao.py", DAO)]
    finding = _sql_finding(tmp_path)
    attach_security_traces([finding], project_root=tmp_path, files=paths, **options)
    return finding, finding["metadata"]["security_trace"]


def _flow(trace):
    by_id = {step["id"]: step for step in trace["steps"]}
    incoming = {}
    for edge in trace["edges"]:
        if edge["kind"] in {"provenance", "data"}:
            incoming.setdefault(edge["to"], []).append(edge["from"])
    [sink] = [step for step in trace["steps"] if step["kind"] == "sink"]
    path = [sink]
    seen = {sink["id"]}
    queue = [[sink["id"]]]
    while queue:
        route = queue.pop(0)
        if by_id[route[0]]["kind"] == "source":
            return [by_id[step_id] for step_id in route]
        for predecessor in incoming.get(route[0], []):
            if predecessor not in seen:
                seen.add(predecessor)
                queue.append([predecessor, *route])
    return path


def test_cross_function_trace_has_source_intermediate_and_sink_with_code(tmp_path):
    _finding, trace = _cross_function_trace(tmp_path)

    flow = _flow(trace)
    assert [(step["kind"], step["file"], step["line"]) for step in flow] == [
        ("source", "views.py", 7),
        ("propagation", "views.py", 7),
        ("propagation", "views.py", 8),
        ("assignment", "dao.py", 4),
        ("sink", "dao.py", 5),
    ]
    assert [step["column"] for step in flow[:3]] == [4, 4, 4]
    assert [step.get("snippet") for step in flow] == [
        "data = await request.post()",
        "data = await request.post()",
        "await Student.create(request.app[<literal>], data[<literal>])",
        "q = <literal> % name",
        "await conn.execute(q)",
    ]
    order = [step["id"] for step in trace["steps"]]
    assert order.index(flow[0]["id"]) < order.index(flow[2]["id"])
    assert order.index(flow[2]["id"]) < order.index(flow[3]["id"])
    assert trace["steps"][-1]["kind"] == "sink"
    [literal] = [step for step in trace["steps"] if step["kind"] == "literal"]
    assert literal["snippet"] == "q = <literal> % name"
    assert "INSERT INTO" not in json.dumps(trace)


def test_sarif_thread_flow_matches_the_trace_steps(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding, trace = _cross_function_trace(tmp_path)

    sarif = SarifExporter([finding], analyzer_owned=True).generate()
    [result] = sarif["runs"][0]["results"]
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]

    assert len(locations) == len(trace["steps"])
    for location, step in zip(locations, trace["steps"]):
        physical = location["location"]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == step["file"]
        assert physical["region"]["startLine"] == step["line"]
        assert physical["region"]["startColumn"] == step["column"] + 1
        if "snippet" in step:
            assert physical["region"]["snippet"] == {"text": step["snippet"]}
        else:
            assert "snippet" not in physical["region"]
    stored = result["properties"]["skylos_metadata"]["security_trace"]["steps"]
    assert [step["id"] for step in stored] == [step["id"] for step in trace["steps"]]
    assert all("snippet" not in step for step in stored)


def test_same_function_flow_only_gains_snippets(tmp_path):
    path = _write(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")
    finding = {
        "rule_id": "SKY-D324",
        "file": str(tmp_path / "sink.py"),
        "line": 2,
        "severity": "HIGH",
        "metadata": {
            "path_provenance": {
                "status": "untrusted",
                "untrusted": [["sink.py:1 input()", "sink.py:2 path `value`"]],
            }
        },
    }

    attach_security_traces([finding], project_root=tmp_path, files=[path])
    trace = finding["metadata"]["security_trace"]

    assert trace["status"] == "source_to_sink"
    assert [(step["kind"], step["line"]) for step in trace["steps"]] == [
        ("source", 1),
        ("assignment", 1),
        ("receiver", 2),
        ("sink", 2),
    ]
    assert [step["snippet"] for step in trace["steps"]] == [
        "value = input()",
        "value = input()",
        "open(value, <literal>)",
        "open(value, <literal>)",
    ]
    assert {edge["kind"] for edge in trace["edges"]} == {"data", "receiver"}


def test_step_on_a_secret_line_has_no_snippet(tmp_path):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    paths = [
        _write(tmp_path, "views.py", CALLER),
        _write(
            tmp_path,
            "dao.py",
            DAO.replace("execute(q)", f'execute(q)  # aws_access_key_id = "{key}"'),
        ),
    ]
    flagged = _sql_finding(tmp_path)
    attach_security_traces(
        [flagged],
        project_root=tmp_path,
        files=paths,
        secrets=[{"file": str(tmp_path / "views.py"), "line": 7}],
    )
    trace = flagged["metadata"]["security_trace"]

    on_flagged_line = [
        step for step in trace["steps"] if (step["file"], step["line"]) == ("views.py", 7)
    ]
    assert len(on_flagged_line) == 2
    assert all("snippet" not in step for step in on_flagged_line)
    assert key not in json.dumps(trace)
    [call] = [
        step for step in trace["steps"] if (step["file"], step["line"]) == ("views.py", 8)
    ]
    assert call["snippet"] == "await Student.create(request.app[<literal>], data[<literal>])"
    [sink] = [step for step in trace["steps"] if step["kind"] == "sink"]
    assert sink["snippet"] == "await conn.execute(q)"


def _quality_finding(**extra):
    return {
        "rule_id": "SKY-Q301",
        "kind": "complexity",
        "category": "QUALITY",
        "severity": "MEDIUM",
        "message": "Cyclomatic complexity is 14 (threshold: 10).",
        "file_path": "app/service.py",
        "line_number": 5,
        "value": 14,
        "threshold": 10,
        "length": 20,
        **extra,
    }


def test_quality_finding_carries_numbers_and_extent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    measured = _quality_finding()
    scoped = _quality_finding(
        rule_id="SKY-Q306", cognitive_scope={"version": 1, "end_line": 30}
    )
    scoped.pop("length")
    secret = {
        "rule_id": "SKY-S101",
        "category": "SECRET",
        "severity": "HIGH",
        "message": "Secret",
        "file_path": "app/service.py",
        "line_number": 3,
        "value": "do-not-upload",
        "threshold": 1,
    }

    results = SarifExporter([measured, scoped, secret]).generate()["runs"][0]["results"]

    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert (region["startLine"], region["endLine"]) == (5, 24)
    assert results[0]["properties"]["skylos_metadata"]["measure"] == {
        "value": 14,
        "threshold": 10,
        "length": 20,
        "end_line": 24,
    }
    assert results[1]["locations"][0]["physicalLocation"]["region"]["endLine"] == 30
    assert results[1]["properties"]["skylos_metadata"]["measure"] == {
        "value": 14,
        "threshold": 10,
        "end_line": 30,
    }
    assert "endLine" not in results[2]["locations"][0]["physicalLocation"]["region"]
    assert "do-not-upload" not in json.dumps(results[2])

    compact = _compact_upload_finding(measured, include_snippet=True)
    assert compact["metadata"]["measure"] == {
        "value": 14,
        "threshold": 10,
        "length": 20,
        "end_line": 24,
    }
    assert "metadata" not in _compact_upload_finding(secret, include_snippet=True)


def test_compact_payload_keeps_step_locations_and_provenance(tmp_path):
    finding, trace = _cross_function_trace(tmp_path)
    finding = {
        **finding,
        "file_path": "dao.py",
        "line_number": 5,
        "snippet": "x" * 300,
    }

    full = _compact_upload_finding(finding, include_snippet=True)
    small = _compact_upload_finding(finding, include_snippet=False)

    assert full["snippet"] == "x" * 300
    assert "snippet" not in small
    steps = small["metadata"]["security_trace"]["steps"]
    assert [(step["file"], step["line"]) for step in steps] == [
        (step["file"], step["line"]) for step in trace["steps"]
    ]
    assert all("snippet" not in step for step in steps)
    assert small["metadata"]["sql_provenance"]["untrusted"] == PROVENANCE["untrusted"]
    assert any("snippet" in step for step in trace["steps"])

    dependency = {
        "rule_id": "SKY-SCA-001",
        "category": "DEPENDENCY",
        "severity": "HIGH",
        "message": "Vulnerable dependency",
        "file_path": "requirements.txt",
        "line_number": 1,
        "metadata": {
            "reachability_verdict": "imported",
            "reachability_reason": "imported in app.py",
            "reachability_tier": 2,
            "reachability_imported_as": "yaml",
        },
    }
    kept = _compact_upload_finding(dependency, include_snippet=False)["metadata"]
    assert kept == dependency["metadata"]


def _contract_problems(finding):
    rules = CONTRACT["finding"]
    problems = []
    if len(finding["file_path"]) > rules["file_path"]["max_length"]:
        problems.append("file_path")
    if type(finding["line_number"]) is not int or finding["line_number"] < 0:
        problems.append("line_number")
    if not 1 <= len(finding["rule_id"]) <= rules["rule_id"]["max_length"]:
        problems.append("rule_id")
    if finding["severity"] not in rules["severity"]["values"]:
        problems.append("severity")
    if len(finding["category"]) > rules["category"]["max_length"]:
        problems.append("category")
    if len(finding.get("message") or "") > rules["message"]["max_length"]:
        problems.append("message")
    if len(finding.get("snippet") or "") > rules["snippet"]["max_length"]:
        problems.append("snippet")
    return problems


def test_upload_shapes_stay_inside_the_upload_contract(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding, _trace = _cross_function_trace(tmp_path)
    finding = {
        **finding,
        "file_path": "dao.py",
        "line_number": 5,
        "snippet": "y" * 5000,
    }
    findings = [finding, _quality_finding()]

    for row in findings:
        for include_snippet in (True, False):
            compact = _compact_upload_finding(row, include_snippet=include_snippet)
            assert _contract_problems(compact) == []

    limit = CONTRACT["finding"]["snippet"]["max_length"]
    for result in SarifExporter(findings).generate()["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert len(region.get("snippet", {}).get("text", "")) <= limit
        for flow in result.get("codeFlows", []):
            for location in flow["threadFlows"][0]["locations"]:
                step_region = location["location"]["physicalLocation"]["region"]
                assert len(step_region.get("snippet", {}).get("text", "")) <= limit
