"""Path uncertainty and its recorded evidence must survive report transports."""

import copy
import json

import pytest

from skylos import api
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import listed_result
from skylos.reporting.sarif import SarifExporter


def _row(status, rule, file, *, source_file="entry.py"):
    source = {
        "unknown": "entry.py:1 caller callback is external",
        "incomplete": "entry.py:1 caller analysis stopped at its work limit",
        "untrusted": "entry.py:1 HTTP request path parameter",
        "safe": "entry.py:1 trusted literal file name",
    }[status]
    return {
        "rule_id": rule,
        "category": "SECURITY",
        "severity": "HIGH",
        "file": file,
        "line": 2,
        "col": 4,
        "symbol": "read_or_write",
        "message": f"Path evidence: {status}",
        "finding_type": "review",
        "listing": {"version": 1, "listed": True, "reason": "finding"},
        "metadata": {
            "path_provenance": {
                "version": 1,
                "status": status,
                "complete_project": True,
                "safety_proven": status == "safe",
                "function": "read_or_write",
                status: [[source, f"{file}:2 filesystem sink"]],
            },
            "security_trace": {
                "version": 1,
                "status": "source_to_sink" if status == "untrusted" else "partial",
                "receiver": {"status": "unknown"},
                "steps": [
                    {
                        "id": "input",
                        "kind": "source" if status == "untrusted" else "unresolved",
                        "file": source_file,
                        "line": 1,
                        "message": source,
                    },
                    {
                        "id": "sink",
                        "kind": "sink",
                        "file": file,
                        "line": 2,
                        "message": "filesystem operation",
                    },
                ],
                "edges": [{"from": "input", "to": "sink"}],
                "limitations": [] if status == "untrusted" else [source],
            },
        },
    }


def _report(tmp_path, *, listing=True):
    rows = [
        _row("unknown", "SKY-D215", "unknown_path.py"),
        _row("incomplete", "SKY-D324", "incomplete_write.py"),
        _row("untrusted", "SKY-D325", "untrusted_read.py"),
    ]
    safe = _row("safe", "SKY-D215", "fixed_path.py")
    for filename in ["entry.py", *(row["file"] for row in rows), safe["file"]]:
        (tmp_path / filename).write_text(
            "# fixture source\n# recorded sink\n", encoding="utf-8"
        )
    result = {
        "danger": rows,
        "suppressed": [safe],
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 5,
            "analysis_error_count": 0,
            "grade_categories": ["security"],
            "path_review": {
                "version": 1,
                "unresolved_count": 2,
                "examples": [{"file": str(tmp_path / "unknown_path.py"), "line": 2}],
            },
        },
        "provenance": None,
        "definitions": {},
    }
    if listing:
        result["listing_policy_version"] = 1
    return result


def _proof_assertions(metadata, expected):
    proof = metadata["path_provenance"]
    original = expected["metadata"]["path_provenance"]
    status = original["status"]
    assert proof["status"] == status
    assert proof["safety_proven"] is False
    assert proof[status] == original[status]
    trace = metadata["security_trace"]
    assert trace["status"] == expected["metadata"]["security_trace"]["status"]
    assert [(step["file"], step["line"]) for step in trace["steps"]] == [
        ("entry.py", 1),
        (expected["file"], 2),
    ]


def _prepare(monkeypatch, tmp_path, result):
    monkeypatch.setattr(
        api, "get_git_info", lambda: ("a" * 40, "main", "fixture", None)
    )
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "_load_repo_link", lambda *_a: {})
    monkeypatch.setattr(api, "detect_ai_code", lambda *_a: {})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_a: None)
    monkeypatch.setattr(api, "source_revision_state", lambda *_a: "unknown")
    return api._prepare_report_upload(result, analyzer_owned=True)


def test_listing_and_gate_count_unknown_incomplete_and_untrusted_paths(tmp_path):
    result = _report(tmp_path)
    before = copy.deepcopy(result)
    listed = listed_result(result)
    assert listed["danger"] == result["danger"]
    assert len(listed["danger"]) == 3
    assert listed["suppressed"] == result["suppressed"]
    assert not any(row["file"] == "fixed_path.py" for row in listed["danger"])
    assert check_gate(listed, {"gate": {"max_security": 2, "max_high": 99}})[0] is False
    assert check_gate(listed, {"gate": {"max_security": 3, "max_high": 99}})[0] is True
    assert result == before


def test_sarif_retains_review_status_and_located_source_gaps(tmp_path):
    result = _report(tmp_path)
    before = copy.deepcopy(result)
    exported = SarifExporter(
        listed_result(result)["danger"], tool_name="Skylos"
    ).generate()
    rows = exported["runs"][0]["results"]
    assert len(rows) == 3
    by_rule = {row["ruleId"]: row for row in rows}
    for expected in result["danger"]:
        row = by_rule[expected["rule_id"]]
        _proof_assertions(row["properties"]["skylos_metadata"], expected)
        assert row["level"] == "error"
        flow = row["codeFlows"][0]["threadFlows"][0]["locations"]
        assert [
            location["location"]["physicalLocation"]["region"]["startLine"]
            for location in flow
        ] == [1, 2]
    assert result == before


@pytest.mark.parametrize("listing", [True, False])
def test_upload_transports_keep_path_reviews_and_leave_local_examples_local(
    tmp_path, monkeypatch, listing
):
    result = _report(tmp_path, listing=listing)
    before = copy.deepcopy(result)
    prepared = _prepare(monkeypatch, tmp_path, result)
    expected = {row["rule_id"]: row for row in result["danger"]}
    for payload in (prepared.core_payload, prepared.legacy_payload):
        rows = payload["runs"][0]["results"]
        assert {row["ruleId"] for row in rows} == set(expected)
        for row in rows:
            _proof_assertions(
                row["properties"]["skylos_metadata"], expected[row["ruleId"]]
            )
        assert "path_review" not in payload.get("summary", {})
        assert "path_review" not in payload["runs"][0].get("properties", {}).get(
            "summary", {}
        )
    inline = prepared.compatibility_payload["findings"]
    assert len(inline) == 3
    for row in inline:
        _proof_assertions(row["metadata"], expected[row["rule_id"]])
    assert prepared.scan_summary["finding_count"] == 3
    assert "path_review" not in prepared.compatibility_payload["summary"]
    assert str(tmp_path) not in json.dumps(prepared.compatibility_payload)
    assert result == before


@pytest.mark.parametrize("status", ["untrusted", "unknown", "incomplete"])
@pytest.mark.parametrize("nested", [False, True])
def test_compact_upload_preserves_process_source_context(status, nested):
    chain = [["routes.py:3 HTTP input", "worker.py:4 URL sink"]]
    record = {
        "status": status,
        "source_kinds": ["cli", "environment"],
        "reason": "the worker's source context still needs review",
        **({"chains": {status: chain}} if nested else {status: chain}),
    }
    metadata = {"process_context": record}
    before = copy.deepcopy(metadata)
    result = api._compact_finding_metadata(metadata)["process_context"]
    assert result["status"] == status
    assert result[status] == chain
    assert result["reason"] == record["reason"]
    assert result["source_kinds"] == record["source_kinds"]
    assert metadata == before
