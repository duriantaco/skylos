import copy

from skylos.api._payloads import _compact_upload_finding
from skylos.core.gatekeeper import check_gate
from skylos.reporting.sarif import SarifExporter


def row_with_trace():
    return {
        "rule_id": "SKY-D211",
        "category": "SECURITY",
        "severity": "CRITICAL",
        "file": "db.py",
        "file_path": "db.py",
        "line": 4,
        "line_number": 4,
        "message": "Possible SQL injection",
        "finding_type": "review",
        "listing": {"version": 1, "listed": True, "reason": "finding"},
        "metadata": {
            "listing": {"version": 1, "listed": True, "reason": "finding"},
            "security_evidence": {
                "source": "request data",
                "sink": "SQL execute",
                "path": ["old unlocated text"],
                "analysis_complete": False,
            },
            "receiver_resolution": {"status": "unknown", "reason": "external factory"},
            "security_trace": {
                "version": 1,
                "trace_id": "static-proof",
                "status": "partial",
                "steps": [
                    {
                        "id": "a",
                        "kind": "source",
                        "message": "request input",
                        "file": "api.py",
                        "line": 12,
                    },
                    {
                        "id": "b",
                        "kind": "call",
                        "message": "helper parameter",
                        "file": "api.py",
                        "line": 13,
                    },
                    {
                        "id": "c",
                        "kind": "sink",
                        "message": "SQL execute",
                        "file": "db.py",
                        "line": 4,
                    },
                ],
                "receiver": {"status": "unknown"},
                "limitations": ["Receiver factory is external"],
            },
        },
    }


def test_compact_upload_preserves_proof_and_listing_without_mutation():
    row = row_with_trace()
    before = copy.deepcopy(row)
    compact = _compact_upload_finding(row, include_snippet=False)
    for key in ("security_evidence", "security_trace", "receiver_resolution"):
        assert compact["metadata"][key] == row["metadata"][key]
    assert compact["severity"] == "CRITICAL"
    assert compact["listing"]["listed"] is True
    assert row == before


def test_sarif_uses_actual_per_step_locations_and_keeps_original_evidence():
    row = row_with_trace()
    before = copy.deepcopy(row)
    report = SarifExporter([row], tool_name="Skylos", version="test").generate()
    result = report["runs"][0]["results"][0]
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    observed = []
    for location in locations:
        physical = location["location"]["physicalLocation"]
        observed.append(
            (physical["artifactLocation"]["uri"], physical["region"]["startLine"])
        )
    assert observed == [("api.py", 12), ("api.py", 13), ("db.py", 4)]
    metadata = result["properties"]["skylos_metadata"]
    assert metadata["security_trace"] == row["metadata"]["security_trace"]
    assert metadata["security_evidence"] == row["metadata"]["security_evidence"]
    assert result["level"] == "error"
    assert row == before


def test_large_located_trace_does_not_consume_listing_or_semantic_proof():
    row = row_with_trace()
    row["metadata"]["security_trace"]["steps"] *= 20
    report = SarifExporter([row], tool_name="Skylos", version="test").generate()
    metadata = report["runs"][0]["results"][0]["properties"]["skylos_metadata"]
    assert len(metadata["security_trace"]["steps"]) == 60
    assert metadata["listing"]["listed"] is True
    assert metadata["security_evidence"] == row["metadata"]["security_evidence"]


def test_located_trace_does_not_change_gate_or_claim_verified_exploitation():
    row = row_with_trace()
    without_trace = copy.deepcopy(row)
    without_trace["metadata"].pop("security_trace")
    config = {"gate": {"max_critical": 0}}
    assert check_gate({"danger": [row]}, config) == check_gate(
        {"danger": [without_trace]}, config
    )
    report = SarifExporter([row], tool_name="Skylos", version="test").generate()
    result = report["runs"][0]["results"][0]
    contract = result["properties"].get("skylos_evidence_contract")
    if contract:
        assert contract["proof_state"] != "verified"
