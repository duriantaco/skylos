"""Group references must identify the same paths as uploaded finding rows."""

from copy import deepcopy

from skylos.api._findings import _normalize_findings
from skylos.api._payloads import _compact_upload_finding
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.sarif import SarifExporter


def _group(source):
    rows = []
    for rule in ("SKY-Q301", "SKY-Q306"):
        rows.append({
            "rule_id": rule,
            "file": str(source),
            "line": 1,
            "severity": "MEDIUM",
            "name": "build",
            "value": 20,
            "threshold": 10,
            "message": rule,
            "metadata": {"original": "retained"},
        })
    return apply_advice_policy({"quality": rows}, project_root=source.parent)


def test_group_references_follow_upload_paths_without_mutating_raw_report(tmp_path):
    source = tmp_path / "service.py"
    source.write_text("def build():\n    return 1\n", encoding="utf-8")
    result = _group(source)
    original = deepcopy(result)
    normalized = _normalize_findings(
        result["quality"], "QUALITY", str(tmp_path), extract_metadata=True
    )
    assert result == original
    assert len(normalized) == 2
    lead = normalized[0]
    companion = normalized[1]
    assert lead["file_path"] == "service.py"
    assert companion["listing"]["lead"] == {
        "rule_id": lead["rule_id"], "file": lead["file_path"], "line": 1,
    }
    assert companion["metadata"]["listing"] == companion["listing"]
    compact = _compact_upload_finding(companion, include_snippet=False)
    assert compact["listing"]["lead"]["file"] == "service.py"
    assert str(tmp_path) not in str(compact)


def test_standalone_sarif_uses_the_same_path_for_group_links_and_locations(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "service.py"
    source.write_text("def build():\n    return 1\n", encoding="utf-8")
    report = _group(source)
    for finding in report["quality"]:
        finding["metadata"]["listing"] = dict(finding["listing"])
    original = deepcopy(report)
    rows = []
    for finding in report["quality"]:
        rows.append({**finding, "category": "QUALITY"})
    records = SarifExporter(rows).generate()["runs"][0]["results"]
    assert report == original
    location = records[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert location == "service.py"
    assert records[1]["properties"]["listing"]["lead"]["file"] == location
    assert records[1]["properties"]["skylos_metadata"]["listing"]["lead"]["file"] == location
