"""Frozen source-to-output logging controls on the normal analyzer path."""

import json
from pathlib import Path

import pytest

from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.benchmarks.security import _scan_case

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/security/manifest.json"
# Lines and polarity were fixed from source before the first native scan.
CONTRACTS = (
    ("logging-corpus-env-token", 5),
    ("logging-corpus-public-name", None),
    ("logging-corpus-literal-redaction", None),
    ("logging-corpus-partial-redaction", 6),
    ("logging-corpus-http-status", None),
    ("logging-corpus-http-request-url", 6),
    ("logging-corpus-redact-identity", 5),
    ("logging-corpus-alias-mutation", None),
    ("logging-corpus-alias-rebind", 6),
)


@pytest.mark.parametrize(("case_id", "expected_line"), CONTRACTS)
def test_logging_corpus_contract(case_id, expected_line):
    cases = json.loads(MANIFEST.read_text())["cases"]
    case = next(case for case in cases if case["id"] == case_id)
    mode = "present" if expected_line is not None else "absent"
    assert case["expect"][mode]["danger"] == ["SKY-D251"]
    raw = _scan_case(MANIFEST.parent / case["path"])
    assert analysis_issues(raw, scanner="skylos") == []
    assert raw["analysis_summary"]["total_files"] == 1
    assert raw["analysis_summary"]["languages"] == {"Python": 1}
    rows = [row for row in raw.get("danger", []) if row["rule_id"] == "SKY-D251"]
    expected = [("app.py", expected_line, "HIGH")] if expected_line else []
    assert [
        (Path(row["file"]).name, row["line"], row["severity"]) for row in rows
    ] == expected
    for row in rows:
        assert row["listing"]["listed"] is True
        assert row["metadata"]["security_evidence"]["evidence_kind"] == "source_to_sink"
