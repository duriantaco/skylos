"""Native TLS corpus contracts preserve unsafe findings and inert lookalikes."""

from pathlib import Path

import pytest

from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.benchmarks.security import _scan_case
from skylos.core.gatekeeper import check_gate


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks/security/fixtures"
# Semantic labels were fixed before the first native scan. None of these target
# programs are executed; _scan_case copies their source to an isolated snapshot.
CASES = (
    ("requests_disabled", "Python", 1, 4),
    ("requests_verified", "Python", 1, None),
    ("context_alias_disabled", "Python", 1, 5),
    ("context_default_verified", "Python", 1, None),
    ("inert_helper", "Python", 1, None),
    ("imported_helper_patch", "Python", 2, 5),
    ("context_required_tampered", "Python", 1, 5),
    ("context_explicit_verified", "Python", 1, None),
    ("ts_agent_disabled", "TypeScript", 1, 3),
    ("ts_agent_verified", "TypeScript", 1, None),
    ("ts_env_disabled", "TypeScript", 1, 1),
    ("ts_env_verified", "TypeScript", 1, None),
    ("ts_string_lookalike", "TypeScript", 1, None),
)


@pytest.mark.parametrize("name,language,source_files,line", CASES)
def test_tls_corpus_native_identity_completeness_and_gate(
    name, language, source_files, line
):
    result = _scan_case(FIXTURES / f"tls_corpus_{name}")
    assert analysis_issues(result, scanner="skylos") == []
    assert result["analysis_summary"]["total_files"] == source_files
    assert result["analysis_summary"]["languages"] == {language: source_files}
    findings = [
        finding
        for finding in result.get("danger", [])
        if finding.get("rule_id") == "SKY-D210"
    ]
    extension = "ts" if language == "TypeScript" else "py"
    expected = [] if line is None else [(f"client.{extension}", line, "HIGH")]
    assert [
        (Path(finding["file"]).name, finding["line"], finding["severity"])
        for finding in findings
    ] == expected
    if line is not None:
        assert findings[0]["listing"]["listed"] is True
        passed, reasons = check_gate(
            result, {"gate": {"max_security": 0, "max_high": 0}}
        )
        assert passed is False
        assert any("security issue" in reason for reason in reasons)
