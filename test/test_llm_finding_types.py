"""Deterministic agent reports compact only Advice, with no LLM/API calls."""

import copy
import json
import re

from skylos.reporting.llm_report import _generate_llm_report
from skylos.core.safe_cache_io import write_text_no_symlink


def _finding(rule, index, *, severity="HIGH"):
    return {
        "rule_id": rule,
        "severity": severity,
        "file": "missing.py",
        "line": index + 1,
        "name": f"item_{index}",
        "message": f"message-{rule}-{index}",
        "evidence": {
            "trace": [f"source-{index}", "sink"],
            "conditions": {"checked": False},
        },
        "value": index,
    }


def _records(report):
    return [
        json.loads(value)
        for value in re.findall(
            r"Record:\n```json\n(.*?)\n```", report, flags=re.DOTALL
        )
    ]


def test_default_report_groups_large_advice_and_keeps_every_risk_record(tmp_path):
    advice = [_finding("SKY-Q301", n) for n in range(1500)]
    defects = [_finding("SKY-L001", n, severity="LOW") for n in range(60)]
    reviews = [_finding("SKY-T103", n) for n in range(75)]
    result = {"quality": [*advice, *defects, *reviews]}
    report = _generate_llm_report(result, tmp_path)
    records = _records(report)

    assert len(records) == 135
    assert records == [*reviews, *defects]
    assert report.startswith(
        "# Skylos Report\n\n60 defects · 75 review · 1500 advice in 1 group."
    )
    assert "SKY-Q301: 1500 findings in 1 file" in report
    assert "--expand-advice" in report
    assert "message-SKY-Q301-" not in report
    assert "Fix each finding" not in report
    assert "Type: Defect" in report and "Type: Review" in report
    assert all(finding["finding_type"] == "advice" for finding in advice)
    assert records[-1]["severity"] == "LOW"


def test_advice_only_report_discloses_records_instead_of_no_findings(tmp_path):
    result = {"quality": [_finding("SKY-Q301", 0), _finding("SKY-R101", 1)]}
    report = _generate_llm_report(result, tmp_path)
    assert "No findings." not in report
    assert "0 defects · 0 review · 2 advice in 2 groups." in report
    assert "SKY-Q301: 1 finding" in report
    assert "SKY-R101: 1 finding" in report
    assert _records(report) == []


def test_expanded_report_includes_every_advice_record(tmp_path):
    advice = [_finding("SKY-Q301", n) for n in range(120)]
    result = {"quality": advice}
    report = _generate_llm_report(result, tmp_path, expand_advice=True)
    assert _records(report) == advice
    assert "Advice groups" not in report
    assert report.count("Type: Advice") == 120
    assert "0 defects · 0 review · 120 advice in 1 group." in report


def test_complete_records_include_sca_exports_cycles_custom_and_errors(tmp_path):
    custom = _finding("SKY-Q301", 3)
    # A custom policy reusing a built-in Advice rule ID must still require Review.
    result = {
        "dependency_vulnerabilities": [_finding("SKY-SCA001", 0)],
        "unused_exports": [_finding("UNKNOWN-EXPORT", 1)],
        "circular_dependencies": [_finding("SKY-Q805", 2)],
        "custom_rules": [custom],
        "analysis_errors": [
            {
                "kind": "parse_error",
                "message": "analysis incomplete",
                "extra": {"file": "x"},
            }
        ],
    }
    report = _generate_llm_report(result, tmp_path)
    records = _records(report)
    assert len(records) == 5
    assert "Analysis incomplete: 1 error." in report
    assert custom in records
    assert custom["finding_type"] == "review"
    assert any(record.get("rule_id") == "SKY-SCA001" for record in records)
    assert any(record.get("rule_id") == "UNKNOWN-EXPORT" for record in records)
    assert any(
        record.get("kind") == "parse_error" and record["extra"] == {"file": "x"}
        for record in records
    )


def test_same_location_evidence_variants_are_not_silently_dropped(tmp_path):
    first = _finding("SKY-T103", 0)
    second = copy.deepcopy(first)
    second["evidence"]["trace"] = ["different source", "sink"]
    result = {"quality": [first, second]}
    assert _records(_generate_llm_report(result, tmp_path)) == [first, second]


def test_secret_full_record_redacts_injected_values_and_avoids_source(tmp_path):
    secret = "ghp_" + "1234567890" + "abcdefghijklmnop" + "qrstuvwxyzABCD"
    source = tmp_path / "settings.py"
    assert write_text_no_symlink(source, f'TOKEN = "{secret}"\n', encoding="utf-8")
    finding = {
        "rule_id": "SKY-S101",
        "severity": "CRITICAL",
        "file": str(source),
        "line": 1,
        "message": "Secret found",
        "preview": "ghp_…ABCD",
        "value": secret,
        "match": secret,
        "evidence": {"token": secret, "source": f'TOKEN = "{secret}"'},
    }
    result = {"secrets": [finding]}
    report = _generate_llm_report(result, tmp_path)
    assert secret not in report
    assert 'TOKEN = "ghp_' not in report
    assert "ghp_…ABCD" in report
    record = _records(report)[0]
    assert record["value"] == "[REDACTED_SECRET]"
    assert record["match"] == "[REDACTED_SECRET]"
    assert record["evidence"]["token"] == "[REDACTED_SECRET]"
    assert record["severity"] == "CRITICAL" and record["finding_type"] == "review"
    assert finding["value"] == secret


def test_empty_report_keeps_plain_no_findings(tmp_path):
    assert _generate_llm_report({}, tmp_path) == "# Skylos Report\n\nNo findings.\n"


def test_generic_secret_echoes_and_match_lists_stay_redacted(tmp_path):
    first = "arbitrary-database-password"
    second = "second-arbitrary-credential"
    finding = {
        "rule_id": "SKY-S101",
        "severity": "HIGH",
        "preview": "****",
        "value": first,
        "match": [second],
        "message": f"Exposed {first}",
        "evidence": {"text": f"{first} / {second}", "trace": [second, first]},
    }
    report = _generate_llm_report({"secrets": [finding]}, tmp_path)
    assert first not in report and second not in report
    record = _records(report)[0]
    assert record["preview"] == "****"
    assert record["match"] == ["[REDACTED_SECRET]"]
    assert record["evidence"]["trace"] == ["[REDACTED_SECRET]", "[REDACTED_SECRET]"]
    assert finding["value"] == first
