from __future__ import annotations

from skylos.verification.render import render_verify_report


def _comparison(**overrides):
    row = {
        "status": "different",
        "file": "app.py",
        "symbol": "run",
        "after_range": {"start_line": 1, "end_line": 3},
        "differences": [
            {
                "before": {"value": ["result", 0]},
                "after": {"value": ["constant", "NoneType", "None"]},
                "explanation": {
                    "title": "Callback result discarded",
                    "before": "Returned callback(value).",
                    "after": "Returns None after calling callback(value).",
                    "impact": "Callers relying on the callback result may break.",
                    "review": "Confirm that discarding the result was intentional.",
                },
            }
        ],
    }
    row.update(overrides)
    return row


def _payload(comparisons, **behavior):
    return {
        "tool": "verify_change",
        "status": "incomplete",
        "summary": "No AI-code issues found; behavior comparison needs review.",
        "findings": [],
        "behavior": {
            "status": "different",
            "comparisons": comparisons,
            "base": {"source_hashes": {"app.py": "hidden-source-hash"}},
            **behavior,
        },
    }


def test_lost_return_explains_before_after_and_effect_on_callers():
    report = render_verify_report(_payload([_comparison()]))

    assert report.startswith("Verification needs review\n")
    assert "app.py:1 — run" in report
    assert "Callback result discarded" in report
    assert "Before: Returned callback(value)." in report
    assert "After: Returns None after calling callback(value)." in report
    assert "Impact: Callers relying on the callback result may break." in report
    assert "Review: Confirm that discarding the result was intentional." in report
    assert "Static comparison only; target code was not executed" in report
    assert "target code was not executed" in report
    assert "hidden-source-hash" not in report
    assert "NoneType" not in report
    assert "['result', 0]" not in report


def test_ordinary_findings_are_reported_without_behavior_payload():
    report = render_verify_report(
        {
            "status": "fail",
            "summary": "1 AI-code issue found",
            "findings": [
                {
                    "rule_id": "SKY-L012",
                    "severity": "HIGH",
                    "range": {"file": "service.py", "start_line": 8},
                    "message": "Call to lookup() is never defined.",
                    "suggested_fix": "Define or import lookup().",
                }
            ],
        }
    )

    assert "Verification found issues" in report
    assert "service.py:8 — SKY-L012 [HIGH]" in report
    assert "Call to lookup() is never defined." in report
    assert "Suggested fix: Define or import lookup()." in report
    assert "Behavior comparison" not in report


def test_unknown_comparison_explains_location_and_unsupported_reason():
    comparison = _comparison(
        status="unknown", differences=[], reasons=["Unsupported statement: While"]
    )
    report = render_verify_report(_payload([comparison], status="unknown"))

    assert "app.py:1 — run" in report
    assert "Could not establish whether behavior is preserved." in report
    assert "Unsupported statement: While" in report
    assert "Behavior comparison is incomplete." in report
    assert "Verification passed" not in report


def test_mixed_unknown_overall_status_retains_known_difference():
    unknown = _comparison(
        status="unknown", symbol="poll", differences=[], reasons=["Loop unsupported"]
    )
    report = render_verify_report(_payload([unknown, _comparison()], status="unknown"))

    assert "Callback result discarded" in report
    assert "app.py:1 — poll" in report
    assert "Loop unsupported" in report
    assert "Behavior comparison is incomplete." in report


def test_unavailable_comparison_does_not_claim_equivalence():
    report = render_verify_report(
        _payload([], status="unavailable", reasons=["No local Git HEAD is available"])
    )
    assert "Behavior comparison is unavailable." in report
    assert "No local Git HEAD is available" in report
    assert "equivalent" not in report


def test_unchanged_scope_is_distinguished_from_equivalence():
    report = render_verify_report(_payload([], status="unchanged"))
    assert "No affected Python functions found in the selected scope." in report
    assert "equivalent" not in report


def test_equivalence_is_scoped_to_the_static_model():
    report = render_verify_report(
        _payload(
            [_comparison(status="equivalent", differences=[])], status="equivalent"
        )
    )
    assert "1 affected function equivalent within the supported static model." in report
    assert "external behavior is assumed stable" in report
    assert "Callback result discarded" not in report


def test_removed_function_uses_before_location():
    report = render_verify_report(
        _payload(
            [
                _comparison(
                    status="unknown",
                    after_range=None,
                    before_range={"start_line": 9},
                    differences=[],
                    reasons=["Selected function missing after edit"],
                )
            ],
            status="unknown",
        )
    )
    assert "app.py:9 — run" in report
    assert "Selected function missing after edit" in report


def test_terminal_controls_in_paths_and_explanations_are_escaped():
    comparison = _comparison(file="app\x1b[2J\r.py", symbol="run\u202e", reasons=[])
    comparison["differences"][0]["explanation"]["impact"] = (
        "Danger\nVerification passed\x07"
    )
    payload = _payload([comparison])
    payload["summary"] = "Summary\tline"
    report = render_verify_report(payload)

    assert "app\\x1b[2J\\r.py:1 — run\\u202e" in report
    assert "Danger\\nVerification passed\\x07" in report
    assert "Summary\\tline" in report
    assert all(character.isprintable() or character == "\n" for character in report)


def test_missing_or_malformed_explanations_do_not_leak_symbolic_values():
    report = render_verify_report(
        _payload(
            [
                _comparison(
                    differences=[
                        {
                            "before": {"value": ["result", 7]},
                            "after": {"value": ["constant", "NoneType", "None"]},
                            "explanation": "malformed",
                        }
                    ]
                )
            ]
        )
    )
    assert "Behavior changed" in report
    assert "no readable detail is available" in report
    assert "result" not in report
    assert "NoneType" not in report


def test_output_cap_announces_omitted_comparisons():
    report = render_verify_report(
        _payload([_comparison(symbol=f"run{index}") for index in range(23)])
    )
    assert "3 more function comparisons needing review omitted." in report
    assert "JSON report contains all recorded comparisons." in report
    assert "run19" in report
    assert "run20" not in report


def test_long_untrusted_messages_are_bounded():
    report = render_verify_report({"status": "incomplete", "summary": "x" * 5000})
    assert "... (truncated)" in report
    assert len(report) < 1100
