"""Coverage gaps are warnings; only failures that block exit 2 (wave-2 0.1).

One unparseable file, a stray file of a language without its engine, or grep
verification that ran out of budget must not turn a whole scan into exit 2.
The gate is decided on what was analysed, and the gap is reported. Exit 2
remains for --strict, for blocking failures, when most of the code was not
analysed, and for diff-scoped scans whose changed code was not analysed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from skylos import cli
from skylos.core import gatekeeper
from skylos.core.gate_incomplete import (
    COVERAGE_COMPLETE,
    COVERAGE_INCOMPLETE,
    COVERAGE_PARTIAL,
    analysis_coverage,
    coverage_record,
    incomplete_analysis_reasons,
)
from skylos.core.gate_outcome import FAILED, INCOMPLETE, PASSED, evaluate_gate, gate_record


def _syntax_error(path="pkg/broken.py", line=3):
    return {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "severity": "HIGH",
        "kind": "syntax_error",
        "message": "invalid syntax",
        "file": path,
        "line": line,
        "suggestion": "Fix the reported syntax.",
    }


def _go_engine_error(affected=1):
    return {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "severity": "HIGH",
        "kind": "language_engine_unavailable",
        "message": "Go analysis incomplete: Go engine binary not found (skylos-go).",
        "file": "tools/gen.go",
        "line": 1,
        "language": "go",
        "affected_file_count": affected,
        "skipped_checks": ["dead_code", "security"],
    }


def _go_summary(total, affected):
    return {
        "total_files": total,
        "incomplete_languages": ["go"],
        "language_engines": {
            "go": {
                "status": "partial",
                "file_count": affected,
                "engine": {"status": "unavailable", "reason": "not found"},
                "skipped_checks": ["dead_code", "security"],
            }
        },
    }


def _result(errors=(), **summary):
    summary.setdefault("total_files", 3)
    return {
        "analysis_errors": list(errors),
        "analysis_summary": summary,
        "danger": [],
        "unused_functions": [],
    }


def _args(**overrides):
    values = {"strict": False, "gate": False, "force": False, "format": "rich"}
    values.update(overrides)
    return SimpleNamespace(**values)


# --- classification ---------------------------------------------------------


def test_one_unparseable_file_is_a_coverage_gap_not_a_blocker():
    coverage = analysis_coverage(_result([_syntax_error()]))

    assert coverage.status == COVERAGE_PARTIAL
    assert coverage.blocking == ()
    assert len(coverage.gaps) == 1
    assert coverage.unchecked_file_count == 1
    assert coverage.source_file_count == 3
    gap = coverage.gaps[0]
    assert gap.text == "Incomplete coverage: 1 of 3 source files could not be analysed"
    assert any("pkg/broken.py:3" in line for line in gap.details)
    assert coverage.unchecked_files[0]["file"] == "pkg/broken.py"
    assert coverage.unchecked_files[0]["kind"] == "syntax_error"


def test_strict_and_require_complete_turn_gaps_into_blockers():
    result = _result([_syntax_error()])

    assert analysis_coverage(result, strict=True).status == COVERAGE_INCOMPLETE
    assert analysis_coverage(result, require_complete=True).status == (
        COVERAGE_INCOMPLETE
    )
    config = {"gate": {"coverage": {"require_complete": True}}}
    assert gatekeeper._analysis_blocking_reasons(result, config=config)
    assert not gatekeeper._analysis_blocking_reasons(result)


def test_most_of_the_code_unanalysed_still_blocks():
    only_file = _result([_syntax_error()], total_files=1)
    coverage = analysis_coverage(only_file)

    assert coverage.status == COVERAGE_INCOMPLETE
    assert coverage.most_code_unchecked is True
    assert coverage.blocking[0].text == (
        "Analysis incomplete: 1 of 1 source file could not be analysed"
    )


def test_half_of_the_files_is_not_most_of_the_code():
    result = _result(
        [_syntax_error("a.py"), _syntax_error("b.py")], total_files=4
    )
    assert analysis_coverage(result).status == COVERAGE_PARTIAL


def test_missing_total_fails_closed():
    result = {"analysis_errors": [_syntax_error()], "analysis_summary": {}}
    assert analysis_coverage(result).status == COVERAGE_INCOMPLETE


def test_stray_go_file_without_engine_is_a_gap():
    result = _result([_go_engine_error(affected=1)], **_go_summary(40, 1))
    coverage = analysis_coverage(result)

    assert coverage.status == COVERAGE_PARTIAL
    assert coverage.unchecked_file_count == 1
    assert any("go" in gap.text for gap in coverage.gaps)


def test_go_repository_without_engine_blocks():
    result = _result([_go_engine_error(affected=392)], **_go_summary(397, 392))
    coverage = analysis_coverage(result)

    assert coverage.status == COVERAGE_INCOMPLETE
    assert coverage.unchecked_file_count == 392


def test_engine_summary_without_engine_records_fails_closed():
    result = _result([], **_go_summary(40, 1))
    assert analysis_coverage(result).status == COVERAGE_INCOMPLETE


@pytest.mark.parametrize(
    "error",
    [
        {"kind": "security_regression_unavailable", "file": "."},
        {"kind": "custom_rules_unavailable", "file": "."},
        {"kind": "config_scan_error", "file": "."},
        {"kind": "something_new", "file": "a.py"},
        {
            "kind": "config_parse_error",
            "component": "github_actions",
            "file": ".github/workflows/ci.yml",
        },
    ],
)
def test_failed_checks_and_unknown_kinds_still_block(error):
    result = _result([error, _syntax_error()], total_files=50)
    coverage = analysis_coverage(result)

    assert coverage.status == COVERAGE_INCOMPLETE
    assert coverage.blocking[0].text.startswith("Analysis incomplete: 1 analysis error")


def test_malformed_errors_block():
    result = _result(total_files=50)
    result["analysis_errors"] = "broken"
    assert analysis_coverage(result).status == COVERAGE_INCOMPLETE


def test_unavailable_dependency_scan_still_blocks():
    result = _result(total_files=10, sca_coverage={"status": "unavailable"})
    assert analysis_coverage(result).status == COVERAGE_INCOMPLETE


@pytest.mark.parametrize(
    "marker",
    [
        {"analysis_summary": {"diff_scoped": True}},
        {"analysis_summary": {"comparison_scope": {"changed_files_only": True}}},
        {"analysis_warnings": [{"kind": "syntax_error", "outside_diff": True}]},
    ],
)
def test_diff_scoped_errors_are_in_changed_code_and_block(marker):
    result = _result([_syntax_error()], total_files=200)
    for key, value in marker.items():
        if key == "analysis_summary":
            result["analysis_summary"].update(value)
        else:
            result[key] = value

    assert analysis_coverage(result).status == COVERAGE_INCOMPLETE


def test_diff_scan_with_engine_errors_moved_outside_diff_is_a_gap():
    result = _result([], **_go_summary(40, 1))
    result["analysis_summary"]["diff_scoped"] = True
    result["analysis_warnings"] = [
        dict(_go_engine_error(), outside_diff=True, severity="LOW")
    ]

    assert analysis_coverage(result).status == COVERAGE_PARTIAL


def test_grep_verification_shortfall_is_a_gap_with_counts():
    error = {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "kind": "grep_budget_exhausted",
        "message": "Grep verification exceeded its 120-second budget.",
        "file": "app.py",
        "candidate_count": 10,
        "unverified_candidate_count": 4,
    }
    coverage = analysis_coverage(_result([error], total_files=500))

    assert coverage.status == COVERAGE_PARTIAL
    assert coverage.unverified_candidate_count == 4
    assert coverage.unchecked_file_count == 0
    assert coverage.gaps[0].text == (
        "Incomplete dead-code verification: grep verification checked 6 of 10 "
        "candidates; 4 unverified candidates not reported"
    )
    # Even in a diff scan it never blocks: unverified candidates are withheld.
    diff = _result([error], total_files=500, diff_scoped=True)
    assert analysis_coverage(diff).status == COVERAGE_PARTIAL


def test_completeness_consumers_still_see_every_gap():
    # Baselines and GitLab completeness need a complete scan.
    reasons = incomplete_analysis_reasons(_result([_syntax_error()]))
    assert [reason.text for reason in reasons] == [
        "Analysis incomplete: 1 analysis error(s) prevented a complete scan"
    ]
    assert gatekeeper._analysis_incomplete_reasons(_result([_syntax_error()]))
    assert incomplete_analysis_reasons(_result()) == []


def test_coverage_record_is_machine_readable():
    record = coverage_record(analysis_coverage(_result([_syntax_error()])))

    assert record["status"] == COVERAGE_PARTIAL
    assert record["exit_blocking"] is False
    assert record["unchecked_file_count"] == 1
    assert record["source_file_count"] == 3
    assert record["unchecked_files"][0]["file"] == "pkg/broken.py"
    assert record["warnings"][0]["message"].startswith("Incomplete coverage")
    assert record["blocking_reasons"] == []
    json.dumps(record)


def test_complete_scan_has_complete_coverage():
    assert analysis_coverage(_result()).status == COVERAGE_COMPLETE


# --- gates and exit codes ---------------------------------------------------


def test_gate_is_decided_on_what_was_analysed():
    clean = _result([_syntax_error()])
    outcome = evaluate_gate(clean, {})
    assert outcome.verdict == PASSED
    assert outcome.exit_code() == 0
    assert [str(gap) for gap in outcome.coverage_gaps] == [
        "Incomplete coverage: 1 of 3 source files could not be analysed"
    ]

    risky = _result([_syntax_error()])
    risky["danger"] = [
        {"rule_id": "SKY-D201", "severity": "CRITICAL", "message": "eval", "file": "a.py", "line": 1}
    ]
    outcome = evaluate_gate(risky, {})
    assert outcome.verdict == FAILED
    assert outcome.exit_code() == 1
    assert outcome.coverage_gaps


def test_gate_with_strict_or_required_coverage_is_incomplete():
    result = _result([_syntax_error()])
    assert evaluate_gate(result, {}, strict=True).verdict == INCOMPLETE
    config = {"gate": {"coverage": {"require_complete": True}}}
    outcome = evaluate_gate(result, config)
    assert outcome.verdict == INCOMPLETE
    assert outcome.exit_code(force=True) == 2


def test_check_gate_passes_on_partial_coverage_and_blocks_with_strict_config():
    result = _result([_syntax_error()])
    passed, reasons = gatekeeper.check_gate(result, {})
    assert passed is True

    passed, reasons = gatekeeper.check_gate(result, {"gate": {"strict": True}})
    assert passed is False
    assert "Incomplete coverage" in str(reasons[0])


def test_gate_record_states_coverage():
    outcome = evaluate_gate(_result([_syntax_error()]), {})
    record = gate_record(outcome, scope="local_configured_policy")

    assert record["verdict"] == "passed"
    assert record["exit_code"] == 0
    assert record["coverage_status"] == "partial"
    assert record["coverage_warnings"] == [
        "Incomplete coverage: 1 of 3 source files could not be analysed"
    ]
    assert record["coverage_warning_details"][0]["details"]

    complete = gate_record(evaluate_gate(_result(), {}), scope="local_configured_policy")
    assert complete["coverage_status"] == "complete"
    assert complete["coverage_warnings"] == []


def test_run_gate_interaction_passes_and_prints_the_gap(capsys):
    exit_code = gatekeeper.run_gate_interaction(
        result=_result([_syntax_error()]), config={}, strict=False
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Quality Gate: PASSED" in out
    assert "Coverage: INCOMPLETE" in out
    assert "pkg/broken.py:3" in out


def test_run_gate_interaction_strict_config_keeps_exit_2():
    exit_code = gatekeeper.run_gate_interaction(
        result=_result([_syntax_error()]), config={"gate": {"strict": True}}
    )
    assert exit_code == 2


def test_summary_markdown_lists_the_gap():
    gaps = gatekeeper._coverage_gap_reasons(_result([_syntax_error()]))
    markdown = gatekeeper.build_summary_markdown(
        _result([_syntax_error()]), True, [], coverage_gaps=gaps
    )
    assert "### Incomplete Coverage" in markdown
    assert "`pkg/broken.py:3  syntax error: invalid syntax`" in markdown


def test_scan_exit_codes():
    gap = _result([_syntax_error()])
    assert cli._strict_scan_exit_code(gap, _args()) == 0
    assert cli._strict_scan_exit_code(gap, _args(strict=True)) == 2
    assert cli._analysis_incomplete_exit_code(gap) == 0
    assert cli._analysis_incomplete_exit_code(gap, strict=True) == 2
    assert cli._analysis_incomplete_exit_code(_result([_syntax_error()], total_files=1)) == 2


def test_formatted_scan_prints_the_gap_on_stderr(capsys):
    exit_code = cli._finish_formatted_scan(
        _result([_syntax_error()]), {}, _args(format="concise", concise=True)
    )
    err = capsys.readouterr().err
    assert exit_code == 0
    assert err.startswith("Coverage: INCOMPLETE")
    assert "pkg/broken.py:3" in err
    assert "--strict" in err


def test_attached_coverage_reflects_this_run():
    result = _result([_syntax_error()])
    record = cli._attach_analysis_coverage(result, {}, _args())
    assert record["exit_blocking"] is False
    assert result["analysis_summary"]["analysis_coverage"] == record

    record = cli._attach_analysis_coverage(result, {}, _args(strict=True))
    assert record["exit_blocking"] is True
    assert record["status"] == COVERAGE_INCOMPLETE
