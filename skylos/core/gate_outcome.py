"""One gate verdict for every output mode.

Rich output prints it with the gatekeeper handlers, line-oriented formats
print the same text on stderr, and the scan result carries it as the
top-level ``gate`` object (JSON, SARIF properties, assessment readouts). The
verdict never changes an exit code; it only states it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skylos.core import gatekeeper

PASSED = "passed"
FAILED = "failed"
INCOMPLETE = "incomplete"
FORCED_PASS_NOTE = "Forced pass (local only)"
SCAN_INCOMPLETE_VERDICT = "Scan: INCOMPLETE — required analysis did not finish (exit 2)"
SCAN_INCOMPLETE_EXPLANATION = (
    "Required analysis did not finish, so this scan cannot count as complete "
    "or clean. --force does not change this."
)
COVERAGE_WARNING_HEADLINE = "Coverage: INCOMPLETE — some code was not analysed"


@dataclass
class GateOutcome:
    """The gate's decision and the reasons behind it."""

    verdict: str
    reasons: list = field(default_factory=list)
    strict: bool = False
    details: str = ""
    hint: str | None = None
    # Coverage gaps that did not block: the verdict was decided on the code
    # that was analysed, and these say what was not.
    coverage_gaps: list = field(default_factory=list)

    def exit_code(self, *, force=False):
        if self.verdict == INCOMPLETE:
            return 2
        if self.verdict == FAILED and not force:
            return 1
        return 0


def evaluate_gate(results, config, *, strict=False, provenance=None):
    """Decide the gate exactly as ``check_gate`` does, keeping the reasons."""
    results = results or {}
    config = config or {}
    incomplete = gatekeeper._analysis_blocking_reasons(
        results, strict=strict, config=config
    )
    if incomplete:
        return GateOutcome(INCOMPLETE, incomplete, strict)
    gaps = gatekeeper._coverage_gap_reasons(results, strict=strict, config=config)
    passed, reasons = gatekeeper.check_gate(
        results, config, strict=strict, provenance=provenance
    )
    if passed:
        details, hint = gatekeeper._passed_gate_summary(results, config, strict=strict)
        return GateOutcome(PASSED, list(reasons), strict, details, hint, gaps)
    hint = gatekeeper.cloud_gate_scope_note(results, config, strict=strict)
    return GateOutcome(FAILED, list(reasons), strict, hint=hint, coverage_gaps=gaps)


def incomplete_scan_outcome(results, *, strict=False):
    """An exit-2 scan that ran no gate still says why it is incomplete."""
    reasons = gatekeeper._analysis_blocking_reasons(results, strict=strict)
    return GateOutcome(INCOMPLETE, reasons, strict) if reasons else None


def coverage_gap_reasons(results, *, strict=False):
    """Coverage gaps a scan reports as a warning (none when they block)."""
    return gatekeeper._coverage_gap_reasons(results, strict=strict)


def coverage_warning_lines(gaps):
    """Plain-text coverage warning for stderr: headline, reasons, next step."""
    if not gaps:
        return []
    from skylos.core.gate_incomplete import COVERAGE_STRICT_HINT

    return [
        COVERAGE_WARNING_HEADLINE,
        *gatekeeper.gate_reasons_text(gaps),
        f"   {COVERAGE_STRICT_HINT}",
    ]


def print_coverage_warning(console, gaps):
    """Rich coverage warning: yellow headline, the reasons, the next step."""
    if not gaps:
        return
    from rich.markup import escape

    from skylos.core.gate_incomplete import COVERAGE_STRICT_HINT

    console.print(
        f"\n[bold yellow]{escape(COVERAGE_WARNING_HEADLINE)}[/bold yellow]",
        soft_wrap=True,
    )
    gatekeeper._print_gate_reasons(console, gaps)
    console.print(f"   [yellow]{escape(COVERAGE_STRICT_HINT)}[/yellow]", soft_wrap=True)


def verdict_line(outcome, *, gate=True):
    if outcome.verdict == PASSED:
        suffix = f": {outcome.details}" if outcome.details else ""
        return f"Quality Gate: PASSED{suffix}"
    if outcome.verdict == FAILED:
        return "Quality Gate: FAILED"
    return gatekeeper.INCOMPLETE_VERDICT if gate else SCAN_INCOMPLETE_VERDICT


def _explanation(outcome, *, gate):
    if outcome.verdict != INCOMPLETE:
        return None
    return gatekeeper.INCOMPLETE_EXPLANATION if gate else SCAN_INCOMPLETE_EXPLANATION


def outcome_text_lines(outcome, *, force=False, gate=True):
    """Plain-text verdict line, then the reasons, for stderr output."""
    lines = [verdict_line(outcome, gate=gate)]
    note = (
        outcome.hint if outcome.verdict == PASSED else _explanation(outcome, gate=gate)
    )
    if note:
        lines.append(f"   {note}")
    lines.extend(gatekeeper.gate_reasons_text(outcome.reasons))
    if outcome.verdict == FAILED and outcome.hint:
        lines.append(f"   {outcome.hint}")
    if outcome.verdict == FAILED and force:
        lines.append(f"   {FORCED_PASS_NOTE}")
    lines.extend(coverage_warning_lines(outcome.coverage_gaps))
    return lines


def print_outcome(console, outcome, *, force=False, gate=True):
    """Print the verdict with the same Rich handlers as ``--gate``."""
    if outcome.verdict == INCOMPLETE:
        gatekeeper._handle_incomplete_gate(
            console,
            outcome.reasons,
            verdict=verdict_line(outcome, gate=gate),
            explanation=_explanation(outcome, gate=gate),
        )
    elif outcome.verdict == PASSED:
        gatekeeper._handle_passed_gate(
            console, None, details=outcome.details, hint=outcome.hint
        )
    else:
        # strict=True: print and return; never prompt from a scan's exit path.
        gatekeeper._handle_failed_gate(
            console, outcome.reasons, force=force, strict=True, hint=outcome.hint
        )
    print_coverage_warning(console, outcome.coverage_gaps)


def _reason_json(reason):
    details, hint = gatekeeper.gate_reason_lines(reason)
    return {"message": str(reason), "details": details, "hint": hint}


def gate_record(outcome, *, scope, force=False):
    """The documented top-level ``gate`` object of a scan result.

    The first five fields are the assessment contract (``passed``,
    ``reasons`` as plain strings, ``scope``, ``status``, ``forced``) that the
    assessment readouts, SARIF properties and report consumers already read.
    The rest state the verdict: its exit code and headline, and for each
    entry of ``reasons`` (same order) the literal detail lines and next step.
    """
    passed = outcome.verdict == PASSED
    return {
        "passed": passed,
        "reasons": [str(reason) for reason in outcome.reasons],
        "scope": scope,
        "status": "incomplete" if outcome.verdict == INCOMPLETE else "evaluated",
        "forced": bool(force and not passed),
        "verdict": outcome.verdict,
        "exit_code": outcome.exit_code(force=force),
        "strict": bool(outcome.strict),
        "headline": verdict_line(outcome),
        "hint": outcome.hint,
        "reason_details": [_reason_json(reason) for reason in outcome.reasons],
        "coverage_status": "incomplete"
        if outcome.verdict == INCOMPLETE
        else "partial"
        if outcome.coverage_gaps
        else "complete",
        "coverage_warnings": [str(reason) for reason in outcome.coverage_gaps],
        "coverage_warning_details": [
            _reason_json(reason) for reason in outcome.coverage_gaps
        ],
    }
