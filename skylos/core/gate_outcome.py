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


@dataclass
class GateOutcome:
    """The gate's decision and the reasons behind it."""

    verdict: str
    reasons: list = field(default_factory=list)
    strict: bool = False
    details: str = ""
    hint: str | None = None

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
    incomplete = gatekeeper._analysis_incomplete_reasons(results)
    if incomplete:
        return GateOutcome(INCOMPLETE, incomplete, strict)
    passed, reasons = gatekeeper.check_gate(
        results, config, strict=strict, provenance=provenance
    )
    if passed:
        details, hint = gatekeeper._passed_gate_summary(results, config, strict=strict)
        return GateOutcome(PASSED, list(reasons), strict, details, hint)
    return GateOutcome(FAILED, list(reasons), strict)


def incomplete_scan_outcome(results):
    """An exit-2 scan that ran no gate still says why it is incomplete."""
    reasons = gatekeeper._analysis_incomplete_reasons(results)
    return GateOutcome(INCOMPLETE, reasons) if reasons else None


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
    if outcome.verdict == FAILED and force:
        lines.append(f"   {FORCED_PASS_NOTE}")
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
            console, outcome.reasons, force=force, strict=True
        )


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
        "hint": outcome.hint if passed else None,
        "reason_details": [_reason_json(reason) for reason in outcome.reasons],
    }
