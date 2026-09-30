"""Evidence levels for static security findings (plan 7.3).

Each eligible finding gets ``metadata["verification"]``:

- ``traced``: the rule proved an untrusted source reaches the sink. AI votes
  are recorded but can never demote it.
- ``ai_verified``: a majority of independent AI runs judged it real.
- ``refuted``: every run refuted it with a code-level safety proof (kind and
  line numbers). The only level allowed to stop a finding from blocking.
- ``unverified``: the runs did not agree. Still blocking.

Findings that were not checked (no model, over budget, unsupported language,
unparsable file) get no record, and stay blocking.

The model only ever sees the flagged file with comments and docstrings
removed (line numbers kept), plus the rule's own message and trace. Nothing
from the PR (title, body, commit messages) is sent, so text written to steer
a reviewer cannot reach it through those channels.
"""

from __future__ import annotations

import ast
import io
import logging
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .security_verifier import (
    PROOF_KIND_FIELD,
    PROOF_LINES_FIELD,
    REASON_KEY,
    REFUTATION_PROOF_KINDS,
    REFUTED_VERDICT,
    REVIEW_MODE,
    SAFETY_PROOF_FIELD,
    SUPPORTED_VERDICT,
    VERDICT_KEY,
    SecurityVerifier,
)

logger = logging.getLogger(__name__)

VERIFICATION_KEY = "verification"
TRACED = "traced"
AI_VERIFIED = "ai_verified"
REFUTED = "refuted"
UNVERIFIED = "unverified"

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SUPPORTED_SUFFIXES = (".py",)
_MAX_REASON = 500


@dataclass(frozen=True)
class VerificationSettings:
    runs: int = 3
    temperature: float = 0.6
    max_findings: int = 20
    min_severity: str = "HIGH"
    batch_size: int = 5


def _metadata(finding: dict[str, Any]) -> dict[str, Any]:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        finding["metadata"] = metadata
    return metadata


def has_deterministic_trace(finding: dict[str, Any]) -> bool:
    """True when the rule itself proved an untrusted source reaches the sink."""
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    if metadata.get("untrusted_source"):
        return True
    evidence = metadata.get("security_evidence")
    return isinstance(evidence, dict) and evidence.get("evidence_kind") == "source_to_sink"


def is_eligible(finding: dict[str, Any], min_severity: str) -> bool:
    rule_id = str(finding.get("rule_id") or "")
    severity = str(finding.get("severity") or "").upper()
    file_path = str(finding.get("file") or "")
    threshold = _SEVERITY_RANK.get(min_severity.upper(), 1)
    return (
        rule_id.startswith("SKY-D")
        and _SEVERITY_RANK.get(severity, 99) <= threshold
        and file_path.endswith(_SUPPORTED_SUFFIXES)
    )


def strip_comments_and_docstrings(source: str) -> str | None:
    """The source with comments and docstrings blanked; line numbers unchanged.

    Returns None when the file doesn't tokenize or parse, so it is left
    unchecked rather than shown to the model with its comments intact.
    """
    lines = source.splitlines(keepends=True)
    blank: dict[int, list[tuple[int, int]]] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                (row, col), (_, end_col) = token.start, token.end
                blank.setdefault(row, []).append((col, end_col))
        tree = ast.parse(source)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None

    docstring_rows: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and first.end_lineno is not None
        ):
            docstring_rows.update(range(first.lineno, first.end_lineno + 1))

    out: list[str] = []
    for row, line in enumerate(lines, start=1):
        ending = "\n" if line.endswith("\n") else ""
        if row in docstring_rows:
            out.append(ending)
            continue
        spans = blank.get(row)
        if spans:
            text = line[: len(line) - len(ending)] if ending else line
            for start, end in sorted(spans, reverse=True):
                text = text[:start] + text[end:]
            out.append(text.rstrip() + ending)
        else:
            out.append(line)
    return "".join(out)


def _valid_refutation(decision: dict[str, Any], line_count: int) -> bool:
    lines = decision.get(PROOF_LINES_FIELD) or []
    return (
        bool(str(decision.get(SAFETY_PROOF_FIELD) or "").strip())
        and decision.get(PROOF_KIND_FIELD) in REFUTATION_PROOF_KINDS
        and bool(lines)
        and all(1 <= line <= line_count for line in lines)
    )


def aggregate_votes(
    decisions: list[dict[str, Any] | None],
    *,
    traced: bool,
    line_count: int,
    runs: int,
) -> dict[str, Any]:
    """Combine independent runs into one evidence level (asymmetric on purpose)."""
    supported = refuted = uncertain = 0
    first_refutation: dict[str, Any] | None = None
    first_support: dict[str, Any] | None = None
    for decision in decisions:
        verdict = str((decision or {}).get(VERDICT_KEY) or "").upper()
        if verdict == SUPPORTED_VERDICT:
            supported += 1
            first_support = first_support or decision
        elif verdict == REFUTED_VERDICT and decision and _valid_refutation(decision, line_count):
            refuted += 1
            first_refutation = first_refutation or decision
        else:
            # Includes failed runs and refutations without a checkable proof.
            uncertain += 1
    uncertain += max(0, runs - len(decisions))

    if traced:
        level = TRACED
    elif refuted == runs and runs > 0:
        level = REFUTED
    elif supported * 2 > runs:
        level = AI_VERIFIED
    else:
        level = UNVERIFIED

    record: dict[str, Any] = {
        "level": level,
        "votes": {"supported": supported, "refuted": refuted, "uncertain": uncertain},
        "runs": runs,
    }
    if traced and refuted:
        # The rule's own trace wins, but a human should see the dispute.
        record["disputed"] = True
    source = first_refutation if level == REFUTED or (traced and refuted) else first_support
    if source:
        reason = str(source.get(REASON_KEY) or "").strip()
        if reason:
            record["reason"] = reason[:_MAX_REASON]
    if first_refutation and (level == REFUTED or record.get("disputed")):
        record["proof_kind"] = first_refutation.get(PROOF_KIND_FIELD)
        record["proof_lines"] = list(first_refutation.get(PROOF_LINES_FIELD) or [])[:20]
    return record


def verify_security_findings(
    findings: list[dict[str, Any]],
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    settings: VerificationSettings = VerificationSettings(),
    read_source: Callable[[str], str | None] | None = None,
    verifier_factory: Callable[[], SecurityVerifier] | None = None,
) -> dict[str, int]:
    """Annotate eligible findings in place; returns counts per level."""
    counts = {TRACED: 0, AI_VERIFIED: 0, REFUTED: 0, UNVERIFIED: 0, "not_checked": 0}
    runs = max(1, int(settings.runs))
    eligible = [f for f in findings if isinstance(f, dict) and is_eligible(f, settings.min_severity)]
    eligible.sort(key=lambda f: (_SEVERITY_RANK.get(str(f.get("severity") or "").upper(), 99),
                                 str(f.get("file") or ""), int(f.get("line") or 0)))
    selected = eligible[: max(0, settings.max_findings)]
    counts["not_checked"] = len(eligible) - len(selected)

    def default_factory() -> SecurityVerifier:
        verifier = SecurityVerifier(
            model=model, api_key=api_key, provider=provider, base_url=base_url,
            max_review=len(selected) or 1, batch_size=settings.batch_size,
        )
        verifier.config.temperature = settings.temperature
        return verifier

    verifier = (verifier_factory or default_factory)()
    reader = read_source or (lambda path: Path(path).read_text(encoding="utf-8"))

    by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in selected:
        by_file.setdefault(str(finding.get("file") or ""), []).append(finding)

    for file_path, file_findings in by_file.items():
        try:
            source = reader(file_path)
        except OSError:
            source = None
        stripped = strip_comments_and_docstrings(source) if source is not None else None
        if stripped is None:
            counts["not_checked"] += len(file_findings)
            continue
        line_count = len(stripped.splitlines())
        votes: dict[int, list[dict[str, Any] | None]] = {id(f): [] for f in file_findings}
        for _ in range(runs):
            for start in range(0, len(file_findings), max(1, settings.batch_size)):
                batch = file_findings[start : start + max(1, settings.batch_size)]
                try:
                    decisions = verifier._review_batch(batch, stripped, file_path, mode=REVIEW_MODE)
                except Exception as exc:  # A failed run is an uncertain vote, never a refutation.
                    logger.warning("Finding verification request failed: %s", exc)
                    decisions = []
                for index, finding in enumerate(batch):
                    votes[id(finding)].append(decisions[index] if index < len(decisions) else None)

        for finding in file_findings:
            record = aggregate_votes(
                votes[id(finding)], traced=has_deterministic_trace(finding),
                line_count=line_count, runs=runs,
            )
            record["model"] = model
            _metadata(finding)[VERIFICATION_KEY] = record
            counts[record["level"]] += 1
    return counts
