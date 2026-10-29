from __future__ import annotations

import copy
import os
from typing import Any, Callable

AI_REVIEW_KEY = "ai_review"
MAX_REVIEWERS = 4
MAX_REASON = 500
DEFAULT_MODEL = "gpt-4.1"
DEAD_CODE_MAX_REVIEWS = 50
JEV_KEY_ENV = "TYPESAFE_API_KEY"
JEV_MODEL = "jev-1.13.0"
VERDICTS = ("real", "false_positive", "unsure")

_LLM_VERDICTS = {
    "TRUE_POSITIVE": "real",
    "FALSE_POSITIVE": "false_positive",
    "UNCERTAIN": "unsure",
}

HarnessRunner = Callable[..., Any]


def _reason(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    return text[:MAX_REASON]


def _verification_verdict(record: dict[str, Any]) -> str | None:
    level = record.get("level")
    votes = record.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    if level == "ai_verified":
        return "real"
    if level == "refuted":
        return "false_positive"
    if level == "unverified":
        return "unsure"
    if level != "traced":
        return None
    if record.get("disputed") is True:
        return "false_positive"
    if int(votes.get("supported") or 0) > int(votes.get("refuted") or 0):
        return "real"
    return "unsure"


def reviewer_from_verification(record: Any) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    verdict = _verification_verdict(record)
    if verdict is None:
        return None
    reviewer: dict[str, Any] = {"name": "llm", "verdict": verdict}
    if isinstance(record.get("model"), str) and record["model"]:
        reviewer["model"] = record["model"]
    runs = record.get("runs")
    if isinstance(runs, int) and 0 < runs <= 9:
        reviewer["runs"] = runs
    reason = _reason(record.get("reason"))
    if reason:
        reviewer["reason"] = reason
    return reviewer


def reviewer_from_llm(
    finding: dict[str, Any], model: str | None
) -> dict[str, Any] | None:
    if finding.get("_verified_by_llm") is False:
        return None
    verdict = _LLM_VERDICTS.get(str(finding.get("_llm_verdict") or "").upper())
    if verdict is None:
        return None
    reviewer: dict[str, Any] = {"name": "llm", "verdict": verdict}
    if model:
        reviewer["model"] = model
    reason = _reason(finding.get("_llm_rationale"))
    if reason:
        reviewer["reason"] = reason
    return reviewer


def reviewer_from_jev(finding: dict[str, Any]) -> dict[str, Any] | None:
    verdict = None
    if finding.get("_jev_agreed") is True:
        verdict = "real"
    elif (
        finding.get("_jev_judged_retained") is True
        or finding.get("_jev_status") == "disagreed"
    ):
        verdict = "false_positive"
    elif finding.get("_jev_status") == "uncertain":
        verdict = "unsure"
    if verdict is None:
        return None
    reviewer: dict[str, Any] = {"name": "jev", "verdict": verdict, "model": JEV_MODEL}
    confidence = finding.get("_jev_confidence")
    if (
        isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and 0 <= confidence <= 1
    ):
        reviewer["confidence"] = float(confidence)
    reason = _reason(finding.get("_jev_rationale"))
    if reason:
        reviewer["reason"] = reason
    return reviewer


def attach_ai_review(
    finding: dict[str, Any], reviewers: list[dict[str, Any] | None]
) -> bool:
    kept = [reviewer for reviewer in reviewers if reviewer][:MAX_REVIEWERS]
    if not kept:
        return False
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    metadata[AI_REVIEW_KEY] = {"reviewers": kept}
    finding["metadata"] = metadata
    return True


def ai_review_state(reviewers: list[dict[str, Any]]) -> str | None:
    verdicts = {reviewer.get("verdict") for reviewer in reviewers}
    if not verdicts:
        return None
    if "real" in verdicts and "false_positive" not in verdicts:
        return "confirmed"
    if "false_positive" in verdicts and "real" not in verdicts:
        return "disputed"
    return "unsure"


def attach_security_reviews(result: dict[str, Any]) -> int:
    attached = 0
    for finding in result.get("danger") or []:
        if not isinstance(finding, dict):
            continue
        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if attach_ai_review(
            finding, [reviewer_from_verification(metadata.get("verification"))]
        ):
            attached += 1
    return attached


def _dead_code_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    from skylos.deadcode.collect import DEAD_CODE_RESULT_KEYS

    findings: list[dict[str, Any]] = []
    for key in DEAD_CODE_RESULT_KEYS:
        findings.extend(
            finding for finding in result.get(key) or [] if isinstance(finding, dict)
        )
    return findings


def _finding_key(finding: dict[str, Any]) -> tuple[str, int, str]:
    name = (
        finding.get("full_name")
        or finding.get("name")
        or finding.get("simple_name")
        or ""
    )
    return (str(finding.get("file") or ""), int(finding.get("line") or 0), str(name))


def review_dead_code(
    result: dict[str, Any],
    *,
    project_root: str,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
    use_llm: bool,
    use_jev: bool,
    max_reviews: int = DEAD_CODE_MAX_REVIEWS,
    run_harness: HarnessRunner | None = None,
) -> int:
    if not use_llm and not use_jev:
        return 0
    originals = _dead_code_findings(result)
    if not originals:
        return 0
    copies = [copy.deepcopy(finding) for finding in originals]
    by_identity = {id(item): original for item, original in zip(copies, originals)}
    by_key = {_finding_key(original): original for original in originals}
    if run_harness is None:
        from skylos.llm.harness import run_verification_harness

        run_harness = run_verification_harness
    harness_result = run_harness(
        findings=copies,
        defs_map=copy.deepcopy(result.get("definitions") or {}),
        project_root=project_root,
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        max_verify=max_reviews,
        max_challenge=0,
        enable_survivor_challenge=False,
        enable_suppression_challenge=False,
        quiet=True,
        verification_mode="production",
        jev_precheck=use_llm and use_jev,
        jev_only=use_jev and not use_llm,
    )
    output = getattr(harness_result, "output", harness_result)
    reviewed = 0
    llm_model = model
    if not use_llm:
        llm_model = None
    for item in (output or {}).get("verified_findings") or []:
        if not isinstance(item, dict):
            continue
        original = by_identity.get(id(item)) or by_key.get(_finding_key(item))
        if original is None:
            continue
        reviewers = [reviewer_from_jev(item)]
        if use_llm:
            reviewers.append(reviewer_from_llm(item, llm_model))
        if attach_ai_review(original, reviewers):
            reviewed += 1
    return reviewed


def jev_available() -> bool:
    return bool(os.environ.get(JEV_KEY_ENV, "").strip())


def summarize_ai_reviews(result: dict[str, Any]) -> dict[str, int]:
    counts = {"confirmed": 0, "disputed": 0, "unsure": 0}
    findings = [
        finding for finding in result.get("danger") or [] if isinstance(finding, dict)
    ]
    findings.extend(_dead_code_findings(result))
    for finding in findings:
        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            continue
        review = metadata.get(AI_REVIEW_KEY)
        if not isinstance(review, dict):
            continue
        state = ai_review_state(review.get("reviewers") or [])
        if state:
            counts[state] += 1
    return counts
