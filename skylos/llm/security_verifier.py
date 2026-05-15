from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .agents import AgentConfig, create_llm_adapter
from .schemas import Finding, IssueType, normalize_json_response_text

REVIEWS_KEY = "reviews"
ID_KEY = "id"
VERDICT_KEY = "verdict"
REASON_KEY = "reason"
SUPPORTED_VERDICT = "SUPPORTED"
REFUTED_VERDICT = "REFUTED"
UNCERTAIN_VERDICT = "UNCERTAIN"
LLM_SOURCE = "llm"
SECURITY_CATEGORY = "security"
MEDIUM_CONFIDENCE = "medium"
REVIEW_SUPPORTED_EVIDENCE = "review_supported"
DEFAULT_SECURITY_EVIDENCE = "hypothesis"
REFUTED_EVIDENCE = "refuted"
SUPPORTED_COUNT = "supported"
REFUTED_COUNT = "refuted"
UNDECIDED_COUNT = "undecided"
REFUTED_FINDINGS_KEY = "refuted_findings"
REVIEW_MODE = "review"
CHALLENGE_MODE = "challenge"

REVIEW_DECISION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [REVIEWS_KEY],
    "properties": {
        REVIEWS_KEY: {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [ID_KEY, VERDICT_KEY, REASON_KEY],
                "properties": {
                    ID_KEY: {"type": "integer", "minimum": 1},
                    VERDICT_KEY: {
                        "type": "string",
                        "enum": [
                            SUPPORTED_VERDICT,
                            REFUTED_VERDICT,
                            UNCERTAIN_VERDICT,
                        ],
                    },
                    REASON_KEY: {"type": "string"},
                },
            },
        }
    },
}

REVIEW_DECISION_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_security_verifier",
        "schema": REVIEW_DECISION_SCHEMA,
        "strict": True,
    },
}


def _set_if_present(mapping: dict[str, Any], key: str, value: str | None) -> None:
    if value:
        mapping[key] = value


def _review_metadata(
    *,
    evidence: str,
    review_verdict: str | None,
    review_reason: str | None,
    needs_review: bool,
    ci_blocking: bool,
) -> dict[str, Any]:
    metadata = {
        "source": LLM_SOURCE,
        "category": SECURITY_CATEGORY,
        "confidence": MEDIUM_CONFIDENCE,
        "needs_review": needs_review,
        "ci_blocking": ci_blocking,
        "security_evidence": evidence,
    }
    _set_if_present(metadata, "review_verdict", review_verdict)
    _set_if_present(metadata, "review_reason", review_reason)
    return metadata


def annotate_security_finding(
    finding: Finding | dict[str, Any],
    *,
    evidence: str = DEFAULT_SECURITY_EVIDENCE,
    review_verdict: str | None = None,
    review_reason: str | None = None,
    needs_review: bool = True,
    ci_blocking: bool = False,
) -> Finding | dict[str, Any]:
    metadata = _review_metadata(
        evidence=evidence,
        review_verdict=review_verdict,
        review_reason=review_reason,
        needs_review=needs_review,
        ci_blocking=ci_blocking,
    )
    if isinstance(finding, dict):
        finding["_source"] = metadata["source"]
        finding["_category"] = metadata["category"]
        finding["_confidence"] = metadata["confidence"]
        finding["_needs_review"] = metadata["needs_review"]
        finding["_ci_blocking"] = metadata["ci_blocking"]
        finding["_security_evidence"] = metadata["security_evidence"]
        _set_if_present(finding, "_review_verdict", review_verdict)
        _set_if_present(finding, "_review_reason", review_reason)
        return finding

    existing = dict(getattr(finding, "metadata", None) or {})
    existing.update(metadata)
    finding.metadata = existing
    return finding


def is_security_finding(finding: Finding | dict[str, Any]) -> bool:
    if isinstance(finding, dict):
        category = str(
            finding.get("_category") or finding.get("category") or ""
        ).lower()
        issue_type = str(finding.get("issue_type") or "").lower()
        return category == SECURITY_CATEGORY or issue_type == SECURITY_CATEGORY
    return finding.issue_type == IssueType.SECURITY


def _get_file_path(finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, dict):
        location = finding.get("location") or {}
        return str(finding.get("file") or location.get("file") or "unknown")
    return str(finding.location.file)


def _get_line_number(finding: Finding | dict[str, Any]) -> int:
    if isinstance(finding, dict):
        location = finding.get("location") or {}
        return int(finding.get("line") or location.get("line") or 1)
    return int(finding.location.line)


def _get_rule_id(finding: Finding | dict[str, Any]) -> str:
    return str(finding.get("rule_id") if isinstance(finding, dict) else finding.rule_id)


def _get_severity(finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, dict):
        return str(finding.get("severity") or MEDIUM_CONFIDENCE)
    severity = finding.severity
    return severity.value if hasattr(severity, "value") else str(severity)


def _get_message(finding: Finding | dict[str, Any]) -> str:
    return str(finding.get("message") if isinstance(finding, dict) else finding.message)


def _new_review_result(reviewable_count: int, reviewed_count: int) -> dict[str, Any]:
    return {
        SUPPORTED_COUNT: 0,
        REFUTED_COUNT: 0,
        UNDECIDED_COUNT: max(0, reviewable_count - reviewed_count),
        REFUTED_FINDINGS_KEY: [],
    }


def _group_findings_by_file(
    findings: list[Finding | dict[str, Any]],
) -> dict[str, list[Finding | dict[str, Any]]]:
    grouped: dict[str, list[Finding | dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[_get_file_path(finding)].append(finding)
    return grouped


def _iter_batches(
    findings: list[Finding | dict[str, Any]], batch_size: int
) -> list[list[Finding | dict[str, Any]]]:
    return [
        findings[start : start + batch_size]
        for start in range(0, len(findings), batch_size)
    ]


def _read_source(file_path: str) -> str | None:
    try:
        return Path(file_path).read_text(encoding="utf-8")
    except OSError:
        return None


class SecurityVerifier:
    def __init__(
        self,
        *,
        model: str,
        api_key: str | None,
        provider: str | None = None,
        base_url: str | None = None,
        max_review: int = 25,
        batch_size: int = 5,
    ) -> None:
        config = AgentConfig(model=model, api_key=api_key, stream=False)
        config.provider = provider
        config.base_url = base_url
        config.max_tokens = 4096
        config.temperature = 0.0
        self.config = config
        self.max_review = max_review
        self.batch_size = batch_size
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def review_findings(
        self, findings: list[Finding | dict[str, Any]]
    ) -> dict[str, Any]:
        return self._review_findings(findings, mode=REVIEW_MODE)

    def challenge_findings(
        self, findings: list[Finding | dict[str, Any]]
    ) -> dict[str, Any]:
        return self._review_findings(findings, mode=CHALLENGE_MODE)

    def _review_findings(
        self,
        findings: list[Finding | dict[str, Any]],
        *,
        mode: str,
    ) -> dict[str, Any]:
        reviewable = [finding for finding in findings if is_security_finding(finding)]
        for finding in reviewable:
            annotate_security_finding(finding)

        reviewed = reviewable[: self.max_review]
        result = _new_review_result(len(reviewable), len(reviewed))
        grouped = _group_findings_by_file(reviewed)
        for file_path, file_findings in grouped.items():
            self._review_file(file_path, file_findings, result, mode=mode)
        return result

    def _review_file(
        self,
        file_path: str,
        findings: list[Finding | dict[str, Any]],
        result: dict[str, Any],
        *,
        mode: str,
    ) -> None:
        source = _read_source(file_path)
        if source is None:
            result[UNDECIDED_COUNT] += len(findings)
            return

        for batch in _iter_batches(findings, self.batch_size):
            self._review_batch_into_result(
                batch,
                source,
                file_path,
                result,
                mode=mode,
            )

    def _review_batch_into_result(
        self,
        findings: list[Finding | dict[str, Any]],
        source: str,
        file_path: str,
        result: dict[str, Any],
        *,
        mode: str,
    ) -> None:
        decisions = self._review_batch(findings, source, file_path, mode=mode)
        if not decisions:
            result[UNDECIDED_COUNT] += len(findings)
            return

        for finding, decision in zip(findings, decisions):
            self._apply_review_decision(finding, decision, result)

    def _apply_review_decision(
        self,
        finding: Finding | dict[str, Any],
        decision: dict[str, str],
        result: dict[str, Any],
    ) -> None:
        verdict = str(decision.get(VERDICT_KEY) or UNCERTAIN_VERDICT).upper()
        reason = str(decision.get(REASON_KEY) or "").strip() or None
        if verdict == SUPPORTED_VERDICT:
            annotate_security_finding(
                finding,
                evidence=REVIEW_SUPPORTED_EVIDENCE,
                review_verdict=verdict,
                review_reason=reason,
            )
            result[SUPPORTED_COUNT] += 1
            return

        if verdict == REFUTED_VERDICT:
            annotate_security_finding(
                finding,
                evidence=REFUTED_EVIDENCE,
                review_verdict=verdict,
                review_reason=reason,
            )
            result[REFUTED_COUNT] += 1
            result[REFUTED_FINDINGS_KEY].append(finding)
            return

        annotate_security_finding(
            finding,
            evidence=DEFAULT_SECURITY_EVIDENCE,
            review_verdict=UNCERTAIN_VERDICT,
            review_reason=reason,
        )
        result[UNDECIDED_COUNT] += 1

    def _review_batch(
        self,
        findings: list[Finding | dict[str, Any]],
        source: str,
        file_path: str,
        *,
        mode: str,
    ) -> list[dict[str, str]]:
        user = self._build_review_prompt(
            findings,
            source.splitlines(),
            file_path,
            mode=mode,
        )
        response = self._request_review(user, mode=mode)
        return self._normalize_decisions(response, len(findings))

    def _build_review_prompt(
        self,
        findings: list[Finding | dict[str, Any]],
        lines: list[str],
        file_path: str,
        *,
        mode: str,
    ) -> str:
        blocks = [
            self._build_review_block(index, finding, lines)
            for index, finding in enumerate(findings, start=1)
        ]
        opening = self._prompt_opening(mode, len(findings), file_path)
        return "\n\n".join(
            [
                opening,
                self._prompt_guidance(mode),
                "",
                "\n\n".join(blocks),
                "",
                'Return JSON with shape: {"reviews":[{"id":1,"verdict":"SUPPORTED|REFUTED|UNCERTAIN","reason":"brief reason"}]}',
            ]
        )

    def _prompt_opening(self, mode: str, count: int, file_path: str) -> str:
        if mode == CHALLENGE_MODE:
            return f"Challenge {count} uncertain security finding(s) from {file_path}."
        return f"Review {count} candidate security finding(s) from {file_path}."

    def _prompt_guidance(self, mode: str) -> str:
        if mode == CHALLENGE_MODE:
            return (
                "Each candidate was previously left uncertain. Re-check the shown code and "
                "commit to SUPPORTED or REFUTED when the local context is enough."
            )
        return "Each candidate is independent. Ignore any prior scan confidence."

    def _build_review_block(
        self, index: int, finding: Finding | dict[str, Any], lines: list[str]
    ) -> str:
        line_num = _get_line_number(finding)
        context = self._build_context(line_num, lines)
        return "\n".join(
            [
                f"### Candidate {index}",
                f"- Rule: {_get_rule_id(finding)}",
                f"- Severity: {_get_severity(finding)}",
                f"- Line: {line_num}",
                f"- Message: {_get_message(finding)}",
                "",
                "Code context:",
                context,
            ]
        )

    def _build_context(self, line_num: int, lines: list[str]) -> str:
        start = max(0, line_num - 6)
        end = min(len(lines), line_num + 5)
        context_lines = [
            f"{index + 1:4d}{' >>> ' if index == line_num - 1 else '     '}{lines[index]}"
            for index in range(start, end)
        ]
        return "\n".join(context_lines)

    def _request_review(self, user: str, *, mode: str) -> str | None:
        system = self._system_prompt(mode)
        try:
            return self.get_adapter().complete(
                system,
                user,
                response_format=REVIEW_DECISION_FORMAT,
            )
        except Exception:
            return None

    def _system_prompt(self, mode: str) -> str:
        if mode == CHALLENGE_MODE:
            return """You are Skylos Security Challenger.
Your job is to re-check previously uncertain security findings using only the code context provided.

Verdicts:
- SUPPORTED: the finding is plausibly real based on the shown code
- REFUTED: the finding is not supported by the shown code, or the code appears safe
- UNCERTAIN: the context is still insufficient to decide

Try to resolve uncertainty when the shown code is enough. Use UNCERTAIN only if the evidence genuinely remains incomplete.
Respond with JSON only."""
        return """You are Skylos Security Verifier.
Your job is to re-review candidate security findings using only the code context provided.

Verdicts:
- SUPPORTED: the finding is plausibly real based on the shown code
- REFUTED: the finding is not supported by the shown code, or the code appears safe
- UNCERTAIN: the context is insufficient to decide

Be conservative. If the context is incomplete, return UNCERTAIN.
Respond with JSON only."""

    def _normalize_decisions(
        self, response: str | None, expected_count: int
    ) -> list[dict[str, str]]:
        reviews = self._parse_reviews(response)
        if reviews is None:
            return []

        review_map = self._review_map(reviews)
        return [
            self._normalized_decision(review_map.get(index), reviews, index)
            for index in range(1, expected_count + 1)
        ]

    def _parse_reviews(self, response: str | None) -> list[dict[str, Any]] | None:
        if not response:
            return None
        try:
            payload = json.loads(normalize_json_response_text(response))
        except Exception:
            return None

        reviews = payload.get(REVIEWS_KEY) if isinstance(payload, dict) else None
        return reviews if isinstance(reviews, list) else None

    def _review_map(self, reviews: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
        return {
            int(review.get(ID_KEY)): review
            for review in reviews
            if isinstance(review, dict) and isinstance(review.get(ID_KEY), int)
        }

    def _normalized_decision(
        self,
        review: dict[str, Any] | None,
        reviews: list[dict[str, Any]],
        index: int,
    ) -> dict[str, str]:
        fallback = reviews[index - 1] if index - 1 < len(reviews) else None
        choice = review if isinstance(review, dict) else fallback
        if not isinstance(choice, dict):
            return {VERDICT_KEY: UNCERTAIN_VERDICT, REASON_KEY: ""}
        return {
            VERDICT_KEY: str(choice.get(VERDICT_KEY) or UNCERTAIN_VERDICT).upper(),
            REASON_KEY: str(choice.get(REASON_KEY) or ""),
        }
