from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4

from skylos.audit.investigator_tools import AuditReadOnlyTools, AuditToolError
from skylos.audit.redaction import sanitize_for_audit
from skylos.llm.harness import HarnessBudgetExceeded
from skylos.llm.harness.guards import (
    enforce_findings_budget,
    enforce_llm_call_budget,
)
from skylos.llm.completion_diagnostics import OUTPUT_BUDGET_SIGNAL
from skylos.llm.schemas import Finding

from .actions import action_fingerprint, parse_action, validate_candidate_coverage
from .adapter import (
    MAX_MODEL_CALL_DIAGNOSTICS,
    complete_with_remaining_budget,
    read_adapter_completion_diagnostic,
    record_adapter_usage,
)
from .evidence import validate_clean_proofs
from .findings import build_findings
from .models import (
    INVESTIGATOR_PROTOCOL_VERSION,
    MAX_INVESTIGATOR_CANDIDATES,
    InvestigationIncompleteError,
    InvestigationLimits,
    InvestigationResult,
)
from .prompts import build_user_prompt, visible_entry_line_count
from .protocol import (
    FINDING_EVIDENCE_REVIEW_CHECKS,
    FINDING_EVIDENCE_REVIEW_INSTRUCTION,
    FINDING_EVIDENCE_REVIEW_VERSION,
    INVESTIGATOR_DEFINITION_HASH,
)
from .repository_tools import execute_tool, new_runner, safe_tool_failure_reason
from .reviewer_packs import (
    reviewer_guidance_metadata,
    select_trusted_reviewer_guidance,
)


_RETRYABLE_EVIDENCE_ERROR_PREFIXES = (
    "evidence file was not inspected by the investigator",
    "evidence file is empty",
    "evidence range is outside",
    "evidence range was not exposed to the investigator",
)
_TERMINAL_FINISH_REASONS = {
    "investigator explicitly reported incomplete context",
    "investigator cannot complete after a denied evidence request",
}
_TRUSTED_FINISH_CORRECTIONS = (
    (
        "finding mitigation citation is not linked to mitigation evidence",
        "mitigation_citation_unlinked: repeat every purpose=mitigation citation "
        "with the exact same file and range under its matching mitigation_evidence",
    ),
    (
        "shared-state evidence requires a causal pair",
        "causal_pair_missing: give each shared-state citation a short causal_pair",
    ),
    (
        "shared-state causal pair requires population and consumption evidence",
        "causal_pair_incomplete: cite both purpose=state_population and "
        "purpose=state_consumption with the same causal_pair",
    ),
)


class LogicInvestigator:
    def __init__(
        self,
        adapter: Any,
        *,
        limits: InvestigationLimits | None = None,
        persist_trace: bool = True,
    ) -> None:
        self.adapter = adapter
        configured_limits = limits or InvestigationLimits()
        self.limits = (
            replace(
                configured_limits,
                max_candidates=MAX_INVESTIGATOR_CANDIDATES,
            )
            if configured_limits.max_candidates > MAX_INVESTIGATOR_CANDIDATES
            else configured_limits
        )
        self.persist_trace = persist_trace

    def investigate(
        self,
        *,
        source: str,
        file_path: str,
        context: str | None,
        candidates: list[dict[str, Any]],
        tools: AuditReadOnlyTools,
        run_id: str | None = None,
    ) -> InvestigationResult:
        if len(candidates) > self.limits.max_candidates:
            raise InvestigationIncompleteError(
                "candidate batch exceeds investigator coverage budget"
            )
        entry_file = tools.register_initial_file(
            file_path,
            visible_end_line=visible_entry_line_count(
                source,
                self.limits.max_initial_source_chars,
            ),
        )
        candidate_ids = _candidate_ids(candidates)
        catalog = tools.catalog_preview()
        trusted_reviewer_guidance = select_trusted_reviewer_guidance(
            entry_file=entry_file,
            source=source,
            candidates=candidates,
            catalog_paths=catalog.get("files", ()),
            max_source_chars=self.limits.max_initial_source_chars,
        )
        run_id = run_id or f"logic-{uuid4().hex[:12]}"
        session = _InvestigationSession(
            adapter=self.adapter,
            limits=self.limits,
            source=source,
            context=context,
            candidates=candidates,
            tools=tools,
            entry_file=entry_file,
            candidate_ids=candidate_ids,
            trusted_reviewer_guidance=trusted_reviewer_guidance,
            runner=new_runner(
                tools=tools,
                run_id=run_id,
                limits=self.limits,
                persist_trace=self.persist_trace,
            ),
            started=time.monotonic(),
        )
        try:
            return session.run()
        except Exception as exc:
            wrapped = session.finish_failure(exc)
            if wrapped is not None:
                raise wrapped from None
            raise


@dataclass
class _InvestigationSession:
    adapter: Any
    limits: InvestigationLimits
    source: str
    context: str | None
    candidates: list[dict[str, Any]]
    tools: AuditReadOnlyTools
    entry_file: str
    candidate_ids: tuple[str, ...]
    trusted_reviewer_guidance: dict[str, Any]
    runner: Any
    started: float
    observations: list[dict[str, Any]] = field(default_factory=list)
    action_counts: dict[str, int] = field(default_factory=dict)
    invalid_responses: int = 0
    llm_calls: int = 0
    final_findings: list[Finding] | None = None
    final_clean_evidence: list[dict[str, Any]] = field(default_factory=list)
    final_reasoning: str = ""
    model_call_diagnostics: list[dict[str, Any]] = field(default_factory=list)
    model_call_diagnostics_truncated: int = 0
    pending_finding_evidence_review: dict[str, Any] | None = None
    finding_evidence_review_requested: bool = False
    finding_evidence_review_completed: bool = False

    def run(self) -> InvestigationResult:
        for turn in range(1, self.limits.max_turns + 1):
            if self._run_turn(turn):
                return self._complete_result()
        if self.pending_finding_evidence_review is not None:
            raise InvestigationIncompleteError(
                "investigator turn budget ended before required finding evidence review"
            )
        raise InvestigationIncompleteError(
            "investigator turn budget ended without an explicit finish"
        )

    def _run_turn(self, turn: int) -> bool:
        user_prompt = self._build_turn_prompt(turn)
        with self.runner.step(
            f"investigator_turn_{turn}",
            input_summary={
                "turn": turn,
                "observation_count": len(self.observations),
                "prompt_chars": len(user_prompt),
            },
        ) as step:
            response = self._request_model(user_prompt)
            action = self._parse_model_action(response, step)
            if action is None:
                return False
            if action["action"] == "tool":
                self._record_tool_action(action, step)
                return False
            try:
                return self._record_finish_action(action, step)
            except (AuditToolError, InvestigationIncompleteError) as exc:
                if not self._retry_invalid_finish(exc, step):
                    raise
                return False

    def _build_turn_prompt(self, turn: int) -> str:
        self.runner.enforce_budget()
        self._enforce_elapsed_budget()
        user_prompt = build_user_prompt(
            entry_file=self.entry_file,
            source=self.source,
            context=self.context,
            candidates=self.candidates,
            observations=self.observations,
            tools=self.tools,
            turn=turn,
            limits=self.limits,
            trusted_reviewer_guidance=self.trusted_reviewer_guidance,
            trusted_finding_evidence_review=self.pending_finding_evidence_review,
        )
        if len(user_prompt) > self.limits.max_prompt_chars:
            raise InvestigationIncompleteError(
                "investigator prompt-size budget exhausted"
            )
        return user_prompt

    def _request_model(self, user_prompt: str) -> Any:
        enforce_llm_call_budget(self.llm_calls + 1, self.runner.run.budget)
        try:
            response = complete_with_remaining_budget(
                self.adapter,
                user_prompt,
                started=self.started,
                limits=self.limits,
            )
        except Exception:
            raise InvestigationIncompleteError(
                "investigator adapter call failed"
            ) from None
        self.llm_calls += 1
        self.runner.update_usage(llm_calls=1)
        record_adapter_usage(self.adapter, self.runner)
        self._record_adapter_completion_diagnostic()
        self._enforce_elapsed_budget()
        return response

    def _parse_model_action(self, response: Any, step: Any) -> dict[str, Any] | None:
        if (
            self.model_call_diagnostics
            and self.model_call_diagnostics[-1].get("signal") == OUTPUT_BUDGET_SIGNAL
        ):
            raise InvestigationIncompleteError(
                "investigator output-token budget exhausted before a complete response"
            )
        try:
            return parse_action(response)
        except InvestigationIncompleteError as exc:
            self.invalid_responses += 1
            if self.invalid_responses > self.limits.max_invalid_responses:
                raise
            self.observations.append(
                {
                    "ok": False,
                    "kind": "protocol_error",
                    "error": str(exc),
                }
            )
            step.set_output_summary(
                action="invalid_response",
                invalid_responses=self.invalid_responses,
            )
            return None

    def _record_adapter_completion_diagnostic(self) -> None:
        diagnostic = read_adapter_completion_diagnostic(
            self.adapter,
            call_index=self.llm_calls,
        )
        if diagnostic is None:
            return
        if len(self.model_call_diagnostics) >= MAX_MODEL_CALL_DIAGNOSTICS:
            self.model_call_diagnostics.pop(0)
            self.model_call_diagnostics_truncated += 1
        self.model_call_diagnostics.append(diagnostic)

    def _record_tool_action(self, action: dict[str, Any], step: Any) -> None:
        fingerprint = action_fingerprint(action)
        repeated_actions = self.action_counts.get(fingerprint, 0) + 1
        self.action_counts[fingerprint] = repeated_actions
        if repeated_actions > self.limits.max_repeated_actions:
            raise InvestigationIncompleteError(
                "investigator repeated an identical tool action"
            )
        observation = execute_tool(
            runner=self.runner,
            tools=self.tools,
            action=action,
        )
        self.observations.append(observation)
        step.set_output_summary(
            action="tool",
            tool=action["tool"],
            ok=observation.get("ok", False),
        )

    def _record_finish_action(self, action: dict[str, Any], step: Any) -> bool:
        findings, clean_evidence = self._validate_finish_action(action)
        enforce_findings_budget(findings, self.runner.run.budget)
        if findings and not self.finding_evidence_review_requested:
            self.finding_evidence_review_requested = True
            self.pending_finding_evidence_review = _finding_evidence_review(action)
            step.set_output_summary(
                action="finding_evidence_review_requested",
                findings=len(findings),
                covered_candidates=len(action["covered_candidate_ids"]),
            )
            return False
        self.finding_evidence_review_completed = self.finding_evidence_review_requested
        self.pending_finding_evidence_review = None
        self.final_findings = findings
        self.final_clean_evidence = clean_evidence
        self.final_reasoning = action["reasoning"]
        step.set_output_summary(
            action="finish",
            findings=len(findings),
            covered_candidates=len(action["covered_candidate_ids"]),
        )
        return True

    def _retry_invalid_finish(self, exc: Exception, step: Any) -> bool:
        if not _is_retryable_finish_error(exc):
            return False
        self.invalid_responses += 1
        if self.invalid_responses > self.limits.max_invalid_responses:
            return False
        self.observations.append(
            {
                "ok": False,
                "kind": "protocol_error",
                "error": _trusted_finish_correction(exc),
            }
        )
        step.set_output_summary(
            action="invalid_finish",
            invalid_responses=self.invalid_responses,
        )
        return True

    def _validate_finish_action(
        self,
        action: dict[str, Any],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        if action["status"] != "complete":
            raise InvestigationIncompleteError(
                "investigator explicitly reported incomplete context"
            )
        self._reject_completion_after_tool_denial()
        validate_candidate_coverage(action["covered_candidate_ids"], self.candidate_ids)
        if not action["findings"] and self.tools.tool_calls == 0:
            raise InvestigationIncompleteError(
                "clean completion requires repository tool inspection"
            )
        findings = build_findings(
            action["findings"],
            entry_file=self.entry_file,
            tools=self.tools,
        )
        self.tools.assert_completion_safe()
        clean_evidence = []
        if not findings:
            clean_evidence = self._validate_clean_completion(action)
        return findings, clean_evidence

    def _reject_completion_after_tool_denial(self) -> None:
        denied = any(
            observation.get("kind") == "tool_denial"
            for observation in self.observations
        )
        if denied:
            raise InvestigationIncompleteError(
                "investigator cannot complete after a denied evidence request"
            )

    def _validate_clean_completion(
        self,
        action: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if self.tools.source_observation_calls == 0:
            raise InvestigationIncompleteError(
                "clean completion requires a source-bearing repository inspection"
            )
        if (
            self.tools.catalog_size > 1
            and not self.tools.has_related_source_observation
        ):
            raise InvestigationIncompleteError(
                "clean completion requires inspecting source beyond the entry file"
            )
        clean_evidence = validate_clean_proofs(
            action["clean_evidence"],
            expected_candidate_ids=self.candidate_ids,
            tools=self.tools,
        )
        self._validate_clean_evidence_files(clean_evidence)
        return clean_evidence

    def _validate_clean_evidence_files(
        self,
        clean_evidence: list[dict[str, Any]],
    ) -> None:
        source_evidence = [
            item for proof in clean_evidence for item in proof["evidence"]
        ]
        if not any(item["file"] == self.entry_file for item in source_evidence):
            raise InvestigationIncompleteError(
                "clean evidence must cover the entry file"
            )
        related_source_is_missing = self.tools.catalog_size > 1 and not any(
            item["file"] != self.entry_file for item in source_evidence
        )
        if related_source_is_missing:
            raise InvestigationIncompleteError(
                "clean evidence must cover inspected related source"
            )

    def _enforce_elapsed_budget(self) -> None:
        if time.monotonic() - self.started > self.limits.max_seconds:
            raise InvestigationIncompleteError(
                "investigator elapsed-time budget exhausted"
            )

    def _complete_result(self) -> InvestigationResult:
        self.runner.finish(status="completed")
        findings = self.final_findings if self.final_findings is not None else []
        metadata = self._completion_metadata()
        for finding in findings:
            finding.metadata.setdefault("investigator", metadata)
        return InvestigationResult(
            findings=findings,
            status="complete",
            metadata=sanitize_for_audit(metadata),
        )

    def _completion_metadata(self) -> dict[str, Any]:
        return {
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "run_id": self.runner.run.run_id,
            "turns": len(self.runner.run.steps),
            "llm_calls": self.llm_calls,
            "usage": dict(self.runner.run.usage),
            "model_call_diagnostics": list(self.model_call_diagnostics),
            "model_call_diagnostics_truncated": (self.model_call_diagnostics_truncated),
            "finish_reasoning_sha256": _text_sha256(self.final_reasoning),
            "finish_reasoning_chars": len(self.final_reasoning),
            "covered_candidate_ids": list(self.candidate_ids),
            "clean_evidence": self.final_clean_evidence,
            "reviewer_guidance": reviewer_guidance_metadata(
                self.trusted_reviewer_guidance
            ),
            "finding_evidence_review": self._finding_evidence_review_metadata(),
            **self.tools.metadata(),
        }

    def finish_failure(self, exc: Exception) -> InvestigationIncompleteError | None:
        self.runner.finish(status="failed", error=type(exc).__name__)
        failure_metadata = sanitize_for_audit(self._failure_metadata())
        if isinstance(exc, InvestigationIncompleteError):
            exc.investigation_metadata = failure_metadata
            return None
        if isinstance(exc, HarnessBudgetExceeded):
            wrapped = InvestigationIncompleteError(
                "investigator orchestration budget exhausted"
            )
            wrapped.investigation_metadata = failure_metadata
            return wrapped
        if isinstance(exc, AuditToolError):
            wrapped = InvestigationIncompleteError(safe_tool_failure_reason(exc))
            wrapped.investigation_metadata = failure_metadata
            return wrapped
        return None

    def _failure_metadata(self) -> dict[str, Any]:
        return {
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "run_id": self.runner.run.run_id,
            "turns": len(self.runner.run.steps),
            "llm_calls": self.llm_calls,
            "usage": dict(self.runner.run.usage),
            "model_call_diagnostics": list(self.model_call_diagnostics),
            "model_call_diagnostics_truncated": (self.model_call_diagnostics_truncated),
            "reviewer_guidance": reviewer_guidance_metadata(
                self.trusted_reviewer_guidance
            ),
            "finding_evidence_review": self._finding_evidence_review_metadata(),
            **self.tools.metadata(),
        }

    def _finding_evidence_review_metadata(self) -> dict[str, Any]:
        return {
            "version": FINDING_EVIDENCE_REVIEW_VERSION,
            "requested": self.finding_evidence_review_requested,
            "completed": self.finding_evidence_review_completed,
        }


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _finding_evidence_review(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_version": FINDING_EVIDENCE_REVIEW_VERSION,
        "instruction": FINDING_EVIDENCE_REVIEW_INSTRUCTION,
        "checks": list(FINDING_EVIDENCE_REVIEW_CHECKS),
        "draft_findings_are_untrusted": True,
        "draft_findings": sanitize_for_audit(action["findings"]),
        "draft_covered_candidate_ids": sanitize_for_audit(
            action["covered_candidate_ids"]
        ),
    }


def _is_retryable_finish_error(exc: Exception) -> bool:
    message = str(exc)
    if isinstance(exc, AuditToolError):
        return type(exc) is AuditToolError and message.startswith(
            _RETRYABLE_EVIDENCE_ERROR_PREFIXES
        )
    return (
        isinstance(exc, InvestigationIncompleteError)
        and message not in _TERMINAL_FINISH_REASONS
    )


def _trusted_finish_correction(exc: Exception) -> str:
    message = str(exc)
    for expected, correction in _TRUSTED_FINISH_CORRECTIONS:
        if message == expected:
            return f"finish result failed validation; {correction}"
    return (
        "finish result failed validation; correct it using only the protocol "
        "schema and inspected evidence"
    )


def _candidate_ids(candidates: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(
        str(candidate.get("candidate_id"))
        for candidate in candidates
        if candidate.get("candidate_id")
    )
