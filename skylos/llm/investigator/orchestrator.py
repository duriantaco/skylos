"""State-machine orchestration for repository-aware Deep Audit."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from skylos.audit.investigator_tools import AuditReadOnlyTools, AuditToolError
from skylos.audit.redaction import sanitize_for_audit
from skylos.llm.harness import HarnessBudgetExceeded
from skylos.llm.harness.guards import (
    enforce_findings_budget,
    enforce_llm_call_budget,
)
from skylos.llm.schemas import Finding

from .actions import action_fingerprint, parse_action, validate_candidate_coverage
from .adapter import complete_with_remaining_budget, record_adapter_usage
from .evidence import validate_clean_proofs
from .findings import build_findings
from .models import (
    INVESTIGATOR_PROTOCOL_VERSION,
    InvestigationIncompleteError,
    InvestigationLimits,
    InvestigationResult,
)
from .prompts import build_user_prompt, visible_entry_line_count
from .protocol import INVESTIGATOR_DEFINITION_HASH
from .repository_tools import execute_tool, new_runner, safe_tool_failure_reason


class LogicInvestigator:
    def __init__(
        self,
        adapter: Any,
        *,
        limits: InvestigationLimits | None = None,
        persist_trace: bool = True,
    ) -> None:
        self.adapter = adapter
        self.limits = limits or InvestigationLimits()
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
    runner: Any
    started: float
    observations: list[dict[str, Any]] = field(default_factory=list)
    action_counts: dict[str, int] = field(default_factory=dict)
    invalid_responses: int = 0
    llm_calls: int = 0
    final_findings: list[Finding] | None = None
    final_clean_evidence: list[dict[str, Any]] = field(default_factory=list)
    final_reasoning: str = ""

    def run(self) -> InvestigationResult:
        for turn in range(1, self.limits.max_turns + 1):
            if self._run_turn(turn):
                return self._complete_result()
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
            self._record_finish_action(action, step)
        return True

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
        self._enforce_elapsed_budget()
        return response

    def _parse_model_action(self, response: Any, step: Any) -> dict[str, Any] | None:
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

    def _record_finish_action(self, action: dict[str, Any], step: Any) -> None:
        findings, clean_evidence = self._validate_finish_action(action)
        enforce_findings_budget(findings, self.runner.run.budget)
        self.final_findings = findings
        self.final_clean_evidence = clean_evidence
        self.final_reasoning = action["reasoning"]
        step.set_output_summary(
            action="finish",
            findings=len(findings),
            covered_candidates=len(action["covered_candidate_ids"]),
        )

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
            "finish_reasoning_sha256": _text_sha256(self.final_reasoning),
            "finish_reasoning_chars": len(self.final_reasoning),
            "covered_candidate_ids": list(self.candidate_ids),
            "clean_evidence": self.final_clean_evidence,
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
            **self.tools.metadata(),
        }


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate_ids(candidates: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(
        str(candidate.get("candidate_id"))
        for candidate in candidates
        if candidate.get("candidate_id")
    )
