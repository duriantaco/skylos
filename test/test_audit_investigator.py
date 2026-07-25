from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from skylos.audit.investigator_tools import (
    AuditReadOnlyTools,
    InvestigationToolLimits,
)
from skylos.audit.types import MAX_AUDIT_SOURCE_BYTES
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.llm.investigator import (
    INVESTIGATION_CATEGORIES,
    INVESTIGATION_CATEGORY_DEFINITIONS,
    INVESTIGATION_CATEGORY_PRECEDENCE,
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
    INVESTIGATOR_SYSTEM_PROMPT,
    MAX_INVESTIGATOR_CANDIDATES,
    InvestigationIncompleteError,
    InvestigationLimits,
    LogicInvestigator,
)
from skylos.llm.investigator.models import (
    InvestigationLimits as ConcreteInvestigationLimits,
)
from skylos.llm.investigator.orchestrator import (
    LogicInvestigator as ConcreteLogicInvestigator,
)


ARGUMENT_KEYS = (
    "path",
    "start_line",
    "end_line",
    "query",
    "path_prefix",
    "name_contains",
)


def test_investigator_package_preserves_public_contract() -> None:
    assert InvestigationLimits is ConcreteInvestigationLimits
    assert LogicInvestigator is ConcreteLogicInvestigator
    assert INVESTIGATOR_PROTOCOL_VERSION == "logic-investigator-v3"
    assert INVESTIGATOR_DEFINITION_HASH == (
        "cbe8cc1d86782dccfbe8a0c8a83577b7bf610f30ef7e5ad2e3a14bcb9ad55a26"
    )


def test_investigator_prompt_defines_security_category_precedence() -> None:
    definitions = dict(INVESTIGATION_CATEGORY_DEFINITIONS)

    assert tuple(definitions) == INVESTIGATION_CATEGORIES
    assert "identity or session" in definitions["authentication_session"]
    assert "observable or durable impact" in definitions["authentication_session"]
    assert "established actor" in definitions["authorization_scope"]
    assert "concurrent operations" in definitions["atomicity"]
    assert "Repeating the same request or event" in definitions["replay_idempotency"]
    assert "crash or downstream failure" in definitions["partial_failure"]
    assert "stable provider idempotency key" in " ".join(
        INVESTIGATION_CATEGORY_PRECEDENCE
    )
    assert "Duplicate transport attempts alone are not" in " ".join(
        INVESTIGATION_CATEGORY_PRECEDENCE
    )
    assert "same concurrency window or partial-failure window" in " ".join(
        INVESTIGATION_CATEGORY_PRECEDENCE
    )
    assert (
        InvestigationLimits().max_turns == InvestigationLimits().max_model_calls == 12
    )
    assert all(
        f"- {category}: {definition}" in INVESTIGATOR_SYSTEM_PROMPT
        for category, definition in INVESTIGATION_CATEGORY_DEFINITIONS
    )
    assert all(
        f"- {guidance}" in INVESTIGATOR_SYSTEM_PROMPT
        for guidance in INVESTIGATION_CATEGORY_PRECEDENCE
    )


def test_investigator_prompt_excludes_unreachable_alternatives_from_proof() -> None:
    assert (
        "Evidence and mitigation_evidence must cite only code or configuration "
        "reachable from the entry behavior" in INVESTIGATOR_SYSTEM_PROMPT
    )
    assert (
        "They may inform counterevidence text only when explicitly labeled "
        "unreachable" in INVESTIGATOR_SYSTEM_PROMPT
    )
    assert (
        "A successfully verified signature proves authenticity and integrity "
        "only for the exact signed payload" in INVESTIGATOR_SYSTEM_PROMPT
    )


def _tool_action(tool: str, **arguments: Any) -> str:
    payload = {
        "action": "tool",
        "tool": tool,
        "arguments": {key: arguments.get(key) for key in ARGUMENT_KEYS},
        "status": None,
        "reasoning": "Inspect the authorization helper before deciding.",
        "findings": [],
        "clean_evidence": [],
        "covered_candidate_ids": [],
    }
    return json.dumps(payload)


def _finish_action(
    *,
    findings: list[dict[str, Any]],
    covered: list[str],
    status: str = "complete",
    clean_evidence: list[dict[str, Any]] | None = None,
) -> str:
    return json.dumps(
        {
            "action": "finish",
            "tool": None,
            "arguments": {key: None for key in ARGUMENT_KEYS},
            "status": status,
            "reasoning": "Relevant authorization behavior was inspected.",
            "findings": findings,
            "clean_evidence": list(clean_evidence or []),
            "covered_candidate_ids": covered,
        }
    )


def _logic_finding() -> dict[str, Any]:
    return {
        "category": "authorization_scope",
        "issue_type": "security",
        "severity": "high",
        "confidence": "high",
        "message": "Order cancellation checks login but not tenant ownership.",
        "primary_file": "routes.py",
        "line": 4,
        "end_line": 5,
        "symbol": "cancel_order",
        "actor": "an authenticated user from another tenant",
        "action": "cancel",
        "resource": "an order owned by a different tenant",
        "trigger": "submit another tenant's order identifier",
        "invariant": "Only a user from the owning tenant may cancel an order.",
        "actual_behavior": "The policy helper accepts any authenticated user.",
        "impact": "Cross-tenant order cancellation is possible.",
        "evidence": [
            {
                "file": "routes.py",
                "line": 4,
                "end_line": 5,
                "role": "state-changing caller",
                "purpose": "entry",
                "causal_pair": None,
            },
            {
                "file": "policy.py",
                "line": 2,
                "end_line": 2,
                "role": "authorization decision without ownership binding",
                "purpose": "mitigation",
                "causal_pair": None,
            },
        ],
        "mitigations_checked": [
            "authorize_order implementation",
            "tenant binding in the entry handler",
        ],
        "mitigation_evidence": [
            {
                "mitigation": "authorize_order implementation",
                "outcome": "insufficient",
                "evidence": [
                    {
                        "file": "policy.py",
                        "line": 2,
                        "end_line": 2,
                        "role": "authorization helper checks login only",
                        "purpose": "mitigation",
                        "causal_pair": None,
                    }
                ],
            },
            {
                "mitigation": "tenant binding in the entry handler",
                "outcome": "absent",
                "evidence": [
                    {
                        "file": "routes.py",
                        "line": 4,
                        "end_line": 5,
                        "role": "entry mutation relies entirely on the helper",
                        "purpose": "mitigation",
                        "causal_pair": None,
                    }
                ],
            },
        ],
        "counterevidence": [],
        "suggestion": "Require order.tenant_id to equal user.tenant_id before mutation.",
    }


def _clean_policy_evidence() -> list[dict[str, Any]]:
    return [
        {
            "invariant": "Only the owning tenant may mutate the order.",
            "candidate_ids": ["candidate-auth"],
            "evidence": [
                {
                    "file": "routes.py",
                    "line": 4,
                    "end_line": 5,
                    "role": "entry mutation is guarded by authorize_order",
                    "purpose": "mitigation",
                    "causal_pair": None,
                },
                {
                    "file": "policy.py",
                    "line": 2,
                    "end_line": 2,
                    "role": "authorization binds order tenant to user tenant",
                    "purpose": "mitigation",
                    "causal_pair": None,
                },
            ],
        },
    ]


class PolicyAwareAdapter:
    def __init__(self) -> None:
        self.calls = 0
        self.prompts: list[str] = []

    def complete(self, system_prompt, user_prompt, response_format=None):
        self.calls += 1
        self.prompts.append(user_prompt)
        if self.calls == 1:
            return _tool_action("find_symbol", query="authorize_order")
        if self.calls == 2:
            return _tool_action(
                "read_file",
                path="policy.py",
                start_line=1,
                end_line=3,
            )
        if "order.tenant_id == user.tenant_id" in user_prompt:
            return _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=_clean_policy_evidence(),
            )
        return _finish_action(
            findings=[_logic_finding()],
            covered=["candidate-auth"],
        )


class SequenceAdapter:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, system_prompt, user_prompt, response_format=None):
        self.prompts.append(user_prompt)
        if not self.responses:
            raise AssertionError("unexpected investigator model call")
        return self.responses.pop(0)


class DiagnosticSequenceAdapter(SequenceAdapter):
    def __init__(
        self,
        responses: list[str],
        diagnostics: list[dict[str, Any]],
    ) -> None:
        super().__init__(responses)
        self.diagnostics = list(diagnostics)
        self.last_completion_diagnostic: dict[str, Any] | None = None

    def complete(self, system_prompt, user_prompt, response_format=None):
        response = super().complete(system_prompt, user_prompt, response_format)
        self.last_completion_diagnostic = self.diagnostics.pop(0)
        return response


def _write_policy_repo(tmp_path: Path, *, safe: bool) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "routes.py").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path helper
        "from policy import authorize_order\n\n"
        "def cancel_order(user, order):\n"
        "    if authorize_order(user, order):\n"
        "        order.status = 'cancelled'\n"
        "    return order\n",
        encoding="utf-8",
    )
    policy = (
        "def authorize_order(user, order):\n"
        "    return user.is_authenticated and order.tenant_id == user.tenant_id\n"
        if safe
        else "def authorize_order(user, order):\n    return user.is_authenticated\n"
    )
    (root / "policy.py").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path helper
        policy,
        encoding="utf-8",
    )
    return root


def test_logic_investigator_caps_public_candidate_limit_to_response_schema(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    investigator = LogicInvestigator(
        SequenceAdapter([]),
        limits=InvestigationLimits(max_candidates=100),
        persist_trace=False,
    )

    assert investigator.limits.max_candidates == MAX_INVESTIGATOR_CANDIDATES
    with pytest.raises(InvestigationIncompleteError, match="coverage budget"):
        investigator.investigate(
            source="def cancel_order():\n    pass\n",
            file_path="routes.py",
            context=None,
            candidates=[
                {"candidate_id": f"candidate-{index}"}
                for index in range(MAX_INVESTIGATOR_CANDIDATES + 1)
            ],
            tools=AuditReadOnlyTools(root),
            run_id="candidate-schema-cap",
        )


@pytest.mark.parametrize(
    ("safe", "expected_findings", "expected_calls"),
    [(False, 1, 4), (True, 0, 3)],
)
def test_investigator_traverses_cross_file_policy_before_verdict(
    tmp_path: Path,
    safe: bool,
    expected_findings: int,
    expected_calls: int,
) -> None:
    root = _write_policy_repo(tmp_path, safe=safe)
    adapter = PolicyAwareAdapter()
    tools = AuditReadOnlyTools(root)
    investigator = LogicInvestigator(adapter, persist_trace=False)
    source = read_project_text_no_symlink(
        root,
        "routes.py",
        max_bytes=MAX_AUDIT_SOURCE_BYTES,
        encoding="utf-8",
    )
    assert source is not None

    result = investigator.investigate(
        source=source,
        file_path="routes.py",
        context=None,
        candidates=[
            {
                "candidate_id": "candidate-auth",
                "kind": "entrypoint",
                "rule_id": "SKY-AUDIT-ENTRYPOINT",
                "reason": "auth boundary",
            }
        ],
        tools=tools,
        run_id=f"cross-file-{'safe' if safe else 'vulnerable'}",
    )

    assert result.status == "complete"
    assert len(result.findings) == expected_findings
    assert adapter.calls == expected_calls
    assert result.metadata["visited_files"] == ["policy.py", "routes.py"]
    assert result.metadata["reviewer_guidance"]["selected_packs"] == [
        {"id": "candidate.entrypoint_invariants", "version": "1.0.0"}
    ]
    assert "policy.py:1" in adapter.prompts[1]
    assert "2:     return user.is_authenticated" in adapter.prompts[2]
    assert '"untrusted_repository_data": true' in adapter.prompts[2]
    assert '"repository_catalog"' in adapter.prompts[0]
    assert '"policy.py"' in adapter.prompts[0]
    if result.findings:
        review = json.loads(adapter.prompts[-1])["trusted_finding_evidence_review"]
        assert review["review_version"] == "finding-evidence-review-v1"
        assert review["draft_findings_are_untrusted"] is True
        assert any(
            "population" in check and "write" in check for check in review["checks"]
        )
        assert any("mitigation_evidence" in check for check in review["checks"])
        assert result.metadata["finding_evidence_review"] == {
            "version": "finding-evidence-review-v1",
            "requested": True,
            "completed": True,
        }
        finding = result.findings[0]
        assert finding.rule_id == "SKY-AUDIT-LOGIC"
        assert finding.location.file == "routes.py"
        evidence = finding.metadata["logic_evidence"]["evidence"]
        assert {item["file"] for item in evidence} == {"routes.py", "policy.py"}
        assert all(len(item["file_hash"]) == 64 for item in evidence)


def test_positive_finding_review_corrects_mitigation_role_without_normalization(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    (root / "pipeline.py").write_text(
        "def dispatch(request, handler):\n    return handler(request)\n",
        encoding="utf-8",
    )
    draft = _logic_finding()
    for check in draft["mitigation_evidence"]:
        check["evidence"] = [
            {
                "file": "pipeline.py",
                "line": 1,
                "end_line": 2,
                "role": "related call path, not the policy implementation",
                "purpose": "mitigation",
                "causal_pair": None,
            }
        ]
    corrected = _logic_finding()
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _tool_action("read_file", path="pipeline.py", start_line=1, end_line=2),
            _finish_action(findings=[draft], covered=["candidate-auth"]),
            _finish_action(findings=[corrected], covered=["candidate-auth"]),
            _finish_action(findings=[corrected], covered=["candidate-auth"]),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="correct-mitigation-role",
    )

    assert "mitigation_citation_unlinked" in adapter.prompts[3]
    review = json.loads(adapter.prompts[4])["trusted_finding_evidence_review"]
    reviewed_draft_mitigation_files = {
        item["file"]
        for check in review["draft_findings"][0]["mitigation_evidence"]
        for item in check["evidence"]
    }
    final_mitigation_files = {
        item["file"]
        for check in result.findings[0].metadata["logic_evidence"][
            "mitigation_evidence"
        ]
        for item in check["evidence"]
    }
    assert "policy.py" in reviewed_draft_mitigation_files
    assert "policy.py" in final_mitigation_files


def test_positive_finding_review_can_read_and_correct_shared_state_range(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    (root / "backend.py").write_text(
        "CACHE = {}\n"
        "def get_or_set(key, factory):\n"
        "    if key in CACHE:\n"
        "        return CACHE[key]\n"
        "    value = factory()\n"
        "    CACHE[key] = value\n"
        "    return value\n",
        encoding="utf-8",
    )
    draft = deepcopy(_logic_finding())
    draft["actual_behavior"] = (
        "The shared cache consumes a tenantless key and can reuse another "
        "tenant's populated value."
    )
    draft["evidence"][1] = {
        "file": "backend.py",
        "line": 2,
        "end_line": 5,
        "role": "cache lookup and factory call before the population write",
        "purpose": "cause",
        "causal_pair": None,
    }
    corrected = deepcopy(draft)
    corrected["evidence"][1]["end_line"] = 7
    corrected["evidence"][1]["role"] = (
        "cache consumption and population paths for the same tenantless key"
    )
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _tool_action("read_file", path="backend.py", start_line=1, end_line=5),
            _finish_action(findings=[draft], covered=["candidate-auth"]),
            _tool_action("read_file", path="backend.py", start_line=6, end_line=7),
            _finish_action(findings=[corrected], covered=["candidate-auth"]),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="correct-shared-state-range",
    )

    review = json.loads(adapter.prompts[3])["trusted_finding_evidence_review"]
    assert review["draft_findings"][0]["evidence"][1]["end_line"] == 5
    final_backend_evidence = next(
        item
        for item in result.findings[0].metadata["logic_evidence"]["evidence"]
        if item["file"] == "backend.py"
    )
    assert final_backend_evidence["end_line"] == 7
    assert result.metadata["tool_calls"] == 3


def test_incomplete_shared_state_pair_gets_trusted_correction(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    (root / "backend.py").write_text(
        "CACHE = {}\n"
        "def get_or_set(key, factory):\n"
        "    if key in CACHE:\n"
        "        return CACHE[key]\n"
        "    value = factory()\n"
        "    CACHE[key] = value\n"
        "    return value\n",
        encoding="utf-8",
    )
    incomplete = deepcopy(_logic_finding())
    incomplete["evidence"].append(
        {
            "file": "backend.py",
            "line": 3,
            "end_line": 4,
            "role": "a prior value is consumed by the tenantless key",
            "purpose": "state_consumption",
            "causal_pair": "tenantless-cache-key",
        }
    )
    corrected = deepcopy(incomplete)
    corrected["evidence"].append(
        {
            "file": "backend.py",
            "line": 5,
            "end_line": 6,
            "role": "the same tenantless key populates the shared cache",
            "purpose": "state_population",
            "causal_pair": "tenantless-cache-key",
        }
    )
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _tool_action("read_file", path="backend.py", start_line=1, end_line=7),
            _finish_action(findings=[incomplete], covered=["candidate-auth"]),
            _finish_action(findings=[corrected], covered=["candidate-auth"]),
            _finish_action(findings=[corrected], covered=["candidate-auth"]),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="correct-causal-pair",
    )

    assert "causal_pair_incomplete" in adapter.prompts[3]
    paired_purposes = {
        item["purpose"]
        for item in result.findings[0].metadata["logic_evidence"]["evidence"]
        if item["causal_pair"] == "tenantless-cache-key"
    }
    assert paired_purposes == {"state_population", "state_consumption"}


def test_positive_finding_review_fails_closed_at_turn_budget(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[_logic_finding()], covered=["candidate-auth"]),
        ]
    )

    with pytest.raises(
        InvestigationIncompleteError,
        match="before required finding evidence review",
    ):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_turns=2, max_model_calls=2),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="finding-review-budget",
        )


def test_malformed_model_output_never_becomes_a_clean_result(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(["not json", "still not json"])

    with pytest.raises(InvestigationIncompleteError, match="malformed JSON"):
        LogicInvestigator(adapter, persist_trace=False).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="malformed",
        )

    assert len(adapter.prompts) == 2


def test_invalid_finish_evidence_gets_one_bounded_correction(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    invalid_evidence = _clean_policy_evidence()
    invalid_evidence[0]["evidence"][1]["line"] = 99
    invalid_evidence[0]["evidence"][1]["end_line"] = 99
    adapter = SequenceAdapter(
        [
            _tool_action(
                "read_file",
                path="policy.py",
                start_line=1,
                end_line=2,
            ),
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=invalid_evidence,
            ),
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=_clean_policy_evidence(),
            ),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="invalid-finish-correction",
    )

    assert result.status == "complete"
    assert len(adapter.prompts) == 3
    assert "finish result failed validation" in adapter.prompts[2]


def test_explicit_incomplete_finish_remains_terminal(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                status="incomplete",
            ),
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=_clean_policy_evidence(),
            ),
        ]
    )

    with pytest.raises(
        InvestigationIncompleteError,
        match="explicitly reported incomplete context",
    ):
        LogicInvestigator(adapter, persist_trace=False).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="explicit-incomplete",
        )

    assert len(adapter.prompts) == 1


def test_missing_candidate_coverage_is_incomplete(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter([_finish_action(findings=[], covered=[])])

    with pytest.raises(InvestigationIncompleteError, match="cover every"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="coverage",
        )


def test_first_turn_clean_verdict_without_repository_inspection_is_incomplete(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter([_finish_action(findings=[], covered=[])])

    with pytest.raises(InvestigationIncompleteError, match="tool inspection"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="no-inspection",
        )


def test_file_listing_alone_cannot_support_a_clean_verdict(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("list_files"),
            _finish_action(findings=[], covered=[]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="source-bearing"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="listing-is-not-evidence",
        )


def test_entry_file_reread_alone_cannot_support_cross_file_clean_verdict(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="routes.py", start_line=1, end_line=2),
            _finish_action(findings=[], covered=[]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="beyond the entry file"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="entry-reread-is-not-context",
        )


def test_clean_verdict_requires_cited_inspected_protection_evidence(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[], covered=[]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="clean_evidence"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="clean-needs-cited-protection",
        )


def test_clean_proof_must_map_each_candidate_to_its_evidence(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    proof = _clean_policy_evidence()
    proof[0]["candidate_ids"] = []
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=proof,
            ),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="map every supplied"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="clean-proof-candidate-map",
        )


def test_uninspected_cross_file_evidence_is_rejected(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    adapter = SequenceAdapter(
        [_finish_action(findings=[_logic_finding()], covered=["candidate-auth"])]
    )

    with pytest.raises(InvestigationIncompleteError, match="not inspected"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="invented-evidence",
        )


def test_logic_mitigation_claim_requires_related_inspected_evidence(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    finding = _logic_finding()
    finding["mitigation_evidence"] = [
        {
            "mitigation": "authorize_order implementation",
            "outcome": "insufficient",
            "evidence": [
                {
                    "file": "routes.py",
                    "line": 4,
                    "end_line": 5,
                    "role": "local caller only",
                    "purpose": "mitigation",
                    "causal_pair": None,
                }
            ],
        },
        {
            "mitigation": "tenant binding in the entry handler",
            "outcome": "absent",
            "evidence": [
                {
                    "file": "routes.py",
                    "line": 4,
                    "end_line": 5,
                    "role": "local caller only",
                    "purpose": "mitigation",
                    "causal_pair": None,
                }
            ],
        },
    ]
    finding["evidence"][1]["purpose"] = "context"
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[finding], covered=["candidate-auth"]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="related-file mitigation"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="mitigation-needs-related-evidence",
        )


def test_every_mitigation_claim_requires_its_own_evidence(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    finding = _logic_finding()
    finding["mitigation_evidence"] = finding["mitigation_evidence"][:1]
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[finding], covered=["candidate-auth"]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="map exactly once"):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_invalid_responses=0),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[{"candidate_id": "candidate-auth"}],
            tools=AuditReadOnlyTools(root),
            run_id="mitigation-claim-map",
        )


def test_denied_tool_request_cannot_be_followed_by_clean_completion(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="/etc/passwd"),
            _finish_action(findings=[], covered=[]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="denied evidence"):
        LogicInvestigator(adapter, persist_trace=False).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="denied-read",
        )

    assert "/etc/passwd" not in adapter.prompts[0]
    assert "tool_denial" in adapter.prompts[1]


def test_turn_budget_without_finish_is_incomplete(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter([_tool_action("list_files")])

    with pytest.raises(
        InvestigationIncompleteError, match="without an explicit finish"
    ):
        LogicInvestigator(
            adapter,
            limits=InvestigationLimits(max_turns=1),
            persist_trace=False,
        ).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="turn-budget",
        )


def test_default_turn_budget_reserves_a_correction_after_repository_reads(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("list_files"),
            _tool_action("find_symbol", query="authorize_order"),
            _tool_action("search_code", query="tenant_id"),
            _tool_action("read_file", path="policy.py", start_line=1, end_line=1),
            _tool_action("read_file", path="policy.py", start_line=2, end_line=2),
            _tool_action("read_file", path="routes.py", start_line=1, end_line=3),
            _tool_action("read_file", path="routes.py", start_line=4, end_line=6),
            "not json",
            _finish_action(
                findings=[],
                covered=["candidate-auth"],
                clean_evidence=_clean_policy_evidence(),
            ),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="finish-correction-turn",
    )

    assert result.status == "complete"
    assert len(adapter.prompts) == 9


def test_truncated_repository_catalog_cannot_finish_clean(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter(
        [
            _tool_action("list_files"),
            _finish_action(findings=[], covered=[]),
        ]
    )
    tools = AuditReadOnlyTools(
        root,
        limits=InvestigationToolLimits(max_catalog_files=1),
    )

    with pytest.raises(InvestigationIncompleteError, match="catalog budget"):
        LogicInvestigator(adapter, persist_trace=False).investigate(
            source=(root / "policy.py").read_text(encoding="utf-8"),
            file_path="policy.py",
            context=None,
            candidates=[],
            tools=tools,
            run_id="truncated-catalog",
        )


def test_result_metadata_does_not_persist_repository_source(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = PolicyAwareAdapter()
    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="metadata",
    )

    serialized = json.dumps(result.metadata, sort_keys=True)
    assert "order.tenant_id" not in serialized
    assert "return user.is_authenticated" not in serialized


def test_result_metadata_preserves_only_bounded_model_call_diagnostics(
    tmp_path: Path,
) -> None:
    root = _write_policy_repo(tmp_path, safe=False)
    adapter = DiagnosticSequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[_logic_finding()], covered=["candidate-auth"]),
            _finish_action(findings=[_logic_finding()], covered=["candidate-auth"]),
        ],
        [
            {
                "finish_reason": "stop",
                "content_chars": 301,
                "completion_tokens": 23,
                "reasoning_tokens": 11,
                "signal": None,
                "raw_content": "must not be persisted",
            },
            {
                "finish_reason": "repository-controlled-finish-reason",
                "content_chars": 902,
                "completion_tokens": 41,
                "reasoning_tokens": 29,
                "signal": None,
                "raw_reasoning": "must not be persisted",
            },
            {
                "finish_reason": "stop",
                "content_chars": 811,
                "completion_tokens": 37,
                "reasoning_tokens": 19,
                "signal": None,
                "raw_content": "must not be persisted either",
            },
        ],
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth"}],
        tools=AuditReadOnlyTools(root),
        run_id="model-call-diagnostics",
    )

    assert result.metadata["model_call_diagnostics"] == [
        {
            "call_index": 1,
            "finish_reason": "stop",
            "content_chars": 301,
            "completion_tokens": 23,
            "reasoning_tokens": 11,
            "signal": None,
        },
        {
            "call_index": 2,
            "finish_reason": None,
            "content_chars": 902,
            "completion_tokens": 41,
            "reasoning_tokens": 29,
            "signal": None,
        },
        {
            "call_index": 3,
            "finish_reason": "stop",
            "content_chars": 811,
            "completion_tokens": 37,
            "reasoning_tokens": 19,
            "signal": None,
        },
    ]
    assert result.metadata["model_call_diagnostics_truncated"] == 0
    serialized = json.dumps(result.metadata, sort_keys=True)
    assert "must not be persisted" not in serialized
    assert "raw_content" not in serialized
    assert "raw_reasoning" not in serialized


@pytest.mark.parametrize(
    ("provider_finish_reason", "response", "content_chars"),
    [
        ("length", "", 0),
        ("length", '{"action":"finish"', 18),
        ("max_tokens", '{"action":"finish"', 18),
        ("MAX_TOKENS", '{"action":"finish"', 18),
        ("max-output-tokens", '{"action":"finish"', 18),
        ("token limit", '{"action":"finish"', 18),
    ],
)
def test_output_budget_completion_fails_without_paid_protocol_retry(
    tmp_path: Path,
    provider_finish_reason: str,
    response: str,
    content_chars: int,
) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = DiagnosticSequenceAdapter(
        [response],
        [
            {
                "finish_reason": provider_finish_reason,
                "content_chars": content_chars,
                "completion_tokens": 4096,
                "reasoning_tokens": 4096,
                "signal": None,
            }
        ],
    )

    with pytest.raises(
        InvestigationIncompleteError,
        match="output-token budget exhausted",
    ) as exc_info:
        LogicInvestigator(adapter, persist_trace=False).investigate(
            source=(root / "routes.py").read_text(encoding="utf-8"),
            file_path="routes.py",
            context=None,
            candidates=[],
            tools=AuditReadOnlyTools(root),
            run_id="output-budget-exhausted",
        )

    assert len(adapter.prompts) == 1
    assert exc_info.value.investigation_metadata["model_call_diagnostics"] == [
        {
            "call_index": 1,
            "finish_reason": "length",
            "content_chars": content_chars,
            "completion_tokens": 4096,
            "reasoning_tokens": 4096,
            "signal": "output_budget_exhausted",
        }
    ]
    assert (
        exc_info.value.investigation_metadata["model_call_diagnostics_truncated"] == 0
    )


def test_repository_investigator_preserves_classic_security_analysis(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    app = root / "app.py"
    app.write_text(
        "def run(user_input):\n    return eval(user_input)\n",
        encoding="utf-8",
    )
    finding = {
        **_logic_finding(),
        "category": "injection",
        "message": "Untrusted input reaches code evaluation.",
        "primary_file": "app.py",
        "line": 2,
        "end_line": 2,
        "symbol": "run",
        "actor": "remote caller",
        "action": "execute supplied Python",
        "resource": "server process",
        "trigger": "send an expression as user_input",
        "invariant": "Untrusted input must never reach a code execution sink.",
        "actual_behavior": "user_input is passed directly to eval.",
        "impact": "Arbitrary code execution in the server process.",
        "evidence": [
            {
                "file": "app.py",
                "line": 2,
                "end_line": 2,
                "role": "untrusted input reaches code execution sink",
                "purpose": "cause",
                "causal_pair": None,
            }
        ],
        "mitigations_checked": ["no parser or allowlist before eval"],
        "mitigation_evidence": [
            {
                "mitigation": "no parser or allowlist before eval",
                "outcome": "absent",
                "evidence": [
                    {
                        "file": "app.py",
                        "line": 2,
                        "end_line": 2,
                        "role": "direct sink call has no parser or allowlist",
                        "purpose": "mitigation",
                        "causal_pair": None,
                    }
                ],
            }
        ],
        "suggestion": "Replace eval with a constrained parser.",
    }
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="app.py", start_line=1, end_line=2),
            _finish_action(findings=[finding], covered=["classic-security"]),
            _finish_action(findings=[finding], covered=["classic-security"]),
        ]
    )

    result = LogicInvestigator(adapter, persist_trace=False).investigate(
        source=app.read_text(encoding="utf-8"),
        file_path="app.py",
        context=None,
        candidates=[{"candidate_id": "classic-security", "rule_id": "SKY-D210"}],
        tools=AuditReadOnlyTools(root),
        run_id="classic-security",
    )

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SKY-AUDIT-SECURITY"
    assert "investigation_evidence" in result.findings[0].metadata
    assert "logic_evidence" not in result.findings[0].metadata
