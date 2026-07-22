from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from skylos.audit.investigator_tools import (
    AuditReadOnlyTools,
    InvestigationToolLimits,
)
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
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
    assert INVESTIGATOR_PROTOCOL_VERSION == "logic-investigator-v2"
    assert INVESTIGATOR_DEFINITION_HASH == (
        "b5602d0501fadd54aaf5d5a5c13ba2c26aea0dd5eba2fd83d8426d47a4d48327"
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
            },
            {
                "file": "policy.py",
                "line": 2,
                "end_line": 2,
                "role": "authorization decision without ownership binding",
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
                },
                {
                    "file": "policy.py",
                    "line": 2,
                    "end_line": 2,
                    "role": "authorization binds order tenant to user tenant",
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


@pytest.mark.parametrize(("safe", "expected_findings"), [(False, 1), (True, 0)])
def test_investigator_traverses_cross_file_policy_before_verdict(
    tmp_path: Path,
    safe: bool,
    expected_findings: int,
) -> None:
    root = _write_policy_repo(tmp_path, safe=safe)
    adapter = PolicyAwareAdapter()
    tools = AuditReadOnlyTools(root)
    investigator = LogicInvestigator(adapter, persist_trace=False)

    result = investigator.investigate(
        source=(root / "routes.py").read_text(encoding="utf-8"),
        file_path="routes.py",
        context=None,
        candidates=[{"candidate_id": "candidate-auth", "reason": "auth boundary"}],
        tools=tools,
        run_id=f"cross-file-{'safe' if safe else 'vulnerable'}",
    )

    assert result.status == "complete"
    assert len(result.findings) == expected_findings
    assert adapter.calls == 3
    assert result.metadata["visited_files"] == ["policy.py", "routes.py"]
    assert "policy.py:1" in adapter.prompts[1]
    assert "2:     return user.is_authenticated" in adapter.prompts[2]
    assert '"untrusted_repository_data": true' in adapter.prompts[2]
    assert '"repository_catalog"' in adapter.prompts[0]
    assert '"policy.py"' in adapter.prompts[0]
    if result.findings:
        finding = result.findings[0]
        assert finding.rule_id == "SKY-AUDIT-LOGIC"
        assert finding.location.file == "routes.py"
        evidence = finding.metadata["logic_evidence"]["evidence"]
        assert {item["file"] for item in evidence} == {"routes.py", "policy.py"}
        assert all(len(item["file_hash"]) == 64 for item in evidence)


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


def test_missing_candidate_coverage_is_incomplete(tmp_path: Path) -> None:
    root = _write_policy_repo(tmp_path, safe=True)
    adapter = SequenceAdapter([_finish_action(findings=[], covered=[])])

    with pytest.raises(InvestigationIncompleteError, match="cover every"):
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
                }
            ],
        },
    ]
    adapter = SequenceAdapter(
        [
            _tool_action("read_file", path="policy.py", start_line=1, end_line=2),
            _finish_action(findings=[finding], covered=["candidate-auth"]),
        ]
    )

    with pytest.raises(InvestigationIncompleteError, match="related-file mitigation"):
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
        LogicInvestigator(adapter, persist_trace=False).investigate(
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
