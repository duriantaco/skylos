from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skylos.benchmarks.deep_audit_logic import evaluate_case, run_manifest
from skylos.llm.agents import AgentConfig, SecurityAuditAgent


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = REPO_ROOT / "benchmarks/deep_audit_logic/expected.json"
FIXTURE_ROOT = EXPECTED_PATH.parent / "fixtures/cross_tenant_refund"
ARGUMENT_KEYS = (
    "path",
    "start_line",
    "end_line",
    "query",
    "path_prefix",
    "name_contains",
)


def _tool_action(tool: str, **arguments: Any) -> str:
    return json.dumps(
        {
            "action": "tool",
            "tool": tool,
            "arguments": {key: arguments.get(key) for key in ARGUMENT_KEYS},
            "status": None,
            "reasoning": "Follow the reachable refund policy before deciding.",
            "findings": [],
            "clean_evidence": [],
            "covered_candidate_ids": [],
        }
    )


def _finish_action(
    *,
    findings: list[dict[str, Any]],
    clean_evidence: list[dict[str, Any]] | None = None,
) -> str:
    return json.dumps(
        {
            "action": "finish",
            "tool": None,
            "arguments": {key: None for key in ARGUMENT_KEYS},
            "status": "complete",
            "reasoning": "The reachable refund service and policy were inspected.",
            "findings": findings,
            "clean_evidence": list(clean_evidence or []),
            "covered_candidate_ids": [],
        }
    )


def _vulnerable_finding() -> dict[str, Any]:
    return {
        "category": "authorization_scope",
        "issue_type": "security",
        "severity": "high",
        "confidence": "high",
        "message": "A support agent can refund an order owned by another tenant.",
        "primary_file": "api.py",
        "line": 7,
        "end_line": 7,
        "symbol": "refund_endpoint",
        "actor": "an authenticated support agent from another tenant",
        "action": "refund",
        "resource": "an order owned by a different tenant",
        "trigger": "submit that order and its captured amount",
        "invariant": "Only support agents in the owning tenant may refund an order.",
        "actual_behavior": (
            "The reachable policy checks authentication and role but not tenant ownership."
        ),
        "impact": "A support agent can perform a cross-tenant refund.",
        "evidence": [
            {
                "file": "api.py",
                "line": 5,
                "end_line": 7,
                "role": "entry point passes the caller-selected order to refund service",
            },
            {
                "file": "refunds/policy.py",
                "line": 2,
                "end_line": 2,
                "role": "reachable authorization decision omits tenant binding",
            },
        ],
        "mitigations_checked": [
            "reachable refund authorization policy",
            "refund state and amount checks",
        ],
        "mitigation_evidence": [
            {
                "mitigation": "reachable refund authorization policy",
                "outcome": "insufficient",
                "evidence": [
                    {
                        "file": "refunds/policy.py",
                        "line": 2,
                        "end_line": 2,
                        "role": "authentication and role are checked without tenant ownership",
                    }
                ],
            },
            {
                "mitigation": "refund state and amount checks",
                "outcome": "not_applicable",
                "evidence": [
                    {
                        "file": "refunds/service.py",
                        "line": 7,
                        "end_line": 10,
                        "role": "state and amount checks do not establish order ownership",
                    }
                ],
            },
        ],
        "counterevidence": [
            "The service constrains order state and amount, but neither binds the actor tenant."
        ],
        "suggestion": "Require actor.tenant_id to equal order.tenant_id in the policy.",
    }


def _safe_evidence() -> list[dict[str, Any]]:
    return [
        {
            "invariant": "Only support agents in the owning tenant may refund an order.",
            "candidate_ids": [],
            "evidence": [
                {
                    "file": "api.py",
                    "line": 5,
                    "end_line": 7,
                    "role": "entry point delegates the refund to the guarded service",
                },
                {
                    "file": "refunds/service.py",
                    "line": 5,
                    "end_line": 6,
                    "role": "service rejects callers denied by the reachable policy",
                },
                {
                    "file": "refunds/policy.py",
                    "line": 2,
                    "end_line": 6,
                    "role": "policy requires authentication, support role, and tenant ownership",
                },
            ],
        }
    ]


class FixtureReasoningAdapter:
    """Deterministic replay over the same evidence contract as the live benchmark."""

    def __init__(self) -> None:
        self.calls = 0
        self.last_usage: dict[str, int] = {}

    def complete(self, system_prompt, user_prompt, response_format=None):
        self.calls += 1
        self.last_usage = {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
        }
        if self.calls == 1:
            return _tool_action("find_symbol", query="refund_order")
        if self.calls == 2:
            return _tool_action(
                "read_file",
                path="refunds/service.py",
                start_line=1,
                end_line=20,
            )
        if self.calls == 3:
            return _tool_action(
                "find_symbol",
                query="can_refund",
                path_prefix="refunds",
            )
        if self.calls == 4:
            return _tool_action(
                "read_file",
                path="refunds/policy.py",
                start_line=1,
                end_line=10,
            )
        if "actor.tenant_id == order.tenant_id" in user_prompt:
            return _finish_action(findings=[], clean_evidence=_safe_evidence())
        return _finish_action(findings=[_vulnerable_finding()])


def _agent_factory(_case: dict[str, Any]) -> SecurityAuditAgent:
    agent = SecurityAuditAgent(AgentConfig(model="fixture-replay", stream=False))
    agent._adapter = FixtureReasoningAdapter()
    return agent


def test_fixture_keeps_callers_identical_and_swaps_only_reachable_policy() -> None:
    vulnerable = FIXTURE_ROOT / "vulnerable"
    safe = FIXTURE_ROOT / "safe"

    assert (vulnerable / "api.py").read_bytes() == (safe / "api.py").read_bytes()
    assert (vulnerable / "refunds/service.py").read_bytes() == (
        safe / "refunds/service.py"
    ).read_bytes()
    assert (vulnerable / "refunds/policy.py").read_bytes() == (
        safe / "archive/policy.py"
    ).read_bytes()
    assert (safe / "refunds/policy.py").read_bytes() == (
        vulnerable / "archive/policy.py"
    ).read_bytes()


def test_checked_in_logic_contract_passes_deterministic_replay() -> None:
    summary = run_manifest(
        EXPECTED_PATH,
        model="fixture-replay",
        api_key=None,
        provider="fixture",
        agent_factory=_agent_factory,
    )

    assert summary["status"] == "pass", summary
    assert summary["execution_mode"] == "injected_agent"
    assert summary["pass_count"] == 2
    assert [case["actual"]["finding_count"] for case in summary["cases"]] == [1, 0]
    assert all(case["actual"]["tool_calls"] == 4 for case in summary["cases"])
    assert all(case["actual"]["total_tokens"] == 75 for case in summary["cases"])


def test_expected_contract_rejects_decoy_policy_as_clean_evidence() -> None:
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))["cases"][1][
        "expect"
    ]
    actual = {
        "status": "complete",
        "finding_count": 0,
        "tool_calls": 4,
        "llm_calls": 5,
        "visited_files": [
            "api.py",
            "refunds/service.py",
            "refunds/policy.py",
            "archive/policy.py",
        ],
        "clean_evidence_files": [
            "api.py",
            "refunds/service.py",
            "archive/policy.py",
        ],
    }

    failures = evaluate_case(actual, expected)

    assert any("refunds/policy.py" in failure for failure in failures)
    assert any("archive/policy.py" in failure for failure in failures)
