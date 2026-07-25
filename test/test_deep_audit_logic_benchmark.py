from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from skylos.benchmarks.deep_audit_logic import (
    DEFAULT_BENCHMARK_MAX_TOKENS,
    MAX_BENCHMARK_ENTRY_BYTES,
    MAX_EXPECTED_MANIFEST_BYTES,
    DeepAuditLogicBenchmarkError,
    _aggregate_metrics,
    _case_label,
    _finding_matches_target,
    _production_agent,
    evaluate_case,
    format_summary,
    load_expected,
    run_manifest,
)
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    save_project_json_cache,
)
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


def _minimal_contract(
    *,
    fixture: str = "fixture",
    entry_file: str = "entry.py",
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "cases": [
            {
                "id": "safe-case",
                "label": "safe",
                "fixture": fixture,
                "entry_file": entry_file,
                "candidates": [],
                "expect": {
                    "status": "complete",
                    "finding_count": {"exact": 0},
                },
            }
        ],
    }


def _save_json(root: Path, relative_path: str, payload: dict[str, Any]) -> Path:
    assert save_project_json_cache(root, relative_path, payload)
    return root / relative_path


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
                "purpose": "entry",
                "causal_pair": None,
            },
            {
                "file": "refunds/policy.py",
                "line": 2,
                "end_line": 2,
                "role": "reachable authorization decision omits tenant binding",
                "purpose": "mitigation",
                "causal_pair": None,
            },
            {
                "file": "refunds/service.py",
                "line": 11,
                "end_line": 14,
                "role": "the unauthorized refund state is durably persisted",
                "purpose": "effect",
                "causal_pair": None,
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
                        "purpose": "mitigation",
                        "causal_pair": None,
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
                        "purpose": "mitigation",
                        "causal_pair": None,
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
                    "purpose": "mitigation",
                    "causal_pair": None,
                },
                {
                    "file": "refunds/service.py",
                    "line": 5,
                    "end_line": 6,
                    "role": "service rejects callers denied by the reachable policy",
                    "purpose": "mitigation",
                    "causal_pair": None,
                },
                {
                    "file": "refunds/policy.py",
                    "line": 2,
                    "end_line": 6,
                    "role": "policy requires authentication, support role, and tenant ownership",
                    "purpose": "mitigation",
                    "causal_pair": None,
                },
            ],
        }
    ]


def _evidence(file: str, line: int, end_line: int, role: str) -> dict[str, Any]:
    return {
        "file": file,
        "line": line,
        "end_line": end_line,
        "role": role,
        "purpose": "context",
        "causal_pair": None,
    }


def _finding_for(case_id: str) -> dict[str, Any]:
    definitions: dict[str, dict[str, Any]] = {
        "middleware-order-vulnerable": {
            "category": "authentication_session",
            "issue_type": "security",
            "primary_file": "app.py",
            "line": 7,
            "symbol": "update_account",
            "actor": "an unauthenticated requester",
            "action": "update",
            "resource": "an account email address",
            "trigger": "send an account update through the public handler",
            "invariant": "Authentication must run before the account handler.",
            "actual_behavior": "The reachable pipeline invokes the handler before auth.",
            "impact": "An unauthenticated request can mutate account state.",
            "suggestion": "Authenticate before invoking the account handler.",
            "evidence": [
                _evidence(
                    "app.py",
                    7,
                    16,
                    "entry point delegates to a handler that durably saves the update",
                ),
                _evidence(
                    "middleware/pipeline.py",
                    4,
                    6,
                    "reachable pipeline calls the handler before authentication",
                ),
                _evidence(
                    "models.py",
                    6,
                    19,
                    "an unauthenticated request user still has an account-backed request shape",
                ),
            ],
            "mitigation": _evidence(
                "middleware/auth.py", 1, 3, "authentication exists but runs too late"
            ),
        },
        "webhook-verification-vulnerable": {
            "category": "cryptographic_trust",
            "issue_type": "security",
            "primary_file": "webhook.py",
            "line": 5,
            "symbol": "webhook",
            "actor": "an unauthenticated webhook sender",
            "action": "apply",
            "resource": "an account plan change",
            "trigger": "submit an invalidly signed event body",
            "invariant": "A webhook signature must be verified before side effects.",
            "actual_behavior": "The reachable service applies the event before verification.",
            "impact": "An invalid webhook can change an account plan.",
            "suggestion": "Verify the signature before parsing or applying the event.",
            "evidence": [
                _evidence("webhook.py", 4, 5, "entry point accepts the webhook"),
                _evidence(
                    "processing/service.py",
                    7,
                    11,
                    "event application occurs before the signature rejection",
                ),
                _evidence(
                    "processing/signatures.py",
                    5,
                    8,
                    "signature verification exists but is invoked after the update",
                ),
                _evidence(
                    "processing/store.py",
                    6,
                    26,
                    "the pre-verification event durably updates the account",
                ),
                _evidence(
                    "processing/models.py",
                    4,
                    7,
                    "the event targets a uniquely mapped persistent account",
                ),
            ],
            "mitigation": _evidence(
                "processing/signatures.py",
                5,
                8,
                "signature comparison is implemented but called too late",
            ),
        },
        "tenant-cache-vulnerable": {
            "category": "authorization_scope",
            "issue_type": "security",
            "primary_file": "api.py",
            "line": 7,
            "symbol": "invoice_endpoint",
            "actor": "an authenticated user in another tenant",
            "action": "read",
            "resource": "a cached invoice belonging to another tenant",
            "trigger": "request an invoice ID already cached by a different tenant",
            "invariant": "Tenant-scoped values must use tenant-scoped cache keys.",
            "actual_behavior": "The cache key omits the caller tenant identifier.",
            "impact": "A cache hit can disclose another tenant's invoice.",
            "suggestion": "Include tenant_id in the invoice cache key.",
            "evidence": [
                _evidence(
                    "api.py", 4, 7, "entry point forwards tenant and invoice IDs"
                ),
                _evidence(
                    "invoices/cache.py",
                    5,
                    7,
                    "reachable cache key contains only the invoice ID",
                ),
                _evidence(
                    "invoices/backend.py",
                    8,
                    16,
                    "the shared cache returns values solely by that key",
                ),
                _evidence(
                    "invoices/models.py",
                    4,
                    15,
                    "invoice numbers are unique only within each tenant",
                ),
            ],
            "mitigation": _evidence(
                "invoices/database.py",
                4,
                5,
                "database lookup is tenant scoped but can be bypassed by a cache hit",
            ),
        },
        "payment-idempotency-vulnerable": {
            "category": "replay_idempotency",
            "issue_type": "bug",
            "primary_file": "payment_webhook.py",
            "line": 8,
            "symbol": "payment_webhook",
            "actor": "a payment provider retry or concurrent delivery",
            "action": "capture",
            "resource": "the same payment",
            "trigger": "deliver the same event concurrently before either receipt is stored",
            "invariant": "A payment event must be claimed atomically before capture.",
            "actual_behavior": "The seen check and receipt insert are separate operations.",
            "impact": "Concurrent deliveries can capture the same payment twice.",
            "suggestion": "Use a unique atomic claim before calling the gateway.",
            "evidence": [
                _evidence(
                    "payment_webhook.py", 5, 8, "entry point verifies provider events"
                ),
                _evidence(
                    "payments/service.py",
                    4,
                    9,
                    "capture occurs between a non-atomic check and receipt insert",
                ),
                _evidence(
                    "payments/store.py",
                    4,
                    9,
                    "seen and mark operations are separate database actions",
                ),
                _evidence(
                    "payments/gateway.py",
                    4,
                    5,
                    "each gateway invocation creates a durable capture",
                ),
                _evidence(
                    "payments/models.py",
                    4,
                    10,
                    "event receipts lack a unique event constraint",
                ),
            ],
            "mitigation": _evidence(
                "payments/store.py",
                4,
                9,
                "receipt storage does not expose an atomic claim operation",
            ),
        },
        "payment-claim-first-vulnerable": {
            "category": "partial_failure",
            "issue_type": "bug",
            "primary_file": "payment_webhook.py",
            "line": 8,
            "symbol": "payment_webhook",
            "actor": "a payment provider retry after an interrupted capture",
            "action": "retry",
            "resource": "a claimed but uncaptured payment event",
            "trigger": "the gateway call fails after the event claim is persisted",
            "invariant": "A claimed event must remain retryable until capture completes.",
            "actual_behavior": (
                "A gateway failure leaves the claim behind, so every retry exits as a "
                "duplicate without capturing the payment."
            ),
            "impact": "A transient failure can permanently lose a payment capture.",
            "suggestion": (
                "Track pending/completed state and retry capture with a provider "
                "idempotency key."
            ),
            "evidence": [
                _evidence(
                    "payment_webhook.py", 5, 8, "entry point verifies provider events"
                ),
                _evidence(
                    "payments/service.py",
                    4,
                    8,
                    "claim is persisted before the fallible gateway call",
                ),
                _evidence(
                    "payments/store.py", 4, 6, "claim survives a later gateway failure"
                ),
                _evidence(
                    "payments/gateway.py", 4, 5, "provider capture can fail after claim"
                ),
                _evidence(
                    "payments/models.py",
                    4,
                    10,
                    "the unique event receipt makes the first claim durable",
                ),
            ],
            "mitigation": _evidence(
                "payments/service.py",
                4,
                8,
                "no pending state or retry path exists after the claim",
            ),
        },
    }
    definition = definitions[case_id]
    mitigation = definition.pop("mitigation")
    mitigation["purpose"] = "mitigation"
    mitigation_name = "reachable invariant enforcement"
    return {
        **definition,
        "severity": "high",
        "confidence": "high",
        "message": definition["impact"],
        "end_line": definition["line"],
        "mitigations_checked": [mitigation_name],
        "mitigation_evidence": [
            {
                "mitigation": mitigation_name,
                "outcome": "insufficient",
                "evidence": [mitigation],
            }
        ],
        "counterevidence": [],
    }


def _clean_evidence_for(case_id: str) -> list[dict[str, Any]]:
    definitions: dict[str, tuple[str, list[dict[str, Any]]]] = {
        "middleware-order-safe": (
            "Authentication runs before the account handler.",
            [
                _evidence(
                    "app.py",
                    7,
                    16,
                    "entry point uses the guarded pipeline before the durable save",
                ),
                _evidence(
                    "middleware/pipeline.py",
                    4,
                    6,
                    "reachable pipeline authenticates before handler invocation",
                ),
                _evidence(
                    "middleware/auth.py", 1, 3, "authentication rejects missing users"
                ),
                _evidence(
                    "models.py",
                    6,
                    19,
                    "the handler target is a persistent account owned by the request user",
                ),
            ],
        ),
        "webhook-verification-lookalike": (
            "Webhook signatures are verified before any event side effect.",
            [
                _evidence("webhook.py", 4, 5, "entry point delegates to service"),
                _evidence(
                    "processing/service.py",
                    7,
                    12,
                    "reachable service verifies before parsing or applying the event",
                ),
                _evidence(
                    "processing/signatures.py",
                    5,
                    8,
                    "signature uses constant-time compare",
                ),
                _evidence(
                    "processing/store.py",
                    6,
                    26,
                    "validated provider revisions and server-owned plan mappings are applied under a subscription lock",
                ),
                _evidence(
                    "processing/models.py",
                    4,
                    7,
                    "subscription mapping is unique and accepts an initial version",
                ),
            ],
        ),
        "tenant-cache-safe": (
            "Invoice cache entries are scoped by tenant and invoice ID.",
            [
                _evidence("api.py", 4, 7, "entry point supplies the actor tenant"),
                _evidence(
                    "invoices/service.py", 4, 5, "service preserves both identifiers"
                ),
                _evidence(
                    "invoices/cache.py",
                    5,
                    7,
                    "cache key includes tenant and invoice IDs",
                ),
                _evidence(
                    "invoices/backend.py",
                    8,
                    16,
                    "the shared cache indexes entries by the complete scoped key",
                ),
                _evidence(
                    "invoices/database.py",
                    4,
                    5,
                    "cache misses load with both tenant and local invoice number",
                ),
                _evidence(
                    "invoices/models.py",
                    4,
                    15,
                    "invoice numbers are explicitly tenant-local",
                ),
            ],
        ),
        "payment-idempotency-lookalike": (
            "Each event remains retryable and provider-idempotent until capture completes.",
            [
                _evidence(
                    "payment_webhook.py", 5, 8, "entry point verifies provider events"
                ),
                _evidence(
                    "payments/signatures.py",
                    6,
                    18,
                    "signature binds every event field used by payment processing",
                ),
                _evidence(
                    "payments/service.py",
                    4,
                    9,
                    "pending events retry capture before being marked completed",
                ),
                _evidence(
                    "payments/store.py",
                    4,
                    18,
                    "durable pending and completed states distinguish retry from duplicate",
                ),
                _evidence(
                    "payments/gateway.py",
                    4,
                    11,
                    "unique provider capture rows use the event ID as their idempotency key",
                ),
                _evidence(
                    "payments/models.py",
                    4,
                    13,
                    "unique event and provider idempotency keys make retries converge",
                ),
            ],
        ),
    }
    invariant, evidence = definitions[case_id]
    return [{"invariant": invariant, "candidate_ids": [], "evidence": evidence}]


REPLAY_READS: dict[str, tuple[str, ...]] = {
    "middleware-order-vulnerable": (
        "app.py",
        "middleware/pipeline.py",
        "middleware/auth.py",
        "models.py",
    ),
    "middleware-order-safe": (
        "app.py",
        "middleware/pipeline.py",
        "middleware/auth.py",
        "models.py",
    ),
    "webhook-verification-vulnerable": (
        "webhook.py",
        "processing/service.py",
        "processing/signatures.py",
        "processing/store.py",
        "processing/models.py",
    ),
    "webhook-verification-lookalike": (
        "webhook.py",
        "processing/service.py",
        "processing/signatures.py",
        "processing/store.py",
        "processing/models.py",
    ),
    "tenant-cache-vulnerable": (
        "api.py",
        "invoices/service.py",
        "invoices/cache.py",
        "invoices/backend.py",
        "invoices/database.py",
        "invoices/models.py",
    ),
    "tenant-cache-safe": (
        "api.py",
        "invoices/service.py",
        "invoices/cache.py",
        "invoices/backend.py",
        "invoices/database.py",
        "invoices/models.py",
    ),
    "payment-idempotency-vulnerable": (
        "payment_webhook.py",
        "payments/signatures.py",
        "payments/service.py",
        "payments/store.py",
        "payments/gateway.py",
        "payments/models.py",
    ),
    "payment-claim-first-vulnerable": (
        "payment_webhook.py",
        "payments/signatures.py",
        "payments/service.py",
        "payments/store.py",
        "payments/gateway.py",
        "payments/models.py",
    ),
    "payment-idempotency-lookalike": (
        "payment_webhook.py",
        "payments/signatures.py",
        "payments/service.py",
        "payments/store.py",
        "payments/gateway.py",
        "payments/models.py",
    ),
}


class FixtureReasoningAdapter:
    """Deterministic replay over the same evidence contract as the live benchmark."""

    def __init__(self, case_id: str, label: str) -> None:
        self.case_id = case_id
        self.label = label
        self.calls = 0
        self.last_usage: dict[str, int] = {}

    def complete(self, system_prompt, user_prompt, response_format=None):
        self.calls += 1
        self.last_usage = {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
        }
        if self.case_id.startswith("cross-tenant-refund") and self.calls == 1:
            return _tool_action("find_symbol", query="refund_order")
        if self.case_id.startswith("cross-tenant-refund") and self.calls == 2:
            return _tool_action(
                "read_file",
                path="refunds/service.py",
                start_line=1,
                end_line=20,
            )
        if self.case_id.startswith("cross-tenant-refund") and self.calls == 3:
            return _tool_action(
                "find_symbol",
                query="can_refund",
                path_prefix="refunds",
            )
        if self.case_id.startswith("cross-tenant-refund") and self.calls == 4:
            return _tool_action(
                "read_file",
                path="refunds/policy.py",
                start_line=1,
                end_line=10,
            )
        if self.case_id == "cross-tenant-refund-safe":
            return _finish_action(findings=[], clean_evidence=_safe_evidence())
        if self.case_id == "cross-tenant-refund-vulnerable":
            return _finish_action(findings=[_vulnerable_finding()])

        reads = REPLAY_READS[self.case_id]
        if self.calls <= len(reads):
            return _tool_action(
                "read_file",
                path=reads[self.calls - 1],
                start_line=1,
                end_line=50,
            )
        if self.label == "vulnerable":
            return _finish_action(findings=[_finding_for(self.case_id)])
        return _finish_action(
            findings=[], clean_evidence=_clean_evidence_for(self.case_id)
        )


def _agent_factory(case: dict[str, Any]) -> SecurityAuditAgent:
    agent = SecurityAuditAgent(AgentConfig(model="fixture-replay", stream=False))
    agent._adapter = FixtureReasoningAdapter(case["id"], case["label"])
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


def test_additional_fixture_pairs_keep_decoys_out_of_the_reachable_path() -> None:
    fixture_root = EXPECTED_PATH.parent / "fixtures"
    pairs = (
        (
            fixture_root / "middleware_order/vulnerable",
            fixture_root / "middleware_order/safe",
            "app.py",
            "middleware/pipeline.py",
            "legacy/pipeline.py",
        ),
        (
            fixture_root / "webhook_verification/vulnerable",
            fixture_root / "webhook_verification/lookalike",
            "webhook.py",
            "processing/service.py",
            "archive/service.py",
        ),
        (
            fixture_root / "tenant_cache/vulnerable",
            fixture_root / "tenant_cache/safe",
            "api.py",
            "invoices/cache.py",
            "archive/cache.py",
        ),
    )

    def implementation(path: Path) -> str:
        source = read_project_text_no_symlink(
            fixture_root,
            path,
            max_bytes=MAX_BENCHMARK_ENTRY_BYTES,
            encoding="utf-8",
        )
        assert source is not None
        return "def " + source.split("def ", 1)[1]

    for vulnerable, negative, entry_file, reachable_file, decoy_file in pairs:
        assert (vulnerable / entry_file).read_bytes() == (
            negative / entry_file
        ).read_bytes()
        assert implementation(vulnerable / reachable_file) == implementation(
            negative / decoy_file
        )
        assert implementation(negative / reachable_file) == implementation(
            vulnerable / decoy_file
        )


def test_webhook_fixture_uses_server_owned_plan_mapping_in_both_variants() -> None:
    fixture_root = EXPECTED_PATH.parent / "fixtures/webhook_verification"
    vulnerable_store = fixture_root / "vulnerable/processing/store.py"
    lookalike_store = fixture_root / "lookalike/processing/store.py"

    assert vulnerable_store.read_bytes() == lookalike_store.read_bytes()
    source = lookalike_store.read_text(encoding="utf-8")
    assert 'PLAN_BY_PRICE_ID = {"price_basic": "basic", "price_pro": "pro"}' in source
    assert 'PLAN_BY_PRICE_ID[event["price_id"]]' in source
    assert 'account.plan = event["plan"]' not in source
    assert "type(version) is not int or version < 0" in source


def test_idempotency_fixtures_separate_concurrency_partial_failure_and_retry() -> None:
    fixture_root = EXPECTED_PATH.parent / "fixtures/idempotency"
    vulnerable = fixture_root / "vulnerable"
    claim_first = fixture_root / "claim_first"
    safe = fixture_root / "lookalike"

    assert (vulnerable / "payment_webhook.py").read_bytes() == (
        claim_first / "payment_webhook.py"
    ).read_bytes()
    assert (claim_first / "payment_webhook.py").read_bytes() == (
        safe / "payment_webhook.py"
    ).read_bytes()

    claim_source = (claim_first / "payments/service.py").read_text(encoding="utf-8")
    safe_service = (safe / "payments/service.py").read_text(encoding="utf-8")
    safe_gateway = (safe / "payments/gateway.py").read_text(encoding="utf-8")
    safe_store = (safe / "payments/store.py").read_text(encoding="utf-8")
    assert claim_source.index("claim_once") < claim_source.index("gateway.capture")
    assert safe_service.index("capture_once") < safe_service.index("ensure_pending")
    assert safe_service.index("ensure_pending") < safe_service.index("mark_completed")
    assert 'status="pending"' in safe_store
    assert "== 1" in safe_store
    assert "payment_id=payment_id" in safe_gateway
    assert '"idempotency_key": event_id' in safe_gateway
    assert "not created" in safe_gateway
    safe_models = (safe / "payments/models.py").read_text(encoding="utf-8")
    assert "payment_id = models.CharField(max_length=255, unique=True)" in safe_models
    assert "get_or_create" in (claim_first / "payments/store.py").read_text(
        encoding="utf-8"
    )
    assert "unique=True" in (claim_first / "payments/models.py").read_text(
        encoding="utf-8"
    )


def test_checked_in_logic_contract_passes_deterministic_replay() -> None:
    summary = run_manifest(
        EXPECTED_PATH,
        model="fixture-replay",
        api_key=None,
        provider="fixture",
        reasoning_effort="high",
        agent_factory=_agent_factory,
    )

    assert summary["status"] == "pass", summary
    assert summary["execution_mode"] == "injected_agent"
    assert summary["reasoning_effort"] == "high"
    assert summary["max_tokens"] == DEFAULT_BENCHMARK_MAX_TOKENS
    assert summary["case_count"] == 11
    assert summary["pass_count"] == 11
    assert [case["label"] for case in summary["cases"]].count("vulnerable") == 6
    assert [case["label"] for case in summary["cases"]].count("safe") == 3
    assert [case["label"] for case in summary["cases"]].count("lookalike") == 2
    assert [case["actual"]["finding_count"] for case in summary["cases"]] == [
        1,
        0,
        1,
        0,
        1,
        0,
        1,
        0,
        1,
        1,
        0,
    ]
    assert all("finding_claims" not in case["actual"] for case in summary["cases"])
    assert summary["confusion_matrix"] == {
        "true_positive": 6,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 5,
    }
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["f1"] == 1.0
    assert summary["false_clean_count"] == 0
    assert summary["wrong_target_count"] == 0
    assert summary["incomplete_count"] == 0
    assert summary["abstention_count"] == 0
    assert summary["classified_count"] == 11
    assert summary["usage"] == {
        "llm_calls": 73,
        "prompt_tokens": 730,
        "completion_tokens": 365,
        "total_tokens": 1095,
        "cases_with_usage": 11,
    }
    assert "reasoning_effort=high" in format_summary(summary)
    assert "max_tokens=4096" in format_summary(summary)


def test_manifest_model_prose_requires_explicit_opt_in() -> None:
    summary = run_manifest(
        EXPECTED_PATH,
        model="fixture-replay",
        api_key=None,
        provider="fixture",
        selected_cases={"cross-tenant-refund-vulnerable"},
        agent_factory=_agent_factory,
        include_model_prose=True,
    )

    claims = summary["cases"][0]["actual"]["finding_claims"]
    assert claims[0]["invariant"].startswith("Only support agents")


def test_manifest_default_error_does_not_reflect_exception_text() -> None:
    class RaisingAgent:
        def investigate(self, *args, **kwargs):
            raise RuntimeError("PROPRIETARY SOURCE LINE sk-secretsecret")

    summary = run_manifest(
        EXPECTED_PATH,
        model="fixture-replay",
        api_key=None,
        provider="fixture",
        selected_cases={"cross-tenant-refund-safe"},
        agent_factory=lambda _case: RaisingAgent(),
    )

    actual = summary["cases"][0]["actual"]
    assert actual["error"] == "benchmark case execution failed"
    assert "PROPRIETARY" not in json.dumps(summary)


def test_production_agent_configures_reasoning_effort(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class FakeSecurityAuditAgent:
        def __init__(self, config: AgentConfig) -> None:
            captured["config"] = config

    monkeypatch.setattr(
        "skylos.benchmarks.deep_audit_logic.SecurityAuditAgent",
        FakeSecurityAuditAgent,
    )

    agent = _production_agent(
        model="gpt-5.4",
        api_key="KEY",
        provider="openai",
        base_url=None,
        reasoning_effort="high",
        max_tokens=16_384,
    )

    assert isinstance(agent, FakeSecurityAuditAgent)
    config = captured["config"]
    assert isinstance(config, AgentConfig)
    assert config.model == "gpt-5.4"
    assert config.reasoning_effort == "high"
    assert config.max_tokens == 16_384


def test_benchmark_script_accepts_and_forwards_high_reasoning(
    monkeypatch,
) -> None:
    import scripts.deep_audit_logic_benchmark as benchmark_script

    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        benchmark_script,
        "resolve_llm_runtime",
        lambda **_kwargs: ("openai", "KEY", None, False),
    )

    def fake_run_manifest(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"status": "pass"}

    monkeypatch.setattr(benchmark_script, "run_manifest", fake_run_manifest)
    monkeypatch.setattr(
        "sys.argv",
        [
            "deep_audit_logic_benchmark.py",
            "--model",
            "gpt-5.4",
            "--reasoning-effort",
            "high",
            "--max-tokens",
            "16384",
            "--json",
        ],
    )

    assert benchmark_script.main() == 0
    assert captured["kwargs"]["reasoning_effort"] == "high"
    assert captured["kwargs"]["max_tokens"] == 16_384


def test_classification_metrics_distinguish_false_clean_from_incomplete() -> None:
    def result(label: str, status: str, findings: int) -> dict[str, Any]:
        return {
            "label": label,
            "actual": {
                "status": status,
                "finding_count": findings,
                "llm_calls": 1,
                "total_tokens": 3,
            },
        }

    metrics = _aggregate_metrics(
        [
            result("vulnerable", "complete", 1),
            result("vulnerable", "complete", 0),
            result("vulnerable", "error", 1),
            result("safe", "complete", 1),
            result("lookalike", "complete", 0),
            result("safe", "error", 0),
        ]
    )

    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 2,
        "true_negative": 1,
    }
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1 / 3
    assert metrics["f1"] == 0.4
    assert metrics["false_clean_count"] == 1
    assert metrics["wrong_target_count"] == 0
    assert metrics["incomplete_count"] == 2
    assert metrics["abstention_count"] == 1
    assert metrics["classified_count"] == 5


def test_classification_requires_one_finding_to_match_the_expected_target() -> None:
    expected = {
        "required_rule_ids": ["SKY-AUDIT-LOGIC"],
        "required_categories": ["authorization_scope"],
        "required_symbols": ["refund_endpoint"],
        "required_primary_files": ["api.py"],
        "required_evidence_files": ["api.py", "refunds/policy.py"],
        "forbidden_evidence_files": ["archive/policy.py"],
    }
    matching_target = {
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": ["authorization_scope"],
        "symbols": ["refund_endpoint"],
        "primary_files": ["api.py"],
        "evidence_files": ["api.py", "refunds/policy.py"],
    }
    split_wrong_targets = [
        {
            **matching_target,
            "categories": ["state_transition"],
        },
        {
            **matching_target,
            "rule_ids": ["SKY-AUDIT-SECURITY"],
        },
    ]
    metrics = _aggregate_metrics(
        [
            {
                "label": "vulnerable",
                "expected": expected,
                # Operational contract failures must not turn a detected target
                # into a false negative.
                "passed": False,
                "failures": ["tool_calls expected at least 3, found 2"],
                "actual": {
                    "status": "complete",
                    "finding_count": 1,
                    "finding_targets": [matching_target],
                },
            },
            {
                "label": "vulnerable",
                "expected": expected,
                "actual": {
                    "status": "complete",
                    "finding_count": 2,
                    # Aggregate sets contain every required value, but neither
                    # individual finding proves the benchmark's target flaw.
                    "finding_targets": split_wrong_targets,
                },
            },
        ]
    )

    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 2,
        "false_negative": 1,
        "true_negative": 0,
    }
    assert metrics["precision"] == 1 / 3
    assert metrics["recall"] == 0.5
    assert metrics["wrong_target_count"] == 1
    assert metrics["false_clean_count"] == 0


def test_case_contract_rejects_required_values_split_across_findings() -> None:
    expected = {
        "status": "complete",
        "finding_count": {"min": 1, "max": 2},
        "required_rule_ids": ["SKY-AUDIT-LOGIC"],
        "required_categories": ["authorization_scope"],
    }
    actual = {
        "status": "complete",
        "finding_count": 2,
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": ["authorization_scope"],
        "finding_targets": [
            {
                "rule_ids": ["SKY-AUDIT-LOGIC"],
                "categories": ["state_transition"],
            },
            {
                "rule_ids": ["SKY-AUDIT-SECURITY"],
                "categories": ["authorization_scope"],
            },
        ],
    }

    assert evaluate_case(actual, expected) == [
        "no individual finding satisfied the complete expected target contract"
    ]


def test_any_category_contract_accepts_semantic_alternatives_on_one_finding() -> None:
    expected = {
        "status": "complete",
        "finding_count": {"min": 1},
        "required_rule_ids": ["SKY-AUDIT-LOGIC"],
        "required_any_categories": ["atomicity", "replay_idempotency"],
        "required_symbols": ["payment_webhook"],
    }
    target = {
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": ["atomicity"],
        "symbols": ["payment_webhook"],
    }
    actual = {
        "status": "complete",
        "finding_count": 1,
        **target,
        "finding_targets": [target],
    }

    assert _finding_matches_target(target, expected)
    assert evaluate_case(actual, expected) == []


def test_any_category_contract_rejects_unrelated_or_split_targets() -> None:
    expected = {
        "status": "complete",
        "finding_count": {"min": 1, "max": 2},
        "required_rule_ids": ["SKY-AUDIT-LOGIC"],
        "required_any_categories": ["atomicity", "replay_idempotency"],
        "required_symbols": ["payment_webhook"],
    }
    unrelated = {
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": ["value_integrity"],
        "symbols": ["payment_webhook"],
    }
    split = {
        "status": "complete",
        "finding_count": 2,
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": ["atomicity", "value_integrity"],
        "symbols": ["payment_webhook", "other_symbol"],
        "finding_targets": [
            {
                "rule_ids": ["SKY-AUDIT-LOGIC"],
                "categories": ["atomicity"],
                "symbols": ["other_symbol"],
            },
            unrelated,
        ],
    }

    assert not _finding_matches_target(unrelated, expected)
    assert evaluate_case(split, expected) == [
        "no individual finding satisfied the complete expected target contract"
    ]


def test_forbidden_mitigation_decoy_fails_case_and_target_contract() -> None:
    expected = {
        "status": "complete",
        "finding_count": {"min": 1},
        "required_categories": ["authorization_scope"],
        "forbidden_mitigation_evidence_files": ["archive/cache.py"],
    }
    target = {
        "categories": ["authorization_scope"],
        "mitigation_evidence_files": ["archive/cache.py"],
    }
    actual = {
        "status": "complete",
        "finding_count": 1,
        "categories": ["authorization_scope"],
        "mitigation_evidence_files": ["archive/cache.py"],
        "finding_targets": [target],
    }

    failures = evaluate_case(actual, expected)

    assert any(
        "mitigation_evidence_files contains forbidden" in item for item in failures
    )
    assert (
        "no individual finding satisfied the complete expected target contract"
        in failures
    )


def test_schema_v1_cases_without_labels_keep_their_legacy_meaning() -> None:
    assert (
        _case_label({"expect": {"finding_count": {"min": 1, "max": 2}}}) == "vulnerable"
    )
    assert _case_label({"expect": {"finding_count": {"exact": 0}}}) == "safe"
    assert (
        _case_label(
            {
                "label": "lookalike",
                "expect": {"finding_count": {"exact": 0}},
            }
        )
        == "lookalike"
    )


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


def test_expected_manifest_may_live_at_a_caller_selected_location(
    tmp_path: Path,
) -> None:
    manifest_root = tmp_path / "caller-selected" / "benchmark-contract"
    manifest_root.mkdir(parents=True)
    _save_json(manifest_root, "fixture/entry.py", {"source": "pass"})
    manifest_path = _save_json(
        manifest_root,
        "custom-name.json",
        _minimal_contract(),
    )

    contract = load_expected(manifest_path)

    assert contract["expected_path"] == str(manifest_path.resolve())


@pytest.mark.parametrize("values", [[], ["atomicity", "atomicity"], [""]])
def test_expected_manifest_rejects_invalid_any_category_contract(
    tmp_path: Path,
    values: list[str],
) -> None:
    _save_json(tmp_path, "fixture/entry.py", {"source": "pass"})
    contract = _minimal_contract()
    contract["cases"][0]["expect"]["required_any_categories"] = values
    manifest_path = _save_json(tmp_path, "expected.json", contract)

    with pytest.raises(DeepAuditLogicBenchmarkError, match="required_any_categories"):
        load_expected(manifest_path)


def test_expected_manifest_rejects_symlink_and_oversize_input(tmp_path: Path) -> None:
    _save_json(tmp_path, "fixture/entry.py", {"source": "pass"})
    real_manifest = _save_json(tmp_path, "real.json", _minimal_contract())
    linked_manifest = tmp_path / "linked.json"
    linked_manifest.symlink_to(real_manifest.name)

    with pytest.raises(DeepAuditLogicBenchmarkError, match="non-symlink"):
        load_expected(linked_manifest)

    oversized = _minimal_contract()
    oversized["padding"] = "x" * MAX_EXPECTED_MANIFEST_BYTES
    oversized_manifest = _save_json(tmp_path, "oversized.json", oversized)

    with pytest.raises(DeepAuditLogicBenchmarkError, match="bounded"):
        load_expected(oversized_manifest)


@pytest.mark.parametrize("fixture_kind", ["parent-traversal", "absolute"])
def test_expected_manifest_rejects_fixture_escape(
    tmp_path: Path,
    fixture_kind: str,
) -> None:
    manifest_root = tmp_path / "contract"
    manifest_root.mkdir()
    escaped_root = tmp_path / "escaped-fixture"
    escaped_root.mkdir()
    _save_json(escaped_root, "entry.py", {"source": "pass"})
    fixture = (
        "../escaped-fixture"
        if fixture_kind == "parent-traversal"
        else str(escaped_root)
    )
    manifest_path = _save_json(
        manifest_root,
        "expected.json",
        _minimal_contract(fixture=fixture),
    )

    with pytest.raises(DeepAuditLogicBenchmarkError, match="fixture.*stay inside"):
        load_expected(manifest_path)


def test_expected_manifest_rejects_symlinked_fixture(tmp_path: Path) -> None:
    _save_json(tmp_path, "real-fixture/entry.py", {"source": "pass"})
    linked_fixture = tmp_path / "linked-fixture"
    linked_fixture.symlink_to(tmp_path / "real-fixture", target_is_directory=True)
    manifest_path = _save_json(
        tmp_path,
        "expected.json",
        _minimal_contract(fixture="linked-fixture"),
    )

    with pytest.raises(DeepAuditLogicBenchmarkError, match="unsafe"):
        load_expected(manifest_path)


@pytest.mark.parametrize("entry_kind", ["parent-traversal", "absolute"])
def test_expected_manifest_rejects_entry_escape(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    _save_json(tmp_path, "fixture/allowed.py", {"source": "pass"})
    escaped_entry = _save_json(tmp_path, "escaped.py", {"source": "pass"})
    entry_file = (
        "../escaped.py" if entry_kind == "parent-traversal" else str(escaped_entry)
    )
    manifest_path = _save_json(
        tmp_path,
        "expected.json",
        _minimal_contract(entry_file=entry_file),
    )

    with pytest.raises(DeepAuditLogicBenchmarkError, match="entry_file.*stay inside"):
        load_expected(manifest_path)


def test_expected_manifest_rejects_symlinked_and_oversized_entries(
    tmp_path: Path,
) -> None:
    real_entry = _save_json(tmp_path, "fixture/real.py", {"source": "pass"})
    linked_entry = tmp_path / "fixture/linked.py"
    linked_entry.symlink_to(real_entry.name)
    linked_manifest = _save_json(
        tmp_path,
        "linked-entry.json",
        _minimal_contract(entry_file="linked.py"),
    )

    with pytest.raises(DeepAuditLogicBenchmarkError, match="unsafe"):
        load_expected(linked_manifest)

    _save_json(
        tmp_path,
        "oversized/entry.py",
        {"source": "x" * MAX_BENCHMARK_ENTRY_BYTES},
    )
    oversized_manifest = _save_json(
        tmp_path,
        "oversized-entry.json",
        _minimal_contract(fixture="oversized"),
    )

    with pytest.raises(DeepAuditLogicBenchmarkError, match="oversized"):
        load_expected(oversized_manifest)


def test_run_manifest_rejects_unknown_selected_case() -> None:
    with pytest.raises(
        DeepAuditLogicBenchmarkError,
        match="unknown deep-audit logic benchmark case IDs: missing-case",
    ):
        run_manifest(
            EXPECTED_PATH,
            model="deterministic-test",
            api_key=None,
            selected_cases={"missing-case"},
            agent_factory=lambda _case: None,
        )
