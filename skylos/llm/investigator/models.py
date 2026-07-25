"""Public types and stable identifiers for Deep Audit investigation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skylos.llm.schemas import Finding


INVESTIGATOR_PROTOCOL_VERSION = "logic-investigator-v3"
MAX_INVESTIGATOR_CANDIDATES = 20
LOGIC_RULE_ID = "SKY-AUDIT-LOGIC"
SECURITY_RULE_ID = "SKY-AUDIT-SECURITY"

LOGIC_CATEGORIES = (
    "authorization_scope",
    "state_transition",
    "value_integrity",
    "atomicity",
    "replay_idempotency",
    "partial_failure",
    "business_invariant",
)

SECURITY_CATEGORIES = (
    "injection",
    "cross_site_scripting",
    "request_forgery",
    "path_file_access",
    "unsafe_deserialization",
    "authentication_session",
    "cryptographic_trust",
    "sensitive_data_exposure",
    "denial_of_service",
    "configuration_supply_chain",
    "other_security",
)

INVESTIGATION_CATEGORIES = (*LOGIC_CATEGORIES, *SECURITY_CATEGORIES)

_CATEGORY_DEFINITIONS = {
    "authorization_scope": (
        "An authenticated or otherwise established actor can access or mutate a "
        "resource outside its owner, tenant, role, or delegated scope."
    ),
    "state_transition": (
        "A reachable operation permits an invalid lifecycle transition, bypasses "
        "a required state precondition, or leaves durable state in a forbidden "
        "state."
    ),
    "value_integrity": (
        "An untrusted, stale, or tampered value is accepted instead of a trusted "
        "server-authoritative value and changes a durable or externally visible "
        "outcome."
    ),
    "atomicity": (
        "A race, check-then-act sequence, or transaction boundary lets concurrent "
        "operations violate one logical state update."
    ),
    "replay_idempotency": (
        "Repeating the same request or event can repeat an externally visible "
        "effect because stable deduplication or idempotency is missing or late."
    ),
    "partial_failure": (
        "A crash or downstream failure between ordered steps can leave durable "
        "state and external effects inconsistent, including lost work."
    ),
    "business_invariant": (
        "A reachable domain operation violates a concrete business relationship, "
        "limit, or conservation rule and produces an observable or durable outcome "
        "not covered by a more specific logic category."
    ),
    "injection": (
        "Attacker-controlled data reaches an interpreter or command, query, code, "
        "template, header, or protocol sink as executable structure without a "
        "context-correct defense."
    ),
    "cross_site_scripting": (
        "Attacker-controlled browser content is rendered into an executable HTML, "
        "script, URL, CSS, or DOM context without context-correct encoding or "
        "sanitization."
    ),
    "request_forgery": (
        "An attacker can induce a trusted browser or server to send a security-"
        "sensitive request across a trust boundary without effective origin, CSRF, "
        "destination, or network-target controls."
    ),
    "path_file_access": (
        "Attacker-controlled path or file metadata can escape the intended root, "
        "follow an unsafe link, overwrite an unintended file, or access a forbidden "
        "filesystem object."
    ),
    "unsafe_deserialization": (
        "Untrusted serialized data is decoded by a mechanism that can instantiate "
        "unsafe types, execute behavior, or violate integrity without an effective "
        "type or format boundary."
    ),
    "authentication_session": (
        "The actor's identity or session is absent, invalid, or weakly established "
        "and a reachable protected action produces an observable or durable impact, "
        "or valid enforcement occurs only after that impact. A late check without "
        "such an effect is not a finding."
    ),
    "cryptographic_trust": (
        "A reachable authenticity, integrity, confidentiality, or freshness decision "
        "relies on missing, broken, misordered, or context-inappropriate "
        "cryptographic verification."
    ),
    "sensitive_data_exposure": (
        "A reachable response, log, store, cache, error, or transfer reveals "
        "sensitive data to an actor or system outside its intended trust boundary."
    ),
    "denial_of_service": (
        "Attacker-controlled work can consume disproportionate CPU, memory, storage, "
        "connections, or downstream capacity and cause a concrete availability "
        "impact."
    ),
    "configuration_supply_chain": (
        "Active configuration, dependency, build, update, or deployment behavior "
        "allows untrusted influence to weaken a security boundary or execute "
        "untrusted artifacts."
    ),
    "other_security": (
        "A proven, reachable security-boundary violation with concrete impact that "
        "does not fit any more specific security category."
    ),
}

INVESTIGATION_CATEGORY_DEFINITIONS = tuple(
    (category, _CATEGORY_DEFINITIONS[category]) for category in INVESTIGATION_CATEGORIES
)

INVESTIGATION_CATEGORY_PRECEDENCE = (
    "Use authentication_session when identity or session enforcement itself is "
    "missing, invalid, or occurs after a reachable protected action with an "
    "observable or durable impact; use "
    "authorization_scope only when an established actor exceeds a resource or "
    "role boundary.",
    "Use replay_idempotency when the concrete trigger is repeating the same "
    "request or event, atomicity when concurrency or transaction interleaving is "
    "the trigger, and partial_failure when a crash or fallible downstream step "
    "creates inconsistent state or lost work.",
    "Choose the category that matches the proven trigger and direct invariant. "
    "Report overlapping categories separately only when each has its own "
    "reachable trigger and impact.",
    "A repeated effect that is only the consequence of the same concurrency "
    "window or partial-failure window belongs to that direct trigger rather "
    "than to a separate replay_idempotency finding.",
    "Duplicate transport attempts alone are not a replay_idempotency finding "
    "when a stable provider idempotency key guarantees convergence on one "
    "observable effect. This does not eliminate partial_failure: report it when "
    "a failure can leave durable local state inconsistent with a completed "
    "external effect and retry or recovery cannot safely reconcile that same "
    "effect.",
    "Durable state remaining temporarily pending after a crash does not by "
    "itself establish partial_failure when the inspected retry path reuses a "
    "stable provider idempotency key, safely recovers the same side effect, and "
    "then converges the durable state. A partial_failure finding requires "
    "recovery to be absent, unsafe, or leave a concrete invariant violation.",
)


class InvestigationIncompleteError(RuntimeError):
    """The investigator did not produce an explicit, validated completion."""


@dataclass(frozen=True)
class InvestigationLimits:
    max_turns: int = 12
    max_model_calls: int = 12
    max_findings: int = 5
    max_seconds: float = 180.0
    max_prompt_chars: int = 180_000
    max_initial_source_chars: int = 32_000
    max_context_chars: int = 16_000
    max_candidates: int = MAX_INVESTIGATOR_CANDIDATES
    max_invalid_responses: int = 1
    max_repeated_actions: int = 2


@dataclass(frozen=True)
class InvestigationResult:
    findings: list[Finding]
    status: str
    metadata: dict[str, Any]
