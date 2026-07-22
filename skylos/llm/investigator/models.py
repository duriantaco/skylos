"""Public types and stable identifiers for Deep Audit investigation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skylos.llm.schemas import Finding


INVESTIGATOR_PROTOCOL_VERSION = "logic-investigator-v2"
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


class InvestigationIncompleteError(RuntimeError):
    """The investigator did not produce an explicit, validated completion."""


@dataclass(frozen=True)
class InvestigationLimits:
    max_turns: int = 8
    max_model_calls: int = 10
    max_findings: int = 5
    max_seconds: float = 180.0
    max_prompt_chars: int = 180_000
    max_initial_source_chars: int = 32_000
    max_context_chars: int = 16_000
    max_candidates: int = 20
    max_invalid_responses: int = 1
    max_repeated_actions: int = 2


@dataclass(frozen=True)
class InvestigationResult:
    findings: list[Finding]
    status: str
    metadata: dict[str, Any]
