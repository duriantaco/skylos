"""Repository-aware security and business-logic investigation."""

from .models import (
    INVESTIGATION_CATEGORIES,
    INVESTIGATOR_PROTOCOL_VERSION,
    LOGIC_CATEGORIES,
    LOGIC_RULE_ID,
    SECURITY_CATEGORIES,
    SECURITY_RULE_ID,
    InvestigationIncompleteError,
    InvestigationLimits,
    InvestigationResult,
)
from .orchestrator import LogicInvestigator
from .protocol import (
    CLEAN_PROOF_SCHEMA,
    EVIDENCE_SCHEMA,
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_SYSTEM_PROMPT,
    INVESTIGATOR_TURN_FORMAT,
    INVESTIGATOR_TURN_SCHEMA,
    LOGIC_FINDING_SCHEMA,
    MITIGATION_CHECK_SCHEMA,
    TOOL_ARGUMENTS_SCHEMA,
)

__all__ = [
    "CLEAN_PROOF_SCHEMA",
    "EVIDENCE_SCHEMA",
    "INVESTIGATION_CATEGORIES",
    "INVESTIGATOR_DEFINITION_HASH",
    "INVESTIGATOR_PROTOCOL_VERSION",
    "INVESTIGATOR_SYSTEM_PROMPT",
    "INVESTIGATOR_TURN_FORMAT",
    "INVESTIGATOR_TURN_SCHEMA",
    "InvestigationIncompleteError",
    "InvestigationLimits",
    "InvestigationResult",
    "LOGIC_CATEGORIES",
    "LOGIC_FINDING_SCHEMA",
    "LOGIC_RULE_ID",
    "LogicInvestigator",
    "MITIGATION_CHECK_SCHEMA",
    "SECURITY_CATEGORIES",
    "SECURITY_RULE_ID",
    "TOOL_ARGUMENTS_SCHEMA",
]
