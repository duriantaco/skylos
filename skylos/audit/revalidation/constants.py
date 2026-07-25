"""Constants shared by Deep Audit revalidation components."""

from __future__ import annotations

from skylos.llm.investigator.protocol import EVIDENCE_PURPOSES


VALID_VERDICTS = frozenset(
    {"true_positive", "false_positive", "fixed", "uncertain"}
)
SUPPRESSING_VERDICTS = frozenset({"false_positive", "fixed"})
SECURITY_AUDIT_ISSUE = "security_audit"
MAX_REVALIDATION_SOURCE_BYTES = 1_000_000
MAX_REFUTING_INVARIANT_CHARS = 2_000
LEGACY_EVIDENCE_FIELDS = frozenset(
    {"file", "line", "end_line", "role", "file_hash"}
)
INVESTIGATOR_EVIDENCE_FIELDS = frozenset(
    {
        "file",
        "line",
        "end_line",
        "role",
        "purpose",
        "causal_pair",
        "file_hash",
    }
)
STATE_EVIDENCE_PURPOSES = frozenset(
    {"state_population", "state_consumption"}
)
VALID_EVIDENCE_PURPOSES = frozenset(EVIDENCE_PURPOSES)
REVALIDATION_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_deep_audit_revalidation",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["verdict", "reason", "evidence", "invariant"],
            "properties": {
                "verdict": {"type": "string", "enum": sorted(VALID_VERDICTS)},
                "reason": {"type": "string"},
                "invariant": {
                    "anyOf": [
                        {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_REFUTING_INVARIANT_CHARS,
                        },
                        {"type": "null"},
                    ]
                },
                "evidence": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 12,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["file", "line", "end_line", "role"],
                        "properties": {
                            "file": {"type": "string"},
                            "line": {"type": "integer", "minimum": 1},
                            "end_line": {"type": "integer", "minimum": 1},
                            "role": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}
