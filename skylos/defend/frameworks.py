from __future__ import annotations

from typing import Any


FRAMEWORK_EVIDENCE_DISCLAIMER = (
    "These mappings indicate static evidence toward the referenced controls. "
    "They are not a compliance determination, certification, or legal advice."
)

FRAMEWORK_LABELS: dict[str, str] = {
    "eu_ai_act": "EU AI Act (Regulation (EU) 2024/1689)",
    "nist_ai_rmf": "NIST AI Risk Management Framework 1.0",
    "iso_42001": "ISO/IEC 42001:2023",
}

# plugin_id -> framework_key -> [{control_id, control_name, contribution}]
#
# Mapping rules (deliberate, keep on edits):
# - "evidence toward" semantics only. a passing check is never a compliance claim.
# - EU AI Act Art. 10 (training data governance) is out of scope for static
#   runtime-code checks  ... do not map it.
# - NIST AI RMF is mapped at trustworthiness characteristic level, not numbered subcat.
# - ISO/IEC 42001 is mapped as named Annex A control themes, not clause ids.
PLUGIN_FRAMEWORK_EVIDENCE: dict[str, dict[str, list[dict[str, str]]]] = {
    "no-dangerous-sink": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15",
                "control_name": "Accuracy, robustness and cybersecurity",
                "contribution": (
                    "No eval/exec/subprocess sink in the LLM output scope is "
                    "evidence toward resilience against output-manipulation "
                    "attacks."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Absence of dangerous execution sinks for model output is "
                    "evidence toward secure output handling."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Model output is not routed to code-execution sinks, "
                    "evidence toward AI system security controls."
                ),
            }
        ],
    },
    "tool-scope": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15",
                "control_name": "Accuracy, robustness and cybersecurity",
                "contribution": (
                    "Agent tools avoiding dangerous calls is evidence toward "
                    "constrained action scope under adversarial input."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Tool implementations free of dangerous calls are evidence "
                    "toward least-privilege agent tooling."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Constrained agent tool scope is evidence toward AI system "
                    "security controls."
                ),
            }
        ],
    },
    "tool-schema-present": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15",
                "control_name": "Accuracy, robustness and cybersecurity",
                "contribution": (
                    "Typed tool schemas are evidence toward validated, "
                    "predictable agent-tool invocation."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Typed tool schemas are evidence toward input validation at "
                    "the agent-tool boundary."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Schema-validated tool arguments are evidence toward AI "
                    "system security controls."
                ),
            }
        ],
    },
    "prompt-delimiter": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15(5)",
                "control_name": "Resilience against AI-specific attacks",
                "contribution": (
                    "Delimiting untrusted input in prompts is evidence toward "
                    "input-manipulation (prompt injection) resilience."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Prompt delimiters around untrusted input are evidence "
                    "toward injection-boundary controls."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Prompt boundary controls are evidence toward AI system "
                    "security controls."
                ),
            }
        ],
    },
    "untrusted-input-to-prompt": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15(5)",
                "control_name": "Resilience against AI-specific attacks",
                "contribution": (
                    "Guarding the untrusted-input-to-prompt path is evidence "
                    "toward input-manipulation (prompt injection) resilience."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Controls on untrusted input reaching prompts are evidence "
                    "toward injection-boundary controls."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Untrusted-input handling before prompt assembly is "
                    "evidence toward AI system security controls."
                ),
            }
        ],
    },
    "rag-context-isolation": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15(5)",
                "control_name": "Resilience against AI-specific attacks",
                "contribution": (
                    "Isolating retrieved context from instructions is evidence "
                    "toward indirect prompt-injection resilience."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "RAG context isolation is evidence toward injection-boundary "
                    "controls for retrieved content."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Separation of retrieved context from instructions is "
                    "evidence toward AI system security controls."
                ),
            }
        ],
    },
    "output-validation": {
        "eu_ai_act": [
            {
                "control_id": "Art. 15",
                "control_name": "Accuracy, robustness and cybersecurity",
                "contribution": (
                    "Validating model output before use is evidence toward "
                    "output robustness controls."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Valid and Reliable",
                "control_name": "Trustworthiness characteristic: Valid and Reliable",
                "contribution": (
                    "Output validation before downstream use is evidence toward "
                    "reliable system behavior."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system security",
                "control_name": "Security controls for AI systems",
                "contribution": (
                    "Validation of model output is evidence toward AI system "
                    "security controls."
                ),
            }
        ],
    },
    "input-length-limit": {
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Input length limits are evidence toward resource-exhaustion "
                    "and payload-abuse resilience."
                ),
            }
        ],
    },
    "output-pii-filter": {
        "nist_ai_rmf": [
            {
                "control_id": "Privacy-Enhanced",
                "control_name": "Trustworthiness characteristic: Privacy-Enhanced",
                "contribution": (
                    "PII filtering on model output is evidence toward "
                    "privacy-enhancing output controls."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — Data protection in AI systems",
                "control_name": "Data protection controls",
                "contribution": (
                    "Output PII filtering is evidence toward data-protection "
                    "controls in AI system output."
                ),
            }
        ],
    },
    "model-pinned": {
        "nist_ai_rmf": [
            {
                "control_id": "Valid and Reliable",
                "control_name": "Trustworthiness characteristic: Valid and Reliable",
                "contribution": (
                    "Pinned model versions are evidence toward controlled, "
                    "reproducible model configuration."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system change management",
                "control_name": "Change management for AI systems",
                "contribution": (
                    "Pinned model identifiers are evidence toward change-managed "
                    "model configuration."
                ),
            }
        ],
    },
    "logging-present": {
        "eu_ai_act": [
            {
                "control_id": "Art. 12",
                "control_name": "Record-keeping",
                "contribution": (
                    "Logging detected in the LLM call scope is evidence toward "
                    "automatic event-recording capability."
                ),
            }
        ],
        "nist_ai_rmf": [
            {
                "control_id": "Accountable and Transparent",
                "control_name": "Trustworthiness characteristic: Accountable and Transparent",
                "contribution": (
                    "LLM call logging is evidence toward traceable system "
                    "operation."
                ),
            }
        ],
        "iso_42001": [
            {
                "control_id": "Annex A — AI system logging and monitoring",
                "control_name": "Logging and monitoring of AI systems",
                "contribution": (
                    "LLM call logging is evidence toward AI system logging and "
                    "monitoring controls."
                ),
            }
        ],
    },
    "cost-controls": {
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Token/cost limits are evidence toward resource-exhaustion "
                    "resilience."
                ),
            }
        ],
    },
    "rate-limiting": {
        "nist_ai_rmf": [
            {
                "control_id": "Secure and Resilient",
                "control_name": "Trustworthiness characteristic: Secure and Resilient",
                "contribution": (
                    "Rate limiting on LLM-facing input paths is evidence toward "
                    "resource-exhaustion resilience."
                ),
            }
        ],
    },
}

FRAMEWORK_NON_CLAIMS: dict[str, list[str]] = {
    "eu_ai_act": [
        "Art. 10 Data and data governance (training data)",
        "Art. 14 Human oversight",
        "Art. 9 Risk management system (organizational process)",
    ],
    "nist_ai_rmf": [
        "GOVERN function (organizational policies and accountability structures)",
        "MAP function (context establishment and risk identification)",
    ],
    "iso_42001": [
        "Management-system clauses (4–10): organizational processes, audits, "
        "and continual improvement",
    ],
}


def compute_framework_evidence(results: list) -> dict[str, Any]:
    """
    Aggregate defense results into per-framework control evidence.

    Control status: "pass" when every mapped check passed, "fail" when every
    mapped check failed, "mixed" otherwise. Controls with no executed checks
    are omitted.

    Called from: skylos/commands/defend_cmd.py _format_defend_output;
        skylos/defend/report.py format_defense_markdown.
    """
    frameworks: dict[str, Any] = {}

    for framework_key, label in FRAMEWORK_LABELS.items():
        controls: dict[str, dict[str, Any]] = {}

        for result in results:
            plugin_id = getattr(result, "plugin_id", None)
            mappings = PLUGIN_FRAMEWORK_EVIDENCE.get(plugin_id, {})
            for ref in mappings.get(framework_key, []):
                control = controls.setdefault(
                    ref["control_id"],
                    {
                        "control_id": ref["control_id"],
                        "control_name": ref["control_name"],
                        "status": "pass",
                        "checks": [],
                    },
                )
                control["checks"].append(
                    {
                        "plugin_id": plugin_id,
                        "passed": bool(result.passed),
                        "integration_location": result.integration_location,
                        "contribution": ref["contribution"],
                    }
                )

        for control in controls.values():
            outcomes = {check["passed"] for check in control["checks"]}
            if outcomes == {True}:
                control["status"] = "pass"
            elif outcomes == {False}:
                control["status"] = "fail"
            else:
                control["status"] = "mixed"

        frameworks[framework_key] = {
            "label": label,
            "controls": [
                controls[control_id] for control_id in sorted(controls)
            ],
        }

    return {
        "disclaimer": FRAMEWORK_EVIDENCE_DISCLAIMER,
        "frameworks": frameworks,
    }
