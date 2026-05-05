from __future__ import annotations

from typing import Any


DEFAULT_OWASP_FRAMEWORK = "llm"
DEFAULT_OWASP_VERSION_BY_FRAMEWORK = {
    "llm": "2025",
    "agentic": "2026",
}

OWASP_FRAMEWORK_ALIASES = {
    "llm": "llm",
    "llms": "llm",
    "agent": "agentic",
    "agents": "agentic",
    "agentic": "agentic",
    "asi": "agentic",
}

OWASP_VERSION_ALIASES = {
    ("llm", "1.1"): "2024",
    ("llm", "v1.1"): "2024",
    ("llm", "2023/24"): "2024",
    ("llm", "2024"): "2024",
    ("llm", "2.0"): "2025",
    ("llm", "v2.0"): "2025",
    ("llm", "2025"): "2025",
    ("agentic", "2026"): "2026",
}

OWASP_REGISTRY: dict[tuple[str, str], dict[str, dict[str, Any]]] = {
    ("llm", "2024"): {
        "LLM01": {
            "name": "Prompt Injection",
            "plugins": [
                "prompt-delimiter",
                "input-length-limit",
                "untrusted-input-to-prompt",
                "rag-context-isolation",
            ],
        },
        "LLM02": {
            "name": "Insecure Output Handling",
            "plugins": ["no-dangerous-sink", "output-validation"],
        },
        "LLM03": {
            "name": "Training Data Poisoning",
            "plugins": [],
        },
        "LLM04": {
            "name": "Model Denial of Service",
            "plugins": ["input-length-limit", "cost-controls", "rate-limiting"],
        },
        "LLM05": {
            "name": "Supply Chain Vulnerabilities",
            "plugins": ["model-pinned"],
        },
        "LLM06": {
            "name": "Sensitive Information Disclosure",
            "plugins": ["output-pii-filter"],
        },
        "LLM07": {
            "name": "Insecure Plugin Design",
            "plugins": ["tool-schema-present", "tool-scope"],
        },
        "LLM08": {
            "name": "Excessive Agency",
            "plugins": ["tool-schema-present", "tool-scope"],
        },
        "LLM09": {
            "name": "Overreliance",
            "plugins": ["output-validation"],
        },
        "LLM10": {
            "name": "Model Theft",
            "plugins": ["rate-limiting", "cost-controls"],
        },
    },
    ("llm", "2025"): {
        "LLM01": {
            "name": "Prompt Injection",
            "plugins": [
                "prompt-delimiter",
                "input-length-limit",
                "untrusted-input-to-prompt",
                "rag-context-isolation",
            ],
        },
        "LLM02": {
            "name": "Sensitive Information Disclosure",
            "plugins": ["output-pii-filter"],
        },
        "LLM03": {
            "name": "Supply Chain",
            "plugins": ["model-pinned"],
        },
        "LLM04": {
            "name": "Data and Model Poisoning",
            "plugins": [],
        },
        "LLM05": {
            "name": "Improper Output Handling",
            "plugins": ["no-dangerous-sink", "output-validation"],
        },
        "LLM06": {
            "name": "Excessive Agency",
            "plugins": ["tool-schema-present", "tool-scope"],
        },
        "LLM07": {
            "name": "System Prompt Leakage",
            "plugins": [],
        },
        "LLM08": {
            "name": "Vector and Embedding Weaknesses",
            "plugins": ["rag-context-isolation"],
        },
        "LLM09": {
            "name": "Misinformation",
            "plugins": ["output-validation"],
        },
        "LLM10": {
            "name": "Unbounded Consumption",
            "plugins": ["input-length-limit", "cost-controls", "rate-limiting"],
        },
    },
    ("agentic", "2026"): {
        "ASI01": {
            "name": "Agent Goal Hijack",
            "plugins": [
                "prompt-delimiter",
                "input-length-limit",
                "untrusted-input-to-prompt",
                "rag-context-isolation",
            ],
        },
        "ASI02": {
            "name": "Tool Misuse and Exploitation",
            "plugins": ["tool-schema-present", "tool-scope", "no-dangerous-sink"],
        },
        "ASI03": {
            "name": "Identity and Privilege Abuse",
            "plugins": ["tool-scope"],
        },
        "ASI04": {
            "name": "Agentic Supply Chain Vulnerabilities",
            "plugins": ["model-pinned", "tool-schema-present"],
        },
        "ASI05": {
            "name": "Unexpected Code Execution (RCE)",
            "plugins": ["no-dangerous-sink", "output-validation", "tool-scope"],
        },
        "ASI06": {
            "name": "Memory & Context Poisoning",
            "plugins": [
                "prompt-delimiter",
                "untrusted-input-to-prompt",
                "rag-context-isolation",
            ],
        },
        "ASI07": {
            "name": "Insecure Inter-Agent Communication",
            "plugins": [],
        },
        "ASI08": {
            "name": "Cascading Failures",
            "plugins": ["logging-present", "cost-controls", "rate-limiting"],
        },
        "ASI09": {
            "name": "Human-Agent Trust Exploitation",
            "plugins": ["output-validation"],
        },
        "ASI10": {
            "name": "Rogue Agents",
            "plugins": ["tool-scope", "logging-present"],
        },
    },
}

OWASP_REPORT_LABELS = {
    ("llm", "2024"): "OWASP LLM Top 10 2024",
    ("llm", "2025"): "OWASP LLM Top 10 2025",
    ("agentic", "2026"): "OWASP Agentic Top 10 2026",
}

OWASP_LLM_MAPPING = OWASP_REGISTRY[("llm", "2025")]


def supported_owasp_frameworks() -> list[str]:
    return sorted({framework for framework, _version in OWASP_REGISTRY})


def supported_owasp_versions(framework: str) -> list[str]:
    framework = normalize_owasp_framework(framework)
    return sorted(version for candidate, version in OWASP_REGISTRY if candidate == framework)


def normalize_owasp_framework(framework: str | None = None) -> str:
    raw = framework or DEFAULT_OWASP_FRAMEWORK
    normalized = OWASP_FRAMEWORK_ALIASES.get(raw.strip().lower())
    if normalized is None:
        valid = ", ".join(supported_owasp_frameworks())
        raise ValueError(f"Unsupported OWASP framework '{raw}'. Valid: {valid}")
    return normalized


def normalize_owasp_selection(
    framework: str | None = None,
    version: str | int | None = None,
) -> tuple[str, str]:
    normalized_framework = normalize_owasp_framework(framework)
    raw_version = (
        DEFAULT_OWASP_VERSION_BY_FRAMEWORK[normalized_framework]
        if version is None
        else str(version).strip().lower()
    )
    normalized_version = OWASP_VERSION_ALIASES.get(
        (normalized_framework, raw_version),
        raw_version,
    )
    if (normalized_framework, normalized_version) not in OWASP_REGISTRY:
        valid = ", ".join(supported_owasp_versions(normalized_framework))
        raise ValueError(
            f"Unsupported OWASP version '{version}' for framework "
            f"'{normalized_framework}'. Valid: {valid}"
        )
    return normalized_framework, normalized_version


def get_owasp_mapping(
    framework: str | None = None,
    version: str | int | None = None,
) -> dict[str, dict[str, Any]]:
    framework, version = normalize_owasp_selection(framework, version)
    return OWASP_REGISTRY[(framework, version)]


def owasp_report_label(
    framework: str | None = None,
    version: str | int | None = None,
) -> str:
    framework, version = normalize_owasp_selection(framework, version)
    return OWASP_REPORT_LABELS[(framework, version)]


def validate_owasp_ids(
    ids: list[str],
    *,
    framework: str | None = None,
    version: str | int | None = None,
) -> list[str]:
    mapping = get_owasp_mapping(framework, version)
    normalized_ids = [owasp_id.strip().upper() for owasp_id in ids if owasp_id.strip()]
    invalid = [owasp_id for owasp_id in normalized_ids if owasp_id not in mapping]
    if invalid:
        valid = ", ".join(sorted(mapping))
        raise ValueError(
            f"Unknown OWASP ID '{invalid[0]}'. Valid for "
            f"{owasp_report_label(framework, version)}: {valid}"
        )
    return normalized_ids


def plugin_ids_for_owasp_filter(
    ids: list[str] | None,
    *,
    framework: str | None = None,
    version: str | int | None = None,
) -> set[str] | None:
    if ids is None:
        return None

    mapping = get_owasp_mapping(framework, version)
    plugin_ids: set[str] = set()
    for owasp_id in validate_owasp_ids(ids, framework=framework, version=version):
        plugin_ids.update(mapping[owasp_id]["plugins"])
    return plugin_ids


def compute_owasp_coverage(
    results: list,
    *,
    framework: str | None = None,
    version: str | int | None = None,
) -> dict[str, dict[str, Any]]:
    mapping = get_owasp_mapping(framework, version)
    coverage = {}

    for owasp_id, info in mapping.items():
        plugin_ids = set(info["plugins"])
        relevant = [result for result in results if result.plugin_id in plugin_ids]
        passed = sum(1 for result in relevant if result.passed)
        total = len(relevant)

        if total == 0:
            status = "not_applicable"
            pct = None
        else:
            pct = round(passed / total * 100)
            if pct == 100:
                status = "covered"
            elif pct > 0:
                status = "partial"
            else:
                status = "uncovered"

        coverage[owasp_id] = {
            "name": info["name"],
            "plugins": info["plugins"],
            "status": status,
            "passed": passed,
            "total": total,
            "coverage_pct": pct,
        }

    return coverage
