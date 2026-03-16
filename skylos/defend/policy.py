from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class DefensePolicy:
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_min_score: Optional[int] = None
    gate_fail_on: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rules": self.rules,
            "gate": {
                "min_score": self.gate_min_score,
                "fail_on": self.gate_fail_on,
            },
        }


OWASP_LLM_MAPPING: dict[str, dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "plugins": ["prompt-delimiter", "input-length-limit", "untrusted-input-to-prompt", "rag-context-isolation"],
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "plugins": ["no-dangerous-sink", "output-validation"],
    },
    "LLM03": {
        "name": "Training Data Poisoning / Supply Chain",
        "plugins": ["model-pinned"],
    },
    "LLM04": {
        "name": "Excessive Agency",
        "plugins": ["tool-schema-present", "tool-scope"],
    },
    "LLM05": {
        "name": "Improper Error Handling",
        "plugins": [],
    },
    "LLM06": {
        "name": "PII Disclosure",
        "plugins": ["output-pii-filter"],
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "plugins": ["tool-schema-present", "tool-scope"],
    },
    "LLM08": {
        "name": "Excessive Autonomy",
        "plugins": ["tool-scope"],
    },
    "LLM09": {
        "name": "Overreliance",
        "plugins": ["output-validation"],
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "plugins": ["input-length-limit", "cost-controls", "rate-limiting"],
    },
}


def load_policy(path: str | Path | None = None) -> Optional[DefensePolicy]:
    if path is not None:
        policy_path = Path(path)
    else:
        candidates = [
            Path("skylos-defend.yaml"),
            Path("skylos-defend.yml"),
            Path(".skylos-defend.yaml"),
            Path(".skylos-defend.yml"),
        ]
        policy_path = None
        for candidate in candidates:
            if candidate.exists():
                policy_path = candidate
                break

        if policy_path is None:
            return None

    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for policy files. Install with: pip install pyyaml"
        )

    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid policy file: expected a YAML mapping, got {type(raw).__name__}")

    return _parse_policy(raw)


def _parse_policy(raw: dict) -> DefensePolicy:
    valid_severities = {"critical", "high", "medium", "low"}
    valid_plugin_ids = {
        "no-dangerous-sink",
        "tool-scope",
        "tool-schema-present",
        "prompt-delimiter",
        "output-validation",
        "model-pinned",
        "input-length-limit",
        "untrusted-input-to-prompt",
        "rag-context-isolation",
        "output-pii-filter",
        "logging-present",
        "cost-controls",
        "rate-limiting",
    }

    rules: dict[str, dict] = {}
    raw_rules = raw.get("rules", {})
    if isinstance(raw_rules, dict):
        for plugin_id, overrides in raw_rules.items():
            if plugin_id not in valid_plugin_ids:
                raise ValueError(
                    f"Unknown plugin '{plugin_id}' in policy. "
                    f"Valid plugins: {', '.join(sorted(valid_plugin_ids))}"
                )
            if not isinstance(overrides, dict):
                raise ValueError(
                    f"Invalid rule for '{plugin_id}': expected a mapping"
                )
            if "severity" in overrides and overrides["severity"] not in valid_severities:
                raise ValueError(
                    f"Invalid severity '{overrides['severity']}' for '{plugin_id}'. "
                    f"Valid: {', '.join(sorted(valid_severities))}"
                )
            rules[plugin_id] = overrides

    gate = raw.get("gate", {})
    gate_min_score = None
    gate_fail_on = None
    if isinstance(gate, dict):
        gate_min_score = gate.get("min_score")
        if gate_min_score is not None:
            gate_min_score = int(gate_min_score)
            if not 0 <= gate_min_score <= 100:
                raise ValueError(f"gate.min_score must be 0-100, got {gate_min_score}")

        gate_fail_on = gate.get("fail_on")
        if gate_fail_on is not None and gate_fail_on not in valid_severities:
            raise ValueError(
                f"Invalid gate.fail_on '{gate_fail_on}'. "
                f"Valid: {', '.join(sorted(valid_severities))}"
            )

    return DefensePolicy(
        rules=rules,
        gate_min_score=gate_min_score,
        gate_fail_on=gate_fail_on,
    )


def compute_owasp_coverage(
    results: list,
) -> dict[str, dict[str, Any]]:
    coverage = {}
    for owasp_id, info in OWASP_LLM_MAPPING.items():
        relevant = [r for r in results if r.owasp_llm == owasp_id]
        passed = sum(1 for r in relevant if r.passed)
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
