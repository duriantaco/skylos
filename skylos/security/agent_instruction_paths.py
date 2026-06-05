from __future__ import annotations

from pathlib import Path


AGENT_RULE_ID = "SKY-D266"

_AGENT_INSTRUCTION_BASENAMES = {
    ".clinerules",
    ".cursorrules",
    ".windsurfrules",
    "agents.md",
    "claude.md",
}

_AGENT_INSTRUCTION_PREFIXES = (".aider",)


def is_agent_instruction_path(path: str | Path) -> bool:
    normalized = Path(path).as_posix().lower()
    if normalized.startswith("./"):
        normalized = normalized[2:]

    basename = Path(normalized).name
    if basename in _AGENT_INSTRUCTION_BASENAMES:
        return True
    if any(basename.startswith(prefix) for prefix in _AGENT_INSTRUCTION_PREFIXES):
        return True
    if normalized == ".github/copilot-instructions.md":
        return True
    if normalized.startswith(".cursor/rules/") and normalized.endswith(".mdc"):
        return True
    if normalized.startswith(".continue/"):
        return True
    return False


def agent_rule_id(is_agent_instruction: bool, default_rule_id: str) -> str:
    if is_agent_instruction:
        return AGENT_RULE_ID
    return default_rule_id


def agent_severity(severity: str, is_agent_instruction: bool) -> str:
    if is_agent_instruction:
        return "CRITICAL"
    return severity
