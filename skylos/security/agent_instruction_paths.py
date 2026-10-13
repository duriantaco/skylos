from __future__ import annotations

from pathlib import Path, PurePosixPath


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


# AI code reviewers' instruction and settings files, checked against each
# vendor's documentation on 13 Oct 2026. (tool, branch the reviewer reads the
# file from: "head" when a pull request's own version applies to its review,
# "base" when the default branch's version does, "" when undocumented).
#
# Each entry: (kind, pattern, tool, branch). Kinds:
#   "exact"    the repository-relative path
#   "name"     a file name in any directory ("**/<pattern>")
#   "tree"     every file under a directory at the root ("<pattern>/**")
#   "any_tree" every file under a directory of that name at any depth
#   "suffix"   a file under a directory with a name suffix: "dir|suffix"
AI_REVIEWER_FILES: tuple[tuple[str, str, str, str], ...] = (
    ("exact", ".coderabbit.yaml", "CodeRabbit", "head"),
    ("exact", ".coderabbit.config.ts", "CodeRabbit", "head"),
    ("exact", "REVIEW.md", "Copilot code review, Claude Code Review and Qodo", "head"),
    ("name", ".cursor/BUGBOT.md", "Cursor Bugbot", ""),
    ("exact", ".cursor/config/bugbot.yaml", "Cursor Bugbot", "base"),
    ("exact", "greptile.json", "Greptile", ""),
    ("any_tree", ".greptile", "Greptile", ""),
    ("exact", ".gemini/styleguide.md", "Gemini Code Assist", ""),
    ("exact", ".gemini/config.yaml", "Gemini Code Assist", ""),
    ("exact", ".pr_agent.toml", "Qodo Merge (PR-Agent)", "base"),
    ("exact", "best_practices.md", "Qodo Merge", ""),
    ("tree", ".macroscope", "Macroscope", "head"),
    ("exact", "macroscope_approvability.md", "Macroscope", "head"),
    ("exact", ".macroscope-ignore", "Macroscope", "head"),
    ("exact", ".github/copilot-instructions.md", "GitHub Copilot", "head"),
    ("suffix", ".github/instructions|.instructions.md", "GitHub Copilot", "head"),
    ("tree", ".github/skills", "GitHub Copilot", "head"),
    ("exact", ".bito.yaml", "Bito", "head"),
    ("exact", ".ellipsis/code-review.yaml", "Ellipsis", "base"),
)

# General agent instruction files that AI reviewers also read: Copilot code
# review reads the root AGENTS.md, CLAUDE.md and GEMINI.md from the pull
# request's head; Claude Code Review reads CLAUDE.md at every level. They are
# edited for many other reasons, so only review-directed changes count.
SHARED_REVIEWER_INSTRUCTION_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "GEMINI.md"})


def _normalized(path: str | Path) -> str:
    text = Path(path).as_posix() if isinstance(path, Path) else str(path)
    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def ai_reviewer_entry(path: str | Path) -> tuple[str, str] | None:
    """(tool, branch) when ``path`` is an AI reviewer's own config file."""
    normalized = _normalized(path)
    for kind, pattern, tool, branch in AI_REVIEWER_FILES:
        if kind == "exact" and normalized == pattern:
            return tool, branch
        if kind == "name" and (
            normalized == pattern or normalized.endswith("/" + pattern)
        ):
            return tool, branch
        if kind == "tree" and normalized.startswith(pattern + "/"):
            return tool, branch
        if kind == "any_tree" and (
            normalized.startswith(pattern + "/") or f"/{pattern}/" in normalized
        ):
            return tool, branch
        if kind == "suffix":
            directory, suffix = pattern.split("|", 1)
            if normalized.startswith(directory + "/") and normalized.endswith(suffix):
                return tool, branch
    return None


# Where a full scan looks for the files above, relative to the scan root.
AI_REVIEWER_GLOBS = (
    ".coderabbit.yaml",
    "REVIEW.md",
    ".cursor/BUGBOT.md",
    ".cursor/config/bugbot.yaml",
    "greptile.json",
    ".greptile/*",
    ".gemini/styleguide.md",
    ".gemini/config.yaml",
    ".pr_agent.toml",
    "best_practices.md",
    ".macroscope/**/*",
    "macroscope_approvability.md",
    ".github/copilot-instructions.md",
    ".github/instructions/**/*.instructions.md",
    ".github/skills/**/*",
    ".bito.yaml",
    ".ellipsis/code-review.yaml",
)


def is_ai_reviewer_config_path(path: str | Path) -> bool:
    return ai_reviewer_entry(path) is not None


def is_shared_reviewer_instruction_path(path: str | Path) -> bool:
    return PurePosixPath(_normalized(path)).name in SHARED_REVIEWER_INSTRUCTION_NAMES


def agent_rule_id(is_agent_instruction: bool, default_rule_id: str) -> str:
    if is_agent_instruction:
        return AGENT_RULE_ID
    return default_rule_id


def agent_severity(severity: str, is_agent_instruction: bool) -> str:
    if is_agent_instruction:
        return "CRITICAL"
    return severity
