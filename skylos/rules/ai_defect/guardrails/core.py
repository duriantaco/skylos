"""Shared types and helpers for the guardrail-tamper rules (SKY-A122, SKY-A125).

Every rule here compares a file at the base with the same file at the head
and reports only what the change did. A file nobody changed is never read,
and a setting that was already weak at the base is not reported again.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

# SKY-A123 to A126 are reserved for this family and not used.
RULE_REVIEWER_CONFIG = "SKY-A122"
RULE_SCANNER_MARKER = "SKY-A125"

GUARDRAIL_RULES = (RULE_REVIEWER_CONFIG, RULE_SCANNER_MARKER)
# Approval-guard veto classes (the shared contract with the approval guard).
GUARDRAIL_CLASS = {
    RULE_REVIEWER_CONFIG: "guardrail_config_changed",
    RULE_SCANNER_MARKER: "checks_silenced",
}
GUARDRAIL_KIND = "guardrail_tamper"
DEFAULT_SEVERITY = "MEDIUM"

MAX_TEXT_BYTES = 2 * 1024 * 1024
# At most this many changes are named in one message; the rest are counted.
MAX_NAMED = 3


@dataclass(frozen=True)
class FileChange:
    """One changed file: its text before and after, and the lines added."""

    path: str
    status: str  # "added", "modified", "deleted" or "renamed"
    base_path: str | None
    base_text: str | None
    head_text: str | None
    added_lines: frozenset[int] = frozenset()

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name


@dataclass
class GuardrailFinding:
    rule: str
    file: str
    line: int | None
    message: str
    kind: str  # what changed, e.g. "reviewer_config_narrowed"
    severity: str = DEFAULT_SEVERITY
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def guardrail_class(self) -> str:
        return GUARDRAIL_CLASS[self.rule]


@dataclass
class GuardrailOutcome:
    findings: list[GuardrailFinding] = field(default_factory=list)
    files_read: int = 0
    # Files a rule wanted to compare but could not parse on one side.
    unparsed: list[str] = field(default_factory=list)
    # Markers added in test files: counted, not listed.
    markers_in_tests: int = 0


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class _Unparsed:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNPARSED"


UNPARSED: Any = _Unparsed()


def parse_json(text: str | None):
    """JSON, also with comments and trailing commas (VS Code, Renovate)."""
    if text is None:
        return None
    if not text.strip():
        return {}
    from skylos.done.lint_config import UNKNOWN, _jsonc

    value = _jsonc(text)
    return UNPARSED if value is UNKNOWN else value


def parse_yaml(text: str | None):
    if text is None:
        return None
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError:
        return UNPARSED
    return {} if value is None else value


def parse_toml(text: str | None):
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return UNPARSED


# ---------------------------------------------------------------------------
# Comparing structured settings
# ---------------------------------------------------------------------------

_LIST_KEYS = ("path", "name", "id", "rule", "pattern", "glob", "match", "label")


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Leaf values by dotted path. Lists of scalars become frozensets (order
    does not count); lists of mappings are keyed by their identifying field."""
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        if not value and prefix:
            out[prefix] = {}
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(item, child))
        return out
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            out[prefix] = frozenset(_scalar_text(item) for item in value)
            return out
        for index, item in enumerate(value):
            label = str(index)
            if isinstance(item, dict):
                for key in _LIST_KEYS:
                    if isinstance(item.get(key), (str, int)):
                        label = f"{key}={item[key]}"
                        break
            out.update(flatten(item, f"{prefix}[{label}]"))
        return out
    out[prefix] = value
    return out


def _scalar_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


@dataclass(frozen=True)
class SettingChange:
    key: str
    before: Any  # MISSING when the key is new
    after: Any  # MISSING when the key is gone


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "MISSING"


MISSING: Any = _Missing()


def compare_settings(before: Any, after: Any) -> list[SettingChange]:
    flat_before = flatten(before) if isinstance(before, (dict, list)) else {}
    flat_after = flatten(after) if isinstance(after, (dict, list)) else {}
    changes = []
    for key in sorted(set(flat_before) | set(flat_after)):
        old = flat_before.get(key, MISSING)
        new = flat_after.get(key, MISSING)
        if _same(old, new):
            continue
        changes.append(SettingChange(key, old, new))
    return changes


def _same(old: Any, new: Any) -> bool:
    if old is MISSING or new is MISSING:
        return old is new
    if isinstance(old, bool) or isinstance(new, bool):
        return type(old) is type(new) and old == new
    return old == new


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def line_of(
    text: str | None, needle: str, added: frozenset[int] | set[int] = frozenset()
) -> int | None:
    """The first added line holding ``needle``, else the first line holding it."""
    if not text or not needle:
        return None
    first = None
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            if index in added:
                return index
            if first is None:
                first = index
    return first


def first_added(change: FileChange) -> int | None:
    return min(change.added_lines) if change.added_lines else None


def shown(value: Any, limit: int = 60) -> str:
    """A setting value as quoted in a message."""
    if value is MISSING:
        return "(unset)"
    if isinstance(value, frozenset):
        value = sorted(value)
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        text = _scalar_text(value)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return f"`{text}`"


def join_changes(parts: list[str]) -> str:
    named = parts[:MAX_NAMED]
    text = "; ".join(named)
    if len(parts) > MAX_NAMED:
        text += f"; and {len(parts) - MAX_NAMED} more"
    return text


_SPACE_RE = re.compile(r"\s+")


def normalized_lines(text: str | None) -> list[str]:
    """Non-blank lines with whitespace collapsed: formatting does not count."""
    if not text:
        return []
    out = []
    for line in text.splitlines():
        cleaned = _SPACE_RE.sub(" ", line).strip()
        if cleaned:
            out.append(cleaned)
    return out


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on", "1"}:
            return True
        if lowered in {"false", "no", "off", "0"}:
            return False
    if isinstance(value, int):
        return bool(value)
    return None


def is_vendored(path: str) -> bool:
    from skylos.done.suppressions import is_vendored as _vendored

    return _vendored(path)
