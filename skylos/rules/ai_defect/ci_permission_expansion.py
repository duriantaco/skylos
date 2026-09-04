"""SKY-A103: diff-aware CI permission expansion detection."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

RULE_ID = "SKY-A103"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PERMISSION_WRITE_RE = re.compile(
    r"^['\"]?(?P<permission>[A-Za-z0-9_-]+)['\"]?\s*:\s*"
    r"['\"]?write['\"]?\s*,?\s*$"
)
_INLINE_PERMISSIONS_RE = re.compile(
    r"(?:^|[{,])\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*:\s*"
    r"['\"]?write['\"]?(?=\s*(?:[,}]|$))"
)
_ON_LINE_RE = re.compile(r"^['\"]?on['\"]?\s*:\s*(?P<value>.*)$")
_PERMISSIONS_LINE_RE = re.compile(r"^['\"]?permissions['\"]?\s*:\s*(?P<value>.*)$")
_PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
_GITHUB_ACTIONS_WORKFLOW_SUFFIXES = {".yml", ".yaml"}
_ROOT_COMPARABLE_SLOTS = {"on:0", "permissions:0"}
_YAML_MAPPING_TAG = "tag:yaml.org,2002:map"
_YAML_SEQUENCE_TAG = "tag:yaml.org,2002:seq"
_YAML_NULL_TAG = "tag:yaml.org,2002:null"
_YAML_SAFE_SCALAR_TAGS = {
    "tag:yaml.org,2002:str",
    _YAML_NULL_TAG,
    "tag:yaml.org,2002:bool",
}
_YAML_NULL_VALUES = {"", "~", "null", "Null", "NULL"}
_YAML_TRUE_VALUES = {"y", "yes", "true", "on"}
_YAML_FALSE_VALUES = {"n", "no", "false", "off"}
_MAX_COMPARABLE_YAML_NODES = 1_000
_WRITE_PERMISSIONS = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


@dataclass(frozen=True)
class _DiffLine:
    line_no: int
    text: str
    change_id: int


def detect_ci_permission_expansion(diff_text: str, file_path: str) -> list[dict]:
    """Return findings when a GitHub Actions diff adds privileged CI behavior."""
    if not _is_github_actions_workflow(file_path):
        return []

    removed, added = _parse_changed_lines(diff_text)
    removed_lines_by_change = _lines_by_change(
        [line for line in removed if _normalize_yaml_line(line.text)]
    )
    added_lines_by_change = _lines_by_change(
        [line for line in added if _normalize_yaml_line(line.text)]
    )
    # Without a full YAML document, only a one-line replacement is safe to
    # compare for indented/job-level containers. Root `on` and `permissions`
    # are unique slots and are handled separately below.
    comparable_changes = {
        change_id
        for change_id, removed_lines in removed_lines_by_change.items()
        if len(removed_lines) == 1
        and len(added_lines_by_change.get(change_id, ())) == 1
    }
    same_code_changes = {
        change_id
        for change_id in comparable_changes
        if _strip_yaml_comment(removed_lines_by_change[change_id][0].text).rstrip()
        == _strip_yaml_comment(added_lines_by_change[change_id][0].text).rstrip()
    }

    removed_root_signals: Counter[tuple[str, str, str]] = Counter()
    removed_by_change: dict[int, Counter[tuple[str, str, str]]] = {}
    for line in removed:
        if not _is_safe_removal_evidence(line.text):
            continue
        for slot, signal in _signal_entries_for_line(line.text):
            removal_key = (slot, signal["expansion_type"], signal["value"])
            if slot in _ROOT_COMPARABLE_SLOTS:
                # These slots have file-wide scope, so harmless moves or
                # adjacent root-key edits can be compared across change blocks.
                removed_root_signals[removal_key] += 1
                continue
            if line.change_id not in comparable_changes:
                continue
            if (
                not _is_comparable_slot(slot)
                and line.change_id not in same_code_changes
            ):
                continue
            counter = removed_by_change.setdefault(line.change_id, Counter())
            counter[removal_key] += 1

    findings: list[dict] = []
    for line in added:
        removed_signals = removed_by_change.get(line.change_id)
        seen_on_line: set[tuple[str, str]] = set()
        for slot, signal in _signal_entries_for_line(line.text):
            removal_key = (slot, signal["expansion_type"], signal["value"])
            if slot in _ROOT_COMPARABLE_SLOTS and removed_root_signals[removal_key] > 0:
                removed_root_signals[removal_key] -= 1
                continue
            if removed_signals and removed_signals[removal_key] > 0:
                removed_signals[removal_key] -= 1
                continue

            finding_key = (signal["expansion_type"], signal["value"])
            if finding_key in seen_on_line:
                continue
            seen_on_line.add(finding_key)
            findings.append(
                _make_finding(
                    file_path,
                    line.line_no,
                    expansion_type=signal["expansion_type"],
                    value=signal["value"],
                    severity=signal["severity"],
                )
            )

    return findings


def _lines_by_change(lines: list[_DiffLine]) -> dict[int, list[_DiffLine]]:
    grouped: dict[int, list[_DiffLine]] = {}
    for line in lines:
        grouped.setdefault(line.change_id, []).append(line)
    return grouped


def _is_comparable_slot(slot: str) -> bool:
    return slot.startswith(("on:", "permissions:"))


def _is_github_actions_workflow(file_path: str) -> bool:
    normalized = str(file_path).replace("\\", "/")
    normalized_path = f"/{normalized}"
    if "/.github/workflows/" not in normalized_path:
        return False

    suffix = Path(normalized).suffix.lower()
    if suffix not in _GITHUB_ACTIONS_WORKFLOW_SUFFIXES:
        return False

    return True


def _parse_changed_lines(diff_text: str) -> tuple[list[_DiffLine], list[_DiffLine]]:
    removed: list[_DiffLine] = []
    added: list[_DiffLine] = []
    old_line = 0
    new_line = 0
    change_id = 0
    in_change = False
    in_hunk = False

    for raw_line in diff_text.splitlines():
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            old_line = int(hunk_match.group(1))
            new_line = int(hunk_match.group(2))
            in_change = False
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if raw_line.startswith("\\ No newline at end of file"):
            continue

        if raw_line.startswith("-"):
            if not in_change:
                change_id += 1
                in_change = True
            removed.append(_DiffLine(old_line, raw_line[1:], change_id))
            old_line += 1
            continue

        if raw_line.startswith("+"):
            if not in_change:
                change_id += 1
                in_change = True
            added.append(_DiffLine(new_line, raw_line[1:], change_id))
            new_line += 1
            continue

        in_change = False
        if raw_line.startswith(" "):
            old_line += 1
            new_line += 1

    return removed, added


def _normalize_yaml_line(line: str) -> str:
    return _strip_yaml_comment(line).strip()


def _strip_yaml_comment(line: str) -> str:
    """Strip a YAML comment without treating quoted ``#`` characters as comments."""
    in_single_quote = False
    in_double_quote = False
    escaped = False
    index = 0

    while index < len(line):
        char = line[index]

        if in_double_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_double_quote = False
            index += 1
            continue

        if in_single_quote:
            if char == "'":
                if index + 1 < len(line) and line[index + 1] == "'":
                    index += 2
                    continue
                in_single_quote = False
            index += 1
            continue

        if char == '"':
            in_double_quote = True
        elif char == "'":
            in_single_quote = True
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1

    return line


def _is_safe_removal_evidence(line: str) -> bool:
    """Require unambiguous YAML before an old signal may suppress a new one."""
    normalized = _normalize_yaml_line(line)
    if not normalized:
        return False

    try:
        # Composed nodes do not retain whether a tag was explicit. Reject all
        # explicit tags so ``!!bool on`` cannot masquerade as the ordinary
        # GitHub Actions key that PyYAML implicitly resolves as a boolean.
        if any(
            getattr(event, "tag", None) is not None
            for event in yaml.parse(normalized, Loader=yaml.SafeLoader)
        ):
            return False
        root = yaml.compose(normalized, Loader=yaml.SafeLoader)
    except Exception:
        return False
    if root is None:
        return False

    pending: list[tuple[Node, bool]] = [(root, False)]
    active: set[int] = set()
    visited: set[int] = set()
    while pending:
        node, leaving = pending.pop()
        node_id = id(node)
        if leaving:
            active.discard(node_id)
            visited.add(node_id)
            continue
        if node_id in active:
            return False
        if node_id in visited:
            continue
        if len(visited) + len(active) >= _MAX_COMPARABLE_YAML_NODES:
            return False
        if not _has_safe_yaml_tag(node):
            return False

        active.add(node_id)
        pending.append((node, True))

        if isinstance(node, MappingNode):
            raw_keys: set[str] = set()
            resolved_keys: set[tuple[str, object]] = set()
            for key_node, value_node in node.value:
                key = _scalar_node_value(key_node)
                resolved_key = _yaml_scalar_identity(key_node)
                if (
                    key is None
                    or resolved_key is None
                    or key in raw_keys
                    or resolved_key in resolved_keys
                ):
                    return False
                raw_keys.add(key)
                resolved_keys.add(resolved_key)
                pending.extend(((value_node, False), (key_node, False)))
        elif isinstance(node, SequenceNode):
            pending.extend((child, False) for child in node.value)

    # ``compose`` preserves useful lexical values (notably the key ``on``),
    # but it does not validate that explicit tags can actually be constructed.
    # A second SafeLoader pass rejects malformed core tags and unsupported tags
    # before the removed line is trusted as suppression evidence.
    try:
        yaml.safe_load(normalized)
    except Exception:
        return False

    return True


def _has_safe_yaml_tag(node: Node) -> bool:
    if isinstance(node, MappingNode):
        return node.tag == _YAML_MAPPING_TAG
    if isinstance(node, SequenceNode):
        return node.tag == _YAML_SEQUENCE_TAG
    if not isinstance(node, ScalarNode) or node.tag not in _YAML_SAFE_SCALAR_TAGS:
        return False
    if node.tag == _YAML_NULL_TAG:
        # PyYAML's explicit ``!!null`` constructor accepts arbitrary text.
        # Only trust the spellings that are actually YAML null values.
        return node.value in _YAML_NULL_VALUES
    return True


def _yaml_scalar_identity(node: Node) -> tuple[str, object] | None:
    """Return a key identity matching SafeLoader's implicit scalar resolution."""
    if not isinstance(node, ScalarNode) or not _has_safe_yaml_tag(node):
        return None
    if node.tag == "tag:yaml.org,2002:str":
        return ("str", node.value)
    if node.tag == _YAML_NULL_TAG:
        return ("null", None)
    if node.tag == "tag:yaml.org,2002:bool":
        normalized = node.value.casefold()
        if normalized in _YAML_TRUE_VALUES:
            return ("bool", True)
        if normalized in _YAML_FALSE_VALUES:
            return ("bool", False)
    return None


def _signal_entries_for_line(line: str) -> list[tuple[str, dict]]:
    normalized = _normalize_yaml_line(line)
    if not normalized:
        return []

    indent = len(line) - len(line.lstrip(" \t"))
    try:
        parsed = yaml.compose(normalized, Loader=yaml.SafeLoader)
    except Exception:
        return _fallback_signal_entries(normalized, indent)

    entries: list[tuple[str, dict]] = []
    if isinstance(parsed, MappingNode):
        has_container = False
        for key_node, value_node in parsed.value:
            key = _scalar_node_value(key_node)
            if key == "on":
                has_container = True
                entries.extend(
                    (f"on:{indent}", signal) for signal in _trigger_signals(value_node)
                )
            elif key == "permissions":
                has_container = True
                entries.extend(
                    (f"permissions:{indent}", signal)
                    for signal in _permission_signals(value_node)
                )

        if has_container:
            return entries

        trigger_keys = [
            key
            for key_node, _ in parsed.value
            if (key := _scalar_node_value(key_node)) in _PRIVILEGED_TRIGGERS
        ]
        for trigger in sorted(set(trigger_keys)):
            entries.append((f"trigger-entry:{indent}", _trigger_signal(trigger)))

        entries.extend(
            (f"permission-entry:{indent}", signal)
            for signal in _permission_signals(parsed)
        )
        return entries

    if isinstance(parsed, SequenceNode):
        entries.extend(
            (f"trigger-entry:{indent}", signal) for signal in _trigger_signals(parsed)
        )
        return entries

    parsed_value = _plain_scalar_token(parsed)
    if parsed_value in _PRIVILEGED_TRIGGERS:
        return [(f"trigger-entry:{indent}", _trigger_signal(parsed_value))]

    return []


def _signals_for_added_line(line: str) -> list[dict]:
    """Return every CI-permission signal an added line introduces.

    Collects ALL matching privileged triggers (sorted, so the result is
    deterministic regardless of PYTHONHASHSEED) instead of early-returning on
    the first match. A line like ``on: [pull_request_target, workflow_run]``
    therefore reports both triggers, not one random pick.
    """
    return [signal for _, signal in _signal_entries_for_line(line)]


def _scalar_node_value(node: Node | None) -> str | None:
    return node.value if isinstance(node, ScalarNode) else None


def _plain_scalar_token(node: Node | None) -> str | None:
    value = _scalar_node_value(node)
    if value is None or not isinstance(node, ScalarNode) or node.style is not None:
        return value
    return value.removesuffix(",").rstrip()


def _trigger_signals(value: Node | None) -> list[dict]:
    triggers: set[str] = set()
    scalar_value = _scalar_node_value(value)
    if scalar_value in _PRIVILEGED_TRIGGERS:
        triggers.add(scalar_value)
    elif isinstance(value, SequenceNode):
        triggers.update(
            item_value
            for item in value.value
            if (item_value := _scalar_node_value(item)) in _PRIVILEGED_TRIGGERS
        )
    elif isinstance(value, MappingNode):
        triggers.update(
            key_value
            for key, _ in value.value
            if (key_value := _scalar_node_value(key)) in _PRIVILEGED_TRIGGERS
        )

    return [_trigger_signal(trigger) for trigger in sorted(triggers)]


def _trigger_signal(trigger: str) -> dict:
    return {
        "expansion_type": "privileged_trigger",
        "value": trigger,
        "severity": "HIGH",
    }


def _permission_signals(value: Node | None) -> list[dict]:
    if _scalar_node_value(value) == "write-all":
        return [
            {
                "expansion_type": "write_all_permissions",
                "value": "permissions: write-all",
                "severity": "HIGH",
            }
        ]

    if not isinstance(value, MappingNode):
        return []

    permissions = sorted(
        permission_value
        for permission, access in value.value
        if (permission_value := _scalar_node_value(permission)) in _WRITE_PERMISSIONS
        and _plain_scalar_token(access) == "write"
    )
    return [
        {
            "expansion_type": "write_permission",
            "value": f"{permission}: write",
            "severity": "HIGH",
        }
        for permission in permissions
    ]


def _fallback_signal_entries(line: str, indent: int) -> list[tuple[str, dict]]:
    entries: list[tuple[str, dict]] = []

    for trigger in sorted(_PRIVILEGED_TRIGGERS):
        if _line_adds_trigger(line, trigger):
            slot = "on" if _ON_LINE_RE.match(line) else "trigger-entry"
            entries.append((f"{slot}:{indent}", _trigger_signal(trigger)))

    permissions_match = _PERMISSIONS_LINE_RE.match(line)
    if permissions_match and re.fullmatch(
        r"['\"]?write-all['\"]?", permissions_match.group("value").strip()
    ):
        entries.append(
            (
                f"permissions:{indent}",
                {
                    "expansion_type": "write_all_permissions",
                    "value": "permissions: write-all",
                    "severity": "HIGH",
                },
            )
        )

    if permissions_match and "{" in permissions_match.group("value"):
        inline_writes: set[str] = set()
        for permission in _INLINE_PERMISSIONS_RE.findall(line):
            if permission in _WRITE_PERMISSIONS:
                inline_writes.add(permission)

        for permission in sorted(inline_writes):
            entries.append(
                (
                    f"permissions:{indent}",
                    {
                        "expansion_type": "write_permission",
                        "value": f"{permission}: write",
                        "severity": "HIGH",
                    },
                )
            )

    match = _PERMISSION_WRITE_RE.match(line)
    if match and match.group("permission") in _WRITE_PERMISSIONS:
        permission = match.group("permission")
        entries.append(
            (
                f"permission-entry:{indent}",
                {
                    "expansion_type": "write_permission",
                    "value": f"{permission}: write",
                    "severity": "HIGH",
                },
            )
        )

    return entries


def _line_adds_trigger(line: str, trigger: str) -> bool:
    line = _normalize_yaml_line(line)
    if trigger not in line:
        return False

    on_match = _ON_LINE_RE.match(line)
    if on_match:
        trigger_pattern = (
            rf"(?<![A-Za-z0-9_-])['\"]?{re.escape(trigger)}['\"]?"
            rf"(?![A-Za-z0-9_-])"
        )
        return re.search(trigger_pattern, on_match.group("value")) is not None

    trigger_entry_pattern = (
        rf"^(?:-\s*)?['\"]?{re.escape(trigger)}['\"]?"
        rf"\s*(?::.*|,?)$"
    )
    return re.match(trigger_entry_pattern, line) is not None


def _make_finding(
    file_path: str,
    line: int,
    *,
    expansion_type: str,
    value: str,
    severity: str,
) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "ci_permission_expansion",
        "severity": severity,
        "message": (
            "AI defect signal: CI workflow privilege expanded in this diff "
            f"({value}). Review whether this permission or trigger is intended."
        ),
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
        "category": "ai_defect",
        "defect_type": "ci_permission_expansion",
        "vibe_category": "ci_permission_expansion",
        "metadata": {
            "expansion_type": expansion_type,
            "added_value": value,
            "signal_only": False,
            "blocking_recommended": True,
        },
    }
