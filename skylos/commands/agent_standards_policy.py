"""Read the opt-in, declarative standards policy used by agent hooks.

The file is data, not executable configuration.  Reject an explicitly present
but unusable policy so an agent cannot evade requested checks by corrupting it.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from skylos.rules.catalog import get_rule_catalog

POLICY_PATH = Path(".skylos/agent-standards.json")
MAX_POLICY_BYTES = 16_384
MAX_STANDARDS_BYTES = 262_144


class AgentStandardsPolicyError(ValueError):
    """An explicitly configured agent standards policy cannot be enforced."""


@dataclass(frozen=True)
class AgentStandardsPolicy:
    standards_file: str
    enforce_rule_ids: frozenset[str]


def supported_quality_rule_ids() -> frozenset[str]:
    """Only built-in quality rules can be selected for hook enforcement."""
    return frozenset(
        entry["id"]
        for entry in get_rule_catalog()
        if entry["category"] == "quality" and entry["source"] == "builtin"
    )


def load_agent_standards_policy(root: Path) -> AgentStandardsPolicy | None:
    policy_path = root / POLICY_PATH
    try:
        policy_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AgentStandardsPolicyError("cannot inspect agent-standards.json") from exc

    if (root / ".skylos").is_symlink():
        raise AgentStandardsPolicyError(".skylos must not be a symlink")
    raw = _read_regular_file(policy_path, MAX_POLICY_BYTES, "agent-standards.json")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentStandardsPolicyError(
            "agent-standards.json is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "standards_file",
        "enforce_rule_ids",
    }:
        raise AgentStandardsPolicyError("agent-standards.json has unsupported fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise AgentStandardsPolicyError(
            "agent-standards.json requires schema_version 1"
        )

    standards_file = data["standards_file"]
    if (
        not isinstance(standards_file, str)
        or not standards_file
        or "\\" in standards_file
        or any(ord(char) < 32 or ord(char) == 127 for char in standards_file)
    ):
        raise AgentStandardsPolicyError(
            "standards_file must be a project-relative path"
        )
    relative = Path(standards_file)
    if relative.is_absolute() or any(
        part in {".", ".."} for part in standards_file.split("/")
    ):
        raise AgentStandardsPolicyError("standards_file must stay within the project")
    if relative.suffix.lower() not in {".md", ".markdown"}:
        raise AgentStandardsPolicyError("standards_file must be a Markdown file")
    standards_path = root
    for part in relative.parts:
        standards_path = standards_path / part
        try:
            if standards_path.is_symlink():
                raise AgentStandardsPolicyError("standards_file must not use a symlink")
        except OSError as exc:
            raise AgentStandardsPolicyError("cannot inspect standards_file") from exc
    standards_raw = _read_regular_file(
        standards_path, MAX_STANDARDS_BYTES, "standards_file"
    )
    try:
        standards_text = standards_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentStandardsPolicyError("standards_file must be UTF-8") from exc
    if not standards_text.strip():
        raise AgentStandardsPolicyError("standards_file must not be empty")

    rule_ids = data["enforce_rule_ids"]
    if not isinstance(rule_ids, list) or len(rule_ids) > 128:
        raise AgentStandardsPolicyError("enforce_rule_ids must be a list of rule IDs")
    if any(not isinstance(rule_id, str) for rule_id in rule_ids):
        raise AgentStandardsPolicyError("enforce_rule_ids must contain only rule IDs")
    if len(set(rule_ids)) != len(rule_ids):
        raise AgentStandardsPolicyError("enforce_rule_ids must not contain duplicates")
    if set(rule_ids) - supported_quality_rule_ids():
        raise AgentStandardsPolicyError(
            "enforce_rule_ids includes unsupported built-in quality rule IDs"
        )
    return AgentStandardsPolicy(standards_file, frozenset(rule_ids))


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        entry = path.lstat()
        if not stat.S_ISREG(entry.st_mode):
            raise AgentStandardsPolicyError(f"{label} must be a regular file")
        if entry.st_size > limit:
            raise AgentStandardsPolicyError(f"{label} exceeds {limit} bytes")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise AgentStandardsPolicyError(f"{label} must be a regular file")
            if info.st_size > limit:
                raise AgentStandardsPolicyError(f"{label} exceeds {limit} bytes")
            raw = stream.read(limit + 1)
    except AgentStandardsPolicyError:
        raise
    except (OSError, ValueError) as exc:
        raise AgentStandardsPolicyError(
            f"cannot read {label} as a regular file"
        ) from exc
    if len(raw) > limit:
        raise AgentStandardsPolicyError(f"{label} exceeds {limit} bytes")
    return raw
