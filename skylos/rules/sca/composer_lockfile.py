"""Bounded, data-only inventory of Composer's composer.lock.

``packages`` are runtime packages and ``packages-dev`` are installed only for
development. A package is a public Packagist identity only when Composer
recorded packagist.org as the repository that served it (its
``notification-url``). Path repositories are the project's own code; VCS,
private and branch (``dev-*``) installs are coverage gaps and never queried:
OSV matches a branch name like ``dev-main`` against every advisory range.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.npm_lockfile import (
    _invalid_constant,
    _source_lines,
    _unique_object,
)

MAX_COMPOSER_LOCK_BYTES = 10_000_000
PACKAGIST_NOTIFICATION_URL = "https://packagist.org/downloads/"
_SECTIONS = (("packages", False), ("packages-dev", True))
_NAME = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126})\Z"
)
_VERSION = re.compile(
    r"[0-9]+(?:\.[0-9]+){0,3}"
    r"(?:[-_.]?(?:alpha|beta|rc|a|b|p|pl|patch)(?:[.-]?[0-9]+)*)?"
    r"(?:\+[0-9A-Za-z.-]+)?\Z",
    re.IGNORECASE,
)
_VCS_TYPES = frozenset({"git", "hg", "svn", "fossil", "github", "gitlab", "bitbucket"})


def composer_version(value: object) -> str | None:
    """A released Composer version without its optional ``v`` prefix."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    version = value
    if version[:1] in {"v", "V"} and version[1:2].isdigit():
        version = version[1:]
    if not _VERSION.fullmatch(version):
        return None
    return version


def is_branch_version(value: object) -> bool:
    return isinstance(value, str) and (
        value.startswith("dev-") or value.endswith("-dev")
    )


def _type(entry: dict, key: str) -> str | None:
    value = entry.get(key)
    if isinstance(value, dict) and isinstance(value.get("type"), str):
        return value["type"]
    return None


def _source(entry: dict) -> tuple[str, str | None]:
    """Return (source type, reason it is not queried)."""
    dist_type = _type(entry, "dist")
    source_type = _type(entry, "source")
    if dist_type == "path" or (dist_type is None and source_type == "path"):
        return "local", None
    vcs = source_type in _VCS_TYPES
    if is_branch_version(entry.get("version")):
        if vcs or source_type is None:
            return "git", "non_registry_source"
        return "url", "non_registry_source"
    notification = entry.get("notification-url")
    if notification is None:
        if vcs:
            return "git", "non_registry_source"
        return "url", "non_registry_source"
    if not isinstance(notification, str) or len(notification) > 2048:
        return "unknown", "invalid_package_source"
    if notification == PACKAGIST_NOTIFICATION_URL:
        return "registry", None
    try:
        parsed = urlsplit(notification)
    except ValueError:
        return "unknown", "invalid_package_source"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "unknown", "invalid_package_source"
    return "registry", "non_public_registry"


def _records(data: dict, max_packages: int) -> list[tuple[str, int, bool, object]]:
    records = []
    for section, dev in _SECTIONS:
        packages = data.get(section)
        if packages is None and section == "packages-dev":
            continue
        if not isinstance(packages, list):
            raise LockfileParseError(f"composer.lock {section} must be an array")
        for index, entry in enumerate(packages):
            records.append((section, index, dev, entry))
            if len(records) > max_packages:
                raise LockfileLimitError("composer.lock exceeds package limit")
    return records


def parse_composer_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory packages and packages-dev without reading composer.json or vendor/."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_COMPOSER_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("composer.lock is unreadable or unsafe")
    if len(text.encode("utf-8")) > MAX_COMPOSER_LOCK_BYTES:
        raise LockfileLimitError("composer.lock exceeds byte limit")
    try:
        data = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("composer.lock is not valid JSON") from exc
    if not isinstance(data, dict) or "packages" not in data:
        raise LockfileParseError("composer.lock must contain packages")
    records = _records(data, max_packages)
    lines = _source_lines(
        text, {(section, index, "name") for section, index, _, _ in records}
    )
    inventory = LockfileInventory(format_version=1, package_count=len(records))
    non_registry_names = set()
    for section, index, dev, entry in records:
        line = lines.get((section, index, "name"), 1)
        issue = {"reason": "", "package": f"{section}[{index}]", "line": line}
        if not isinstance(entry, dict):
            issue["reason"] = "invalid_package_entry"
            inventory.unresolved.append(issue)
            continue
        raw_name = entry.get("name")
        if not isinstance(raw_name, str) or not _NAME.fullmatch(raw_name):
            issue["reason"] = "invalid_package_name"
            inventory.unresolved.append(issue)
            continue
        name = raw_name.lower()
        issue.update(package=name, name=name)
        raw_version = entry.get("version")
        version = composer_version(raw_version)
        if version is not None:
            issue["version"] = version
        kind, reason = _source(entry)
        if kind == "local":
            inventory.local_package_count += 1
            non_registry_names.add(name)
            inventory.not_checked.append(
                dict(issue, reason="local_package", source_type="local")
            )
            continue
        if reason in {"non_registry_source", "non_public_registry"}:
            non_registry_names.add(name)
            inventory.not_checked.append(dict(issue, reason=reason, source_type=kind))
            continue
        if reason:
            non_registry_names.add(name)
            inventory.unresolved.append(dict(issue, reason=reason, source_type=kind))
            continue
        if version is None:
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        inventory.dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "Packagist",
                "file": str(path),
                "line": line,
                "snippet": f"{name}@{raw_version}",
                "exact": True,
                "version_spec": raw_version,
                "lockfile_version": 1,
                "package_path": f"{section}[{index}]",
                "source_type": "registry",
                "environment_scope": "all_locked_environments",
                "dependency_kind": "unknown",
                "dependency_kinds": ["unknown"],
                "dependency_sections": [section],
                "dependency_dev": dev,
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
