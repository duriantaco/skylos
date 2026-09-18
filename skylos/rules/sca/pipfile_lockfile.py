"""Bounded, data-only inventory of Pipenv's Pipfile.lock format 6.

The lock records every resolved package per category, but not dependency edges
or which packages were direct. Source URLs are inspected only to decide whether
an OSV PyPI identity is safe; they are never fetched or copied to results.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

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
from skylos.rules.sca.poetry_lockfile import _version, _workspace_path
from skylos.rules.sca.uv_lockfile import _name, _public_registry

MAX_PIPFILE_LOCK_BYTES = 10_000_000
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SOURCE_KEYS = frozenset({"git", "hg", "svn", "bzr", "path", "file", "url"})
_MARKER_KEYS = frozenset(
    {
        "markers",
        "os_name",
        "sys_platform",
        "platform_machine",
        "platform_python_implementation",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_version",
        "python_full_version",
        "implementation_name",
        "implementation_version",
    }
)


def _label(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 256 and bool(_LABEL.fullmatch(value))
    )


def _marker(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 4096
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and "://" not in value
        and "@" not in value
    )


def _sources(meta: dict) -> tuple[list[dict], dict[str, dict]]:
    raw = meta.get("sources")
    if not isinstance(raw, list) or not raw:
        raise LockfileParseError("Pipfile.lock must record package sources")
    by_name = {}
    for source in raw:
        if not isinstance(source, dict):
            raise LockfileParseError("Pipfile.lock source must be an object")
        name, url = source.get("name"), source.get("url")
        if not _label(name) or not isinstance(url, str) or not url:
            raise LockfileParseError("Pipfile.lock source identity is invalid")
        if name in by_name:
            raise LockfileParseError("Pipfile.lock has duplicate source names")
        by_name[name] = source
    return raw, by_name


def _source(entry: dict, sources: list[dict], by_name: dict) -> tuple[str, str | None]:
    if "editable" in entry and type(entry["editable"]) is not bool:
        return "unknown", "invalid_package_source"
    origins = _SOURCE_KEYS.intersection(entry)
    if origins or entry.get("editable") is True:
        if origins == {"path"} and isinstance(entry["path"], str):
            return "local", None
        return "non_registry", "non_registry_source"
    if "index" in entry:
        index = entry["index"]
        if not _label(index) or index not in by_name:
            return "unknown", "invalid_package_source"
        source = by_name[index]
        source_type = "registry"
    else:
        # Pipenv resolves unqualified packages from its first/default source.
        source = sources[0]
        source_type = "registry_unspecified"
    if not _public_registry({"registry": source["url"]}):
        return "non_registry", "non_public_registry"
    if source.get("verify_ssl", True) is not True:
        return "unknown", "invalid_package_source"
    return source_type, None


def parse_pipfile_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory all lock categories without reading Pipfile or source paths."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_PIPFILE_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("Pipfile.lock is unreadable or unsafe")
    try:
        if len(text.encode("utf-8")) > MAX_PIPFILE_LOCK_BYTES:
            raise LockfileLimitError("Pipfile.lock exceeds byte limit")
        data = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("Pipfile.lock is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("_meta"), dict):
        raise LockfileParseError("Pipfile.lock must contain _meta")
    meta = data["_meta"]
    if type(meta.get("pipfile-spec")) is not int or meta["pipfile-spec"] != 6:
        raise LockfileParseError("Only Pipfile.lock spec 6 is supported")
    sources, by_name = _sources(meta)
    requires = meta.get("requires", {})
    if not isinstance(requires, dict):
        raise LockfileParseError("Pipfile.lock requires must be an object")
    python = requires.get("python_full_version", requires.get("python_version"))
    if python is not None and not _marker(python):
        raise LockfileParseError("Pipfile.lock Python requirement is invalid")

    records = []
    for group, packages in data.items():
        if group == "_meta":
            continue
        if not _label(group) or not isinstance(packages, dict):
            raise LockfileParseError("Pipfile.lock category is invalid")
        for raw_name, entry in packages.items():
            records.append((group, raw_name, entry))
            if len(records) > max_packages:
                raise LockfileLimitError("Pipfile.lock exceeds package limit")
    wanted = {(group, raw_name) for group, raw_name, _ in records}
    wanted.update((group, raw_name, "version") for group, raw_name, _ in records)
    lines = _source_lines(text, wanted)
    inventory = LockfileInventory(format_version=6, package_count=len(records))
    non_registry_names = set()
    workspace_paths = set()
    for group, raw_name, entry in records:
        key = (group, raw_name)
        line = lines.get(key + ("version",), lines.get(key, 1))
        name = _name(raw_name)
        issue = {"reason": "", "package": name, "line": line, "group": group}
        if name is None:
            issue["reason"] = "invalid_package_name"
            inventory.unresolved.append(issue)
            continue
        issue["name"] = name
        if not isinstance(entry, dict):
            issue["reason"] = "invalid_package_entry"
            inventory.unresolved.append(issue)
            continue
        source_type, reason = _source(entry, sources, by_name)
        if source_type == "local":
            inventory.local_package_count += 1
            non_registry_names.add(name)
            relative = _workspace_path({"url": entry["path"]})
            if relative is not None:
                workspace_paths.add(relative)
            continue
        if reason:
            issue.update(reason=reason, source_type=source_type)
            inventory.unresolved.append(issue)
            non_registry_names.add(name)
            continue
        version_spec = entry.get("version")
        version = (
            version_spec[2:]
            if isinstance(version_spec, str) and version_spec.startswith("==")
            else None
        )
        if not _version(version):
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        markers = {}
        for field in sorted(_MARKER_KEYS.intersection(entry)):
            if not _marker(entry[field]):
                issue["reason"] = "invalid_environment_marker"
                inventory.unresolved.append(issue)
                break
            markers[field] = entry[field]
        else:
            optional = entry.get("optional")
            if optional is not None and type(optional) is not bool:
                issue["reason"] = "invalid_optional_flag"
                inventory.unresolved.append(issue)
                continue
            inventory.dependencies.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "file": str(path),
                    "line": line,
                    "snippet": f"{name}=={version}",
                    "exact": True,
                    "version_spec": version_spec,
                    "lockfile_version": 6,
                    "package_path": f"{group}.{name}",
                    "source_type": source_type,
                    "environment_scope": "all_locked_environments",
                    "marker_evaluation": "not_evaluated",
                    "lockfile_requires_python": python,
                    "dependency_kind": "unknown",
                    "dependency_kinds": ["unknown"],
                    "dependency_groups": [group],
                    "dependency_sections": [group],
                    "dependency_dev": True
                    if group == "develop"
                    else False
                    if group == "default"
                    else None,
                    "dependency_optional": optional,
                    "dependency_markers": markers,
                    "dependency_roots": [],
                    "dependency_graph_complete": False,
                }
            )
    inventory.non_registry_names = sorted(non_registry_names)
    inventory.workspace_paths = sorted(workspace_paths)
    return inventory
