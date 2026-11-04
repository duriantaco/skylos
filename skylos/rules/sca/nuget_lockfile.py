"""Bounded, data-only inventory of NuGet's packages.lock.json (versions 1 and 2).

NuGet restore records one resolved version per package and target framework.
``Project`` entries are other projects of the same build, not registry
packages. The lockfile does not record which feed served a package, so the
other entries are queried by their public NuGet identity, as ``dotnet``'s own
vulnerability audit does.
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

MAX_NUGET_LOCK_BYTES = 10_000_000
MAX_NUGET_VERSION_CHARS = 256
NUGET_VERSION_RE = re.compile(
    r"[0-9]+(?:\.[0-9]+){0,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
NUGET_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_FORMATS = frozenset({1, 2})
_REGISTRY_TYPES = frozenset({"Direct", "Transitive", "CentralTransitive"})
_FRAMEWORK = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_/-]{0,127}\Z")


def nuget_version(spec: str) -> tuple[str, bool] | None:
    """Return a static NuGet version and whether restore is pinned to it.

    NuGet treats 1, 1.0 and 1.0.0 as the same package version, drops a zero
    revision and build metadata, and removes leading numeric zeroes.
    """
    spec = spec.strip()
    exact = spec.startswith("[") and spec.endswith("]")
    version = spec
    if exact:
        version = spec[1:-1]
    if len(version) > MAX_NUGET_VERSION_CHARS or not NUGET_VERSION_RE.fullmatch(
        version
    ):
        return None
    without_build = version.partition("+")[0]
    numeric, separator, prerelease = without_build.partition("-")
    parts = [part.lstrip("0") or "0" for part in numeric.split(".")]
    parts.extend(["0"] * (3 - len(parts)))
    if len(parts) == 4 and parts[-1] == "0":
        parts.pop()
    normalized = ".".join(parts)
    if separator:
        normalized += f"-{prerelease}"
    return normalized, exact


def _records(data: dict, max_packages: int) -> list[tuple[str, object, object]]:
    frameworks = data.get("dependencies")
    if not isinstance(frameworks, dict):
        raise LockfileParseError("packages.lock.json dependencies must be an object")
    records = []
    for framework, packages in frameworks.items():
        if not _FRAMEWORK.fullmatch(framework) or not isinstance(packages, dict):
            raise LockfileParseError("packages.lock.json target framework is invalid")
        for name, entry in packages.items():
            records.append((framework, name, entry))
            if len(records) > max_packages:
                raise LockfileLimitError("packages.lock.json exceeds package limit")
    return records


def parse_nuget_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory every target framework without reading project files or feeds."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_NUGET_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("packages.lock.json is unreadable or unsafe")
    if len(text.encode("utf-8")) > MAX_NUGET_LOCK_BYTES:
        raise LockfileLimitError("packages.lock.json exceeds byte limit")
    try:
        data = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("packages.lock.json is not valid JSON") from exc
    if (
        not isinstance(data, dict)
        or type(data.get("version")) is not int
        or data["version"] not in _FORMATS
    ):
        raise LockfileParseError(
            "Only packages.lock.json versions 1 and 2 are supported"
        )
    records = _records(data, max_packages)
    lines = _source_lines(
        text, {("dependencies", framework, name) for framework, name, _ in records}
    )
    inventory = LockfileInventory(
        format_version=data["version"], package_count=len(records)
    )
    non_registry_names = set()
    for framework, name, entry in records:
        line = lines.get(("dependencies", framework, name), 1)
        issue = {"reason": "", "package": name, "line": line, "group": framework}
        if not NUGET_NAME_RE.fullmatch(name):
            issue["reason"] = "invalid_package_name"
            inventory.unresolved.append(issue)
            continue
        issue["name"] = name
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
            issue["reason"] = "invalid_package_entry"
            inventory.unresolved.append(issue)
            continue
        kind = entry["type"]
        if kind == "Project":
            inventory.local_package_count += 1
            non_registry_names.add(name)
            inventory.not_checked.append(
                dict(issue, reason="local_package", source_type="local")
            )
            continue
        if kind not in _REGISTRY_TYPES:
            issue["reason"] = "unsupported_package_source"
            inventory.unresolved.append(issue)
            continue
        resolved = entry.get("resolved")
        classified = None
        if isinstance(resolved, str):
            classified = nuget_version(resolved)
        if classified is None or classified[1]:
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        version = classified[0]
        dependency_kind = "transitive"
        if kind == "Direct":
            dependency_kind = "direct"
        inventory.dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "NuGet",
                "file": str(path),
                "line": line,
                "snippet": f"{name}@{resolved}",
                "version_spec": resolved,
                "exact": True,
                "conditional": False,
                "version_override": False,
                "reference_mutated": False,
                "lockfile_version": data["version"],
                "package_path": f"{framework}/{name}",
                "source_type": "registry_unspecified",
                "environment_scope": "all_locked_environments",
                "dependency_kind": dependency_kind,
                "dependency_kinds": [dependency_kind],
                "dependency_groups": [framework],
                "dependency_sections": [kind],
                "dependency_dev": None,
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
