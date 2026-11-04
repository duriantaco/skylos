"""Bounded, data-only inventory of Gradle's single-file gradle.lockfile.

Each line is ``group:artifact:version=configuration,...`` (Gradle 6.0+), plus
one ``empty=`` line for configurations without dependencies. The resolved
version is exact. The lockfile does not record which repository served an
artifact, so entries are queried by their Maven coordinates, as OSV-Scanner
and Trivy do. A module locked only in test configurations is development-only.
"""

from __future__ import annotations

import re
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)

MAX_GRADLE_LOCKFILE_BYTES = 10_000_000
_COORDINATE = re.compile(
    r"(?P<group>[A-Za-z0-9_][A-Za-z0-9_.-]{0,255})"
    r":(?P<artifact>[A-Za-z0-9_][A-Za-z0-9_.-]{0,255})"
    r":(?P<version>[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127})"
    r"=(?P<configurations>[A-Za-z0-9_,]*)\Z"
)
_EMPTY = re.compile(r"empty=[A-Za-z0-9_,]*\Z")
_CONFIGURATION = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}\Z")


def is_test_configuration(name: str) -> bool:
    return (
        name.startswith(("test", "androidTest"))
        or "UnitTest" in name
        or "AndroidTest" in name
    )


def parse_gradle_lockfile(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory locked modules without reading or running build scripts."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_GRADLE_LOCKFILE_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("gradle.lockfile is unreadable or unsafe")
    if len(text.encode("utf-8")) > MAX_GRADLE_LOCKFILE_BYTES:
        raise LockfileLimitError("gradle.lockfile exceeds byte limit")
    entries = []
    for lineno, raw_line in enumerate(text.split("\n"), 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or _EMPTY.fullmatch(line):
            continue
        match = _COORDINATE.fullmatch(line)
        if match is None:
            raise LockfileParseError(
                "gradle.lockfile line is not group:artifact:version="
            )
        configurations = [item for item in match["configurations"].split(",") if item]
        if not configurations or not all(
            _CONFIGURATION.fullmatch(item) for item in configurations
        ):
            raise LockfileParseError("gradle.lockfile configurations are invalid")
        entries.append((match, configurations, lineno))
        if len(entries) > max_packages:
            raise LockfileLimitError("gradle.lockfile exceeds package limit")
    inventory = LockfileInventory(format_version=1, package_count=len(entries))
    for match, configurations, line in entries:
        name = f"{match['group']}:{match['artifact']}"
        version = match["version"]
        inventory.dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "Maven",
                "file": str(path),
                "line": line,
                "snippet": f"{name}:{version}",
                "exact": True,
                "version_spec": version,
                "lockfile_version": 1,
                "package_path": name,
                "source_type": "registry_unspecified",
                "environment_scope": "all_locked_environments",
                "dependency_kind": "unknown",
                "dependency_kinds": ["unknown"],
                "dependency_groups": sorted(configurations),
                "dependency_dev": all(
                    is_test_configuration(item) for item in configurations
                ),
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    return inventory
