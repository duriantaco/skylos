"""Bounded, data-only inventory of Dart/Flutter pubspec.lock.

``hosted`` packages served by pub.dev (or its former pub.dartlang.org host)
are public Pub identities. ``path`` packages are the project's own code and
``sdk`` packages ship with the Dart or Flutter SDK. ``git`` packages and other
hosted servers are coverage gaps and never queried. ``direct dev`` packages
are development-only; transitive scope is not recorded.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.cargo_lockfile import semver
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.pnpm_lockfile import _LockLoader, _line

MAX_PUBSPEC_LOCK_BYTES = 10_000_000
PUB_HOSTS = frozenset({"pub.dev", "pub.dartlang.org"})
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_DEV_SCOPE = {"direct main": False, "direct dev": True, "direct overridden": None}


def public_pub_host(url: object) -> bool:
    if not isinstance(url, str) or len(url) > 2048:
        return False
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in PUB_HOSTS
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def load_pub_yaml(text: str):
    """One YAML document as data: no anchors, aliases, tags or YAML 1.1 booleans."""
    loader = _LockLoader(text)
    try:
        document = loader.get_single_data()
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("pub YAML is invalid") from exc
    finally:
        loader.dispose()
    return document


def _source(entry: dict) -> tuple[str, str | None]:
    source = entry.get("source")
    description = entry.get("description")
    if source == "path":
        return "local", None
    if source == "sdk":
        return "sdk", None
    if source == "git":
        return "git", "non_registry_source"
    if source != "hosted":
        return "unknown", "unsupported_package_source"
    if not isinstance(description, dict):
        return "unknown", "invalid_package_source"
    if public_pub_host(description.get("url")):
        return "registry", None
    if isinstance(description.get("url"), str):
        return "registry", "non_public_registry"
    return "unknown", "invalid_package_source"


def parse_pubspec_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory every locked package without reading pubspec.yaml or caches."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_PUBSPEC_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("pubspec.lock is unreadable or unsafe")
    if len(text.encode("utf-8")) > MAX_PUBSPEC_LOCK_BYTES:
        raise LockfileLimitError("pubspec.lock exceeds byte limit")
    data = load_pub_yaml(text)
    if not isinstance(data, dict):
        raise LockfileParseError("pubspec.lock must be a mapping")
    packages = data.get("packages")
    if packages is None:
        packages = {}
    if not isinstance(packages, dict):
        raise LockfileParseError("pubspec.lock packages must be a mapping")
    if len(packages) > max_packages:
        raise LockfileLimitError("pubspec.lock exceeds package limit")
    inventory = LockfileInventory(format_version=1, package_count=len(packages))
    non_registry_names = set()
    for name, entry in packages.items():
        line = _line(packages, name)
        issue = {"reason": "", "package": name, "line": line}
        if not _NAME.fullmatch(name):
            issue["reason"] = "invalid_package_name"
            inventory.unresolved.append(issue)
            continue
        issue["name"] = name
        if not isinstance(entry, dict):
            issue["reason"] = "invalid_package_entry"
            inventory.unresolved.append(issue)
            continue
        version = entry.get("version")
        if semver(version):
            issue["version"] = version
        kind, reason = _source(entry)
        if kind == "local":
            inventory.local_package_count += 1
            non_registry_names.add(name)
            inventory.not_checked.append(
                dict(issue, reason="local_package", source_type="local")
            )
            continue
        if kind == "sdk":
            non_registry_names.add(name)
            inventory.not_checked.append(
                dict(issue, reason="sdk_package", source_type="sdk")
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
        if "version" not in issue:
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        scope = entry.get("dependency")
        if not isinstance(scope, str):
            scope = "unknown"
        dependency_kind = "transitive"
        if scope.startswith("direct"):
            dependency_kind = "direct"
        inventory.dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "Pub",
                "file": str(path),
                "line": line,
                "snippet": f"{name} {version}",
                "exact": True,
                "version_spec": version,
                "lockfile_version": 1,
                "package_path": f"packages.{name}",
                "source_type": "registry",
                "environment_scope": "all_locked_environments",
                "dependency_kind": dependency_kind,
                "dependency_kinds": [dependency_kind],
                "dependency_sections": [scope],
                "dependency_dev": _DEV_SCOPE.get(scope),
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
