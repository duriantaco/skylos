"""Bounded, data-only inventory of Bundler's Gemfile.lock.

Specs under a ``GEM`` source served by rubygems.org are public RubyGems
identities. ``PATH`` sources are the project's own code. ``GIT``, plugin and
other ``GEM`` remotes (mirrors, private servers) are coverage gaps and never
queried. Bundler writes a platform-specific gem as ``name (version-platform)``;
the platform is not part of the RubyGems version. The lockfile does not record
Gemfile groups, so development scope is unknown.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)

MAX_GEMFILE_LOCK_BYTES = 10_000_000
_SOURCE_SECTIONS = frozenset({"GEM", "GIT", "PATH", "PLUGIN SOURCE"})
_SECTION = re.compile(r"[A-Z][A-Z ]{0,63}\Z")
_ATTRIBUTE = re.compile(r"  (?P<key>[a-z_]{1,32}):(?: (?P<value>.*))?\Z")
_SPEC = re.compile(
    r"    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
    r" \((?P<version>[^-()\s]{1,128})(?:-(?P<platform>[A-Za-z0-9_.-]{1,64}))?\)\Z"
)
_VERSION = re.compile(r"[0-9]+(?:\.[0-9A-Za-z]+)*\Z")
_RUBYGEMS_HOSTS = frozenset({"rubygems.org", "www.rubygems.org"})


def _public_remote(remote: str) -> bool:
    try:
        url = urlsplit(remote)
        port = url.port
    except ValueError:
        return False
    return (
        url.scheme in {"https", "http"}
        and url.hostname in _RUBYGEMS_HOSTS
        and port in {None, 80, 443}
        and url.username is None
        and url.password is None
        and url.path in {"", "/"}
        and not url.query
        and not url.fragment
    )


def _source_kind(source: dict) -> tuple[str, str | None]:
    kind = source["section"]
    if kind == "PATH":
        return "local", None
    if kind == "GIT":
        return "git", "non_registry_source"
    if kind == "PLUGIN SOURCE":
        return "url", "non_registry_source"
    remotes = source["remotes"]
    if remotes and all(_public_remote(remote) for remote in remotes):
        return "registry", None
    return "registry", "non_public_registry"


def _specs(text: str, max_packages: int) -> list[tuple[dict, re.Match, int]]:
    specs = []
    source = None
    for lineno, raw_line in enumerate(text.split("\n"), 1):
        line = raw_line.removesuffix("\r")
        if not line.strip():
            continue
        if not line.startswith(" "):
            if not _SECTION.fullmatch(line):
                raise LockfileParseError("Gemfile.lock section header is invalid")
            source = None
            if line in _SOURCE_SECTIONS:
                source = {"section": line, "remotes": [], "specs": False}
            continue
        if source is None:
            continue
        if line.startswith("      "):
            if not specs or specs[-1][0] is not source:
                raise LockfileParseError("Gemfile.lock dependency has no spec")
            continue
        if line.startswith("    "):
            match = _SPEC.fullmatch(line)
            if not source["specs"] or match is None:
                raise LockfileParseError("Gemfile.lock spec line is invalid")
            specs.append((source, match, lineno))
            if len(specs) > max_packages:
                raise LockfileLimitError("Gemfile.lock exceeds package limit")
            continue
        attribute = _ATTRIBUTE.fullmatch(line)
        if attribute is None or source["specs"]:
            raise LockfileParseError("Gemfile.lock source attribute is invalid")
        if attribute["key"] == "specs":
            source["specs"] = True
        elif attribute["key"] == "remote":
            source["remotes"].append(attribute["value"] or "")
    return specs


def parse_gemfile_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory every locked gem without reading the Gemfile or gem sources."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_GEMFILE_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("Gemfile.lock is unreadable or unsafe")
    if len(text.encode("utf-8")) > MAX_GEMFILE_LOCK_BYTES:
        raise LockfileLimitError("Gemfile.lock exceeds byte limit")
    specs = _specs(text, max_packages)
    inventory = LockfileInventory(format_version=1, package_count=len(specs))
    non_registry_names = set()
    for index, (source, match, line) in enumerate(specs):
        name, raw_version = match["name"], match["version"]
        platform = match["platform"]
        issue = {"reason": "", "package": name, "name": name, "line": line}
        if _VERSION.fullmatch(raw_version):
            issue["version"] = raw_version
        kind, reason = _source_kind(source)
        if kind == "local":
            inventory.local_package_count += 1
            non_registry_names.add(name)
            inventory.not_checked.append(
                dict(issue, reason="local_package", source_type="local")
            )
            continue
        if reason:
            non_registry_names.add(name)
            inventory.not_checked.append(dict(issue, reason=reason, source_type=kind))
            continue
        if "version" not in issue:
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        markers = []
        label = f"{name} ({raw_version})"
        if platform:
            markers.append(f"platform:{platform}")
            label = f"{name} ({raw_version}-{platform})"
        inventory.dependencies.append(
            {
                "name": name,
                "version": raw_version,
                "ecosystem": "RubyGems",
                "file": str(path),
                "line": line,
                "snippet": label,
                "exact": True,
                "version_spec": raw_version,
                "lockfile_version": 1,
                "package_path": f"specs[{index}]",
                "source_type": "registry",
                "environment_scope": "all_locked_environments",
                "marker_evaluation": "not_evaluated",
                "dependency_markers": markers,
                "dependency_kind": "unknown",
                "dependency_kinds": ["unknown"],
                "dependency_dev": None,
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
