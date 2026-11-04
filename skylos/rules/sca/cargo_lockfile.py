"""Bounded, data-only inventory of Cargo.lock (lockfile versions 1 to 4).

Cargo records every resolved package with its source id. Only the crates.io
index (git or sparse protocol) is a public crates.io identity. Packages with
no source are workspace members or path dependencies: the project's own code.
Git sources and other registries are reported as coverage gaps and never
queried. Cargo.lock does not record dev/build scopes.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.poetry_lockfile import _tree_bound
from skylos.rules.sca.uv_lockfile import _package_lines

MAX_CARGO_LOCK_BYTES = 10_000_000
CRATES_IO_SOURCES = frozenset(
    {
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    }
)
_FORMATS = frozenset({1, 2, 3, 4})
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_MAX_SOURCE_CHARS = 4096


def _name(value: object) -> str | None:
    if isinstance(value, str) and _NAME.fullmatch(value):
        return value
    return None


def semver(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 256 and bool(_SEMVER.fullmatch(value))
    )


def _source(package: dict) -> tuple[str, str | None]:
    """Return (source type, reason it is not queried) from a Cargo source id."""
    if "source" not in package:
        return "local", None
    source = package["source"]
    if (
        not isinstance(source, str)
        or not source
        or len(source) > _MAX_SOURCE_CHARS
        or any(char.isspace() or ord(char) < 32 for char in source)
    ):
        return "unknown", "invalid_package_source"
    if source in CRATES_IO_SOURCES:
        return "registry", None
    if source.startswith("git+"):
        return "git", "non_registry_source"
    if source.startswith("path+"):
        return "local", None
    if source.startswith(("registry+", "sparse+")):
        return "registry", "non_public_registry"
    return "unknown", "unsupported_package_source"


def parse_cargo_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory every locked package without reading Cargo.toml or sources."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_CARGO_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        raise LockfileParseError("Cargo.lock is unreadable, unsafe or oversized")
    if len(text.encode("utf-8")) > MAX_CARGO_LOCK_BYTES:
        raise LockfileLimitError("Cargo.lock exceeds byte limit")
    try:
        data = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise LockfileParseError("Cargo.lock is not valid TOML") from exc
    _tree_bound(data)
    format_version = data.get("version", 1)
    if type(format_version) is not int or format_version not in _FORMATS:
        raise LockfileParseError("Unsupported Cargo.lock version; expected 1 to 4")
    packages = data.get("package", [])
    if not isinstance(packages, list) or not all(
        isinstance(package, dict) for package in packages
    ):
        raise LockfileParseError("Cargo.lock must contain a package array")
    if len(packages) > max_packages:
        raise LockfileLimitError("Cargo.lock exceeds package limit")
    lines = []
    if packages:
        try:
            lines = _package_lines(text + "\n")
        except LockfileParseError as exc:
            raise LockfileParseError(
                "Unsupported Cargo.lock TOML location syntax"
            ) from exc
    if len(lines) != len(packages):
        raise LockfileParseError("Cargo.lock packages must use [[package]] tables")
    inventory = LockfileInventory(
        format_version=format_version, package_count=len(packages)
    )
    non_registry_names = set()
    for index, (package, line) in enumerate(zip(packages, lines)):
        name = _name(package.get("name"))
        version = package.get("version")
        issue = {"reason": "", "package": package.get("name"), "line": line}
        if name is None:
            issue["reason"] = "invalid_package_name"
            inventory.unresolved.append(issue)
            continue
        issue.update(package=name, name=name)
        if semver(version):
            issue["version"] = version
        kind, reason = _source(package)
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
        if not semver(version):
            issue["reason"] = "invalid_locked_version"
            inventory.unresolved.append(issue)
            continue
        inventory.dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "crates.io",
                "file": str(path),
                "line": line,
                "snippet": f"{name} {version}",
                "exact": True,
                "version_spec": version,
                "lockfile_version": format_version,
                "package_path": f"package[{index}]",
                "source_type": "registry",
                "environment_scope": "all_locked_environments",
                "dependency_kind": "unknown",
                "dependency_kinds": ["unknown"],
                "dependency_dev": None,
                "dependency_roots": [],
                "dependency_graph_complete": False,
            }
        )
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
