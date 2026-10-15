"""Bounded, data-only inventory of Bun's text lockfile ``bun.lock``.

``bun.lock`` is JSON with trailing commas (JSONC). Versions 0 and 1 come
from Bun 1.1–1.3; Bun 1.4 writes 2, and 3 when a project uses nested or
version-scoped overrides (it adds a top-level ``overrides`` object). The
``packages`` entries have the same shape in every version:

    "<install path>": ["<name>@<resolution>", "<registry>", {<details>}, "<integrity>"]

The install path is the package name, or ``parent/child`` for a copy nested
under another package. ``<registry>`` is empty for the default registry.
Workspace, ``file:`` and ``link:`` entries are the project's own code; Git,
tarball and other-registry entries have no public npm identity. Bun is never
run and no target path is read.
"""

from __future__ import annotations

import json
import re
from json.decoder import scanstring
from pathlib import Path
from urllib.parse import urlsplit

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.npm_lockfile import _exact_version, _name

_MAX_BYTES = 10_000_000
_MAX_DEPTH = 64
SUPPORTED_BUN_LOCK_VERSIONS = frozenset({0, 1, 2, 3})
_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
_LOCAL_PREFIXES = ("workspace:", "file:", "link:")
_GIT_PREFIXES = ("github:", "gitlab:", "bitbucket:", "git+", "git:", "git@")
_PACKAGE_KEY_LINE = re.compile(r'^[ \t]*"')
_SAFE_KEY = re.compile(r"[A-Za-z0-9@~._/-]{1,512}")


def _is_nested(key: str) -> bool:
    """``parent/child`` (or ``@scope/parent/child``) installs under a parent."""
    depth = 2 if key.startswith("@") else 1
    return key.count("/") >= depth


def _strip_jsonc(text: str) -> str:
    """Drop comments and trailing commas outside strings; keep line breaks."""
    out = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            try:
                _, end = scanstring(text, index + 1)
            except ValueError as exc:
                raise LockfileParseError("invalid bun.lock string") from exc
            out.append(text[index:end])
            index = end
            continue
        if char == "/" and text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
            continue
        if char == "/" and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise LockfileParseError("unterminated bun.lock comment")
            out.append("\n" * text.count("\n", index, end))
            index = end + 2
            continue
        if char == ",":
            probe = index + 1
            while probe < length and text[probe] in " \t\r\n":
                probe += 1
            if probe < length and text[probe] in "}]":
                index += 1
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _no_duplicates(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise LockfileParseError("duplicate bun.lock key")
        data[key] = value
    return data


def _depth_ok(value, depth=0) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if isinstance(value, dict):
        return all(_depth_ok(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return all(_depth_ok(item, depth + 1) for item in value)
    return True


def _package_lines(text: str, keys) -> dict[str, int]:
    """Line of each ``packages`` key; Bun writes one package per line."""
    wanted = set(keys)
    lines: dict[str, int] = {}
    in_packages = False
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not in_packages:
            in_packages = stripped.startswith('"packages"')
            continue
        if not _PACKAGE_KEY_LINE.match(raw):
            continue
        try:
            key, _ = scanstring(stripped, 1)
        except ValueError:
            continue
        if key in wanted and key not in lines:
            lines[key] = number
    return lines


def _split_label(label) -> tuple[str, str] | None:
    if not isinstance(label, str) or not 2 < len(label) <= 8192:
        return None
    position = label.find("@", 1)
    if position < 1:
        return None
    name, resolution = label[:position], label[position + 1 :]
    if _name(name) is None or not resolution:
        return None
    return name, resolution


def _registry_source(entry: list) -> tuple[str, str | None]:
    registry = entry[1] if len(entry) > 1 else ""
    if registry == "":
        # The default registry, which bunfig.toml can point elsewhere.
        return "registry_unspecified", None
    if not isinstance(registry, str) or len(registry) > 2048:
        return "unknown", "invalid_package_source"
    try:
        parsed = urlsplit(registry)
    except ValueError:
        return "unknown", "invalid_package_source"
    if (
        parsed.scheme in ("https", "http")
        and parsed.hostname == "registry.npmjs.org"
        and parsed.username is None
        and parsed.password is None
    ):
        return "npm_registry", None
    return "external", "non_registry_source"


def _workspaces(data: dict, inventory: LockfileInventory):
    workspaces = data.get("workspaces", {})
    if not isinstance(workspaces, dict):
        inventory.unresolved.append({"reason": "invalid_workspaces"})
        return {}, set()
    direct: dict[str, set[str]] = {}
    roots = set()
    for root, workspace in workspaces.items():
        if not isinstance(root, str) or not isinstance(workspace, dict):
            inventory.unresolved.append({"reason": "invalid_workspaces"})
            continue
        if root and ".." not in root.split("/") and not root.startswith("/"):
            roots.add(root)
        for section in _SECTIONS:
            values = workspace.get(section, {})
            if not isinstance(values, dict):
                inventory.unresolved.append(
                    {"reason": "invalid_dependency_section", "section": section}
                )
                continue
            for name in values:
                if isinstance(name, str):
                    direct.setdefault(name, set()).add(section)
    return direct, roots


def parse_bun_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory a ``bun.lock`` without running Bun or reading targets."""
    if text is None:
        text = read_text_no_symlink(path, max_bytes=_MAX_BYTES, encoding="utf-8")
    if text is None:
        raise LockfileParseError("lockfile cannot be read as bounded UTF-8 text")
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise LockfileLimitError("lockfile size exceeds limit")
    text = text.lstrip("\ufeff")
    try:
        data = json.loads(_strip_jsonc(text), object_pairs_hook=_no_duplicates)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("invalid bun.lock JSON") from exc
    if not isinstance(data, dict) or not _depth_ok(data):
        raise LockfileParseError("invalid bun.lock document")
    version = data.get("lockfileVersion")
    if type(version) is not int or version not in SUPPORTED_BUN_LOCK_VERSIONS:
        raise LockfileParseError("unsupported bun.lock lockfileVersion")
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        raise LockfileParseError("bun.lock packages must be an object")
    if len(packages) > max_packages:
        raise LockfileLimitError("lockfile package count exceeds limit")

    inventory = LockfileInventory(format_version=version)
    inventory.package_count = len(packages)
    direct, roots = _workspaces(data, inventory)
    inventory.workspace_paths = sorted(roots)
    lines = _package_lines(text, packages)
    non_registry = set()
    for key, entry in packages.items():
        line = lines.get(key, 1)
        problem = {
            "package": key if _SAFE_KEY.fullmatch(key) else "<invalid>",
            "line": line,
        }
        split = _split_label(entry[0]) if isinstance(entry, list) and entry else None
        if split is None:
            inventory.unresolved.append(dict(problem, reason="invalid_package_entry"))
            continue
        name, resolution = split
        if resolution.startswith(_LOCAL_PREFIXES):
            inventory.local_package_count += 1
            reason = (
                "workspace_package"
                if resolution.startswith("workspace:")
                else "local_package"
            )
            inventory.not_checked.append(
                dict(problem, reason=reason, source_type="local")
            )
            continue
        if resolution.startswith(_GIT_PREFIXES) or "://" in resolution:
            non_registry.add(name)
            inventory.unresolved.append(
                dict(
                    problem,
                    reason="non_registry_source",
                    source_type="git"
                    if resolution.startswith(_GIT_PREFIXES)
                    else "external",
                )
            )
            continue
        resolution = resolution.removeprefix("npm:")
        exact = _exact_version(resolution)
        if exact is None:
            inventory.unresolved.append(dict(problem, reason="invalid_package_version"))
            continue
        source, error = _registry_source(entry)
        if error:
            non_registry.add(name)
            inventory.unresolved.append(dict(problem, reason=error, source_type=source))
            continue
        is_direct = not _is_nested(key) and name in direct
        inventory.dependencies.append(
            {
                "name": name,
                "version": exact,
                "ecosystem": "npm",
                "file": str(path),
                "line": line,
                "snippet": f"{name}@{exact}",
                "lockfile_version": version,
                "package_path": key,
                "dependency_kind": "direct" if is_direct else "transitive",
                "dependency_kinds": ["direct" if is_direct else "transitive"],
                "dependency_sections": sorted(direct.get(name, ()))
                if is_direct
                else [],
                "environment_scope": "all_recorded",
                "source_type": source,
            }
        )
    inventory.non_registry_names = sorted(non_registry)
    return inventory
