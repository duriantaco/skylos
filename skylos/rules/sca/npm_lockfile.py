"""Read npm lockfiles as bounded inventories, without installing target code."""

from __future__ import annotations

import json
import re
from json.decoder import scanstring
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)

_MAX_BYTES = 10_000_000
_MAX_DEPTH = 128
_NAME = re.compile(r"(?:@[A-Za-z0-9~][A-Za-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*\Z")
_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_SPACE = re.compile(r"\s*")
_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LockfileParseError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise LockfileParseError("invalid JSON constant")


def _source_lines(text: str, wanted: set[tuple]) -> dict[tuple, int]:
    """Locate structural keys, including escaped keys and repeated versions.

    json.loads validates the grammar first. This second walk records only the
    requested locations; it neither searches for version text nor builds a
    potentially enormous index of every newline in an untrusted document.
    """
    offsets = {}
    decoder = json.JSONDecoder()

    def visit(pos, path, depth):
        if depth > _MAX_DEPTH:
            raise LockfileLimitError("lockfile JSON nesting exceeds limit")
        pos = _SPACE.match(text, pos).end()
        char = text[pos]
        if char == "{":
            pos = _SPACE.match(text, pos + 1).end()
            if text[pos] == "}":
                return pos + 1
            while True:
                key_start = pos
                key, pos = scanstring(text, pos + 1)
                key_path = path + (key,)
                if key_path in wanted:
                    offsets[key_path] = key_start
                pos = _SPACE.match(text, pos).end() + 1  # colon
                pos = visit(pos, key_path, depth + 1)
                pos = _SPACE.match(text, pos).end()
                if text[pos] == "}":
                    return pos + 1
                pos = _SPACE.match(text, pos + 1).end()  # comma
        if char == "[":
            pos = _SPACE.match(text, pos + 1).end()
            index = 0
            if text[pos] == "]":
                return pos + 1
            while True:
                pos = visit(pos, path + (index,), depth + 1)
                pos = _SPACE.match(text, pos).end()
                if text[pos] == "]":
                    return pos + 1
                pos = _SPACE.match(text, pos + 1).end()
                index += 1
        return decoder.raw_decode(text, pos)[1]

    visit(0, (), 0)
    result = {}
    last_offset, line = 0, 1
    for path, offset in sorted(offsets.items(), key=lambda item: item[1]):
        line += text.count("\n", last_offset, offset)
        result[path] = line
        last_offset = offset
    return result


def _name(value) -> str | None:
    if isinstance(value, str) and len(value) <= 214 and _NAME.fullmatch(value):
        return value
    return None


def _exact_version(value) -> str | None:
    if not isinstance(value, str) or len(value) > 256:
        return None
    match = _VERSION.fullmatch(value)
    if match is None:
        return None
    if any(int(part) > 9007199254740991 for part in match.groups()[:3]):
        return None
    prerelease = match.group(4)
    if prerelease and any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease.split(".")
    ):
        return None
    return value.partition("+")[0]


def _installed_name(location: str) -> str | None:
    parts = location.split("/")
    if "\\" in location or any(part in (".", "..", "") for part in parts):
        return None
    segments = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not segments:
        return None
    return _name("/".join(parts[segments[-1] + 1 :]))


def _local_location(location: str) -> bool:
    return location == "" or (
        not location.startswith("/")
        and "\\" not in location
        and all(part not in ("", ".", "node_modules") for part in location.split("/"))
    )


def _source(entry: dict, name: str) -> tuple[str, str | None]:
    """Return source context and a reason when npm identity is unproven."""
    resolved = entry.get("resolved")
    if "resolved" not in entry:
        version = entry.get("version", "")
        if isinstance(version, str):
            if version.startswith(("file:", "link:", "workspace:")):
                return "local", "non_registry_source"
            if version.startswith(("git", "github:", "gitlab:", "bitbucket:")):
                return "git", "non_registry_source"
            if ":" in version and not version.startswith("npm:"):
                return "external", "non_registry_source"
        return "registry_unspecified", None
    if not isinstance(resolved, str) or not resolved or len(resolved) > 8192:
        return "unknown", "invalid_package_source"
    if resolved.startswith(("file:", "link:", "workspace:", "./", "../", "/")):
        return "local", "non_registry_source"
    if resolved.startswith(("git", "github:", "gitlab:", "bitbucket:")):
        return "git", "non_registry_source"
    try:
        parsed = urlsplit(resolved)
    except ValueError:
        return "unknown", "invalid_package_source"
    if parsed.scheme or parsed.netloc:
        if (
            parsed.scheme not in ("https", "http")
            or parsed.hostname != "registry.npmjs.org"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.netloc != "registry.npmjs.org"
        ):
            return "external", "non_registry_source"
        tarball = unquote(parsed.path).lstrip("/")
        source_type = "npm_registry"
    else:
        # v1 permits registry-relative tarball paths. The configured registry
        # cannot be established from the lockfile, as with an omitted resolved.
        tarball = unquote(parsed.path)
        source_type = "registry_unspecified"
    if not tarball.startswith(name + "/-/") or not tarball.endswith(".tgz"):
        return source_type, "unverified_registry_identity"
    return source_type, None


def _declarations(entry: dict, *, legacy=False):
    if legacy:
        requires = entry.get("requires", {})
        if isinstance(requires, dict):
            for name, spec in requires.items():
                if _name(name) is not None and isinstance(spec, str):
                    yield "dependencies", name, spec
        return
    optional = entry.get("optionalDependencies", {})
    for section in _SECTIONS:
        values = entry.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if _name(name) is None or not isinstance(spec, str):
                continue
            if (
                section == "dependencies"
                and isinstance(optional, dict)
                and name in optional
            ):
                continue
            yield section, name, spec


def _entry_problems(entry: dict, *, legacy: bool):
    """Validate context without dropping an otherwise exact package record."""
    sections = ("requires",) if legacy else _SECTIONS
    for section in sections:
        if section not in entry:
            continue
        values = entry[section]
        if not isinstance(values, dict):
            yield {"reason": "invalid_dependency_section", "section": section}
            continue
        for name, spec in values.items():
            if _name(name) is None or not isinstance(spec, str):
                issue = {"reason": "invalid_dependency_declaration", "section": section}
                if _name(name) is not None:
                    issue["dependency"] = name
                yield issue
    if (
        legacy
        and "dependencies" in entry
        and not isinstance(entry["dependencies"], dict)
    ):
        yield {"reason": "invalid_nested_dependencies"}
    if "name" in entry and _name(entry["name"]) is None:
        yield {"reason": "invalid_package_name"}
    if "version" in entry and not isinstance(entry["version"], str):
        yield {"reason": "invalid_package_version"}
    for field in ("link", "dev", "optional", "devOptional", "peer"):
        if field in entry and type(entry[field]) is not bool:
            yield {"reason": "invalid_package_metadata", "field": field}
    for field in ("os", "cpu"):
        if field in entry and (
            not isinstance(entry[field], list)
            or not all(isinstance(value, str) for value in entry[field])
        ):
            yield {"reason": "invalid_package_metadata", "field": field}
    if "engines" in entry and (
        not isinstance(entry["engines"], dict)
        or not all(isinstance(value, str) for value in entry["engines"].values())
    ):
        yield {"reason": "invalid_package_metadata", "field": "engines"}
    if "workspaces" in entry:
        workspaces = entry["workspaces"]
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages")
        if not isinstance(workspaces, list) or not all(
            isinstance(value, str) for value in workspaces
        ):
            yield {"reason": "invalid_workspaces"}
    if "peerDependenciesMeta" in entry:
        metadata = entry["peerDependenciesMeta"]
        if not isinstance(metadata, dict) or any(
            _name(name) is None
            or not isinstance(value, dict)
            or ("optional" in value and type(value["optional"]) is not bool)
            for name, value in metadata.items()
        ):
            yield {"reason": "invalid_peer_dependencies_metadata"}


def _optional_peer(entry: dict, name: str) -> bool:
    metadata = entry.get("peerDependenciesMeta", {})
    details = metadata.get(name, {}) if isinstance(metadata, dict) else {}
    return isinstance(details, dict) and details.get("optional") is True


def _resolve_path(location: str, name: str, package_paths: set[str]) -> str | None:
    if _name(name) is None:
        return None
    current = location
    while True:
        if PurePosixPath(current).name != "node_modules":
            candidate = (
                f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
            )
            if candidate in package_paths:
                return candidate
        if not current:
            return None
        parent = str(PurePosixPath(current).parent)
        if parent == current:
            return None
        current = "" if parent == "." else parent


def _records(data: dict, version: int, max_packages: int) -> list[tuple]:
    records = []
    if version >= 2:
        packages = data.get("packages")
        if not isinstance(packages, dict):
            raise LockfileParseError("lockfile packages must be an object")
        if len(packages) > max_packages:
            raise LockfileLimitError("lockfile package count exceeds limit")
        return [
            (location, entry, ("packages", location))
            for location, entry in packages.items()
        ]

    packages = data.get("dependencies", {})
    if not isinstance(packages, dict):
        raise LockfileParseError("lockfile dependencies must be an object")
    stack = [(packages, "", ("dependencies",))]
    while stack:
        entries, parent, json_path = stack.pop()
        for name, entry in entries.items():
            if len(records) >= max_packages:
                raise LockfileLimitError("lockfile package count exceeds limit")
            location = (
                f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
            )
            path = json_path + (name,)
            records.append((location, entry, path))
            if isinstance(entry, dict) and isinstance(entry.get("dependencies"), dict):
                stack.append(
                    (entry["dependencies"], location, path + ("dependencies",))
                )
    return records


def parse_package_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Parse npm lockfile versions 1–3, including every recorded environment.

    npm v1 does not distinguish hoisted transitives from direct dependencies;
    its top-level dependency kind is therefore unknown. Modern lockfiles use
    the authoritative packages table and declarations of root/workspace nodes.
    No referenced file, package script, URL, or registry is accessed here.
    """
    if text is None:
        text = read_text_no_symlink(path, max_bytes=_MAX_BYTES, encoding="utf-8")
    if text is None:
        raise LockfileParseError("lockfile cannot be read as bounded UTF-8 text")
    try:
        if len(text.encode("utf-8")) > _MAX_BYTES:
            raise LockfileLimitError("lockfile size exceeds limit")
        data = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("invalid lockfile JSON") from exc
    if not isinstance(data, dict):
        raise LockfileParseError("lockfile must be an object")
    version = data.get("lockfileVersion")
    if type(version) is not int or version not in (1, 2, 3):
        raise LockfileParseError("unsupported npm lockfile version")

    records = _records(data, version, max_packages)
    wanted = {key for _, _, key in records}
    wanted.update(key + ("version",) for _, _, key in records)
    lines = _source_lines(text, wanted)
    inventory = LockfileInventory(format_version=version, package_count=len(records))
    package_paths = {location for location, _, _ in records}
    entries = {location: entry for location, entry, _ in records}
    non_registry_names = set()
    roots = {}
    direct = {}
    if version >= 2:
        for location, entry, _ in records:
            if (
                isinstance(entry, dict)
                and _local_location(location)
                and entry.get("link") is not True
            ):
                roots[location] = entry
                for group, name, _ in _declarations(entry):
                    resolved = _resolve_path(location, name, package_paths)
                    if resolved is not None:
                        direct.setdefault(resolved, []).append((location, group))

    for location, entry, key in records:
        line = lines.get(key + ("version",), lines.get(key, 1))
        problem = {"package": location, "line": line}

        def unresolved(reason, source_type=None):
            issue = dict(problem, reason=reason)
            if source_type is not None:
                issue["source_type"] = source_type
            inventory.unresolved.append(issue)

        if not isinstance(entry, dict):
            unresolved("invalid_package_entry")
            continue
        if version >= 2 and location not in roots and _installed_name(location) is None:
            unresolved("invalid_package_path")
            continue
        inventory.unresolved.extend(
            dict(problem, **issue)
            for issue in _entry_problems(entry, legacy=version == 1)
        )
        edges = []
        for group, edge_name, spec in _declarations(entry, legacy=version == 1):
            edge = {"name": edge_name, "version_spec": spec, "group": group}
            target = _resolve_path(location, edge_name, package_paths)
            if target is not None:
                edge["package_path"] = target
            elif version >= 2 and (
                group == "dependencies"
                or (group == "devDependencies" and location in roots)
                or (
                    group == "peerDependencies" and not _optional_peer(entry, edge_name)
                )
            ):
                inventory.unresolved.append(
                    dict(
                        problem,
                        reason="missing_locked_dependency",
                        dependency=edge_name,
                        section=group,
                    )
                )
            # npm v1 'requires' merges ordinary and optional requirements, so a
            # missing v1 edge alone cannot prove that the inventory is incomplete.
            edges.append(edge)
        if version >= 2 and location in roots:
            inventory.local_package_count += 1
            local_name = _name(
                entry.get("name", data.get("name") if location == "" else None)
            )
            if local_name is not None:
                non_registry_names.add(local_name)
            continue
        if version >= 2 and entry.get("link") is True:
            inventory.local_package_count += 1
            installed_name = _installed_name(location)
            if installed_name is not None:
                non_registry_names.add(installed_name)
            else:
                unresolved("invalid_package_name")
            target = entry.get("resolved")
            target_entry = entries.get(target) if isinstance(target, str) else None
            if not isinstance(target_entry, dict) or target_entry.get("link") is True:
                unresolved("missing_link_target", "local")
            elif _name(target_entry.get("name")) is not None:
                non_registry_names.add(target_entry["name"])
            continue
        installed_name = _name(key[-1]) if version == 1 else _installed_name(location)
        name = _name(entry.get("name", installed_name))
        raw_version = entry.get("version")
        if isinstance(raw_version, str) and raw_version.startswith("npm:"):
            alias_name, separator, raw_version = raw_version[4:].rpartition("@")
            name = _name(alias_name) if separator else None
        if name is None or installed_name is None:
            unresolved("invalid_package_name")
            continue
        problem.update(name=name, installed_name=installed_name)
        exact_version = _exact_version(raw_version)
        if exact_version is not None:
            problem["version"] = exact_version
        source_type, source_error = _source(entry, name)
        if source_error:
            unresolved(source_error, source_type)
            continue
        if exact_version is None:
            reason = (
                "non_exact_version"
                if isinstance(raw_version, str)
                else "missing_or_invalid_version"
            )
            unresolved(reason, source_type)
            continue
        groups = {group for _, group in direct.get(location, [])}
        for flag, group in (
            ("dev", "devDependencies"),
            ("optional", "optionalDependencies"),
            ("devOptional", "devOptional"),
            ("peer", "peerDependencies"),
        ):
            if entry.get(flag) is True:
                groups.add(group)
        if location in direct:
            kind = "direct"
        elif roots or location.split("/").count("node_modules") > 1:
            kind = "transitive"
        else:
            kind = "unknown"
        dependency = {
            "name": name,
            "version": exact_version,
            "ecosystem": "npm",
            "file": str(path),
            "line": line,
            "snippet": f"{name}@{raw_version} ({location})",
            "lockfile_version": version,
            "package_path": location,
            "dependency_kind": kind,
            "dependency_groups": sorted(groups),
            "dependency_markers": {
                field: entry[field]
                for field in ("os", "cpu", "engines")
                if field in entry
            },
            "dependency_optional": entry.get("optional") is True,
            "dependency_dev": entry.get("dev") is True,
            "source_type": source_type,
            "dependencies": edges,
        }
        if location in direct:
            dependency["dependency_roots"] = sorted(
                {root for root, _ in direct[location]}
            )
        inventory.dependencies.append(dependency)
    inventory.non_registry_names = sorted(non_registry_names)
    inventory.workspace_paths = sorted(roots)
    return inventory
