"""Bounded, data-only Yarn Classic v1 and Berry v4/v6/v8 inventories.

Yarn lockfiles do not separate production from development dependencies. Berry
also omits virtual peer installations. Keep that uncertainty instead of
inventing installed contexts; preserve recorded declarations and conditions.
"""

from __future__ import annotations

from collections import deque
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import yaml

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.npm_lockfile import _exact_version, _name, _source
from skylos.rules.sca.pnpm_lockfile import _LockLoader, _MarkedDict, _line, _root_path

_MAX_BYTES = 10_000_000
_MAX_NODES = 200_000
_MAX_GRAPH_WORK = 100_000
_MAX_DEPTH = 64
_BERRY_VERSIONS = {4, 6, 8}
_HEADER = re.compile(r"^#\s*yarn lockfile v(\d+)\s*$", re.MULTILINE)
_BARE = re.compile(r"[^\s:,\"#]+")
_SAFE_SPEC = re.compile(r"[A-Za-z0-9@~^*+._|<>= /-]+\Z")


def _classic_tokens(line):
    tokens = []
    position = 0
    decoder = json.JSONDecoder()
    while position < len(line):
        char = line[position]
        if char == " ":
            position += 1
            continue
        if char == "#":
            break
        if char in ":,":
            tokens.append((char, char))
            position += 1
            continue
        if char == '"':
            try:
                value, position = decoder.raw_decode(line, position)
            except ValueError as exc:
                raise LockfileParseError("invalid Classic quoted value") from exc
        else:
            match = _BARE.match(line, position)
            if match is None:
                raise LockfileParseError("invalid Classic token")
            value = match.group()
            position = match.end()
        tokens.append(("value", value))
    return tokens


def _classic_document(text):
    """Read the writer's indentation grammar, not YAML or executable JS."""
    data = _MarkedDict()
    stack = [data]
    nodes = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise LockfileParseError("invalid Classic indentation")
        indent = len(raw) - len(raw.lstrip(" "))
        depth = indent // 2
        if indent % 2 or depth >= len(stack):
            raise LockfileParseError("invalid Classic indentation")
        if depth > _MAX_DEPTH:
            raise LockfileLimitError("lockfile nesting exceeds limit")
        stack = stack[: depth + 1]
        tokens = _classic_tokens(raw[indent:])
        nodes += len(tokens)
        if nodes > _MAX_NODES:
            raise LockfileLimitError("lockfile tree exceeds limit")
        if not tokens or tokens[0][0] != "value":
            raise LockfileParseError("invalid Classic declaration")
        keys = [tokens[0][1]]
        cursor = 1
        while cursor < len(tokens) and tokens[cursor][0] == ",":
            cursor += 1
            if cursor >= len(tokens) or tokens[cursor][0] != "value":
                raise LockfileParseError("invalid Classic selector list")
            keys.append(tokens[cursor][1])
            cursor += 1
        tokens = tokens[cursor:]
        nested = tokens == [(":", ":")]
        if nested:
            value = _MarkedDict()
        else:
            if tokens and tokens[0][0] == ":":
                tokens.pop(0)
            if len(tokens) != 1 or tokens[0][0] != "value" or len(keys) != 1:
                raise LockfileParseError("invalid Classic value")
            value = tokens[0][1]
        if depth and len(keys) != 1:
            raise LockfileParseError("nested Classic selector lists unsupported")
        key = ", ".join(keys)
        if key in stack[-1]:
            raise LockfileParseError("duplicate Classic mapping key")
        stack[-1][key] = value
        stack[-1].lines[key] = number
        if nested:
            stack.append(value)
    return data


def _document(text):
    headers = _HEADER.findall(text)
    if headers:
        if headers != ["1"]:
            raise LockfileParseError("unsupported Yarn Classic lockfile version")
        return 1, _classic_document(text)
    try:
        loader = _LockLoader(text)
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("invalid Yarn lockfile YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("__metadata"), dict):
        raise LockfileParseError("missing Yarn lockfile version")
    version = data["__metadata"].get("version")
    if type(version) is not int or version not in _BERRY_VERSIONS:
        raise LockfileParseError("unsupported Yarn Berry lockfile version")
    return version, data


def _descriptor(value):
    if not isinstance(value, str) or len(value) > 8192:
        return None
    position = value.find("@", 1)
    name, reference = value[:position], value[position + 1 :]
    if position < 1 or _name(name) is None or not reference:
        return None
    return name, reference


def _npm_reference(name, reference):
    """Return actual registry identity; npm aliases name a different package."""
    if reference.startswith("npm:"):
        reference = reference[4:]
        alias = _descriptor(reference)
        if alias:
            name, reference = alias
    if not reference or _SAFE_SPEC.fullmatch(reference) is None:
        return None
    # Bare slash references are GitHub shorthands, not npm semver/tag ranges.
    if "/" in reference or "@" in reference:
        return None
    return name, reference


def _display_spec(reference):
    if reference.startswith(("workspace:", "link:", "portal:", "file:")):
        return "<local>"
    if _npm_reference("package", reference) is not None:
        return reference
    return "<non-registry>"


def _key(value):
    # Descriptors can contain private URLs, credentials, local paths and patches.
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise LockfileParseError("invalid lockfile UTF-8 value") from exc
    return "yarn:" + hashlib.sha256(encoded).hexdigest()


def _classic_source(entry, name):
    resolved = entry.get("resolved")
    if isinstance(resolved, str):
        try:
            parsed = urlsplit(resolved)
        except ValueError:
            return "unknown", "invalid_package_source"
        if parsed.netloc == "registry.yarnpkg.com" and parsed.scheme in (
            "https",
            "http",
        ):
            entry = dict(
                entry, resolved=parsed._replace(netloc="registry.npmjs.org").geturl()
            )
    return _source(entry, name)


def _identity(entry, descriptors, version):
    if version == 1:
        identities = [_npm_reference(*descriptor) for descriptor in descriptors]
        if any(identity is None for identity in identities):
            if all(
                reference.startswith(("file:", "link:", "workspace:"))
                for _, reference in descriptors
            ):
                return None, "local", "unsupported_package_source", None
            return None, "external", "non_registry_source", None
        names = {identity[0] for identity in identities}
        if len(names) != 1:
            return None, "unknown", "conflicting_package_identity", None
        name = names.pop()
        exact = _exact_version(entry.get("version"))
        source, problem = _classic_source(entry, name)
    else:
        locator = _descriptor(entry.get("resolution"))
        if locator is None:
            return None, "unknown", "invalid_package_source", None
        name, reference = locator
        if reference.startswith("workspace:"):
            root = _root_path(reference[len("workspace:") :])
            return (
                None,
                "local",
                None if root is not None else "invalid_workspace_path",
                root,
            )
        if reference.startswith(("link:", "portal:")):
            return None, "local", "unsupported_package_source", None
        if not reference.startswith("npm:"):
            return None, "external", "non_registry_source", None
        identity = _npm_reference(name, reference)
        if identity is None:
            return None, "external", "non_registry_source", None
        name, raw_version = identity
        exact = _exact_version(raw_version)
        if exact is not None and _exact_version(entry.get("version")) != exact:
            return None, "unknown", "conflicting_package_identity", None
        # npm: locators do not identify which configured registry served them.
        source, problem = "registry_unspecified", None
        if entry.get("linkType", "hard") != "hard":
            return None, "unknown", "conflicting_package_source", None
        for alias, spec in descriptors:
            declared = _npm_reference(alias, spec)
            if declared is None:
                return None, "external", "non_registry_source", None
            if declared[0] != name:
                return None, "unknown", "conflicting_package_identity", None
    if exact is None:
        return None, source, "invalid_package_version", None
    if problem:
        return None, source, problem, None
    return (name, exact), source, None, None


def _metadata(entry, problem, inventory):
    result = {}
    for field in ("dependenciesMeta", "peerDependenciesMeta"):
        table = entry.get(field, {})
        if not isinstance(table, dict):
            inventory.unresolved.append(
                dict(problem, reason="invalid_package_metadata", field=field)
            )
            continue
        clean = {}
        for name, values in table.items():
            descriptor = _descriptor(name)
            valid_name = _name(name) is not None or (
                descriptor is not None and _exact_version(descriptor[1]) is not None
            )
            if (
                not valid_name
                or not isinstance(values, dict)
                or any(
                    key not in {"optional", "built", "unplugged"}
                    or type(value) is not bool
                    for key, value in values.items()
                )
            ):
                inventory.unresolved.append(
                    dict(problem, reason="invalid_package_metadata", field=field)
                )
            else:
                clean[name] = dict(values)
        if clean:
            result[field] = clean
    if "conditions" in entry:
        conditions = entry["conditions"]
        if isinstance(conditions, str) and len(conditions) <= 8192:
            # Conditions are uninterpreted environment evidence, never evaluated.
            result["conditions"] = (
                conditions
                if re.fullmatch(r"[A-Za-z0-9._=!&| ()-]+", conditions)
                else _key(conditions)
            )
        else:
            inventory.unresolved.append(
                dict(problem, reason="invalid_package_metadata", field="conditions")
            )
    return result


def parse_yarn_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory recorded packages without executing Yarn or reading targets."""
    if text is None:
        text = read_text_no_symlink(path, max_bytes=_MAX_BYTES, encoding="utf-8")
    if text is None:
        raise LockfileParseError("lockfile cannot be read as bounded UTF-8 text")
    try:
        if len(text.encode("utf-8")) > _MAX_BYTES:
            raise LockfileLimitError("lockfile size exceeds limit")
        version, data = _document(text.lstrip("\ufeff"))
    except UnicodeError as exc:
        raise LockfileParseError("invalid lockfile UTF-8 text") from exc
    inventory = LockfileInventory(format_version=version)
    records = {key: value for key, value in data.items() if key != "__metadata"}
    if len(records) > max_packages:
        raise LockfileLimitError("lockfile package count exceeds limit")
    inventory.package_count = len(records)
    descriptors = {}
    information = {}
    non_registry = set()
    roots = {}
    work = 0
    for key, entry in records.items():
        problem = {"package": _key(key), "line": _line(data, key)}
        grouped = []
        for selector in re.split(r" *, *", key):
            work += 1
            if work > _MAX_GRAPH_WORK:
                raise LockfileLimitError("lockfile descriptor count exceeds limit")
            descriptor = _descriptor(selector)
            if descriptor is None:
                inventory.unresolved.append(
                    dict(problem, reason="invalid_package_descriptor")
                )
                continue
            if selector in descriptors:
                raise LockfileParseError("duplicate Yarn package descriptor")
            descriptors[selector] = key
            grouped.append(descriptor)
            if version in {4, 6} and ":" not in descriptor[1]:
                normalized = f"{descriptor[0]}@npm:{descriptor[1]}"
                if normalized in descriptors and descriptors[normalized] != key:
                    raise LockfileParseError("duplicate Yarn package descriptor")
                descriptors[normalized] = key
        if not isinstance(entry, dict) or not grouped:
            inventory.unresolved.append(dict(problem, reason="invalid_package_entry"))
            continue
        identity, source, error, workspace = _identity(entry, grouped, version)
        if source == "local":
            inventory.local_package_count += 1
        if workspace is not None:
            roots[key] = workspace
        if identity is None:
            non_registry.update(name for name, _ in grouped)
            for descriptor in grouped:
                public_identity = _npm_reference(*descriptor)
                if public_identity is not None:
                    non_registry.add(public_identity[0])
            locator = _descriptor(entry.get("resolution"))
            if locator:
                non_registry.add(locator[0])
        if error:
            inventory.unresolved.append(dict(problem, reason=error, source_type=source))
        markers = _metadata(entry, problem, inventory)
        information[key] = (identity, source, grouped, markers)
    inventory.workspace_paths = sorted(set(roots.values()))
    inventory.non_registry_names = sorted(non_registry)

    adjacency = {key: [] for key in records}
    edges = {}
    for key, (identity, source, grouped, markers) in information.items():
        entry = records[key]
        problem = {"package": _key(key), "line": _line(data, key)}
        edges[key] = []
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            table = entry.get(section, {})
            if not isinstance(table, dict):
                inventory.unresolved.append(
                    dict(problem, reason="invalid_dependency_section", section=section)
                )
                continue
            for name, reference in table.items():
                work += 1
                if work > _MAX_GRAPH_WORK:
                    raise LockfileLimitError("lockfile dependency graph exceeds limit")
                if (
                    _name(name) is None
                    or not isinstance(reference, str)
                    or not reference
                    or len(reference) > 8192
                ):
                    inventory.unresolved.append(
                        dict(
                            problem,
                            reason="invalid_dependency_declaration",
                            section=section,
                        )
                    )
                    continue
                metadata = markers.get(
                    "peerDependenciesMeta"
                    if section == "peerDependencies"
                    else "dependenciesMeta",
                    {},
                ).get(name, {})
                optional = (
                    section == "optionalDependencies"
                    or metadata.get("optional") is True
                )
                edge = {
                    "name": name,
                    "version_spec": _display_spec(reference),
                    "group": section,
                    "optional": optional,
                }
                edges[key].append(edge)
                if section == "peerDependencies":
                    # Lockfiles do not record the virtual provider installation.
                    continue
                target = descriptors.get(f"{name}@{reference}")
                if target is None and version != 1:
                    normalized = reference if ":" in reference else "npm:" + reference
                    target = descriptors.get(f"{name}@{normalized}")
                if target is None:
                    inventory.unresolved.append(
                        dict(
                            problem,
                            reason="missing_locked_dependency",
                            dependency=name,
                            section=section,
                        )
                    )
                    continue
                edge["package_path"] = _key(target)
                if target in roots:
                    edge["workspace"] = roots[target]
                adjacency[key].append((target, optional))

    usage = {key: set() for key in records}
    kinds = {key: set() for key in records}
    queue = deque((key, root, False, True) for key, root in roots.items())
    seen = set()
    while queue:
        key, root, optional, direct = queue.popleft()
        state = key, root, optional, direct
        if state in seen:
            continue
        seen.add(state)
        work += 1
        if work > _MAX_GRAPH_WORK:
            raise LockfileLimitError("lockfile dependency graph exceeds limit")
        for target, edge_optional in adjacency[key]:
            target_optional = optional or edge_optional
            usage[target].add((root, target_optional))
            kinds[target].add("direct" if direct else "transitive")
            queue.append((target, root, target_optional, False))

    for key, (identity, source, grouped, markers) in information.items():
        if identity is None:
            continue
        name, exact = identity
        markers["yarn_descriptors"] = [
            f"{alias}@{_display_spec(spec)}" for alias, spec in grouped
        ]
        if usage[key]:
            markers["yarn_usage"] = [
                {"root": root, "optional": optional}
                for root, optional in sorted(usage[key])
            ]
        inventory.dependencies.append(
            {
                "name": name,
                "version": exact,
                "ecosystem": "npm",
                "file": str(path),
                "line": _line(data, key),
                "snippet": f"{name}@{exact}",
                "lockfile_version": version,
                "package_path": _key(key),
                "dependency_kind": "direct"
                if "direct" in kinds[key]
                else "transitive"
                if kinds[key]
                else "unknown",
                "dependency_kinds": sorted(kinds[key]) or ["unknown"],
                "dependency_roots": sorted({root for root, _ in usage[key]}),
                "dependency_markers": markers,
                "environment_scope": "all_recorded",
                "source_type": source,
                "dependencies": edges[key],
            }
        )
    return inventory
