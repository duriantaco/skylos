"""Bounded, data-only inventories for pnpm lockfile formats 6.0 and 9.0.

The v9 packages table describes sources; snapshots describe installations with
distinct peer contexts. Neither referenced paths nor package scripts are read.
"""

from __future__ import annotations

from collections import deque
import hashlib
from pathlib import Path
import posixpath
import re

import yaml

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.npm_lockfile import _exact_version, _name, _source

_MAX_BYTES = 10_000_000
_MAX_NODES = 200_000
_MAX_DEPTH = 64
_MAX_GRAPH_WORK = 100_000
_PROJECT_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_ENVIRONMENT_SECTIONS = ("configDependencies", "packageManagerDependencies")
_SECTIONS = _PROJECT_SECTIONS + _ENVIRONMENT_SECTIONS
_ENVIRONMENT_DOCUMENT_KEYS = {
    "lockfileVersion",
    "importers",
    "packages",
    "snapshots",
}


class _MarkedDict(dict):
    """A mapping with structural key positions, not text-search locations."""

    def __init__(self):
        super().__init__()
        self.lines = {}


class _LockLoader(yaml.SafeLoader):
    """Reject YAML references and oversized trees before construction."""

    def __init__(self, stream):
        self.node_count = 0
        self.node_depth = 0
        super().__init__(stream)

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise LockfileParseError(
                "lockfile YAML aliases and anchors are unsupported"
            )
        if getattr(event, "tag", None) is not None:
            raise LockfileParseError("explicit lockfile YAML tags are unsupported")
        self.node_count += 1
        self.node_depth += 1
        if self.node_count > _MAX_NODES or self.node_depth > _MAX_DEPTH:
            raise LockfileLimitError("lockfile YAML tree exceeds limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise LockfileParseError("invalid lockfile YAML mapping")
        result = _MarkedDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise LockfileParseError("lockfile YAML mapping keys must be strings")
            if key in result:
                raise LockfileParseError("duplicate lockfile YAML mapping key")
            result[key] = self.construct_object(value_node, deep=True)
            result.lines[key] = key_node.start_mark.line + 1
        return result


# pnpm's writer uses YAML 1.2. PyYAML's YAML 1.1 yes/no/on/off booleans
# otherwise corrupt valid package names and aliases. Do not mutate SafeLoader.
_LockLoader.yaml_implicit_resolvers = {
    first: [
        (tag, pattern)
        for tag, pattern in rules
        if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")
    ]
    for first, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_LockLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)
_LockLoader.add_constructor("tag:yaml.org,2002:map", _LockLoader.construct_mapping)


def _line(mapping, key, fallback=1):
    return getattr(mapping, "lines", {}).get(key, fallback)


def _root_path(value):
    if value == ".":
        return ""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\\" in value
        or ":" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
        or any(ord(char) < 32 for char in value)
    ):
        return None
    return value


def _base_key(key):
    """Strip balanced peer/patch context; retain its full key on occurrences."""
    if not isinstance(key, str) or not key or len(key) > 8192:
        return None
    depth = 0
    suffix = False
    for char in key:
        if ord(char) < 33 or ord(char) > 126:
            return None
        if char == "(":
            depth += 1
            suffix = True
            if depth > _MAX_DEPTH:
                return None
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif suffix and depth == 0:
            return None
    if depth:
        return None
    return key.partition("(")[0]


def _identity(key, version):
    base = _base_key(key)
    if base is None or (version == 6 and not base.startswith("/")):
        return None
    if version == 6:
        base = base[1:]
    name, separator, raw_version = base.rpartition("@")
    exact = _exact_version(raw_version)
    if not separator or _name(name) is None or exact is None:
        return None
    return name, exact


def _display_key(value, version):
    """Source keys may contain authenticated URLs; never copy those to output."""
    if len(value) > 8192:
        return "<invalid>"
    if any(char in value for char in (":", "?", "#", "%", "\\")) or any(
        ord(char) < 32 for char in value
    ):
        identity = _identity(value, version)
        if identity is not None:
            name, exact = identity
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            return f"{name}@{exact}(context={digest})"
        return "<non-registry>"
    return value


def _display_reference(value):
    if value.startswith(("link:", "workspace:", "file:")):
        return "<local>"
    stripped = value[4:] if value.startswith("npm:") else value
    if any(char in stripped for char in (":", "?", "#", "%", "\\")) or any(
        ord(char) < 32 for char in stripped
    ):
        return "<non-registry>"
    return value


def _source_context(metadata, snapshot, name, version, registry):
    resolution = metadata.get("resolution")
    if not isinstance(resolution, dict) or not resolution:
        return "unknown", "missing_or_invalid_resolution"
    if any(
        key in resolution for key in ("type", "repo", "commit", "directory", "path")
    ):
        source = "local" if "directory" in resolution else "external"
        if resolution.get("type") == "git" or "repo" in resolution:
            source = "git"
        return source, "non_registry_source"
    if "id" in metadata or "id" in snapshot:
        return "external", "non_registry_source"
    if ("name" in metadata and metadata["name"] != name) or (
        "version" in metadata and _exact_version(metadata["version"]) != version
    ):
        return "unknown", "conflicting_package_identity"
    if "tarball" in resolution:
        return _source({"resolved": resolution["tarball"]}, name)
    for registry_value in (registry, resolution.get("registry")):
        if registry_value is not None and registry_value not in (
            "https://registry.npmjs.org/",
            "https://registry.npmjs.org",
            "http://registry.npmjs.org/",
            "http://registry.npmjs.org",
        ):
            return "external", "non_registry_source"
    if not isinstance(resolution.get("integrity"), str) or not resolution["integrity"]:
        return "unknown", "missing_or_invalid_resolution"
    if set(resolution) - {"integrity", "registry"}:
        return "unknown", "unsupported_package_resolution"
    # Integrity alone does not establish which configured registry was used.
    return "registry_unspecified", None


def _metadata_problems(entry):
    for field in ("dev", "optional"):
        if field in entry and type(entry[field]) is not bool:
            yield {"reason": "invalid_package_metadata", "field": field}
    for field in ("os", "cpu", "libc", "transitivePeerDependencies"):
        if field in entry and (
            not isinstance(entry[field], list)
            or not all(isinstance(value, str) for value in entry[field])
        ):
            yield {"reason": "invalid_package_metadata", "field": field}
    for field in ("engines", "peerDependencies"):
        if field in entry and (
            not isinstance(entry[field], dict)
            or not all(isinstance(value, str) for value in entry[field].values())
        ):
            yield {"reason": "invalid_package_metadata", "field": field}
    for field in ("bundledDependencies", "bundleDependencies"):
        if field not in entry:
            continue
        value = entry[field]
        if type(value) is not bool and (
            not isinstance(value, list)
            or not all(_name(name) is not None for name in value)
        ):
            yield {"reason": "invalid_package_metadata", "field": field}


def _metadata_limitations(entry):
    if any(
        entry.get(field) is True
        or (
            isinstance(entry.get(field), list)
            and bool(entry[field])
            and all(_name(name) is not None for name in entry[field])
        )
        for field in ("bundledDependencies", "bundleDependencies")
    ):
        yield {"reason": "bundled_dependencies_not_enumerated"}


def _copy_marked_mapping(mapping):
    copied = _MarkedDict()
    copied.update(mapping)
    copied.lines.update(getattr(mapping, "lines", {}))
    return copied


def _merge_marked_mappings(first, second):
    """Merge lockfile tables without allowing one document to shadow another."""
    merged = _copy_marked_mapping(first)
    for key, value in second.items():
        if key in merged and merged[key] != value:
            raise LockfileParseError("conflicting pnpm lockfile documents")
        if key not in merged:
            merged[key] = value
            merged.lines[key] = _line(second, key)
    return merged


def _is_environment_document(data):
    """Recognize pnpm's narrowly defined leading environment lock document."""
    if (
        not isinstance(data, dict)
        or set(data) != _ENVIRONMENT_DOCUMENT_KEYS
        or str(data.get("lockfileVersion")) != "9.0"
    ):
        return False
    importers = data.get("importers")
    packages = data.get("packages")
    snapshots = data.get("snapshots")
    if (
        not isinstance(importers, dict)
        or set(importers) != {"."}
        or not isinstance(packages, dict)
        or not isinstance(snapshots, dict)
    ):
        return False
    root = importers["."]
    return (
        isinstance(root, dict)
        and bool(set(root) & set(_ENVIRONMENT_SECTIONS))
        and not (set(root) - set(_ENVIRONMENT_SECTIONS))
    )


def _dependency_references(data, sections):
    importers = data.get("importers", {})
    snapshots = data.get("snapshots", {})
    for table, allowed_sections in (
        (importers, sections),
        (snapshots, ("dependencies", "optionalDependencies")),
    ):
        for entry in table.values():
            if not isinstance(entry, dict):
                continue
            for section in allowed_sections:
                declarations = entry.get(section, {})
                if not isinstance(declarations, dict):
                    continue
                for name, declaration in declarations.items():
                    reference = (
                        declaration.get("version")
                        if isinstance(declaration, dict)
                        else declaration
                    )
                    if _name(name) is not None and isinstance(reference, str):
                        yield name, reference


def _reject_cross_document_repairs(environment, project):
    """Do not let either document make an incomplete peer look complete."""
    environment_packages = environment["packages"]
    environment_snapshots = environment["snapshots"]
    project_packages = project.get("packages", {})
    project_snapshots = project.get("snapshots", {})

    if any(
        reference.startswith("link:")
        for _, reference in _dependency_references(environment, _ENVIRONMENT_SECTIONS)
    ):
        raise LockfileParseError("unsupported pnpm environment dependency reference")

    for (
        importers,
        packages,
        snapshots,
        other_packages,
        other_snapshots,
        sections,
    ) in (
        (
            environment["importers"],
            environment_packages,
            environment_snapshots,
            project_packages,
            project_snapshots,
            _ENVIRONMENT_SECTIONS,
        ),
        (
            project.get("importers", {}),
            project_packages,
            project_snapshots,
            environment_packages,
            environment_snapshots,
            _SECTIONS,
        ),
    ):
        snapshot_bases = {_base_key(key) for key in snapshots}
        other_snapshot_bases = {_base_key(key) for key in other_snapshots}
        if (set(packages) - snapshot_bases) & other_snapshot_bases or (
            snapshot_bases - set(packages)
        ) & set(other_packages):
            raise LockfileParseError("cross-document pnpm package record")

        combined_snapshots = {**other_snapshots, **snapshots}
        for name, reference in _dependency_references(
            {"importers": importers, "snapshots": snapshots},
            sections,
        ):
            if (
                _reference(name, reference, 9, snapshots) is None
                and _reference(name, reference, 9, combined_snapshots) is not None
            ):
                raise LockfileParseError("cross-document pnpm dependency reference")


def _merge_environment_document(environment, project):
    """Combine pnpm's env and project inventories after strict shape checks."""
    if (
        not _is_environment_document(environment)
        or not isinstance(project, dict)
        or _is_environment_document(project)
    ):
        raise LockfileParseError("unsupported pnpm multi-document lockfile")
    if str(project.get("lockfileVersion")) != "9.0":
        raise LockfileParseError("conflicting pnpm lockfile documents")

    project_importers = project.get("importers", {})
    project_packages = project.get("packages", {})
    project_snapshots = project.get("snapshots", {})
    if not all(
        isinstance(table, dict)
        for table in (project_importers, project_packages, project_snapshots)
    ):
        raise LockfileParseError("invalid pnpm project lockfile document")
    if "." not in project_importers or not isinstance(project_importers["."], dict):
        raise LockfileParseError("pnpm project document has no root importer")
    if any(
        isinstance(importer, dict)
        and any(section in importer for section in _ENVIRONMENT_SECTIONS)
        for importer in project_importers.values()
    ):
        raise LockfileParseError("unsupported pnpm project lockfile document")
    _reject_cross_document_repairs(environment, project)

    importers = _copy_marked_mapping(project_importers)
    environment_root = environment["importers"]["."]
    importers["."] = _merge_marked_mappings(importers["."], environment_root)
    importers.lines["."] = _line(
        project_importers,
        ".",
        _line(environment["importers"], "."),
    )

    merged = _copy_marked_mapping(project)
    for key, value in (
        (
            "packages",
            _merge_marked_mappings(environment["packages"], project_packages),
        ),
        (
            "snapshots",
            _merge_marked_mappings(environment["snapshots"], project_snapshots),
        ),
        ("importers", importers),
    ):
        merged[key] = value
        merged.lines[key] = _line(
            project,
            key,
            _line(environment, key),
        )
    return merged


def _load_lockfile_document(text):
    """Load one lockfile, accepting pnpm's bounded env + project stream."""
    loader = _LockLoader(text)
    try:
        documents = []
        while loader.check_data():
            if len(documents) == 2:
                raise LockfileParseError("unsupported pnpm YAML document stream")
            documents.append(loader.get_data())
    finally:
        loader.dispose()

    if len(documents) == 1:
        if _is_environment_document(documents[0]):
            raise LockfileParseError(
                "pnpm environment document has no project document"
            )
        return documents[0]
    if len(documents) == 2:
        return _merge_environment_document(documents[0], documents[1])
    raise LockfileParseError("unsupported pnpm YAML document stream")


def _table(data, key, inventory):
    value = data.get(key, {})
    if not isinstance(value, dict):
        inventory.unresolved.append(
            {
                "reason": "invalid_lockfile_table",
                "section": key,
                "line": _line(data, key),
            }
        )
        return {}
    return value


def _reference(name, reference, version, nodes):
    if reference in nodes:
        return reference
    value = reference[4:] if reference.startswith("npm:") else reference
    base = _base_key(value)
    if base is None:
        return None
    if _exact_version(base) is not None:
        value = f"{name}@{value}"
    if version == 6 and not value.startswith("/"):
        value = "/" + value
    return value if value in nodes else None


def _contexts(adjacency, roots, records):
    contexts = {key: set() for key in records}
    kinds = {key: set() for key in records}
    queue = deque()
    seen = set()
    work = 0

    def enqueue(state):
        nonlocal work
        work += 1
        if work > _MAX_GRAPH_WORK:
            raise LockfileLimitError("lockfile dependency graph exceeds limit")
        if state not in seen:
            seen.add(state)
            queue.append(state)

    for root in roots:
        for target, group in adjacency.get(("importer", root), []):
            enqueue(
                (
                    target,
                    root,
                    group,
                    group == "devDependencies",
                    group == "optionalDependencies",
                    True,
                )
            )
    while queue:
        node, root, group, dev, optional, direct = queue.popleft()
        node_type, key = node
        if node_type == "package":
            record = records[key]
            optional = optional or record[1].get("optional") is True
            contexts[key].add((root, group, dev, optional))
            kinds[key].add("direct" if direct else "transitive")
        for target, edge_group in adjacency.get(node, []):
            if node_type == "importer" and edge_group == "devDependencies":
                continue  # A workspace link does not install that workspace's tools.
            enqueue(
                (
                    target,
                    root,
                    group,
                    dev,
                    optional or edge_group == "optionalDependencies",
                    False,
                )
            )
    return contexts, kinds


def parse_pnpm_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Read all recorded packages/environments, never evaluating their code."""
    if text is None:
        text = read_text_no_symlink(path, max_bytes=_MAX_BYTES, encoding="utf-8")
    if text is None:
        raise LockfileParseError("lockfile cannot be read as bounded UTF-8 text")
    try:
        if len(text.encode("utf-8")) > _MAX_BYTES:
            raise LockfileLimitError("lockfile size exceeds limit")
        data = _load_lockfile_document(text)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, LockfileParseError):
            raise
        raise LockfileParseError("invalid lockfile YAML") from exc
    if not isinstance(data, dict):
        raise LockfileParseError("lockfile must be a mapping")
    raw_version = data.get("lockfileVersion")
    if type(raw_version) not in (str, float) or str(raw_version) not in ("6.0", "9.0"):
        raise LockfileParseError("unsupported pnpm lockfile version")
    version = int(float(raw_version))
    inventory = LockfileInventory(format_version=version)
    packages = _table(data, "packages", inventory)
    snapshots = _table(data, "snapshots", inventory) if version == 9 else packages
    importers = (
        _table(data, "importers", inventory) if "importers" in data else {".": data}
    )
    if (
        len(packages) > max_packages
        or len(snapshots) > max_packages
        or len(importers) > max_packages
    ):
        raise LockfileLimitError("lockfile package count exceeds limit")
    if "importers" in data and any(data.get(section) for section in _SECTIONS):
        inventory.unresolved.append({"reason": "ambiguous_importer_layout", "line": 1})
        # Preserve declarations from both layouts instead of choosing a winner.
        importers = dict(importers)
        if "." not in importers:
            importers["."] = data
        else:
            inventory.unresolved.append(
                {"reason": "unread_root_declarations", "line": 1}
            )
    for field in (
        "packageManagerDependencies",
        "configDependencies",
        "ignoredOptionalDependencies",
    ):
        if data.get(field):
            inventory.unresolved.append(
                {
                    "reason": "unsupported_lockfile_section",
                    "section": field,
                    "line": _line(data, field),
                }
            )

    records = {}
    matched = set()
    for key, snapshot in snapshots.items():
        base = _base_key(key)
        metadata = packages.get(base) if version == 9 else snapshot
        line = _line(snapshots, key)
        if version == 9 and base in packages:
            matched.add(base)
        if not isinstance(snapshot, dict):
            inventory.unresolved.append(
                {
                    "reason": "invalid_package_snapshot",
                    "package": _display_key(key, version),
                    "line": line,
                }
            )
            snapshot = {}
        if not isinstance(metadata, dict):
            inventory.unresolved.append(
                {
                    "reason": "missing_package_metadata"
                    if metadata is None
                    else "invalid_package_entry",
                    "package": _display_key(key, version),
                    "line": line,
                }
            )
            metadata = {}
        records[key] = (metadata, snapshot, line)
    if version == 9:
        for key, metadata in packages.items():
            if key in matched:
                continue
            line = _line(packages, key)
            inventory.unresolved.append(
                {
                    "reason": "missing_package_snapshot",
                    "package": _display_key(key, version),
                    "line": line,
                }
            )
            if not isinstance(metadata, dict):
                inventory.unresolved.append(
                    {
                        "reason": "invalid_package_entry",
                        "package": _display_key(key, version),
                        "line": line,
                    }
                )
                metadata = {}
            records.setdefault(key, (metadata, {}, line))
    if len(records) > max_packages:
        raise LockfileLimitError("lockfile package count exceeds limit")
    roots = {}
    for key, importer in importers.items():
        root = _root_path(key)
        if root is None or not isinstance(importer, dict):
            inventory.unresolved.append(
                {
                    "reason": "invalid_importer",
                    "package": _display_key(key, version),
                    "line": _line(importers, key),
                }
            )
            continue
        roots[root] = importer
    inventory.workspace_paths = sorted(roots)
    inventory.local_package_count = len(roots)
    inventory.package_count = len(records) + len(roots)
    if inventory.package_count > max_packages:
        raise LockfileLimitError("lockfile package count exceeds limit")
    non_registry_names = set()
    aliases_by_key = {key: set() for key in records}
    adjacency = {}
    edges_by_key = {}
    edge_count = 0
    sources = [(("importer", root), importer, 1) for root, importer in roots.items()]
    sources.extend(
        (("package", key), record[1], record[2]) for key, record in records.items()
    )
    for node, entry, line in sources:
        node_type, key = node
        edges = []
        adjacency[node] = []
        sections = (
            _SECTIONS
            if node_type == "importer"
            else ("dependencies", "optionalDependencies")
        )
        for section in sections:
            declarations = entry.get(section, {})
            if not isinstance(declarations, dict):
                inventory.unresolved.append(
                    {
                        "reason": "invalid_dependency_section",
                        "package": _display_key(key, version),
                        "section": section,
                        "line": _line(entry, section, line),
                    }
                )
                continue
            for name, declaration in declarations.items():
                edge_count += 1
                if edge_count > _MAX_GRAPH_WORK:
                    raise LockfileLimitError("lockfile dependency graph exceeds limit")
                problem = {
                    "package": _display_key(key, version),
                    "dependency": name if _name(name) is not None else "<invalid>",
                    "section": section,
                    "line": _line(declarations, name, line),
                }
                reference = (
                    declaration.get("version")
                    if isinstance(declaration, dict)
                    else declaration
                )
                if (
                    _name(name) is None
                    or not isinstance(reference, str)
                    or not reference
                    or len(reference) > 8192
                ):
                    inventory.unresolved.append(
                        dict(problem, reason="invalid_dependency_declaration")
                    )
                    continue
                if node_type == "importer" and (
                    not isinstance(declaration, dict)
                    or not isinstance(declaration.get("specifier"), str)
                ):
                    inventory.unresolved.append(
                        dict(problem, reason="invalid_dependency_specifier")
                    )
                edge = {
                    "name": name,
                    "version_spec": _display_reference(reference),
                    "group": section,
                }
                if isinstance(declaration, dict) and isinstance(
                    declaration.get("specifier"), str
                ):
                    edge["specifier"] = _display_reference(declaration["specifier"])
                edges.append(edge)
                if reference.startswith("link:"):
                    non_registry_names.add(name)
                    target = posixpath.normpath(
                        posixpath.join(
                            key if node_type == "importer" else "", reference[5:]
                        )
                    )
                    normalized = "" if target == "." else _root_path(target)
                    if node_type == "importer" and normalized in roots:
                        edge["workspace"] = normalized
                        adjacency[node].append((("importer", normalized), section))
                    else:
                        inventory.unresolved.append(
                            dict(
                                problem,
                                reason="missing_link_target",
                                source_type="local",
                            )
                        )
                    continue
                resolved = _reference(name, reference, version, records)
                if resolved is None:
                    inventory.unresolved.append(
                        dict(problem, reason="missing_locked_dependency")
                    )
                    if reference.startswith(
                        ("file:", "workspace:", "git", "http:", "https:")
                    ):
                        non_registry_names.add(name)
                    continue
                edge["package_path"] = _display_key(resolved, version)
                aliases_by_key[resolved].add(name)
                adjacency[node].append((("package", resolved), section))
        if node_type == "package":
            edges_by_key[key] = edges

    contexts, kinds = _contexts(adjacency, roots, records)
    for key, (metadata, snapshot, line) in records.items():
        problem = {"package": _display_key(key, version), "line": line}
        identity = _identity(key, version)
        if identity is None:
            name = _name(metadata.get("name"))
            if name:
                non_registry_names.add(name)
            non_registry_names.update(aliases_by_key[key])
            inventory.unresolved.append(
                dict(problem, reason="non_registry_source", source_type="unknown")
            )
            continue
        name, exact = identity
        problem.update(name=name, version=exact)
        source_type, source_error = _source_context(
            metadata, snapshot, name, exact, data.get("registry")
        )
        if source_error:
            non_registry_names.add(name)
            non_registry_names.update(aliases_by_key[key])
            if _name(metadata.get("name")):
                non_registry_names.add(metadata["name"])
            inventory.unresolved.append(
                dict(problem, reason=source_error, source_type=source_type)
            )
            continue
        record_limitations = {}
        for entry in (metadata,) if metadata is snapshot else (metadata, snapshot):
            inventory.unresolved.extend(
                dict(problem, **issue) for issue in _metadata_problems(entry)
            )
            for limitation in _metadata_limitations(entry):
                record_limitations.setdefault(
                    limitation["reason"], dict(problem, **limitation)
                )
        inventory.limitations.extend(record_limitations.values())
        usage = contexts[key]
        groups = {group for _, group, _, _ in usage}
        if (
            any(optional for _, _, _, optional in usage)
            or snapshot.get("optional") is True
        ):
            groups.add("optionalDependencies")
        if metadata.get("dev") is True:
            groups.add("devDependencies")
        markers = {
            field: metadata[field]
            for field in ("os", "cpu", "libc", "engines")
            if field in metadata
        }
        if usage:
            markers["pnpm_usage"] = [
                {"root": root, "group": group, "dev": dev, "optional": optional}
                for root, group, dev, optional in sorted(usage)
            ]
        dependency = {
            "name": name,
            "version": exact,
            "ecosystem": "npm",
            "file": str(path),
            "line": line,
            "snippet": _display_key(key, version),
            "lockfile_version": version,
            "package_path": _display_key(key, version),
            "dependency_kind": "direct"
            if "direct" in kinds[key]
            else "transitive"
            if kinds[key]
            else "unknown",
            "dependency_kinds": sorted(kinds[key]) or ["unknown"],
            "dependency_roots": sorted({root for root, _, _, _ in usage}),
            "dependency_groups": sorted(groups),
            "dependency_dev": all(dev for _, _, dev, _ in usage)
            if usage
            else metadata.get("dev") is True,
            "dependency_optional": all(optional for _, _, _, optional in usage)
            if usage
            else snapshot.get("optional") is True,
            "dependency_markers": markers,
            "environment_scope": "all_recorded",
            "source_type": source_type,
            "dependencies": edges_by_key[key],
        }
        if "bundled_dependencies_not_enumerated" in record_limitations:
            dependency["dependency_graph_complete"] = False
        inventory.dependencies.append(dependency)
    inventory.non_registry_names = sorted(non_registry_names)
    return inventory
