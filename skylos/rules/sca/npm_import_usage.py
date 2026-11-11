"""Static import evidence for exact, directly declared npm lock entries."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import unicodedata
from urllib.parse import unquote, urlsplit

from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.commands.hook_package_versions import (
    npm_satisfies,
    parse_npm_range,
    parse_npm_version,
)
from skylos.core.js_ast import is_type_only, node_text
from skylos.core.safe_cache_io import (
    _close_file_descriptor,
    _directory_open_flags,
    read_project_text_no_symlink,
)
from skylos.rules.ai_defect.js_api_hallucination import _NODE_BUILTINS
from skylos.rules.sca.npm_lockfile import (
    _SECTIONS,
    _exact_version,
    _installed_name,
    _invalid_constant,
    _name,
    _resolve_path,
    _source,
    _unique_object,
)

_LOCKS = ("npm-shrinkwrap.json", "package-lock.json")
_OTHER_LOCKS = ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", ".pnp.cjs")
_CONFIGS = ("tsconfig.json", "jsconfig.json")
_CUSTOM_RESOLVERS = tuple(
    f"{name}.config.{suffix}"
    for name in ("vite", "webpack", "rollup", "next", "esbuild", "rspack")
    for suffix in ("js", "cjs", "mjs", "ts", "cts", "mts")
)
_MARKERS = ("package.json", *_LOCKS, *_OTHER_LOCKS, *_CONFIGS, *_CUSTOM_RESOLVERS)
_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
_TYPE_CONTEXTS = frozenset(
    {
        "ambient_declaration",
        "implements_clause",
        "interface_declaration",
        "type_alias_declaration",
        "type_annotation",
        "type_arguments",
        "type_parameter",
        "type_query",
    }
)
_KIND = frozenset({"static_import", "reexport", "dynamic_import", "require"})
_UNKNOWN = frozenset(
    {
        "no_import_evidence",
        "ambiguous_identity",
        "unsupported_lockfile",
        "source_scope_unavailable",
        "source_incomplete",
    }
)
_SELECTION_KINDS = frozenset(
    {
        "repository_root",
        "repository_root_with_exclusions",
        "subdirectory",
        "file",
        "multiple_paths",
        "changed_files",
        "symlink",
    }
)
_MAX_SITES = 5
_MAX_PATH = 512
_MAX_DEPTH = 64
_MAX_FILES = 5000
_MAX_FILE_BYTES = 512 * 1024
_MAX_LOCK_BYTES = 10_000_000
_MAX_TOTAL_BYTES = 24 * 1024 * 1024
_MAX_FILE_NODES = 20_000
_MAX_TOTAL_NODES = 500_000
_MAX_READS = 8192
_MAX_PATH_PROBES = 50_000
_MAX_RESOLUTIONS = 10_000
_MAX_ALIAS_CHECKS = 100_000
_MAX_ALIAS_PATTERNS = 512


def _safe_path(value) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_PATH
        and "\\" not in value
        and ":" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and not any(unicodedata.category(char).startswith("C") for char in value)
        and sanitize_untrusted_text(
            value, max_length=_MAX_PATH, neutralize_mentions=False
        )
        == value
    )


def normalize_npm_import_usage(value) -> dict | None:
    """Validate and bound an import evidence record for report transports."""
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int:
        return None
    status = value.get("status")
    reason = value.get("reason")
    scope = value.get("identity_scope")
    raw_sites = value.get("sites")
    if (
        value["schema_version"] != 1
        or not isinstance(reason, str)
        or not isinstance(raw_sites, list)
    ):
        return None
    sites = []
    seen = set()
    for row in raw_sites[:_MAX_SITES]:
        if not isinstance(row, dict):
            return None
        file = row.get("file")
        line = row.get("line")
        kind = row.get("kind")
        type_only = row.get("type_only")
        if (
            not _safe_path(file)
            or type(line) is not int
            or not 0 < line <= 2**31 - 1
            or not isinstance(kind, str)
            or kind not in _KIND
            or type(type_only) is not bool
        ):
            return None
        key = (file, line, kind, type_only)
        if key not in seen:
            seen.add(key)
            sites.append(dict(file=file, line=line, kind=kind, type_only=type_only))
    if status == "imported":
        valid = (
            reason == "observed_static_import"
            and scope == "locked_occurrence"
            and any(not row["type_only"] for row in sites)
        )
    elif status == "unknown" and reason == "type_only_import":
        valid = (
            scope == "locked_occurrence"
            and bool(sites)
            and all(row["type_only"] for row in sites)
        )
    else:
        valid = (
            status == "unknown"
            and reason in _UNKNOWN
            and scope == "unknown"
            and not sites
        )
    if not valid:
        return None
    return dict(
        schema_version=1,
        status=status,
        reason=reason,
        identity_scope=scope,
        sites=sites,
    )


def _usage_metadata(reason, sites=()):
    return {
        "schema_version": 1,
        "status": "imported" if reason == "observed_static_import" else "unknown",
        "reason": reason,
        "identity_scope": "locked_occurrence" if sites else "unknown",
        "sites": list(sites),
    }


def _advisory_identity(metadata):
    vuln_id = metadata.get("vuln_id")
    if (
        metadata.get("ecosystem") != "npm"
        or metadata.get("malicious") is True
        or not isinstance(vuln_id, str)
        or not vuln_id
        or vuln_id.upper().startswith("MAL-")
    ):
        return None
    name = _name(metadata.get("package_name"))
    version = _exact_version(metadata.get("package_version"))
    return (name, version) if name and version else None


def _package_specifier(value: str) -> str | None:
    if (
        not value
        or len(value) > _MAX_PATH
        or "\\" in value
        or value in _NODE_BUILTINS
        or any(not part for part in value.split("/"))
    ):
        return None
    segments = value.split("/")
    package_length = 2 if value.startswith("@") else 1
    if any(part in {".", ".."} for part in segments):
        return None
    if any(
        not all(char.isascii() and (char.isalnum() or char in "._~-") for char in part)
        for part in segments[package_length:]
    ):
        return None
    return _name("/".join(segments[:package_length]))


def _module_literal(source, node):
    if node is None or node.end_byte - node.start_byte > _MAX_PATH + 2:
        return None
    text = node_text(source, node)
    if node.type == "string" and text[:1] in {"'", '"'} and text[-1:] == text[:1]:
        return text[1:-1]
    if node.type == "template_string" and all(
        child.type == "string_fragment" for child in node.named_children
    ):
        return text[1:-1]
    return None


def _only_type_specifiers(node):
    if is_type_only(node):
        return True
    for child in node.named_children:
        if child.type == "import_clause":
            parts = [part for part in child.named_children if part.type != "comment"]
            if len(parts) != 1 or parts[0].type != "named_imports":
                return False
            child = parts[0]
        if child.type in {"named_imports", "export_clause"}:
            specifiers = [
                part for part in child.named_children if part.type != "comment"
            ]
            return bool(specifiers) and all(is_type_only(part) for part in specifiers)
    return False


def _require_callee(node):
    parent = node.parent
    return parent is not None and (
        parent.type == "call_expression"
        and parent.child_by_field_name("function") == node
    )


def _source_imports(root_node, source, file, package_type, targeted_names):
    """Collect syntax sites, declining bare require if its binding is uncertain."""
    suffix = Path(file).suffix.lower()
    require_safe = suffix in {".cjs", ".cts"} or (
        suffix not in {".mjs", ".mts"} and package_type in (None, "commonjs")
    )
    declaration = file.lower().endswith(_DECLARATION_SUFFIXES)
    stack = [(root_node, declaration)]
    sites = []
    while stack:
        node, type_context = stack.pop()
        type_context = type_context or node.type in _TYPE_CONTEXTS
        stack.extend((child, type_context) for child in reversed(node.named_children))
        if node.type == "with_statement":
            require_safe = False
        if node.type in {
            "identifier",
            "property_identifier",
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
        }:
            name = node_text(source, node)
            if (
                "\\" in name
                or name == "eval"
                or (name == "require" and not _require_callee(node))
            ):
                require_safe = False
        if node.type in {"import_statement", "export_statement"}:
            if suffix not in {".cjs", ".cts"}:
                require_safe = False
            kind = "static_import" if node.type == "import_statement" else "reexport"
            literal = _module_literal(source, node.child_by_field_name("source"))
            type_only = type_context or _only_type_specifiers(node)
        elif node.type == "call_expression":
            callee = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if callee is None or args is None or args.type != "arguments":
                continue
            if callee.type == "import":
                kind = "dynamic_import"
            elif callee.type == "identifier" and node_text(source, callee) == "require":
                kind = "require"
            else:
                continue
            arguments = [part for part in args.named_children if part.type != "comment"]
            if not arguments or (kind == "require" and len(arguments) != 1):
                continue
            literal = _module_literal(source, arguments[0])
            type_only = type_context
        else:
            continue
        package = _package_specifier(literal or "")
        if package in targeted_names:
            sites.append(
                (
                    literal,
                    package,
                    dict(
                        file=file,
                        line=node.start_point.row + 1,
                        kind=kind,
                        type_only=type_only,
                    ),
                )
            )
    return [row for row in sites if require_safe or row[2]["kind"] != "require"]


def _declared_specs(entry, name):
    specs = {}
    for section in _SECTIONS:
        declarations = entry.get(section, {})
        if not isinstance(declarations, dict):
            return None
        if name in declarations:
            spec = declarations[name]
            if not isinstance(spec, str):
                return None
            specs[section] = spec
    # npm's optional declaration overrides the same name in dependencies.
    if "optionalDependencies" in specs:
        specs.pop("dependencies", None)
    return specs


def _matches_version(spec, installed_name, name, version):
    if spec.startswith("npm:"):
        alias_target, sep, spec = spec[4:].rpartition("@")
        if not sep or alias_target != name:
            return False
    elif installed_name != name:
        return False
    parsed = parse_npm_version(version)
    constraint = parse_npm_range(spec)
    return (
        parsed is not None
        and constraint is not None
        and npm_satisfies(parsed, constraint)
    )


def _entry_identity(entry, installed_name):
    if (
        not isinstance(entry, dict)
        or entry.get("link", False) is not False
        or entry.get("inBundle", False) is not False
    ):
        return None
    name = _name(entry.get("name", installed_name))
    raw_version = entry.get("version")
    version = _exact_version(raw_version)
    if not name or not version or _source(entry, name) != ("npm_registry", None):
        return None
    resolved = entry["resolved"]
    if not resolved.startswith("https://"):
        return None
    url = urlsplit(resolved)
    tarball = f"/{name}/-/{name.rsplit('/', 1)[-1]}-{raw_version}.tgz"
    if url.query or url.fragment or unquote(url.path) != tarball:
        return None
    return name, version


class _Scan:
    def __init__(self, root, occurrences, targeted_names):
        self.root = root
        self.occurrences = occurrences
        self.targeted_names = targeted_names
        self.ambiguous_names = set()
        self.reasons = Counter()
        self.counts = Counter()
        self.marker_cache = {}
        self.data_cache = {}
        self.lock_paths_cache = {}
        self.resolution_cache = {}

    def read(self, path, max_bytes):
        self.counts["read_attempts"] += 1
        if (
            self.counts["read_attempts"] > _MAX_READS
            or self.counts["bytes_read"] + max_bytes > _MAX_TOTAL_BYTES
        ):
            self.reasons["read_budget"] += 1
            return None
        data = read_project_text_no_symlink(
            self.root, path, max_bytes=max_bytes, newline=""
        )
        if data is None:
            self.reasons["unreadable_or_oversized"] += 1
            return None
        self.counts["bytes_read"] += len(data.encode("utf-8"))
        return data

    def markers(self, parent):
        if parent not in self.marker_cache:
            self.marker_cache[parent] = self._read_markers(parent)
        return self.marker_cache[parent]

    def _read_markers(self, parent):
        if self.counts["path_probes"] + len(_MARKERS) > _MAX_PATH_PROBES:
            self.reasons["path_probe_budget"] += 1
            return None
        self.counts["path_probes"] += len(_MARKERS)
        flags = _directory_open_flags()
        fd = None
        present = set()
        try:
            fd = os.open(self.root, flags)
            for part in parent.parts:
                child = os.open(part, flags, dir_fd=fd)
                _close_file_descriptor(fd)
                fd = child
            for name in _MARKERS:
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                present.add(name)
            return present
        except OSError:
            self.reasons["unreadable_source_directory"] += 1
            return None
        finally:
            _close_file_descriptor(fd)

    def data(self, path, *, lock=False, config=False):
        if path not in self.data_cache:
            raw = self.read(path, _MAX_LOCK_BYTES if lock else _MAX_FILE_BYTES)
            data = None
            if raw is not None:
                try:
                    raw = raw.removeprefix("\ufeff")
                    if config:
                        from skylos.visitors.languages.typescript.workspace import (
                            _strip_json_comments,
                            _strip_trailing_commas,
                        )

                        raw = _strip_trailing_commas(_strip_json_comments(raw))
                    data = json.loads(
                        raw,
                        object_pairs_hook=_unique_object,
                        parse_constant=_invalid_constant,
                    )
                except (ValueError, RecursionError):
                    self.reasons["invalid_metadata"] += 1
            self.data_cache[path] = data if isinstance(data, dict) else None
        return self.data_cache[path]

    def locate(self, parents):
        manifest = None
        for parent in parents:
            markers = self.markers(parent)
            if markers is None or markers.intersection(_OTHER_LOCKS):
                return None, None
            if manifest is None and "package.json" in markers:
                manifest = parent / "package.json"
            lock = next((parent / name for name in _LOCKS if name in markers), None)
            if lock is not None:
                return manifest, lock
        return None, None

    def mapped(self, parents, literal):
        for parent in parents:
            markers = self.markers(parent)
            if markers is None or markers.intersection(_CUSTOM_RESOLVERS):
                return True
            for filename in _CONFIGS:
                if filename not in markers:
                    continue
                config = self.data(parent / filename, config=True)
                if config is None or "extends" in config:
                    return True
                options = config.get("compilerOptions", {})
                if not isinstance(options, dict) or "baseUrl" in options:
                    return True
                mappings = options.get("paths", {})
                if not isinstance(mappings, dict):
                    return True
                if (
                    len(mappings) > _MAX_ALIAS_PATTERNS
                    or self.counts["alias_checks"] + len(mappings) > _MAX_ALIAS_CHECKS
                ):
                    self.reasons["alias_budget"] += 1
                    return True
                self.counts["alias_checks"] += len(mappings)
                for pattern in mappings:
                    prefix, star, suffix = pattern.partition("*")
                    if (not star and literal == pattern) or (
                        star
                        and literal.startswith(prefix)
                        and literal.endswith(suffix)
                        and len(literal) >= len(prefix) + len(suffix)
                    ):
                        return True
        return False

    def resolve(self, file, parents, manifest, lock, literal, package):
        key = (file.parent, literal)
        if key not in self.resolution_cache:
            if len(self.resolution_cache) >= _MAX_RESOLUTIONS:
                self.reasons["resolution_budget"] += 1
                return None
            identity = self._resolve(file, parents, manifest, lock, literal, package)
            self.resolution_cache[key] = identity
        return self.resolution_cache[key]

    def _resolve(self, file, parents, manifest, lock, literal, package):
        manifest_data = self.data(manifest)
        if not manifest_data or manifest_data.get("name") == package:
            return None
        manager = manifest_data.get("packageManager")
        if manager is not None and (
            not isinstance(manager, str) or not manager.startswith("npm@")
        ):
            return None
        data = self.data(lock, lock=True)
        if data is None or type(data.get("lockfileVersion")) is not int:
            return None
        version = data["lockfileVersion"]
        entries = data.get("packages")
        if (
            version not in (2, 3)
            or not isinstance(entries, dict)
            or len(entries) > 5000
        ):
            return None
        scope = manifest.parent.relative_to(lock.parent).as_posix()
        scope = "" if scope == "." else scope
        locked_manifest = entries.get(scope)
        if not isinstance(locked_manifest, dict) or locked_manifest.get("link") is True:
            return None
        specs = _declared_specs(manifest_data, package)
        if not specs or specs != _declared_specs(locked_manifest, package):
            return None
        if lock not in self.lock_paths_cache:
            self.lock_paths_cache[lock] = set(entries)
        package_paths = self.lock_paths_cache[lock]
        location = file.parent.relative_to(lock.parent).as_posix()
        location = "" if location == "." else location
        install_path = _resolve_path(location, package, package_paths)
        if install_path is None or install_path != _resolve_path(
            scope, package, package_paths
        ):
            return None
        identity = _entry_identity(entries[install_path], package)
        if identity is None or not all(
            _matches_version(spec, package, *identity) for spec in specs.values()
        ):
            return None
        if (lock, install_path, scope, version, identity) not in self.occurrences:
            return None
        if self.mapped(parents, literal):
            return None
        return identity


def _inventory_index(root, inventory, identities):
    occurrences = set()
    supported = set()
    direct = set()
    targeted_names = defaultdict(set)
    for row in getattr(inventory, "occurrences", ()):
        if row.get("ecosystem") != "npm" or row.get("lockfile_version") not in (2, 3):
            continue
        path = Path(row["file"])
        if path.name not in _LOCKS:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        identity = (row.get("name"), row.get("version"))
        if identity not in identities:
            continue
        supported.add(identity)
        if row.get("source_type") != "npm_registry":
            continue
        installed_name = _installed_name(row["package_path"])
        if installed_name is None:
            continue
        for scope in row.get("dependency_roots", ()):
            direct.add(identity)
            targeted_names[installed_name].add(identity)
            occurrences.add(
                (
                    relative,
                    row["package_path"],
                    scope,
                    row["lockfile_version"],
                    identity,
                )
            )
    return occurrences, supported, direct, targeted_names


def _selected_sources(root, paths, reasons):
    selected = set()
    for raw in paths or ():
        path = Path(raw)
        if path.suffix.lower() not in _SUFFIXES:
            continue
        if path.is_absolute():
            try:
                path = path.relative_to(root)
            except ValueError:
                reasons["outside_root"] += 1
                continue
        if (
            not _safe_path(path.as_posix())
            or len(path.parts) > _MAX_DEPTH
            or "node_modules" in path.parts
            or ".git" in path.parts
        ):
            reasons["outside_root"] += 1
            continue
        selected.add(path)
        if len(selected) > _MAX_FILES:
            reasons["file_budget"] += 1
            break
    return sorted(selected)[:_MAX_FILES]


def _record_site(sites, site):
    if site in sites:
        return
    if len(sites) < _MAX_SITES:
        sites.append(site)
    elif not site["type_only"] and all(row["type_only"] for row in sites):
        sites[-1] = site


def _collect(scan, sources):
    from skylos.visitors.languages.typescript.analysis import _entry_parser_for_path

    evidence = defaultdict(list)
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        scan.reasons["no_follow_unavailable"] += 1
        return evidence
    for file in sources:
        parents = tuple(file.parents)
        manifest, lock = scan.locate(parents)
        if manifest is None or lock is None:
            scan.counts["sources_without_supported_project"] += 1
            if scan.reasons["path_probe_budget"]:
                break
            continue
        manifest_data = scan.data(manifest)
        if manifest_data is None:
            continue
        raw = scan.read(file, _MAX_FILE_BYTES)
        if raw is None:
            if scan.reasons["read_budget"]:
                break
            continue
        source = raw.encode("utf-8")
        parser = _entry_parser_for_path(file.as_posix())
        tree = parser.parse(source) if parser is not None else None
        if tree is None or tree.root_node.has_error:
            scan.reasons["parse_failed"] += 1
            continue
        root_node = tree.root_node
        count = root_node.descendant_count
        if count > _MAX_FILE_NODES:
            scan.reasons["file_node_budget"] += 1
            continue
        if scan.counts["nodes_visited"] + count > _MAX_TOTAL_NODES:
            scan.reasons["total_node_budget"] += 1
            break
        scan.counts["nodes_visited"] += count
        scan.counts["sources_parsed"] += 1
        package_type = manifest_data.get("type")
        for literal, name, site in _source_imports(
            root_node, source, file.as_posix(), package_type, scan.targeted_names
        ):
            identity = scan.resolve(file, parents, manifest, lock, literal, name)
            if identity is not None:
                _record_site(evidence[identity], site)
            else:
                scan.ambiguous_names.add(name)
    return evidence


def enrich_npm_import_usage(
    findings, root, *, source_files, inventory, source_scope=None
):
    """Attach bounded import evidence without modifying advisory decisions."""
    advisories = []
    for finding in findings:
        metadata = finding.get("metadata")
        identity = _advisory_identity(metadata) if isinstance(metadata, dict) else None
        if identity is not None:
            advisories.append((metadata, identity))
    if not advisories:
        return {"schema_version": 1, "status": "not_applicable"}

    root = Path(root).resolve()
    identities = {identity for _, identity in advisories}
    occurrences, supported, direct, targeted_names = _inventory_index(
        root, inventory, identities
    )
    scan = _Scan(root, occurrences, targeted_names)
    sources = _selected_sources(root, source_files, scan.reasons)
    evidence = _collect(scan, sources) if sources and occurrences else {}
    ambiguous = {
        identity for name in scan.ambiguous_names for identity in targeted_names[name]
    }
    outcome_counts = Counter()
    for metadata, identity in advisories:
        sites = evidence.get(identity, ())
        if any(not site["type_only"] for site in sites):
            reason = "observed_static_import"
        elif sites:
            reason = "type_only_import"
        elif not sources and scan.reasons:
            reason = "source_incomplete"
        elif not sources:
            reason = "source_scope_unavailable"
        elif identity not in supported:
            reason = "unsupported_lockfile"
        elif scan.reasons:
            reason = "source_incomplete"
        elif identity in ambiguous or identity not in direct:
            reason = "ambiguous_identity"
        else:
            reason = "no_import_evidence"
        metadata["import_usage"] = _usage_metadata(reason, sites)
        outcome_counts[reason] += 1

    scope = source_scope or {}
    kind = scope.get("kind")
    selection = {
        "kind": kind
        if isinstance(kind, str) and kind in _SELECTION_KINDS
        else "unknown",
        "complete_repository": scope.get("complete_repository") is True,
        "changed_files_only": scope.get("changed_files_only") is True,
    }
    if scan.reasons or scan.counts["sources_without_supported_project"]:
        status = "partial"
    elif not sources:
        status = "no_source"
    elif not supported:
        status = "unsupported_lockfile"
    else:
        status = "complete"
    return {
        "schema_version": 1,
        "status": status,
        "selection": selection,
        "counts": {"selected_sources": len(sources), **scan.counts},
        "limits": {
            "files": _MAX_FILES,
            "file_bytes": _MAX_FILE_BYTES,
            "total_bytes": _MAX_TOTAL_BYTES,
            "file_nodes": _MAX_FILE_NODES,
            "total_nodes": _MAX_TOTAL_NODES,
            "path_probes": _MAX_PATH_PROBES,
            "resolutions": _MAX_RESOLUTIONS,
            "alias_checks": _MAX_ALIAS_CHECKS,
        },
        "reasons": dict(scan.reasons),
        "outcomes": dict(outcome_counts),
    }
