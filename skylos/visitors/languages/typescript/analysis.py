from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

from skylos.file_discovery import should_exclude_path

from .nextjs import (
    NEXTJS_CONVENTION_EXPORTS,
    NEXTJS_CONVENTION_FILES,
    is_nextjs_convention_export,
    is_nextjs_convention_file,
    is_nextjs_pages_api_file,
    is_nextjs_pages_router_file,
)
from .resolve import (
    _find_nearest_tsconfig,
    _parse_tsconfig_references,
    _resolve_path_target,
)

_NEXTJS_CONVENTION_EXPORTS = NEXTJS_CONVENTION_EXPORTS
_NEXTJS_CONVENTION_FILES = NEXTJS_CONVENTION_FILES
_is_nextjs_convention_file = is_nextjs_convention_file
_TS_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx")
_TS_JS_ENTRY_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    "/index.ts",
    "/index.tsx",
    "/index.js",
    "/index.jsx",
)


def resolve_ts_module(source: str, importer: str, monorepo_resolver=None) -> str | None:
    if not source.startswith("."):
        if monorepo_resolver:
            return monorepo_resolver.resolve(source, importer)
        return None
    base = os.path.dirname(importer)
    target = os.path.normpath(os.path.join(base, source))

    candidates: list[str] = []
    if target.endswith(".js"):
        candidates.extend(
            [target[:-3] + ".ts", target[:-3] + ".tsx", target, target[:-3] + ".jsx"]
        )
    elif target.endswith(".jsx"):
        candidates.extend([target[:-4] + ".tsx", target[:-4] + ".js", target])
    else:
        candidates.append(target)

    for suffix in _TS_JS_ENTRY_SUFFIXES:
        candidate = target + suffix
        candidates.append(candidate)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            return candidate
    return None


def build_ts_import_graph(ts_raw_imports: dict, defs: dict, monorepo_resolver=None):
    consumed_exports = defaultdict(set)
    wildcard_edges = defaultdict(set)
    importers_of = defaultdict(set)

    for importer_file, raw_imports in ts_raw_imports.items():
        for imp in raw_imports:
            resolved = resolve_ts_module(
                imp["source"], str(importer_file), monorepo_resolver
            )
            if resolved:
                importers_of[resolved].add(str(importer_file))
                for name in imp["names"]:
                    if name == "*":
                        wildcard_edges[str(importer_file)].add(resolved)
                    else:
                        actual_name = (
                            name.split(" as ")[0].strip() if " as " in name else name
                        )
                        consumed_exports[resolved].add(actual_name)
                    target_key = f"{resolved}:{name}"
                    if target_key in defs:
                        defs[target_key].references += 1

    _resolve_wildcard_consumed(consumed_exports, wildcard_edges, defs)
    _resolve_reexport_aliases(consumed_exports, ts_raw_imports, defs, monorepo_resolver)
    _resolve_namespace_reexports(
        consumed_exports, wildcard_edges, defs, ts_raw_imports, monorepo_resolver
    )

    return consumed_exports, wildcard_edges, importers_of


def _resolve_wildcard_consumed(consumed_exports, wildcard_edges, defs):
    if not wildcard_edges:
        return

    local_defs_by_file = defaultdict(set)
    for defn in defs.values():
        if defn.type != "import":
            local_defs_by_file[str(defn.filename)].add(defn.simple_name)

    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for reexporter, sources in wildcard_edges.items():
            consumed_from_reexporter = consumed_exports.get(reexporter, set())
            if not consumed_from_reexporter:
                continue
            local_names = local_defs_by_file.get(reexporter, set())
            pass_through = consumed_from_reexporter - local_names
            if not pass_through:
                continue
            for source_file in sources:
                source_defs = local_defs_by_file.get(source_file, set())
                for name in pass_through:
                    if name in source_defs:
                        before = len(consumed_exports[source_file])
                        consumed_exports[source_file].add(name)
                        if len(consumed_exports[source_file]) > before:
                            changed = True
                            target_key = f"{source_file}:{name}"
                            if target_key in defs:
                                defs[target_key].references += 1


def _resolve_reexport_aliases(
    consumed_exports, ts_raw_imports, defs, monorepo_resolver=None
):
    reexport_aliases: dict[str, dict[str, str]] = {}

    for importer_file, raw_imports in ts_raw_imports.items():
        for imp in raw_imports:
            resolved = resolve_ts_module(
                imp["source"], str(importer_file), monorepo_resolver
            )
            if not resolved:
                continue
            for name in imp["names"]:
                if " as " in name:
                    original, alias = name.split(" as ", 1)
                    original = original.strip()
                    alias = alias.strip()
                    reexport_aliases.setdefault(str(importer_file), {})[alias] = (
                        original,
                        resolved,
                    )

    if not reexport_aliases:
        return

    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for reexporter, alias_map in reexport_aliases.items():
            consumed_from_reexporter = consumed_exports.get(reexporter, set())
            for alias, (original, source_file) in alias_map.items():
                if alias in consumed_from_reexporter:
                    before = len(consumed_exports[source_file])
                    consumed_exports[source_file].add(original)
                    if len(consumed_exports[source_file]) > before:
                        changed = True
                        target_key = f"{source_file}:{original}"
                        if target_key in defs:
                            defs[target_key].references += 1


def _resolve_namespace_reexports(
    consumed_exports, wildcard_edges, defs, ts_raw_imports, monorepo_resolver=None
):
    local_defs_by_file = defaultdict(set)
    for defn in defs.values():
        if defn.type != "import":
            local_defs_by_file[str(defn.filename)].add(defn.simple_name)

    for reexporter, sources in wildcard_edges.items():
        consumed_from_reexporter = consumed_exports.get(reexporter, set())
        if not consumed_from_reexporter:
            continue

        for source_file in sources:
            for importer_file, raw_imports in ts_raw_imports.items():
                if str(importer_file) != reexporter:
                    continue
                for imp in raw_imports:
                    resolved = resolve_ts_module(
                        imp["source"], str(importer_file), monorepo_resolver
                    )
                    if resolved != source_file:
                        continue
                    if "*" in imp["names"]:
                        ns_names = set()
                        for dk, dv in defs.items():
                            if str(dv.filename) == reexporter and dv.type == "import":
                                ns_names.add(dv.simple_name)
                        for ns_name in ns_names:
                            if ns_name in consumed_from_reexporter:
                                source_defs = local_defs_by_file.get(source_file, set())
                                for name in source_defs:
                                    consumed_exports[source_file].add(name)
                                    target_key = f"{source_file}:{name}"
                                    if target_key in defs:
                                        defs[target_key].references += 1


def demote_unconsumed_ts_exports(defs, consumed_exports):
    demoted = []
    for _name, defn in defs.items():
        if not defn.is_exported:
            continue
        if not str(defn.filename).endswith(_TS_JS_EXTENSIONS):
            continue
        if defn.type == "import":
            continue

        consumed = consumed_exports.get(str(defn.filename), set())
        if defn.simple_name not in consumed:
            defn.is_exported = False
            demoted.append(defn)
    return demoted


_TEST_SUFFIXES = (
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.jsx",
)

_CONFIG_FILES = frozenset(
    {
        "vitest.config.ts",
        "vitest.config.mts",
        "vitest.config.js",
        "vitest.config.mjs",
        "jest.config.ts",
        "jest.config.js",
        "jest.config.cjs",
        "tsconfig.ts",
        "source.config.ts",
        "source.config.tsx",
        "source.config.js",
        "source.config.jsx",
        "tailwind.config.ts",
        "tailwind.config.js",
        "tailwind.config.cjs",
        "next.config.ts",
        "next.config.mts",
        "next.config.js",
        "next.config.mjs",
        "postcss.config.ts",
        "postcss.config.js",
        "postcss.config.cjs",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.js",
        "eslint.config.mjs",
        "vite.config.ts",
        "vite.config.mts",
        "vite.config.js",
        "vite.config.mjs",
    }
)

_TS_ENTRY_FILES = frozenset(
    {
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "main.ts",
        "main.tsx",
        "main.js",
        "main.jsx",
    }
)


def _is_ts_entry_or_infra(sf: str) -> bool:
    if sf.endswith(_TEST_SUFFIXES) or "/__tests__/" in sf:
        return True
    if "/test/" in sf or "/tests/" in sf:
        return True
    if "/bench/" in sf or "/benchmark/" in sf or "/benchmarks/" in sf:
        return True
    if sf.endswith(".d.ts"):
        return True
    if "/scripts/" in sf:
        return True
    basename = os.path.basename(sf)
    if is_nextjs_pages_router_file(sf) or is_nextjs_pages_api_file(sf):
        return True
    if basename in _NEXTJS_CONVENTION_FILES:
        return True
    if basename in _CONFIG_FILES:
        return True
    return False


def _resolve_exclude_root(files, project_root: str | None) -> Path | None:
    if project_root:
        return Path(project_root).resolve()

    resolved_files: list[Path] = []
    for file_path in files:
        p = Path(str(file_path))
        try:
            resolved_files.append(p.resolve())
        except OSError:
            continue

    if not resolved_files:
        return None

    try:
        common_root = Path(os.path.commonpath([str(path) for path in resolved_files]))
    except ValueError:
        return None

    if common_root.is_file():
        return common_root.parent.resolve()
    return common_root.resolve()


def _is_excluded_path(path_str: str, exclude_folders, root_path: Path | None) -> bool:
    if not exclude_folders or root_path is None:
        return False

    path = Path(path_str)
    if not path.is_absolute():
        path = root_path / path

    return should_exclude_path(path.resolve(), root_path, exclude_folders)


def _read_json_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _iter_package_entry_targets(entry):
    if isinstance(entry, str):
        yield entry
        return
    if isinstance(entry, list):
        for item in entry:
            yield from _iter_package_entry_targets(item)
        return
    if isinstance(entry, dict):
        for value in entry.values():
            yield from _iter_package_entry_targets(value)


def _discover_package_entry_files(package_root: str) -> set[str]:
    data = _read_json_file(os.path.join(package_root, "package.json"))
    if not data:
        return set()

    targets: list[str] = []
    seen_targets: set[str] = set()
    for field in (
        "main",
        "module",
        "types",
        "typings",
        "source",
        "browser",
        "bin",
        "exports",
    ):
        for target in _iter_package_entry_targets(data.get(field)):
            if target in seen_targets:
                continue
            seen_targets.add(target)
            targets.append(target)

    entry_files: set[str] = set()
    for target in targets:
        resolved = _resolve_path_target(package_root, target)
        if resolved:
            entry_files.add(os.path.realpath(resolved))
    return entry_files


def _workspace_package_roots(workspace_inventory) -> list[Path]:
    package_roots: set[Path] = set()
    if (
        workspace_inventory
        and workspace_inventory.root_package
        and workspace_inventory.root_package.has_package_json
    ):
        package_roots.add(workspace_inventory.root_package.root.resolve())
    if workspace_inventory:
        for workspace in workspace_inventory.packages:
            if workspace.has_package_json and (
                "package.json:workspaces" in workspace.discovered_from
                or "pnpm-workspace.yaml" in workspace.discovered_from
            ):
                package_roots.add(workspace.root.resolve())
    return sorted(package_roots, key=lambda path: len(str(path)), reverse=True)


def _find_owning_package_root(
    file_path: Path, package_roots: list[Path]
) -> Path | None:
    for package_root in package_roots:
        try:
            file_path.relative_to(package_root)
            return package_root
        except ValueError:
            continue
    return None


def _discover_referenced_package_roots(
    files, project_root: str, workspace_inventory, exclude_folders=None
) -> set[Path]:
    project_root_path = Path(project_root).resolve()
    exclude_root = _resolve_exclude_root(files, project_root)
    package_roots = _workspace_package_roots(workspace_inventory)
    if not package_roots:
        return set()

    referenced_roots: set[Path] = set()
    active_tsconfigs: set[str] = set()

    for file_path in {
        Path(str(f)).resolve()
        for f in files
        if str(f).endswith(_TS_JS_EXTENSIONS)
        and not _is_excluded_path(str(f), exclude_folders, exclude_root)
    }:
        owning_package_root = _find_owning_package_root(file_path, package_roots)
        if owning_package_root is None:
            continue
        tsconfig = _find_nearest_tsconfig(str(file_path), project_root)
        if tsconfig:
            active_tsconfigs.add(os.path.realpath(tsconfig))

    for tsconfig in active_tsconfigs:
        for ref_root in _parse_tsconfig_references(tsconfig):
            resolved_root = Path(ref_root).resolve()
            try:
                resolved_root.relative_to(project_root_path)
            except ValueError:
                continue
            if (resolved_root / "package.json").is_file():
                referenced_roots.add(resolved_root)

    return referenced_roots


def _discover_ts_reachability_entry_files(
    files,
    project_root: str | None = None,
    workspace_inventory=None,
    exclude_folders=None,
) -> set[str]:
    exclude_root = _resolve_exclude_root(files, project_root)
    ts_files = {
        os.path.realpath(str(f))
        for f in files
        if str(f).endswith(_TS_JS_EXTENSIONS)
        and not _is_excluded_path(str(f), exclude_folders, exclude_root)
    }
    if not ts_files:
        return set()

    entry_files = {
        tf
        for tf in ts_files
        if os.path.basename(tf) in _TS_ENTRY_FILES or _is_ts_entry_or_infra(tf)
    }

    if not project_root or workspace_inventory is None:
        return entry_files

    package_roots = set(_workspace_package_roots(workspace_inventory))
    package_roots.update(
        _discover_referenced_package_roots(
            files,
            project_root,
            workspace_inventory,
            exclude_folders=exclude_folders,
        )
    )

    for package_root in package_roots:
        entry_files.update(_discover_package_entry_files(str(package_root)))

    return entry_files & ts_files


def _is_ts_reachability_root(path: str, entry_files: set[str]) -> bool:
    real_path = os.path.realpath(path)
    return real_path in entry_files


def find_dead_ts_files(
    files,
    exclude_folders,
    importers_of,
    wildcard_edges,
    project_root: str | None = None,
    workspace_inventory=None,
):
    exclude_root = _resolve_exclude_root(files, project_root)
    ts_files = set()
    for f in files:
        sf = str(f)
        if not sf.endswith(_TS_JS_EXTENSIONS):
            continue
        if _is_excluded_path(sf, exclude_folders, exclude_root):
            continue
        if _is_ts_entry_or_infra(sf):
            continue
        ts_files.add(os.path.realpath(sf))

    norm_importers = defaultdict(set)
    for target, importers in importers_of.items():
        real_target = os.path.realpath(target)
        for imp in importers:
            norm_importers[real_target].add(os.path.realpath(imp))
    for reexporter, sources in wildcard_edges.items():
        for src in sources:
            norm_importers[os.path.realpath(src)].add(os.path.realpath(reexporter))

    entry_points = _discover_ts_reachability_entry_files(
        files,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
    )

    dead_set = set()
    for tf in ts_files - entry_points:
        if not norm_importers.get(tf):
            dead_set.add(tf)

    changed = True
    iterations = 0
    while changed and iterations < 50:
        changed = False
        iterations += 1
        for tf in ts_files - entry_points - dead_set:
            live_importers = norm_importers.get(tf, set()) - dead_set
            if not live_importers:
                dead_set.add(tf)
                changed = True

    dead_files = []
    for tf in sorted(dead_set):
        dead_files.append(
            {
                "rule_id": "SKY-E003",
                "message": "Unused TypeScript/JavaScript file (not imported by any other file)",
                "file": tf,
                "line": 1,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }
        )
    return dead_files


def find_unused_ts_exports(
    demoted_exports,
    wildcard_edges,
    files=None,
    exclude_folders=None,
    project_root: str | None = None,
    workspace_inventory=None,
):
    if not demoted_exports:
        return []

    candidate_files: list[str] = [str(defn.filename) for defn in demoted_exports]
    for reexporter, sources in wildcard_edges.items():
        candidate_files.append(reexporter)
        candidate_files.extend(sources)
    analysis_files = files if files is not None else candidate_files
    entry_points = _discover_ts_reachability_entry_files(
        analysis_files,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
    )

    api_surface = set()
    if wildcard_edges:
        reexported_by = defaultdict(set)
        for reexporter, sources in wildcard_edges.items():
            for src in sources:
                reexported_by[os.path.realpath(src)].add(os.path.realpath(reexporter))

        for src_real in reexported_by:
            visited = set()
            queue = [src_real]
            reaches_entry = False
            while queue:
                current = queue.pop()
                if current in visited:
                    continue
                visited.add(current)
                if _is_ts_reachability_root(current, entry_points):
                    reaches_entry = True
                    break
                for parent in reexported_by.get(current, []):
                    queue.append(parent)
            if reaches_entry:
                api_surface.add(src_real)

    findings = []
    for defn in demoted_exports:
        if defn.references <= 0:
            continue
        fname = str(defn.filename)
        if _is_ts_reachability_root(fname, entry_points):
            continue
        if defn.type == "method":
            continue
        if os.path.realpath(fname) in api_surface:
            continue
        if is_nextjs_convention_export(defn.simple_name, fname):
            continue
        findings.append(
            {
                "rule_id": "SKY-E004",
                "name": defn.simple_name,
                "message": (
                    f"Unnecessary `export` on `{defn.simple_name}` "
                    f"(used internally but not imported by any other file)"
                ),
                "file": fname,
                "line": defn.line,
                "type": defn.type,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }
        )
    return findings
