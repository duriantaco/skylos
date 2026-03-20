from __future__ import annotations

import os
from collections import defaultdict

def resolve_ts_module(source: str, importer: str) -> str | None:
    if not source.startswith("."):
        return None
    base = os.path.dirname(importer)
    target = os.path.normpath(os.path.join(base, source))

    if target.endswith(".js"):
        ts_target = target[:-3] + ".ts"
        if os.path.isfile(ts_target):
            return ts_target
        tsx_target = target[:-3] + ".tsx"
        if os.path.isfile(tsx_target):
            return tsx_target
    elif target.endswith(".jsx"):
        tsx_target = target[:-4] + ".tsx"
        if os.path.isfile(tsx_target):
            return tsx_target

    for suffix in (".ts", ".tsx", "/index.ts", "/index.tsx"):
        candidate = target + suffix
        if os.path.isfile(candidate):
            return candidate
    if os.path.isfile(target):
        return target
    return None


def build_ts_import_graph(ts_raw_imports: dict, defs: dict):
    consumed_exports = defaultdict(set)
    wildcard_edges = defaultdict(set)
    importers_of = defaultdict(set)

    for importer_file, raw_imports in ts_raw_imports.items():
        for imp in raw_imports:
            resolved = resolve_ts_module(imp["source"], str(importer_file))
            if resolved:
                importers_of[resolved].add(str(importer_file))
                for name in imp["names"]:
                    if name == "*":
                        wildcard_edges[str(importer_file)].add(resolved)
                    else:
                        consumed_exports[resolved].add(name)
                    target_key = f"{resolved}:{name}"
                    if target_key in defs:
                        defs[target_key].references += 1

    _resolve_wildcard_consumed(consumed_exports, wildcard_edges, defs)

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


def demote_unconsumed_ts_exports(defs, consumed_exports):
    demoted = []
    for _name, defn in defs.items():
        if not defn.is_exported:
            continue
        if not str(defn.filename).endswith((".ts", ".tsx")):
            continue
        if defn.type == "import":
            continue

        consumed = consumed_exports.get(str(defn.filename), set())
        if defn.simple_name not in consumed:
            defn.is_exported = False
            demoted.append(defn)
    return demoted


_TEST_SUFFIXES = (".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")

_NEXTJS_CONVENTION_FILES = frozenset(
    {
        "page.tsx",
        "page.ts",
        "layout.tsx",
        "layout.ts",
        "loading.tsx",
        "loading.ts",
        "error.tsx",
        "error.ts",
        "not-found.tsx",
        "not-found.ts",
        "route.ts",
        "route.tsx",
        "middleware.ts",
        "middleware.tsx",
        "layout.config.tsx",
        "layout.config.ts",
    }
)

_CONFIG_FILES = frozenset(
    {
        "vitest.config.ts",
        "vitest.config.mts",
        "jest.config.ts",
        "tsconfig.ts",
        "source.config.ts",
        "source.config.tsx",
        "tailwind.config.ts",
        "next.config.ts",
        "next.config.mts",
        "postcss.config.ts",
        "eslint.config.ts",
        "eslint.config.mts",
        "vite.config.ts",
        "vite.config.mts",
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
    if basename in _NEXTJS_CONVENTION_FILES:
        return True
    if basename in _CONFIG_FILES:
        return True
    return False


def find_dead_ts_files(files, exclude_folders, importers_of, wildcard_edges):
    ts_files = set()
    for f in files:
        sf = str(f)
        if not sf.endswith((".ts", ".tsx")):
            continue
        if any(ex in sf for ex in (exclude_folders or [])):
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
            norm_importers[os.path.realpath(src)].add(
                os.path.realpath(reexporter)
            )

    entry_points = set()
    for tf in ts_files:
        if os.path.basename(tf) in ("index.ts", "index.tsx"):
            entry_points.add(tf)

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
                "message": "Unused TypeScript file (not imported by any other file)",
                "file": tf,
                "line": 1,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }
        )
    return dead_files


def find_unused_ts_exports(demoted_exports, wildcard_edges):
    if not demoted_exports:
        return []

    api_surface = set()
    if wildcard_edges:
        reexported_by = defaultdict(set)
        for reexporter, sources in wildcard_edges.items():
            for src in sources:
                reexported_by[os.path.realpath(src)].add(
                    os.path.realpath(reexporter)
                )

        for src_real in reexported_by:
            visited = set()
            queue = [src_real]
            reaches_entry = False
            while queue:
                current = queue.pop()
                if current in visited:
                    continue
                visited.add(current)
                if os.path.basename(current) in ("index.ts", "index.tsx"):
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
        basename = os.path.basename(fname)
        if basename in ("index.ts", "index.tsx"):
            continue
        if defn.type == "method":
            continue
        if os.path.realpath(fname) in api_surface:
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
