from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from skylos.visitors.languages.typescript.workspace import (
    _load_jsonc,
    discover_workspace_inventory,
)

_SOURCE_FILE_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
    "/index.ts",
    "/index.tsx",
    "/index.js",
    "/index.jsx",
    "/index.mts",
    "/index.cts",
    "/index.mjs",
    "/index.cjs",
)


def _find_nearest_tsconfig(start_path: str, stop_dir: str | None = None) -> str | None:
    current = os.path.dirname(os.path.realpath(start_path))
    stop_real = os.path.realpath(stop_dir) if stop_dir else None

    while True:
        for name in ("tsconfig.json", "tsconfig.base.json"):
            candidate = os.path.join(current, name)
            if os.path.isfile(candidate):
                return candidate

        if stop_real and current == stop_real:
            break

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _resolve_extends_path(tsconfig_dir: str, extends: str) -> str | None:
    if not extends:
        return None

    candidates: list[str] = []
    if os.path.isabs(extends):
        candidates.append(extends)
    else:
        candidates.append(os.path.normpath(os.path.join(tsconfig_dir, extends)))

    if not extends.endswith(".json"):
        if os.path.isabs(extends):
            candidates.append(extends + ".json")
        else:
            candidates.append(
                os.path.normpath(os.path.join(tsconfig_dir, extends + ".json"))
            )

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            return candidate

    if not os.path.isabs(extends) and not extends.startswith("."):
        current = os.path.realpath(tsconfig_dir)
        while True:
            package_root = os.path.join(current, "node_modules", extends)
            package_candidates = [package_root, package_root + ".json"]

            if os.path.isdir(package_root):
                package_candidates.append(os.path.join(package_root, "tsconfig.json"))
                package_json = _read_json_file(
                    os.path.join(package_root, "package.json")
                )
                package_tsconfig = package_json.get("tsconfig")
                if isinstance(package_tsconfig, str):
                    package_candidates.append(
                        os.path.normpath(os.path.join(package_root, package_tsconfig))
                    )

            for candidate in package_candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                if os.path.isfile(candidate):
                    return candidate

            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
    return None


def _parse_tsconfig_paths(
    tsconfig_path: str, _seen: set[str] | None = None
) -> tuple[str, dict[str, list[str]]]:
    if _seen is None:
        _seen = set()

    real_tsconfig_path = os.path.realpath(tsconfig_path)
    if real_tsconfig_path in _seen:
        return os.path.dirname(tsconfig_path), {}
    _seen.add(real_tsconfig_path)

    data = _load_jsonc(Path(tsconfig_path))
    if not data:
        return os.path.dirname(tsconfig_path), {}

    tsconfig_dir = os.path.dirname(tsconfig_path)
    compiler_opts = data.get("compilerOptions", {})

    parent_base = tsconfig_dir
    parent_paths: dict[str, list[str]] = {}

    extends = data.get("extends")
    if isinstance(extends, str):
        ext_path = _resolve_extends_path(tsconfig_dir, extends)
        if ext_path:
            parent_base, parent_paths = _parse_tsconfig_paths(ext_path, _seen)

    base_url = compiler_opts.get("baseUrl")
    if isinstance(base_url, str):
        base_url_abs = os.path.normpath(os.path.join(tsconfig_dir, base_url))
    else:
        base_url_abs = parent_base

    raw_paths = compiler_opts.get("paths", {})
    paths: dict[str, list[str]] = dict(parent_paths)
    if isinstance(raw_paths, dict):
        for key, value in raw_paths.items():
            if isinstance(value, list):
                resolved_targets: list[str] = []
                for item in value:
                    if not isinstance(item, str):
                        continue
                    if os.path.isabs(item):
                        resolved_targets.append(item)
                    else:
                        resolved_targets.append(
                            os.path.normpath(os.path.join(base_url_abs, item))
                        )
                paths[key] = resolved_targets

    return base_url_abs, paths


def _parse_tsconfig_references(tsconfig_path: str) -> list[str]:
    data = _load_jsonc(Path(tsconfig_path))
    refs = data.get("references")
    if not isinstance(refs, list):
        return []

    tsconfig_dir = os.path.dirname(tsconfig_path)
    results: list[str] = []
    seen: set[str] = set()

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        ref_path = ref.get("path")
        if not isinstance(ref_path, str) or not ref_path:
            continue

        candidates = [os.path.normpath(os.path.join(tsconfig_dir, ref_path))]
        if not ref_path.endswith(".json"):
            candidates.append(
                os.path.normpath(os.path.join(tsconfig_dir, ref_path + ".json"))
            )

        resolved_root: str | None = None
        for candidate in candidates:
            if os.path.isdir(candidate):
                resolved_root = os.path.realpath(candidate)
                break
            if os.path.isfile(candidate):
                resolved_root = os.path.realpath(os.path.dirname(candidate))
                break

        if resolved_root and resolved_root not in seen:
            seen.add(resolved_root)
            results.append(resolved_root)

    return results


def _build_package_map(project_root: str) -> dict[str, str]:
    pkg_map: dict[str, str] = {}
    inventory = discover_workspace_inventory(Path(project_root))

    package_roots: list[Path] = []
    if inventory.root_package and inventory.root_package.has_package_json:
        package_roots.append(inventory.root_package.root)
    for workspace in inventory.packages:
        if workspace.has_package_json and (
            "package.json:workspaces" in workspace.discovered_from
            or "pnpm-workspace.yaml" in workspace.discovered_from
        ):
            package_roots.append(workspace.root)

    for package_root in package_roots:
        pkg_json = os.path.join(str(package_root), "package.json")
        data = _read_json_file(pkg_json)
        name = data.get("name")
        if isinstance(name, str) and name.strip():
            pkg_map[name] = str(package_root)
    return pkg_map


@lru_cache(maxsize=None)
def _read_json_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _find_nearest_package_dir(start_path: str, stop_dir: str) -> str | None:
    current = os.path.dirname(start_path)
    stop_dir = os.path.realpath(stop_dir)

    while True:
        pkg_json = os.path.join(current, "package.json")
        if os.path.isfile(pkg_json):
            return current
        current_real = os.path.realpath(current)
        if current_real == stop_dir:
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    root_pkg = os.path.join(stop_dir, "package.json")
    if os.path.isfile(root_pkg):
        return stop_dir
    return None


def _candidate_package_targets(target: str) -> list[str]:
    base_target = target.replace("dist/", "src/").replace("/prod/", "/")
    candidates = [base_target]

    if base_target.endswith(".js"):
        candidates.extend(
            [
                base_target[:-3] + ".ts",
                base_target[:-3] + ".tsx",
                base_target[:-3] + ".mts",
                base_target[:-3] + ".cts",
                base_target[:-3] + ".jsx",
            ]
        )
    elif base_target.endswith(".jsx"):
        candidates.extend([base_target[:-4] + ".tsx", base_target[:-4] + ".js"])
    elif base_target.endswith(".mjs") or base_target.endswith(".cjs"):
        base_no_ext = base_target.rsplit(".", 1)[0]
        candidates.extend(
            [
                base_no_ext + ".mts",
                base_no_ext + ".cts",
                base_no_ext + ".ts",
                base_no_ext + ".tsx",
                base_no_ext + ".js",
                base_no_ext + ".jsx",
            ]
        )

    ordered: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered


def _resolve_path_target(base_dir: str, target: str) -> str | None:
    seen: set[str] = set()
    for candidate_target in _candidate_package_targets(target):
        resolved_base = os.path.normpath(os.path.join(base_dir, candidate_target))
        for candidate in [resolved_base, *[resolved_base + suffix for suffix in _SOURCE_FILE_SUFFIXES]]:
            if candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate):
                return candidate
    return None


def _extract_package_target(entry) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, list):
        for item in entry:
            target = _extract_package_target(item)
            if target:
                return target
    if isinstance(entry, dict):
        for key in ("types", "import", "default", "require", "node"):
            if key in entry:
                target = _extract_package_target(entry[key])
                if target:
                    return target
        for value in entry.values():
            target = _extract_package_target(value)
            if target:
                return target
    return None


def _match_wildcard_map(source: str, mapping: dict) -> str | None:
    for pattern, target_entry in mapping.items():
        if "*" not in pattern:
            continue
        prefix, suffix = pattern.split("*", 1)
        if not source.startswith(prefix):
            continue
        if suffix and not source.endswith(suffix):
            continue
        matched = source[len(prefix) :]
        if suffix:
            matched = matched[: -len(suffix)]
        target = _extract_package_target(target_entry)
        if not target:
            continue
        return target.replace("*", matched)
    return None


def _resolve_package_exports(pkg_dir: str, subpath: str | None = None) -> str | None:
    pkg_json = os.path.join(pkg_dir, "package.json")
    data = _read_json_file(pkg_json)
    exports = data.get("exports")
    if exports is None:
        return None

    if subpath is None and not isinstance(exports, dict):
        target = _extract_package_target(exports)
        if not target:
            return None
        return _resolve_path_target(pkg_dir, target)

    if subpath is None and isinstance(exports, dict):
        if "." not in exports and not any(
            isinstance(key, str) and key.startswith(".") for key in exports
        ):
            target = _extract_package_target(exports)
            if not target:
                return None
            return _resolve_path_target(pkg_dir, target)

    if not isinstance(exports, dict):
        return None

    export_key = "." if not subpath else f"./{subpath}"
    target = _extract_package_target(exports.get(export_key))
    if not target:
        target = _match_wildcard_map(export_key, exports)
    if not target:
        return None
    return _resolve_path_target(pkg_dir, target)


def _resolve_package_imports(
    project_root: str, importer: str, source: str
) -> str | None:
    pkg_dir = _find_nearest_package_dir(importer, project_root)
    if not pkg_dir:
        return None

    pkg_json = os.path.join(pkg_dir, "package.json")
    data = _read_json_file(pkg_json)
    imports = data.get("imports")
    if not isinstance(imports, dict):
        return None

    target = _extract_package_target(imports.get(source))
    if not target:
        target = _match_wildcard_map(source, imports)
    if not target:
        return None
    return _resolve_path_target(pkg_dir, target)


def _resolve_from_pkg_dir(pkg_dir: str, subpath: str | None = None) -> str | None:
    resolved_via_exports = _resolve_package_exports(pkg_dir, subpath)
    if resolved_via_exports:
        return resolved_via_exports

    if subpath:
        for suffix in _SOURCE_FILE_SUFFIXES:
            candidate = os.path.join(pkg_dir, "src", subpath + suffix)
            if os.path.isfile(candidate):
                return candidate
            candidate = os.path.join(pkg_dir, subpath + suffix)
            if os.path.isfile(candidate):
                return candidate
        return None

    for entry in (
        "src/index.ts",
        "src/index.tsx",
        "src/index.js",
        "src/index.jsx",
        "src/index.mts",
        "src/index.cts",
        "src/index.mjs",
        "src/index.cjs",
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "index.mts",
        "index.cts",
        "index.mjs",
        "index.cjs",
    ):
        candidate = os.path.join(pkg_dir, entry)
        if os.path.isfile(candidate):
            return candidate

    pkg_json = os.path.join(pkg_dir, "package.json")
    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            for field in ("module", "main"):
                val = data.get(field)
                if val:
                    for src_val in _candidate_package_targets(val):
                        candidate = os.path.normpath(os.path.join(pkg_dir, src_val))
                        if os.path.isfile(candidate):
                            return candidate
        except (json.JSONDecodeError, OSError):
            pass
    return None


class MonorepoResolver:
    def __init__(self, project_root: str) -> None:
        self.project_root = project_root
        self._package_map: dict[str, str] | None = None
        self._tsconfig_cache: dict[
            str, tuple[str, dict[str, list[str]], list[str]]
        ] = {}

    def _get_tsconfig_context(
        self, importer: str
    ) -> tuple[str, dict[str, list[str]], list[str]] | None:
        tsconfig = _find_nearest_tsconfig(importer, self.project_root)
        if not tsconfig:
            return None

        if tsconfig not in self._tsconfig_cache:
            base_url, paths = _parse_tsconfig_paths(tsconfig)
            references = _parse_tsconfig_references(tsconfig)
            self._tsconfig_cache[tsconfig] = (base_url, paths, references)
        return self._tsconfig_cache[tsconfig]

    def _ensure_package_map(self) -> dict[str, str]:
        if self._package_map is None:
            self._package_map = _build_package_map(self.project_root)
        return self._package_map

    def resolve(self, source: str, importer: str) -> str | None:
        if source.startswith("."):
            return None

        if source.startswith("#"):
            result = _resolve_package_imports(self.project_root, importer, source)
            if result:
                return result

        tsconfig_context = self._get_tsconfig_context(importer)
        if tsconfig_context is not None:
            base_url, tsconfig_paths, project_references = tsconfig_context
            result = self._resolve_via_tsconfig(source, base_url, tsconfig_paths)
            if result:
                return result
            result = self._resolve_via_project_references(source, project_references)
            if result:
                return result

        return self._resolve_via_packages(source)

    def _resolve_via_tsconfig(
        self, source: str, base_url: str, tsconfig_paths: dict[str, list[str]]
    ) -> str | None:
        if source in tsconfig_paths:
            for resolved in tsconfig_paths[source]:
                if os.path.isfile(resolved):
                    return resolved
                for suffix in _SOURCE_FILE_SUFFIXES:
                    if os.path.isfile(resolved + suffix):
                        return resolved + suffix

        for pattern, targets in tsconfig_paths.items():
            if not pattern.endswith("/*"):
                continue
            prefix = pattern[:-2]
            if not source.startswith(prefix + "/"):
                continue
            rest = source[len(prefix) + 1 :]
            for target_pattern in targets:
                if not target_pattern.endswith("/*"):
                    continue
                target_base = target_pattern[:-2]
                resolved_base = os.path.normpath(os.path.join(target_base, rest))
                for suffix in ("", *_SOURCE_FILE_SUFFIXES):
                    candidate = resolved_base + suffix
                    if os.path.isfile(candidate):
                        return candidate

        resolved_base = os.path.normpath(os.path.join(base_url, source))
        for suffix in ("", *_SOURCE_FILE_SUFFIXES):
            candidate = resolved_base + suffix
            if os.path.isfile(candidate):
                return candidate
        return None

    def _resolve_via_project_references(
        self, source: str, project_references: list[str]
    ) -> str | None:
        if not project_references:
            return None

        parts = source.split("/")
        package_name: str | None = None
        subpath: str | None = None

        if parts[0].startswith("@") and len(parts) >= 2:
            package_name = parts[0] + "/" + parts[1]
            if len(parts) > 2:
                subpath = "/".join(parts[2:])
        elif parts:
            package_name = parts[0]
            if len(parts) > 1:
                subpath = "/".join(parts[1:])

        if not package_name:
            return None

        for reference_root in project_references:
            pkg_json = os.path.join(reference_root, "package.json")
            pkg_data = _read_json_file(pkg_json)
            ref_name = pkg_data.get("name")
            if ref_name != package_name:
                continue
            return _resolve_from_pkg_dir(reference_root, subpath)

        return None

    def _resolve_via_packages(self, source: str) -> str | None:
        pkg_map = self._ensure_package_map()
        if not pkg_map:
            return None

        if source in pkg_map:
            return _resolve_from_pkg_dir(pkg_map[source])

        parts = source.split("/")
        if parts[0].startswith("@") and len(parts) >= 2:
            pkg_name = parts[0] + "/" + parts[1]
            if len(parts) > 2:
                subpath = "/".join(parts[2:])
            else:
                subpath = None
            if pkg_name in pkg_map:
                return _resolve_from_pkg_dir(pkg_map[pkg_name], subpath)
        elif len(parts) >= 2:
            pkg_name = parts[0]
            subpath = "/".join(parts[1:])
            if pkg_name in pkg_map:
                return _resolve_from_pkg_dir(pkg_map[pkg_name], subpath)

        return None
