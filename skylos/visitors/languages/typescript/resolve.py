from __future__ import annotations

import json
import os
from functools import lru_cache


def _find_tsconfig(project_root: str) -> str | None:
    for name in ("tsconfig.json", "tsconfig.base.json"):
        candidate = os.path.join(project_root, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _parse_tsconfig_paths(tsconfig_path: str) -> tuple[str, dict[str, list[str]]]:
    try:
        with open(tsconfig_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return os.path.dirname(tsconfig_path), {}

    tsconfig_dir = os.path.dirname(tsconfig_path)
    compiler_opts = data.get("compilerOptions", {})
    base_url = compiler_opts.get("baseUrl", ".")
    base_url_abs = os.path.normpath(os.path.join(tsconfig_dir, base_url))
    paths = compiler_opts.get("paths", {})

    extends = data.get("extends")
    if extends and not paths:
        ext_path = os.path.normpath(os.path.join(tsconfig_dir, extends))
        if os.path.isfile(ext_path):
            parent_base, parent_paths = _parse_tsconfig_paths(ext_path)
            if not paths:
                paths = parent_paths
            if base_url == ".":
                base_url_abs = parent_base

    return base_url_abs, paths


def _build_package_map(project_root: str) -> dict[str, str]:
    pkg_map: dict[str, str] = {}
    skip = {"node_modules", ".git", "dist", "build", ".next", "__pycache__"}

    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        if "package.json" in filenames:
            pkg_json = os.path.join(dirpath, "package.json")
            if dirpath == project_root:
                continue
            try:
                with open(pkg_json) as f:
                    data = json.load(f)
                name = data.get("name")
                if name:
                    pkg_map[name] = dirpath
            except (json.JSONDecodeError, OSError):
                pass
    return pkg_map


@lru_cache(maxsize=None)
def _read_json_file(path: str) -> dict:
    try:
        with open(path) as f:
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


def _normalize_package_target(target: str) -> str:
    normalized = target.replace("dist/", "src/").replace("/prod/", "/")
    for ext_from, ext_to in [
        (".js", ".ts"),
        (".jsx", ".tsx"),
        (".mjs", ".ts"),
        (".cjs", ".ts"),
    ]:
        normalized = normalized.replace(ext_from, ext_to)
    return normalized


def _resolve_path_target(base_dir: str, target: str) -> str | None:
    normalized_target = _normalize_package_target(target)
    resolved_base = os.path.normpath(os.path.join(base_dir, normalized_target))

    candidates = [resolved_base]
    for suffix in (".ts", ".tsx", "/index.ts", "/index.tsx"):
        candidates.append(resolved_base + suffix)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            return candidate
    return None


def _extract_package_target(entry) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in ("types", "import", "default", "require", "node"):
            if key in entry:
                target = _extract_package_target(entry[key])
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
        for suffix in (".ts", ".tsx", "/index.ts", "/index.tsx"):
            candidate = os.path.join(pkg_dir, "src", subpath + suffix)
            if os.path.isfile(candidate):
                return candidate
            candidate = os.path.join(pkg_dir, subpath + suffix)
            if os.path.isfile(candidate):
                return candidate
        return None

    for entry in ("src/index.ts", "src/index.tsx", "index.ts", "index.tsx"):
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
                    src_val = val.replace("dist/", "src/").replace("/prod/", "/")
                    for ext_from, ext_to in [(".js", ".ts"), (".jsx", ".tsx")]:
                        src_val = src_val.replace(ext_from, ext_to)
                    candidate = os.path.normpath(os.path.join(pkg_dir, src_val))
                    if os.path.isfile(candidate):
                        return candidate
        except (json.JSONDecodeError, OSError):
            pass
    return None


class MonorepoResolver:
    def __init__(self, project_root: str) -> None:
        self.project_root = project_root
        self._tsconfig_paths: dict[str, list[str]] | None = None
        self._base_url: str = project_root
        self._package_map: dict[str, str] | None = None
        self._initialized = False

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        tsconfig = _find_tsconfig(self.project_root)
        if tsconfig:
            self._base_url, paths = _parse_tsconfig_paths(tsconfig)
            if paths:
                self._tsconfig_paths = paths

    def _ensure_package_map(self) -> dict[str, str]:
        if self._package_map is None:
            self._package_map = _build_package_map(self.project_root)
        return self._package_map

    def resolve(self, source: str, importer: str) -> str | None:
        if source.startswith("."):
            return None

        self._ensure_init()

        if source.startswith("#"):
            result = _resolve_package_imports(self.project_root, importer, source)
            if result:
                return result

        if self._tsconfig_paths:
            result = self._resolve_via_tsconfig(source)
            if result:
                return result

        return self._resolve_via_packages(source)

    def _resolve_via_tsconfig(self, source: str) -> str | None:
        if not self._tsconfig_paths:
            return None

        if source in self._tsconfig_paths:
            for target_pattern in self._tsconfig_paths[source]:
                resolved = os.path.normpath(
                    os.path.join(self._base_url, target_pattern)
                )
                if os.path.isfile(resolved):
                    return resolved
                for suffix in (".ts", ".tsx", "/index.ts", "/index.tsx"):
                    if os.path.isfile(resolved + suffix):
                        return resolved + suffix

        for pattern, targets in self._tsconfig_paths.items():
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
                resolved_base = os.path.normpath(
                    os.path.join(self._base_url, target_base, rest)
                )
                for suffix in ("", ".ts", ".tsx", "/index.ts", "/index.tsx"):
                    candidate = resolved_base + suffix
                    if os.path.isfile(candidate):
                        return candidate
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
