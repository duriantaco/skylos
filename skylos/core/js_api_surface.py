from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_JS_MODULE,
    cache_api_symbol_surface,
)
from skylos.core.js_api_surface_exports import collect_js_exports_from_file
from skylos.core.js_api_surface_utils import (
    EXCLUDED_JS_API_DIRS,
    JS_SOURCE_SUFFIXES,
    MAX_JS_API_ENTRYPOINTS_PER_PACKAGE,
    MAX_JS_API_PACKAGE_JSON_BYTES,
    MAX_JS_API_PACKAGES,
    has_js_source_suffix as _has_js_source_suffix,
    path_has_excluded_part as _path_has_excluded_part,
    relative_posix as _relative_posix,
    resolve_entrypoint_target as _resolve_entrypoint_target,
    safe_name as _safe_name,
    utc_timestamp as _utc_timestamp,
)
from skylos.core.safe_cache_io import read_text_no_symlink


def build_js_api_surfaces(project_root: str | Path) -> list[dict[str, Any]]:
    root = _safe_project_root(project_root)
    if root is None:
        return []

    surfaces: list[dict[str, Any]] = []
    for package_json in _discover_package_json_files(root):
        package_dir = package_json.parent
        package_data = _read_package_json(package_json)
        package_name = _safe_name(package_data.get("name"))
        if package_name is None:
            continue

        for surface_name, entrypoint in _package_entrypoints(
            root,
            package_dir,
            package_name,
            package_data,
        ):
            members: dict[str, dict[str, Any]] = {}
            visited: set[Path] = set()
            collect_js_exports_from_file(
                root,
                entrypoint,
                members,
                visited,
                depth=0,
            )
            if not members:
                continue

            surface: dict[str, Any] = {
                "kind": SURFACE_KIND_JS_MODULE,
                "name": surface_name,
                "source": "js_api_surface",
                "origin": _relative_posix(root, package_json),
                "captured_at": _utc_timestamp(),
                "exports": sorted(members),
                "members": members,
                "metadata": {
                    "package_dir": _relative_posix(root, package_dir),
                    "entrypoint": _relative_posix(root, entrypoint),
                },
            }
            version = package_data.get("version")
            if isinstance(version, str) and version.strip():
                surface["version"] = version.strip()
            surfaces.append(surface)

    return surfaces
def cache_js_api_surfaces(project_root: str | Path) -> list[dict[str, Any]]:
    surfaces = build_js_api_surfaces(project_root)
    for surface in surfaces:
        cache_api_symbol_surface(project_root, surface)
    return surfaces
def _safe_project_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir():
        return None
    return root
def _discover_package_json_files(root: Path) -> list[Path]:
    package_files: list[Path] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = [
            dirname
            for dirname in sorted(dirnames)
            if dirname not in EXCLUDED_JS_API_DIRS
            and not _path_has_excluded_part(current_path / dirname, root)
            and not (current_path / dirname).is_symlink()
        ]
        if "package.json" not in filenames:
            continue
        package_json = current_path / "package.json"
        if package_json.is_symlink():
            continue
        if _path_has_excluded_part(package_json, root):
            continue
        package_files.append(package_json)
        if len(package_files) >= MAX_JS_API_PACKAGES:
            break
    return package_files
def _read_package_json(path: Path) -> dict[str, Any]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_JS_API_PACKAGE_JSON_BYTES,
        encoding="utf-8",
    )
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}
def _package_entrypoints(
    root: Path,
    package_dir: Path,
    package_name: str,
    package_data: dict[str, Any],
) -> list[tuple[str, Path]]:
    entrypoints: list[tuple[str, Path]] = []
    seen: set[str] = set()
    resolved_export_keys: set[str] = set()

    exports = package_data.get("exports")
    for export_key, target in _export_targets(exports):
        if export_key in resolved_export_keys:
            continue
        surface_name = _surface_name_for_export(package_name, export_key)
        if surface_name is None:
            continue
        resolved = _resolve_entrypoint_target(root, package_dir, target)
        if resolved is None:
            continue
        marker = f"{surface_name}\0{resolved}"
        if marker in seen:
            continue
        seen.add(marker)
        resolved_export_keys.add(export_key)
        entrypoints.append((surface_name, resolved))
        if len(entrypoints) >= MAX_JS_API_ENTRYPOINTS_PER_PACKAGE:
            return entrypoints

    if entrypoints:
        return entrypoints
    if exports is not None:
        return entrypoints

    for field in ("source", "module", "main", "types"):
        target = package_data.get(field)
        if not isinstance(target, str):
            continue
        resolved = _resolve_entrypoint_target(root, package_dir, target)
        if resolved is None:
            continue
        entrypoints.append((package_name, resolved))
        return entrypoints

    for default_entry in (
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
        resolved = _resolve_entrypoint_target(root, package_dir, default_entry)
        if resolved is not None:
            entrypoints.append((package_name, resolved))
            return entrypoints

    return entrypoints
def _export_targets(exports: Any) -> list[tuple[str, str]]:
    if exports is None:
        return []
    if isinstance(exports, str):
        return [(".", exports)]
    if isinstance(exports, list):
        return [(".", target) for target in _extract_package_targets(exports)]
    if not isinstance(exports, dict):
        return []
    if _has_subpath_export_keys(exports):
        return _subpath_export_targets(exports)
    return [(".", target) for target in _extract_package_targets(exports)]


def _has_subpath_export_keys(exports: dict[Any, Any]) -> bool:
    return any(isinstance(key, str) and key.startswith(".") for key in exports)


def _subpath_export_targets(exports: dict[Any, Any]) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for key, value in exports.items():
        if not _valid_subpath_export_key(key):
            continue
        results.extend(
            (key, target)
            for target in _extract_package_targets(value)
            if "*" not in target
        )
    return results


def _valid_subpath_export_key(key: Any) -> bool:
    return isinstance(key, str) and key.startswith(".") and "*" not in key
def _extract_package_targets(value: Any) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()

    def add(target: str) -> None:
        if target in seen:
            return
        seen.add(target)
        targets.append(target)

    if isinstance(value, str):
        add(value)
        return targets
    if isinstance(value, list):
        for item in value:
            for target in _extract_package_targets(item):
                add(target)
        return targets
    if isinstance(value, dict):
        priority_keys = (
            "source",
            "import",
            "module",
            "default",
            "require",
            "node",
            "browser",
            "types",
        )
        for key in priority_keys:
            for target in _extract_package_targets(value.get(key)):
                add(target)
        for key, item in value.items():
            if key in priority_keys:
                continue
            for target in _extract_package_targets(item):
                add(target)
    return targets
def _surface_name_for_export(package_name: str, export_key: str) -> str | None:
    if export_key == ".":
        return package_name
    if not export_key.startswith("./"):
        return None
    subpath = export_key[2:].strip("/")
    if not subpath:
        return package_name
    if any(part in {"", ".", ".."} for part in subpath.split("/")):
        return None
    return f"{package_name}/{subpath}"
