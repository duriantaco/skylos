from __future__ import annotations

import time
from pathlib import Path
from typing import Any


MAX_JS_API_PACKAGE_JSON_BYTES = 1_000_000
MAX_JS_API_SURFACE_SOURCE_BYTES = 1_000_000
MAX_JS_API_PACKAGES = 128
MAX_JS_API_ENTRYPOINTS_PER_PACKAGE = 64
MAX_JS_API_REEXPORT_DEPTH = 8

JS_SOURCE_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
    ".d.ts",
)
EXCLUDED_JS_API_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "node_modules",
    "bower_components",
    "coverage",
    "dist",
    "build",
    "out",
    "generated",
    "vendor",
    "__pycache__",
}


def resolve_entrypoint_target(root: Path, package_dir: Path, target: str) -> Path | None:
    if not isinstance(target, str) or not target.strip():
        return None
    if "://" in target or target.startswith("node:"):
        return None

    for candidate_target in _candidate_package_targets(target.strip()):
        resolved_base = package_dir / candidate_target
        for candidate in _candidate_files_for_base(resolved_base):
            safe_candidate = _safe_source_file(root, candidate)
            if safe_candidate is not None:
                return safe_candidate
    return None
def _candidate_package_targets(target: str) -> list[str]:
    base_target = (
        target.replace("dist/", "src/")
        .replace("out/", "src/")
        .replace("/prod/", "/")
    )
    candidates = [base_target]
    if base_target.endswith(".d.ts"):
        base_no_dts = base_target[: -len(".d.ts")]
        candidates.extend(
            [
                base_no_dts + ".ts",
                base_no_dts + ".tsx",
                base_no_dts + ".js",
                base_no_dts + ".jsx",
            ]
        )
    elif base_target.endswith(".js"):
        base_no_ext = base_target[:-3]
        candidates.extend(
            [
                base_no_ext + ".ts",
                base_no_ext + ".tsx",
                base_no_ext + ".mts",
                base_no_ext + ".cts",
                base_no_ext + ".jsx",
            ]
        )
    elif base_target.endswith(".jsx"):
        base_no_ext = base_target[:-4]
        candidates.extend([base_no_ext + ".tsx", base_no_ext + ".js"])
    elif base_target.endswith((".mjs", ".cjs")):
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
def _candidate_files_for_base(base: Path) -> list[Path]:
    candidates = [base]
    if not has_js_source_suffix(base):
        candidates.extend(Path(str(base) + suffix) for suffix in JS_SOURCE_SUFFIXES)
    candidates.extend(base / f"index{suffix}" for suffix in JS_SOURCE_SUFFIXES)
    return candidates
def _safe_source_file(root: Path, candidate: Path) -> Path | None:
    try:
        if candidate.is_symlink():
            return None
        if _path_or_parent_is_symlink(root, candidate):
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if path_has_excluded_part(resolved, root):
        return None
    if not resolved.is_file():
        return None
    if not has_js_source_suffix(resolved):
        return None
    return resolved
def _path_or_parent_is_symlink(root: Path, candidate: Path) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True

    current = root
    for part in relative.parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False
def safe_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if len(raw) > 300:
        return None
    if any(ch in raw for ch in "\x00\r\n"):
        return None
    return raw
def has_js_source_suffix(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in JS_SOURCE_SUFFIXES)
def path_has_excluded_part(path: Path, root: Path) -> bool:
    try:
        relative = path.resolve(strict=False).relative_to(root)
    except ValueError:
        return True
    return any(part in EXCLUDED_JS_API_DIRS for part in relative.parts)
def relative_posix(root: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
