"""Resolve a proved SvelteKit 2 library alias for dead-code analysis."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.visitors.languages.typescript.workspace import (
    _strip_json_comments,
    _strip_trailing_commas,
)

_CONFIG_NAMES = ("tsconfig.json", "tsconfig.base.json", "jsconfig.json")
_GENERATED_CONFIG = ".svelte-kit/tsconfig.json"
_VITE_EXTENSIONS = (".mjs", ".js", ".mts", ".ts", ".jsx", ".tsx", ".json")
_JS_SOURCE_EXTENSIONS = {
    ".js": (".ts", ".tsx"),
    ".jsx": (".tsx",),
    ".mjs": (".mts",),
    ".cjs": (".cts",),
}


def _read_config(owner: Path, config: Path) -> dict:
    raw = read_project_text_no_symlink(owner, config, max_bytes=128_000)
    if raw is None:
        raise ValueError("Unreadable compiler configuration")
    data = json.loads(
        _strip_trailing_commas(_strip_json_comments(raw.lstrip("\ufeff")))
    )
    if not isinstance(data, dict):
        raise TypeError("Invalid compiler configuration")
    return data


def _compiler_paths(data: dict) -> dict:
    options = data.get("compilerOptions", {})
    if not isinstance(options, dict):
        raise TypeError("Invalid compiler options")
    if "baseUrl" in options:
        raise ValueError("Unproved compiler path configuration")
    paths = options.get("paths", {})
    if not isinstance(paths, dict):
        raise TypeError("Invalid compiler paths")
    return paths


def _path_matches(pattern: str, source: str) -> bool:
    prefix, wildcard, suffix = pattern.partition("*")
    if not wildcard:
        return source == pattern
    return (
        len(source) >= len(prefix) + len(suffix)
        and source.startswith(prefix)
        and source.endswith(suffix)
    )


def _compiler_claims(owner: Path, library: Path, config: Path) -> set[str]:
    data = _read_config(owner, config)
    claims = set(_compiler_paths(data))
    if "extends" not in data:
        return claims
    if config.parent != owner or data["extends"] not in (
        _GENERATED_CONFIG,
        "./" + _GENERATED_CONFIG,
    ):
        raise ValueError("Unsupported compiler config inheritance")

    generated = owner / _GENERATED_CONFIG
    if generated.parent.resolve() != generated.parent:
        raise ValueError("Non-local generated compiler configuration")
    if not os.path.lexists(generated):
        return claims
    inherited = _read_config(owner, generated)
    if "extends" in inherited:
        raise ValueError("Unsupported generated compiler config inheritance")
    expected = os.path.relpath(library, generated.parent).replace(os.sep, "/")
    for pattern, targets in _compiler_paths(inherited).items():
        if (pattern == "$lib" and targets == [expected]) or (
            pattern == "$lib/*" and targets == [expected + "/*"]
        ):
            # These are the exact paths SvelteKit derives from kit.files.lib.
            continue
        claims.add(pattern)
    return claims


def _resolve_library_path(library: Path, parts: list[str]) -> str | None:
    target = library.joinpath(*parts)
    if target.resolve() != target:
        return None
    if target.is_file():
        return str(target)

    candidates = [
        target.with_suffix(extension)
        for extension in _JS_SOURCE_EXTENSIONS.get(target.suffix, ())
    ]
    candidates.extend(Path(str(target) + suffix) for suffix in _VITE_EXTENSIONS)
    if target.is_dir() and not os.path.lexists(target / "package.json"):
        candidates.extend(target / ("index" + suffix) for suffix in _VITE_EXTENSIONS)
    for candidate in candidates:
        if candidate.resolve() != candidate:
            return None
        if candidate.is_file():
            return str(candidate) if candidate.is_relative_to(library) else None
    return None


def _library_config_claims(
    owner: Path, library: Path, directory: Path
) -> frozenset[str]:
    if (
        directory.resolve() != directory
        or not library.is_relative_to(owner)
        or "node_modules" in directory.relative_to(owner).parts
    ):
        raise ValueError("Unproved SvelteKit library scope")
    claims = set()
    for parent in (directory, *directory.parents):
        for name in _CONFIG_NAMES:
            config = parent / name
            if os.path.lexists(config):
                claims.update(_compiler_claims(owner, library, config))
        if parent == owner:
            break
    return frozenset(claims)


def _resolve_library_import(
    source: str, path: Path, library: Path, claims: frozenset[str]
) -> str | None:
    if (
        not (source == "$lib" or source.startswith("$lib/"))
        or any(char in source for char in "?#\\\0")
        or path.is_symlink()
    ):
        return None
    parts = source.split("/")[1:]
    if any(part in {"", ".", ".."} for part in parts) or any(
        _path_matches(pattern, source) for pattern in claims
    ):
        return None
    return _resolve_library_path(library, parts)


def resolve_default_sveltekit_library(
    source: str, importer: str, package_root: str, library_path: str
) -> str | None:
    """Resolve a library alias after the caller has established a default owner."""
    package = Path(package_root)
    try:
        owner = package.resolve(strict=True)
        path = owner / Path(importer).absolute().relative_to(package)
        library = owner / Path(library_path).relative_to(package)
        claims = _library_config_claims(owner, library, path.parent)
        result = _resolve_library_import(source, path, library, claims)
        return str(package / Path(result).relative_to(owner)) if result else None
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


class _SvelteKitResolver:
    def __init__(self, inner, lib_directories: Mapping[str, str]) -> None:
        self._inner = inner
        self._libraries = {
            Path(root): Path(lib) for root, lib in lib_directories.items()
        }
        self._config_claims: dict[Path, tuple[Path, frozenset[str]] | None] = {}

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _library_scope(self, directory: Path) -> tuple[Path, frozenset[str]] | None:
        if directory not in self._config_claims:
            self._config_claims[directory] = self._find_library_scope(directory)
        return self._config_claims[directory]

    def _find_library_scope(
        self, directory: Path
    ) -> tuple[Path, frozenset[str]] | None:
        if not any(directory.is_relative_to(owner) for owner in self._libraries):
            return None
        try:
            owner = next(
                (
                    parent
                    for parent in (directory, *directory.parents)
                    if os.path.lexists(parent / "package.json")
                ),
                None,
            )
            library = self._libraries.get(owner)
            if library is None:
                return None
            return library, _library_config_claims(owner, library, directory)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    def resolve(self, source: str, importer: str) -> str | None:
        resolved = self._inner.resolve(source, importer)
        if resolved is not None or not (source == "$lib" or source.startswith("$lib/")):
            return resolved
        if self._inner.claims_local_source(source, importer):
            return None
        path = Path(os.path.abspath(importer))
        scope = self._library_scope(path.parent)
        if scope is None:
            return None
        library, claims = scope
        try:
            return _resolve_library_import(source, path, library, claims)
        except (OSError, RuntimeError, ValueError):
            return None

    def resolve_relative_runtime_import(
        self, source: str, importer: str, entry: str | None = None
    ) -> str | None:
        if any(char in source for char in "?#\\\0"):
            return None
        directory = Path(importer).parent
        entry_directory = Path(entry or importer).parent
        for owner in (entry_directory, *entry_directory.parents):
            if not os.path.lexists(owner / "package.json"):
                continue
            path = Path(os.path.normpath(directory / source))
            project_root = Path(self._inner.project_root)
            if owner in self._libraries and path.is_relative_to(project_root):
                try:
                    return _resolve_library_path(
                        project_root, list(path.relative_to(project_root).parts)
                    )
                except (OSError, RuntimeError, ValueError):
                    return None
            break
        return None


def sveltekit_resolver(resolver, lib_directories: Mapping[str, str]):
    """Keep existing resolution first, then resolve the scoped library alias."""
    return (
        _SvelteKitResolver(resolver, lib_directories) if lib_directories else resolver
    )


def resolve_sveltekit_component(
    source: str, importer: str, resolver, *, entry: str
) -> str | None:
    """Prefer the framework's file identity before applying JS/TS conventions."""
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    if isinstance(resolver, _SvelteKitResolver) and source.startswith(("./", "../")):
        resolved = resolver.resolve_relative_runtime_import(
            source, importer, entry=entry
        )
        if resolved is not None:
            return resolved
    return resolve_ts_module(source, importer, resolver)


def resolve_sveltekit_entry_imports(raw_imports, entry_modules, resolver) -> None:
    """Preserve Vite's file identity on modules reached from runtime entries."""
    if not isinstance(resolver, _SvelteKitResolver):
        return
    from skylos.visitors.languages.typescript.resolve import _find_nearest_package_dir

    project_root = resolver.project_root
    imports_by_path = {str(file): items for file, items in raw_imports.items()}
    pending = list(entry_modules)
    checked = set()
    package_roots = {}

    def owning_package(path):
        if path not in package_roots:
            package_roots[path] = _find_nearest_package_dir(path, project_root)
        return package_roots[path]

    while pending:
        importer = pending.pop()
        if importer in checked:
            continue
        checked.add(importer)
        owner = owning_package(importer)
        if owner is None or Path(owner) not in resolver._libraries:
            continue
        for item in imports_by_path.get(importer, ()):
            if item.get("type_only"):
                continue
            source = item.get("source", "")
            target = item.get("resolved_file")
            if target is None:
                if source.startswith(("./", "../")):
                    target = resolver.resolve_relative_runtime_import(source, importer)
                elif source == "$lib" or source.startswith("$lib/"):
                    target = resolver.resolve(source, importer)
                if target is not None:
                    item["resolved_file"] = target
            if target in imports_by_path and owning_package(target) == owner:
                pending.append(target)
