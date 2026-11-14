"""Platform-specific module files of React Native projects.

Metro (and Expo's web bundler) resolve ``import './useScale'`` to
``useScale.ios.ts``, ``useScale.android.ts``, ``useScale.native.ts`` or
``useScale.web.ts`` before ``useScale.ts``, depending on the platform being
bundled. One import statement therefore loads every platform sibling of its
target. The rule applies only when a ``package.json`` above the importing
file depends on ``react-native``, ``react-native-web`` or ``expo``; elsewhere
``scale.web.ts`` is an ordinary module that needs its own importer.
"""

from __future__ import annotations

import os
from functools import lru_cache

from .conventions import depends_on_any

PLATFORM_SUFFIXES = ("ios", "android", "native", "web", "windows", "macos")
_PLATFORM_PACKAGES = ("react-native", "react-native-web", "expo")
_SOURCE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_MAX_ADDED_IMPORTS = 50_000


@lru_cache(maxsize=4096)
def _uses_platform_resolution(directory: str) -> bool:
    return depends_on_any(
        os.path.join(directory, "module"), packages=_PLATFORM_PACKAGES
    )


@lru_cache(maxsize=4096)
def _directory_names(directory: str) -> frozenset[str]:
    try:
        return frozenset(os.listdir(directory))
    except OSError:
        return frozenset()


def _without_source_extension(path: str) -> str:
    for extension in _SOURCE_EXTENSIONS:
        if path.endswith(extension):
            return path[: -len(extension)]
    return path


def _platform_stems(stem_path: str) -> list[str]:
    directory, stem = os.path.split(stem_path)
    if stem.rsplit(".", 1)[-1] in PLATFORM_SUFFIXES and "." in stem:
        return []
    names = _directory_names(directory)
    found = []
    for platform in PLATFORM_SUFFIXES:
        if any(
            f"{stem}.{platform}{extension}" in names for extension in _SOURCE_EXTENSIONS
        ):
            found.append(os.path.join(directory, f"{stem}.{platform}"))
    return found


def expand_platform_imports(raw_imports: dict, resolve) -> dict:
    """Add one import per platform sibling of each import's target.

    ``resolve(source, importer)`` returns the file an import loads, or None.
    Returns ``raw_imports`` itself when nothing is added.
    """
    additions: dict = {}
    added = 0
    for importer, imports in raw_imports.items():
        importer_path = os.path.abspath(str(importer))
        importer_dir = os.path.dirname(importer_path)
        if not _uses_platform_resolution(importer_dir):
            continue
        extra = []
        for item in imports:
            source = item.get("source")
            if not isinstance(source, str) or not source:
                continue
            resolved = resolve(source, importer_path)
            if resolved is not None:
                stem_path = _without_source_extension(os.path.abspath(resolved))
            elif source.startswith("."):
                stem_path = _without_source_extension(
                    os.path.normpath(os.path.join(importer_dir, source))
                )
            else:
                continue
            for platform_stem in _platform_stems(stem_path):
                relative = os.path.relpath(platform_stem, importer_dir).replace(
                    os.sep, "/"
                )
                if not relative.startswith("."):
                    relative = "./" + relative
                if relative == source:
                    continue
                extra.append({**item, "source": relative})
                added += 1
                if added > _MAX_ADDED_IMPORTS:
                    return raw_imports
        if extra:
            additions[importer] = extra
    if not additions:
        return raw_imports
    expanded = dict(raw_imports)
    for importer, extra in additions.items():
        expanded[importer] = [*raw_imports[importer], *extra]
    return expanded
