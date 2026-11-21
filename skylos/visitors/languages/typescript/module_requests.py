"""Literal module requests of scanned JS/TS sources and component scripts.

A module request is one ``import``/``export ... from``/``require()``/
``import()`` whose specifier is a string literal. The TypeScript scanner tags
those raw imports with ``import_kind``; globs, path joins, ``require.resolve``
and JSDoc type references carry no kind and are not requests. Vue, Svelte and
Astro script blocks are read as source data (never compiled or executed).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink

TS_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
COMPONENT_SUFFIXES = (".vue", ".svelte", ".astro")
REQUEST_KINDS = frozenset({"import", "reexport", "require", "dynamic"})
MAX_COMPONENT_FILES = 5_000
MAX_COMPONENT_BYTES = 1_000_000


@dataclass(frozen=True)
class ModuleRequest:
    importer: str
    source: str
    line: int
    kind: str
    type_only: bool = False
    guarded: bool = False
    deferred: bool = False

    @property
    def loads_at_startup(self) -> bool:
        """Whether evaluating the importer evaluates the target first."""
        if self.type_only or self.kind == "dynamic":
            return False
        return not (self.kind == "require" and self.deferred)


@dataclass
class ModuleRequests:
    requests: list[ModuleRequest]
    files: set[str]
    component_files: set[str]
    unparsed_components: int = 0


def _request(importer: str, record: dict) -> ModuleRequest | None:
    kind = record.get("import_kind")
    source = record.get("source")
    if kind not in REQUEST_KINDS or not isinstance(source, str) or not source:
        return None
    try:
        line = max(1, int(record.get("line") or 1))
    except (TypeError, ValueError):
        line = 1
    return ModuleRequest(
        importer=importer,
        source=source,
        line=line,
        kind=kind,
        type_only=bool(record.get("type_import") or record.get("type_only")),
        guarded=bool(record.get("guarded_import")),
        deferred=bool(record.get("deferred_import")),
    )


def _component_requests(root: Path, exclude_folders) -> tuple[list, set, int]:
    from skylos.deadcode.component_imports import _imports

    requests: list[ModuleRequest] = []
    parsed: set[str] = set()
    unparsed = 0
    try:
        components = discover_source_files(
            root, COMPONENT_SUFFIXES, exclude_folders=exclude_folders
        )
    except (OSError, ValueError):
        return requests, parsed, 1
    for path in components[:MAX_COMPONENT_FILES]:
        real = os.path.realpath(str(path))
        try:
            relative = Path(real).relative_to(root)
        except ValueError:
            continue
        text = read_project_text_no_symlink(
            root, relative, max_bytes=MAX_COMPONENT_BYTES
        )
        if text is None:
            unparsed += 1
            continue
        records, complete, notes, _blocks = _imports(Path(real), text)
        if not complete or notes:
            # A script that does not parse cannot prove a specifier exact.
            unparsed += 1
            continue
        parsed.add(real)
        for record in records:
            request = _request(real, record)
            if request is not None:
                requests.append(request)
    unparsed += max(0, len(components) - MAX_COMPONENT_FILES)
    return requests, parsed, unparsed


def collect_module_requests(
    project_root, files, ts_raw_imports, *, exclude_folders=None
) -> ModuleRequests:
    """Return literal module requests of scanned files and component scripts.

    Records the component expansion copied into a loader (``is_component_import``)
    are skipped; each component's own script is read once instead, so its
    requests keep their own file, line and specifier.
    """
    root = Path(os.path.realpath(str(project_root)))
    scanned = {
        os.path.realpath(str(file))
        for file in files
        if str(file).endswith(TS_JS_SUFFIXES)
    }
    requests: list[ModuleRequest] = []
    for importer, records in (ts_raw_imports or {}).items():
        real = os.path.realpath(str(importer))
        if real not in scanned:
            continue
        for record in records or ():
            if not isinstance(record, dict) or record.get("is_component_import"):
                continue
            request = _request(real, record)
            if request is not None:
                requests.append(request)
    component_requests, components, unparsed = _component_requests(
        root, exclude_folders
    )
    requests.extend(component_requests)
    requests.sort(key=lambda item: (item.importer, item.line, item.source, item.kind))
    return ModuleRequests(
        requests=requests,
        files=scanned,
        component_files=components,
        unparsed_components=unparsed,
    )


class CachedModuleResolver:
    """Resolve a specifier once per importing directory.

    Relative, tsconfig ``paths`` and package ``imports`` resolution all depend
    only on the importer's directory, so the cache key is exact.
    """

    def __init__(self, resolver=None) -> None:
        self.resolver = resolver
        self._cache: dict[tuple[str, str], str | None] = {}

    def resolve(self, source: str, importer: str) -> str | None:
        from .analysis import resolve_ts_module

        key = (source, os.path.dirname(importer))
        if key not in self._cache:
            try:
                resolved = resolve_ts_module(source, importer, self.resolver)
            except (OSError, ValueError, TypeError, RecursionError):
                resolved = None
            self._cache[key] = os.path.realpath(resolved) if resolved else None
        return self._cache[key]
