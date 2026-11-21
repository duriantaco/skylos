"""Files that static-site generators load by convention, and their aliases.

Astro and Docusaurus page, endpoint and config conventions are rows of the
plugin table (``plugin_facts``). This module keeps what is not a glob
pattern: Jekyll ``_includes`` named by an ``{% include %}`` tag, and the
Docusaurus ``@site``/``@theme`` alias resolution with webpack's extension
order. Each is recognised only from the generator's own evidence, so a folder
that merely shares a name with a convention is still checked normally.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

from .conventions import _normalized

_CONFIG_STEMS_EXTENSIONS = (".ts", ".js", ".mjs", ".mts", ".cjs", ".cts")
DEFAULT_EXPORT = frozenset({"default"})

_JEKYLL_CONFIGS = ("_config.yml", "_config.yaml", "_config.toml")
_JEKYLL_PAGE_SUFFIXES = (
    ".html",
    ".htm",
    ".md",
    ".markdown",
    ".liquid",
    ".xml",
    ".svg",
    ".js",
)
_JEKYLL_INCLUDE_RE = re.compile(
    r"{%-?\s*include(?:_relative)?\s+[\"']?(?P<name>[^\s\"'%}]+)"
)
_JEKYLL_SKIP_DIRS = frozenset(
    {"_site", "node_modules", ".git", "vendor", ".jekyll-cache"}
)
_MAX_JEKYLL_PAGE_BYTES = 2_000_000


@lru_cache(maxsize=64)
def _jekyll_included_names(site_root: str) -> frozenset[str]:
    """Every name passed to ``{% include %}`` by the site's pages, layouts and
    includes."""
    names = set()
    for directory, subdirectories, files in os.walk(site_root):
        subdirectories[:] = [
            name for name in subdirectories if name not in _JEKYLL_SKIP_DIRS
        ]
        for filename in files:
            if not filename.endswith(_JEKYLL_PAGE_SUFFIXES):
                continue
            page = os.path.join(directory, filename)
            try:
                if os.path.getsize(page) > _MAX_JEKYLL_PAGE_BYTES:
                    continue
                with open(page, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            for match in _JEKYLL_INCLUDE_RE.finditer(text):
                names.add(match.group("name"))
    return frozenset(names)


def _jekyll_entry(path: str) -> tuple[str, frozenset[str]] | None:
    marker = os.sep + "_includes" + os.sep
    index = path.rfind(marker)
    if index == -1:
        return None
    site_root = path[:index]
    if not any(
        os.path.isfile(os.path.join(site_root, name)) for name in _JEKYLL_CONFIGS
    ):
        return None
    include_name = path[index + len(marker) :].replace(os.sep, "/")
    if include_name in _jekyll_included_names(site_root):
        return "jekyll-include", DEFAULT_EXPORT
    return None


def site_generator_entry(
    path: str | os.PathLike[str],
) -> tuple[str, frozenset[str]] | None:
    """Why a site generator loads ``path`` and which exports it reads, or None."""
    absolute = _normalized(path)
    if absolute.endswith(".d.ts"):
        return None
    return _jekyll_entry(absolute)


# --------------------------------------------------------------- Docusaurus

_DOCUSAURUS_CONFIGS = tuple(
    "docusaurus.config" + extension for extension in _CONFIG_STEMS_EXTENSIONS
)
# ``resolve.extensions`` of @docusaurus/core's webpack config
# (``['.wasm', '.mjs', '.js', '.jsx', '.ts', '.tsx', '.json']``): plain
# webpack 5 defaults to ``['.js', '.json', '.wasm']`` and TypeScript tries
# ``.ts``/``.tsx`` before ``.js``, but a Docusaurus build loads ``index.js``
# when both ``index.js`` and ``index.tsx`` sit in one folder.
DOCUSAURUS_EXTENSIONS = (".mjs", ".js", ".jsx", ".ts", ".tsx")


@lru_cache(maxsize=4096)
def docusaurus_site_root(directory: str) -> str | None:
    """The Docusaurus site (folder with ``docusaurus.config.*``) holding
    ``directory``; the search stops at the first enclosing ``package.json``."""
    current = os.path.abspath(directory)
    while True:
        if any(os.path.isfile(os.path.join(current, name)) for name in _DOCUSAURUS_CONFIGS):
            return current
        if os.path.isfile(os.path.join(current, "package.json")):
            return None
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def resolve_with_extensions(base: str, extensions=DOCUSAURUS_EXTENSIONS) -> str | None:
    """Webpack-style lookup: the file, ``base<ext>``, then ``base/index<ext>``."""
    if os.path.isfile(base):
        return base
    for extension in extensions:
        if os.path.isfile(base + extension):
            return base + extension
    for extension in extensions:
        candidate = os.path.join(base, "index" + extension)
        if os.path.isfile(candidate):
            return candidate
    return None


def resolve_docusaurus_alias(source: str, importer: str) -> str | None:
    """Resolve ``@site/...`` (the site root) and ``@theme/...`` (a swizzled
    component in ``src/theme``) for an importer inside a Docusaurus site.

    ``@theme/X`` without a swizzled file, ``@theme-original/``,
    ``@docusaurus/`` and ``@generated/`` name theme or core package modules,
    not project files.
    """
    aliases = _docusaurus_aliases()
    alias = next((key for key in aliases if source.startswith(key + "/")), None)
    if alias is None:
        return None
    site = docusaurus_site_root(os.path.dirname(os.path.abspath(importer)))
    if site is None:
        return None
    relative = source[len(alias) + 1 :]
    if not relative or ".." in relative.split("/"):
        return None
    base = os.path.join(site, aliases[alias], relative)
    return resolve_with_extensions(os.path.normpath(base))


@lru_cache(maxsize=1)
def _docusaurus_aliases() -> dict[str, str]:
    """``@site`` -> the site root, ``@theme`` -> ``src/theme`` (plugin table)."""
    from .plugin_facts import plugin_named

    row = plugin_named("docusaurus")
    return dict((row.skylos.get("aliases") or {}) if row is not None else {})
