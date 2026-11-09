"""Files that static-site generators load by convention.

Astro, Docusaurus and Jekyll read some files because of where they live, not
because another module imports them. Each generator is recognised only from
its own evidence (a dependency in the enclosing ``package.json``, its config
file, or for Jekyll an ``{% include %}`` that names the file), so a folder
that merely shares a name with a convention is still checked normally.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

from .conventions import (
    _depends_on,
    _enclosing_package_roots,
    _normalized,
    _package_data,
)

_SCRIPT_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs", ".cts")
_CONFIG_STEMS_EXTENSIONS = (".ts", ".js", ".mjs", ".mts", ".cjs", ".cts")

ASTRO_ENDPOINT_EXPORTS = frozenset(
    {
        "default",
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "ALL",
        "HEAD",
        "OPTIONS",
        "getStaticPaths",
        "prerender",
        "partial",
    }
)
ASTRO_CONTENT_CONFIG_EXPORTS = frozenset({"collections"})
ASTRO_MIDDLEWARE_EXPORTS = frozenset({"onRequest"})
ASTRO_ACTIONS_EXPORTS = frozenset({"server"})
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


def _relative(path: str, root: str) -> str | None:
    prefix = root.rstrip(os.sep) + os.sep
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :].replace(os.sep, "/")


def _has_config(root: str, stem: str) -> bool:
    return any(
        os.path.isfile(os.path.join(root, stem + extension))
        for extension in _CONFIG_STEMS_EXTENSIONS
    )


def _is_config(relative: str, stem: str) -> bool:
    return any(relative == stem + extension for extension in _CONFIG_STEMS_EXTENSIONS)


def _astro_entry(relative: str) -> tuple[str, frozenset[str]] | None:
    if relative.startswith("src/pages/") and relative.endswith(_SCRIPT_EXTENSIONS):
        return "astro-route", ASTRO_ENDPOINT_EXPORTS
    if _is_config(relative, "src/content.config") or _is_config(
        relative, "src/content/config"
    ):
        return "astro-content-config", ASTRO_CONTENT_CONFIG_EXPORTS
    if _is_config(relative, "src/middleware") or _is_config(
        relative, "src/middleware/index"
    ):
        return "astro-middleware", ASTRO_MIDDLEWARE_EXPORTS
    if _is_config(relative, "src/actions/index"):
        return "astro-actions", ASTRO_ACTIONS_EXPORTS
    return None


def _docusaurus_entry(
    relative: str, *, classic: bool
) -> tuple[str, frozenset[str]] | None:
    if not relative.endswith(_SCRIPT_EXTENSIONS):
        return None
    if classic:
        if relative == "siteConfig.js":
            return "docusaurus-site-config", DEFAULT_EXPORT
        if relative.startswith(("core/", "pages/")):
            return "docusaurus-component", DEFAULT_EXPORT
        return None
    if _is_config(relative, "docusaurus.config") or _is_config(relative, "sidebars"):
        return "docusaurus-config", DEFAULT_EXPORT
    if relative.startswith(("src/pages/", "src/theme/")):
        return "docusaurus-component", DEFAULT_EXPORT
    return None


def _package_entry(path: str) -> tuple[str, frozenset[str]] | None:
    for root in _enclosing_package_roots(path):
        relative = _relative(path, root)
        if relative is None:
            continue
        data = _package_data(root)
        if _depends_on(data, "astro") or _has_config(root, "astro.config"):
            entry = _astro_entry(relative)
            if entry is not None:
                return entry
        if _depends_on(data, "@docusaurus/core"):
            entry = _docusaurus_entry(relative, classic=False)
            if entry is not None:
                return entry
        if _depends_on(data, "docusaurus"):
            entry = _docusaurus_entry(relative, classic=True)
            if entry is not None:
                return entry
    return None


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
    return _package_entry(absolute) or _jekyll_entry(absolute)
