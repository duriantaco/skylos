from __future__ import annotations

import os
import re
from functools import lru_cache

from .resolve import _read_json_file

_SCRIPT_EXTS = ("js", "jsx", "ts", "tsx")
_TS_EXTS = ("ts", "tsx")
_NEXT_CONFIG_FILES = tuple(
    f"next.config.{ext}" for ext in ("js", "mjs", "cjs", "ts", "mts", "cts")
)
_PACKAGE_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_ROOT_CONVENTION_DIRS = ("", "src/")
_MAX_NEXT_CONFIG_BYTES = 256 * 1024

_NEXTJS_DEFAULT_EXPORT_BASENAMES = frozenset(
    {
        "page",
        "layout",
        "loading",
        "error",
        "not-found",
        "template",
        "global-error",
        "global-not-found",
        "default",
        "forbidden",
        "unauthorized",
    }
)

_NEXTJS_TS_INFRA_BASENAMES = frozenset(
    {
        "route",
        "middleware",
        "proxy",
        "instrumentation",
        "instrumentation-client",
        "layout.config",
    }
)

_NEXTJS_ROUTE_HANDLER_EXPORTS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)
_NEXTJS_MIDDLEWARE_EXPORTS = frozenset({"middleware", "config"})
_NEXTJS_PROXY_EXPORTS = frozenset({"proxy", "config"})
_NEXTJS_INSTRUMENTATION_EXPORTS = frozenset({"register", "onRequestError"})
# Root files Next.js loads by name, with the named exports it calls.
_NEXTJS_ROOT_FILE_EXPORTS = {
    "instrumentation-client": frozenset({"onRouterTransitionStart"}),
    "mdx-components": frozenset({"useMDXComponents"}),
}
_NEXTJS_PAGES_ROUTER_EXPORTS = frozenset(
    {"getServerSideProps", "getStaticProps", "getStaticPaths", "getInitialProps"}
)
_NEXTJS_METADATA_EXPORTS = frozenset(
    {"metadata", "generateMetadata", "viewport", "generateViewport"}
)
_NEXTJS_ROUTE_SEGMENT_CONFIG_EXPORTS = frozenset(
    {
        "dynamic",
        "dynamicParams",
        "revalidate",
        "fetchCache",
        "runtime",
        "preferredRegion",
        "maxDuration",
        "experimental_ppr",
    }
)
_NEXTJS_DYNAMIC_ROUTE_EXPORTS = frozenset({"generateStaticParams"})

# Metadata route files (app/robots.ts, app/sitemap.ts, app/icon.tsx, ...):
# Next.js serves their default export and reads these named exports.
_NEXTJS_METADATA_ROUTE_FILE_RE = re.compile(
    r"^(?:robots|sitemap|manifest|(?:icon|apple-icon|opengraph-image|twitter-image)\d*)"
    r"\.(?:js|jsx|ts|tsx)$"
)
_NEXTJS_METADATA_IMAGE_FILE_RE = re.compile(
    r"^(?:icon|apple-icon|opengraph-image|twitter-image)\d*\.(?:js|jsx|ts|tsx)$"
)
_NEXTJS_METADATA_IMAGE_EXPORTS = frozenset(
    {"alt", "size", "contentType", "generateImageMetadata"}
)
_NEXTJS_SITEMAP_EXPORTS = frozenset({"generateSitemaps"})
# Pages Router files may export a page or API route ``config`` object;
# ``reportWebVitals`` is the custom ``pages/_app`` hook.
_NEXTJS_PAGES_CONFIG_EXPORTS = frozenset({"config"})
_NEXTJS_APP_HOOK_EXPORTS = frozenset({"reportWebVitals"})
_NEXTJS_APP_ROUTER_BASENAMES = _NEXTJS_DEFAULT_EXPORT_BASENAMES | {"route"}
_NEXTJS_ROOT_CONVENTION_BASENAMES = frozenset(
    {
        "middleware",
        "proxy",
        "instrumentation",
        "instrumentation-client",
        "mdx-components",
    }
)

NEXTJS_IMPORTED_CONVENTION_EXPORTS = frozenset(
    _NEXTJS_PAGES_ROUTER_EXPORTS
    | _NEXTJS_METADATA_EXPORTS
    | _NEXTJS_ROUTE_SEGMENT_CONFIG_EXPORTS
    | _NEXTJS_DYNAMIC_ROUTE_EXPORTS
)

NEXTJS_CONVENTION_EXPORTS = frozenset(
    {
        "default",
        "loading",
        "error",
        "layout",
        "page",
    }
    | _NEXTJS_ROUTE_HANDLER_EXPORTS
    | _NEXTJS_MIDDLEWARE_EXPORTS
    | _NEXTJS_PROXY_EXPORTS
    | _NEXTJS_INSTRUMENTATION_EXPORTS
    | _NEXTJS_PAGES_ROUTER_EXPORTS
    | _NEXTJS_METADATA_EXPORTS
    | _NEXTJS_ROUTE_SEGMENT_CONFIG_EXPORTS
    | _NEXTJS_DYNAMIC_ROUTE_EXPORTS
    | _NEXTJS_METADATA_IMAGE_EXPORTS
    | _NEXTJS_SITEMAP_EXPORTS
    | _NEXTJS_PAGES_CONFIG_EXPORTS
    | _NEXTJS_APP_HOOK_EXPORTS
    | frozenset().union(*_NEXTJS_ROOT_FILE_EXPORTS.values())
)

NEXTJS_DEFAULT_EXPORT_FILES = frozenset(
    f"{name}.{ext}" for name in _NEXTJS_DEFAULT_EXPORT_BASENAMES for ext in _SCRIPT_EXTS
).union(
    {
        "middleware.js",
        "middleware.jsx",
        "middleware.ts",
        "middleware.tsx",
    }
)

NEXTJS_CONVENTION_FILES = frozenset(
    f"{name}.{ext}"
    for name in (_NEXTJS_DEFAULT_EXPORT_BASENAMES | _NEXTJS_TS_INFRA_BASENAMES)
    for ext in _TS_EXTS
)

NEXTJS_CONVENTION_DIRS = ("app/", "pages/", "api/")


def _normalized_path(fname: str | os.PathLike[str]) -> str:
    return str(fname).replace(os.sep, "/")


@lru_cache(maxsize=4096)
def _directory_is_nextjs_root(directory: str) -> bool:
    if any(
        os.path.isfile(os.path.join(directory, name)) for name in _NEXT_CONFIG_FILES
    ):
        return True
    package_json = os.path.join(directory, "package.json")
    if not os.path.isfile(package_json):
        return False
    data = _read_json_file(package_json)
    return any(
        isinstance(data.get(field), dict) and "next" in data[field]
        for field in _PACKAGE_DEPENDENCY_FIELDS
    )


def _nextjs_project_locations(
    fname: str | os.PathLike[str],
) -> list[tuple[str, str]]:
    absolute = os.path.abspath(os.fspath(fname))
    directory = os.path.dirname(absolute)
    locations: list[tuple[str, str]] = []
    while True:
        if _directory_is_nextjs_root(directory):
            locations.append(
                (directory, os.path.relpath(absolute, directory).replace(os.sep, "/"))
            )
        parent = os.path.dirname(directory)
        if parent == directory:
            return locations
        directory = parent


def nextjs_project_paths(fname: str | os.PathLike[str]) -> list[str]:
    """Return ``fname`` relative to each enclosing Next.js project root.

    A Next.js project root is a directory holding a ``next.config.*`` file or a
    ``package.json`` that depends on ``next``. Roots are listed innermost
    first; the list is empty outside any Next.js project.
    """
    return [relative for _, relative in _nextjs_project_locations(fname)]


@lru_cache(maxsize=4096)
def _root_has_directory(root: str, name: str) -> bool:
    return os.path.isdir(os.path.join(root, name))


_PAGE_EXTENSIONS_RE = re.compile(r"\bpageExtensions\s*:\s*\[([^\]]*)\]")
_PAGE_EXTENSION_ITEM_RE = re.compile(r"""\s*(['"`])([^'"`\s]+)\1\s*""")


@lru_cache(maxsize=1024)
def _nextjs_page_extensions(root: str) -> tuple[str, ...] | None:
    """The literal ``pageExtensions`` of the project's ``next.config.*``.

    ``None`` when the config is missing, unreadable, does not set the option,
    or sets it to anything but an array of string literals.
    """
    for name in _NEXT_CONFIG_FILES:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:  # skylos: ignore[SKY-D215] analyzer reads the scanned project's next.config
                source = handle.read(_MAX_NEXT_CONFIG_BYTES)
        except (OSError, UnicodeDecodeError):
            return None
        match = _PAGE_EXTENSIONS_RE.search(source)
        if match is None:
            return None
        items = [item for item in match.group(1).split(",") if item.strip()]
        extensions = []
        for item in items:
            literal = _PAGE_EXTENSION_ITEM_RE.fullmatch(item)
            if literal is None:
                return None
            extensions.append(literal.group(2).lstrip("."))
        return tuple(extensions) or None
    return None


def _router_relative_path(root: str, relative_path: str, router: str) -> str | None:
    """The path inside the ``app`` or ``pages`` router, or None.

    ``src/app`` and ``src/pages`` are used only when the project root has no
    ``app``/``pages`` directory of its own; Next.js ignores them otherwise.
    """
    if relative_path.startswith(f"{router}/"):
        return relative_path[len(router) + 1 :]
    if relative_path.startswith(f"src/{router}/") and not _root_has_directory(
        root, router
    ):
        return relative_path[len(router) + 5 :]
    return None


def _app_router_basename(root: str, relative_path: str) -> str | None:
    """Basename of a routed App Router file, or None.

    A ``_folder`` is a private folder that Next.js leaves out of routing, so
    files below one are ordinary modules.
    """
    inside = _router_relative_path(root, relative_path, "app")
    if inside is None:
        return None
    *folders, basename = inside.split("/")
    if any(folder.startswith("_") for folder in folders):
        return None
    return basename


def _has_page_extension(basename: str, page_extensions) -> bool:
    return any(basename.endswith(f".{extension}") for extension in page_extensions)


def _is_metadata_route_path(root: str, relative_path: str) -> bool:
    basename = _app_router_basename(root, relative_path)
    return basename is not None and bool(_NEXTJS_METADATA_ROUTE_FILE_RE.match(basename))


def _is_app_router_convention_path(root: str, relative_path: str) -> bool:
    basename = _app_router_basename(root, relative_path)
    if basename is None:
        return False
    page_extensions = _nextjs_page_extensions(root) or _SCRIPT_EXTS
    return any(
        basename == f"{convention}.{extension}"
        for extension in page_extensions
        for convention in _NEXTJS_APP_ROUTER_BASENAMES
    )


def _is_root_convention_path(relative_path: str) -> bool:
    for prefix in _ROOT_CONVENTION_DIRS:
        if not relative_path.startswith(prefix):
            continue
        remainder = relative_path[len(prefix) :]
        stem, dot, ext = remainder.rpartition(".")
        if (
            dot
            and "/" not in remainder
            and ext in _SCRIPT_EXTS
            and stem in _NEXTJS_ROOT_CONVENTION_BASENAMES
        ):
            return True
    return False


def is_nextjs_metadata_route_file(fname: str | os.PathLike[str]) -> bool:
    """``app/robots.ts``, ``app/sitemap.ts``, ``app/**/opengraph-image.tsx``..."""
    return any(
        _is_metadata_route_path(root, relative)
        for root, relative in _nextjs_project_locations(fname)
    )


def is_nextjs_project_pages_file(fname: str | os.PathLike[str]) -> bool:
    """Whether Next.js serves ``fname`` from its Pages Router.

    The file must be under ``pages/`` (or ``src/pages/`` when the project has
    no ``pages/``) and, when ``next.config.*`` sets a literal
    ``pageExtensions``, end with one of those extensions.
    """
    for root, relative in _nextjs_project_locations(fname):
        if _router_relative_path(root, relative, "pages") is None:
            continue
        page_extensions = _nextjs_page_extensions(root)
        if page_extensions is None or _has_page_extension(
            os.path.basename(relative), page_extensions
        ):
            return True
    return False


def is_nextjs_project_entry_file(fname: str | os.PathLike[str]) -> bool:
    """Whether Next.js loads ``fname`` by file convention in its project.

    Covers App Router route files (honouring ``pageExtensions``), metadata
    route files, and root ``middleware``/``proxy``/``instrumentation``/
    ``mdx-components`` files, only inside a detected Next.js project.
    """
    basename = os.path.basename(fname)
    first_segment = basename.split(".", 1)[0]
    if not (
        first_segment in _NEXTJS_APP_ROUTER_BASENAMES
        or first_segment in _NEXTJS_ROOT_CONVENTION_BASENAMES
        or _NEXTJS_METADATA_ROUTE_FILE_RE.match(basename)
    ):
        return False
    return any(
        _is_metadata_route_path(root, relative)
        or _is_app_router_convention_path(root, relative)
        or _is_root_convention_path(relative)
        for root, relative in _nextjs_project_locations(fname)
    )


def _is_nextjs_pages_config_export(name: str, fname: str | os.PathLike[str]) -> bool:
    if name in _NEXTJS_PAGES_CONFIG_EXPORTS:
        return (
            is_nextjs_pages_router_file(fname) or is_nextjs_pages_api_file(fname)
        ) and bool(nextjs_project_paths(fname))
    if name in _NEXTJS_APP_HOOK_EXPORTS:
        stem = os.path.basename(fname).rpartition(".")[0]
        return (
            stem == "_app"
            and is_nextjs_pages_router_file(fname)
            and bool(nextjs_project_paths(fname))
        )
    return False


def _is_nextjs_root_file_export(name: str, fname: str | os.PathLike[str]) -> bool:
    stem, _, ext = os.path.basename(fname).rpartition(".")
    if ext not in _SCRIPT_EXTS or name not in _NEXTJS_ROOT_FILE_EXPORTS.get(stem, ()):
        return False
    return any(_is_root_convention_path(path) for path in nextjs_project_paths(fname))


def _is_nextjs_metadata_route_export(name: str, fname: str | os.PathLike[str]) -> bool:
    basename = os.path.basename(fname)
    if not _NEXTJS_METADATA_ROUTE_FILE_RE.match(basename):
        return False
    if name in _NEXTJS_METADATA_IMAGE_EXPORTS:
        allowed = bool(_NEXTJS_METADATA_IMAGE_FILE_RE.match(basename))
    elif name in _NEXTJS_SITEMAP_EXPORTS:
        allowed = basename.startswith("sitemap.")
    else:
        allowed = name == "default" or name in _NEXTJS_ROUTE_SEGMENT_CONFIG_EXPORTS
    return allowed and is_nextjs_metadata_route_file(fname)


def is_nextjs_convention_file(fname: str | os.PathLike[str]) -> bool:
    normalized = _normalized_path(fname)
    for directory in NEXTJS_CONVENTION_DIRS:
        if f"/{directory}" in normalized or normalized.startswith(directory):
            return True
    return False


def is_nextjs_pages_router_file(fname: str | os.PathLike[str]) -> bool:
    normalized = _normalized_path(fname)
    return (
        ("/pages/" in normalized or normalized.startswith("pages/"))
        and "/pages/api/" not in normalized
        and not normalized.startswith("pages/api/")
    )


def is_nextjs_pages_api_file(fname: str | os.PathLike[str]) -> bool:
    normalized = _normalized_path(fname)
    return "/pages/api/" in normalized or normalized.startswith("pages/api/")


def is_nextjs_default_export_file(fname: str | os.PathLike[str]) -> bool:
    basename = os.path.basename(fname)
    return (
        basename in NEXTJS_DEFAULT_EXPORT_FILES
        or is_nextjs_pages_router_file(fname)
        or is_nextjs_pages_api_file(fname)
        or (
            bool(_NEXTJS_METADATA_ROUTE_FILE_RE.match(basename))
            and is_nextjs_metadata_route_file(fname)
        )
        or (
            # ``layout.page.tsx`` under a custom ``pageExtensions``.
            basename.split(".", 1)[0] in _NEXTJS_DEFAULT_EXPORT_BASENAMES
            and any(
                _is_app_router_convention_path(root, relative)
                for root, relative in _nextjs_project_locations(fname)
            )
        )
    )


def is_nextjs_route_segment_file(fname: str | os.PathLike[str]) -> bool:
    return os.path.basename(fname) in {
        "page.ts",
        "page.tsx",
        "page.js",
        "page.jsx",
        "layout.ts",
        "layout.tsx",
        "layout.js",
        "layout.jsx",
        "route.ts",
        "route.tsx",
        "route.js",
        "route.jsx",
    }


def is_nextjs_metadata_file(fname: str | os.PathLike[str]) -> bool:
    return os.path.basename(fname) in {
        "page.ts",
        "page.tsx",
        "page.js",
        "page.jsx",
        "layout.ts",
        "layout.tsx",
        "layout.js",
        "layout.jsx",
        "global-not-found.ts",
        "global-not-found.tsx",
        "global-not-found.js",
        "global-not-found.jsx",
    }


def is_nextjs_convention_export(name: str, fname: str | os.PathLike[str]) -> bool:
    basename = os.path.basename(fname)

    if name == "default" and is_nextjs_default_export_file(fname):
        return True
    if name in _NEXTJS_ROUTE_HANDLER_EXPORTS and basename in {
        "route.ts",
        "route.tsx",
        "route.js",
        "route.jsx",
    }:
        return True
    if name in _NEXTJS_MIDDLEWARE_EXPORTS and basename in {
        "middleware.ts",
        "middleware.tsx",
        "middleware.js",
        "middleware.jsx",
    }:
        return True
    if name in _NEXTJS_PROXY_EXPORTS and basename in {
        "proxy.ts",
        "proxy.tsx",
        "proxy.js",
        "proxy.jsx",
    }:
        return True
    if name in _NEXTJS_INSTRUMENTATION_EXPORTS and basename in {
        "instrumentation.ts",
        "instrumentation.tsx",
        "instrumentation.js",
        "instrumentation.jsx",
    }:
        return True
    if name in _NEXTJS_PAGES_ROUTER_EXPORTS and is_nextjs_pages_router_file(fname):
        return True
    if name in _NEXTJS_METADATA_EXPORTS and is_nextjs_metadata_file(fname):
        return True
    if name in _NEXTJS_ROUTE_SEGMENT_CONFIG_EXPORTS and is_nextjs_route_segment_file(
        fname
    ):
        return True
    if name in _NEXTJS_DYNAMIC_ROUTE_EXPORTS and is_nextjs_route_segment_file(fname):
        return True
    if _is_nextjs_pages_config_export(name, fname):
        return True
    if _is_nextjs_root_file_export(name, fname):
        return True
    return _is_nextjs_metadata_route_export(name, fname)
