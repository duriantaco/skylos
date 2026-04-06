from __future__ import annotations

import os

_SCRIPT_EXTS = ("js", "jsx", "ts", "tsx")
_TS_EXTS = ("ts", "tsx")

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
_NEXTJS_PAGES_ROUTER_EXPORTS = frozenset(
    {"getServerSideProps", "getStaticProps", "getStaticPaths"}
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
    if name in _NEXTJS_DYNAMIC_ROUTE_EXPORTS and os.path.basename(fname) in {
        "page.ts",
        "page.tsx",
        "page.js",
        "page.jsx",
        "layout.ts",
        "layout.tsx",
        "layout.js",
        "layout.jsx",
    }:
        return True
    return False
