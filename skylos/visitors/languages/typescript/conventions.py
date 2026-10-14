"""JS/TS files that a framework or tool loads by file convention, not by import.

Nothing imports these files, so the import graph alone would call them dead.
Each rule follows the tool's documented lookup and is gated on evidence that
the tool is in use, so an ordinary module with a similar name stays judged:

* **Expo Router** (``expo-router`` in the enclosing package's dependencies):
  every ``*.{ts,tsx,js,jsx}`` file under the router root is a route. The root
  is ``extra.router.root`` / the ``expo-router`` plugin ``root`` in
  ``app.json``, else ``src/app`` when it exists, else ``app`` (Expo CLI's
  ``getRouterDirectory``). Expo Router reads the default export plus
  ``unstable_settings``, ``ErrorBoundary``, ``generateStaticParams`` and
  ``loader``; ``+api`` files export HTTP method handlers and
  ``+native-intent`` files export ``redirectSystemPath``/``legacy_subscribe``.
* **React Email** (``react-email`` in the enclosing package's dependencies):
  the ``email dev|build|export`` CLI renders every ``.js``/``.jsx``/``.tsx``
  file with a default export under ``./emails`` (or the ``--dir``/``-d`` path
  named in a package script), skipping sub-directories that start with ``_``
  and ``static`` (react-email ``getEmailsDirectoryMetadata``).
* **Jest manual mocks**: modules under a ``__mocks__`` directory replace the
  real module when Jest resolves it; every export of a mock is read by Jest.
* **Tool config files**: ``<tool>.config.<ext>`` next to a ``package.json``
  (``metro``, ``babel``, ``drizzle``, ``app`` for Expo, ``stylelint``,
  ``openapi-ts``, ...). Tools resolve these by name from the package root and
  read their exports.
* **Turborepo generators**: ``turbo/generators/config.{ts,js}`` in the
  repository or a workspace package, loaded by ``turbo gen``.
"""

from __future__ import annotations

import os
import re
import shlex
from functools import lru_cache

from skylos.core.safe_cache_io import read_text_no_symlink

from .resolve import _read_json_file

_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_ROUTE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx")
_REACT_EMAIL_EXTENSIONS = (".js", ".jsx", ".tsx")
_CONFIG_EXTENSIONS = ("js", "cjs", "mjs", "ts", "cts", "mts")
_TOOL_CONFIG_RE = re.compile(
    r"^[A-Za-z0-9_@-][A-Za-z0-9_.@-]*\.config\.(?:"
    + "|".join(_CONFIG_EXTENSIONS)
    + r")$"
)
_TURBO_GENERATOR_SUFFIXES = tuple(
    f"turbo/generators/config.{ext}" for ext in _CONFIG_EXTENSIONS
)
_MAX_TEMPLATE_BYTES = 512 * 1024

EXPO_ROUTER_EXPORTS = frozenset(
    {"default", "unstable_settings", "ErrorBoundary", "generateStaticParams", "loader"}
)
EXPO_API_ROUTE_EXPORTS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
EXPO_NATIVE_INTENT_EXPORTS = frozenset({"redirectSystemPath", "legacy_subscribe"})

# react-email's own detection heuristic (``isFileAnEmail``).
_REACT_EMAIL_DEFAULT_EXPORT_RES = (
    re.compile(r"\bexport\s+default\b"),
    re.compile(r"\bmodule\.exports\s*="),
    re.compile(r"\bexport\s+\{[^}]*\bdefault\b[^}]*\}"),
)
_REACT_EMAIL_COMMANDS = frozenset({"dev", "build", "export"})
_REACT_EMAIL_BINARIES = frozenset({"email", "email-dev", "react-email"})


def _normalized(path: str | os.PathLike[str]) -> str:
    return os.path.abspath(os.fspath(path))


@lru_cache(maxsize=8192)
def _package_data(directory: str) -> dict | None:
    package_json = os.path.join(directory, "package.json")
    if not os.path.isfile(package_json):
        return None
    return _read_json_file(package_json)


def _enclosing_package_roots(path: str) -> list[str]:
    """Directories holding a ``package.json`` above ``path``, innermost first."""
    roots = []
    directory = os.path.dirname(path)
    while True:
        if _package_data(directory) is not None:
            roots.append(directory)
        parent = os.path.dirname(directory)
        if parent == directory:
            return roots
        directory = parent


def _depends_on(data: dict | None, package: str, fields=_DEPENDENCY_FIELDS) -> bool:
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(field), dict) and package in data[field] for field in fields
    )


def _is_within(path: str, directory: str) -> bool:
    return path.startswith(directory.rstrip(os.sep) + os.sep)


# --------------------------------------------------------------------- Expo


@lru_cache(maxsize=1024)
def _configured_expo_router_root(package_root: str) -> str | None:
    app_json = os.path.join(package_root, "app.json")
    if not os.path.isfile(app_json):
        return None
    data = _read_json_file(app_json)
    expo = data.get("expo") if isinstance(data.get("expo"), dict) else data
    if not isinstance(expo, dict):
        return None
    extra = expo.get("extra")
    router = extra.get("router") if isinstance(extra, dict) else None
    if isinstance(router, dict) and isinstance(router.get("root"), str):
        return router["root"]
    plugins = expo.get("plugins")
    if isinstance(plugins, list):
        for plugin in plugins:
            if (
                isinstance(plugin, list)
                and len(plugin) >= 2
                and plugin[0] == "expo-router"
                and isinstance(plugin[1], dict)
                and isinstance(plugin[1].get("root"), str)
            ):
                return plugin[1]["root"]
    return None


@lru_cache(maxsize=1024)
def expo_router_root(package_root: str) -> str | None:
    """The Expo Router app directory of ``package_root``, or None."""
    # Expo CLI's ``isExpoRouterApp`` checks dependencies and devDependencies.
    if not _depends_on(
        _package_data(package_root),
        "expo-router",
        fields=("dependencies", "devDependencies"),
    ):
        return None
    configured = _configured_expo_router_root(package_root)
    if configured:
        root = os.path.normpath(os.path.join(package_root, configured))
        if _is_within(root, package_root) and os.path.isdir(root):
            return root
        return None
    for candidate in (
        os.path.join(package_root, "src", "app"),
        os.path.join(package_root, "app"),
    ):
        if os.path.isdir(candidate):
            return candidate
    return None


def is_expo_router_file(path: str | os.PathLike[str]) -> bool:
    absolute = _normalized(path)
    if not absolute.endswith(_ROUTE_EXTENSIONS) or absolute.endswith(".d.ts"):
        return False
    for package_root in _enclosing_package_roots(absolute):
        root = expo_router_root(package_root)
        if root is not None and _is_within(absolute, root):
            return True
    return False


def expo_router_exports(path: str | os.PathLike[str]) -> frozenset[str]:
    """Export names Expo Router reads from a route file (empty if not a route)."""
    if not is_expo_router_file(path):
        return frozenset()
    stem = os.path.basename(os.fspath(path)).split(".", 1)[0]
    if stem.endswith("+api"):
        return EXPO_API_ROUTE_EXPORTS
    if stem == "+native-intent":
        return EXPO_NATIVE_INTENT_EXPORTS
    return EXPO_ROUTER_EXPORTS


# -------------------------------------------------------------- React Email


def _script_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return command.split()


@lru_cache(maxsize=1024)
def react_email_directories(package_root: str) -> tuple[str, ...]:
    """Template directories the react-email CLI reads for ``package_root``."""
    data = _package_data(package_root)
    if not _depends_on(data, "react-email"):
        return ()
    directories = {os.path.join(package_root, "emails")}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if isinstance(scripts, dict):
        for command in scripts.values():
            if not isinstance(command, str):
                continue
            tokens = _script_tokens(command)
            for index, token in enumerate(tokens):
                if os.path.basename(token) not in _REACT_EMAIL_BINARIES:
                    continue
                if (
                    index + 1 >= len(tokens)
                    or tokens[index + 1] not in _REACT_EMAIL_COMMANDS
                ):
                    continue
                args = tokens[index + 2 :]
                for arg_index, arg in enumerate(args):
                    value = None
                    if arg in {"--dir", "-d"} and arg_index + 1 < len(args):
                        value = args[arg_index + 1]
                    elif arg.startswith("--dir="):
                        value = arg.split("=", 1)[1]
                    if value:
                        directory = os.path.normpath(os.path.join(package_root, value))
                        if (
                            _is_within(directory, package_root)
                            or directory == package_root
                        ):
                            directories.add(directory)
    return tuple(sorted(d for d in directories if os.path.isdir(d)))


@lru_cache(maxsize=8192)
def _has_react_email_default_export(path: str) -> bool:
    # No symlinks, regular files only, bounded: ``path`` comes from source
    # discovery inside the scanned project.
    source = read_text_no_symlink(path, max_bytes=_MAX_TEMPLATE_BYTES, errors="ignore")
    if source is None:
        return False
    return any(pattern.search(source) for pattern in _REACT_EMAIL_DEFAULT_EXPORT_RES)


def is_react_email_template(path: str | os.PathLike[str]) -> bool:
    absolute = _normalized(path)
    if not absolute.endswith(_REACT_EMAIL_EXTENSIONS):
        return False
    for package_root in _enclosing_package_roots(absolute):
        for directory in react_email_directories(package_root):
            if not _is_within(absolute, directory):
                continue
            relative = os.path.relpath(os.path.dirname(absolute), directory)
            folders = [] if relative == "." else relative.split(os.sep)
            if any(folder.startswith("_") or folder == "static" for folder in folders):
                continue
            return _has_react_email_default_export(absolute)
    return False


# ------------------------------------------------------- Jest, tool configs


def is_jest_manual_mock(path: str | os.PathLike[str]) -> bool:
    normalized = os.fspath(path).replace(os.sep, "/")
    return "/__mocks__/" in normalized or normalized.startswith("__mocks__/")


def is_package_tool_config(path: str | os.PathLike[str]) -> bool:
    """``<tool>.config.<ext>`` in a package root, or a Turborepo generator."""
    absolute = _normalized(path)
    normalized = absolute.replace(os.sep, "/")
    if normalized.endswith(_TURBO_GENERATOR_SUFFIXES):
        return True
    basename = os.path.basename(absolute)
    if not _TOOL_CONFIG_RE.match(basename):
        return False
    return _package_data(os.path.dirname(absolute)) is not None


def convention_reason(path: str | os.PathLike[str]) -> str | None:
    """Why a framework or tool loads ``path`` by convention, or None."""
    if is_jest_manual_mock(path):
        return "jest-manual-mock"
    if is_package_tool_config(path):
        return "tool-config"
    if is_expo_router_file(path):
        return "expo-router-route"
    if is_react_email_template(path):
        return "react-email-template"
    return None


def is_dev_convention_file(path: str | os.PathLike[str]) -> bool:
    """Convention files that only development tooling loads."""
    return is_jest_manual_mock(path) or is_package_tool_config(path)
