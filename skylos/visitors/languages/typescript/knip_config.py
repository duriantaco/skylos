"""Honour a repository's own Knip configuration, read as data.

A project that runs Knip has written down its entry files and the issues it
does not want: ``knip.json``, ``knip.jsonc``, ``.knip.json(c)``, ``knip.ts``
/ ``knip.js`` / ``knip.config.*`` (when the exported value is a static
literal; nothing is executed) or ``package.json#knip``.

Only keys that remove findings are honoured, so the config can never add one:

* ``entry`` (top level for the root workspace, ``workspaces[dir].entry``):
  the files are roots and their exports are public;
* ``project``: a file outside the workspace's project patterns gets no
  dead-code finding;
* ``ignore`` / ``ignoreFiles``: no finding in (no unused-file finding for)
  matching files;
* ``ignoreDependencies``, ``ignoreBinaries``, ``ignoreUnresolved``: strings
  (Knip turns a string with regex characters into a regex) or regex
  literals; no SKY-U005/Q408/Q413, SKY-Q409 or SKY-Q414 finding for them;
* ``ignoreExportsUsedInFile``: no "unnecessary export" (SKY-E004) finding,
  for every kind (``true``) or the kinds an object enables;
* ``ignoreWorkspaces``: no dead-code or dependency finding in those
  workspaces. Opt-in (``knip_ignore_workspaces = true`` in the Skylos
  config): those folders often hold real dead code the project merely does
  not gate on.

A key whose value is not a literal is skipped (its findings stay); a key
with a partly literal list honours only its literal items. Suppressed
findings move to ``suppressed`` with the key as the reason.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from functools import lru_cache

from .glob_patterns import GlobSet
from .static_config import (
    ABSENT,
    UNKNOWN,
    JsRegex,
    OpenDict,
    lookup,
    read_static_config,
)

KNIP_CONFIG_FILES = (
    "knip.json",
    "knip.jsonc",
    ".knip.json",
    ".knip.jsonc",
    "knip.ts",
    "knip.mts",
    "knip.cts",
    "knip.js",
    "knip.mjs",
    "knip.cjs",
    "knip.config.ts",
    "knip.config.mts",
    "knip.config.cts",
    "knip.config.js",
    "knip.config.mjs",
    "knip.config.cjs",
)
_REGEX_CHARS = re.compile(r"[*+\\(|{^$]")
_DEAD_CODE_KEYS = (
    "unused_functions",
    "unused_imports",
    "unused_classes",
    "unused_variables",
    "unused_parameters",
    "unused_files",
    "unused_exports",
)
_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_DEPENDENCY_RULES = {"SKY-U005", "SKY-Q408", "SKY-Q413"}
_TYPE_KINDS = {"type", "interface", "type_alias", "typealias", "enum"}

_settings = {"enabled": True, "ignore_workspaces": False}


def configure(*, enabled: bool = True, ignore_workspaces: bool = False) -> None:
    """Set from the Skylos config for this scan."""
    changed = _settings["enabled"] != bool(enabled)
    _settings["enabled"] = bool(enabled)
    _settings["ignore_workspaces"] = bool(ignore_workspaces)
    if changed:
        from .plugin_facts import plugin_entry

        plugin_entry.cache_clear()


@dataclass
class _Matcher:
    """Names (strings or regexes), matched as the config format defines."""

    exact: set[str] = field(default_factory=set)
    patterns: list = field(default_factory=list)

    def add(self, value) -> bool:
        if isinstance(value, JsRegex):
            compiled = value.compile()
            if compiled is None:
                return False
            self.patterns.append(compiled)
            return True
        if not isinstance(value, str) or not value:
            return False
        if _REGEX_CHARS.search(value):
            try:
                self.patterns.append(re.compile(value))
            except re.error:
                return False
            return True
        self.exact.add(value)
        return True

    def matches(self, name: str | None) -> bool:
        if not name:
            return False
        return name in self.exact or any(pattern.search(name) for pattern in self.patterns)

    def __bool__(self) -> bool:
        return bool(self.exact or self.patterns)


@dataclass
class KnipWorkspace:
    directory: str  # relative to the config root, "" for the root workspace
    entry: GlobSet | None = None
    project: GlobSet | None = None
    ignore: GlobSet | None = None
    ignore_files: GlobSet | None = None
    ignore_dependencies: _Matcher = field(default_factory=_Matcher)
    ignore_binaries: _Matcher = field(default_factory=_Matcher)
    ignore_unresolved: _Matcher = field(default_factory=_Matcher)
    ignore_exports_used_in_file: frozenset[str] = frozenset()


@dataclass
class KnipConfig:
    path: str
    root: str
    root_workspace: KnipWorkspace
    workspaces: list[tuple[GlobSet, KnipWorkspace]]
    ignore_workspaces: GlobSet | None
    honoured: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)


def _literal_strings(value, key: str, unread: list[str]) -> list[str]:
    if value is ABSENT:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        unread.append(key)
        return []
    items = [item for item in value if isinstance(item, str)]
    if len(items) != len(value):
        unread.append(key)
    return items


def _globs(value, key: str, unread: list[str], strip_production: bool = False):
    items = _literal_strings(value, key, unread)
    if strip_production:
        # ``src/index.ts!`` marks a production entry; the path is the same.
        items = [item.removesuffix("!") for item in items]
    return GlobSet(items) if items else None


def _names(value, key: str, unread: list[str]) -> _Matcher:
    matcher = _Matcher()
    if value is ABSENT:
        return matcher
    values = value if isinstance(value, list) else [value]
    complete = isinstance(value, (list, str, JsRegex))
    for item in values:
        if not matcher.add(item):
            complete = False
    if not complete:
        unread.append(key)
    return matcher


def _used_in_file_kinds(value, key: str, unread: list[str]) -> frozenset[str]:
    if value is ABSENT or value is False:
        return frozenset()
    if value is True:
        return frozenset({"*"})
    if isinstance(value, dict) and not isinstance(value, OpenDict):
        kinds = {kind for kind, enabled in value.items() if enabled is True}
        return frozenset(kinds)
    unread.append(key)
    return frozenset()


def _workspace(directory: str, data, prefix: str, unread: list[str], *, root: bool) -> KnipWorkspace:
    def get(key):
        if data is UNKNOWN:
            return UNKNOWN
        return lookup(data, key)

    def name(key):
        return f"{prefix}{key}"

    workspace = KnipWorkspace(directory)
    workspace.entry = _globs(get("entry"), name("entry"), unread, strip_production=True)
    workspace.project = _globs(get("project"), name("project"), unread, strip_production=True)
    workspace.ignore = _globs(get("ignore"), name("ignore"), unread)
    workspace.ignore_files = _globs(get("ignoreFiles"), name("ignoreFiles"), unread)
    workspace.ignore_dependencies = _names(get("ignoreDependencies"), name("ignoreDependencies"), unread)
    workspace.ignore_binaries = _names(get("ignoreBinaries"), name("ignoreBinaries"), unread)
    workspace.ignore_unresolved = _names(get("ignoreUnresolved"), name("ignoreUnresolved"), unread)
    if root:
        workspace.ignore_exports_used_in_file = _used_in_file_kinds(
            get("ignoreExportsUsedInFile"), name("ignoreExportsUsedInFile"), unread
        )
    # ``project`` patterns that could not be read must not shrink the
    # reported universe: an unread project key keeps every file in scope.
    if name("project") in unread:
        workspace.project = None
    return workspace


def _find_config(root: str) -> tuple[str, str | None] | None:
    for name in KNIP_CONFIG_FILES:
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate):
            return candidate, None
    manifest = os.path.join(root, "package.json")
    if os.path.isfile(manifest):
        value = read_static_config(manifest, "knip")
        if value is not ABSENT and value is not UNKNOWN:
            return manifest, "knip"
    return None


@lru_cache(maxsize=64)
def load_knip_config(root: str) -> KnipConfig | None:
    """The Knip config at ``root`` (a repository or package root), or None."""
    root = os.path.abspath(root)
    found = _find_config(root)
    if found is None:
        return None
    path, key = found
    data = read_static_config(path, key)
    unread: list[str] = []
    if data is UNKNOWN or not isinstance(data, dict):
        return KnipConfig(path, root, KnipWorkspace(""), [], None, [], ["(whole config)"])
    root_workspace = _workspace("", data, "", unread, root=True)
    workspaces = []
    raw = lookup(data, "workspaces")
    if isinstance(raw, dict):
        if isinstance(raw, OpenDict):
            unread.append("workspaces")
        for directory, settings in raw.items():
            if not isinstance(directory, str):
                continue
            normalised = directory.strip().strip("/")
            normalised = normalised.removeprefix("./")
            if normalised in {"", "."}:
                # ``workspaces["."]`` configures the root workspace.
                root_workspace = _workspace("", settings, "workspaces[.].", unread, root=True)
                continue
            workspaces.append(
                (
                    GlobSet([normalised]),
                    _workspace(normalised, settings, f"workspaces[{normalised}].", unread, root=False),
                )
            )
    elif raw not in (ABSENT,):
        unread.append("workspaces")
    ignore_workspaces = _globs(lookup(data, "ignoreWorkspaces"), "ignoreWorkspaces", unread)
    honoured = sorted(
        key
        for key in (
            "entry",
            "project",
            "ignore",
            "ignoreFiles",
            "ignoreDependencies",
            "ignoreBinaries",
            "ignoreUnresolved",
            "ignoreExportsUsedInFile",
            "ignoreWorkspaces",
            "workspaces",
        )
        if lookup(data, key) is not ABSENT and key not in unread
    )
    return KnipConfig(path, root, root_workspace, workspaces, ignore_workspaces, honoured, unread)


@lru_cache(maxsize=4096)
def _config_root_for(directory: str) -> str | None:
    """The outermost enclosing package root that holds a Knip config."""
    from .conventions import _enclosing_package_roots

    roots = _enclosing_package_roots(os.path.join(directory, "_"))
    for root in reversed(roots):
        if _find_config(root) is not None:
            return root
    return None


def _relative(path: str, root: str) -> str | None:
    prefix = root.rstrip(os.sep) + os.sep
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :].replace(os.sep, "/")


def _workspace_of(config: KnipConfig, relative: str) -> tuple[KnipWorkspace, str]:
    """The innermost configured workspace holding ``relative`` (its
    ``directory`` set to the matched folder) and the path inside it."""
    parts = relative.split("/")
    for index in range(len(parts) - 1, 0, -1):
        directory = "/".join(parts[:index])
        for matcher, workspace in config.workspaces:
            if matcher.matches(directory):
                return replace(workspace, directory=directory), "/".join(parts[index:])
    return config.root_workspace, relative


def _package_directory(config: KnipConfig, relative: str) -> str:
    """The innermost folder holding a ``package.json`` (a workspace), relative
    to the config root; "" for the root workspace."""
    parts = relative.split("/")
    for index in range(len(parts) - 1, 0, -1):
        if os.path.isfile(os.path.join(config.root, *parts[:index], "package.json")):
            return "/".join(parts[:index])
    return ""


def _in_nested_package(config: KnipConfig, relative: str) -> bool:
    """A file of a package below the config root (not the root workspace)."""
    parts = relative.split("/")
    for index in range(1, len(parts)):
        if os.path.isfile(os.path.join(config.root, *parts[:index], "package.json")):
            return True
    return False


def _config_for(path: str) -> tuple[KnipConfig, str] | None:
    if not _settings["enabled"]:
        return None
    absolute = os.path.abspath(path)
    root = _config_root_for(os.path.dirname(absolute))
    if root is None:
        return None
    config = load_knip_config(root)
    if config is None:
        return None
    relative = _relative(absolute, config.root)
    if relative is None:
        return None
    return config, relative


def knip_entry(path: str | os.PathLike[str]) -> bool:
    """``path`` is an entry file the project's Knip config declares."""
    found = _config_for(os.fspath(path))
    if found is None:
        return False
    config, relative = found
    workspace, inner = _workspace_of(config, relative)
    if workspace.directory == "" and _in_nested_package(config, relative):
        return False
    return bool(workspace.entry and workspace.entry.matches(inner))


# -------------------------------------------------------------- finding filter


def _finding_path(finding: dict, project_root: str) -> str | None:
    value = finding.get("file") or finding.get("filename")
    if not isinstance(value, str) or not value:
        return None
    if not os.path.isabs(value):
        value = os.path.join(project_root, value)
    return os.path.abspath(value)


def _suppression_reason(finding: dict, list_key: str, project_root: str) -> str | None:
    path = _finding_path(finding, project_root)
    if path is None:
        return None
    found = _config_for(path)
    if found is None:
        return None
    config, relative = found
    workspace, inner = _workspace_of(config, relative)
    rule = finding.get("rule_id")
    dead_code = list_key in _DEAD_CODE_KEYS
    if dead_code and not path.endswith(_JS_SUFFIXES):
        return None
    if not dead_code and rule not in _DEPENDENCY_RULES | {"SKY-Q409", "SKY-Q414"}:
        return None
    if rule == "SKY-U005" and (finding.get("metadata") or {}).get("ecosystem") not in (None, "npm"):
        return None
    if _settings["ignore_workspaces"] and config.ignore_workspaces:
        directory = _package_directory(config, relative)
        if directory and config.ignore_workspaces.matches(directory):
            return "knip ignoreWorkspaces"
    for scope, candidate in ((config.root_workspace, relative), (workspace, inner)):
        if scope.ignore and scope.ignore.matches(candidate):
            return "knip ignore"
        if rule == "SKY-E003" and scope.ignore_files and scope.ignore_files.matches(candidate):
            return "knip ignoreFiles"
    name = finding.get("name") or (finding.get("metadata") or {}).get("package_name")
    if rule in _DEPENDENCY_RULES:
        package = (finding.get("metadata") or {}).get("package_name") or name
        if config.root_workspace.ignore_dependencies.matches(package) or workspace.ignore_dependencies.matches(package):
            return "knip ignoreDependencies"
        return None
    if rule == "SKY-Q409":
        if config.root_workspace.ignore_binaries.matches(name) or workspace.ignore_binaries.matches(name):
            return "knip ignoreBinaries"
        return None
    if rule == "SKY-Q414":
        specifier = name or (finding.get("metadata") or {}).get("specifier")
        if config.root_workspace.ignore_unresolved.matches(specifier) or workspace.ignore_unresolved.matches(specifier):
            return "knip ignoreUnresolved"
        return None
    if not dead_code:
        return None
    if workspace.project is not None:
        nested_root_file = workspace.directory == "" and _in_nested_package(config, relative)
        if not nested_root_file and not workspace.project.matches(inner):
            return "knip project"
    kinds = config.root_workspace.ignore_exports_used_in_file
    if rule == "SKY-E004" and kinds:
        kind = str(finding.get("type") or "").lower()
        if "*" in kinds or (kind in _TYPE_KINDS and ({"type", "interface"} & kinds)) or kind in kinds:
            return "knip ignoreExportsUsedInFile"
    return None


def apply_knip_config(result: dict, project_root: str) -> dict:
    """Move findings the project's Knip config ignores to ``suppressed``."""
    if not _settings["enabled"] or not isinstance(result, dict):
        return {}
    project_root = os.path.abspath(project_root)
    root = _config_root_for(project_root) or (
        project_root if _find_config(project_root) is not None else None
    )
    if root is None:
        return {}
    config = load_knip_config(root)
    if config is None:
        return {}
    suppressed = result.setdefault("suppressed", [])
    counts: dict[str, int] = {}
    for key in (*_DEAD_CODE_KEYS, "quality"):
        findings = result.get(key)
        if not isinstance(findings, list):
            continue
        kept = []
        for finding in findings:
            reason = (
                _suppression_reason(finding, key, project_root)
                if isinstance(finding, dict)
                else None
            )
            if reason is None:
                kept.append(finding)
                continue
            counts[reason] = counts.get(reason, 0) + 1
            suppressed.append({**finding, "reason": reason})
        result[key] = kept
    honoured = [
        key
        for key in config.honoured
        if key != "ignoreWorkspaces" or _settings["ignore_workspaces"]
    ]
    summary = {
        "file": os.path.relpath(config.path, project_root),
        "honoured_keys": honoured,
        "unread_keys": config.unread,
        "ignore_workspaces": _settings["ignore_workspaces"],
        "suppressed": counts,
    }
    if isinstance(result.get("analysis_summary"), dict):
        result["analysis_summary"]["knip_config"] = summary
    return summary


def clear_caches() -> None:
    load_knip_config.cache_clear()
    _config_root_for.cache_clear()
