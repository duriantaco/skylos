"""Tool knowledge as data: which files a JS/TS tool loads without an import.

``data/plugin_facts.json`` has one row per tool (plugin). Each row names the
packages that switch the tool on (enablers), its config files, and the files
it loads by convention: ``entry`` patterns (development: tests, configs,
stories) and ``production`` patterns (routes, pages, server handlers). Each
row records its ``origin`` and the ``source`` URLs its facts were checked at. The rows are
static facts (package names and glob patterns); no project code is executed.
Each row may carry a ``skylos`` block:

* ``export_rules`` / ``exports_default`` / ``entry_exports``: which exports
  the tool reads from the files it loads (default: every export; ``"none"``
  keeps the file a root but leaves its exports judged, as for test runners,
  whose tests export nothing they read);
* ``extra_entry`` / ``extra_production``: further conventions Skylos adds;
* ``enable_files``: config files that switch the tool on by themselves;
* ``entry_keys`` / ``dir_keys``: config keys whose literal values name entry
  files, entry globs or relocated convention directories;
* ``abstain``: the files an unreadable entry key could select (default: the
  tool's own entry and production patterns);
* ``defer_to``: a hand-written module models the tool more precisely (Next.js
  routing, Expo Router roots, react-email folders), so the row's patterns
  are kept as data but produce no entries;
* ``aliases``, ``class_contracts``, ``test_call_entries``,
  ``text_fixture_dirs``: other data a tool contributes.

A tool is on for a package when that package or an enclosing one declares an
enabler (a workspace inherits its ancestors' tools). Its patterns are
relative to each enclosing package root. Defaults always stay: a config key
that names entries only adds to them. When such a key cannot be read
statically, the files it could select (the row's ``abstain`` patterns, else
the tool's own patterns; for a directory key, those patterns under any
folder) are *abstained*: they become roots whose exports count as read. So
the table can only remove findings, never add them.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .conventions import (
    _DEPENDENCY_FIELDS,
    _enclosing_package_roots,
    _normalized,
    _package_data,
)
from .glob_patterns import GlobSet, expand_braces, static_prefix
from .static_config import (
    ABSENT,
    UNKNOWN,
    lookup,
    read_static_config,
    string_values,
)

DATA_FILE = Path(__file__).with_name("data") / "plugin_facts.json"
ALL_EXPORTS = frozenset({"*"})
NO_EXPORTS: frozenset[str] = frozenset()
_SCRIPT_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
_MAX_ABSTAIN_REASONS = 64


@dataclass(frozen=True)
class PluginEntry:
    """Why a tool loads a file: ``kind`` is ``production``, ``entry``,
    ``config`` or ``abstain``; ``exports`` are the export names it reads
    (``{"*"}`` for all, empty for none)."""

    plugin: str
    kind: str
    exports: frozenset[str]


@dataclass(frozen=True)
class _ExportRule:
    globs: GlobSet
    exports: frozenset[str]


class Plugin:
    """One row of the table, with its patterns compiled."""

    def __init__(self, row: dict) -> None:
        self.row = row
        self.name: str = row["name"]
        self.origin: str = row.get("origin", "external")
        skylos = row.get("skylos") or {}
        self.skylos: dict = skylos
        names, patterns = set(), []
        for enabler in row.get("enablers") or ():
            if isinstance(enabler, str) and len(enabler) > 2 and enabler.startswith("/") and enabler.endswith("/"):
                try:
                    patterns.append(re.compile(enabler[1:-1]))
                except re.error:
                    continue
            elif isinstance(enabler, str):
                names.add(enabler)
        self.enabler_names = frozenset(names)
        self.enabler_patterns = tuple(patterns)
        self.enable: dict = row.get("enable") or {}
        self.enable_files = tuple(skylos.get("enable_files") or ())
        self.config_patterns = tuple(row.get("config") or ())
        self.config = GlobSet(p for p in self.config_patterns if not p.endswith("package.json"))
        self.entry = GlobSet([*(row.get("entry") or ()), *(skylos.get("extra_entry") or ())])
        self.production = GlobSet([*(row.get("production") or ()), *(skylos.get("extra_production") or ())])
        self.package_json_key = skylos.get("package_json_key") or row.get("package_json_key")
        default = skylos.get("exports_default", "*")
        self.exports_default = NO_EXPORTS if default == "none" else ALL_EXPORTS
        # Test runners read no exports from their (development) entries.
        self.entry_exports = (
            NO_EXPORTS if skylos.get("entry_exports") == "none" else self.exports_default
        )
        rules = []
        for rule in skylos.get("export_rules") or ():
            exports = rule.get("exports")
            exports = ALL_EXPORTS if exports == "*" else frozenset(exports or ())
            rules.append(_ExportRule(GlobSet(rule.get("globs") or ()), exports))
        self.export_rules = tuple(rules)
        self.entry_keys = tuple(skylos.get("entry_keys") or ())
        self.dir_keys = dict(skylos.get("dir_keys") or {})
        self.abstain = tuple(skylos.get("abstain") or ())
        # A hand-written module models this tool more precisely; the row's
        # patterns stay as data but produce no entries.
        self.deferred = bool(skylos.get("defer_to"))

    def __repr__(self) -> str:
        return f"Plugin({self.name!r})"

    def exports_for(self, relative: str, kind: str = "production") -> frozenset[str]:
        for rule in self.export_rules:
            if rule.globs.matches(relative):
                return rule.exports
        return self.entry_exports if kind == "entry" else self.exports_default

    def enabled_here(self, package_root: str, data: dict | None, declared: frozenset[str]) -> bool:
        if self.enabler_names & declared:
            return True
        if self.enabler_patterns and any(
            pattern.search(name) for name in declared for pattern in self.enabler_patterns
        ):
            return True
        for pattern in self.enable_files:
            if _exists_any(package_root, pattern):
                return True
        enable = self.enable
        if not enable:
            return False
        if enable.get("always"):
            return True
        for pattern in enable.get("files") or ():
            if _exists_any(package_root, pattern):
                return True
        if not isinstance(data, dict):
            return False
        manager = enable.get("package_manager")
        if manager and str(data.get("packageManager", "")).startswith(manager):
            return True
        for key in enable.get("manifest_keys") or ():
            if lookup(data, key) not in (ABSENT, UNKNOWN):
                return True
        name_pattern = enable.get("manifest_name")
        if name_pattern and isinstance(data.get("name"), str) and re.search(name_pattern, data["name"]):
            return True
        scripts = data.get("scripts")
        for needle in enable.get("script_contains") or ():
            if isinstance(scripts, dict) and any(
                isinstance(command, str) and needle in command for command in scripts.values()
            ):
                return True
        return False


def _exists_any(directory: str, pattern: str) -> bool:
    if "*" in pattern:
        prefix = static_prefix(pattern)
        folder = os.path.join(directory, prefix) if prefix else directory
        if not os.path.isdir(folder):
            return False
        matcher = GlobSet([pattern])
        try:
            names = os.listdir(folder)
        except OSError:
            return False
        return any(
            matcher.matches(f"{prefix}/{name}" if prefix else name) for name in names
        )
    return any(os.path.isfile(os.path.join(directory, name)) for name in expand_braces(pattern))


@lru_cache(maxsize=1)
def load_table() -> tuple[Plugin, ...]:
    with DATA_FILE.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return tuple(Plugin(row) for row in data.get("plugins", ()) if isinstance(row, dict) and row.get("name"))


@lru_cache(maxsize=256)
def plugin_named(name: str) -> Plugin | None:
    return next((plugin for plugin in load_table() if plugin.name == name), None)


def _declared_packages(data: dict | None) -> frozenset[str]:
    if not isinstance(data, dict):
        return frozenset()
    names = set()
    for field in _DEPENDENCY_FIELDS:
        declared = data.get(field)
        if isinstance(declared, dict):
            names.update(name for name in declared if isinstance(name, str))
    return frozenset(names)


@lru_cache(maxsize=4096)
def _own_plugins(package_root: str) -> frozenset[str]:
    data = _package_data(package_root)
    declared = _declared_packages(data)
    return frozenset(
        plugin.name
        for plugin in load_table()
        if not plugin.deferred and plugin.enabled_here(package_root, data, declared)
    )


@lru_cache(maxsize=4096)
def enabled_plugins(package_root: str) -> frozenset[str]:
    """Tools on for ``package_root``: its own enablers plus its ancestors'."""
    package_root = _normalized(package_root)
    enabled = set(_own_plugins(package_root))
    for ancestor in _enclosing_package_roots(package_root):
        enabled |= _own_plugins(ancestor)
    return frozenset(enabled)


def _relative(path: str, root: str) -> str | None:
    prefix = root.rstrip(os.sep) + os.sep
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :].replace(os.sep, "/")


# ------------------------------------------------------- config-derived entries


@dataclass(frozen=True)
class _ConfigEntries:
    """Entries one tool's config files name for one package root."""

    production: GlobSet
    entry: GlobSet
    files: frozenset[str]  # relative paths named exactly
    production_files: frozenset[str]
    abstain: GlobSet
    unknown_keys: tuple[str, ...]


_EMPTY = GlobSet(())


def _config_files(plugin: Plugin, package_root: str) -> list[str]:
    found = []
    for pattern in plugin.config_patterns:
        if "**" in pattern or pattern.endswith("package.json"):
            continue
        for name in expand_braces(pattern):
            if "*" in name:
                continue
            candidate = os.path.join(package_root, name)
            if os.path.isfile(candidate):
                found.append(candidate)
    if plugin.package_json_key and os.path.isfile(os.path.join(package_root, "package.json")):
        found.append(os.path.join(package_root, "package.json"))
    return found


def _rebase(value: str, base_dir: str, package_root: str) -> str | None:
    """``value`` (relative to ``base_dir``) relative to ``package_root``."""
    negated = value.startswith("!")
    if negated:
        value = value[1:]
    if os.path.isabs(value):
        return None
    joined = os.path.normpath(os.path.join(base_dir, value))
    relative = _relative(joined, package_root)
    if relative is None:
        if joined == package_root:
            relative = ""
        else:
            return None
    return ("!" if negated else "") + relative


def _module_candidates(relative: str) -> list[str]:
    stem, extension = os.path.splitext(relative)
    candidates = [relative]
    if extension.lower() in {".js", ".jsx", ".mjs", ".cjs"}:
        candidates += [stem + suffix for suffix in (".ts", ".tsx", ".mts", ".cts")]
    if not extension or extension.lower() not in _SCRIPT_SUFFIXES:
        candidates += [relative + suffix for suffix in _SCRIPT_SUFFIXES]
        candidates += [relative + "/index" + suffix for suffix in _SCRIPT_SUFFIXES]
    return candidates


def _read_key(config: str, plugin: Plugin, key: str):
    package_json_key = plugin.package_json_key if os.path.basename(config) == "package.json" else None
    value = read_static_config(config, package_json_key)
    if os.path.basename(config) == "package.json" and value is ABSENT:
        return ABSENT
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, list):
        # An array of configs (``defineConfig([a, b])``): each may set the key.
        found = []
        for item in value:
            if not isinstance(item, dict):
                return UNKNOWN
            item_value = lookup(item, key)
            if item_value is UNKNOWN:
                return UNKNOWN
            if item_value is not ABSENT:
                found.append(item_value)
        return found if found else ABSENT
    return lookup(value, key)


def _default_scope(plugin: Plugin) -> list[str]:
    """What an unread entry key could select: the tool's own patterns."""
    if plugin.abstain:
        return list(plugin.abstain)
    return [
        *(plugin.row.get("entry") or ()),
        *(plugin.row.get("production") or ()),
        *(plugin.skylos.get("extra_entry") or ()),
        *(plugin.skylos.get("extra_production") or ()),
    ]


def _relocatable_scope(plugin: Plugin, default: str, applies) -> list[str]:
    """An unread directory key: the tool's patterns under any directory."""
    scope = []
    for group in applies:
        for pattern in [*(plugin.row.get(group) or ()), *(plugin.skylos.get(f"extra_{group}") or ())]:
            if pattern.startswith("!"):
                continue
            if default and pattern.startswith(default + "/"):
                scope.append("**/" + pattern[len(default) + 1 :])
            elif not default:
                scope.append("**/" + pattern)
    return scope


@lru_cache(maxsize=4096)
def _config_entries(plugin_name: str, package_root: str) -> _ConfigEntries | None:
    plugin = plugin_named(plugin_name)
    if plugin is None or not (plugin.entry_keys or plugin.dir_keys):
        return None
    configs = _config_files(plugin, package_root)
    if not configs:
        return None
    production, entry, abstain = [], [], []
    files, production_files = set(), set()
    unknown_keys = []
    for config in configs:
        config_dir = os.path.dirname(config)
        for spec in plugin.entry_keys:
            key = spec.get("key")
            if not key:
                continue
            value = _read_key(config, plugin, key)
            if value is ABSENT:
                continue
            values, complete = string_values(value) if value is not UNKNOWN else ([], False)
            base_dir = config_dir
            base = spec.get("base", "config")
            if base.startswith("key:"):
                base_value = _read_key(config, plugin, base[4:])
                if base_value is ABSENT:
                    base_value = spec.get("default_base", ".")
                if not isinstance(base_value, str):
                    complete = False
                    values = []
                else:
                    # ``spec_dir``/``sourceRoot`` are relative to the project
                    # (the tool's working directory), not the config file.
                    base_dir = os.path.normpath(os.path.join(package_root, base_value))
            elif base == "root":
                base_dir = package_root
            if not complete:
                unknown_keys.append(f"{os.path.basename(config)}:{key}")
                abstain.extend(_default_scope(plugin))
            production_kind = bool(spec.get("production"))
            for item in values:
                rebased = _rebase(item, base_dir, package_root)
                if rebased is None:
                    continue
                kind = spec.get("kind", "glob")
                if kind in {"file", "module"} or not any(ch in rebased for ch in "*?[{("):
                    if rebased.startswith("!"):
                        continue  # an exclusion never adds an entry
                    target = production_files if production_kind else files
                    target.update(_module_candidates(rebased))
                else:
                    (production if production_kind else entry).append(rebased)
        for key, spec in plugin.dir_keys.items():
            value = _read_key(config, plugin, key)
            if value is ABSENT:
                continue
            default = str(spec.get("default", ".")).strip("./")
            if not isinstance(value, str):
                unknown_keys.append(f"{os.path.basename(config)}:{key}")
                if spec.get("glob"):
                    abstain.append("**/" + spec["glob"])
                else:
                    abstain.extend(
                        _relocatable_scope(plugin, default, spec.get("applies_to") or ("production",))
                    )
                continue
            moved = _rebase(value, config_dir, package_root)
            if moved is None:
                continue
            moved = moved.strip("/")
            if spec.get("glob"):
                production.append(f"{moved}/{spec['glob']}" if moved else spec["glob"])
                continue
            applies = spec.get("applies_to") or ("production",)
            for group in applies:
                patterns = plugin.row.get(group) or ()
                patterns = [*patterns, *(plugin.skylos.get(f"extra_{group}") or ())]
                for pattern in patterns:
                    negated = pattern.startswith("!")
                    body = pattern[1:] if negated else pattern
                    if default:
                        if not body.startswith(default + "/"):
                            continue
                        body = body[len(default) + 1 :]
                    relocated = f"{moved}/{body}" if moved else body
                    (production if group == "production" else entry).append(
                        ("!" if negated else "") + relocated
                    )
    return _ConfigEntries(
        production=GlobSet(production) if production else _EMPTY,
        entry=GlobSet(entry) if entry else _EMPTY,
        files=frozenset(files),
        production_files=frozenset(production_files),
        abstain=GlobSet(abstain) if abstain else _EMPTY,
        unknown_keys=tuple(unknown_keys[:_MAX_ABSTAIN_REASONS]),
    )


# ------------------------------------------------------------ jscodeshift tests

_MAX_TEST_BYTES = 512 * 1024
_TEST_NAME_RE = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$")


@lru_cache(maxsize=4096)
def _test_call_names(directory: str, calls: tuple[str, ...]) -> frozenset[str]:
    """Transform names that tests in child folders of ``directory`` load
    with ``defineTest(__dirname, "<name>")`` (path ``<test dir>/../<name>``)."""
    pattern = re.compile(
        r"\b(?:" + "|".join(map(re.escape, calls)) + r")\s*\(\s*__dirname\s*,\s*(?P<q>['\"])(?P<name>[^'\"\r\n]+)(?P=q)"
    )
    names = set()
    try:
        children = [entry for entry in os.scandir(directory) if entry.is_dir(follow_symlinks=False)]
    except OSError:
        return frozenset()
    for child in children:
        if child.name in {"node_modules", ".git"}:
            continue
        try:
            entries = list(os.scandir(child.path))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                continue
            if not (child.name == "__tests__" or _TEST_NAME_RE.search(entry.name)):
                continue
            if not entry.name.endswith(_SCRIPT_SUFFIXES):
                continue
            try:
                if entry.stat().st_size > _MAX_TEST_BYTES:
                    continue
                text = Path(entry.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__dirname" not in text:
                continue
            for match in pattern.finditer(text):
                name = match.group("name")
                if name.startswith("/") or ".." in name.split("/"):
                    continue
                names.add(os.path.normpath(name).replace(os.sep, "/"))
    return frozenset(names)


def _test_call_entry(absolute: str) -> str | None:
    """The table row whose test helper loads ``absolute`` by name, or None.

    A test in ``<base>/<child>/`` names a transform relative to ``<base>``;
    ``<base>`` is the transform's folder or, for a nested name, an ancestor.
    """
    stem = os.path.splitext(absolute)[0]
    for plugin in load_table():
        spec = plugin.skylos.get("test_call_entries")
        if not spec:
            continue
        calls = tuple(spec.get("calls") or ())
        base = os.path.dirname(absolute)
        for _depth in range(4):
            for name in _test_call_names(base, calls):
                target = os.path.normpath(os.path.join(base, name))
                if target in {absolute, stem}:
                    return plugin.name
            parent = os.path.dirname(base)
            if parent == base:
                break
            base = parent
    return None


@lru_cache(maxsize=1)
def text_fixture_directories() -> frozenset[str]:
    """Folders whose files tools read as text (fixtures), from the table."""
    names = set()
    for plugin in load_table():
        names.update(plugin.skylos.get("text_fixture_dirs") or ())
    return frozenset(names)


# ----------------------------------------------------------------- public API


@lru_cache(maxsize=1024)
def _ordered_plugins(names: frozenset[str]) -> tuple[Plugin, ...]:
    return tuple(plugin for plugin in load_table() if plugin.name in names)


@lru_cache(maxsize=65536)
def plugin_entry(path: str | os.PathLike[str]) -> PluginEntry | None:
    """Why a tool in the table loads ``path``, or None.

    Every matching tool contributes the exports it reads; a production or
    config match outranks a development entry, which outranks abstention.
    """
    absolute = _normalized(path)
    if absolute.endswith(_DECLARATION_SUFFIXES):
        return None
    matches: list[tuple[str, str, frozenset[str]]] = []
    package_roots = _enclosing_package_roots(absolute)
    for package_root in package_roots:
        relative = _relative(absolute, package_root)
        if relative is None:
            continue
        for plugin in _ordered_plugins(enabled_plugins(package_root)):
            kind = None
            if plugin.production.matches(relative):
                kind = "production"
            elif plugin.config.matches(relative):
                kind = "config"
            elif plugin.entry.matches(relative):
                kind = "entry"
            configured = _config_entries(plugin.name, package_root)
            if kind is None and configured is not None:
                if relative in configured.production_files or configured.production.matches(relative):
                    kind = "production"
                elif relative in configured.files or configured.entry.matches(relative):
                    kind = "entry"
                elif configured.abstain.matches(relative):
                    kind = "abstain"
            if kind is None:
                continue
            if plugin.name == "sveltekit" and kind in {"production", "entry"}:
                from skylos.deadcode.sveltekit import supersedes_default_entry

                manifest = _package_data(package_root) or {}
                if package_root != package_roots[0] or not any(
                    isinstance(manifest.get(field), dict)
                    and "@sveltejs/kit" in manifest[field]
                    for field in _DEPENDENCY_FIELDS
                ):
                    continue
                if supersedes_default_entry(package_root, relative):
                    continue
            # An abstained file may be an entry whose exports the tool reads.
            exports = ALL_EXPORTS if kind == "abstain" else plugin.exports_for(relative, kind)
            if kind == "config":
                exports = ALL_EXPORTS if plugin.exports_default else NO_EXPORTS
            matches.append((plugin.name, kind, exports))
    from .knip_config import knip_entry

    if knip_entry(absolute):
        # The project's own Knip config declares it an entry: an entry file's
        # exports are public.
        matches.append(("knip-config", "production", ALL_EXPORTS))
    if not matches:
        name = _test_call_entry(absolute)
        if name is not None:
            return PluginEntry(name, "entry", ALL_EXPORTS)
        return None
    rank = {"production": 0, "config": 1, "entry": 2, "abstain": 3}
    matches.sort(key=lambda item: rank[item[1]])
    plugin, kind, _ = matches[0]
    exports: set[str] = set()
    for _name, _kind, names in matches:
        exports |= names
    return PluginEntry(plugin, kind, ALL_EXPORTS if "*" in exports else frozenset(exports))


def plugin_entry_exports(path: str | os.PathLike[str]) -> frozenset[str] | None:
    """Exports a tool reads from ``path`` (``{"*"}`` for all), or None when
    no tool in the table loads it."""
    found = plugin_entry(path)
    if found is None:
        return None
    return found.exports


def abstained_config_keys(package_root: str) -> list[str]:
    """Config keys Skylos could not read statically for ``package_root``."""
    keys = []
    for plugin in _ordered_plugins(enabled_plugins(_normalized(package_root))):
        configured = _config_entries(plugin.name, _normalized(package_root))
        if configured is not None:
            keys.extend(f"{plugin.name}:{key}" for key in configured.unknown_keys)
    return keys


def plugin_aliases(package_root: str) -> dict[str, str]:
    """Module aliases (``$lib`` -> ``src/lib``) of the tools on for a package."""
    aliases: dict[str, str] = {}
    for plugin in _ordered_plugins(enabled_plugins(_normalized(package_root))):
        for key, target in (plugin.skylos.get("aliases") or {}).items():
            aliases.setdefault(key, target)
    return aliases


_DATA_CONFIG_SUFFIXES = (".json", ".jsonc", ".json5", ".yml", ".yaml", ".toml")
_SCRIPT_CONFIG_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx")


@lru_cache(maxsize=1)
def config_file_names() -> tuple[frozenset[str], frozenset[str]]:
    """Basenames of the table's config files: (data configs, JS/TS configs).

    Data configs are JSON/YAML/TOML or extensionless rc files; the
    dependency rules read their string values as package-name evidence.
    """
    data, scripts = set(), set()
    for plugin in load_table():
        if plugin.skylos.get("config_strings") is False:
            continue
        for pattern in plugin.config_patterns:
            if pattern.endswith("package.json"):
                continue
            for name in expand_braces(pattern):
                base = name.rsplit("/", 1)[-1]
                if not base or any(char in base for char in "*?[(!"):
                    continue
                lower = base.lower()
                if lower.endswith(_SCRIPT_CONFIG_SUFFIXES):
                    scripts.add(base)
                elif lower.endswith(_DATA_CONFIG_SUFFIXES) or "." not in base.lstrip("."):
                    data.add(base)
    return frozenset(data), frozenset(scripts)


@lru_cache(maxsize=1)
def _config_globs() -> GlobSet:
    patterns = []
    for plugin in load_table():
        if plugin.skylos.get("config_strings") is False:
            continue
        patterns.extend(p for p in plugin.config_patterns if not p.endswith("package.json"))
    return GlobSet(patterns)


def is_plugin_config_path(relative: str) -> bool:
    """``relative`` (to its package root) is a config file of a table row."""
    return _config_globs().matches(relative.replace(os.sep, "/"))


def class_contracts() -> list[dict]:
    """Interfaces whose methods a framework calls (Lit ``ReactiveController``)."""
    contracts = []
    for plugin in load_table():
        contracts.extend(plugin.skylos.get("class_contracts") or ())
    return contracts


def coverage_counts() -> dict[str, int]:
    """How many rows with external facts (``origin`` other than ``skylos``)
    the table turns into Skylos entries or config reads."""
    external = [plugin for plugin in load_table() if plugin.origin != "skylos"]
    with_entries = [p for p in external if p.entry or p.production or p.config]
    with_keys = [p for p in external if p.entry_keys or p.dir_keys]
    return {
        "external_plugins": len(external),
        "with_file_patterns": len(with_entries),
        "with_config_keys": len(with_keys),
    }


def clear_caches() -> None:
    for function in (
        load_table,
        plugin_named,
        _own_plugins,
        enabled_plugins,
        _config_entries,
        _test_call_names,
        _ordered_plugins,
        config_file_names,
        _config_globs,
        text_fixture_directories,
        plugin_entry,
    ):
        function.cache_clear()
