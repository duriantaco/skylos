"""SKY-Q414: a relative or path-alias JS/TS import that names no file.

Resolution follows the module rules of TypeScript, Node and the common
bundlers, read from static files only (no config or project code executes):

* relative specifiers try the exact path, every source, declaration,
  component and data extension (``.ts .tsx .mts .cts .js .jsx .mjs .cjs
  .d.ts .vue .svelte .astro .json`` and any other single extension),
  React Native platform variants, ``.js`` -> ``.ts`` source mapping, index
  files, a directory ``package.json`` and tsconfig ``rootDirs``;
* an alias is a tsconfig ``paths`` pattern (other than the ``*`` catch-all)
  or a package.json ``imports`` key that matches the specifier; each mapped
  target is tried like a relative path, with build output mapped to source.

Only requests that load at run time are checked; type-only imports are
erased by every compiler and bundler. Bare package specifiers belong to
SKY-Q408. Quiet by design: query or loader suffixes, URL/virtual modules
(``virtual:``, ``astro:``, ``~icons/``, ``$app/``, ``$env/``), optional loads
(``try`` bodies, ``import().catch``), ambient ``declare module`` names,
specifiers under a ``resolve.alias`` key of a JS bundler config (an alias
Skylos cannot read holds back every alias specifier below that config),
targets in excluded, ignored or out-of-project paths, importers in fixture,
snapshot and template directories, and alias requests under a tsconfig that
extends a generated config that is not on disk.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_project_text_no_symlink

from .module_requests import CachedModuleResolver, ModuleRequest
from .platform_extensions import PLATFORM_SUFFIXES
from .resolve import (
    _candidate_package_targets,
    _find_nearest_tsconfig,
    _read_json_file,
    _resolve_extends_path,
)
from .workspace import _load_jsonc

RULE_ID = "SKY-Q414"
SEVERITY = "MEDIUM"

_URL_SPECIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_VIRTUAL_PREFIXES = ("~icons/", "~virtual/", "$app/", "$env/", "$service-worker")
_OPAQUE_CHARACTERS = ("?", "!", "*", "\\", "\0", "${")
_JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
_DECLARATION_RESTS = frozenset({"d.ts", "d.mts", "d.cts"})
_CODE_EXTENSIONS = frozenset(
    {"ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "vue", "svelte", "astro"}
)
_TS_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")
# Sample projects, codemod inputs, scaffolding templates and recorded outputs
# hold imports on purpose, for tools that read or copy them as data. Names are
# compared without case, ``_`` or ``-`` (``__testfixtures__``, ``test-data``).
_DATA_DIRECTORIES = frozenset(
    {
        "fixture",
        "fixtures",
        "testfixtures",
        "testdata",
        "snapshots",
        "template",
        "templates",
    }
)
# A file under a test directory that is neither a test nor imported by any
# module is input for the code under test (a compiler or plugin sample), read
# as text rather than loaded.
_TEST_DIRECTORIES = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "e2e", "__mocks__"}
)
_TEST_FILE = re.compile(
    r"[.\-_](?:test|spec|e2e)\.(?:[cm]?[jt]sx?|vue|svelte|astro)$", re.IGNORECASE
)
# A declaration starts its line; the same words in a comment do not count.
_AMBIENT_MODULE = re.compile(
    rb"^[ \t]*(?:export[ \t]+)?declare[ \t]+module[ \t]+(['\"])"
    rb"(?P<name>[^'\"\r\n]+)\1",
    re.MULTILINE,
)
_BUNDLER_TOOLS = (
    "vite|vitest|webpack|rollup|rspack|rsbuild|nuxt|astro|svelte|quasar|vue|"
    "craco|next|tsup|metro|babel|snowpack|umi|farm|modern|parcel|esbuild|"
    "remix|react-router|electron\\.vite|storybook"
)
_BUNDLER_CONFIG_NAME = re.compile(
    rf"^(?:\.?(?:{_BUNDLER_TOOLS})(?:[.-][\w-]+)*\.config(?:\.[\w-]+)*"
    r"|webpack(?:[.-][\w-]+)*|\.babelrc|\.umirc(?:\.[\w-]+)*)"
    r"\.(?:js|cjs|mjs|ts|cts|mts)$",
    re.IGNORECASE,
)
# Storybook's ``main`` config customises the bundler for the whole project.
_STORYBOOK_MAIN = re.compile(r"^main\.(?:js|cjs|mjs|ts|cts|mts)$")
_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+$", re.IGNORECASE)
_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_JSON_ALIAS_CONFIGS = frozenset({".babelrc", ".babelrc.json", "babel.config.json"})
_ALIAS_KEYS = frozenset({"alias", "extraNodeModules"})
_MAX_WALK_ENTRIES = 200_000
_MAX_CONFIG_BYTES = 1_000_000
_MAX_AMBIENT_FILES = 20_000
_MAX_AMBIENT_BYTES = 2_000_000


@dataclass
class _AliasScope:
    directory: str
    keys: set[str] = field(default_factory=set)
    opaque: bool = False


@dataclass
class _TsconfigFacts:
    root_dirs: list[str]
    generated_base_missing: bool
    # The effective ``paths`` (the nearest config in the extends chain that
    # declares them wins whole, as in TypeScript) and every directory its
    # targets may be relative to: the effective ``baseUrl`` and the declaring
    # config's own directory.
    paths: dict = field(default_factory=dict)
    path_bases: list[str] = field(default_factory=list)


class _PathProbe:
    """Existence checks with one directory listing per directory."""

    def __init__(self) -> None:
        self._entries: dict[str, frozenset[str]] = {}

    def _list(self, directory: str) -> frozenset[str]:
        if directory not in self._entries:
            try:
                self._entries[directory] = frozenset(os.listdir(directory))
            except OSError:
                self._entries[directory] = frozenset()
        return self._entries[directory]

    def _has_variant(self, directory: str, stem: str, *, code_only: bool) -> bool:
        prefix = stem + "."
        for entry in self._list(directory):
            if not entry.startswith(prefix):
                continue
            rest = entry[len(prefix) :]
            if rest in _DECLARATION_RESTS:
                pass
            else:
                parts = rest.split(".")
                if len(parts) == 2 and parts[0] in PLATFORM_SUFFIXES:
                    extension = parts[1]
                elif len(parts) == 1:
                    extension = parts[0]
                else:
                    continue
                if not extension or (code_only and extension not in _CODE_EXTENSIONS):
                    continue
            if os.path.isfile(os.path.join(directory, entry)):
                return True
        return False

    def exists(self, target: str) -> bool:
        if os.path.isfile(target):
            return True
        if os.path.isdir(target):
            if os.path.isfile(os.path.join(target, "package.json")):
                return True
            if self._has_variant(target, "index", code_only=False):
                return True
        directory, name = os.path.split(target)
        if not name or not os.path.isdir(directory):
            return False
        if self._has_variant(directory, name, code_only=False):
            return True
        return any(
            name.endswith(extension)
            and len(name) > len(extension)
            and self._has_variant(directory, name[: -len(extension)], code_only=True)
            for extension in _JS_EXTENSIONS
        )


def _within(path: str, directory: str) -> bool:
    try:
        return os.path.commonpath([path, directory]) == directory
    except ValueError:
        return False


def _pattern_match(pattern: str, source: str) -> str | None:
    if pattern.count("*") > 1:
        return None
    if "*" not in pattern:
        return "" if source == pattern else None
    prefix, _, suffix = pattern.partition("*")
    if (
        len(source) >= len(prefix) + len(suffix)
        and source.startswith(prefix)
        and source.endswith(suffix)
    ):
        return source[len(prefix) : len(source) - len(suffix)]
    return None


def _package_targets(entry, found: list[str | None]) -> None:
    if entry is None or isinstance(entry, str):
        found.append(entry)
    elif isinstance(entry, list):
        for item in entry:
            _package_targets(item, found)
    elif isinstance(entry, dict):
        for value in entry.values():
            _package_targets(value, found)
    else:
        found.append(None)


def _ambient_matches(source: str, patterns: set[str]) -> bool:
    return any(_pattern_match(pattern, source) is not None for pattern in patterns)


def _is_out_of_scope_specifier(source: str) -> bool:
    return (
        any(token in source for token in _OPAQUE_CHARACTERS)
        or source.startswith(_VIRTUAL_PREFIXES)
        or bool(_URL_SPECIFIER.match(source))
        or source.startswith("/")
    )


def _in_data_directory(path: str, root: str) -> bool:
    try:
        parts = Path(path).relative_to(root).parts
    except ValueError:
        return False
    return any(
        part.lower().replace("_", "").replace("-", "") in _DATA_DIRECTORIES
        for part in parts[:-1]
    )


class _Checker:
    def __init__(self, root: str, resolver, exclude_folders) -> None:
        self.root = root
        self.cached = (
            resolver
            if isinstance(resolver, CachedModuleResolver)
            else CachedModuleResolver(resolver)
        )
        self.exclude_folders = exclude_folders
        self.probe = _PathProbe()
        self.reasons: Counter[str] = Counter()
        self._tsconfig_facts: dict[str, _TsconfigFacts] = {}
        self._alias_scopes: list[_AliasScope] | None = None
        self._ambient: set[str] | None = None
        self._ambient_files: list[str] = []

    # -- configuration facts -------------------------------------------------

    def _facts(self, importer: str) -> _TsconfigFacts | None:
        tsconfig = _find_nearest_tsconfig(importer, self.root)
        if tsconfig is None:
            return None
        if tsconfig not in self._tsconfig_facts:
            self._tsconfig_facts[tsconfig] = _read_tsconfig_facts(tsconfig)
        return self._tsconfig_facts[tsconfig]

    def _alias_scopes_list(self) -> list[_AliasScope]:
        if self._alias_scopes is None:
            self._alias_scopes = _discover_alias_scopes(
                self.root, self.exclude_folders
            )
        return self._alias_scopes

    def set_ambient_sources(self, files) -> None:
        self._ambient_files = sorted(
            file for file in files if file.endswith(_TS_SOURCE_SUFFIXES)
        )

    def _ambient_patterns(self) -> set[str]:
        if self._ambient is None:
            self._ambient = set()
            for file in self._ambient_files[:_MAX_AMBIENT_FILES]:
                try:
                    if os.path.getsize(file) > _MAX_AMBIENT_BYTES:
                        continue
                    data = Path(file).read_bytes()
                except OSError:
                    continue
                if b"declare" not in data:
                    continue
                for match in _AMBIENT_MODULE.finditer(data):
                    self._ambient.add(match.group("name").decode("utf-8", "replace"))
        return self._ambient

    # -- per request -----------------------------------------------------------

    def _target_held_back(self, target: str) -> str | None:
        if not _within(target, self.root):
            return "target_outside_project"
        if "node_modules" in Path(target).parts:
            return "target_in_node_modules"
        if self.exclude_folders and should_exclude_path(
            Path(target), Path(self.root), self.exclude_folders
        ):
            return "target_excluded"
        return None

    def _relative_targets(self, request: ModuleRequest) -> list[str]:
        target = os.path.normpath(
            os.path.join(os.path.dirname(request.importer), request.source)
        )
        targets = [target]
        facts = self._facts(request.importer)
        if facts is not None and facts.root_dirs:
            # rootDirs merges several directories into one virtual tree.
            for base in facts.root_dirs:
                if _within(target, base):
                    relative = os.path.relpath(target, base)
                    targets.extend(
                        os.path.normpath(os.path.join(other, relative))
                        for other in facts.root_dirs
                        if other != base
                    )
        return targets

    def _tsconfig_alias(self, request: ModuleRequest):
        facts = self._facts(request.importer)
        if facts is None or not facts.paths:
            return None
        matched_patterns, targets = [], []
        for pattern, pattern_targets in facts.paths.items():
            if pattern == "*" or not isinstance(pattern, str):
                continue
            matched = _pattern_match(pattern, request.source)
            if matched is None or not isinstance(pattern_targets, list):
                continue
            matched_patterns.append(pattern)
            for item in pattern_targets:
                if not isinstance(item, str):
                    continue
                item = item.replace("*", matched, 1) if "*" in item else item
                targets.extend(
                    os.path.normpath(os.path.join(base, item))
                    for base in facts.path_bases
                )
        if not matched_patterns:
            return None
        return f"tsconfig paths alias '{min(matched_patterns)}'", targets

    def _package_imports_alias(self, request: ModuleRequest):
        directory = os.path.dirname(request.importer)
        while True:
            manifest = os.path.join(directory, "package.json")
            if os.path.isfile(manifest):
                break
            if directory == self.root or not _within(directory, self.root):
                return None
            parent = os.path.dirname(directory)
            if parent == directory:
                return None
            directory = parent
        imports = _read_json_file(manifest).get("imports")
        if not isinstance(imports, dict):
            return None
        matched_keys, raw_targets = [], []
        for key, entry in imports.items():
            if not isinstance(key, str):
                continue
            matched = _pattern_match(key, request.source)
            if matched is None:
                continue
            matched_keys.append(key)
            found: list[str | None] = []
            _package_targets(entry, found)
            for item in found:
                if not isinstance(item, str) or not item.startswith("./"):
                    # null exclusions and package targets are not files here.
                    return "opaque"
                raw_targets.append(item.replace("*", matched))
        if not matched_keys:
            return None
        targets = [
            os.path.normpath(os.path.join(directory, variant))
            for item in raw_targets
            for variant in _candidate_package_targets(item)
        ]
        return f"package.json imports key '{min(matched_keys)}'", targets

    def _package_may_provide(self, request: ModuleRequest) -> bool:
        """Whether a matching npm package could load an alias that misses.

        TypeScript and bundlers fall back to ``node_modules`` when a
        ``paths`` substitution finds no file.
        """
        parts = request.source.split("/")
        name = "/".join(parts[:2]) if request.source.startswith("@") else parts[0]
        if not _PACKAGE_NAME.match(name):
            return False
        directory = os.path.dirname(request.importer)
        while True:
            if os.path.isdir(os.path.join(directory, "node_modules", name)):
                return True
            manifest = _read_json_file(os.path.join(directory, "package.json"))
            if any(
                isinstance(manifest.get(field_name), dict)
                and name in manifest[field_name]
                for field_name in _DEPENDENCY_FIELDS
            ):
                return True
            parent = os.path.dirname(directory)
            if directory == self.root or parent == directory:
                return False
            directory = parent

    def _bundler_holds_back(self, request: ModuleRequest) -> bool:
        for scope in self._alias_scopes_list():
            if scope.opaque and _within(request.importer, scope.directory):
                return True
            if any(request.source.startswith(key) for key in scope.keys):
                return True
        return False

    def check(self, request: ModuleRequest) -> tuple[dict, list[str]] | None:
        source = request.source
        if request.guarded:
            self.reasons["optional_load"] += 1
            return None
        if request.type_only:
            # Erased by every compiler and bundler: a type checker's concern.
            self.reasons["type_only_request"] += 1
            return None
        if _is_out_of_scope_specifier(source):
            if not source.startswith("node:"):
                self.reasons["query_url_or_virtual_specifier"] += 1
            return None
        relative = source in {".", ".."} or source.startswith(("./", "../"))
        if self.cached.resolve(source, request.importer):
            return None
        alias = None
        if relative:
            targets = self._relative_targets(request)
        else:
            if source.startswith("#"):
                alias = self._package_imports_alias(request)
            if alias is None:
                alias = self._tsconfig_alias(request)
            if alias is None:
                return None  # a bare package specifier: SKY-Q408's concern
            if alias == "opaque":
                self.reasons["non_file_alias_target"] += 1
                return None
            alias, targets = alias
            if self._package_may_provide(request):
                self.reasons["package_may_provide"] += 1
                return None
        if any(self.probe.exists(target) for target in targets):
            return None
        for target in targets:
            reason = self._target_held_back(target)
            if reason is not None:
                self.reasons[reason] += 1
                return None
        facts = self._facts(request.importer)
        if facts is not None and facts.generated_base_missing and not relative:
            self.reasons["generated_tsconfig_missing"] += 1
            return None
        if not relative and self._bundler_holds_back(request):
            self.reasons["bundler_alias"] += 1
            return None
        if _ambient_matches(source, self._ambient_patterns()):
            self.reasons["ambient_module_declaration"] += 1
            return None
        finding = _finding(request, alias, targets[0] if targets else None, self.root)
        return finding, targets


def _read_tsconfig_facts(tsconfig: str) -> _TsconfigFacts:
    """Read ``paths``, ``baseUrl`` and ``rootDirs`` through ``extends``.

    Configs are visited nearest first (a later ``extends`` entry overrides an
    earlier one), so the first config declaring an option supplies it.
    """
    root_dirs = paths = paths_dir = base_url = None
    generated_base_missing = False
    config_dir = os.path.dirname(tsconfig)

    def option_path(directory: str, value: str) -> str:
        # TypeScript 5.5 ``${configDir}`` names the directory of the config
        # in use, whichever config in the chain spells it.
        value = value.replace("${configDir}", config_dir)
        return os.path.normpath(os.path.join(directory, value))

    order, pending, seen = [], [tsconfig], set()
    while pending and len(seen) <= 32:
        # Depth first, last ``extends`` entry first: the precedence order.
        current = pending.pop()
        real = os.path.realpath(current)
        if real in seen:
            continue
        seen.add(real)
        data = _load_jsonc(Path(current))
        order.append((current, data))
        extends = data.get("extends")
        bases = extends if isinstance(extends, list) else [extends]
        for base in bases:
            if not isinstance(base, str) or not base:
                continue
            resolved = _resolve_extends_path(os.path.dirname(current), base)
            if resolved is not None:
                pending.append(resolved)
            elif base.startswith((".", "/")):
                generated_base_missing = True
    for current, data in order:
        options = data.get("compilerOptions")
        if not isinstance(options, dict):
            continue
        directory = os.path.dirname(current)
        if root_dirs is None and isinstance(options.get("rootDirs"), list):
            root_dirs = [
                option_path(directory, item)
                for item in options["rootDirs"]
                if isinstance(item, str)
            ]
        if paths is None and isinstance(options.get("paths"), dict):
            paths = {
                pattern: [
                    item.replace("${configDir}", config_dir)
                    if isinstance(item, str)
                    else item
                    for item in targets
                ]
                if isinstance(targets, list)
                else targets
                for pattern, targets in options["paths"].items()
            }
            paths_dir = directory
        if base_url is None and isinstance(options.get("baseUrl"), str):
            base_url = option_path(directory, options["baseUrl"])
    path_bases = [base for base in (base_url, paths_dir) if base]
    return _TsconfigFacts(
        root_dirs=root_dirs or [],
        generated_base_missing=generated_base_missing,
        paths=paths or {},
        path_bases=list(dict.fromkeys(path_bases)),
    )


def _finding(request: ModuleRequest, alias: str | None, target: str | None, root):
    if alias:
        mapped = os.path.relpath(target, root).replace(os.sep, "/") if target else "?"
        detail = f"its {alias} maps it to '{mapped}', which matches no file"
    else:
        detail = (
            "no file, extension variant, index file or package.json matches it"
        )
    message = f"Unresolved import '{request.source}': {detail}."
    return {
        "rule_id": RULE_ID,
        "kind": "quality",
        "type": "import",
        "severity": SEVERITY,
        "name": request.source,
        "simple_name": request.source,
        "value": "unresolved",
        "message": message,
        "file": request.importer,
        "basename": Path(request.importer).name,
        "line": request.line,
        "col": 0,
        "metadata": {
            "specifier": request.source,
            "import_kind": request.kind,
            "type_only": request.type_only,
            "alias": alias,
        },
    }


# -- bundler aliases ---------------------------------------------------------


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _string_value(source: bytes, node) -> str | None:
    if node is None or node.type != "string":
        return None
    text = _node_text(source, node)
    if len(text) < 2 or "\\" in text:
        return None
    return text[1:-1]


def _key_name(source: bytes, key) -> str | None:
    if key is None:
        return None
    if key.type in {"property_identifier", "identifier"}:
        return _node_text(source, key)
    return _string_value(source, key)


def _alias_value(source: bytes, value, scope: _AliasScope) -> None:
    if value is None:
        scope.opaque = True
        return
    if value.type == "object":
        for child in value.named_children:
            if child.type == "pair":
                key = _key_name(source, child.child_by_field_name("key"))
                if key:
                    scope.keys.add(key.rstrip("$"))
                else:
                    scope.opaque = True
            elif child.type == "shorthand_property_identifier":
                scope.keys.add(_node_text(source, child))
            elif child.type != "comment":
                scope.opaque = True
        return
    if value.type == "array":
        for element in value.named_children:
            if element.type == "comment":
                continue
            find = None
            if element.type == "object":
                for child in element.named_children:
                    if child.type == "pair" and _key_name(
                        source, child.child_by_field_name("key")
                    ) == "find":
                        find = _string_value(source, child.child_by_field_name("value"))
            if find:
                scope.keys.add(find)
            else:
                scope.opaque = True
        return
    scope.opaque = True


def _scan_js_config(path: str, scope: _AliasScope) -> None:
    from .analysis import _entry_parser_for_path, _parse_entry_source

    try:
        if os.path.getsize(path) > _MAX_CONFIG_BYTES:
            scope.opaque = True
            return
        source = Path(path).read_bytes()
    except OSError:
        return
    if b"alias" not in source and b"extraNodeModules" not in source:
        return
    parser = _entry_parser_for_path(path)
    if parser is None:
        scope.opaque = True
        return
    root = _parse_entry_source(parser, source, path).root_node
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "pair":
            key = _key_name(source, node.child_by_field_name("key"))
            if key in _ALIAS_KEYS:
                _alias_value(source, node.child_by_field_name("value"), scope)
                continue
        elif node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None and _node_text(source, prop) in _ALIAS_KEYS:
                scope.opaque = True
        elif (
            node.type == "shorthand_property_identifier"
            and _node_text(source, node) in _ALIAS_KEYS
        ):
            scope.opaque = True
        pending.extend(node.named_children)


def _json_alias_keys(data, scope: _AliasScope, depth: int = 0) -> None:
    if depth > 16:
        return
    if isinstance(data, dict):
        for key, value in data.items():
            if key in _ALIAS_KEYS:
                if isinstance(value, dict):
                    scope.keys.update(str(item).rstrip("$") for item in value)
                else:
                    scope.opaque = True
            else:
                _json_alias_keys(value, scope, depth + 1)
    elif isinstance(data, list):
        for item in data:
            _json_alias_keys(item, scope, depth + 1)


def _discover_alias_scopes(root: str, exclude_folders) -> list[_AliasScope]:
    scopes: list[_AliasScope] = []
    seen = 0
    root_path = Path(root)
    for directory, dirnames, filenames in os.walk(root):
        seen += len(dirnames) + len(filenames)
        if seen > _MAX_WALK_ENTRIES:
            # Configuration beyond the walk budget is unknown: hold back aliases.
            scopes.append(_AliasScope(directory=root, opaque=True))
            break
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in {"node_modules", ".git"}
            and not os.path.islink(os.path.join(directory, name))
            and not (
                exclude_folders
                and should_exclude_path(
                    Path(directory, name), root_path, exclude_folders
                )
            )
        )
        scope = _AliasScope(directory=directory)
        for name in sorted(filenames):
            path = os.path.join(directory, name)
            if os.path.islink(path):
                continue
            if name in _JSON_ALIAS_CONFIGS:
                text = read_project_text_no_symlink(
                    root, os.path.relpath(path, root), max_bytes=_MAX_CONFIG_BYTES
                )
                try:
                    _json_alias_keys(json.loads(text or "{}"), scope)
                except ValueError:
                    pass
            elif name == "package.json":
                # Babel options and Parcel's top-level ``alias`` field.
                data = _read_json_file(path)
                _json_alias_keys(
                    {key: data[key] for key in ("babel", "alias") if key in data},
                    scope,
                )
            elif _BUNDLER_CONFIG_NAME.match(name) or (
                _STORYBOOK_MAIN.match(name)
                and os.path.basename(directory) == ".storybook"
            ):
                _scan_js_config(path, scope)
        if scope.keys or scope.opaque:
            if os.path.basename(directory) == ".storybook":
                scope.directory = os.path.dirname(directory)
            scopes.append(scope)
    return scopes


# -- git ignore ---------------------------------------------------------------


def _git_ignored(root: str, findings: list[dict], targets: dict[int, list[str]]):
    """Drop findings whose every candidate is ignored by Git (generated)."""
    from skylos.core.git_safety import (
        read_only_git_command,
        read_only_git_environment,
    )

    candidates = sorted(
        {
            os.path.relpath(candidate, root)
            for paths in targets.values()
            for candidate in paths
            if _within(candidate, root)
        }
    )
    if not candidates or not os.path.exists(os.path.join(root, ".git")):
        return findings, 0
    try:
        result = subprocess.run(
            read_only_git_command(["check-ignore", "--stdin", "-z"]),
            input="\0".join(candidates) + "\0",
            capture_output=True,
            text=True,
            timeout=10,
            cwd=root,
            env=read_only_git_environment(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return findings, 0
    if result.returncode not in {0, 1}:
        return findings, 0
    ignored = {
        os.path.normpath(os.path.join(root, item))
        for item in result.stdout.split("\0")
        if item
    }
    kept = []
    for index, finding in enumerate(findings):
        if any(path in ignored for path in targets.get(index, ())):
            continue
        kept.append(finding)
    return kept, len(findings) - len(kept)


def _ignore_candidates(target: str) -> list[str]:
    candidates = [target]
    candidates.extend(
        f"{target}.{extension}" for extension in sorted(_CODE_EXTENSIONS | {"json"})
    )
    candidates.extend(f"{target}.{rest}" for rest in sorted(_DECLARATION_RESTS))
    candidates.extend(
        os.path.join(target, f"index.{extension}")
        for extension in sorted(_CODE_EXTENSIONS)
    )
    for extension in _JS_EXTENSIONS:
        if target.endswith(extension):
            stem = target[: -len(extension)]
            candidates.extend(
                f"{stem}.{other}" for other in ("ts", "tsx", "mts", "cts")
            )
    return candidates


def _test_input_file(path: str, root: str) -> bool:
    try:
        parts = Path(path).relative_to(root).parts
    except ValueError:
        return False
    return (
        any(part.lower() in _TEST_DIRECTORIES for part in parts[:-1])
        and not _TEST_FILE.search(parts[-1])
    )


def _drop_unimported_test_inputs(findings, module_requests, checker, root):
    if not any(_test_input_file(item["file"], root) for item in findings):
        return findings
    imported = {
        checker.cached.resolve(request.source, request.importer)
        for request in module_requests.requests
    }
    kept = [
        item
        for item in findings
        if not _test_input_file(item["file"], root) or item["file"] in imported
    ]
    if len(kept) != len(findings):
        checker.reasons["unimported_test_input"] += len(findings) - len(kept)
    return kept


def find_unresolved_imports(
    project_root, module_requests, resolver=None, *, exclude_folders=None
) -> tuple[list[dict], dict]:
    """Return SKY-Q414 findings and a coverage receipt for literal requests."""
    root = os.path.realpath(str(project_root))
    checker = _Checker(root, resolver, exclude_folders)
    checker.set_ambient_sources(module_requests.files)
    findings: list[dict] = []
    targets: dict[int, list[str]] = {}
    checked = 0
    for request in module_requests.requests:
        if _in_data_directory(request.importer, root):
            checker.reasons["data_directory"] += 1
            continue
        checked += 1
        outcome = checker.check(request)
        if outcome is None:
            continue
        finding, finding_targets = outcome
        targets[len(findings)] = [
            candidate
            for target in finding_targets
            for candidate in _ignore_candidates(target)
        ]
        findings.append(finding)
    findings, ignored = _git_ignored(root, findings, targets)
    if ignored:
        checker.reasons["target_git_ignored"] += ignored
    findings = _drop_unimported_test_inputs(findings, module_requests, checker, root)
    receipt = {
        "scope": "relative_and_alias_module_requests",
        "requests_seen": checked,
        "component_files": len(module_requests.component_files),
        "unparsed_components": module_requests.unparsed_components,
        "reported": len(findings),
        "held_back": dict(sorted(checker.reasons.items())),
    }
    return findings, receipt
