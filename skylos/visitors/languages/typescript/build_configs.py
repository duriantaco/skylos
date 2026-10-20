"""Entry files and module aliases declared by Jest and Angular workspace configs.

Jest (``jest.config.*`` or the ``jest`` field of ``package.json``):

* ``setupFiles``, ``setupFilesAfterEnv``, ``globalSetup``, ``testEnvironment``,
  ``transform``, ``reporters`` and the other path-valued options name files
  Jest loads itself. Paths may start with ``<rootDir>`` and are otherwise
  relative to ``rootDir`` (the config's directory unless ``rootDir`` is set).
* ``moduleNameMapper`` maps an import specifier (a regular expression) to a
  file, so under Jest ``import { x } from "pkg/sub"`` reads ``x`` from the
  mapped file. Mappings apply to importers under ``rootDir`` and only when the
  specifier does not resolve to a project file by itself.

Angular (``angular.json`` / ``.angular.json``): every target's ``options`` and
``configurations`` name the build's entry files (``main``, ``browser``,
``server``, ``polyfills``, ``scripts``, ``ssr.entry``, ``karmaConfig``,
``proxyConfig``) relative to the workspace root. ``fileReplacements`` swaps
``replace`` for ``with`` in a build configuration: the replacement is the
same module under another build, so it is imported by, and its exports are
consumed by, whoever imports the replaced file.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

try:
    from re import _parser as _regex_parser
except ImportError:  # Python 3.10
    import sre_parse as _regex_parser

from skylos.core.safe_cache_io import read_text_no_symlink

_JEST_CONFIG_EXTENSIONS = ("js", "ts", "mjs", "cjs", "mts", "cts", "json")
JEST_CONFIG_NAMES = tuple(f"jest.config.{ext}" for ext in _JEST_CONFIG_EXTENSIONS)
_JEST_FILE_OPTIONS = (
    "setupFiles",
    "setupFilesAfterEnv",
    "globalSetup",
    "globalTeardown",
    "testEnvironment",
    "snapshotResolver",
    "snapshotSerializers",
    "testSequencer",
    "resolver",
    "runner",
    "testRunner",
    "testResultsProcessor",
    "dependencyExtractor",
    "watchPlugins",
    "reporters",
    "transform",
)
_ROOT_DIR_TOKEN = "<rootDir>"

ANGULAR_WORKSPACE_NAMES = ("angular.json", ".angular.json")
_ANGULAR_ENTRY_OPTIONS = (
    "main",
    "browser",
    "server",
    "polyfills",
    "scripts",
    "karmaConfig",
    "proxyConfig",
)
_ANGULAR_TEST_TARGETS = frozenset({"test", "e2e"})
_MAX_CONFIG_BYTES = 1024 * 1024
_SOURCE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")


@dataclass(frozen=True)
class JestModuleMapping:
    root_dir: str
    pattern: re.Pattern[str]
    targets: tuple[str, ...]


@dataclass(frozen=True)
class JestConfig:
    path: str
    entry_files: frozenset[str]
    mappings: tuple[JestModuleMapping, ...]


@dataclass(frozen=True)
class AngularWorkspace:
    path: str
    # (file, scope) with scope "prod" for build targets, "dev" for tests.
    entry_files: frozenset[tuple[str, str]]
    # (replaced file, replacement file)
    file_replacements: tuple[tuple[str, str], ...]


def _read_json(path: str):
    text = read_text_no_symlink(path, max_bytes=_MAX_CONFIG_BYTES, errors="ignore")
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _source_file(base_dir: str, value) -> str | None:
    """``value`` as a JS/TS file path relative to ``base_dir``, if one exists."""
    if not isinstance(value, str) or not value or "://" in value:
        return None
    target = os.path.normpath(os.path.join(base_dir, value))
    candidates = [target]
    if not target.endswith(_SOURCE_EXTENSIONS):
        candidates.extend(target + extension for extension in _SOURCE_EXTENSIONS)
        candidates.extend(
            os.path.join(target, "index" + extension)
            for extension in _SOURCE_EXTENSIONS
        )
    for candidate in candidates:
        if candidate.endswith(_SOURCE_EXTENSIONS) and os.path.isfile(candidate):
            return os.path.realpath(candidate)
    return None


# ------------------------------------------------------------------- Jest


def _jest_path(root_dir: str, value: str) -> str:
    if value.startswith(_ROOT_DIR_TOKEN):
        value = root_dir + value[len(_ROOT_DIR_TOKEN) :]
    return value


def _json_strings(value):
    """String values (not object keys) nested in a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_strings(item)


# Mapper patterns come from the scanned repository and run against its import
# specifiers, so bound both and skip nested quantifiers (``(a+)+``).
_MAX_JEST_PATTERN_CHARS = 256
_MAX_JEST_MAPPINGS = 128
_MAX_SPECIFIER_CHARS = 512


def _bounded_jest_pattern(pattern: str) -> bool:
    """Accept a bounded subset without backtracking amplification.

    Common mapper patterns need anchors, literals, character classes and a
    single wildcard capture. Reject repeated alternatives, nested repetition,
    backreferences/lookarounds and many independent repetitions. Merely
    limiting input length does not bound Python's exponential regex matcher.
    """
    repetitions = variable_repetitions = 0
    alternatives = 1
    pending = [(list(_regex_parser.parse(pattern)), False)]
    while pending:
        tokens, repeated = pending.pop()
        for operation, value in tokens:
            kind = str(operation)
            if kind in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
                if repeated:
                    return False
                low, high, child = value
                repetitions += 1
                if high != low:
                    if high - low > 1:
                        variable_repetitions += 1
                    else:
                        alternatives *= 2
                if (
                    repetitions > 8
                    or variable_repetitions > 1
                    or alternatives > 32
                    or low > _MAX_SPECIFIER_CHARS
                ):
                    return False
                pending.append((list(child), True))
            elif kind == "SUBPATTERN":
                pending.append((list(value[-1]), repeated))
            elif kind == "BRANCH":
                if repeated:
                    return False
                alternatives *= len(value[1])
                if alternatives > 32:
                    return False
                pending.extend((list(branch), False) for branch in value[1])
            elif kind not in {"LITERAL", "NOT_LITERAL", "ANY", "IN", "AT", "CATEGORY"}:
                return False
    return True


def _compile_jest_pattern(pattern) -> re.Pattern[str] | None:
    if not isinstance(pattern, str) or len(pattern) > _MAX_JEST_PATTERN_CHARS:
        return None
    try:
        if not _bounded_jest_pattern(pattern):
            return None
        return re.compile(pattern)
    except (re.error, TypeError, RecursionError):
        return None


def _jest_config_from_options(path: str, options: dict, base_dir: str) -> JestConfig:
    root_dir = base_dir
    raw_root = options.get("rootDir")
    if isinstance(raw_root, str) and raw_root:
        root_dir = os.path.normpath(os.path.join(base_dir, raw_root))

    entry_files: set[str] = set()
    for option in _JEST_FILE_OPTIONS:
        for value in _json_strings(options.get(option)):
            resolved = _source_file(root_dir, _jest_path(root_dir, value))
            if resolved:
                entry_files.add(resolved)

    mappings: list[JestModuleMapping] = []
    mapper = options.get("moduleNameMapper")
    if isinstance(mapper, dict):
        for pattern, target in mapper.items():
            compiled = _compile_jest_pattern(pattern)
            targets = tuple(
                _jest_path(root_dir, value) for value in _json_strings(target)
            )
            if compiled is not None and targets:
                mappings.append(
                    JestModuleMapping(os.path.realpath(root_dir), compiled, targets)
                )

    projects = options.get("projects")
    for project in projects if isinstance(projects, list) else ():
        if isinstance(project, dict):
            nested = _jest_config_from_options(path, project, root_dir)
            entry_files.update(nested.entry_files)
            mappings.extend(nested.mappings)

    return JestConfig(
        path, frozenset(entry_files), tuple(mappings[:_MAX_JEST_MAPPINGS])
    )


_JS_ESCAPE_RE = re.compile(
    r"\\(?:u\{(?P<code>[0-9A-Fa-f]+)\}|u(?P<u4>[0-9A-Fa-f]{4})"
    r"|x(?P<x2>[0-9A-Fa-f]{2})|(?P<char>[\s\S]))"
)
_JS_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
}


def _js_unescape(raw: str) -> str:
    """The value of a JS string literal from its source text between quotes."""

    def replace(match: re.Match[str]) -> str:
        code = match.group("code") or match.group("u4") or match.group("x2")
        if code is not None:
            try:
                return chr(int(code, 16))
            except (ValueError, OverflowError):
                return match.group(0)
        char = match.group("char")
        if char in "\r\n":
            return ""  # line continuation
        return _JS_SIMPLE_ESCAPES.get(char, char)

    return _JS_ESCAPE_RE.sub(replace, raw)


def _js_config_options(config_path: str) -> dict:
    """Literal options of a ``module.exports``/``export default`` config."""
    from .analysis import (
        _find_config_root_objects,
        _iter_object_pairs,
        _load_entry_config_ast,
        _pair_key_text,
        _pair_value_node,
        _string_node_value,
    )

    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None:
        return {}

    def literal(node):
        if node is None:
            return None
        if node.type == "string":
            value = _string_node_value(source, node)
            return _js_unescape(value) if value is not None else None
        if node.type == "array":
            return [literal(child) for child in node.named_children]
        if node.type == "object":
            values = {}
            for pair in _iter_object_pairs(node):
                key = _pair_key_text(source, pair)
                if key is not None and pair.named_children[0].type == "string":
                    key = _js_unescape(key)
                if key is not None:
                    values[key] = literal(_pair_value_node(pair))
            return values
        return None

    options: dict = {}
    for object_node in _find_config_root_objects(source, root_node):
        value = literal(object_node)
        if isinstance(value, dict):
            for key, item in value.items():
                options.setdefault(key, item)
    return options


def load_jest_configs(package_root: str) -> list[JestConfig]:
    configs: list[JestConfig] = []
    for name in JEST_CONFIG_NAMES:
        path = os.path.join(package_root, name)
        if not os.path.isfile(path):
            continue
        if name.endswith(".json"):
            options = _read_json(path)
        else:
            options = _js_config_options(path)
        if isinstance(options, dict):
            configs.append(_jest_config_from_options(path, options, package_root))
    package_json = os.path.join(package_root, "package.json")
    if os.path.isfile(package_json):
        data = _read_json(package_json)
        if isinstance(data, dict) and isinstance(data.get("jest"), dict):
            configs.append(
                _jest_config_from_options(package_json, data["jest"], package_root)
            )
    return configs


def _within(path: str, directory: str) -> bool:
    return path.startswith(directory.rstrip(os.sep) + os.sep)


def resolve_jest_mapping(
    mappings, source: str, importer: str, ts_files: set[str] | None = None
) -> str | None:
    """The file a Jest ``moduleNameMapper`` entry maps ``source`` to."""
    if len(source) > _MAX_SPECIFIER_CHARS:
        return None
    for mapping in mappings:
        if not _within(os.path.abspath(importer), mapping.root_dir):
            continue
        match = mapping.pattern.search(source)
        if match is None:
            continue
        for target in mapping.targets:
            try:
                mapped = re.sub(
                    r"\$(\d+)",
                    lambda group: match.group(int(group.group(1))) or "",
                    target,
                )
            except (IndexError, re.error):
                continue
            if not os.path.isabs(mapped):
                # A package name (``identity-obj-proxy``) is not a project file.
                continue
            resolved = _source_file(mapping.root_dir, mapped)
            if resolved and (ts_files is None or resolved in ts_files):
                return resolved
        # Jest uses the first matching pattern.
        return None
    return None


class JestMappedResolver:
    """Resolve bare specifiers as before, then through ``moduleNameMapper``."""

    def __init__(self, inner, mappings, ts_files: set[str]) -> None:
        self._inner = inner
        self._mappings = tuple(mappings)
        self._ts_files = ts_files

    def resolve(self, source: str, importer: str) -> str | None:
        if self._inner is not None:
            resolved = self._inner.resolve(source, importer)
            if resolved:
                return resolved
        return resolve_jest_mapping(
            self._mappings, source, importer, ts_files=self._ts_files
        )

    def __getattr__(self, name):
        inner = self.__dict__.get("_inner")
        if inner is None:
            raise AttributeError(name)
        return getattr(inner, name)


# ---------------------------------------------------------------- Angular


def _angular_option_files(base_dir: str, options: dict) -> set[str]:
    files: set[str] = set()
    if not isinstance(options, dict):
        return files
    for option in _ANGULAR_ENTRY_OPTIONS:
        value = options.get(option)
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, dict):
                entry = entry.get("input")
            resolved = _source_file(base_dir, entry) if isinstance(entry, str) else None
            if resolved:
                files.add(resolved)
    ssr = options.get("ssr")
    if isinstance(ssr, dict):
        resolved = _source_file(base_dir, ssr.get("entry"))
        if resolved:
            files.add(resolved)
    return files


def _angular_replacements(base_dir: str, options: dict) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not isinstance(options, dict):
        return pairs
    for item in options.get("fileReplacements") or ():
        if not isinstance(item, dict):
            continue
        replaced = item.get("replace", item.get("src"))
        replacement = item.get("with", item.get("replaceWith"))
        replaced_file = _source_file(base_dir, replaced)
        replacement_file = _source_file(base_dir, replacement)
        if replaced_file and replacement_file and replaced_file != replacement_file:
            pairs.append((replaced_file, replacement_file))
    return pairs


def load_angular_workspace(directory: str) -> AngularWorkspace | None:
    for name in ANGULAR_WORKSPACE_NAMES:
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            break
    else:
        return None
    data = _read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("projects"), dict):
        return None

    entry_files: set[tuple[str, str]] = set()
    replacements: list[tuple[str, str]] = []
    for project in data["projects"].values():
        if not isinstance(project, dict):
            continue
        targets = project.get("architect") or project.get("targets")
        if not isinstance(targets, dict):
            continue
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            scope = "dev" if target_name in _ANGULAR_TEST_TARGETS else "prod"
            option_sets = [target.get("options")]
            configurations = target.get("configurations")
            if isinstance(configurations, dict):
                option_sets.extend(configurations.values())
            for options in option_sets:
                for file_path in _angular_option_files(directory, options):
                    entry_files.add((file_path, scope))
                replacements.extend(_angular_replacements(directory, options))

    return AngularWorkspace(
        path, frozenset(entry_files), tuple(dict.fromkeys(replacements))
    )


def apply_ts_module_substitutions(
    replacements, consumed_exports, importers_of, wildcard_edges
) -> None:
    """Give a replacement file the importers and consumers of the replaced one."""
    if not replacements:
        return

    def keys_for(mapping, real_path):
        return [key for key in mapping if os.path.realpath(key) == real_path]

    for replaced, replacement in replacements:
        for key in keys_for(importers_of, replaced):
            importers_of[replacement].update(importers_of[key])
        for key in keys_for(consumed_exports, replaced):
            consumed_exports[replacement].update(consumed_exports[key])
        for sources in wildcard_edges.values():
            if any(os.path.realpath(source) == replaced for source in sources):
                sources.add(replacement)
