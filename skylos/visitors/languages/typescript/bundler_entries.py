"""Map a package's build outputs back to the bundler entries that emit them.

``package.json`` names built files (``./build/modern/production.js``); the
module behind that public path is the bundler entry that emits it. tsdown,
tsup, Rollup and Rolldown configs beside the manifest are read statically
(never executed): every ``entry``/``input`` option written as a string, an
array of strings or globs (``src/*.ts``, ``!src/*.test.ts``), or an object of
named entries. Wrapper calls do not hide them (``modernConfig({ entry: [...]
})``).

Output names follow the bundlers: a named entry is emitted under its key;
an array or glob entry under its path relative to the entries' lowest common
ancestor (tsup/tsdown ``outbase``), and Rollup uses the file name. A target
maps back only when exactly one entry source matches its output path.
"""

from __future__ import annotations

import os
from functools import lru_cache

from .safe_glob import safe_glob_paths

_CONFIG_STEMS = ("tsdown.config", "tsup.config", "rolldown.config", "rollup.config")
_CONFIG_EXTENSIONS = (".ts", ".mts", ".cts", ".js", ".mjs", ".cjs")
_ENTRY_KEYS = frozenset({"entry", "input"})
_SOURCE_SUFFIXES = frozenset(
    {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
)
_OUTPUT_SUFFIXES = (
    ".d.mts",
    ".d.cts",
    ".d.ts",
    ".mjs",
    ".cjs",
    ".jsx",
    ".js",
)
_MAX_ENTRY_FILES = 512


def _config_files(package_root: str) -> list[str]:
    return [
        os.path.join(package_root, stem + extension)
        for stem in _CONFIG_STEMS
        for extension in _CONFIG_EXTENSIONS
        if os.path.isfile(os.path.join(package_root, stem + extension))
    ]


def _literal(source: bytes, node) -> str | None:
    if node is None or node.type != "string":
        return None
    text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
    if len(text) < 2 or "\\" in text:
        return None
    return text[1:-1]


def _key(source: bytes, pair) -> str | None:
    key = pair.child_by_field_name("key")
    if key is None:
        return None
    text = source[key.start_byte : key.end_byte].decode("utf-8", "replace")
    return text.strip("'\"")


def _entry_values(source: bytes, value):
    """Yield ``(name_or_None, literal)`` for one entry option value."""
    literal = _literal(source, value)
    if literal is not None:
        yield None, literal
        return
    if value.type == "array":
        for child in value.named_children:
            literal = _literal(source, child)
            if literal is not None:
                yield None, literal
        return
    if value.type == "object":
        for pair in value.named_children:
            if pair.type != "pair":
                continue
            literal = _literal(source, pair.child_by_field_name("value"))
            name = _key(source, pair)
            if literal is not None and name:
                yield name, literal


def _config_entries(config_path: str):
    from .analysis import _iter_ts_nodes, _load_entry_config_ast

    source, root = _load_entry_config_ast(config_path)
    if source is None or root is None:
        return []
    found = []
    for node in _iter_ts_nodes(root):
        if node.type != "pair" or _key(source, node) not in _ENTRY_KEYS:
            continue
        value = node.child_by_field_name("value")
        if value is not None:
            found.extend(_entry_values(source, value))
    return found


def _expand(base: str, pattern: str) -> list[str]:
    if any(char in pattern for char in "*?[]{}"):
        return safe_glob_paths(
            base,
            pattern,
            allowed_suffixes=_SOURCE_SUFFIXES,
            max_matches=_MAX_ENTRY_FILES,
        )
    from .resolve import _resolve_path_target

    resolved = _resolve_path_target(base, pattern)
    if not resolved or os.path.splitext(resolved)[1].lower() not in _SOURCE_SUFFIXES:
        # ``html({ input: "index.html" })`` names a page, not a module entry.
        return []
    return [os.path.realpath(resolved)]


def _stem(path: str) -> str:
    for suffix in _OUTPUT_SUFFIXES:
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return os.path.splitext(path)[0]


@lru_cache(maxsize=1024)
def bundler_outputs(package_root: str) -> tuple[tuple[int, str, str], ...]:
    """``(rank, output stem, entry source)`` triples of the package's bundler
    configs; a lower rank is a more exact output name."""
    root = os.path.realpath(package_root)
    triples: set[tuple[int, str, str]] = set()
    for config in _config_files(root):
        named, listed, excluded = [], set(), set()
        for name, value in _config_entries(config):
            if value.startswith("!"):
                excluded.update(_expand(root, value[1:]))
            elif name is not None:
                named.extend((name, path) for path in _expand(root, value)[:1])
            else:
                listed.update(_expand(root, value))
        listed -= excluded
        if len(listed) > _MAX_ENTRY_FILES:
            continue
        for name, path in named:
            triples.add((0, name.replace(os.sep, "/"), path))
        if not listed:
            continue
        base = os.path.commonpath([os.path.dirname(path) for path in listed])
        for path in listed:
            relative = os.path.relpath(path, base).replace(os.sep, "/")
            triples.add((0, _stem(relative), path))
            triples.add((1, _stem(os.path.basename(path)), path))
    return tuple(sorted(triples))


def built_output_source(package_root: str, target: str) -> str | None:
    """The bundler entry source that emits ``target``, when exactly one does."""
    if not isinstance(target, str) or "*" in target:
        return None
    wanted = _stem(target.replace("\\", "/").lstrip("./"))
    if not wanted:
        return None
    outputs = bundler_outputs(package_root)
    for rank in (0, 1):
        matches = {
            source
            for level, output, source in outputs
            if level == rank and (wanted == output or wanted.endswith("/" + output))
        }
        if len(matches) == 1:
            return next(iter(matches))
        if matches:
            return None
    return None
