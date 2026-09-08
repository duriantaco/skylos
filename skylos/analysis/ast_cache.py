"""Run-scoped cache of parsed Python module ASTs.

Repo-wide rule passes (phantom refs, API hallucination coverage, API
signature checks, dead-code liveness) each need the same files parsed.
This cache lets them share one tree per file while preserving each call
site's read semantics: sources are cached per (path, read mode), and a
tree is parsed once per distinct source text, so call sites with
different read modes still share a tree whenever the decoded source is
identical (the common case of a regular, valid-UTF-8 file).

Equal sources are pooled per path, so a file read under several modes
costs one string rather than one per mode.

Lifetime is a session. Every entry point that populates the cache -- the
analyzer run and each public rule scanner -- runs inside one, and the
outermost session clears on the way out, so nothing outlives the call the
caller made. Sessions nest, so a scanner called from the analyzer still
shares the run's cache instead of dropping it early. Within a session,
entries are dropped when a file's identity changes. Derived per-tree
caches can register a clear callback so their id(tree)-keyed entries
never outlive the trees stored here.

Not thread-safe: the caches and the session depth are plain module
globals, so sessions must not overlap across threads -- two entry points
running concurrently would clear each other's live entries. Skylos'
own file-level parallelism is process-based, and every caller of these
entry points is single-threaded.
"""

from __future__ import annotations

import ast
import functools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

# Read modes. Each mirrors the exact read semantics of the call sites it
# replaces; adding a mode must not change an existing one.
MODE_REPLACE = "replace"  # read_text(encoding="utf-8", errors="replace")
MODE_STRICT = "strict"  # read_text(encoding="utf-8")
MODE_SAFE_REPLACE_2MB = "safe_replace_2mb"  # no-symlink read, 2 MiB cap
MODE_SAFE_IGNORE_1MB = "safe_ignore_1mb"  # no-symlink read, 1 MiB cap
MODE_IGNORE = "ignore"  # read_text(encoding="utf-8", errors="ignore")

_SAFE_MODE_ARGS = {
    MODE_SAFE_REPLACE_2MB: {"max_bytes": 2 * 1024 * 1024, "errors": "replace"},
    MODE_SAFE_IGNORE_1MB: {"max_bytes": 1_000_000, "errors": "ignore"},
}

_MISSING = object()

_sources: dict[tuple[str, str], str | None] = {}
_trees: dict[str, dict[str, ast.Module | None]] = {}
_source_pool: dict[str, dict[str, str]] = {}
_path_tokens: dict[str, tuple | None] = {}
_dependent_clears: list[Callable[[], None]] = []
_session_depth = 0


def mode_max_bytes(mode: str) -> int | None:
    """Byte cap enforced by ``mode``, or None when the mode reads uncapped."""
    safe_args = _SAFE_MODE_ARGS.get(mode)
    return None if safe_args is None else safe_args["max_bytes"]


def _read_source(path: Path, mode: str) -> str | None:
    if mode == MODE_REPLACE:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    if mode == MODE_IGNORE:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
    if mode == MODE_STRICT:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
    safe_args = _SAFE_MODE_ARGS[mode]
    return read_text_no_symlink(path, encoding="utf-8", **safe_args)


def _path_token(path: Path) -> tuple | None:
    """Identity of the file at ``path``, or None when it cannot be stat-ed.

    Includes st_ctime_ns so that a rewrite whose size and mtime are then
    restored -- what ``cp -p``, ``rsync -t`` and a test calling os.utime
    all do -- is still seen as a change.
    """
    try:
        stat_result = path.stat()
    except OSError:
        return None
    return (
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
        stat_result.st_size,
        stat_result.st_ino,
        stat_result.st_dev,
    )


def _drop_path(key: str) -> None:
    """Forget everything cached for ``key`` after the file changed."""
    for callback in _dependent_clears:
        callback()
    for cached_key in [entry for entry in _sources if entry[0] == key]:
        del _sources[cached_key]
    _trees.pop(key, None)
    _source_pool.pop(key, None)


def load_python_source(path: Path, mode: str) -> str | None:
    """Return the decoded source for ``path`` under ``mode``, or None."""
    path = Path(path)
    key = str(path)

    token = _path_token(path)
    cached_token = _path_tokens.get(key, _MISSING)
    if cached_token is _MISSING:
        _path_tokens[key] = token
    elif cached_token != token:
        _drop_path(key)
        _path_tokens[key] = token

    source = _sources.get((key, mode), _MISSING)
    if source is _MISSING:
        source = _read_source(path, mode)
        if source is not None:
            # Modes differ only in read policy, so they usually decode to
            # equal text; keep one string object per file rather than one
            # per mode.
            source = _source_pool.setdefault(key, {}).setdefault(source, source)
        _sources[(key, mode)] = source
    return source


def load_python_module(path: Path, mode: str) -> tuple[str | None, ast.Module | None]:
    """Return ``(source, tree)`` for ``path`` under read mode ``mode``.

    ``source`` is None when the file cannot be read under that mode;
    ``tree`` is None when the file cannot be read or does not parse.
    """
    source = load_python_source(path, mode)
    if source is None:
        return None, None
    per_path = _trees.setdefault(str(path), {})
    tree = per_path.get(source, _MISSING)
    if tree is _MISSING:
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            tree = None
        per_path[source] = tree
    return source, tree


def register_dependent_clear(callback: Callable[[], None]) -> None:
    """Register a callback run whenever this cache is cleared.

    Used by caches keyed on id(tree) for trees held here, so their
    entries are dropped before the trees can be garbage collected.
    """
    if callback not in _dependent_clears:
        _dependent_clears.append(callback)


@contextmanager
def python_ast_cache_session() -> Iterator[None]:
    """Scope the cache to this block.

    Sessions nest and only the outermost one clears -- on the way in as
    well as on the way out -- so a rule pass entered directly starts clean
    and releases everything it cached, while the same pass nested inside an
    analyzer run neither inherits stale entries nor drops the run's.
    """
    global _session_depth
    if _session_depth == 0:
        clear_python_ast_cache()
    _session_depth += 1
    try:
        yield
    finally:
        _session_depth -= 1
        if _session_depth == 0:
            clear_python_ast_cache()


def releases_python_ast_cache(func):
    """Run ``func`` inside a cache session, preserving its signature."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with python_ast_cache_session():
            return func(*args, **kwargs)

    return wrapper


def clear_python_ast_cache() -> None:
    for callback in _dependent_clears:
        callback()
    _sources.clear()
    _trees.clear()
    _source_pool.clear()
    _path_tokens.clear()
