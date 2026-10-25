from __future__ import annotations

from pathlib import Path

from skylos.changemap.symbols import ParsedFile, module_name, parse_source
from skylos.changemap.ts_imports import Resolver, is_ts_path, ts_module_name
from skylos.changemap.ts_symbols import parse_ts_source

PYTHON_SUFFIX = ".py"


def is_mapped(path: str) -> bool:
    return path.endswith(PYTHON_SUFFIX) or is_ts_path(path)


def any_module_name(root: Path, path: str) -> str:
    if is_ts_path(path):
        return ts_module_name(path)
    return module_name(root, path)


def parse_any(module: str, path: str, source: str, resolver: Resolver) -> ParsedFile | None:
    if is_ts_path(path):
        return parse_ts_source(module, path, source, resolver)
    return parse_source(module, path, source)


def same_language(first: str, second: str) -> bool:
    return is_ts_path(first) == is_ts_path(second)
