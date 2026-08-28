from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from skylos.analysis.ast_cache import (
    MODE_STRICT,
    load_python_module,
    releases_python_ast_cache,
)


@dataclass(frozen=True)
class ParsedPythonFile:
    path: Path
    tree: ast.Module


@releases_python_ast_cache
def parse_python_files(files: Iterable[Path]) -> list[ParsedPythonFile]:
    """Parse ``files``, skipping any that cannot be read or parsed.

    The returned entries own their trees, so the session drops the cache's
    duplicate references on the way out. Nested in an analyzer run the
    session is a no-op and the trees stay shared with the other passes.
    """
    parsed: list[ParsedPythonFile] = []
    for path in files:
        _, tree = load_python_module(path, MODE_STRICT)
        if tree is None:
            continue
        parsed.append(ParsedPythonFile(path=path, tree=tree))
    return parsed
