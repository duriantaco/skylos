from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ParsedPythonFile:
    path: Path
    tree: ast.Module


def parse_python_files(files: Iterable[Path]) -> list[ParsedPythonFile]:
    parsed: list[ParsedPythonFile] = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        parsed.append(ParsedPythonFile(path=path, tree=tree))
    return parsed
