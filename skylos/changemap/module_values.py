from __future__ import annotations

import ast

from skylos.changemap.inputs import ChangeInputs, FileChange
from skylos.changemap.risk import is_test_file
from skylos.changemap.symbols import KIND_CLASS, ParsedFile


def _ts_users(parsed: ParsedFile, name: str) -> list[str]:
    return sorted(q for q, s in parsed.symbols.items() if s.kind != KIND_CLASS and name in s.reads)


def _users(parsed: ParsedFile, name: str) -> list[str]:
    if parsed.language != "python":
        return _ts_users(parsed, name)
    users = []
    for qual, node in parsed.nodes.items():
        if parsed.symbols[qual].kind == KIND_CLASS:
            continue
        if any(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load) for n in ast.walk(node)):
            users.append(qual)
    return sorted(users)


def _changed_constants(change: FileChange, head: ParsedFile, base: ParsedFile | None) -> list[tuple[str, int]]:
    base_values = {}
    if base is not None:
        base_values = base.assignments
    found = []
    for name, (start, end, value) in head.assignments.items():
        touched = set(range(start, end + 1)) & change.new_lines
        if touched and name in base_values and base_values[name][2] != value:
            found.append((name, start))
    return found


def module_changes(inputs: ChangeInputs, base_parsed: dict, head_parsed: dict) -> list[dict]:
    out = []
    for path, change in inputs.files.items():
        if path not in head_parsed or path not in base_parsed or is_test_file(path):
            continue
        head = head_parsed[path]
        for name, line in _changed_constants(change, head, base_parsed.get(path)):
            users = _users(head, name)
            if users:
                out.append({"file": path, "name": name, "line": line, "used_by": users})
    return sorted(out, key=lambda item: (item["file"], item["line"]))
