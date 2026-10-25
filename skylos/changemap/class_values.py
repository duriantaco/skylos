from __future__ import annotations

import ast

from skylos.changemap.graph import HeadGraph
from skylos.changemap.risk import is_security_setting
from skylos.changemap.symbols import KIND_CLASS, KIND_METHOD, Symbol


def _reads_attribute(node, class_name: str, attribute: str) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr == attribute and isinstance(child.value, ast.Name):
            if child.value.id in ("self", "cls", class_name):
                return True
    return False


def _reads(method: Symbol, class_qual: str, attribute: str) -> bool:
    if method.node is None:
        return f"this.{attribute}" in method.reads
    return _reads_attribute(method.node, class_qual, attribute)


def _class_methods(graph: HeadGraph, path: str, class_qual: str) -> list[Symbol]:
    parsed = graph.parsed.get(path)
    if parsed is None:
        return []
    return [s for q, s in parsed.symbols.items() if q.startswith(class_qual + ".") and s.kind == KIND_METHOD]


def values_changed(graph: HeadGraph, path: str, before: Symbol | None, after: Symbol | None) -> list[dict]:
    if before is None or after is None or after.kind != KIND_CLASS:
        return []
    methods = _class_methods(graph, path, after.qual)
    changed = []
    for name, value in sorted(after.attributes.items()):
        old = before.attributes.get(name)
        if old is None or old == value:
            continue
        changed.append({
            "name": name, "before": old, "after": value,
            "used_by": sorted(m.qual for m in methods if _reads(m, after.qual, name)),
            "security": is_security_setting(name),
        })
    return changed
