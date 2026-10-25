from __future__ import annotations

import ast

from skylos.changemap.facts import dotted
from skylos.changemap.graph import HeadGraph
from skylos.changemap.risk import simple_name
from skylos.changemap.symbols import KIND_CLASS, KIND_METHOD, Symbol
from skylos.changemap.ts_nodes import POSITIONAL

_BOUND_FIRST = frozenset({"self", "cls"})
_NAMED = (POSITIONAL, "keyword")


def _params(symbol: Symbol, bound: bool) -> list[tuple]:
    params = list(symbol.params)
    if bound and params and params[0][0] == POSITIONAL and params[0][1] in _BOUND_FIRST:
        params = params[1:]
    return params


def _layout(params: list[tuple]) -> dict:
    return {
        POSITIONAL: [name for kind, name, _ in params if kind == POSITIONAL],
        "names": {name for kind, name, _ in params if kind in _NAMED},
        "required": {name for kind, name, has_default in params if kind in _NAMED and not has_default},
        "varargs": any(kind == "varargs" for kind, _, _ in params),
        "varkw": any(kind == "varkw" for kind, _, _ in params),
    }


def _unknown_shape(call: ast.Call) -> bool:
    return any(isinstance(arg, ast.Starred) for arg in call.args) or any(k.arg is None for k in call.keywords)


def _positional_breaks(count: int, old: dict, new: dict) -> bool:
    if count > len(new[POSITIONAL]) and not new["varargs"]:
        return True
    return old[POSITIONAL][:count] != new[POSITIONAL][:count]


def _keyword_breaks(keywords: set[str], bound: set[str], new: dict) -> bool:
    if keywords - new["names"] and not new["varkw"]:
        return True
    return bool(keywords & bound) or bool(new["required"] - bound - keywords)


def call_breaks(call: ast.Call, before: list[tuple], after: list[tuple]) -> bool | None:
    if _unknown_shape(call):
        return None
    old = _layout(before)
    new = _layout(after)
    count = len(call.args)
    bound = set(new[POSITIONAL][:count])
    keywords = {k.arg for k in call.keywords}
    return _positional_breaks(count, old, new) or _keyword_breaks(keywords, bound, new)


def _target(symbol: Symbol) -> tuple[str, bool]:
    if symbol.kind == KIND_CLASS:
        return simple_name(symbol.full_name), True
    if symbol.kind == KIND_METHOD and symbol.qual.endswith(".__init__"):
        return simple_name(symbol.full_name.rsplit(".", 1)[0]), True
    return simple_name(symbol.full_name), symbol.kind == KIND_METHOD


def _calls_in(graph: HeadGraph, caller: dict, simple: str) -> list[ast.Call]:
    parsed = graph.parsed.get(caller["file"])
    if parsed is None:
        return []
    node = parsed.nodes.get(caller["name"][len(parsed.module) + 1:])
    if node is None:
        return []
    return [c for c in ast.walk(node) if isinstance(c, ast.Call) and simple_name(dotted(c.func) or "") == simple]


def _ts_shape_breaks(shape: tuple[int, bool], params: list[tuple]) -> bool:
    count, unknown = shape
    if unknown:
        return False
    positional = [p for p in params if p[0] == POSITIONAL]
    rest = any(p[0] == "varargs" for p in params)
    required = 0
    for _, _, has_default in positional:
        if has_default:
            break
        required += 1
    return (count > len(positional) and not rest) or count < required


def _ts_breaks(graph: HeadGraph, caller: dict, after: Symbol) -> bool:
    parsed = graph.parsed.get(caller["file"])
    if parsed is None:
        return False
    target = after.full_name
    if after.kind == KIND_METHOD and after.qual.endswith(".constructor"):
        target = after.full_name.rsplit(".", 1)[0]
    shapes = parsed.call_shapes.get(caller["name"], {})
    found = [s for alias in graph._aliases(target) for s in shapes.get(alias, [])]
    return any(_ts_shape_breaks(shape, list(after.params)) for shape in found)


def _breaks(graph: HeadGraph, caller: dict, before: Symbol, after: Symbol) -> bool:
    if after.node is None:
        return _ts_breaks(graph, caller, after)
    simple, bound = _target(after)
    old = _params(before, bound)
    new = _params(after, bound)
    return any(call_breaks(call, old, new) for call in _calls_in(graph, caller, simple))


def _summary(affected: list[dict], breaking: list[str]) -> dict:
    return {
        "production": sum(1 for c in affected if not c["is_test"]),
        "tests": sum(1 for c in affected if c["is_test"]),
        "breaking": breaking,
    }


def affected_callers(graph: HeadGraph, callers: list[dict], change: str | None, before: Symbol | None, after: Symbol | None) -> dict:
    if change is None:
        return _summary([], [])
    stale = [c for c in callers if not c["in_change"]]
    if change == "compatible":
        return _summary(stale, [])
    affected = [c for c in stale if _breaks(graph, c, before, after)]
    return _summary(affected, sorted(c["name"] for c in affected))
