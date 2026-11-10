from __future__ import annotations

import ast
import hashlib
from functools import lru_cache
from pathlib import Path

from skylos.changemap.facts import dotted
from skylos.changemap.languages import parse_any
from skylos.changemap.risk import is_test_file
from skylos.changemap.symbols import KIND_CLASS, owner_of
from skylos.changemap.ts_imports import Resolver, is_ts_path
from skylos.graph.other_languages import extract_other, other_language

DOC_LIMIT = 300
MAX_FILE_BYTES = 1_500_000


@lru_cache(maxsize=4)
def _resolver(root: str) -> Resolver:
    return Resolver(Path(root))


def code_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _docstring(node) -> str:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return ""
    text = ast.get_docstring(node) or ""
    first = text.strip().split("\n\n", 1)[0]
    first = " ".join(first.split())
    if len(first) > DOC_LIMIT:
        return first[: DOC_LIMIT - 3] + "..."
    return first


def _bases(node) -> list[str]:
    if not isinstance(node, ast.ClassDef):
        return []
    names = []
    for base in node.bases:
        name = dotted(base)
        if name and name not in {"object", "Generic", "Protocol"}:
            names.append(name)
    return names


def _called_python(node) -> list[str]:
    if node is None:
        return []
    names = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return sorted(names)


def _called(parsed, symbols: dict) -> dict[str, list[str]]:
    called = {}
    for full_name, symbol in symbols.items():
        if parsed.language == "python":
            names = _called_python(symbol.node)
        else:
            sites = parsed.call_sites.get(full_name) or {}
            if not sites:
                continue
            names = sorted({target.rsplit(".", 1)[-1] for target in sites})
        if names:
            called[full_name] = names
    return called


def _targets(owner: str, kind: str, targets) -> list[str]:
    kept = []
    for target in targets:
        if kind != KIND_CLASS and target.startswith(owner + "."):
            continue
        kept.append(target)
    return sorted(kept)


def _expectations(path: str, source: str) -> list[dict]:
    from skylos.done.expected_answers import js_cases, python_cases

    if path.endswith(".py"):
        cases = python_cases(path, source)
    else:
        cases = js_cases(path, source)
    found = []
    for case in cases:
        found.append(_case_record(case, is_ts_path(path)))
    return found


def _case_record(case, js: bool) -> dict:
    from skylos.done.expected_answers import _NONLIT, _show

    calls = []
    for call in case.calls:
        args = []
        for value in call.args:
            if value == _NONLIT:
                args.append("…")
            else:
                args.append(_show(value, js))
        for name, value in call.kwargs:
            if value == _NONLIT:
                args.append(f"{name}=…")
            else:
                args.append(f"{name}={_show(value, js)}")
        calls.append({"name": call.name, "text": f"{call.name}({', '.join(args)})"})
    expected = sorted(_show(value, js) for value in case.expected)
    return {"test": case.test, "calls": calls, "expected": expected}


def inside(root: Path, path: str) -> Path | None:
    base = root.resolve()
    full = (base / path).resolve()
    if full == base or base not in full.parents:
        return None
    return full


def extract_file(root: str, path: str, module: str) -> dict:
    full = inside(Path(root), path)
    if full is None:
        return {"path": path, "error": "points outside the repository"}
    try:
        if full.stat().st_size > MAX_FILE_BYTES:
            return {"path": path, "error": "file is larger than 1.5 MB"}
        raw = full.read_bytes()  # skylos: ignore[SKY-D325] path is from git's file list, resolved inside the repository by inside(), size checked above
    except OSError as exc:
        return {"path": path, "error": f"could not read: {exc.strerror or exc}"}
    source = raw.decode("utf-8", "replace")
    return extract_source(root, path, module, source)


def extract_source(root: str, path: str, module: str, source: str) -> dict:
    """Extract graph facts from a caller's bounded source snapshot, without rereading it."""
    digest = code_hash(source)
    if other_language(path):
        try:
            return extract_other(path, module, source, digest)
        except (RecursionError, ValueError, MemoryError) as exc:
            return {"path": path, "hash": digest, "error": f"could not parse: {type(exc).__name__}"}
    try:
        parsed = parse_any(module, path, source, _resolver(root))
    except (RecursionError, ValueError, MemoryError) as exc:
        return {"path": path, "hash": digest, "error": f"could not parse: {type(exc).__name__}"}
    if parsed is None:
        return {"path": path, "hash": digest, "error": "could not parse"}
    symbols = []
    for symbol in parsed.symbols.values():
        node = symbol.node
        symbols.append({
            "qual": symbol.qual,
            "full_name": symbol.full_name,
            "kind": symbol.kind,
            "start": symbol.start,
            "end": symbol.end,
            "signature": symbol.signature,
            "decorators": list(symbol.decorators),
            "doc": _docstring(node),
            "bases": _bases(node),
            "attributes": sorted(symbol.attributes),
            "code_hash": code_hash(symbol.shape),
        })
    kinds = {s["full_name"]: s["kind"] for s in symbols}
    merged: dict[str, set[str]] = {}
    for name, targets in parsed.graph.items():
        owner = name
        if owner not in kinds:
            owner = owner_of(name, kinds)
        if owner is None:
            continue
        merged.setdefault(owner, set()).update(targets)
    calls = {}
    for owner, targets in merged.items():
        kept = _targets(owner, kinds[owner], targets)
        if kept:
            calls[owner] = kept
    record = {
        "path": path,
        "hash": digest,
        "module": parsed.module,
        "language": parsed.language,
        "lines": source.count("\n") + 1,
        "is_test": is_test_file(path),
        "symbols": symbols,
        "calls": calls,
        "called": _called(parsed, {s.full_name: s for s in parsed.symbols.values()}),
        "aliases": dict(parsed.aliases),
        "star_from": list(parsed.star_from),
    }
    if record["is_test"]:
        try:
            record["expectations"] = _expectations(path, source)
        except (RecursionError, ValueError, SyntaxError):
            record["expectations"] = []
    return record


def extract_many(root: str, items: list[tuple[str, str]]) -> list[dict]:
    return [extract_file(root, path, module) for path, module in items]
