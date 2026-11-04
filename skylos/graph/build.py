from __future__ import annotations

import collections
import hashlib
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from datetime import datetime, timezone
from pathlib import Path

from skylos.changemap.languages import any_module_name
from skylos.changemap.symbols import KIND_CLASS
from skylos.graph.areas import AREAS_VERSION, compute_areas, fingerprint, previous_assignment
from skylos.graph.extract import extract_file, extract_many
from skylos.graph.files import list_repo_files
from skylos.graph.other_languages import link_by_name, other_language, other_module_name
from skylos.graph.store import AREAS_FILE, CACHE_FILE, GRAPH_FILE, ensure_dir, read_json, write_json

SCHEMA_VERSION = 1
ENGINE_VERSION = 7
PARALLEL_THRESHOLD = 40
CHUNK = 24
ALIAS_HOPS = 6


def _engine_key() -> str:
    from skylos import __version__

    return f"{ENGINE_VERSION}:{__version__}"


def _files_stamp(repo, stats: dict) -> str:
    digest = hashlib.sha256(f"{_engine_key()}|{AREAS_VERSION}|{repo.head}|{repo.dirty}".encode())
    for path in repo.paths:
        digest.update(f"\0{path}\0{stats.get(path)}".encode())
    return digest.hexdigest()


def _stat_key(path: Path) -> list[int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return [stat.st_size, stat.st_mtime_ns]


def _load_cache(directory: Path) -> dict:
    data = read_json(directory / CACHE_FILE)
    if not isinstance(data, dict) or data.get("engine") != _engine_key():
        return {}
    files = data.get("files")
    if not isinstance(files, dict):
        return {}
    return files


def _workers() -> int:
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def _can_spawn() -> bool:
    main = sys.modules.get("__main__")
    if main is None:
        return False
    if getattr(main, "__spec__", None) is not None:
        return True
    path = getattr(main, "__file__", None)
    return bool(path) and Path(path).is_file()


def _extract(root: Path, todo: list[tuple[str, str]], progress) -> list[dict]:
    if len(todo) < PARALLEL_THRESHOLD or not _can_spawn():
        found = []
        for path, module in todo:
            found.append(extract_file(str(root), path, module))
            if progress:
                progress(len(found), len(todo))
        return found
    chunks = [todo[i:i + CHUNK] for i in range(0, len(todo), CHUNK)]
    found = []
    try:
        with ProcessPoolExecutor(max_workers=_workers()) as pool:
            for batch in pool.map(extract_many, [str(root)] * len(chunks), chunks):
                found.extend(batch)
                if progress:
                    progress(len(found), len(todo))
        return found
    except (BrokenProcessPool, OSError):
        done = {record["path"] for record in found}
        for path, module in todo:
            if path in done:
                continue
            found.append(extract_file(str(root), path, module))
            if progress:
                progress(len(found), len(todo))
        return found


class Resolver:
    def __init__(self, records: list[dict]):
        self.nodes: dict[str, dict] = {}
        self.aliases: dict[str, str] = {}
        self.stars: dict[str, list[str]] = collections.defaultdict(list)
        self.suffixes: dict[str, set[str]] = collections.defaultdict(set)
        self.classes: dict[str, list[str]] = collections.defaultdict(list)
        self.bases: dict[str, list[str]] = {}
        for record in records:
            for symbol in record.get("symbols", ()):
                self.nodes[symbol["full_name"]] = symbol
            self.aliases.update(record.get("aliases") or {})
            for target in record.get("star_from") or ():
                self.stars[record["module"]].append(target)
        for full_name, symbol in self.nodes.items():
            parts = full_name.split(".")
            for index in range(1, len(parts) - 2):
                self.suffixes[".".join(parts[index:])].add(full_name)
            if symbol["kind"] == KIND_CLASS:
                self.classes[parts[-1]].append(full_name)
        for full_name, symbol in self.nodes.items():
            if symbol["kind"] == KIND_CLASS and symbol.get("bases"):
                found = []
                for base in symbol["bases"]:
                    target = self.base_class(full_name, base)
                    if target:
                        found.append(target)
                self.bases[full_name] = found

    def base_class(self, owner: str, base: str) -> str | None:
        module = owner.rsplit(".", 1)[0]
        for candidate in (f"{module}.{base}", base):
            resolved = self._direct(candidate, 0)
            if resolved and self.nodes[resolved]["kind"] == KIND_CLASS:
                return resolved
        options = self.classes.get(base.rsplit(".", 1)[-1], [])
        if len(options) == 1:
            return options[0]
        same_package = [o for o in options if o.rsplit(".", 2)[0] == owner.rsplit(".", 2)[0]]
        if len(same_package) == 1:
            return same_package[0]
        return None

    def _direct(self, target: str, depth: int) -> str | None:
        if target in self.nodes:
            return target
        if depth >= ALIAS_HOPS:
            return None
        canonical = self.aliases.get(target)
        if canonical and canonical != target:
            return self._direct(canonical, depth + 1)
        parts = target.split(".")
        for size in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:size])
            rest = ".".join(parts[size:])
            canonical = self.aliases.get(prefix)
            if canonical and canonical != prefix:
                found = self._direct(f"{canonical}.{rest}", depth + 1)
                if found:
                    return found
            for module in self.stars.get(prefix, ()):
                found = self._direct(f"{module}.{rest}", depth + 1)
                if found:
                    return found
        return None

    def _defines_attribute(self, cls: str, member: str) -> bool:
        return member in (self.nodes.get(cls, {}).get("attributes") or ())

    def _inherited(self, cls: str, member: str, depth: int = 0) -> str | None:
        if depth > 4 or self._defines_attribute(cls, member):
            return None
        for base in self.bases.get(cls, ()):
            candidate = f"{base}.{member}"
            if candidate in self.nodes:
                return candidate
            found = self._inherited(base, member, depth + 1)
            if found:
                return found
        return None

    def resolve(self, target: str) -> str | None:
        found = self._direct(target, 0)
        if found:
            return found
        owner, _, member = target.rpartition(".")
        if owner in self.nodes and self.nodes[owner]["kind"] == KIND_CLASS:
            found = self._inherited(owner, member)
            if found:
                return found
        options = self.suffixes.get(target)
        if options and len(options) == 1:
            return next(iter(options))
        parts = target.split(".")
        if len(parts) == 2:
            classes = self.classes.get(parts[0], [])
            if len(classes) == 1:
                candidate = f"{classes[0]}.{parts[1]}"
                if candidate in self.nodes:
                    return candidate
                return self._inherited(classes[0], parts[1])
        return None


def _node(record: dict, symbol: dict) -> dict:
    return {
        "id": symbol["full_name"],
        "kind": symbol["kind"],
        "name": symbol["qual"],
        "module": record["module"],
        "file": record["path"],
        "start": symbol["start"],
        "end": symbol["end"],
        "lines": max(1, symbol["end"] - symbol["start"] + 1),
        "language": record["language"],
        "is_test": symbol.get("is_test", record["is_test"]),
        "signature": symbol["signature"],
        "doc": symbol.get("doc", ""),
        "decorators": symbol.get("decorators", []),
        "code_hash": symbol["code_hash"],
    }


def _class_edge(owner_calls: set[str] | None, target: str, found: str) -> str:
    if owner_calls is None:
        return "creates"
    if target.rsplit(".", 1)[-1] in owner_calls or found.rsplit(".", 1)[-1] in owner_calls:
        return "creates"
    return "uses"


def _edges(records: list[dict], resolver: Resolver) -> list[list[str]]:
    edges = set()
    for record in records:
        called = record.get("called")
        for owner, targets in (record.get("calls") or {}).items():
            owner_calls = None
            if called is not None and (record["language"] == "python" or owner in called):
                owner_calls = set(called.get(owner, ()))
            for target in targets:
                found = resolver.resolve(target)
                if not found or found == owner:
                    continue
                if owner.startswith(found + "."):
                    continue
                kind = "calls"
                if resolver.nodes[found]["kind"] == KIND_CLASS:
                    kind = _class_edge(owner_calls, target, found)
                edges.add((owner, found, kind))
    for cls, bases in resolver.bases.items():
        for base in bases:
            if base != cls:
                edges.add((cls, base, "inherits"))
    return [list(edge) for edge in sorted(edges)]


def _expectations(records: list[dict], callees: dict[str, set[str]], nodes: dict[str, dict]) -> dict:
    by_simple: dict[str, list[str]] = collections.defaultdict(list)
    for node_id, node in nodes.items():
        if not node["is_test"] and node["kind"] != KIND_CLASS:
            by_simple[node["name"].rsplit(".", 1)[-1]].append(node_id)
    found: dict[str, list[dict]] = collections.defaultdict(list)
    for record in records:
        for case in record.get("expectations") or ():
            qualified = case["test"].partition("::")[2]
            test_id = f"{record['module']}.{qualified}"
            reached = callees.get(test_id, set())
            for call in case["calls"]:
                simple = call["name"].rsplit(".", 1)[-1]
                matches = [
                    n for n in reached
                    if n in nodes and not nodes[n]["is_test"] and nodes[n]["name"].rsplit(".", 1)[-1] == simple
                ]
                how = "called by the test"
                if not matches:
                    options = by_simple.get(simple, [])
                    if len(options) == 1:
                        matches = options
                        how = "matched by name"
                for match in matches[:1]:
                    entry = {
                        "test": case["test"],
                        "call": call["text"],
                        "expected": case["expected"],
                        "how": how,
                    }
                    if len(found[match]) < 25:
                        found[match].append(entry)
    return dict(found)


def _module_name(root: Path, path: str) -> str:
    if other_language(path):
        return other_module_name(path)
    return any_module_name(root, path)


def _areas(directory: Path, nodes: dict[str, dict], edges: list, name_edges: list) -> list[dict]:
    key = fingerprint(nodes, edges, name_edges)
    cached = read_json(directory / AREAS_FILE)
    if isinstance(cached, dict) and cached.get("version") == AREAS_VERSION and cached.get("key") == key:
        areas = cached.get("areas")
        if isinstance(areas, list):
            return areas
    pools: dict = {}
    areas = compute_areas(nodes, edges, name_edges, previous_assignment(cached), pools)
    write_json(directory / AREAS_FILE, {"version": AREAS_VERSION, "key": key, "areas": areas, "pools": pools})
    return areas


def build_graph(target: str | Path = ".", *, progress=None) -> dict:
    started = time.time()
    repo = list_repo_files(target)
    root = repo.root
    directory = ensure_dir(root)
    cache = _load_cache(directory)
    modules = {path: _module_name(root, path) for path in repo.paths}
    records: list[dict] = []
    todo: list[tuple[str, str]] = []
    stats: dict[str, list[int] | None] = {}
    for path in repo.paths:
        stats[path] = _stat_key(root / path)
        cached = cache.get(path)
        if cached and cached.get("stat") == stats[path] and cached.get("record", {}).get("module") == modules[path]:
            records.append(cached["record"])
        else:
            todo.append((path, modules[path]))
    reused = len(records)
    records.extend(_extract(root, todo, progress))
    records.sort(key=lambda r: r["path"])
    failed = [{"file": r["path"], "reason": r["error"]} for r in records if r.get("error")]
    good = [r for r in records if not r.get("error")]
    write_json(directory / CACHE_FILE, {
        "engine": _engine_key(),
        "files": {r["path"]: {"stat": stats.get(r["path"]), "record": r} for r in records},
    })
    computed = [r for r in good if not other_language(r["path"])]
    named = [r for r in good if other_language(r["path"])]
    resolver = Resolver(computed)
    nodes = {}
    computed_nodes = {}
    files = []
    for record in good:
        for symbol in record["symbols"]:
            node = _node(record, symbol)
            nodes[symbol["full_name"]] = node
            if not other_language(record["path"]):
                computed_nodes[symbol["full_name"]] = node
        files.append({
            "file": record["path"],
            "module": record["module"],
            "language": record["language"],
            "lines": record["lines"],
            "is_test": record["is_test"],
            "symbols": len(record["symbols"]),
        })
    edges = _edges(computed, resolver)
    callees: dict[str, set[str]] = collections.defaultdict(set)
    for source, target_id, _kind in edges:
        callees[source].add(target_id)
    name_edges, name_stats = link_by_name(named, root)
    expectations = _expectations(computed, callees, computed_nodes)
    areas = _areas(directory, nodes, edges, name_edges)
    graph = {
        "schema_version": SCHEMA_VERSION,
        "engine": _engine_key(),
        "files_stamp": _files_stamp(repo, stats),
        "repo": root.name,
        "commit": repo.head,
        "dirty": repo.dirty,
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "coverage": {
            "files": len(repo.paths),
            "parsed": len(good),
            "reused": reused,
            "failed": failed,
            "not_mapped": repo.not_mapped,
            "name_links": name_stats,
        },
        "seconds": round(time.time() - started, 2),
        "files": files,
        "nodes": sorted(nodes.values(), key=lambda n: (n["file"], n["start"], n["id"])),
        "edges": edges,
        "name_edges": name_edges,
        "expectations": expectations,
        "areas": areas,
    }
    write_json(directory / GRAPH_FILE, graph)
    graph["root"] = str(root)
    return graph


def fresh_index(target: str | Path = "."):
    from skylos.graph.query import GraphIndex
    from skylos.graph.store import load_changes, load_graph, load_notes

    repo = list_repo_files(target)
    root = repo.root
    graph = load_graph(root)
    stats = {path: _stat_key(root / path) for path in repo.paths}
    if graph is None or graph.get("files_stamp") != _files_stamp(repo, stats):
        graph = build_graph(target)
    return GraphIndex(root, graph, load_notes(root), load_changes(root))
