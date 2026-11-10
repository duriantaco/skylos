"""Source-bound cleanup impact using the existing graph parser and queries."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from skylos.changemap.languages import any_module_name
from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.graph.build import Resolver, _edges, _node
from skylos.graph.extract import MAX_FILE_BYTES, extract_source
from skylos.graph.query import GraphIndex

SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


def build_cleanup_impact(
    tasks,
    root: Path,
    *,
    exclude_folders=(),
    max_files=250,
    max_bytes=32_000_000,
    max_symbols=20_000,
):
    """Resolve relationships in a bounded snapshot; never execute target code."""
    root = Path(root).resolve(strict=True)
    if min(max_files, max_bytes, max_symbols) < 1:
        raise ValueError("cleanup graph budgets must be positive")
    selected = {task["file"] for task in tasks}
    paths = discover_source_files(root, SUFFIXES, exclude_folders=exclude_folders)
    paths.sort(
        key=lambda path: (
            path.relative_to(root).as_posix() not in selected,
            path.as_posix(),
        )
    )
    records, digests, limitations = [], {}, []
    if any(Path(file).suffix not in SUFFIXES for file in selected):
        limitations.append(
            "Some tasks are outside the graph's supported language scope"
        )
    used, symbol_count = 0, 0
    for path in paths[:max_files]:
        relative = path.relative_to(root).as_posix()
        source = read_project_text_no_symlink(
            root, relative, max_bytes=MAX_FILE_BYTES, newline=""
        )
        if source is None:
            limitations.append(f"Graph source unavailable: {relative}")
            continue
        size = len(source.encode("utf-8"))
        if used + size > max_bytes:
            limitations.append("Graph source byte budget reached")
            break
        used += size
        try:
            record = extract_source(
                str(root), relative, any_module_name(root, relative), source
            )
        except (ValueError, SyntaxError, RecursionError, MemoryError):
            record = {"error": "could not parse"}
        if record.get("error"):
            limitations.append(f"Graph parse unavailable: {relative}")
            continue
        symbol_count += len(record["symbols"])
        if symbol_count > max_symbols:
            limitations.append("Graph symbol budget reached")
            break
        records.append(record)
        digests[relative] = sha256(source.encode("utf-8")).hexdigest()
    if len(paths) > max_files:
        limitations.append("Graph file budget reached; unseen callers may exist")
    nodes = [
        _node(record, symbol) for record in records for symbol in record["symbols"]
    ]
    graph = {
        "nodes": nodes,
        "edges": _edges(records, Resolver(records)),
        "name_edges": [],
    }
    index = GraphIndex(root, graph)
    results = []
    for task in tasks:
        line = int(task.get("line") or 1)
        matches = [
            node
            for node in nodes
            if node["file"] == task["file"] and node["start"] <= line <= node["end"]
        ]
        matches.sort(key=lambda node: (node["end"] - node["start"], node["id"]))
        item = {
            "task_id": task["id"],
            "file": task["file"],
            "resolution": "not_found",
            "callers": [],
            "possible_callers": [],
            "suggested_tests": [],
        }
        if task["file"] not in digests:
            item["resolution"] = "source_unavailable"
            limitations.append(
                f"Task source unavailable or outside the bounded graph: {task['file']}"
            )
        elif (
            task.get("source_sha256")
            and digests.get(task["file"]) != task["source_sha256"]
        ):
            item["resolution"] = "stale_source"
            limitations.append(f"Task source differs from its scan: {task['file']}")
        elif matches:
            smallest = matches[0]["end"] - matches[0]["start"]
            exact = [
                node for node in matches if node["end"] - node["start"] == smallest
            ]
            if len(exact) != 1:
                item["resolution"] = "ambiguous"
            else:
                node = exact[0]
                impact = index.impact(node["id"])
                item.update(
                    resolution="static_symbol",
                    symbol=index.label(node["id"]),
                    callers=[
                        {**caller, "distance": distance}
                        for distance, level in enumerate(
                            impact["callers_by_distance"], 1
                        )
                        for caller in level
                    ][:50],
                    possible_callers=impact["possible_callers"][:50],
                    suggested_tests=impact["tests"][:50],
                )
        results.append(item)
    # Catch an editor changing a source after extraction. Relationships from a
    # moving snapshot cannot support a current-source assertion.
    for relative, digest in digests.items():
        current = read_project_text_no_symlink(
            root, relative, max_bytes=MAX_FILE_BYTES, newline=""
        )
        if current is None or sha256(current.encode("utf-8")).hexdigest() != digest:
            limitations.append("Graph source changed during analysis")
            for item in results:
                item.update(
                    resolution="stale_source",
                    callers=[],
                    possible_callers=[],
                    suggested_tests=[],
                )
            break
    return {
        "version": 1,
        "status": "partial" if limitations else "complete",
        "parsed_files": len(records),
        "discovered_files": len(paths),
        "source_hashes": digests,
        "tasks": results,
        "limitations": sorted(set(limitations)),
        "assumptions": [
            "Source-resolved graph relationships are static observations, not runtime reachability or complete external callers.",
            "Suggested tests are graph-linked candidates; test execution and behavior coverage require separate evidence.",
        ],
    }
