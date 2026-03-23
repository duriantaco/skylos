from __future__ import annotations

from collections import defaultdict
from pathlib import Path

## called via cli, but imported by city.py for topology generation NOT UNUSED
def _compute_loc(node) -> int:
    if node is None:
        return 1
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is not None and end is not None:
        return max(1, end - start + 1)
    return 1


def _squarify(items: list[dict], x: float, y: float, w: float, h: float) -> list[dict]:
    if not items:
        return []

    total = sum(it["area"] for it in items)
    if total == 0:
        for it in items:
            it.update({"x": x, "y": y, "w": 0, "h": 0})
        return items

    for it in items:
        it["_norm"] = (it["area"] / total) * w * h

    items = sorted(items, key=lambda it: it["_norm"], reverse=True)

    _layout_strip(items, x, y, w, h)

    for it in items:
        it.pop("_norm", None)

    return items


def _layout_strip(items: list[dict], x: float, y: float, w: float, h: float):
    if not items:
        return

    if len(items) == 1:
        items[0].update({"x": round(x, 2), "y": round(y, 2),
                         "w": round(w, 2), "h": round(h, 2)})
        return

    total = sum(it["_norm"] for it in items)
    if total == 0:
        for it in items:
            it.update({"x": round(x, 2), "y": round(y, 2), "w": 0, "h": 0})
        return

    horizontal = w >= h

    row = [items[0]]
    row_area = items[0]["_norm"]
    best_ratio = _worst_ratio(row, row_area, w if horizontal else h)

    i = 1
    while i < len(items):
        trial_row = row + [items[i]]
        trial_area = row_area + items[i]["_norm"]
        trial_ratio = _worst_ratio(trial_row, trial_area, w if horizontal else h)

        if trial_ratio <= best_ratio:
            row = trial_row
            row_area = trial_area
            best_ratio = trial_ratio
            i += 1
        else:
            break

    if horizontal:
        row_w = row_area / h if h > 0 else 0
        offset = 0.0
        for it in row:
            it_h = (it["_norm"] / row_w) if row_w > 0 else 0
            it.update({"x": round(x, 2), "y": round(y + offset, 2),
                       "w": round(row_w, 2), "h": round(it_h, 2)})
            offset += it_h
        remaining_x = x + row_w
        remaining_w = w - row_w
        _layout_strip(items[i:], remaining_x, y, remaining_w, h)
    else:
        row_h = row_area / w if w > 0 else 0
        offset = 0.0
        for it in row:
            it_w = (it["_norm"] / row_h) if row_h > 0 else 0
            it.update({"x": round(x + offset, 2), "y": round(y, 2),
                       "w": round(it_w, 2), "h": round(row_h, 2)})
            offset += it_w
        remaining_y = y + row_h
        remaining_h = h - row_h
        _layout_strip(items[i:], x, remaining_y, w, remaining_h)


def _worst_ratio(row: list[dict], total_area: float, side: float) -> float:
    if not row or total_area == 0 or side == 0:
        return float("inf")

    s2 = (total_area) ** 2
    w2 = side ** 2

    worst = 0.0
    for it in row:
        a = it["_norm"]
        if a == 0:
            continue
        r1 = (w2 * a) / s2
        r2 = s2 / (w2 * a)
        worst = max(worst, max(r1, r2))
    return worst


def _complexity_color(complexity: int) -> str:
    if complexity <= 3:
        return "#4caf50"
    elif complexity <= 7:
        return "#ffeb3b"
    elif complexity <= 12:
        return "#ff9800"
    else:
        return "#f44336"


def _grade_from_avg_complexity(avg: float) -> str:
    if avg <= 3:
        return "A"
    elif avg <= 5:
        return "B"
    elif avg <= 8:
        return "C"
    elif avg <= 12:
        return "D"
    else:
        return "F"


def generate_topology(analysis_result: dict, canvas_size: float = 100.0) -> dict:
    definitions = analysis_result.get("definitions", {})

    dead_names = set()
    for key in ("unused_functions", "unused_imports", "unused_classes",
                "unused_variables", "unused_parameters"):
        for item in analysis_result.get(key, []):
            dead_names.add(item.get("name", ""))

    dir_files: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))

    for qname, defn in definitions.items():
        filepath = defn.get("file", "")
        if not filepath:
            continue

        p = Path(filepath)
        directory = str(p.parent) if str(p.parent) != "." else "(root)"
        filename = p.name

        building = {
            "name": defn.get("name", qname),
            "qualified_name": qname,
            "type": defn.get("type", "function"),
            "file": filepath,
            "line": defn.get("line", 0),
            "loc": defn.get("loc", 1),
            "complexity": defn.get("complexity", 1),
            "dead": qname in dead_names or defn.get("name", "") in dead_names,
            "calls": defn.get("calls", []),
            "called_by": defn.get("called_by", []),
            "color": _complexity_color(defn.get("complexity", 1)),
        }

        dir_files[directory][filename].append(building)

    districts = []
    all_edges = []
    total_complexity = 0
    total_buildings = 0

    district_items = []
    for directory, files_map in sorted(dir_files.items()):
        total_loc = sum(b["loc"] for bs in files_map.values() for b in bs)
        district_items.append({
            "directory": directory,
            "files_map": files_map,
            "area": max(total_loc, 1),
        })

    _squarify(district_items, 0, 0, canvas_size, canvas_size)

    for d_item in district_items:
        directory = d_item["directory"]
        files_map = d_item["files_map"]
        dx, dy = d_item.get("x", 0), d_item.get("y", 0)
        dw, dh = d_item.get("w", 0), d_item.get("h", 0)

        block_items = []
        for filename, buildings in sorted(files_map.items()):
            block_loc = sum(b["loc"] for b in buildings)
            block_items.append({
                "filename": filename,
                "buildings": buildings,
                "area": max(block_loc, 1),
            })

        pad = 0.5
        _squarify(block_items, dx + pad, dy + pad,
                  max(dw - 2 * pad, 0), max(dh - 2 * pad, 0))

        blocks = []
        for b_item in block_items:
            filename = b_item["filename"]
            buildings = b_item["buildings"]
            bx, by = b_item.get("x", 0), b_item.get("y", 0)
            bw, bh = b_item.get("w", 0), b_item.get("h", 0)

            building_items = []
            for bld in buildings:
                building_items.append({
                    **bld,
                    "area": max(bld["loc"], 1),
                })

            bpad = 0.3
            _squarify(building_items, bx + bpad, by + bpad,
                      max(bw - 2 * bpad, 0), max(bh - 2 * bpad, 0))

            final_buildings = []
            for bi in building_items:
                total_complexity += bi["complexity"]
                total_buildings += 1

                for target in bi.get("calls", []):
                    all_edges.append({
                        "from": bi["qualified_name"],
                        "to": target,
                    })

                final_buildings.append({
                    "name": bi["name"],
                    "qualified_name": bi["qualified_name"],
                    "type": bi["type"],
                    "file": bi["file"],
                    "line": bi["line"],
                    "loc": bi["loc"],
                    "height": bi["loc"],
                    "complexity": bi["complexity"],
                    "color": bi["color"],
                    "dead": bi["dead"],
                    "calls": bi.get("calls", []),
                    "called_by": bi.get("called_by", []),
                    "x": bi.get("x", 0),
                    "y": bi.get("y", 0),
                    "w": bi.get("w", 0),
                    "h": bi.get("h", 0),
                })

            blocks.append({
                "name": filename,
                "path": str(Path(directory) / filename) if directory != "(root)" else filename,
                "buildings": final_buildings,
                "x": bx,
                "y": by,
                "w": bw,
                "h": bh,
            })

        districts.append({
            "name": directory,
            "blocks": blocks,
            "x": dx,
            "y": dy,
            "w": dw,
            "h": dh,
        })

    circular_deps = analysis_result.get("circular_dependencies", [])

    avg_complexity = total_complexity / total_buildings if total_buildings > 0 else 0
    grade = _grade_from_avg_complexity(avg_complexity)

    dead_count = sum(
        1 for d in districts
        for b in d["blocks"]
        for bld in b["buildings"]
        if bld["dead"]
    )

    return {
        "districts": districts,
        "edges": all_edges,
        "circular_deps": circular_deps,
        "grade": grade,
        "summary": {
            "total_districts": len(districts),
            "total_blocks": sum(len(d["blocks"]) for d in districts),
            "total_buildings": total_buildings,
            "dead_buildings": dead_count,
            "avg_complexity": round(avg_complexity, 2),
            "total_edges": len(all_edges),
            "canvas_size": canvas_size,
        },
    }


def format_rich_summary(topology: dict) -> str:
    s = topology["summary"]
    grade = topology["grade"]
    lines = [
        f"Code City Grade: {grade}",
        f"  Districts: {s['total_districts']}  |  Files: {s['total_blocks']}  |  "
        f"Functions/Classes: {s['total_buildings']}",
        f"  Dead: {s['dead_buildings']}  |  Avg Complexity: {s['avg_complexity']}  |  "
        f"Edges: {s['total_edges']}",
    ]

    if topology.get("circular_deps"):
        lines.append(f"  Circular Dependencies: {len(topology['circular_deps'])}")

    complex_buildings = []
    for d in topology["districts"]:
        for b in d["blocks"]:
            for bld in b["buildings"]:
                complex_buildings.append(bld)

    complex_buildings.sort(key=lambda b: b["complexity"], reverse=True)

    if complex_buildings:
        lines.append("")
        lines.append("Hotspots (highest complexity):")
        for bld in complex_buildings[:10]:
            dead_tag = " [DEAD]" if bld["dead"] else ""
            lines.append(
                f"  {bld['qualified_name']} — complexity={bld['complexity']} "
                f"loc={bld['loc']}{dead_tag}"
            )

    dead_buildings = [b for b in complex_buildings if b["dead"]]
    if dead_buildings:
        lines.append("")
        lines.append(f"Abandoned Buildings ({len(dead_buildings)}):")
        for bld in dead_buildings[:10]:
            lines.append(f"  {bld['qualified_name']} ({bld['file']}:{bld['line']})")
        if len(dead_buildings) > 10:
            lines.append(f"  ... and {len(dead_buildings) - 10} more")

    return "\n".join(lines)
