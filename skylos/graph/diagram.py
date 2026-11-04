"""Diagram data for the viewer's Graph tab.

The codebase level draws every area as a box, linked when their members call,
create, inherit or use each other; the weight is the number of proven links.
Links matched by name only are counted apart and never added to the weight.
The area level draws the area's classes (with one row per method) and
functions UML-style, plus the members of other areas it links to.

Changed code carries its review bucket from changes.json. With impact on,
everything that calls changed code within three steps is marked, and the links
along those paths are marked too. Code whose logic is proven the same (the
skip bucket) is not a starting point, because nothing can behave differently.
"""

from __future__ import annotations

import collections

from skylos.changemap.symbols import KIND_CLASS
from skylos.graph.query import CONSTRUCTORS

AREA_CAP = 60
OTHER_ID = "area:other"
EXTERNAL_CAP = 12
MEMBER_LIMIT = 80
MEMBER_LIMIT_MAX = 400
CLASS_ROW_CAP = 24
IMPACT_STEPS = 3
BUCKET_RANK = {"read_first": 0, "read": 1, "skim": 2, "skip": 3}
IMPACT_BUCKETS = ("read_first", "read", "skim")
NAME = "name"


def _area_key(area_id: int) -> str:
    return f"area:{area_id}"


def reviews(index) -> dict[str, dict]:
    found = {}
    for node_id, entry in index.change_by_id.items():
        node = index.nodes.get(node_id)
        if node is None or node["is_test"] or entry.get("is_test"):
            continue
        found[node_id] = {"review": entry.get("review") or "read", "verdict": entry.get("verdict")}
    return found


def worst(buckets) -> str | None:
    found = None
    for bucket in buckets:
        if bucket is None:
            continue
        if found is None or BUCKET_RANK.get(bucket, 1) < BUCKET_RANK.get(found, 1):
            found = bucket
    return found


def impact_steps(index, changed: dict[str, dict]) -> dict[str, int]:
    steps = {}
    frontier = set()
    for node_id, info in changed.items():
        if info["review"] in IMPACT_BUCKETS:
            steps[node_id] = 0
            frontier.add(node_id)
    for step in range(1, IMPACT_STEPS + 1):
        following = set()
        for current in frontier:
            for caller, _kind in index.callers.get(current, ()):
                node = index.nodes.get(caller)
                if caller in steps or node is None or node["is_test"]:
                    continue
                steps[caller] = step
                following.add(caller)
        if not following:
            break
        frontier = following
    return steps


def _target_step(index, target: str, kind: str, steps: dict[str, int]) -> int | None:
    found = steps.get(target)
    if kind != "creates":
        return found
    for name in CONSTRUCTORS:
        step = steps.get(f"{target}.{name}")
        if step is not None and (found is None or step < found):
            found = step
    return found


def _on_impact_path(index, source: str, target: str, kind: str, steps: dict[str, int]) -> bool:
    source_step = steps.get(source)
    if source_step is None:
        return False
    target_step = _target_step(index, target, kind, steps)
    return target_step is not None and target_step < IMPACT_STEPS


def _summary(index, node_id: str | None) -> str:
    if not node_id or node_id not in index.nodes:
        return ""
    return index.label(node_id)["summary"]


def _proven_links(index):
    for source, targets in index.callees.items():
        for target, kind in targets:
            yield source, target, kind


def _name_links(index):
    for source, targets in index.name_callees.items():
        for target, kind in targets:
            yield source, target, kind


def codebase_diagram(index, impact: bool = False) -> dict:
    changed = reviews(index)
    steps = {}
    if impact:
        steps = impact_steps(index, changed)
    buckets_by_area: dict[int, list[str]] = collections.defaultdict(list)
    for node_id, info in changed.items():
        area_id = index.node_area.get(node_id)
        if area_id is not None:
            buckets_by_area[area_id].append(info["review"])
    affected_by_area: collections.Counter = collections.Counter()
    for node_id, step in steps.items():
        area_id = index.node_area.get(node_id)
        if step > 0 and area_id is not None:
            affected_by_area[area_id] += 1
    areas = list(index.graph.get("areas") or ())
    ordered = sorted(areas, key=lambda area: (not buckets_by_area.get(area["id"]), -area["size"], -area.get("links_out", 0), area["id"]))
    kept = ordered
    folded = []
    if len(ordered) > AREA_CAP:
        kept = ordered[:AREA_CAP - 1]
        folded = ordered[AREA_CAP - 1:]
    key_of = {}
    nodes = []
    for area in kept:
        key_of[area["id"]] = _area_key(area["id"])
        node = {
            "id": _area_key(area["id"]),
            "kind": "area",
            "area": area["id"],
            "name": area["name"],
            "where": area["where"],
            "size": area["size"],
            "files": area.get("files", 0),
            "hub": area.get("hub"),
            "summary": _summary(index, area.get("hub")),
            "review": worst(buckets_by_area.get(area["id"], ())),
            "changed": len(buckets_by_area.get(area["id"], ())),
        }
        if impact:
            node["affected"] = affected_by_area.get(area["id"], 0)
            node["impacted"] = node["affected"] > 0
        nodes.append(node)
    if folded:
        folded_buckets = []
        for area in folded:
            key_of[area["id"]] = OTHER_ID
            folded_buckets.extend(buckets_by_area.get(area["id"], ()))
        other = {
            "id": OTHER_ID,
            "kind": "other",
            "name": f"{len(folded)} smaller areas",
            "where": "",
            "size": sum(area["size"] for area in folded),
            "areas": len(folded),
            "summary": "Smaller areas folded together; their links are not drawn. The Areas tab lists every one.",
            "review": worst(folded_buckets),
            "changed": len(folded_buckets),
        }
        if impact:
            other["affected"] = sum(affected_by_area.get(area["id"], 0) for area in folded)
            other["impacted"] = other["affected"] > 0
        nodes.append(other)
    weights: collections.Counter = collections.Counter()
    name_weights: collections.Counter = collections.Counter()
    hot = set()
    for source, target, kind in _proven_links(index):
        pair = _area_pair(index, key_of, source, target)
        if pair is None:
            continue
        weights[pair] += 1
        if impact and _on_impact_path(index, source, target, kind, steps):
            hot.add(pair)
    for source, target, _kind in _name_links(index):
        pair = _area_pair(index, key_of, source, target)
        if pair is not None:
            name_weights[pair] += 1
    edges = []
    for pair in set(weights) | set(name_weights):
        edge = {"source": pair[0], "target": pair[1], "weight": weights.get(pair, 0), "name_links": name_weights.get(pair, 0)}
        if impact:
            edge["impact"] = pair in hot
        edges.append(edge)
    edges.sort(key=lambda edge: (-edge["weight"], -edge["name_links"], edge["source"], edge["target"]))
    return {
        "level": "codebase",
        "nodes": nodes,
        "edges": edges,
        "areas_total": len(areas),
        "folded": len(folded),
        "changes": bool(index.changes),
        "impact": impact,
    }


def _area_pair(index, key_of: dict, source: str, target: str):
    first = index.node_area.get(source)
    second = index.node_area.get(target)
    if first is None or second is None:
        return None
    first_key = key_of.get(first)
    second_key = key_of.get(second)
    if first_key is None or second_key is None or first_key == second_key:
        return None
    return first_key, second_key


def _box_of(index, member: str, inside: set[str]) -> str:
    node = index.nodes[member]
    owner = member.rsplit(".", 1)[0]
    if node["kind"] == "method" and owner in inside and index.nodes.get(owner, {}).get("kind") == KIND_CLASS:
        return owner
    return member


def _symbol(index, node_id: str, changed: dict, steps: dict, impact: bool) -> dict:
    node = index.nodes[node_id]
    info = changed.get(node_id) or {}
    result = {
        "id": node_id,
        "kind": node["kind"],
        "name": node["name"],
        "file": node["file"],
        "line": node["start"],
        "summary": _summary(index, node_id),
        "review": info.get("review"),
        "verdict": info.get("verdict"),
    }
    if impact:
        result["impacted"] = steps.get(node_id, 0) > 0
    return result


def _boxes(index, area: dict, inside: set[str]) -> tuple[list[str], dict[str, list[str]], int]:
    from skylos.graph.rank import order_by_importance

    members = order_by_importance(index, list(area["members"]))
    rows_of: dict[str, list[str]] = collections.defaultdict(list)
    order = []
    seen = set()
    for member in members:
        box = _box_of(index, member, inside)
        if box != member:
            rows_of[box].append(member)
        if box not in seen:
            seen.add(box)
            order.append(box)
    return order, rows_of, len(members)


def _is_real_caller(index, source: str, target: str, kind: str) -> bool:
    if kind != "creates":
        return True
    return any(other == target for other, _kind in index.callees.get(source, ()))


def area_diagram(index, area_id: int, impact: bool = False, limit: int = MEMBER_LIMIT) -> dict | None:
    area = index.area_by_id.get(area_id)
    if area is None:
        return None
    limit = max(1, min(int(limit), MEMBER_LIMIT_MAX))
    changed = reviews(index)
    steps = {}
    if impact:
        steps = impact_steps(index, changed)
    inside = set(area["members"])
    order, rows_of, total = _boxes(index, area, inside)
    row_cap = max(CLASS_ROW_CAP, limit // 3)
    hidden_rows = False
    endpoint = {}
    nodes = []
    used = 0
    shown = 0
    drawn = 0
    for box in order:
        if used >= limit:
            break
        rows = sorted(rows_of.get(box, ()), key=lambda item: (index.nodes[item]["start"], item))
        node = _symbol(index, box, changed, steps, impact)
        endpoint[box] = box
        shown += 1
        if index.nodes[box]["kind"] == KIND_CLASS:
            node["members"] = []
            for row in rows[:row_cap]:
                item = _symbol(index, row, changed, steps, impact)
                node["members"].append({key: value for key, value in item.items() if key not in ("kind", "file")})
                endpoint[row] = row
                shown += 1
            node["members_total"] = len(rows)
            for row in rows[row_cap:]:
                endpoint[row] = box
                hidden_rows = True
        nodes.append(node)
        drawn += 1
        used += 1 + len(rows[:row_cap])
    links = _Links(index, endpoint, inside, steps, impact)
    for member in list(endpoint):
        for target, kind in index.callees.get(member, ()):
            links.add(member, target, kind, False)
        for source, kind in index.callers.get(member, ()):
            if source not in inside and _is_real_caller(index, source, member, kind):
                links.add(source, member, kind, False)
        for target, kind in index.name_callees.get(member, ()):
            links.add(member, target, kind, True)
        for source, kind in index.name_callers.get(member, ()):
            if source not in inside:
                links.add(source, member, kind, True)
    externals = sorted(set(links.proven_out) | set(links.named_out), key=lambda item: (-links.proven_out[item], -links.named_out[item], item))
    externals = externals[:EXTERNAL_CAP]
    for item in externals:
        node = _symbol(index, item, changed, steps, impact)
        other_area = index.node_area[item]
        node["external"] = True
        node["area"] = other_area
        node["area_name"] = index.area_by_id[other_area]["name"]
        node["links"] = links.proven_out[item]
        node["name_links"] = links.named_out[item]
        nodes.append(node)
    chosen = set(externals)
    for source, target, kind, named, hot in links.outside:
        if source in chosen or target in chosen:
            links.keep(source, target, kind, named, hot)
    summary = index.area_summary(area)
    summary["summary"] = _summary(index, area.get("hub"))
    summary["review"] = worst(changed[m]["review"] for m in area["members"] if m in changed)
    summary["changed"] = sum(1 for m in area["members"] if m in changed)
    return {
        "level": "area",
        "area": summary,
        "nodes": nodes,
        "edges": links.edges(impact),
        "shown": shown,
        "total": total,
        "limit": limit,
        "more": limit < MEMBER_LIMIT_MAX and (drawn < len(order) or hidden_rows),
        "changes": bool(index.changes),
        "impact": impact,
    }


class _Links:
    def __init__(self, index, endpoint: dict, inside: set[str], steps: dict, impact: bool):
        self.index = index
        self.endpoint = endpoint
        self.inside = inside
        self.steps = steps
        self.impact = impact
        self.found: dict[tuple[str, str, str], bool] = {}
        self.proven_pairs: set[tuple[str, str]] = set()
        self.proven_out: collections.Counter = collections.Counter()
        self.named_out: collections.Counter = collections.Counter()
        self.outside: list[tuple[str, str, str, bool, bool]] = []

    def add(self, source: str, target: str, kind: str, named: bool) -> None:
        hot = False
        if self.impact and not named:
            hot = _on_impact_path(self.index, source, target, kind, self.steps)
        source_inside = source in self.inside
        target_inside = target in self.inside
        if source_inside and target_inside:
            first = self.endpoint.get(source)
            second = self.endpoint.get(target)
            if first is None or second is None:
                return
            if _box_of(self.index, first, self.inside) == _box_of(self.index, second, self.inside):
                return
            self.keep(first, second, kind, named, hot)
            return
        other = target
        if target_inside:
            other = source
        if not _external_candidate(self.index, other):
            return
        if source_inside:
            first = self.endpoint.get(source)
            if first is None:
                return
            self.outside.append((first, target, kind, named, hot))
        else:
            second = self.endpoint.get(target)
            if second is None:
                return
            self.outside.append((source, second, kind, named, hot))
        if named:
            self.named_out[other] += 1
        else:
            self.proven_out[other] += 1

    def keep(self, source: str, target: str, kind: str, named: bool, hot: bool) -> None:
        key = (source, target, kind)
        if named:
            key = (source, target, NAME)
        else:
            self.proven_pairs.add((source, target))
        self.found[key] = self.found.get(key, False) or hot

    def edges(self, impact: bool) -> list[dict]:
        result = []
        for (source, target, kind), hot in self.found.items():
            if kind == NAME and (source, target) in self.proven_pairs:
                continue
            edge = {"source": source, "target": target, "kind": kind}
            if impact:
                edge["impact"] = hot
            result.append(edge)
        result.sort(key=lambda edge: (edge["source"], edge["target"], edge["kind"]))
        return result


def _external_candidate(index, node_id: str) -> bool:
    node = index.nodes.get(node_id)
    return node is not None and not node["is_test"] and index.node_area.get(node_id) is not None
