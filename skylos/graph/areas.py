"""Group the graph's functions and classes into areas.

Areas start from the folder structure. Every folder is a pool, and folders
with only a couple of functions or classes are folded into their parent. A
pool with a handful of units stays one area per connected piece; a larger pool
is split by how strongly its units (a class with its methods, or a function)
are linked, using networkx community detection with each file as weak glue
between its own units. Links are weighted by kind, and links matched
by name count half. Pools whose units and links did not change keep their
previous split, and area ids follow their members from one build to the next.
"""

from __future__ import annotations

import collections
import hashlib
import json
from pathlib import PurePosixPath

AREAS_VERSION = "folders-2"
SEED = 20261103
SMALL_FOLDER = 3
SMALL_POOL = 8
FILE_GLUE = 0.5
NAME_LINK_FACTOR = 0.5
KIND_WEIGHT = {"inherits": 2.0, "calls": 1.0, "creates": 1.0, "uses": 0.5}
ROOT = "."


def _digest(value) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def fingerprint(nodes: dict[str, dict], edges, name_edges) -> str:
    shape = sorted((node_id, node["file"], node["kind"], bool(node["is_test"])) for node_id, node in nodes.items())
    return _digest([AREAS_VERSION, shape, sorted(list(edge) for edge in edges), sorted(list(edge) for edge in name_edges)])


def previous_assignment(cached) -> dict:
    found = {"area_of": {}, "pools": {}}
    if not isinstance(cached, dict):
        return found
    for area in cached.get("areas") or ():
        if not isinstance(area, dict) or not isinstance(area.get("id"), int):
            continue
        for member in area.get("members") or ():
            if isinstance(member, str):
                found["area_of"][member] = area["id"]
    pools = cached.get("pools")
    if cached.get("version") == AREAS_VERSION and isinstance(pools, dict):
        found["pools"] = pools
    return found


def _folder(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    if parent in ("", "."):
        return ROOT
    return parent


def _parent_folder(folder: str) -> str:
    if folder == ROOT:
        return ROOT
    return _folder(folder)


def _units(nodes: dict[str, dict]) -> dict[str, str]:
    production = {node_id for node_id, node in nodes.items() if not node["is_test"]}
    unit_of = {}
    for node_id in production:
        file = nodes[node_id]["file"]
        parts = node_id.split(".")
        top = node_id
        for size in range(1, len(parts)):
            prefix = ".".join(parts[:size])
            if prefix in production and nodes[prefix]["file"] == file:
                top = prefix
                break
        unit_of[node_id] = top
    return unit_of


def _pools(unit_folder: dict[str, str]) -> dict[str, str]:
    sizes: collections.Counter = collections.Counter(unit_folder.values())
    every = set(sizes)
    for folder in list(sizes):
        current = folder
        while current != ROOT:
            current = _parent_folder(current)
            every.add(current)
    moved = {}
    for folder in sorted(every, key=lambda item: (-len(PurePosixPath(item).parts), item)):
        if folder == ROOT or sizes[folder] >= SMALL_FOLDER:
            continue
        parent = _parent_folder(folder)
        sizes[parent] += sizes[folder]
        moved[folder] = parent
    pool_of = {}
    for folder in sizes:
        target = folder
        while target in moved:
            target = moved[target]
        pool_of[folder] = target
    return pool_of


def _unit_weights(edges, name_edges, unit_of: dict[str, str]) -> dict[tuple[str, str], float]:
    weights: dict[tuple[str, str], float] = collections.defaultdict(float)
    for links, factor in ((edges, 1.0), (name_edges, NAME_LINK_FACTOR)):
        for source, target, kind in links:
            first = unit_of.get(source)
            second = unit_of.get(target)
            if first is None or second is None or first == second:
                continue
            pair = (min(first, second), max(first, second))
            weights[pair] += KIND_WEIGHT.get(kind, 0.5) * factor
    return weights


def _pieces(units: list[str], unit_file: dict[str, str], weights: dict[tuple[str, str], float]) -> list[list[str]]:
    parent = {unit: unit for unit in units}

    def find(unit: str) -> str:
        while parent[unit] != unit:
            parent[unit] = parent[parent[unit]]
            unit = parent[unit]
        return unit

    def join(first: str, second: str) -> None:
        roots = sorted((find(first), find(second)))
        parent[roots[1]] = roots[0]

    first_in_file: dict[str, str] = {}
    for unit in units:
        file = unit_file[unit]
        if file in first_in_file:
            join(first_in_file[file], unit)
        else:
            first_in_file[file] = unit
    for first, second in weights:
        join(first, second)
    groups: dict[str, list[str]] = collections.defaultdict(list)
    for unit in units:
        groups[find(unit)].append(unit)
    return sorted(sorted(group) for group in groups.values())


def _split(units: list[str], unit_file: dict[str, str], weights: dict[tuple[str, str], float]) -> list[list[str]]:
    if len(units) <= SMALL_POOL:
        return _pieces(units, unit_file, weights)
    import networkx as nx

    position = {unit: number for number, unit in enumerate(units)}
    files = sorted({unit_file[unit] for unit in units})
    anchor = {file: len(units) + number for number, file in enumerate(files)}
    graph = nx.Graph()
    graph.add_nodes_from(range(len(units) + len(files)))
    links = [(position[unit], anchor[unit_file[unit]], FILE_GLUE) for unit in units]
    for (first, second), weight in sorted(weights.items()):
        links.append((position[first], position[second], weight))
    graph.add_weighted_edges_from(links)
    groups = nx.community.louvain_communities(graph, weight="weight", resolution=1.0, seed=SEED)
    found = []
    for group in groups:
        members = sorted(units[number] for number in group if number < len(units))
        if members:
            found.append(members)
    return sorted(found)


_NAME_TIERS = ("function", "class", "method")


def _hub(members: list[str], fan_in: dict[str, float], nodes: dict[str, dict]) -> str:
    for kind in _NAME_TIERS:
        pool = [node_id for node_id in members if nodes[node_id].get("kind") == kind]
        if pool:
            return min(pool, key=lambda node_id: (-fan_in.get(node_id, 0.0), node_id.count("."), node_id))
    return min(members, key=lambda node_id: (-fan_in.get(node_id, 0.0), node_id.count("."), node_id))


def _where(members: list[str], nodes: dict[str, dict]) -> str:
    counts = collections.Counter(_folder(nodes[node_id]["file"]) for node_id in members)
    return min(counts, key=lambda folder: (-counts[folder], len(folder), folder))


_NAME_FILES = 2


def _stem(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.stem == "__init__" and pure.parent.name:
        return pure.parent.name
    return pure.stem


def _files_label(members: list[str], nodes: dict[str, dict]) -> str:
    counts = collections.Counter(_stem(nodes[node_id]["file"]) for node_id in members)
    ordered = sorted(counts, key=lambda stem: (-counts[stem], stem))
    text = ", ".join(ordered[:_NAME_FILES])
    if len(ordered) > _NAME_FILES:
        text += f" +{len(ordered) - _NAME_FILES}"
    return text


def _label(where: str) -> str:
    if where == ROOT:
        return ROOT
    return PurePosixPath(where).name


def _assign_ids(groups: list[list[str]], area_of: dict[str, int]) -> list[int]:
    overlaps = []
    for number, members in enumerate(groups):
        counts = collections.Counter(area_of[m] for m in members if m in area_of)
        for old_id, count in counts.items():
            overlaps.append((-count, old_id, members[0], number))
    overlaps.sort()
    ids: list[int | None] = [None] * len(groups)
    taken = set()
    for _count, old_id, _first, number in overlaps:
        if ids[number] is None and old_id not in taken:
            ids[number] = old_id
            taken.add(old_id)
    next_id = max(list(area_of.values()) + [-1]) + 1
    fresh = sorted((number for number in range(len(groups)) if ids[number] is None), key=lambda n: (-len(groups[n]), groups[n][0]))
    for number in fresh:
        ids[number] = next_id
        next_id += 1
    return [int(value) for value in ids]


def _link_counts(members: set[str], area_index: dict[str, int], own: int, links) -> tuple[int, int, int]:
    inside = 0
    outside = 0
    pairs = set()
    for source, target, _kind in links:
        source_in = source in members
        target_in = target in members
        if source_in and target_in:
            inside += 1
            if source != target:
                pairs.add((min(source, target), max(source, target)))
        elif source_in or target_in:
            other = target
            if target_in:
                other = source
            other_area = area_index.get(other)
            if other_area is not None and other_area != own:
                outside += 1
    return inside, outside, len(pairs)


def compute_areas(nodes: dict[str, dict], edges, name_edges, previous: dict | None = None, pools_out: dict | None = None) -> list[dict]:
    previous = previous or {}
    area_of = previous.get("area_of") or {}
    old_pools = previous.get("pools") or {}
    unit_of = _units(nodes)
    unit_members: dict[str, list[str]] = collections.defaultdict(list)
    for node_id, unit in unit_of.items():
        unit_members[unit].append(node_id)
    unit_file = {unit: nodes[unit]["file"] for unit in unit_members}
    unit_folder = {unit: _folder(file) for unit, file in unit_file.items()}
    pool_of_folder = _pools(unit_folder)
    pool_units: dict[str, list[str]] = collections.defaultdict(list)
    for unit in sorted(unit_members):
        pool_units[pool_of_folder[unit_folder[unit]]].append(unit)
    weights = _unit_weights(edges, name_edges, unit_of)
    pool_weights: dict[str, dict] = collections.defaultdict(dict)
    for (first, second), weight in weights.items():
        pool = pool_of_folder[unit_folder[first]]
        if pool == pool_of_folder[unit_folder[second]]:
            pool_weights[pool][(first, second)] = weight
    groups: list[list[str]] = []
    for pool in sorted(pool_units):
        units = pool_units[pool]
        inner = pool_weights.get(pool, {})
        signature = _digest([
            [[unit, unit_file[unit], sorted(unit_members[unit])] for unit in units],
            [[first, second, round(weight, 6)] for (first, second), weight in sorted(inner.items())],
        ])
        old = old_pools.get(pool)
        split = None
        if isinstance(old, dict) and old.get("signature") == signature and isinstance(old.get("groups"), list):
            split = old["groups"]
        if split is None:
            split = _split(units, unit_file, inner)
        if pools_out is not None:
            pools_out[pool] = {"signature": signature, "groups": split}
        for unit_group in split:
            members = sorted(member for unit in unit_group for member in unit_members[unit])
            if members:
                groups.append(members)
    groups.sort()
    ids = _assign_ids(groups, area_of)
    area_index = {member: ids[number] for number, members in enumerate(groups) for member in members}
    links = [link for link in list(edges) + list(name_edges) if link[0] in area_index or link[1] in area_index]
    fan_in: dict[str, float] = collections.defaultdict(float)
    for source, target, _kind in edges:
        if source in area_index and target in area_index and source != target:
            fan_in[target] += 1.0
    for source, target, _kind in name_edges:
        if source in area_index and target in area_index and source != target:
            fan_in[target] += NAME_LINK_FACTOR
    members_links: dict[int, list] = collections.defaultdict(list)
    for link in links:
        owners = {area_index.get(link[0]), area_index.get(link[1])}
        for owner in owners:
            if owner is not None:
                members_links[owner].append(link)
    areas = []
    for number, members in enumerate(groups):
        area_id = ids[number]
        hub = _hub(members, fan_in, nodes)
        where = _where(members, nodes)
        inside, outside, pairs = _link_counts(set(members), area_index, area_id, members_links.get(area_id, ()))
        size = len(members)
        cohesion = 0.0
        if size > 1:
            cohesion = round(pairs / (size * (size - 1) / 2), 4)
        areas.append({
            "id": area_id,
            "name": f"{_label(where)}: {_files_label(members, nodes)}",
            "hub": hub,
            "size": size,
            "files": len({nodes[m]["file"] for m in members}),
            "where": where,
            "cohesion": cohesion,
            "links_inside": inside,
            "links_out": outside,
            "members": members,
        })
    areas.sort(key=lambda area: area["id"])
    _unique_names(areas, nodes)
    return areas


def _unique_names(areas: list[dict], nodes: dict[str, dict]) -> None:
    counts = collections.Counter(area["name"] for area in areas)
    for area in areas:
        if counts[area["name"]] > 1:
            area["name"] = f"{area['name']} · {nodes[area['hub']]['name']}"
    counts = collections.Counter(area["name"] for area in areas)
    for area in areas:
        if counts[area["name"]] > 1:
            area["name"] = f"{area['where']}: {_files_label(area['members'], nodes)} · {nodes[area['hub']]['name']}"
    seen: collections.Counter = collections.Counter()
    for area in areas:
        seen[area["name"]] += 1
        if seen[area["name"]] > 1:
            area["name"] = f"{area['name']} ({seen[area['name']]})"