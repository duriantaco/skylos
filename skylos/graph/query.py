from __future__ import annotations

import collections
from pathlib import Path

from skylos.changemap.symbols import KIND_CLASS
from skylos.graph.extract import inside
from skylos.graph.store import load_changes, load_graph, load_notes

CODE_LINE_LIMIT = 400
IMPACT_DEPTH = 3
IMPACT_PREVIEW_LIMIT = 12
TEST_DEPTH = 3
CONSTRUCTORS = ("__init__", "constructor")
MAX_SOURCE_BYTES = 1_500_000
MATCH_NAME = "name"
AREA_MEMBER_LIMIT = 200
AREA_NEIGHBOUR_LIMIT = 8


class GraphIndex:
    def __init__(self, root: str | Path, graph: dict, notes: dict | None = None, changes: dict | None = None):
        self.root = Path(root)
        self.graph = graph
        self.notes = notes or {"nodes": {}, "changes": {}}
        self.changes = changes
        self.nodes: dict[str, dict] = {n["id"]: n for n in graph["nodes"]}
        self.callees: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        self.callers: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for source, target, kind in graph["edges"]:
            self.callees[source].append((target, kind))
            self.callers[target].append((source, kind))
            if kind == "creates":
                for name in CONSTRUCTORS:
                    if f"{target}.{name}" in self.nodes:
                        self.callers[f"{target}.{name}"].append((source, kind))
        self.change_by_id: dict[str, dict] = {}
        if changes:
            for entry in changes.get("symbols", ()):
                key = entry.get("node_id") or entry.get("full_name")
                if key:
                    self.change_by_id[key] = entry
        self.members: dict[str, list[str]] = collections.defaultdict(list)
        for node in self.nodes.values():
            if node["kind"] == "method":
                owner = node["id"].rsplit(".", 1)[0]
                if owner in self.nodes:
                    self.members[owner].append(node["id"])
        self.name_callees: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        self.name_callers: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for source, target, kind in graph.get("name_edges") or ():
            if source in self.nodes and target in self.nodes:
                self.name_callees[source].append((target, kind))
                self.name_callers[target].append((source, kind))
        self.area_by_id: dict[int, dict] = {}
        self.node_area: dict[str, int] = {}
        for area in graph.get("areas") or ():
            self.area_by_id[area["id"]] = area
            for member in area.get("members", ()):
                self.node_area[member] = area["id"]
        self._importance: dict[str, float] | None = None

    @classmethod
    def load(cls, root: str | Path) -> GraphIndex | None:
        graph = load_graph(root)
        if graph is None:
            return None
        return cls(root, graph, load_notes(root), load_changes(root))

    def note(self, node_id: str) -> dict | None:
        entry = self.notes.get("nodes", {}).get(node_id)
        node = self.nodes.get(node_id)
        if not entry or not node:
            return None
        result = dict(entry)
        result["stale"] = entry.get("code_hash") != node["code_hash"]
        return result

    def label(self, node_id: str) -> dict:
        node = self.nodes.get(node_id, {})
        note = self.note(node_id)
        summary = ""
        if note and not note["stale"]:
            summary = note.get("text", "")
        return {
            "id": node_id,
            "name": node.get("name", node_id),
            "kind": node.get("kind", ""),
            "file": node.get("file", ""),
            "line": node.get("start", 0),
            "is_test": node.get("is_test", False),
            "summary": summary,
        }

    def find(self, query: str, limit: int = 20, include_tests: bool = False) -> list[dict]:
        text = query.strip().lower()
        if not text:
            return []
        scored = []
        for node in self.nodes.values():
            if node["is_test"] and not include_tests:
                continue
            name = node["name"].lower()
            last = name.rsplit(".", 1)[-1]
            full = node["id"].lower()
            score = None
            if text in (name, last, full):
                score = 0
            elif last.startswith(text) or name.startswith(text):
                score = 1
            elif text in name:
                score = 2
            elif text in full or text in node["file"].lower():
                score = 3
            if score is not None:
                scored.append((score, len(name), node["file"], node["start"], node["id"]))
        scored.sort()
        return [self.label(item[-1]) for item in scored[:limit]]

    def resolve_name(self, query: str) -> str | None:
        if query in self.nodes:
            return query
        if "::" in query:
            path, _, qual = query.partition("::")
            for node in self.nodes.values():
                if node["file"] == path and node["name"] == qual:
                    return node["id"]
        found = self.find(query, limit=2, include_tests=True)
        if found and (len(found) == 1 or found[0]["name"].lower().rsplit(".", 1)[-1] == query.lower().rsplit(".", 1)[-1]):
            return found[0]["id"]
        return None

    def code(self, node_id: str) -> dict | None:
        node = self.nodes.get(node_id)
        if node is None:
            return None
        full = inside(self.root, node["file"])
        if full is None:
            return None
        try:
            if full.stat().st_size > MAX_SOURCE_BYTES:
                return None
            lines = full.read_text(encoding="utf-8", errors="replace").splitlines()  # skylos: ignore[SKY-D325] graph file path resolved inside the repository by inside(), size checked above
        except OSError:
            return None
        start = max(1, node["start"])
        end = min(len(lines), node["end"], start + CODE_LINE_LIMIT - 1)
        return {
            "start": start,
            "end": end,
            "clipped": node["end"] > end,
            "text": "\n".join(lines[start - 1:end]),
        }

    def tests_reaching(self, node_id: str) -> list[dict]:
        found: dict[str, int] = {}
        frontier = {node_id}
        seen = {node_id}
        for depth in range(1, TEST_DEPTH + 1):
            next_frontier = set()
            for current in frontier:
                for caller, _kind in self.callers.get(current, ()):
                    if caller in seen:
                        continue
                    seen.add(caller)
                    if self.nodes.get(caller, {}).get("is_test"):
                        found.setdefault(caller, depth)
                    else:
                        next_frontier.add(caller)
            frontier = next_frontier
        ordered = sorted(found.items(), key=lambda item: (item[1], item[0]))
        return [dict(self.label(test_id), steps=depth) for test_id, depth in ordered]

    def impact(self, node_id: str, depth: int = IMPACT_DEPTH) -> dict:
        levels = []
        seen = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            level = set()
            for current in frontier:
                for caller, _kind in self.callers.get(current, ()):
                    if caller not in seen and not self.nodes.get(caller, {}).get("is_test"):
                        seen.add(caller)
                        level.add(caller)
            if not level:
                break
            levels.append([self.label(item) for item in sorted(level)])
            frontier = level
        return {
            "node": self.label(node_id),
            "callers_by_distance": levels,
            "total": sum(len(level) for level in levels),
            "tests": self.tests_reaching(node_id),
            "possible_callers": self.possible_callers(node_id, depth, seen),
        }

    def possible_callers(self, node_id: str, depth: int, resolved: set[str]) -> list[dict]:
        reached = {node_id: 0}
        frontier = {node_id}
        for step in range(1, depth + 1):
            following = set()
            for current in frontier:
                for caller, _kind in list(self.callers.get(current, ())) + list(self.name_callers.get(current, ())):
                    if caller in reached or self.nodes.get(caller, {}).get("is_test"):
                        continue
                    reached[caller] = step
                    following.add(caller)
            if not following:
                break
            frontier = following
        found = sorted((steps, item) for item, steps in reached.items() if item not in resolved)
        return [dict(self.label(item), steps=steps, match=MATCH_NAME) for steps, item in found]

    def area_summary(self, area: dict) -> dict:
        return {key: value for key, value in area.items() if key != "members"}

    def areas(self) -> list[dict]:
        return [self.area_summary(area) for area in self.graph.get("areas") or ()]

    def area_of(self, node_id: str) -> dict | None:
        area_id = self.node_area.get(node_id)
        if area_id is None:
            return None
        return self.area_summary(self.area_by_id[area_id])

    def area(self, area_id: int, limit: int = AREA_MEMBER_LIMIT) -> dict | None:
        area = self.area_by_id.get(area_id)
        if area is None:
            return None
        from skylos.graph.rank import order_by_importance

        members = order_by_importance(self, list(area["members"]))
        scores = self.importance()
        neighbours: collections.Counter = collections.Counter()
        inside = set(area["members"])
        for member in area["members"]:
            links = list(self.callees.get(member, ())) + list(self.callers.get(member, ()))
            links += list(self.name_callees.get(member, ())) + list(self.name_callers.get(member, ()))
            for other, _kind in links:
                other_area = self.node_area.get(other)
                if other not in inside and other_area is not None:
                    neighbours[other_area] += 1
        linked = sorted(neighbours.items(), key=lambda item: (-item[1], item[0]))[:AREA_NEIGHBOUR_LIMIT]
        result = self.area_summary(area)
        result["members"] = [dict(self.label(m), score=round(scores.get(m, 0.0), 4)) for m in members[:limit]]
        result["members_total"] = len(members)
        result["linked_areas"] = [dict(self.area_summary(self.area_by_id[other]), links=count) for other, count in linked]
        return result

    def importance(self, files=None) -> dict[str, float]:
        from skylos.graph.rank import importance

        if files:
            return importance(self, files)
        if self._importance is None:
            self._importance = importance(self)
        return self._importance

    def ranked(self, limit: int = 15, files=None) -> list[dict]:
        from skylos.graph.rank import order_by_importance

        scores = self.importance(files)
        ordered = order_by_importance(self, sorted(scores), scores)
        return [dict(self.label(node_id), score=round(scores[node_id], 4)) for node_id in ordered[:limit]]

    def relevant(self, files=None, budget: int | None = None) -> dict:
        from skylos.graph.rank import DEFAULT_BUDGET, relevant

        if budget is None:
            budget = DEFAULT_BUDGET
        return relevant(self, files, budget)

    def card(self, node_id: str, with_code: bool = True) -> dict | None:
        node = self.nodes.get(node_id)
        if node is None:
            return None
        callers = [dict(self.label(c), edge=k) for c, k in sorted(self.callers.get(node_id, ()))]
        callees = [dict(self.label(c), edge=k) for c, k in sorted(self.callees.get(node_id, ()))]
        name_callers = [dict(self.label(c), edge=k, match=MATCH_NAME) for c, k in sorted(self.name_callers.get(node_id, ()))]
        name_callees = [dict(self.label(c), edge=k, match=MATCH_NAME) for c, k in sorted(self.name_callees.get(node_id, ()))]
        result = {
            "node": node,
            "note": self.note(node_id),
            "used_by": [c for c in callers if not c["is_test"]],
            "uses": callees,
            "used_by_name": [c for c in name_callers if not c["is_test"]],
            "uses_name": name_callees,
            "tests": self.tests_reaching(node_id),
            "expected_outputs": self.graph.get("expectations", {}).get(node_id, []),
            "members": [self.label(m) for m in sorted(self.members.get(node_id, ()))],
            "change": self.change_by_id.get(node_id),
            "change_note": self.change_note(node_id),
            "description": self.description(node_id),
            "impact_preview": self.impact_preview(node_id),
            "area": self.area_of(node_id),
        }
        if with_code:
            result["code"] = self.code(node_id)
        return result

    def change_note(self, node_id: str) -> dict | None:
        change = self.change_by_id.get(node_id)
        if not change:
            return None
        note = self.notes.get("changes", {}).get(change.get("change_key"))
        if not isinstance(note, dict):
            return None
        result = dict(note)
        impact = []
        for row in note.get("impact") or ():
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                continue
            label = self.label(row["id"])
            impact.append(dict(row, name=label["name"], file=label["file"], line=label["line"]))
        result["impact"] = impact
        return result

    def description(self, node_id: str) -> dict:
        note = self.note(node_id)
        if note is None:
            return {"now": None, "before": None}
        now = {"text": note.get("text", ""), "source": note.get("source"), "stale": note["stale"]}
        before = None
        previous = note.get("previous")
        code_changed = isinstance(previous, dict) and previous.get("code_hash") != self.nodes[node_id]["code_hash"]
        if code_changed and not note["stale"] and isinstance(previous.get("text"), str):
            before = {"text": previous["text"], "source": previous.get("source")}
        return {"now": now, "before": before}

    def impact_preview(self, node_id: str, limit: int = IMPACT_PREVIEW_LIMIT) -> list[dict]:
        reach = self.impact(node_id, IMPACT_DEPTH)
        rows = []
        for steps, level in enumerate(reach["callers_by_distance"], start=1):
            for item in level:
                rows.append(dict(item, steps=steps))
        rows.extend(reach["tests"])
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "file": row["file"],
                "line": row["line"],
                "steps": row["steps"],
                "is_test": row["is_test"],
                "description": row["summary"],
            }
            for row in rows[:limit]
        ]

    def reach_size(self, node_id: str, limit: int = 400) -> int:
        seen = {node_id}
        stack = [node_id]
        while stack and len(seen) < limit:
            current = stack.pop()
            for target, _kind in self.callees.get(current, ()):
                if target not in seen:
                    seen.add(target)
                    stack.append(target)
        return len(seen) - 1

    def entry_points(self, limit: int = 15) -> list[dict]:
        candidates = []
        for node in self.nodes.values():
            if node["is_test"] or node["kind"] == KIND_CLASS:
                continue
            last = node["name"].rsplit(".", 1)[-1]
            if last.startswith("_") and last != "__call__":
                continue
            production_callers = [c for c, _ in self.callers.get(node["id"], ()) if not self.nodes[c]["is_test"]]
            if production_callers:
                continue
            reach = self.reach_size(node["id"])
            if reach == 0 and not node.get("decorators"):
                continue
            candidates.append((-reach, node["file"], node["start"], node["id"]))
        candidates.sort()
        return [dict(self.label(item[-1]), reaches=-item[0]) for item in candidates[:limit]]

    def hubs(self, limit: int = 15) -> list[dict]:
        counted = []
        for node_id, callers in self.callers.items():
            node = self.nodes.get(node_id)
            if not node or node["is_test"]:
                continue
            production = {c for c, _ in callers if not self.nodes[c]["is_test"]}
            if production:
                counted.append((-len(production), node_id))
        counted.sort()
        return [dict(self.label(node_id), used_by=-count) for count, node_id in counted[:limit]]

    def overview(self) -> dict:
        graph = self.graph
        kinds = collections.Counter(n["kind"] for n in graph["nodes"] if not n["is_test"])
        languages = collections.Counter(f["language"] for f in graph["files"])
        described = 0
        stale = 0
        for node_id in self.nodes:
            note = self.note(node_id)
            if note:
                if note["stale"]:
                    stale += 1
                else:
                    described += 1
        return {
            "repo": graph.get("repo"),
            "commit": graph.get("commit"),
            "dirty": graph.get("dirty"),
            "built_at": graph.get("built_at"),
            "coverage": graph.get("coverage"),
            "files": len(graph["files"]),
            "functions": kinds.get("function", 0),
            "methods": kinds.get("method", 0),
            "classes": kinds.get("class", 0),
            "links": len(graph["edges"]),
            "name_links": len(graph.get("name_edges") or ()),
            "areas": len(graph.get("areas") or ()),
            "languages": dict(languages),
            "described": described,
            "stale_descriptions": stale,
            "tests_with_expected_outputs": len(graph.get("expectations", {})),
            "has_changes": bool(self.changes),
        }
