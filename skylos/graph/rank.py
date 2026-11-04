"""Rank the graph's code by importance and find the code relevant to files.

Importance mixes four counts over the links between production code, each
step worth half the step before: how much code leads into a function, how
often entry points reach it, how much code it reaches itself, and how many
tests reach it. Credit from tests is never larger than the production credit,
so code that only tests use cannot outrank real entry points. Test code gets
no score.

Relevance starts from the code in the given files and walks out along the
code they use and the code that uses them, fading with every step, and keeps
the most relevant items that fit a token budget.
"""

from __future__ import annotations

import collections
import math
import posixpath
import re
from pathlib import Path

DEFAULT_BUDGET = 2000
STEP_FADE = 0.5
NAME_FACTOR = 0.5
CALLER_FACTOR = 0.8
HORIZON = 3
ENTRY_HORIZON = 5
LINK_STRENGTH = {"calls": 1.0, "creates": 1.0, "inherits": 1.0, "uses": 0.5}
UPSTREAM_WEIGHT = 1.0
ENTRY_WEIGHT = 0.5
DOWNSTREAM_WEIGHT = 0.35
TEST_WEIGHT = 0.25
SIGNATURE_LIMIT = 120
SUMMARY_LIMIT = 160
CHARS_PER_TOKEN = 4
DECLARATION_LANGUAGES = frozenset({"go", "java", "rust", "php"})


def _strength(kind: str) -> float:
    return LINK_STRENGTH.get(kind, 0.5)


class _Links:
    def __init__(self, index):
        nodes = index.nodes
        self.production = {node_id for node_id, node in nodes.items() if not node["is_test"]}
        self.forward: dict[str, list[tuple[str, float]]] = collections.defaultdict(list)
        self.backward: dict[str, list[tuple[str, float]]] = collections.defaultdict(list)
        self.from_tests: dict[str, list[tuple[str, float]]] = collections.defaultdict(list)
        self.has_callers: set[str] = set()
        for table, factor in ((index.callees, 1.0), (index.name_callees, NAME_FACTOR)):
            for source, targets in table.items():
                if source not in nodes:
                    continue
                for target, kind in targets:
                    if target not in self.production or target == source:
                        continue
                    strength = _strength(kind) * factor
                    if source in self.production:
                        self.forward[source].append((target, strength))
                        self.backward[target].append((source, strength))
                        self.has_callers.add(target)
                    else:
                        self.from_tests[source].append((target, strength))


def _walks(start: dict[str, float], adjacency, steps: int, first_factor: float = 1.0) -> dict[str, float]:
    total: dict[str, float] = collections.defaultdict(float)
    current = start
    factor = first_factor
    for _ in range(steps):
        following: dict[str, float] = collections.defaultdict(float)
        for node, amount in current.items():
            for other, strength in adjacency.get(node, ()):
                following[other] += amount * strength
        for node, amount in following.items():
            total[node] += amount * factor
        current = following
        factor *= STEP_FADE
    return total


def _is_entry(node: dict, links: _Links, downstream: dict[str, float]) -> bool:
    if node["kind"] == "class" or node["id"] in links.has_callers:
        return False
    if node["name"].rsplit(".", 1)[-1].startswith("_"):
        return False
    return downstream.get(node["id"], 0.0) > 0 or bool(node.get("decorators"))


def _global(index) -> dict[str, float]:
    links = _Links(index)
    ones = {node_id: 1.0 for node_id in links.production}
    upstream = _walks(ones, links.forward, HORIZON)
    downstream = _walks(ones, links.backward, HORIZON)
    entries = {node_id: 1.0 for node_id in links.production if _is_entry(index.nodes[node_id], links, downstream)}
    entry = _walks(entries, links.forward, ENTRY_HORIZON)
    first: dict[str, float] = collections.defaultdict(float)
    for targets in links.from_tests.values():
        for target, strength in targets:
            first[target] += strength
    tested = _walks(first, links.forward, HORIZON - 1, STEP_FADE)
    raw = {}
    for node_id in links.production:
        production = (
            UPSTREAM_WEIGHT * math.log1p(upstream.get(node_id, 0.0))
            + ENTRY_WEIGHT * math.log1p(entry.get(node_id, 0.0) + entries.get(node_id, 0.0))
            + DOWNSTREAM_WEIGHT * math.log1p(downstream.get(node_id, 0.0))
        )
        tests = TEST_WEIGHT * math.log1p(first.get(node_id, 0.0) + tested.get(node_id, 0.0))
        raw[node_id] = production + min(tests, production)
    return _normalised(raw)


def _normalised(raw: dict[str, float]) -> dict[str, float]:
    top = max(raw.values(), default=0.0)
    if top <= 0:
        return {node_id: 0.0 for node_id in raw}
    return {node_id: value / top for node_id, value in raw.items()}


def importance(index, files=None) -> dict[str, float]:
    scores = _global(index)
    if not files:
        return scores
    known, _unknown = _paths(index, files)
    reached = _proximity(index, _seeds(index, known))
    personal = {node_id: closeness * (0.5 + 0.5 * scores.get(node_id, 0.0)) for node_id, (closeness, _relation) in reached.items()}
    return _normalised(personal)


def order_by_importance(index, node_ids, scores: dict[str, float] | None = None) -> list[str]:
    if scores is None:
        scores = index.importance()
    return sorted(node_ids, key=lambda node_id: (-scores.get(node_id, -1.0), node_id))


def _paths(index, files) -> tuple[list[str], list[str]]:
    known_files = {entry["file"] for entry in index.graph.get("files") or ()}
    root = Path(index.root)
    known: list[str] = []
    unknown: list[str] = []
    for raw in files or ():
        text = str(raw).strip()
        candidate = text.replace("\\", "/")
        if Path(candidate).is_absolute():
            try:
                candidate = Path(candidate).resolve().relative_to(root.resolve()).as_posix()
            except (ValueError, OSError):
                unknown.append(text)
                continue
        candidate = posixpath.normpath(candidate)
        matched = []
        if candidate in known_files:
            matched = [candidate]
        elif candidate not in (".", ""):
            prefix = candidate.rstrip("/") + "/"
            matched = sorted(path for path in known_files if path.startswith(prefix))
        if not matched:
            unknown.append(text)
            continue
        for path in matched:
            if path not in known:
                known.append(path)
    return known, unknown


def _seeds(index, files: list[str]) -> set[str]:
    wanted = set(files)
    return {node_id for node_id, node in index.nodes.items() if node["file"] in wanted}


def _neighbours(index, node_id: str, direction: str):
    if direction == "down":
        resolved = index.callees.get(node_id, ())
        named = index.name_callees.get(node_id, ())
    else:
        resolved = index.callers.get(node_id, ())
        named = index.name_callers.get(node_id, ())
    for other, kind in resolved:
        yield other, _strength(kind), False
    for other, kind in named:
        yield other, _strength(kind) * NAME_FACTOR, True


def _relation(direction: str, steps: int, by_name: bool) -> str:
    text = "used by the given files"
    if direction == "up":
        text = "uses the given files"
    if steps > 1:
        text = f"{text}, {steps} steps away"
    if by_name:
        text = f"possibly {text} (matched by name)"
    return text


def _proximity(index, seeds: set[str]) -> dict[str, tuple[float, str]]:
    best: dict[str, tuple[float, str]] = {}
    for direction, factor in (("down", 1.0), ("up", CALLER_FACTOR)):
        frontier = {seed: (1.0, False) for seed in seeds}
        seen = set(seeds)
        for step in range(1, HORIZON + 1):
            following: dict[str, tuple[float, bool]] = {}
            for node_id, (amount, by_name) in frontier.items():
                for other, strength, named in _neighbours(index, node_id, direction):
                    node = index.nodes.get(other)
                    if other in seen or node is None or node["is_test"]:
                        continue
                    value = amount * strength
                    if step > 1:
                        value *= STEP_FADE
                    if other not in following or value > following[other][0]:
                        following[other] = (value, by_name or named)
            for other, (value, by_name) in following.items():
                seen.add(other)
                closeness = value * factor
                if other not in best or closeness > best[other][0]:
                    best[other] = (closeness, _relation(direction, step, by_name))
            frontier = following
    return {node_id: found for node_id, found in best.items() if node_id not in seeds}


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _shown(node: dict) -> str:
    signature = " ".join((node.get("signature") or "").split())
    name = node["name"]
    if not signature or node["kind"] == "class":
        return name
    if node.get("language") in DECLARATION_LANGUAGES:
        return signature
    if node.get("language") == "python":
        params, arrow, returns = signature.partition("->")
        text = f"{name}({params.strip()})"
        if arrow:
            text = f"{text} -> {returns.strip()}"
        return text
    compact = re.sub(r"\s*([(),:<>\[\]{}|=.])\s*", r"\1", signature)
    return name + compact.replace(",", ", ").replace(":", ": ")


def _tokens(text: str) -> int:
    return max(1, (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def _item(index, node_id: str, score: float, relation: str) -> dict:
    node = index.nodes[node_id]
    label = index.label(node_id)
    signature = _clip(node.get("signature") or "", SIGNATURE_LIMIT)
    summary = label.get("summary") or ""
    shown = _clip(_shown(node), SIGNATURE_LIMIT)
    line_text = f"{node['file']}:{node['start']}  {shown}  ({relation})"
    if summary:
        line_text = f"{line_text}  {_clip(summary, SUMMARY_LIMIT)}"
    area = index.area_of(node_id)
    area_label = None
    if area:
        area_label = {"id": area["id"], "name": area["name"]}
    return {
        "id": node_id,
        "name": node["name"],
        "kind": node["kind"],
        "file": node["file"],
        "line": node["start"],
        "signature": signature,
        "summary": summary,
        "score": round(score, 4),
        "line_text": line_text,
        "relation": relation,
        "area": area_label,
    }


def relevant(index, files, budget: int = DEFAULT_BUDGET) -> dict:
    budget = int(budget)
    scores = index.importance()
    known: list[str] = []
    unknown: list[str] = []
    candidates: dict[str, tuple[float, str]] = {}
    if files:
        known, unknown = _paths(index, files)
        if known:
            for node_id, (closeness, relation) in _proximity(index, _seeds(index, known)).items():
                candidates[node_id] = (closeness * (0.5 + 0.5 * scores.get(node_id, 0.0)), relation)
    else:
        for node_id, score in scores.items():
            candidates[node_id] = (score, "important across the repository")
    ordered = sorted(candidates.items(), key=lambda item: (-item[1][0], item[0]))
    items = []
    used = 0
    for node_id, (score, relation) in ordered:
        item = _item(index, node_id, score, relation)
        cost = _tokens(item["line_text"])
        if items and used + cost > budget:
            break
        items.append(item)
        used += cost
    return {
        "files": known,
        "unknown_files": unknown,
        "budget_tokens": budget,
        "used_tokens": used,
        "items": items,
        "more": len(ordered) - len(items),
    }
