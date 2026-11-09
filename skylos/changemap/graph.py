from __future__ import annotations

import collections
import re

from skylos.changemap.inputs import ChangeInputs
from skylos.changemap.risk import is_test_file
from skylos.changemap.languages import parse_any, same_language
from skylos.changemap.symbols import KIND_FUNCTION, KIND_METHOD, ParsedFile, Symbol, owner_of
from skylos.changemap.ts_imports import Resolver, is_ts_path

CALLER_DEPTH = 3
FRONTIER_CAP = 40
REACH_PARSE_BUDGET = 120
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class HeadGraph:
    def __init__(self, inputs: ChangeInputs, modules: dict[str, str], resolver: Resolver | None = None):
        self.inputs = inputs
        self.resolver = resolver or Resolver(inputs.root)
        self.alias_index: dict[str, set[str]] = collections.defaultdict(set)
        self.star_index: dict[str, set[str]] = collections.defaultdict(set)
        self.modules = modules
        self.by_module = {module: path for path, module in modules.items()}
        self.parsed: dict[str, ParsedFile] = {}
        self.texts: dict[str, str] = {}
        self.token_cache: dict[str, set[str]] = {}
        self.calls: dict[str, set[str]] = {}
        self.reverse: dict[str, set[str]] = collections.defaultdict(set)
        self.owner: dict[str, tuple[str, str]] = {}
        self.owner_files: dict[str, str] = {}
        self.reach_parses = 0
        self.reach_capped = False

    def add(self, path: str, parsed: ParsedFile) -> None:
        if path in self.parsed:
            return
        self.parsed[path] = parsed
        for alias, canonical in parsed.aliases.items():
            self.alias_index[canonical].add(alias)
        for target in parsed.star_from:
            self.star_index[target].add(parsed.module)
        full_names = {symbol.full_name for symbol in parsed.symbols.values()}
        for full_name in full_names:
            self.owner_files[full_name] = path
        for name, targets in parsed.graph.items():
            self.calls[name] = targets
            for target in targets:
                self.reverse[target].add(name)
            owner = owner_of(name, full_names)
            if owner is not None:
                self.owner[name] = (path, owner)

    def text(self, path: str) -> str:
        if path not in self.texts:
            change = self.inputs.files.get(path)
            if change is not None:
                self.texts[path] = change.head_source or ""
            else:
                try:
                    self.texts[path] = (self.inputs.root / path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    self.texts[path] = ""
        return self.texts[path]

    def tokens(self, path: str) -> set[str]:
        if path not in self.token_cache:
            self.token_cache[path] = set(_IDENTIFIER.findall(self.text(path)))
        return self.token_cache[path]

    def ensure(self, path: str) -> None:
        if path in self.parsed or path not in self.modules:
            return
        parsed = parse_any(self.modules[path], path, self.text(path), self.resolver)
        if parsed is not None:
            self.add(path, parsed)

    def symbol(self, full_name: str) -> Symbol | None:
        path = self.owner_files.get(full_name)
        if path is None:
            return None
        parsed = self.parsed[path]
        return parsed.symbols.get(full_name[len(parsed.module) + 1:])

    def kind_of(self, full_name: str) -> str:
        symbol = self.symbol(full_name)
        if symbol is None:
            return KIND_FUNCTION
        return symbol.kind

    def language_path(self, full_name: str) -> str:
        return self.owner_files.get(full_name, "")

    def _could_call(self, path: str, full_name: str, kind: str) -> bool:
        tokens = self.tokens(path)
        parts = full_name.split(".")
        owner = self.language_path(full_name)
        if (owner and not same_language(owner, path)) or parts[-1] not in tokens:
            return False
        if kind == KIND_METHOD and len(parts) >= 2:
            return parts[-2] in tokens
        return is_ts_path(path) or self._module_anchored(path, full_name, tokens)

    def _module_anchored(self, path: str, full_name: str, tokens: set[str]) -> bool:
        module = full_name.rsplit(".", 1)[0]
        if self.modules.get(path) == module:
            return True
        anchors = set(module.split(".")[1:]) or set(module.split("."))
        return bool(anchors & tokens)

    def _wanted(self, path: str, targets, for_reach: bool) -> bool:
        if path in self.parsed or (for_reach and is_test_file(path)):
            return False
        return any(self._could_call(path, name, kind) for name, kind in targets)

    def expand_for(self, targets: list[tuple[str, str]], *, for_reach: bool = False) -> None:
        for path in self.inputs.project_python_files:
            if not self._wanted(path, targets, for_reach):
                continue
            if for_reach and self.reach_parses >= REACH_PARSE_BUDGET:
                self.reach_capped = True
                return
            if for_reach:
                self.reach_parses += 1
            self.ensure(path)

    def ensure_callee(self, name: str) -> None:
        parts = name.split(".")
        for size in range(len(parts) - 1, 0, -1):
            path = self.by_module.get(".".join(parts[:size]))
            if path is not None:
                self.ensure(path)
                return

    def _ts_aliases(self, full_name: str) -> set[str]:
        found = set(self.alias_index.get(full_name, ()))
        module, _, name = full_name.rpartition(".")
        for barrel in self.star_index.get(module, ()):
            found.add(f"{barrel}.{name}")
        for alias in list(found):
            found |= self.alias_index.get(alias, set())
        return found

    def _aliases(self, full_name: str) -> list[str]:
        parts = full_name.split(".")
        suffixes = [".".join(parts[i:]) for i in range(1, len(parts) - 2)]
        return [full_name] + sorted(self._ts_aliases(full_name)) + suffixes

    def callers_of(self, full_name: str) -> list[tuple[str, str]]:
        found = set()
        for alias in self._aliases(full_name):
            for name in self.reverse.get(alias, ()):
                path, owner = self.owner.get(name, (None, None))
                if owner is not None and owner != full_name:
                    found.add((owner, path))
        return sorted(found)

    def closure(self, full_name: str) -> set[str]:
        seen: set[str] = set()
        frontier = set(self.calls.get(full_name, set()))
        for _ in range(CALLER_DEPTH):
            next_frontier = set()
            for name in frontier - seen - {full_name}:
                seen.add(name)
                self.ensure_callee(name)
                next_frontier.update(self.calls.get(name, set()))
            frontier = next_frontier
        return seen | frontier


def _next_callers(graph: HeadGraph, frontier: set[str], seen: set[str], origin: str) -> set[str]:
    found = set()
    for name in sorted(frontier):
        for owner, _ in graph.callers_of(name):
            if owner not in seen and owner != origin:
                seen.add(owner)
                found.add(owner)
    return found


def reach(graph: HeadGraph, full_name: str) -> int:
    seen: set[str] = set()
    frontier = {full_name}
    for _ in range(CALLER_DEPTH):
        found = _next_callers(graph, frontier, seen, full_name)
        frontier = {n for n in found if not is_test_file(graph.owner_files.get(n, ""))}
        frontier = set(sorted(frontier)[:FRONTIER_CAP])
        if not frontier:
            break
        graph.expand_for([(name, graph.kind_of(name)) for name in sorted(frontier)], for_reach=True)
    return len(seen)


