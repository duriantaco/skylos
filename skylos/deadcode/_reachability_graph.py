"""Definition identities, source references and separate uncertainty edges."""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from skylos.deadcode._reachability_bindings import (
    MODULE_BINDING,
    QUALIFIED_BINDING,
    Binding,
    Bindings,
    ModuleInfo,
)
from skylos.deadcode._reachability_receivers import (
    CLASS_BINDING,
    INSTANCE_BINDING,
    RECEIVER_BINDINGS,
    ClassInfo,
)

if TYPE_CHECKING:
    from skylos.visitors.base import Definition


@dataclass(frozen=True)
class SourceReference:
    name: str
    target: str | None
    owner: str | None


@dataclass
class SourceIndex:
    modules: dict[Path, ModuleInfo] = field(default_factory=dict)
    module_names: dict[str, list[ModuleInfo]] = field(
        default_factory=lambda: defaultdict(list)
    )
    candidates: dict[str, Definition] = field(default_factory=dict)
    by_location: dict[tuple[Path, int], str] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    by_simple_name: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    initial_references: dict[str, int] = field(default_factory=dict)
    binding_targets: dict[Binding | None, frozenset[str]] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    class_locations: dict[tuple[Path, int], str] = field(default_factory=dict)
    method_classes: dict[str, str] = field(default_factory=dict)

    def qualified(self, name: str, seen: tuple[str, ...] = ()) -> Binding | None:
        if name in seen or len(seen) >= 24:
            return None
        parts = name.split(".")
        for end in range(len(parts), 0, -1):
            modules = self.module_names.get(".".join(parts[:end]), ())
            if len(modules) == 1:
                return self._module_member(modules[0], name, parts, end, seen)
        return None

    def _module_member(
        self,
        module: ModuleInfo,
        name: str,
        parts: list[str],
        end: int,
        seen: tuple[str, ...],
    ) -> Binding | None:
        if end == len(parts):
            return (MODULE_BINDING, name)
        binding = module.bindings.get(parts[end])
        if binding and binding[0] == QUALIFIED_BINDING:
            binding = self.qualified(binding[1], (*seen, name))
        for member in parts[end + 1 :]:
            binding = self.receiver_member(binding, member)
        return binding

    def receiver_member(self, binding: Binding | None, name: str) -> Binding | None:
        if binding and binding[0] in RECEIVER_BINDINGS:
            key = self.classes[binding[1]].methods.get(name)
            if key is not None:
                return ("symbol", key)
        return None

    def resolve(
        self, node: ast.AST, module: ModuleInfo, local: Bindings
    ) -> Binding | None:
        binding = None
        if isinstance(node, ast.Name):
            binding = (
                local.get(node.id) if node.id in local else module.bindings.get(node.id)
            )
            if binding and binding[0] == QUALIFIED_BINDING:
                binding = self.qualified(binding[1])
        elif isinstance(node, ast.Attribute):
            base = self.resolve(node.value, module, local)
            if base and base[0] == MODULE_BINDING:
                binding = self.qualified(f"{base[1]}.{node.attr}")
            else:
                binding = self.receiver_member(base, node.attr)
                if base and base[0] == INSTANCE_BINDING and node.attr == "__class__":
                    binding = (CLASS_BINDING, base[1])
        elif isinstance(node, ast.Call):
            constructor = self.resolve(node.func, module, local)
            if constructor and constructor[0] == CLASS_BINDING:
                binding = (INSTANCE_BINDING, constructor[1])
        return binding

    def escaped_symbols(self, binding: Binding | None) -> frozenset[str]:
        cached = self.binding_targets.get(binding)
        if cached is not None:
            return cached
        possible: set[str] = set()
        todo = [binding]
        seen = set()
        while todo:
            current = todo.pop()
            if current and current not in seen:
                seen.add(current)
                self._expand_binding(current, possible, todo)
        result = frozenset(possible)
        self.binding_targets[binding] = result
        return result

    def _expand_binding(
        self, binding: Binding, possible: set[str], todo: list[Binding | None]
    ) -> None:
        kind, name = binding
        if kind == "symbol":
            possible.add(name)
        elif kind in RECEIVER_BINDINGS:
            possible.update(self.classes[name].methods.values())
        elif kind == QUALIFIED_BINDING:
            todo.append(self.qualified(name))
        elif kind == MODULE_BINDING:
            for module in self.module_names.get(name, ()):
                possible.update(module.functions.values())
                todo.extend(module.bindings.values())


@dataclass
class ReferenceGraph:
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    uncertain_edges: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    opaque_owners: set[str] = field(default_factory=set)
    roots: set[str] = field(default_factory=set)
    uncertain_roots: set[str] = field(default_factory=set)
    receiver_roots: set[str] = field(default_factory=set)
    receiver_edges: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    observed: Counter[str] = field(default_factory=Counter)
    references: dict[tuple[Path, int], list[SourceReference]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def protect(self, symbols: Iterable[str], owner: str | None) -> None:
        destination = (
            self.uncertain_roots if owner is None else self.uncertain_edges[owner]
        )
        destination.update(symbols)

    def record(
        self,
        index: SourceIndex,
        module: ModuleInfo,
        node: ast.AST,
        name: str,
        binding: Binding | None,
        *,
        owner: str | None,
        import_only: bool = False,
        proven: bool = True,
    ) -> None:
        target = binding[1] if binding and binding[0] == "symbol" else None
        self._record_lines(module.path, node, SourceReference(name, target, owner))
        if target is None:
            if not import_only:
                self.protect(index.by_simple_name.get(name, ()), owner)
            return
        self.observed[target] += 1
        if not import_only:
            self._add_edge(target, owner, proven=proven)

    def _record_lines(
        self, path: Path, node: ast.AST, reference: SourceReference
    ) -> None:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if 0 < start <= end and end - start < 64:
            for line in range(start, end + 1):
                self.references[path, line].append(reference)

    def _add_edge(self, target: str, owner: str | None, *, proven: bool) -> None:
        if owner is None:
            (self.roots if proven else self.uncertain_roots).add(target)
        else:
            self.edges[owner].add(target)

    def traverse(
        self, roots: Iterable[str], candidates: Iterable[str], *, uncertainty: bool
    ) -> set[str]:
        reached = set()
        todo = list(roots)
        expanded_opaque = False
        while todo:
            key = todo.pop()
            if key in reached:
                continue
            reached.add(key)
            todo.extend(self.edges.get(key, ()))
            if uncertainty:
                todo.extend(self.uncertain_edges.get(key, ()))
                if key in self.opaque_owners and not expanded_opaque:
                    todo.extend(candidates)
                    expanded_opaque = True
        return reached
