"""Index attribute contexts while preserving the original scoring arithmetic."""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
import struct
from typing import Any, Iterable

_DEFAULT_WEIGHTS = {
    "same_file_attr": 1.0,
    "same_pkg_attr": 0.3,
    "global_attr": 0.1,
}
_BUILTIN_NUMBERS = (int, float)
_ADDITION_CACHE_LIMIT = 4096
_MIN_CONTEXTS_TO_INDEX = 32


def _numeric_key(value: int | float) -> tuple[type, Any]:
    # Float equality merges signed zeros and cannot identify NaN payloads.
    return type(value), struct.pack("!d", value) if type(value) is float else value


class _ExactAddition:
    def __init__(self):
        self.results = OrderedDict()

    def add(self, initial: int | float, weight: int | float, count: int):
        key = (_numeric_key(initial), _numeric_key(weight), count)
        if key not in self.results:
            value = initial
            for _ in range(count):
                value = value + weight
            if len(self.results) >= _ADDITION_CACHE_LIMIT:
                self.results.popitem(last=False)
            self.results[key] = value
        return self.results[key]


def _first_other(firsts, excluded):
    return next(index for name, index in firsts if name != excluded)


@dataclass
class _Contexts:
    raw: list = field(default_factory=list)
    modules: dict = field(default_factory=dict)
    packages: dict = field(default_factory=dict)
    module_first: dict = field(default_factory=dict)
    package_modules: dict = field(default_factory=lambda: defaultdict(list))
    first_modules: list = field(default_factory=list)
    first_packages: list = field(default_factory=list)
    standard: bool = True

    def add(self, context):
        index = len(self.raw)
        self.raw.append(context)
        module = context[0]
        if type(module) is not str:
            self.standard = False
            return
        package = module.split(".")[0] if module else ""
        if module not in self.modules:
            self._first_module(module, package, index)
        if package not in self.packages and len(self.first_packages) < 2:
            self.first_packages.append((package, index))
        self.modules[module] = self.modules.get(module, 0) + 1
        self.packages[package] = self.packages.get(package, 0) + 1

    def _first_module(self, module, package, index):
        self.module_first[module] = index
        if len(self.first_modules) < 2:
            self.first_modules.append((module, index))
        if len(self.package_modules[package]) < 2:
            self.package_modules[package].append((module, index))

    def updates(self, module, package):
        same_file = self.modules.get(module, 0)
        same_package = self.packages.get(package, 0) - same_file if package else 0
        global_count = len(self.raw) - same_file - same_package
        updates = []
        if same_file:
            updates.append((self.module_first[module], "same_file_attr", same_file))
        if same_package:
            first = _first_other(self.package_modules[package], module)
            updates.append((first, "same_pkg_attr", same_package))
        if global_count:
            firsts = self.first_packages if package else self.first_modules
            excluded = package if package else module
            updates.append(
                (_first_other(firsts, excluded), "global_attr", global_count)
            )
        return sorted(updates)


def _definition_location(definition):
    # Preserve the existing full rsplit: deeper dotted names use their first
    # component here. This optimization does not change reference resolution.
    module = definition.name.rsplit(".")[0] if "." in definition.name else ""
    package = module.split(".")[0] if module else ""
    return module, package


def _original_updates(definition, contexts, weights, module, package):
    """Compatibility path for overloaded arithmetic or mapping behavior."""
    for context_module, _class, _line in contexts:
        context_package = context_module.split(".")[0] if context_module else ""
        if context_module == module:
            definition.heuristic_refs["same_file_attr"] = definition.heuristic_refs.get(
                "same_file_attr", 0.0
            ) + weights.get("same_file_attr", 1.0)
        elif context_package and package and context_package == package:
            definition.heuristic_refs["same_pkg_attr"] = definition.heuristic_refs.get(
                "same_pkg_attr", 0.0
            ) + weights.get("same_pkg_attr", 0.3)
        else:
            definition.heuristic_refs["global_attr"] = definition.heuristic_refs.get(
                "global_attr", 0.0
            ) + weights.get("global_attr", 0.1)


class AttributeContextIndex:
    def __init__(self, contexts: Iterable[tuple]):
        self.by_attribute = defaultdict(list)
        self.indexed_attributes = {}
        self.seen_attributes = set()
        self.addition = _ExactAddition()
        for attribute, module, owner, line in contexts:
            self.by_attribute[attribute].append((module, owner, line))

    def mark(self, definition: Any, weights: dict) -> None:
        attribute = definition.simple_name
        contexts = self.by_attribute.get(attribute)
        if contexts is None:
            return
        module, package = _definition_location(definition)
        indexed = (
            self._index_for(attribute, contexts)
            if len(contexts) > _MIN_CONTEXTS_TO_INDEX
            else None
        )
        if indexed is None:
            _original_updates(definition, contexts, weights, module, package)
            return
        self._mark_indexed(definition, indexed, weights, module, package)

    def _index_for(self, attribute, contexts):
        # Short and single-use context lists cost less with the original loop.
        if attribute not in self.seen_attributes:
            self.seen_attributes.add(attribute)
            return None
        if attribute not in self.indexed_attributes:
            indexed = _Contexts()
            for context in contexts:
                indexed.add(context)
            self.indexed_attributes[attribute] = indexed
        return self.indexed_attributes[attribute]

    def _mark_indexed(self, definition, contexts, weights, module, package):
        if not self._can_group(definition, contexts, weights):
            _original_updates(definition, contexts.raw, weights, module, package)
            return
        updates = contexts.updates(module, package)
        values = self._builtin_values(definition.heuristic_refs, updates, weights)
        if values is None:
            _original_updates(definition, contexts.raw, weights, module, package)
            return
        try:
            scores = [
                (marker, self.addition.add(initial, weight, count))
                for marker, initial, weight, count in values
            ]
        except OverflowError:
            # Replay before writing anything to preserve the original partial
            # mutation and exception position for huge int/float combinations.
            _original_updates(definition, contexts.raw, weights, module, package)
            return
        for marker, score in scores:
            definition.heuristic_refs[marker] = score

    @staticmethod
    def _can_group(definition, contexts, weights):
        return (
            contexts.standard
            and type(definition.name) is str
            and type(definition.heuristic_refs) is dict
            and type(weights) is dict
        )

    @staticmethod
    def _builtin_values(references, updates, weights):
        values = []
        for _first, marker, count in updates:
            initial = references.get(marker, 0.0)
            weight = weights.get(marker, _DEFAULT_WEIGHTS[marker])
            if (
                type(initial) not in _BUILTIN_NUMBERS
                or type(weight) not in _BUILTIN_NUMBERS
            ):
                return None
            values.append((marker, initial, weight, count))
        return values
