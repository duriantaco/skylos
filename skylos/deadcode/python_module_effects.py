"""Source namespaces from a proved file-loader execution and return.

Only the existing same-spec execution contract can create these values. Target
modules remain parsed source; their code is never imported or executed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from skylos.deadcode.module_loader_proofs import (
    _loader_contract,
    _providers_intact,
    _supplied_arguments,
)
from skylos.deadcode.python_project_sources import (
    Class,
    Function,
    Record,
    Symbol,
    alternatives,
    merge,
)
from skylos.deadcode.python_proofs import _provider_available


def inspect_provider_available(index, path):
    cache = getattr(index, "_inspect_provider_paths", None)
    if cache is None:
        cache = {}
        index._inspect_provider_paths = cache
    if path not in cache:
        cache[path] = _provider_available("inspect", str(path))
    return cache[path]


class NamespaceValues(dict):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner


@dataclass
class SourceNamespace:
    path: Path
    valid: bool = True
    values: NamespaceValues | None = field(default=None, repr=False)

    def attribute(self, index, name):
        if not self.valid:
            return None
        if name == "__file__":
            return self.path
        if self.values is None:
            index.initialize_module(self.path)
            self.values = NamespaceValues(self)
            names = set(index.definitions.get(self.path, {}))
            names.update(index.imports.get(self.path, {}))
            names.update(index.assignments.get(self.path, {}))
            for symbol in sorted(names):
                self.values[symbol] = index.global_value(self.path, symbol)
        if name == "__dict__":
            return self.values
        return self.values.get(name)


def invalidate_namespace(value):
    if isinstance(value, SourceNamespace):
        value.valid = False
        return True
    if isinstance(value, NamespaceValues):
        value.owner.valid = False
        return True
    return False


def source_loader_result(index, function, arguments, keywords):
    tree = index.trees.get(function.path)
    if tree is None:
        return None
    contracts = getattr(index, "_source_module_contracts", None)
    if contracts is None:
        contracts = {}
        index._source_module_contracts = contracts
    identity = (function.path, function.node.lineno)
    if identity not in contracts:
        contracts[identity] = _loader_contract(function, tree)
    contract = contracts[identity]
    if contract is None or not contract[1]:
        return None
    if not _providers_intact(index, function, tree):
        return None
    supplied = _supplied_arguments(function, arguments, keywords)
    if supplied is None:
        return None
    namespaces = []
    for value in alternatives(supplied.get(contract[0])):
        if not isinstance(value, (str, Path)):
            continue
        path = Path(value)
        if not path.is_absolute():
            path = index.root / path
        try:
            if any(part.is_symlink() for part in [path, *path.parents]):
                continue
            path = path.resolve()
            path.relative_to(index.root)
        except (OSError, ValueError):
            continue
        if path in index.trees:
            index.initialize_module(path)
            namespaces.append(SourceNamespace(path))
    return merge(namespaces)


def source_isclass(value):
    if isinstance(value, Class):
        if (
            value.node is not None
            and value.node.decorator_list
            and not value.generated_init
        ):
            return None
        return True
    if isinstance(value, Symbol):
        if value.invalid:
            return None
        if value.kind == "module":
            return False
        return None
    if isinstance(
        value, (Function, Record, SourceNamespace, str, int, list, tuple, dict)
    ):
        return False
    return None


def source_issubclass(index, candidate, parent, seen=frozenset()):
    if isinstance(parent, list):
        outcomes = []
        for item in parent:
            outcomes.append(source_issubclass(index, candidate, item, seen))
        if True in outcomes:
            return True
        if None in outcomes:
            return None
        return False
    if not isinstance(candidate, Class) or not isinstance(parent, Class):
        return None
    if candidate.node is None or parent.node is None:
        return None
    if candidate.node.decorator_list and not candidate.generated_init:
        return None
    if parent.node.decorator_list and not parent.generated_init:
        return None
    if candidate.node.keywords or parent.node.keywords:
        return None
    for node in parent.node.body:
        if isinstance(node, ast.FunctionDef) and node.name in {
            "__subclasscheck__",
            "__subclasshook__",
        }:
            return None
    if candidate.path == parent.path and candidate.node is parent.node:
        return True
    if id(candidate.node) in seen:
        return None
    uncertain = False
    for base in candidate.node.bases:
        value = index.evaluate(base, candidate.path, {})
        outcome = source_issubclass(index, value, parent, seen | {id(candidate.node)})
        if outcome is True:
            return True
        if outcome is None:
            uncertain = True
    if uncertain:
        return None
    return False
