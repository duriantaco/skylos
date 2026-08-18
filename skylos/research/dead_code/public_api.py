"""Infer the externally consumable API surface of a library repository.

The reachability model assumes callers live inside the analysed repository.
That assumption holds for applications, where routes and CLI entrypoints are
the only ways in.  It fails for libraries: ``Flask.open_instance_resource`` has
no in-repo call site because its callers are downstream projects.

This module identifies the surface a distribution actually publishes:

1. names re-exported through package ``__init__`` modules;
2. classes reachable from those names;
3. first-party ancestors of those classes, whose inherited methods are equally
   callable through the exported subclass.

Public methods of that closure are recorded as uncertainty rather than
liveness.  The analysis abstains on them: it can neither prove them used nor
safely call them dead from repository-local evidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from skylos.research.dead_code.binding import dotted_name


@dataclass
class PublicApi:
    exported_names: set[str] = field(default_factory=set)
    exported_classes: set[str] = field(default_factory=set)

    def covers_class(self, qualified_class: str) -> bool:
        return qualified_class in self.exported_classes


def collect_public_api(
    module_names: dict[Path, str], trees: dict[Path, ast.Module]
) -> PublicApi:
    api = PublicApi()

    class_bases: dict[str, list[str]] = {}
    class_modules: dict[str, str] = {}

    for path, tree in trees.items():
        module = module_names.get(path, "")
        _collect_class_bases(tree, module, class_bases, class_modules)
        if path.name == "__init__.py":
            api.exported_names.update(_collect_reexports(tree, module))

    # Seed with exported names that name a class, then close over first-party
    # ancestors so inherited public methods are covered too.
    frontier = [name for name in api.exported_names if name in class_bases]
    seen: set[str] = set()
    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        api.exported_classes.add(current)
        for base in class_bases.get(current, []):
            resolved = _resolve_base(base, class_bases, class_modules, current)
            if resolved and resolved not in seen:
                frontier.append(resolved)

    return api


def _collect_class_bases(
    tree: ast.Module,
    module: str,
    class_bases: dict[str, list[str]],
    class_modules: dict[str, str],
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        qualified = f"{module}.{node.name}" if module else node.name
        class_bases[qualified] = [dotted_name(base) for base in node.bases]
        class_modules[qualified] = module


def _collect_reexports(tree: ast.Module, module: str) -> set[str]:
    """Names an ``__init__`` module republishes to importers."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = module
                if node.module:
                    base = f"{module}.{node.module}" if module else node.module
            else:
                base = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                names.add(f"{base}.{alias.name}" if base else alias.name)
    return names


def _resolve_base(
    base: str,
    class_bases: dict[str, list[str]],
    class_modules: dict[str, str],
    current: str,
) -> str | None:
    """Best-effort mapping of a base-class expression to a first-party class."""
    if not base:
        return None
    if base in class_bases:
        return base

    simple = base.rsplit(".", 1)[-1]
    module = class_modules.get(current, "")
    candidate = f"{module}.{simple}" if module else simple
    if candidate in class_bases:
        return candidate

    matches = [name for name in class_bases if name.rsplit(".", 1)[-1] == simple]
    if len(matches) == 1:
        return matches[0]
    return None
