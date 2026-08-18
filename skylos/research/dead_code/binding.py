"""Resolve decorator expressions to dotted import origins.

Root inference needs to know *where a decorator came from*, not merely what it
is called.  This module walks a single module's AST and builds two binding
tables:

``import_bindings``
    Local name -> dotted origin, from ``import x``, ``import x as y``, and
    ``from a.b import c as d``.
``instance_bindings``
    Local name -> dotted origin of the class that produced it, for module-level
    assignments such as ``app = Flask(__name__)`` or
    ``hookimpl = pluggy.HookimplMarker("proj")``, and for functions that a
    group-producing decorator turns into a command group
    (``@click.group()`` over ``def cli()`` binds ``cli`` to ``click.Group``).

Resolution is intentionally partial.  When a name cannot be traced to an
import, the caller receives ``None`` and must treat the decorator as
unresolved evidence rather than as proof of liveness.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from skylos.research.dead_code.frameworks import (
    FRAMEWORK_INSTANCE_CLASSES,
    GROUP_PRODUCING_DECORATORS,
)


def dotted_name(node: ast.AST | None) -> str:
    """Return the dotted source text of a Name/Attribute chain, or ""."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


@dataclass
class ModuleBindings:
    import_bindings: dict[str, str] = field(default_factory=dict)
    instance_bindings: dict[str, str] = field(default_factory=dict)

    def resolve(self, dotted: str) -> str | None:
        """Resolve a dotted decorator expression to its import origin."""
        if not dotted:
            return None
        head, _, rest = dotted.partition(".")
        base = self.instance_bindings.get(head) or self.import_bindings.get(head)
        if base is None:
            return None
        return f"{base}.{rest}" if rest else base


def collect_bindings(tree: ast.Module, module_name: str) -> ModuleBindings:
    bindings = ModuleBindings()
    _collect_imports(tree, module_name, bindings)
    # Instance bindings depend on imports, so they run as a second pass.
    _collect_instances(tree, bindings)
    return bindings


def _collect_imports(
    tree: ast.Module, module_name: str, bindings: ModuleBindings
) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                origin = alias.name
                if alias.asname is None and "." in alias.name:
                    origin = alias.name.split(".")[0]
                bindings.import_bindings[local] = origin
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative import: attribute it to the containing package so
                # first-party detection treats it as local, not third-party.
                package = module_name.rsplit(".", node.level)[0] if module_name else ""
                base = f"{package}.{node.module}" if node.module else package
            else:
                base = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                bindings.import_bindings[local] = (
                    f"{base}.{alias.name}" if base else alias.name
                )


def _collect_instances(tree: ast.Module, bindings: ModuleBindings) -> None:
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            _bind_assignment(node, bindings)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _bind_group_function(node, bindings)


def _bind_assignment(node: ast.Assign | ast.AnnAssign, bindings: ModuleBindings) -> None:
    value = node.value
    if not isinstance(value, ast.Call):
        return
    origin = bindings.resolve(dotted_name(value.func))
    if origin is None or origin not in FRAMEWORK_INSTANCE_CLASSES:
        return

    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Name):
            bindings.instance_bindings[target.id] = origin


def _bind_group_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef, bindings: ModuleBindings
) -> None:
    """``@click.group()`` over ``def cli()`` makes ``cli`` a command group."""
    for decorator in node.decorator_list:
        origin = bindings.resolve(dotted_name(decorator))
        if origin is None:
            continue
        produced = GROUP_PRODUCING_DECORATORS.get(origin)
        if produced:
            bindings.instance_bindings[node.name] = produced
            return
