"""Source-defined classes and stable receiver bindings for reachability.

Unknown values stay unknown. Legacy inferred type names are deliberately not
used as proof of an object's runtime class.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from pathlib import Path

from skylos.deadcode._reachability_bindings import (
    FUNCTION_NODES,
    Bindings,
    ModuleInfo,
    argument_nodes,
    bound_names,
    function_bindings,
)

if TYPE_CHECKING:
    from skylos.deadcode._reachability_graph import SourceIndex

CLASS_BINDING = "class"
INSTANCE_BINDING = "instance"
RECEIVER_BINDINGS = {CLASS_BINDING, INSTANCE_BINDING}


@dataclass
class ClassInfo:
    key: str
    definition: Any
    node: ast.ClassDef
    module: ModuleInfo
    methods: dict[str, str]


def _namespace_name(class_name: str, member_name: str) -> str:
    prefix = class_name.lstrip("_")
    if prefix and member_name.startswith("__") and not member_name.endswith("__"):
        return f"_{prefix}{member_name}"
    return member_name


def _plain_class(node: ast.ClassDef) -> bool:
    if node.bases or node.keywords or node.decorator_list:
        return False
    for statement in node.body:
        if isinstance(statement, FUNCTION_NODES):
            if statement.decorator_list or statement.name in {
                "__new__",
                "__getattr__",
                "__getattribute__",
                "__setattr__",
                "__delattr__",
            }:
                return False
        elif isinstance(statement, ast.Pass):
            continue
        elif isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Constant
        ):
            continue
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            # Executable class namespace expressions can install descriptors or
            # mutate methods. Literal state has no such execution effects.
            try:
                ast.literal_eval(statement.value)
            except (ValueError, TypeError, SyntaxError, RecursionError):
                return False
        else:
            return False
    return True


def bind_classes(index: SourceIndex, definitions: Any) -> None:
    locations = {
        (Path(d.filename).resolve(), d.line, d.simple_name, d.type): (key, d)
        for key, d in definitions.items()
        if d.type in {"class", "method"}
    }
    for module in index.modules.values():
        counts = bound_names(module.tree.body).counts
        for node in module.tree.body:
            if not isinstance(node, ast.ClassDef) or counts[node.name] != 1:
                continue
            _bind_class(index, module, node, locations)


def _bind_class(
    index: SourceIndex, module: ModuleInfo, node: ast.ClassDef, locations: dict
) -> None:
    entry = locations.get((module.path, node.lineno, node.name, "class"))
    if entry is None or not _plain_class(node):
        return
    key, definition = entry
    members = bound_names(node.body).counts
    namespace: Counter[str] = Counter()
    for name, count in members.items():
        namespace[_namespace_name(node.name, name)] += count
    if any(count > 1 for count in namespace.values()):
        # Python mangles private names before binding the class
        # namespace. A raw spelling can overwrite a private method.
        return
    methods = {}
    for member in node.body:
        if not isinstance(member, FUNCTION_NODES) or members[member.name] != 1:
            continue
        match = locations.get((module.path, member.lineno, member.name, "method"))
        if match is None:
            continue
        method_key, method = match
        methods[member.name] = method_key
        methods[_namespace_name(node.name, member.name)] = method_key
        index.candidates[method_key] = method
        index.by_location[module.path, member.lineno] = method_key
        index.by_name[method.name].append(method_key)
        index.by_simple_name[method.simple_name].add(method_key)
        index.initial_references[method_key] = method.references
        index.method_classes[method_key] = key
        module.functions[member.lineno] = method_key
    index.classes[key] = ClassInfo(key, definition, node, module, methods)
    index.class_locations[module.path, node.lineno] = key
    module.bindings[node.name] = (CLASS_BINDING, key)


def stable_receivers(
    index: SourceIndex,
    module: ModuleInfo,
    statements: list[ast.stmt],
    local: Bindings,
    *,
    parameters: set[str] | None = None,
) -> Bindings:
    """Resolve only unconditional, single-write assignments in this scope.

    A branch, loop, unpacking or reassignment cannot establish a receiver.
    Unknown RHS values are not filled in using annotations or naming rules.
    """
    counts = bound_names(statements).counts
    protected = parameters or set()
    result = dict(local)
    for statement in statements:
        if isinstance(statement, ast.Assign):
            targets, value = statement.targets, statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            targets, value = [statement.target], statement.value
        else:
            continue
        binding = index.resolve(value, module, result)
        if not binding or binding[0] not in RECEIVER_BINDINGS:
            continue
        for target in targets:
            if (
                isinstance(target, ast.Name)
                and counts[target.id] == 1
                and target.id not in protected
            ):
                result[target.id] = binding
    return result


def function_receivers(
    index: SourceIndex, module: ModuleInfo, node: Any
) -> tuple[Bindings, bool]:
    local, writes = function_bindings(node, module)
    parameters = {arg.arg for arg in argument_nodes(node.args)}
    key = module.functions.get(node.lineno)
    class_key = index.method_classes.get(key)
    positional = [*node.args.posonlyargs, *node.args.args]
    if class_key and positional:
        receiver = positional[0].arg
        if receiver not in bound_names(node.body).counts:
            local[receiver] = (INSTANCE_BINDING, class_key)
    if not writes:
        local = stable_receivers(index, module, node.body, local, parameters=parameters)
    return local, writes
