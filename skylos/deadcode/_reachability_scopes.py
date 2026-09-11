"""Source identities and lexical parents for stable named nested functions."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from skylos.deadcode._reachability_bindings import (
    FUNCTION_NODES,
    argument_nodes,
    bound_names,
    namespace_name,
)

if TYPE_CHECKING:
    from skylos.deadcode._reachability_graph import SourceIndex


def bind_nested_functions(index: SourceIndex, locations: dict) -> None:
    for module in index.modules.values():
        # ast.walk visits parents before children. Unsupported parents never
        # acquire local bindings or turn their descendants into negative proofs.
        for node in ast.walk(module.tree):
            if not isinstance(node, FUNCTION_NODES):
                continue
            owner = module.functions.get(node.lineno)
            if owner is None:
                continue
            _bind_scope(index, module, node, owner, locations)


def _bind_scope(index, module, node, owner, locations) -> None:
    class_key = index.method_classes.get(owner)
    class_name = (
        index.classes[class_key].node.name
        if class_key is not None
        else index.scope_classes.get(owner, "")
    )
    index.scope_classes[owner] = class_name
    names = bound_names(node.body, class_name=class_name)
    if names.scope_writes:
        return
    parameters = {
        namespace_name(class_name, arg.arg) for arg in argument_nodes(node.args)
    }
    for child in node.body:
        if not isinstance(child, FUNCTION_NODES) or getattr(child, "type_params", ()):
            continue
        matches = locations.get((module.path, child.lineno, child.name), ())
        if len(matches) != 1:
            continue
        key, definition = matches[0]
        name = namespace_name(class_name, child.name)
        index.add_function(module, child, key, definition)
        index.nested_parents[key] = owner
        index.scope_classes[key] = class_name
        if names.counts[name] == 1 and name not in parameters:
            index.local_functions[owner][name] = ("symbol", key)
        else:
            # Rebinding and private-name collisions cannot justify deletion.
            # Keep the declarations without choosing a lexical value for them.
            index.uncertain_nested_keys.add(key)
