"""Collection identities exposed through module and object dictionaries.

Only eager module/class code is considered. Reads and known unrelated keys do
not invalidate a test; unknown dictionary escapes keep its identity unproved.
No target namespace is imported or evaluated.
"""

from __future__ import annotations

import ast

from skylos.done.inventory import _import_aliases
from skylos.rules.quality._pytest_collection import _matches_name
from skylos.rules.quality._receivers import _scope_bindings
from skylos.rules.quality._test_flow import unreachable_test_nodes

_READS = frozenset({"get", "keys", "items", "values", "copy", "__contains__"})
_WRITES = frozenset(
    {"pop", "popitem", "clear", "update", "setdefault", "__setitem__", "__delitem__"}
)
_METADATA = frozenset(
    {
        "__test__",
        "pytestmark",
        "__unittest_skip__",
        "__unittest_expecting_failure__",
        "__wrapped__",
        "__pytest_wrapped__",
        "_pytestfixturefunction",
    }
)


def uncertain_collection_names(module, config, bindings) -> set[str]:
    """Names whose original declaration is no longer proved collectable.

    None in a dictionary-owner set denotes the module namespace. Class-local
    vars()/locals() instead refer to that class's collection identity.
    """
    blocked = set()
    objects = {name: {name} for name in bindings.names}
    mappings = {}
    class_locals = set()
    conditional = 0
    dead = unreachable_test_nodes(module)
    classes = {node.name for node in module.body if isinstance(node, ast.ClassDef)}
    methods = {
        node.name: {
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node in module.body
        if isinstance(node, ast.ClassDef)
    }
    framework = {
        name
        for name, target in _import_aliases(module.body).items()
        if target and target[0] in {"pytest", "unittest"}
    }

    def owners(expression):
        if isinstance(expression, ast.Name):
            return objects.get(expression.id, set())
        if isinstance(expression, ast.Attribute):
            roots = owners(expression.value)
            return {
                f"{root}.{expression.attr}"
                if root in methods and expression.attr in methods[root]
                else root
                for root in roots
            }
        return set()

    def mapping(expression, namespace):
        if isinstance(expression, ast.Name):
            return mappings.get(expression.id, set())
        if isinstance(expression, ast.Attribute) and expression.attr == "__dict__":
            return owners(expression.value)
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id in {"globals", "vars", "locals"}
            and expression.func.id not in bindings.names
            and expression.func.id not in class_locals
            and not expression.keywords
        ):
            if not expression.args:
                return {None if expression.func.id == "globals" else namespace}
            if expression.func.id == "vars" and len(expression.args) == 1:
                return owners(expression.args[0])
        return set()

    def key_of(expression):
        return (
            expression.value
            if isinstance(expression, ast.Constant)
            and isinstance(expression.value, str)
            else None
        )

    def invalidate(targets, key=None, value=None):
        for owner in targets:
            if owner is None:
                blocked.update(
                    bindings.names if key is None else {key} & bindings.names
                )
            elif (
                key is None
                or owner in framework
                or key in _METADATA
                or owner in classes
                and (
                    key in {"__init__", "__new__"}
                    or _matches_name(key, config.python_functions)
                )
            ):
                # A sole explicit opt-in does not replace the original callable.
                if (
                    key == "__test__"
                    and isinstance(value, ast.Constant)
                    and value.value is True
                ):
                    continue
                if owner in methods and key in methods[owner]:
                    blocked.add(f"{owner}.{key}")
                else:
                    blocked.add(owner)

    def visit(node, namespace=None):
        nonlocal objects, mappings, class_locals, conditional, dead
        if id(node) in dead:
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for field, value in ast.iter_fields(node):
                if field == "body":
                    continue
                for child in value if isinstance(value, list) else [value]:
                    if isinstance(child, ast.AST):
                        visit(child, namespace)
            return
        if isinstance(node, ast.ClassDef):
            for child in [*node.bases, *node.keywords, *node.decorator_list]:
                visit(child, namespace)
            outer_objects, outer_mappings, outer_locals, outer_dead = (
                objects,
                mappings,
                class_locals,
                dead,
            )
            objects = {name: set(value) for name, value in objects.items()}
            mappings = {name: set(value) for name, value in mappings.items()}
            class_locals = _scope_bindings(node).names
            dead = dead | unreachable_test_nodes(node)
            for name in class_locals:
                objects.pop(name, None)
                mappings.pop(name, None)
            local_names = {
                child.name
                for child in node.body
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            }
            objects.update({name: {f"{node.name}.{name}"} for name in local_names})
            for child in node.body:
                visit(child, node.name)
            objects, mappings, class_locals, dead = (
                outer_objects,
                outer_mappings,
                outer_locals,
                outer_dead,
            )
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is not None:
                visit(node.value, namespace)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            mapped, owned = mapping(node.value, namespace), owners(node.value)
            for target in targets:
                if isinstance(target, ast.Name):
                    # Union retains evidence through uncertain branch ordering.
                    if mapped:
                        if conditional:
                            mappings.setdefault(target.id, set()).update(mapped)
                        else:
                            mappings[target.id] = set(mapped)
                    elif not conditional:
                        mappings.pop(target.id, None)
                    if owned:
                        if conditional:
                            objects.setdefault(target.id, set()).update(owned)
                        else:
                            objects[target.id] = set(owned)
                    elif not conditional:
                        objects.pop(target.id, None)
                elif isinstance(target, ast.Subscript):
                    invalidate(
                        mapping(target.value, namespace),
                        key_of(target.slice),
                        node.value,
                    )
                    visit(target, namespace)
                else:
                    visit(target, namespace)
            return
        if isinstance(node, (ast.Delete, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Delete) else [node.target]
            for target in targets:
                if isinstance(target, ast.Subscript):
                    invalidate(mapping(target.value, namespace), key_of(target.slice))
        if isinstance(node, ast.Call):
            target = (
                mapping(node.func.value, namespace)
                if isinstance(node.func, ast.Attribute)
                else set()
            )
            if target and node.func.attr in _WRITES:
                method = node.func.attr
                if method == "update" and len(node.args) <= 1:
                    update = node.args[0] if node.args else None
                    if update is not None and not isinstance(update, ast.Dict):
                        invalidate(target)
                    elif isinstance(update, ast.Dict):
                        for key, value in zip(update.keys, update.values):
                            invalidate(target, key_of(key), value)
                    for keyword in node.keywords:
                        invalidate(target, keyword.arg, keyword.value)
                else:
                    key = (
                        key_of(node.args[0])
                        if node.args and method not in {"clear", "popitem"}
                        else None
                    )
                    value = (
                        node.args[1]
                        if len(node.args) > 1
                        and method in {"setdefault", "__setitem__"}
                        else None
                    )
                    invalidate(target, key, value)
            elif not (
                target
                and node.func.attr in _READS
                or isinstance(node.func, ast.Name)
                and node.func.id in {"len", "bool", "dict"}
                and node.func.id not in bindings.names | class_locals
            ):
                for argument in [
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                ]:
                    invalidate(mapping(argument, namespace))
        branching = isinstance(
            node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match)
        )
        conditional += branching
        try:
            for child in ast.iter_child_nodes(node):
                visit(child, namespace)
        finally:
            conditional -= branching

    for statement in module.body:
        visit(statement)
    return blocked
