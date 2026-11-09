from __future__ import annotations

from skylos.changemap.ts_nodes import BODY, CONSTRUCTOR, DECLARATOR, IDENTIFIER, NAME, NEW, PARAMETERS, VALUE
from skylos.changemap.ts_walk import Scope, resolve_name


def _type_name(annotation, text) -> str | None:
    if annotation is None:
        return None
    stack = [annotation]
    while stack:
        current = stack.pop(0)
        if current.type == "type_identifier":
            return text(current)
        stack.extend(current.children)
    return None


def _param(node, index: int, text) -> tuple[str, str, bool]:
    kind = "positional"
    if node.type == "rest_pattern" or any(c.type == "rest_pattern" for c in node.children):
        kind = "varargs"
    has_default = node.type in ("optional_parameter", "assignment_pattern") or node.child_by_field_name(VALUE) is not None
    pattern = node.child_by_field_name("pattern") or node.child_by_field_name("left") or node
    name = f"_arg{index}"
    if pattern.type == IDENTIFIER:
        name = text(pattern)
    return kind, name, has_default


def _params(function_node, text) -> tuple:
    single = function_node.child_by_field_name("parameter")
    if single is not None:
        return (("positional", text(single), False),)
    formal = function_node.child_by_field_name(PARAMETERS)
    if formal is None:
        return ()
    items = [c for c in formal.named_children if c.type != "comment"]
    return tuple(_param(item, index, text) for index, item in enumerate(items))


def _signature(function_node, file) -> str:
    parts = []
    for field_name in (PARAMETERS, "parameter", "return_type"):
        node = function_node.child_by_field_name(field_name)
        if node is not None:
            parts.append(file.tokens(node))
    return " ".join(parts)


def _declarators(function_node) -> list:
    found = []
    stack = [n for n in [function_node.child_by_field_name(BODY)] if n is not None]
    while stack:
        node = stack.pop()
        if node.type == DECLARATOR:
            found.append(node)
        stack.extend(node.children)
    return found


def _typed_locals(function_node, scope: Scope, file) -> dict[str, str]:
    typed = {}
    formal = function_node.child_by_field_name(PARAMETERS)
    candidates = []
    if formal is not None:
        candidates.extend(formal.named_children)
    candidates.extend(_declarators(function_node))
    for node in candidates:
        _typed_local(node, scope, file, typed)
    return typed


def _constructed_type(value, file) -> str | None:
    if value is None or value.type != NEW:
        return None
    constructor = value.child_by_field_name(CONSTRUCTOR)
    if constructor is None or constructor.type != IDENTIFIER:
        return None
    return file.text(constructor)


def _typed_local(node, scope: Scope, file, typed: dict[str, str]) -> None:
    name_node = node.child_by_field_name("pattern") or node.child_by_field_name(NAME)
    if name_node is None or name_node.type != IDENTIFIER:
        return
    type_name = _type_name(node.child_by_field_name("type"), file.text)
    type_name = type_name or _constructed_type(node.child_by_field_name(VALUE), file)
    resolved = resolve_name(type_name or "", scope, file.local_tops)
    if resolved:
        typed[file.text(name_node)] = resolved
