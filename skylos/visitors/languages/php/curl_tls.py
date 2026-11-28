"""Inspect statically resolved cURL verification options."""

from __future__ import annotations

import re

OPTIONS = frozenset({"CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"})
KNOWN_OPTIONS = OPTIONS | {
    "CURLOPT_CONNECTTIMEOUT",
    "CURLOPT_FOLLOWLOCATION",
    "CURLOPT_HTTPHEADER",
    "CURLOPT_POST",
    "CURLOPT_POSTFIELDS",
    "CURLOPT_RETURNTRANSFER",
    "CURLOPT_TIMEOUT",
    "CURLOPT_URL",
}
_NUMBERED_TLS_OPTIONS = {"64": "CURLOPT_SSL_VERIFYPEER", "81": "CURLOPT_SSL_VERIFYHOST"}
_PARAMETERS = {
    "curl_setopt": ("handle", "option", "value"),
    "curl_setopt_array": ("handle", "options"),
}
_SCOPE_NODES = {"program", "compound_statement"}
_LINEAR_PARENTS = {
    "argument",
    "arguments",
    "array_creation_expression",
    "array_element_initializer",
    "assignment_expression",
    "expression_statement",
    "function_call_expression",
    "parenthesized_expression",
    "return_statement",
}
_MAX_PREVIOUS_STATEMENTS = 64


def _arguments(node, names, text):
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return {}
    bound = {}
    named = False
    arguments = (item for item in arguments.named_children if item.type != "comment")
    for index, argument in enumerate(arguments):
        if argument.type != "argument" or not argument.named_children:
            return {}
        label = argument.child_by_field_name("name")
        if label is not None:
            named = True
            key = text(label)
        elif named or index >= len(names):
            return {}
        else:
            key = names[index]
        value = argument.named_children[-1]
        if key not in names or key in bound or value.type == "variadic_unpacking":
            return {}
        bound[key] = value
    return bound if len(bound) == len(names) else {}


def _local_value(node, text, unwrap, *, depth=0):
    """Follow consecutive local statements until a known write or use."""
    node = unwrap(node)
    if node is None or node.type != "variable_name":
        return node
    if depth >= 8:
        return None
    name = text(node)
    statement = node
    while statement.parent is not None and statement.parent.type not in _SCOPE_NODES:
        if statement.parent.type not in _LINEAR_PARENTS:
            return None
        statement = statement.parent
    occurrence = re.compile(rf"{re.escape(name)}(?!\w)")
    for _ in range(_MAX_PREVIOUS_STATEMENTS):
        statement = statement.prev_named_sibling
        if statement is None:
            break
        if statement.type == "comment" or not occurrence.search(text(statement)):
            continue
        if statement.type == "expression_statement" and statement.named_children:
            assignment = statement.named_children[0]
            left = assignment.child_by_field_name("left")
            if (
                assignment.type == "assignment_expression"
                and left is not None
                and left.type == "variable_name"
                and text(left) == name
            ):
                return _local_value(
                    assignment.child_by_field_name("right"),
                    text,
                    unwrap,
                    depth=depth + 1,
                )
        break
    return None


def _option(node, text, shadowed):
    if node is None:
        return None
    name = text(node)
    if node.type in {"name", "qualified_name"}:
        if name.startswith("\\"):
            return name[1:] if name[1:] in KNOWN_OPTIONS else None
        return name if name in KNOWN_OPTIONS and name not in shadowed else None
    if node.type == "integer" and re.fullmatch(r"[1-9][0-9]*|0", name):
        return _NUMBERED_TLS_OPTIONS.get(name, "")
    if node.type in {"string", "encapsed_string"} and all(
        child.type == "string_content" for child in node.named_children
    ):
        return _NUMBERED_TLS_OPTIONS.get(name[1:-1], "")
    return None


def _disabled(node, text):
    if node is None:
        return False
    value = text(node)
    if node.type in {"boolean", "null"}:
        return value.lower() in {"false", "null"}
    if node.type == "integer":
        return bool(re.fullmatch(r"(?:0+|0[xob]0+)", value.lower().replace("_", "")))
    return node.type == "string" and value in {"''", "'0'", '""', '"0"'}


def disabled_options(node, name, text, unwrap, shadowed):
    if name not in _PARAMETERS:
        return set()
    args = _arguments(node, _PARAMETERS[name], text)
    if not args:
        return set()
    if name == "curl_setopt":
        option = _option(_local_value(args["option"], text, unwrap), text, shadowed)
        value = _local_value(args["value"], text, unwrap)
        return {option} if option in OPTIONS and _disabled(value, text) else set()
    options = _local_value(args["options"], text, unwrap)
    if options is None or options.type != "array_creation_expression":
        return set()
    disabled = set()
    for element in options.named_children:
        if element.type == "comment":
            continue
        fields = element.named_children
        if element.type != "array_element_initializer" or len(fields) != 2:
            disabled.clear()
            continue
        key, value = fields
        option = _option(_local_value(key, text, unwrap), text, shadowed)
        if option is None:
            # An unresolved key can overwrite an earlier literal option.
            disabled.clear()
        elif option in OPTIONS:
            if _disabled(_local_value(value, text, unwrap), text):
                disabled.add(option)
            else:
                disabled.discard(option)
    return disabled
