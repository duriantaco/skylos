"""Window messaging checks with browser, payload and action evidence."""

import re

from .security_flow import _string_value, terminates

_WINDOW_ROOTS = frozenset({"window", "parent", "top", "opener"})
_WINDOW_MEMBERS = frozenset({"window", "parent", "top", "opener", "frames"})
_DOM_QUERIES = frozenset({"getElementById", "querySelector"})
_CALLBACKS = frozenset(
    {"arrow_function", "function_expression", "function_declaration", "function"}
)
_LITERAL_TYPES = frozenset(
    {"string", "number", "true", "false", "null", "undefined", "regex"}
)


def _stable_global(flow, path, node):
    return flow.is_stable_global_path(
        path, node.start_byte, flow.scope_for_node(node).id
    )


def _binding_value(flow, node, *, hoisted=False):
    if node is None or node.type != "identifier":
        return None
    scope_id = flow.scope_for_node(node).id
    resolve = (
        flow.resolve_unique_binding_with_hoisted_functions
        if hoisted
        else flow.resolve_unique_binding
    )
    binding = resolve(flow.node_text(node), node.start_byte, scope_id)
    if binding is None or not flow.is_binding_value_stable(
        binding, node.start_byte, scope_id
    ):
        return None
    value = binding.value_node
    if value is None and hoisted:
        value = binding.declaration_node
    return flow.unwrap(value)


def _member(flow, node):
    if node is None or node.type not in {"member_expression", "subscript_expression"}:
        return None, ""
    prop = node.child_by_field_name("property") or node.child_by_field_name("index")
    if prop is None:
        return None, ""
    name = (
        _string_value(flow.source, prop)
        if prop.type == "string"
        else flow.node_text(prop)
        if node.type == "member_expression"
        else ""
    )
    return flow.unwrap(node.child_by_field_name("object")), name or ""


def _property(flow, node, key):
    node = flow.unwrap(node)
    if node is None or node.type != "object":
        return None
    for child in reversed(node.named_children):
        if child.type == "spread_element":
            return None
        prop = child.child_by_field_name("key")
        if flow.node_text(prop) == key or _string_value(flow.source, prop) == key:
            return child.child_by_field_name("value")
    return None


def _literal(flow, node):
    node = flow.unwrap(node)
    return _string_value(flow.source, node) if node is not None else None


def _document_element(flow, node, depth=0):
    node = flow.unwrap(node)
    if node is None or depth >= 8:
        return False
    if node.type == "identifier":
        return _document_element(flow, _binding_value(flow, node), depth + 1)
    path = flow._expression_path(node)
    if path in {("document", "body"), ("document", "documentElement")}:
        return _stable_global(flow, path, node)
    if node.type != "call_expression":
        return False
    path = flow.callee_path(node)
    return (
        len(path) == 2
        and path[0] == "document"
        and path[1] in _DOM_QUERIES
        and _stable_global(flow, path, node)
    )


def _window_path(path):
    if path[:2] == ("globalThis", "window"):
        path = path[1:]
    return (
        bool(path)
        and path[0] in _WINDOW_ROOTS
        and all(member in _WINDOW_MEMBERS for member in path[1:])
    )


def _browser_window(flow, node, depth=0):
    node = flow.unwrap(node)
    if node is None or depth >= 8:
        return False
    path = flow._expression_path(node)
    if _window_path(path) and _stable_global(flow, path, node):
        return True
    receiver, member = _member(flow, node)
    if member == "contentWindow":
        return _document_element(flow, receiver)
    if node.type == "identifier":
        return _browser_window(flow, _binding_value(flow, node), depth + 1)
    return (
        node.type == "call_expression"
        and flow.callee_path(node) == ("window", "open")
        and _stable_global(flow, ("window", "open"), node)
    )


def _runtime_payload(flow, node, depth=0):
    node = flow.unwrap(node)
    if node is None or depth >= 8 or node.type in _LITERAL_TYPES:
        return False
    if node.type == "identifier":
        value = _binding_value(flow, node)
        return value is None or _runtime_payload(flow, value, depth + 1)
    if node.type in {"object", "array", "pair", "spread_element", "template_string"}:
        children = (
            (node.child_by_field_name("value"),)
            if node.type == "pair"
            else node.named_children
        )
        return any(_runtime_payload(flow, child, depth + 1) for child in children)
    return node.type in {
        "shorthand_property_identifier",
        "member_expression",
        "subscript_expression",
        "call_expression",
        "binary_expression",
        "template_substitution",
    }


def _data_from_message(flow, node, parameter, depth=0):
    node = flow.unwrap(node)
    if node is None or depth >= 12:
        return False
    owner, member = _member(flow, node)
    if member == "data" and flow.node_text(owner) == parameter:
        return True
    if member:
        return _data_from_message(flow, owner, parameter, depth + 1)
    if node.type == "identifier":
        return _data_from_message(
            flow, _binding_value(flow, node), parameter, depth + 1
        )
    if (
        node.type == "call_expression"
        and flow.callee_path(node) in {("JSON", "parse"), ("JSON", "stringify")}
        and _stable_global(flow, flow.callee_path(node), node)
    ):
        return any(
            _data_from_message(flow, arg, parameter, depth + 1)
            for arg in flow.call_arguments(node)
        )
    return False


def _action_payload(flow, node):
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        owner, member = _member(flow, left)
        path = flow._expression_path(left)
        if (
            member in {"innerHTML", "outerHTML"} and _document_element(flow, owner)
        ) or (
            path in {("window", "location"), ("window", "location", "href")}
            and _stable_global(flow, path, left)
        ):
            return node.child_by_field_name("right")
    if node.type != "call_expression":
        return None
    owner, member = _member(flow, node.child_by_field_name("function"))
    args = flow.call_arguments(node)
    path = flow.callee_path(node)
    if (
        member == "insertAdjacentHTML"
        and len(args) >= 2
        and _document_element(flow, owner)
    ):
        return args[1]
    if (
        args
        and path
        in {
            ("document", "write"),
            ("document", "writeln"),
            ("window", "location", "assign"),
            ("window", "location", "replace"),
        }
        and _stable_global(flow, path, node)
    ):
        return args[0]
    if len(args) == 2 and path in {("fetch",), ("window", "fetch")}:
        target = _literal(flow, args[0])
        method = _literal(flow, _property(flow, args[1], "method"))
        if (
            target
            and target.startswith("/")
            and not target.startswith(("//", "/\\"))
            and method in {"POST", "PUT", "PATCH", "DELETE"}
            and _stable_global(flow, path, node)
        ):
            return _property(flow, args[1], "body")
    return None


def _origin_member(flow, node, parameter, depth=0):
    node = flow.unwrap(node)
    if node is None or depth >= 8:
        return False
    owner, prop = _member(flow, node)
    if prop == "origin" and flow.node_text(owner) == parameter:
        return True
    value = _binding_value(flow, node)
    return _origin_member(flow, value, parameter, depth + 1)


def _origin_comparison(flow, condition, parameter):
    condition = flow.unwrap(condition)
    if condition is None or condition.type != "binary_expression":
        return ""
    operator = flow.node_text(condition.child_by_field_name("operator"))
    if operator not in {"===", "!==", "==", "!="}:
        return ""
    left = condition.child_by_field_name("left")
    right = condition.child_by_field_name("right")
    for origin, target in ((left, right), (right, left)):
        if not _origin_member(flow, origin, parameter):
            continue
        expected = _literal(flow, target) or _literal(
            flow, _binding_value(flow, target)
        )
        if expected and re.fullmatch(r"https?://[^/\s?#]+", expected):
            return operator
    return ""


def _protected_action(flow, node, parameter):
    """The action is skipped or lies on a proven exact-origin branch."""
    child = node
    while child.parent is not None:
        parent = child.parent
        if parent.type in _CALLBACKS:
            return False
        if parent.type == "if_statement":
            operator = _origin_comparison(
                flow, parent.child_by_field_name("condition"), parameter
            )
            if (
                operator in {"===", "=="}
                and child == parent.child_by_field_name("consequence")
            ) or (
                operator in {"!==", "!="}
                and child == parent.child_by_field_name("alternative")
            ):
                return True
        if parent.type == "statement_block":
            for earlier in parent.named_children:
                if earlier == child:
                    break
                if terminates(earlier):
                    return True
                if earlier.type == "if_statement":
                    operator = _origin_comparison(
                        flow, earlier.child_by_field_name("condition"), parameter
                    )
                    if operator in {"!==", "!="} and terminates(
                        earlier.child_by_field_name("consequence")
                    ):
                        return True
                    if operator in {"===", "=="} and terminates(
                        earlier.child_by_field_name("alternative")
                    ):
                        return True
        child = parent
    return False


def _message_parameter(flow, callback):
    params = callback.child_by_field_name("parameters")
    parameter = callback.child_by_field_name("parameter")
    if parameter is None and params is not None and params.named_children:
        first = params.named_children[0]
        parameter = first.child_by_field_name("pattern") or first
    return (
        flow.node_text(parameter)
        if parameter is not None and parameter.type == "identifier"
        else ""
    )


def _parameter_mutation(flow, node, name):
    if node.type == "variable_declarator":
        return flow.node_text(node.child_by_field_name("name")) == name
    if node.type in {"assignment_expression", "augmented_assignment_expression"}:
        path = flow._expression_path(node.child_by_field_name("left"))
        return path in {(name,), (name, "data"), (name, "origin")}
    return False


def _message_actions(flow, callback):
    callback = flow.unwrap(callback)
    if callback is None:
        return []
    if callback.type == "identifier":
        callback = _binding_value(flow, callback, hoisted=True)
    if callback is None or callback.type not in _CALLBACKS:
        return []
    param = _message_parameter(flow, callback)
    body = callback.child_by_field_name("body")
    if not param or body is None:
        return []
    actions = []
    for node in flow.iter_nodes(body, skip_nested_functions=True):
        if _parameter_mutation(flow, node, param):
            break
        if _data_from_message(
            flow, _action_payload(flow, node), param
        ) and not _protected_action(flow, node, param):
            actions.append(node)
    return actions


def find_browser_message_issues(flow):
    findings = {}

    def add(node, message):
        findings[node.start_byte] = {
            "rule_id": "SKY-D431",
            "severity": "HIGH",
            "message": message,
            "file": flow.file_path,
            "line": node.start_point[0] + 1,
            "col": node.start_point[1],
            "category": "danger",
        }

    for node in flow.iter_nodes():
        if not flow.analysis_complete:
            return []
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            receiver, name = _member(flow, left)
            if name == "onmessage" and _browser_window(flow, receiver):
                callback = node.child_by_field_name("right")
                for action in _message_actions(flow, callback):
                    add(
                        action,
                        "Window message data reaches a browser action without an origin check.",
                    )
        if node.type != "call_expression":
            continue
        receiver, name = _member(flow, node.child_by_field_name("function"))
        if name not in {"postMessage", "addEventListener"} or not _browser_window(
            flow, receiver
        ):
            continue
        if not _stable_global_method(flow, node, receiver, name):
            continue
        args = flow.call_arguments(node)
        if len(args) < 2:
            continue
        if name == "addEventListener" and _literal(flow, args[0]) == "message":
            for action in _message_actions(flow, args[1]):
                add(
                    action,
                    "Window message data reaches a browser action without an origin check.",
                )
        if name == "postMessage" and _runtime_payload(flow, args[0]):
            target = _property(flow, args[1], "targetOrigin")
            if _literal(flow, target if target is not None else args[1]) == "*":
                add(
                    node,
                    "Window postMessage sends runtime data with a wildcard target origin.",
                )
    return list(findings.values()) if flow.analysis_complete else []


def _stable_global_method(flow, call, receiver, name):
    path = flow._expression_path(receiver)
    if _window_path(path):
        return _stable_global(flow, (*path, name), call)
    if receiver is not None and receiver.type == "identifier":
        binding = flow.resolve_unique_binding(
            flow.node_text(receiver), call.start_byte, flow.scope_for_node(call).id
        )
        return (
            binding is not None
            and flow.is_binding_member_unmodified_allowing_escape(
                binding, name, call.start_byte, flow.scope_for_node(call).id
            )
        )
    return True
