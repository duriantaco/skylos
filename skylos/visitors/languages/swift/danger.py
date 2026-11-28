"""Credential writes to the Foundation preferences store."""

import re

from .core import descendants

_SENSITIVE_NAMES = frozenset(
    {
        "accesstoken",
        "accountpassword",
        "apikey",
        "authpassword",
        "authtoken",
        "clientsecret",
        "credential",
        "credentials",
        "encryptionkey",
        "idtoken",
        "passcode",
        "passphrase",
        "password",
        "privatekey",
        "refreshtoken",
        "secretkey",
        "secrettoken",
        "sessiontoken",
        "signingkey",
        "symmetrickey",
    }
)
_SAFE_CONSTANTS = frozenset({"nil", "true", "false", '""'})


def _navigation(core, node):
    if node is None or node.type != "navigation_expression":
        return None, ""
    suffix = node.child_by_field_name("suffix")
    member = suffix.child_by_field_name("suffix") if suffix is not None else None
    return node.child_by_field_name("target"), core.name(member)


def _unqualified(core, node, expected):
    return (
        node is not None
        and node.type == "simple_identifier"
        and core.name(node) == expected
        and expected not in core.types
        and not core._name_shadowed(
            expected, core.node_scopes.get(node.id), node.start_byte
        )
    )


def _foundation_type(core, node):
    if _unqualified(core, node, "UserDefaults"):
        return True
    qualifier, name = _navigation(core, node)
    return name == "UserDefaults" and _unqualified(core, qualifier, "Foundation")


def _unwrapped(node):
    while node is not None and node.type == "postfix_expression":
        operation = node.child_by_field_name("operation")
        if operation is None or operation.type != "bang":
            break
        node = node.child_by_field_name("target")
    return node


def _defaults_receiver(core, node, seen=frozenset()):
    node = _unwrapped(node)
    if node is None or len(seen) >= 12:
        return False
    owner, member = _navigation(core, node)
    if member == "standard":
        return _foundation_type(core, owner)
    if node.type == "call_expression" and node.named_children:
        return _foundation_type(core, node.named_children[0])
    if node.type != "simple_identifier":
        return False
    binding = core._binding(node)
    return bool(
        binding is not None
        and binding.constant
        and not binding.writes
        and binding not in seen
        and _defaults_receiver(core, binding.value, seen | {binding})
    )


def _static_key(core, node, seen=frozenset()):
    if node is None or len(seen) >= 12:
        return ""
    if node.type == "line_string_literal" and all(
        child.type == "line_str_text" for child in node.named_children
    ):
        return core.text(node)[1:-1]
    if node.type == "simple_identifier":
        binding = core._binding(node)
        if binding and binding.constant and not binding.writes and binding not in seen:
            return _static_key(core, binding.value, seen | {binding})
    return ""


def _sensitive_name(name):
    parts = [re.sub(r"[_-]", "", part).casefold() for part in name.split(".") if part]
    return bool(parts and parts[-1] in _SENSITIVE_NAMES)


def scan_foundation_storage(core):
    if core.root_node is None or core.root_node.has_error:
        return []
    if b"UserDefaults" not in core.source or not any(
        item["source"] in {"Foundation", "class Foundation.UserDefaults"}
        for item in core.raw_imports
    ):
        return []
    findings = []
    for node in descendants(core.root_node):
        if node.type != "call_expression" or not node.named_children:
            continue
        receiver, method = _navigation(core, node.named_children[0])
        if method not in {"set", "setValue"}:
            continue
        args = core._arguments(node)
        if len(args) != 2 or core.name(args[1].child_by_field_name("name")) != "forKey":
            continue
        value = args[0].child_by_field_name("value")
        key = args[1].child_by_field_name("value")
        if value is None or core.text(value) in _SAFE_CONSTANTS:
            continue
        if not _defaults_receiver(core, receiver):
            continue
        if not (
            _sensitive_name(_static_key(core, key)) or _sensitive_name(core.text(value))
        ):
            continue
        findings.append(
            {
                "rule_id": "SKY-D434",
                "severity": "HIGH",
                "message": "Sensitive data is stored in Foundation UserDefaults.",
                "file": core.file_path,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                "category": "danger",
            }
        )
    return findings
