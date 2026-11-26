"""Bounded source evidence for Unix permission reviews on std::fs types."""

from __future__ import annotations

import re

READONLY_RULE = "SKY-D415"
MODE_RULE = "SKY-D416"
PERMISSIONS = "std::fs::Permissions"
METADATA = "std::fs::Metadata"
FILE = "std::fs::File"
OPTIONS = "std::fs::OpenOptions"
BUILDER = "std::fs::DirBuilder"
FS_TYPES = frozenset({PERMISSIONS, METADATA, FILE, OPTIONS, BUILDER})
UNIX_FS = "std::os::unix::fs::"
MODE_TRAITS = {
    (PERMISSIONS, "set_mode"): UNIX_FS + "PermissionsExt",
    (OPTIONS, "mode"): UNIX_FS + "OpenOptionsExt",
    (BUILDER, "mode"): UNIX_FS + "DirBuilderExt",
}
MODE_RECEIVERS = {
    trait + "::" + method: receiver for (receiver, method), trait in MODE_TRAITS.items()
}
FS_CALL_RESULTS = {
    "std::fs::metadata": "result_" + METADATA,
    "std::fs::symlink_metadata": "result_" + METADATA,
    FILE + "::open": "result_" + FILE,
    FILE + "::create": "result_" + FILE,
    FILE + "::create_new": "result_" + FILE,
    FILE + "::options": OPTIONS,
    OPTIONS + "::new": OPTIONS,
    BUILDER + "::new": BUILDER,
    METADATA + "::permissions": PERMISSIONS,
}


def trait_in_scope(state, trait):
    return any(
        state.get(name).api == trait
        for frame in reversed(state.frames)
        for name in frame
    )


def ambiguous_mode_literal(literal):
    if len(literal) > 64:
        return False
    number = literal.removesuffix("u32").replace("_", "")
    if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", number):
        return False
    return 7 < int(number, 16 if number.startswith("0x") else 10) <= 0xFFFFFFFF


def unix_cfg(tokens):
    """Evaluate only target facts forced on Unix. Other predicates are unknown."""
    if tokens == ("unix",) or tokens == ("target_family", "=", '"unix"'):
        return True
    if tokens == ("windows",):
        return False
    if len(tokens) == 3 and tokens[1] == "=":
        if tokens[0] == "target_family" and tokens[2] == '"windows"':
            return False
        if tokens[0] == "target_os" and tokens[2] in {'"windows"', '"none"', '"uefi"'}:
            return False
    if len(tokens) < 3 or tokens[1] != "(" or tokens[-1] != ")":
        return None
    name = tokens[0]
    if name not in {"all", "any", "not"}:
        return None
    if len(tokens) > 256:
        return None
    values = []
    depth = 0
    start = 2
    for offset in range(2, len(tokens) - 1):
        token = tokens[offset]
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif token == "," and depth == 0:
            values.append(unix_cfg(tokens[start:offset]))
            start = offset + 1
    if start < len(tokens) - 1:
        values.append(unix_cfg(tokens[start:-1]))
    if name == "not":
        if len(values) == 1 and values[0] is not None:
            return not values[0]
        return None
    decisive = name == "any"
    if decisive in values:
        return decisive
    return None if None in values else not decisive


def review_finding(rule, node, file_path, api, argument):
    if rule == READONLY_RULE:
        message = (
            "On Unix, set_readonly(false) adds write permission for the owner, "
            "group and everyone else. Review the intended mode before applying "
            "these permissions to a file."
        )
    else:
        message = (
            f"The Unix permission mode {argument} is written as a non-octal "
            "literal. Check the intended permission bits and express the mode "
            "in octal or with named flags."
        )
    return {
        "rule_id": rule,
        "category": "danger",
        "severity": "MEDIUM",
        "file": file_path,
        "line": node.start_point[0] + 1,
        "col": node.start_point[1],
        "message": message,
        "review_item": {"kind": "unix_permissions", "blocking": False},
        "metadata": {
            "security_evidence": {
                "evidence_kind": "rust_std_unix_permissions",
                "api": api,
                "argument": argument,
            }
        },
    }
