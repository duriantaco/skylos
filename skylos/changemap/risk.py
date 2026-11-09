from __future__ import annotations

import math
import re
from pathlib import Path

from skylos.changemap.symbols import KIND_CLASS
from skylos.constants import is_test_path
from skylos.rules.quality.regression import (
    _AUTH_DECORATORS,
    _AUTH_DEPENDS,
    _CSRF_PROTECTIONS,
    _PERMISSION_DECORATORS,
    _RATE_LIMIT_DECORATORS,
    _VALIDATION_DECORATORS,
)

STATUS_ADDED = "added"
STATUS_MODIFIED = "modified"
STATUS_DELETED = "deleted"

_SECURITY_TOKENS = frozenset({
    "auth", "authenticate", "authenticated", "authentication", "authn", "authz",
    "authorize", "authorized", "authorization", "authorise", "authorised", "authorisation",
    "login", "permission", "permissions", "perm", "perms", "csrf", "sanitize", "sanitise",
    "escape", "validate", "validation", "verify", "verification", "acl", "rbac", "hmac",
})
_SECURITY_DECORATORS = _PERMISSION_DECORATORS | _RATE_LIMIT_DECORATORS | _VALIDATION_DECORATORS | _CSRF_PROTECTIONS
RISKY_CALL = re.compile(
    r"^(?:subprocess\.(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput)"
    r"|os\.(?:system|popen|exec\w*|spawn\w*|remove|unlink|rmdir|getenv)|os\.environ\.get"
    r"|eval|exec|requests\.(?:get|post|put|patch|delete|head|request|Session)"
    r"|httpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)|urllib\.request\.urlopen"
    r"|socket\.socket|pickle\.(?:load|loads|Unpickler)|marshal\.loads?|yaml\.load|shutil\.rmtree"
    r"|child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)"
    r"|fs(?:/promises)?\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)"
    r"|vm\.(?:runInNewContext|runInThisContext|runInContext)|Function|dangerouslySetInnerHTML)$"
)
_TOKEN_SPLIT = re.compile(r"[_\W]+|(?<=[a-z0-9])(?=[A-Z])")


def simple_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _tokens(name: str) -> set[str]:
    return {part.lower() for part in _TOKEN_SPLIT.split(name) if part}


def is_security_call(name: str) -> bool:
    simple = simple_name(name)
    if simple in _AUTH_DECORATORS or simple in _AUTH_DEPENDS:
        return True
    return bool(_tokens(simple) & _SECURITY_TOKENS)


_GUARD_VERBS = frozenset({"require", "requires", "check", "ensure", "verify", "authorize", "authenticate", "assert", "has", "can"})


_SETTING_TOKENS = _SECURITY_TOKENS | frozenset({
    "sandbox", "ssl", "tls", "secure", "insecure", "trust", "trusted", "allow", "allowed",
    "deny", "denied", "unsafe", "readonly", "privileged", "root", "admin", "public",
})


def is_security_setting(name: str) -> bool:
    return bool({part.lower() for part in _TOKEN_SPLIT.split(name) if part} & _SETTING_TOKENS)


def is_guard_call(name: str) -> bool:
    simple = simple_name(name)
    if simple in _AUTH_DECORATORS or simple in _AUTH_DEPENDS:
        return True
    parts = [part.lower() for part in _TOKEN_SPLIT.split(simple) if part]
    return bool(parts) and parts[0] in _GUARD_VERBS and bool(set(parts) & _SECURITY_TOKENS)


def is_security_decorator(name: str) -> bool:
    simple = simple_name(name)
    if simple in _AUTH_DECORATORS or simple in _SECURITY_DECORATORS or name in _SECURITY_DECORATORS:
        return True
    return bool(_tokens(simple) & _SECURITY_TOKENS)


def is_test_file(path: str) -> bool:
    name = Path(path).name
    return is_test_path(path) or name.startswith("test_") or name == "conftest.py"


def _security_reason(entry: dict) -> tuple[int, list[str]]:
    security_removed = entry["security_removed"]
    if not security_removed:
        return 0, []
    reasons = []
    for item in security_removed:
        if item.startswith("@"):
            reasons.append(f"removed decorator {item}")
        elif item.startswith("inline "):
            reasons.append(f"removed {item}")
        else:
            reasons.append(f"stopped calling {item}")
    return 6 + min(len(security_removed) - 1, 2), reasons


def _binding_reason(entry: dict) -> tuple[int, list[str]]:
    if not entry["binding_changed"]:
        return 0, []
    if entry["calls_retargeted"] and not entry["calls_added"] and not entry["calls_removed"]:
        return 1, ["code unchanged; calls functions that moved: " + ", ".join(entry["calls_retargeted"][:3])]
    return 3, ["code unchanged, but its calls now resolve to different functions"]


_VALIDATION_ERRORS = frozenset({
    "ValueError", "ValidationError", "PermissionError", "PermissionDenied", "BadRequest", "InvalidInput",
    "InvalidArgument", "UnauthorizedError", "ForbiddenError", "AuthenticationError", "AuthorizationError",
    "HTTPException", "HttpException",
})
_VALIDATION_TOKENS = frozenset({"invalid", "validation", "forbidden", "unauthorized", "denied", "permission", "auth"})


def is_validation_rejection(label: str) -> bool:
    name = label.split(" ", 1)[-1].split("(", 1)[0]
    if name in _VALIDATION_ERRORS:
        return True
    return bool({part.lower() for part in _TOKEN_SPLIT.split(name) if part} & _VALIDATION_TOKENS)


def _rejection_reason(entry: dict) -> tuple[int, list[str]]:
    removed = entry["rejections_removed"]
    return 2 * len(removed[:3]), [f"stopped rejecting: {label}" for label in removed]


def _values_reason(entry: dict) -> tuple[int, list[str]]:
    points = 0
    reasons = []
    for value in entry["values_changed"]:
        change = f"{value['name']} {value['before']} → {value['after']}"
        if value["security"]:
            points += 6
            reasons.append(f"security setting changed: {change}")
        else:
            points += 1
            reasons.append(f"class value changed: {change}; read by {len(value['used_by'])} method(s)")
    return points, reasons


def _move_reason(entry: dict) -> tuple[int, list[str]]:
    if entry["moved_from"]:
        return 0, [f"moved from {entry['moved_from'].split('::')[0]}, code unchanged"]
    if entry["moved_to"]:
        return 0, [f"moved to {entry['moved_to'].split('::')[0]}"]
    return 0, []


def _risky_reason(entry: dict) -> tuple[int, list[str]]:
    if entry["risky_calls_added"]:
        return 3, ["new " + ", ".join(entry["risky_calls_added"][:3])]
    return 0, []


def _signature_reason(entry: dict) -> tuple[int, list[str]]:
    change = entry["signature_change"]
    if change is None:
        return 0, []
    stale = entry["callers_not_updated"]
    if change == "breaking":
        if stale:
            return 4, [f"breaking signature change, {stale} caller(s) not in this change"]
        return 1, ["incompatible signature change, but no caller outside this change breaks"]
    if stale and entry["new_optional_params"]:
        names = ", ".join(entry["new_optional_params"])
        return 2, [f"new optional parameter {names}; {stale} caller(s) not in this change use the default"]
    return 1, ["signature changed (compatible)"]


def _guard_reason(entry: dict) -> tuple[int, list[str]]:
    if not entry["guards_replaced_by"]:
        return 0, []
    removed = ", ".join(entry["guards_removed"])
    replaced = ", ".join(entry["guards_replaced_by"])
    return 5, [f"access check changed: {removed} replaced by {replaced}"]


def _deleted_reason(entry: dict) -> tuple[int, list[str]]:
    if entry["status"] == STATUS_DELETED and entry["still_referenced_by"]:
        return 5, [f"deleted but still called by {len(entry['still_referenced_by'])}"]
    return 0, []


def _reach_reason(entry: dict) -> tuple[int, list[str]]:
    if entry["reach"]:
        return min(3, int(math.log2(entry["reach"] + 1))), [f"reached by {entry['reach']} caller(s)"]
    return 0, []


def _size_reason(entry: dict) -> tuple[int, list[str]]:
    if entry["lines_changed"] > 30:
        return 1, [f"{entry['lines_changed']} lines changed"]
    return 0, []


def _orphan_reason(entry: dict) -> tuple[int, list[str]]:
    orphan = (
        entry["status"] == STATUS_ADDED and not entry["callers"] and not entry["moved_from"]
        and entry["kind"] != KIND_CLASS and not entry["is_test"]
    )
    if orphan:
        return 0, ["no callers found"]
    return 0, []


_REASONS = (
    _security_reason, _guard_reason, _rejection_reason, _values_reason, _move_reason, _binding_reason, _risky_reason, _signature_reason,
    _deleted_reason, _reach_reason, _size_reason, _orphan_reason,
)


def _retarget_only(entry: dict) -> bool:
    return bool(entry["calls_retargeted"]) and not entry["calls_added"] and not entry["calls_removed"]


def _stale_contract(entry: dict) -> bool:
    if entry["callers_not_updated"] == 0:
        return False
    return entry["signature_change"] == "breaking" or bool(entry["new_optional_params"])


_ALARMS = (
    lambda e: bool(e["security_removed"] or e["guards_replaced_by"] or e["risky_calls_added"]),
    lambda e: e["status"] == STATUS_DELETED and bool(e["still_referenced_by"]),
    lambda e: e["binding_changed"] and not _retarget_only(e),
    _stale_contract,
    lambda e: any(value["security"] for value in e["values_changed"]),
    lambda e: any(is_validation_rejection(label) for label in e["rejections_removed"]),
)


def is_alarm(entry: dict) -> bool:
    if entry["is_test"] or entry["moved_from"] or entry["moved_to"]:
        return False
    return any(check(entry) for check in _ALARMS)


def reasons_and_risk(entry: dict) -> tuple[int, list[str]]:
    risk = 0
    reasons: list[str] = []
    for check in _REASONS:
        points, found = check(entry)
        risk += points
        reasons.extend(found)
    if entry["moved_from"] or entry["moved_to"]:
        risk = min(risk, 1)
    if entry["is_test"]:
        risk = -1
    return risk, reasons


