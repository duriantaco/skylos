from __future__ import annotations

from skylos.changemap.ts_nodes import ARGUMENTS, CONSTRUCTOR, FUNCTION, MEMBER, NEW, PROPERTY


_DENIAL_THROWS = frozenset({
    "ForbiddenException", "UnauthorizedException", "ForbiddenError", "UnauthorizedError",
    "AuthenticationError", "AuthorizationError", "PermissionError", "PermissionDeniedError",
    "NotAuthorizedError", "AccessDeniedError",
})


_STATUS_EXCEPTIONS = frozenset({"HttpException", "HTTPException", "HttpError", "HTTPError", "ApiError"})


_STATUS_CALLEES = frozenset({"status", "sendStatus", "code", "json", "Response", "abort", "error", "NextResponse"})


_DENIAL_CODES = frozenset({"401", "403"})


_DENIAL_MEMBERS = {"FORBIDDEN": "403", "UNAUTHORIZED": "401"}


def _descendants(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def callee_simple(node, text) -> str:
    func = node.child_by_field_name(FUNCTION) or node.child_by_field_name(CONSTRUCTOR)
    if func is None:
        return ""
    if func.type != MEMBER:
        return text(func)
    prop = func.child_by_field_name(PROPERTY)
    if prop is None:
        return ""
    return text(prop)


def _member_code(child, text) -> str | None:
    if child.type != MEMBER:
        return None
    prop = child.child_by_field_name(PROPERTY)
    if prop is None:
        return None
    return _DENIAL_MEMBERS.get(text(prop))


def _denial_code(node, text) -> str | None:
    for child in _descendants(node):
        if child.type == "number" and text(child) in _DENIAL_CODES:
            return text(child)
        code = _member_code(child, text)
        if code:
            return code
    return None


def status_guard(node, text) -> str | None:
    callee = callee_simple(node, text)
    arguments = node.child_by_field_name(ARGUMENTS)
    if arguments is None or (callee not in _STATUS_CALLEES and callee not in _STATUS_EXCEPTIONS):
        return None
    code = _denial_code(arguments, text)
    if code:
        return f"inline {code} check"
    return None


def _message(created, text) -> str:
    arguments = created.child_by_field_name(ARGUMENTS)
    if arguments is None:
        return ""
    strings = [c for c in arguments.named_children if c.type in ("string", "template_string")]
    if not strings:
        return ""
    return text(strings[0]).strip("'\"`")[:60]


def throw_facts(node, text) -> tuple[str | None, str | None]:
    created = [c for c in node.named_children if c.type == NEW]
    if not created:
        return None, None
    name = callee_simple(created[0], text)
    rejection = f"throw {name}('{_message(created[0], text)}')"
    if name in _DENIAL_THROWS:
        return rejection, f"inline {name} check"
    return rejection, None
