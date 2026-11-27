"""Cookie identities and flags at cookie-jar additions."""

from dataclasses import replace

from ._security_bindings import UNKNOWN, Value

_MODULES = ("cookie", "actix_web::cookie", "axum_extra::extract::cookie")
JARS = {module + "::CookieJar" for module in _MODULES}
ACTIX = "actix_web::HttpResponseBuilder"
RECEIVERS = JARS | {ACTIX}
_COOKIES = {module + "::Cookie" for module in _MODULES}
_BUILDERS = {module + "::CookieBuilder" for module in _MODULES}
_SESSION_NAMES = {
    "session",
    "sessionid",
    "session_id",
    "sid",
    "access_token",
    "refresh_token",
    "auth_token",
    "jwt",
    "connect.sid",
}
COOKIE = "session_cookie"
BUILDER = "session_cookie_builder"
TYPES = {COOKIE, BUILDER}
_ADD = "SKY-D252"


def _literal(node, state, text):
    if node.type == "identifier":
        value = state.get(text(node))
        return value.literal if value.kind == "string" and not value.items else None
    if node.type == "string_literal" and text(node).startswith('"'):
        return text(node)[1:-1]
    return None


def constructor(api, args, state, text):
    owner, _, name = api.rpartition("::")
    if (
        owner == "actix_web::HttpResponse"
        and (
            name
            in {
                "Ok",
                "Created",
                "Accepted",
                "Found",
                "SeeOther",
                "TemporaryRedirect",
                "PermanentRedirect",
            }
            and not args
            or name == "build"
            and len(args) == 1
        )
    ) or (owner == ACTIX and name == "new" and len(args) == 1):
        return Value(kind=ACTIX)
    if owner in JARS and name in {"new", "default"} and not args:
        return Value(kind=owner)
    if owner in _COOKIES and name == "build":
        if len(args) == 1 and args[0].type == "tuple_expression":
            args = [
                n
                for n in args[0].named_children
                if n.type not in {"line_comment", "block_comment"}
            ]
        kind = BUILDER
    elif owner in _COOKIES and name == "new":
        kind = COOKIE
    elif owner in _BUILDERS and name == "new":
        kind = BUILDER
    else:
        return None
    if (
        len(args) != 2
        or (_literal(args[0], state, text) or "").lower() not in _SESSION_NAMES
    ):
        return UNKNOWN
    if _literal(args[1], state, text) == "":
        return UNKNOWN
    return Value(kind=kind, cookie_secure=False)


def method(node, receiver_node, receiver, name, args, arg_nodes, state, flow):
    if receiver.items:
        return None
    if receiver.kind in RECEIVERS:
        actix = receiver.kind == ACTIX
        uses_cookie = (name == "cookie" and actix and _finished_response(node)) or (
            name == "add"
            and not actix
            and (not receiver.kind.startswith("axum_extra::") or _returned(node))
        )
        if uses_cookie and len(args) == 1:
            cookie = args[0]
            if (
                cookie.kind in TYPES
                and not cookie.items
                and cookie.cookie_secure is False
            ):
                flow.configuration_finding(
                    _ADD,
                    node,
                    state,
                    "rust_cookie_jar",
                    "A session cookie lacks the Secure flag. Set secure(true) before adding it.",
                )
        return None
    if receiver.kind not in TYPES:
        return None
    if name == "clone" and not args:
        return receiver
    if receiver.kind == BUILDER:
        if name in {"build", "finish"} and not args:
            return replace(receiver, kind=COOKIE)
        if name == "secure" and len(args) == 1:
            return replace(receiver, cookie_secure=_bool_option(arg_nodes[0]))
        if name == "same_site" and len(args) == 1:
            mode = state.resolve(flow.text(arg_nodes[0]))
            if mode in {
                m + "::SameSite::" + s for m in _MODULES for s in ("Lax", "Strict")
            }:
                return receiver
        if name in {"domain", "http_only", "path"} and len(args) == 1:
            return receiver
        # SameSite=None and partitioned cookies may acquire Secure at serialization.
        return UNKNOWN
    if name == "into_owned" and not args:
        return receiver
    if receiver_node.type == "identifier":
        if name == "set_secure" and len(args) == 1:
            state.assign(
                flow.text(receiver_node),
                replace(receiver, cookie_secure=_bool_option(arg_nodes[0])),
            )
        elif name not in {
            "name",
            "value",
            "secure",
            "http_only",
            "set_http_only",
            "set_path",
            "set_domain",
        }:
            state.assign(flow.text(receiver_node), UNKNOWN)
    return UNKNOWN


def _bool_option(node):
    if node.type == "boolean_literal":
        return node.text == b"true"
    return None


def _finished_response(node):
    field = node.parent
    if field is None or field.type != "field_expression" or field.parent is None:
        return False
    method = field.child_by_field_name("field")
    return (
        field.parent.type == "call_expression"
        and method is not None
        and method.text in {b"finish", b"body", b"json", b"message_body", b"streaming"}
    )


def _returned(node):
    """An axum CookieJar is consumed; only a returned jar propagates its cookies."""
    while node.parent is not None:
        parent = node.parent
        if parent.type == "return_expression":
            return True
        if parent.type == "block":
            last = next(
                (
                    ch
                    for ch in reversed(parent.named_children)
                    if ch.type not in {"line_comment", "block_comment"}
                ),
                None,
            )
            if node != last:
                return False
            if parent.parent is not None and parent.parent.type == "function_item":
                return True
        elif parent.type not in {"tuple_expression", "parenthesized_expression"}:
            return False
        node = parent
    return False
