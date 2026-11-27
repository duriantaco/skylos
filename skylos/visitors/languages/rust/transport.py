"""Cleartext destinations carrying HTTP authentication in reqwest."""

from ipaddress import ip_address
from urllib.parse import urlsplit

from . import sensitive
from ._security_bindings import UNKNOWN

HTTP_ALLOWED = "allows_http"
CLEARTEXT = "cleartext_url"
AUTHENTICATED = "cleartext_with_auth"


def cleartext_url(literal):
    if not literal or not literal.lower().startswith("http://"):
        return False
    # Rust string escapes and URL backslashes need a different interpretation.
    if "\\" in literal or any(ord(c) <= 32 for c in literal):
        return False
    try:
        parts = urlsplit(literal)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # Validate the port as reqwest's URL parser would.
    except ValueError:
        return False
    if not host or host.endswith((".local", ".localhost")):
        return False
    try:
        addr = ip_address(host)
    except ValueError:
        # A numeric last label can be a noncanonical IPv4 loopback address.
        labels = host.split(".")
        return (
            len(labels) > 1
            and labels[-1].isalpha()
            and all(
                part.isascii()
                and part
                and part.replace("-", "").isalnum()
                and not part.startswith("-")
                and not part.endswith("-")
                for part in labels
            )
        )
    addr = getattr(addr, "ipv4_mapped", None) or addr
    return not (addr.is_loopback or addr.is_unspecified or addr.is_link_local)


def carries_auth(name, args):
    if name == "bearer_auth" and len(args) == 1:
        return args[0].literal != ""
    if name == "basic_auth" and len(args) == 2:
        return args[0].literal != ""
    if name == "header" and len(args) == 2:
        key, value = args
        return value.literal != "" and (
            (key.literal or "").lower() == "authorization"
            or key.api
            in {"reqwest::header::AUTHORIZATION", "http::header::AUTHORIZATION"}
        )
    return False


def exposed_url(parts):
    """An exposed value in a fixed origin's path or query is sent to the server."""
    if not parts or not any(
        v.kind == sensitive.EXPOSED and not v.items for _, v in parts
    ):
        return False
    prefix = parts[0][0]
    if not prefix.lower().startswith(("https://", "http://")) or "\\" in prefix:
        return False
    try:
        parsed = urlsplit(prefix)
        if not parsed.hostname or not (parsed.path.startswith("/") or "?" in prefix):
            return False
    except ValueError:
        return False
    for literal, value in parts:
        if "#" in literal:
            return False
        if value.kind == sensitive.EXPOSED and not value.items:
            return True
    return False


def query_pairs(node, state, text):
    if node.type == "reference_expression":
        node = node.child_by_field_name("value")
    if node is None or node.type != "array_expression":
        return False
    for pair in node.named_children:
        if pair.type != "tuple_expression":
            continue
        fields = [
            n
            for n in pair.named_children
            if n.type not in {"line_comment", "block_comment"}
        ]
        if len(fields) != 2 or fields[0].type != "string_literal":
            continue
        field = fields[1]
        value = UNKNOWN
        if field.type == "identifier":
            value = state.get(text(field))
        elif field.type == "call_expression":
            member = field.child_by_field_name("function")
            args = field.child_by_field_name("arguments")
            if (
                member is not None
                and member.type == "field_expression"
                and args is not None
                and not args.named_children
            ):
                owner = member.child_by_field_name("value")
                if owner is not None and owner.type == "identifier":
                    name = text(member.child_by_field_name("field"))
                    value = (
                        sensitive.method_result(state.get(text(owner)), name, [], state)
                        or UNKNOWN
                    )
        if value.kind == sensitive.EXPOSED and not value.items:
            return True
    return False
