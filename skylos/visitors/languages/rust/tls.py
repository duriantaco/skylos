"""Rust client options that disable certificate-chain or hostname verification."""

from dataclasses import replace

from ._security_bindings import UNKNOWN, Value

NATIVE = "native_tls::TlsConnectorBuilder"
CURL = frozenset({"curl::easy::Easy", "curl::easy::Easy2"})
_REQWEST_BUILDERS = {
    "reqwest_client_builder": "reqwest::ClientBuilder",
    "reqwest_blocking_client_builder": "reqwest::blocking::ClientBuilder",
}
HANDLE_TYPES = CURL | {NATIVE} | set(_REQWEST_BUILDERS.values())
_ACCEPT_INVALID = {
    "danger_accept_invalid_certs": "certificate-chain",
    "danger_accept_invalid_hostnames": "hostname",
}
_REQWEST_OPTIONS = {
    **_ACCEPT_INVALID,
    **{"tls_" + k: v for k, v in _ACCEPT_INVALID.items()},
}
_CURL_OPTIONS = {
    "ssl_verify_peer": "certificate-chain",
    "ssl_verify_host": "hostname",
}
OPTIONS = _REQWEST_OPTIONS.keys() | _CURL_OPTIONS.keys()
OPTION_NAMES = tuple(option.encode() for option in OPTIONS)
_CONSTRUCTORS = {
    ("native_tls::TlsConnector::builder", 0): NATIVE,
    ("curl::easy::Easy::new", 0): "curl::easy::Easy",
    ("curl::easy::Easy::default", 0): "curl::easy::Easy",
    ("curl::easy::Easy2::new", 1): "curl::easy::Easy2",
}
BOOLEAN = "rust_tls_boolean"
PARAMETER = "rust_tls_bool_parameter"
STDIN = "rust_stdin"
EMPTY_BUFFER = "rust_empty_string_buffer"
INPUT_LINE = "rust_stdin_line"
EITHER = Value(kind=BOOLEAN)
TRUE = Value(kind=BOOLEAN, literal="true")
FALSE = Value(kind=BOOLEAN, literal="false")


def constructor(api, arity):
    return _CONSTRUCTORS.get((api, arity))


def setting(kind, method):
    """Return the API, the affected check, and the Boolean that disables it."""
    if kind in _REQWEST_BUILDERS and method in _REQWEST_OPTIONS:
        return _REQWEST_BUILDERS[kind], _REQWEST_OPTIONS[method], TRUE
    if kind == NATIVE and method in _ACCEPT_INVALID:
        return kind, _ACCEPT_INVALID[method], TRUE
    if kind in CURL and method in _CURL_OPTIONS:
        return kind, _CURL_OPTIONS[method], FALSE
    return None


def literal(node):
    return TRUE if node.text == b"true" else FALSE


def inverted(value):
    if value.kind != BOOLEAN or value.items:
        return UNKNOWN
    if value.literal is None:
        return EITHER
    return FALSE if value.literal == "true" else TRUE


def direct_call_path(node):
    """Only propagate a caller's switch through ordinary straight-line code.

    A guard or a delayed callback can make the disabling caller and the
    setting mutually exclusive. Without a path proof, drop that witness.
    """
    while node.parent is not None:
        if node.type in {
            "async_block",
            "closure_expression",
            "if_expression",
            "match_expression",
            "while_expression",
            "for_expression",
            "loop_expression",
        }:
            return False
        if node.type == "function_item":
            return True
        if node.parent.type == "block":
            prior = node.prev_named_sibling
            while prior is not None:
                # An earlier guard clause might exclude this caller's value.
                if b"return" in prior.text and _contains_return(prior):
                    return False
                prior = prior.prev_named_sibling
        node = node.parent
    return False


def _contains_return(node):
    pending = [node]
    while pending:
        child = pending.pop()
        if child.type == "return_expression":
            return True
        if child.type not in {"function_item", "closure_expression", "async_block"}:
            pending.extend(child.named_children)
    return False


def caller_disables(parameter, disabled, calls):
    """Find an explicit disabling value passed to this exact local parameter."""
    pending = [parameter]
    visited = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        for value in calls.get(key, ()):
            if value.kind == BOOLEAN and value.literal in {disabled.literal, None}:
                return True
            if value.kind == PARAMETER:
                pending.extend(value.sources)
    return False


def stdin_buffer(receiver, method, arg_nodes, state):
    """An empty String can receive a Boolean from Stdin::read_line."""
    if (
        receiver.kind != STDIN
        or receiver.items
        or method != "read_line"
        or len(arg_nodes) != 1
    ):
        return None
    argument = arg_nodes[0]
    target = argument.child_by_field_name("value")
    if (
        argument.type != "reference_expression"
        or target is None
        or target.type != "identifier"
        or not any(c.type == "mutable_specifier" for c in argument.named_children)
    ):
        return None
    name = target.text.decode("utf-8", "replace")
    return name if state.get(name).kind == EMPTY_BUFFER else None


def input_method(receiver, receiver_node, name, args, state):
    if receiver.items:
        return None
    if receiver.kind in {INPUT_LINE, EMPTY_BUFFER}:
        if not args and name in {"trim", "trim_end", "trim_start", "as_str"}:
            return receiver
        if receiver_node.type == "identifier":
            # Other methods can change the buffer. clear() restores the one
            # starting state that proves read_line contributes the whole text.
            result_kind = EMPTY_BUFFER if name == "clear" and not args else None
            state.assign(
                receiver_node.text.decode("utf-8", "replace"),
                replace(receiver, kind=result_kind),
            )
    if receiver.kind == "result_" + BOOLEAN and name == "unwrap_or" and len(args) == 1:
        return EITHER
    if (
        receiver.kind in {"std::fs::Metadata", "path"}
        and not args
        and name in {"is_file", "is_dir", "is_symlink"}
    ):
        return EITHER
    if receiver.kind == "path" and not args:
        if name == "exists":
            return EITHER
        if name == "try_exists":
            return Value(kind="result_" + BOOLEAN)
    return None
