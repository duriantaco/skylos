"""Unbounded socket input decoded into a growable Rust sequence."""

from .permissions import trait_in_scope

SOCKET = "std::net::TcpStream"
READ_BUFFERS = {
    "read_to_end": "rust_unbounded_socket_bytes",
    "read_to_string": "rust_unbounded_socket_text",
}
BUFFER_DECODERS = {
    "serde_json::from_slice": READ_BUFFERS["read_to_end"],
    "serde_json::from_str": READ_BUFFERS["read_to_string"],
}


def read_destination(receiver, name, args, state):
    if (
        receiver.kind != SOCKET
        or receiver.items
        or name not in READ_BUFFERS
        or len(args) != 1
    ):
        return None
    if not trait_in_scope(state, "std::io::Read"):
        return None
    target = args[0]
    value = target.child_by_field_name("value")
    if (
        target.type == "reference_expression"
        and value is not None
        and value.type == "identifier"
        and any(c.type == "mutable_specifier" for c in target.named_children)
    ):
        return value
    return None


def vector_result(node, state):
    callee = node.child_by_field_name("function")
    declared = None
    if callee is not None and callee.type == "generic_function":
        args = callee.child_by_field_name("type_arguments")
        if args is not None and args.named_children:
            declared = args.named_children[-1]
    if declared is None:
        parent = node.parent
        if parent is not None and parent.type == "try_expression":
            parent = parent.parent
        if parent is not None and parent.type == "let_declaration":
            declared = parent.child_by_field_name("type")
    if declared is None or declared.type != "generic_type":
        return False
    name = declared.child_by_field_name("type")
    return (
        name is not None
        and state.resolve(name.text.decode("utf-8", "replace")) == "std::vec::Vec"
    )


def immediately_after_read(node, source):
    # Only carry this proof to the next statement. It cannot cross a length
    # guard, replacement, conversion, or control-flow join.
    statement = node
    while statement.parent is not None and statement.parent.type != "block":
        if statement.type not in {
            "call_expression",
            "try_expression",
            "let_declaration",
            "expression_statement",
        }:
            return False
        statement = statement.parent
    previous = statement.prev_named_sibling
    while previous is not None and previous.type in {"line_comment", "block_comment"}:
        previous = previous.prev_named_sibling
    return previous is not None and source.network_read_statement == previous.start_byte


def target_statement_offset(node):
    while node.parent is not None and node.parent.type != "block":
        parent = node.parent
        if parent.type not in {
            "try_expression",
            "parenthesized_expression",
            "let_declaration",
            "expression_statement",
        }:
            # Reads in a branch or on the right of &&/|| may never occur.
            return None
        node = parent
    return node.start_byte


def unbounded_decode(api, node, args, state):
    if len(args) != 1 or args[0].items:
        return False
    source = args[0]
    if api == "serde_json::from_reader" and source.kind == SOCKET:
        return vector_result(node, state)
    if api in BUFFER_DECODERS and source.kind == BUFFER_DECODERS[api]:
        return vector_result(node, state) and immediately_after_read(node, source)
    return False
