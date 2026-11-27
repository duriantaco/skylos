"""Request-derived regex fragments and unbounded allocation capacities."""

SIZE = "rust_request_usize"
REGEX = {"regex::Regex::new", "regex::bytes::Regex::new", "fancy_regex::Regex::new"}
_BYTE_ELEMENTS = {
    b"u8",
    b"i8",
    b"u16",
    b"i16",
    b"u32",
    b"i32",
    b"u64",
    b"i64",
    b"usize",
    b"isize",
}


EMPTY_VEC = "rust_empty_vector"


def integer_vec(node, state):
    if node is None or node.type != "generic_type":
        return False
    owner = node.child_by_field_name("type")
    args = node.child_by_field_name("type_arguments")
    return (
        owner is not None
        and state.resolve(owner.text.decode("utf-8", "replace")) == "std::vec::Vec"
        and args is not None
        and len(args.named_children) == 1
        and args.named_children[0].text in _BYTE_ELEMENTS
        and not any(
            args.named_children[0].text.decode("ascii") in frame
            for frame in state.frames
        )
    )


def empty_constructor(value, state):
    if value is None or value.type != "call_expression":
        return False
    callee = value.child_by_field_name("function")
    args = value.child_by_field_name("arguments")
    return (
        callee is not None
        and args is not None
        and not args.named_children
        and state.resolve(callee.text.decode("utf-8", "replace"))
        == "std::vec::Vec::new"
    )


def unchecked_capacity(node, state):
    """Only the straight-line prefix of the function, before any possible size check."""
    arguments = node.child_by_field_name("arguments")
    values = (
        [
            c
            for c in arguments.named_children
            if c.type not in {"line_comment", "block_comment"}
        ]
        if arguments
        else []
    )
    if len(values) != 1:
        return False
    value = values[0]
    while value.type == "parenthesized_expression":
        children = [
            c
            for c in value.named_children
            if c.type not in {"line_comment", "block_comment"}
        ]
        if len(children) != 1:
            return False
        value = children[0]
    # A block or conditional expression in the argument can enforce its own cap.
    if value.type != "identifier":
        return False
    child = node
    while child.parent is not None:
        parent = child.parent
        if parent.type == "function_item":
            return True
        if parent.type == "block":
            for earlier in parent.named_children:
                if earlier == child:
                    break
                if earlier.type in {"line_comment", "block_comment", "use_declaration"}:
                    continue
                if earlier.type == "let_declaration":
                    value = earlier.child_by_field_name("value")
                    if value is not None and (
                        value.type == "identifier" or empty_constructor(value, state)
                    ):
                        continue
                return False
        elif parent.type not in {"let_declaration", "expression_statement"}:
            return False
        child = parent
    return False
