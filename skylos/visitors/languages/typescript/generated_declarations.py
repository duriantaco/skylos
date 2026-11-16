"""Declaration-only generated output, without trusting a marker on runtime code."""

import re


_GENERATOR_MARKER = re.compile(r"\bgenerated\s+by\s+[^\r\n]+", re.IGNORECASE)
_DECLARATIONS = frozenset({
    "ambient_declaration", "class_declaration", "abstract_class_declaration",
    "interface_declaration", "type_alias_declaration", "enum_declaration",
    "function_signature", "import_statement", "import_alias", "empty_statement",
})


def is_generated_declaration_output(root_node, source, file_path):
    """Scope lint-disable advice out of generated type surfaces only.

    A header alone never exempts executable source. Even a declaration suffix
    declines this proof when the AST contains an implementation or initializer.
    Other public-type and security checks keep their existing behavior.
    """
    if not str(file_path).lower().endswith((".d.ts", ".d.mts", ".d.cts")):
        return False
    if root_node is None or root_node.has_error:
        return False
    header = []
    for child in root_node.named_children:
        if child.type != "comment":
            break
        header.append(source[child.start_byte:child.end_byte].decode("utf-8", errors="replace"))
    if not _GENERATOR_MARKER.search("\n".join(header)):
        return False
    for child in root_node.named_children:
        if child.type == "comment" or child.type in _DECLARATIONS:
            continue
        if child.type != "export_statement":
            return False
        if any(part.type not in _DECLARATIONS | {"export_clause", "namespace_export", "string", "comment"} for part in child.named_children):
            return False
    pending = [root_node]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > 100_000:
            return False
        pending.extend(node.named_children)
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression", "new_expression", "await_expression", "class_static_block", "throw_statement"}:
            return False
        if node.type in {"variable_declarator", "public_field_definition"} and node.child_by_field_name("value") is not None:
            return False
        if node.type in {"function_declaration", "generator_function_declaration", "method_definition", "arrow_function", "function_expression"}:
            return False
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            values = list(arguments.named_children) if arguments is not None else []
            if function is None or function.type != "import" or len(values) != 1 or values[0].type != "string":
                return False
    return True
