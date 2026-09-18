from __future__ import annotations

import re
from collections import Counter

from tree_sitter import Language, Node, Parser

try:
    import tree_sitter_cpp as tscpp
except ImportError:
    tscpp = None

from skylos.visitors.base import Definition

try:
    CPP_LANG: Language | None = (
        Language(tscpp.language()) if tscpp is not None else None
    )
except Exception:
    CPP_LANG = None

_SOURCE_EXTS = frozenset({".cpp", ".cc", ".cxx"})
_CLASS_CONTAINERS = frozenset(
    {"class_specifier", "struct_specifier", "union_specifier", "lambda_expression"}
)
_DECLARATOR_WRAPPERS = frozenset({"pointer_declarator", "reference_declarator"})
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


class CppScanError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        kind: str,
        line: int = 1,
        column: int = 1,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.lineno = line
        self.offset = column


def scan_symbols(
    file_path: str, source: str
) -> tuple[list[Definition], list[tuple[str, str]], list[dict]]:
    """Return conservative C++ function definitions and same-file references.

    C++ name lookup, macro expansion, and linking require a build configuration.
    Until one is available, only plainly file-local free functions are eligible
    for dead-code reporting. Ambiguous syntax is treated as live.
    """
    if CPP_LANG is None:
        raise CppScanError(
            "C++ parser grammar is unavailable; install tree-sitter-cpp",
            kind="cpp_parser_unavailable",
        )

    source_bytes = source.encode("utf-8")
    try:
        tree = Parser(CPP_LANG).parse(source_bytes)
    except Exception as exc:
        raise CppScanError(
            "C++ parser failed; dead-code analysis skipped",
            kind="cpp_parse_error",
        ) from exc
    root = tree.root_node
    if root.has_error:
        error_node = _first_error_node(root)
        point = error_node.start_point if error_node is not None else root.start_point
        raise CppScanError(
            "C++ parse error; dead-code analysis skipped",
            kind="cpp_parse_error",
            line=point.row + 1,
            column=point.column + 1,
        )

    nodes = list(_walk(root))
    function_names: Counter[str] = Counter()
    for node in nodes:
        if node.type == "function_declarator":
            declarator = node.child_by_field_name("declarator")
            if declarator is not None and declarator.type == "identifier":
                function_names[_text(declarator, source_bytes)] += 1

    macro_identifiers: set[str] = set()
    token_pasting = False
    for node in nodes:
        if not node.type.startswith("preproc_"):
            continue
        if node.parent is not None and node.parent.type.startswith("preproc_"):
            continue
        macro_text = _text(node, source_bytes)
        macro_identifiers.update(_IDENTIFIER_RE.findall(macro_text))
        token_pasting |= "##" in macro_text
    definitions: list[Definition] = []
    definition_name_offsets: set[int] = set()

    for node in nodes:
        if node.type != "function_definition":
            continue
        name_node = _function_name_node(node)
        if name_node is None:
            continue

        name = _text(name_node, source_bytes)
        definition_name_offsets.add(name_node.start_byte)
        definition = Definition(
            name,
            "function",
            file_path,
            name_node.start_point.row + 1,
        )

        candidate = _is_file_local_function(node, file_path, source_bytes)
        # A same-named overload or declaration cannot be resolved reliably by
        # simple-name references. Preprocessor token pasting can synthesize a
        # reference that is not present as an identifier in the syntax tree.
        if function_names[name] != 1 or token_pasting or not name.isascii():
            candidate = False
        elif candidate and name in macro_identifiers:
            candidate = False

        definition.is_exported = not candidate
        if definition.is_exported:
            definition.references = 1
        definitions.append(definition)

    # Counting all ordinary identifier uses (not just calls) protects address-
    # taken callbacks, registration tables, and similar indirect uses. String
    # and comment text cannot create identifier nodes in the C++ grammar.
    refs = [
        (_text(node, source_bytes), file_path)
        for node in nodes
        if node.type == "identifier" and node.start_byte not in definition_name_offsets
    ]
    return definitions, refs, []


def _walk(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _first_error_node(root: Node) -> Node | None:
    for node in _walk(root):
        if node.type == "ERROR" or node.is_missing:
            return node
    return None


def _text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", "ignore")


def _function_name_node(function: Node) -> Node | None:
    declarator = function.child_by_field_name("declarator")
    while declarator is not None and declarator.type in _DECLARATOR_WRAPPERS:
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None or declarator.type != "function_declarator":
        return None
    name = declarator.child_by_field_name("declarator")
    return name if name is not None and name.type == "identifier" else None


def _is_file_local_function(
    function: Node, file_path: str, source_bytes: bytes
) -> bool:
    if not file_path.lower().endswith(tuple(_SOURCE_EXTS)):
        return False

    is_anonymous_namespace = False
    parent = function.parent
    while parent is not None:
        if parent.type in _CLASS_CONTAINERS:
            return False
        if parent.type == "template_declaration" or parent.type.startswith("preproc_"):
            return False
        if (
            parent.type == "namespace_definition"
            and parent.child_by_field_name("name") is None
        ):
            is_anonymous_namespace = True
        parent = parent.parent

    storage = {
        _text(child, source_bytes)
        for child in function.named_children
        if child.type == "storage_class_specifier"
    }
    return ("static" in storage or is_anonymous_namespace) and "extern" not in storage
