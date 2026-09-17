"""Grammar-level tree-sitter helpers shared by every JS/TS analysis path."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, NamedTuple

from skylos.core.js_api_surface_utils import safe_name

_IDENTIFIER = "identifier"
DEFAULT_IMPORT = "default"
NAMESPACE_IMPORT = "*"


class ImportBinding(NamedTuple):
    """One local name an import clause introduces.

    Attributes:
        local: Name the importing module binds.
        imported: Exported name, or DEFAULT_IMPORT / NAMESPACE_IMPORT.
        type_only: Whether the specifier itself carries the `type` keyword.
        kind: One of "named", "default" or "namespace".
    """

    local: str
    imported: str
    type_only: bool
    kind: str


def node_text(source: bytes, node: Any | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def string_literal_value(source: bytes, node: Any) -> str | None:
    text = node_text(source, node).strip()
    if len(text) < 2:
        return None
    if text[0] not in {"'", '"'} or text[-1] != text[0]:
        return None
    return text[1:-1]


def member_chain(source: bytes, node: Any) -> list[str]:
    """Flatten `a.b.c` to its name parts, walking the spine without recursing."""
    parts: list[str] = []
    current: Any | None = node
    while current is not None and current.type == "member_expression":
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property")
        if object_node is None or property_node is None:
            current = None
            break
        parts.append(node_text(source, property_node))
        current = object_node
    if current is not None and current.type in {_IDENTIFIER, "property_identifier"}:
        parts.append(node_text(source, current))
    parts.reverse()
    return parts


def is_type_only(node: Any) -> bool:
    """Report whether an import statement or specifier is type-only."""
    return any(child.type == "type" for child in node.children)


def iter_import_clause_bindings(source: bytes, clause: Any) -> Iterator[ImportBinding]:
    """Yield every local binding an `import_clause` introduces."""
    for child in clause.named_children:
        if child.type == "named_imports":
            yield from _named_import_bindings(source, child)
            continue
        if child.type == _IDENTIFIER:
            name_node, imported, kind = child, DEFAULT_IMPORT, "default"
        elif child.type == "namespace_import":
            name_node = _namespace_alias(child)
            imported, kind = NAMESPACE_IMPORT, "namespace"
        else:
            continue
        name = safe_name(node_text(source, name_node))
        if name is not None:
            yield ImportBinding(name, imported, False, kind)


def _namespace_alias(binding: Any) -> Any | None:
    return next(
        (node for node in binding.named_children if node.type == _IDENTIFIER), None
    )


def _named_import_bindings(source: bytes, clause: Any) -> Iterator[ImportBinding]:
    for specifier in clause.named_children:
        if specifier.type != "import_specifier":
            continue
        name_node = specifier.child_by_field_name("name")
        imported_name = safe_name(
            string_literal_value(source, name_node)
            if name_node is not None and name_node.type == "string"
            else node_text(source, name_node)
        )
        local_name = safe_name(
            node_text(source, specifier.child_by_field_name("alias") or name_node)
        )
        if imported_name is not None and local_name is not None:
            yield ImportBinding(
                local_name, imported_name, is_type_only(specifier), "named"
            )
