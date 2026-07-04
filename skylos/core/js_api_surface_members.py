from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.core.js_api_surface_utils import (
    relative_posix as _relative_posix,
    safe_name as _safe_name,
)


def _object_export_members(source: bytes, node: Any | None) -> list[tuple[str, str]]:
    if node is None or node.type != "object":
        return []
    names: list[tuple[str, str]] = []
    for child in node.named_children:
        if child.type == "shorthand_property_identifier":
            names.append((_node_text(source, child), "value"))
            continue
        if child.type == "method_definition":
            name_node = child.child_by_field_name("name")
            safe_name = _safe_name(_node_text(source, name_node)) if name_node else None
            if safe_name is not None:
                names.append((safe_name, "function"))
            continue
        if child.type != "pair":
            continue
        key_node = child.child_by_field_name("key")
        value_node = child.child_by_field_name("value")
        if key_node is None:
            named = list(child.named_children)
            key_node = named[0] if named else None
            value_node = named[1] if len(named) > 1 else None
        safe_name = _property_key_name(source, key_node)
        if safe_name is not None:
            names.append((safe_name, _value_kind(value_node)))
    return names
def _named_export_clause_pairs(
    source: bytes,
    export_node: Any,
) -> list[tuple[str, str, bool]]:
    names: list[tuple[str, str, bool]] = []
    for child in export_node.named_children:
        if child.type != "export_clause":
            continue
        for specifier in child.named_children:
            if specifier.type != "export_specifier":
                continue
            identifiers = [
                _node_text(source, item)
                for item in specifier.named_children
                if item.type in {"identifier", "property_identifier"}
            ]
            if not identifiers:
                continue
            safe_original = _safe_name(identifiers[0])
            safe_exported = _safe_name(identifiers[-1])
            if safe_original is not None and safe_exported is not None:
                specifier_text = _node_text(source, specifier).lstrip()
                names.append(
                    (
                        safe_original,
                        safe_exported,
                        specifier_text.startswith("type "),
                    )
                )
    return names
def _namespace_export_name(source: bytes, export_node: Any) -> str | None:
    for child in export_node.named_children:
        if child.type != "namespace_export":
            continue
        for item in child.named_children:
            if item.type == "identifier":
                return _safe_name(_node_text(source, item))
    return None
def _exported_function_signature_names(source: bytes, export_node: Any) -> list[str]:
    names: list[str] = []
    for child in export_node.named_children:
        if child.type == "function_signature":
            name = _safe_name(_node_text(source, child.child_by_field_name("name")))
            if name is not None:
                names.append(name)
            continue
        if child.type != "ambient_declaration":
            continue
        for nested in child.named_children:
            if nested.type != "function_signature":
                continue
            name = _safe_name(_node_text(source, nested.child_by_field_name("name")))
            if name is not None:
                names.append(name)
    return names
def _exported_direct_member_pairs(
    source: bytes,
    export_node: Any,
    text: str,
) -> list[tuple[str, str]]:
    if text.startswith("export default"):
        return []

    members: list[tuple[str, str]] = []
    for child in export_node.named_children:
        _collect_direct_member_pair(source, child, members)
    return members
def _collect_direct_member_pair(
    source: bytes,
    node: Any,
    members: list[tuple[str, str]],
) -> None:
    if node.type == "function_declaration":
        _append_member_pair(source, node.child_by_field_name("name"), "function", members)
        return
    if node.type in {"class_declaration", "abstract_class_declaration"}:
        _append_member_pair(source, node.child_by_field_name("name"), "class", members)
        return
    if node.type in {"interface_declaration", "type_alias_declaration"}:
        _append_member_pair(source, node.child_by_field_name("name"), "type", members)
        return
    if node.type == "enum_declaration":
        _append_member_pair(source, node.child_by_field_name("name"), "class", members)
        return
    if node.type not in {"lexical_declaration", "variable_declaration"}:
        return

    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        value_node = child.child_by_field_name("value")
        kind = "function" if _value_kind(value_node) == "function" else "variable"
        _append_member_pair(source, child.child_by_field_name("name"), kind, members)
def _append_member_pair(
    source: bytes,
    name_node: Any | None,
    kind: str,
    members: list[tuple[str, str]],
) -> None:
    for name in _binding_names(source, name_node):
        members.append((name, kind))
def _exported_ambient_member_pairs(
    source: bytes,
    export_node: Any,
) -> list[tuple[str, str]]:
    members: list[tuple[str, str]] = []
    for child in export_node.named_children:
        if child.type != "ambient_declaration":
            continue
        for nested in child.named_children:
            _collect_declared_member_pairs(source, nested, members)
    return members
def _collect_declared_member_pairs(
    source: bytes,
    node: Any,
    members: list[tuple[str, str]],
) -> None:
    if node.type == "function_signature":
        name = _safe_name(_node_text(source, node.child_by_field_name("name")))
        if name is not None:
            members.append((name, "function"))
        return
    if node.type in {"class_declaration", "abstract_class_declaration"}:
        name = _safe_name(_node_text(source, node.child_by_field_name("name")))
        if name is not None:
            members.append((name, "class"))
        return
    if node.type in {"interface_declaration", "type_alias_declaration"}:
        name = _safe_name(_node_text(source, node.child_by_field_name("name")))
        if name is not None:
            members.append((name, "type"))
        return
    if node.type == "enum_declaration":
        name = _safe_name(_node_text(source, node.child_by_field_name("name")))
        if name is not None:
            members.append((name, "class"))
        return
    if node.type not in {"lexical_declaration", "variable_declaration"}:
        return
    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        for name in _binding_names(source, child.child_by_field_name("name")):
            members.append((name, "variable"))
def _exported_namespace_names(source: bytes, export_node: Any) -> list[str]:
    names: list[str] = []
    for child in _iter_nodes(export_node):
        if child.type != "internal_module":
            continue
        for nested in child.named_children:
            if nested.type != "identifier":
                continue
            name = _safe_name(_node_text(source, nested))
            if name is not None:
                names.append(name)
            break
        break
    return names
def _export_statement_is_type_only(text: str) -> bool:
    return text.startswith("export type ")
def _export_statement_is_star_export(text: str) -> bool:
    return text.startswith("export *") or text.startswith("export type *")
def _export_source_literal(source: bytes, export_node: Any) -> str | None:
    for child in export_node.named_children:
        if child.type == "string":
            return _string_literal_value(source, child)
    return None
def _add_export_member(
    root: Path,
    members: dict[str, dict[str, Any]],
    name: str,
    kind: str,
    file_path: Path,
    line: int,
    *,
    source: str,
    target: str | None = None,
) -> None:
    safe_name = _safe_name(name)
    if safe_name is None:
        return
    existing = members.get(safe_name)
    if isinstance(existing, dict):
        existing_source = existing.get("source")
        if existing_source == "star_reexport" and source in {
            "named_export",
            "named_reexport",
            "namespace_reexport",
            "static_export",
        }:
            pass
        elif existing_source != "named_export":
            return

    member: dict[str, Any] = {
        "kind": kind,
        "source": source,
        "source_path": _relative_posix(root, file_path),
        "line": line,
    }
    if target:
        member["target"] = target
    members[safe_name] = member
def _module_scope_exportable_bindings(source: bytes, root_node: Any | None) -> dict[str, str]:
    bindings: dict[str, str] = {}
    if root_node is None:
        return bindings
    for child in root_node.named_children:
        _collect_module_scope_bindings(source, child, bindings)
    return bindings
def _collect_module_scope_bindings(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> None:
    if node.type == "export_statement":
        _collect_export_child_bindings(source, node, bindings)
        return
    if _collect_declaration_binding(source, node, bindings):
        return
    if node.type in {"ambient_declaration", "expression_statement"}:
        _collect_nested_module_bindings(source, node, bindings)
        return
    if node.type == "internal_module":
        _collect_internal_module_binding(source, node, bindings)
        return
    if node.type in {"lexical_declaration", "variable_declaration"}:
        _collect_variable_declarator_bindings(source, node, bindings)


def _collect_export_child_bindings(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> None:
    for child in node.named_children:
        if child.type in {"export_clause", "namespace_export", "string"}:
            continue
        _collect_module_scope_bindings(source, child, bindings)


def _collect_declaration_binding(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> bool:
    kind = _declaration_binding_kind(node)
    if kind is None:
        return False
    _add_module_binding(source, node.child_by_field_name("name"), kind, bindings)
    return True


def _declaration_binding_kind(node: Any) -> str | None:
    if node.type in {"function_declaration", "function_signature"}:
        return "function"
    if node.type in {"class_declaration", "abstract_class_declaration"}:
        return "class"
    if node.type in {"interface_declaration", "type_alias_declaration"}:
        return "type"
    if node.type == "enum_declaration":
        return "class"
    return None


def _collect_nested_module_bindings(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> None:
    for child in node.named_children:
        if node.type == "expression_statement" and child.type != "internal_module":
            continue
        _collect_module_scope_bindings(source, child, bindings)


def _collect_internal_module_binding(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> None:
    for child in node.named_children:
        if child.type != "identifier":
            continue
        _add_module_binding(source, child, "namespace", bindings)
        break


def _collect_variable_declarator_bindings(
    source: bytes,
    node: Any,
    bindings: dict[str, str],
) -> None:
    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        name_node = child.child_by_field_name("name")
        value_node = child.child_by_field_name("value")
        kind = "function" if _value_kind(value_node) == "function" else "variable"
        _add_module_bindings(source, name_node, kind, bindings)
def _add_module_binding(
    source: bytes,
    name_node: Any | None,
    kind: str,
    bindings: dict[str, str],
) -> None:
    safe_name = _safe_name(_node_text(source, name_node)) if name_node else None
    if safe_name is not None:
        bindings[safe_name] = kind
def _add_module_bindings(
    source: bytes,
    name_node: Any | None,
    kind: str,
    bindings: dict[str, str],
) -> None:
    for name in _binding_names(source, name_node):
        bindings[name] = kind
def _binding_names(source: bytes, node: Any | None) -> list[str]:
    if node is None:
        return []
    if node.type in {
        "identifier",
        "type_identifier",
        "shorthand_property_identifier_pattern",
    }:
        name = _safe_name(_node_text(source, node))
        return [name] if name is not None else []
    if node.type in {"object_pattern", "array_pattern"}:
        names: list[str] = []
        for child in node.named_children:
            names.extend(_binding_names(source, child))
        return names
    if node.type == "pair_pattern":
        named = list(node.named_children)
        if len(named) < 2:
            return []
        return _binding_names(source, named[-1])
    if node.type == "object_assignment_pattern":
        named = list(node.named_children)
        if not named:
            return []
        return _binding_names(source, named[0])
    if node.type in {"rest_pattern", "assignment_pattern"}:
        named = list(node.named_children)
        if not named:
            return []
        return _binding_names(source, named[0])
    return []
def _default_export_kind(node: Any) -> str:
    for child in node.named_children:
        if child.type in {"function_declaration", "function_expression", "arrow_function"}:
            return "function"
        if child.type in {"class_declaration", "abstract_class_declaration"}:
            return "class"
        if child.type in {"interface_declaration", "type_alias_declaration"}:
            return "type"
    return "value"
def _value_kind(node: Any | None) -> str:
    if node is None:
        return "value"
    if node.type in {"function", "function_expression", "arrow_function"}:
        return "function"
    if node.type in {"class", "class_declaration", "class_expression"}:
        return "class"
    return "value"
def _member_chain(source: bytes, node: Any) -> list[str]:
    if node.type in {"identifier", "property_identifier"}:
        return [_node_text(source, node)]
    if node.type != "member_expression":
        return []

    object_node = node.child_by_field_name("object")
    property_node = node.child_by_field_name("property")
    if object_node is None or property_node is None:
        return []
    return _member_chain(source, object_node) + [_node_text(source, property_node)]
def _property_key_name(source: bytes, node: Any | None) -> str | None:
    if node is None:
        return None
    if node.type in {"property_identifier", "identifier"}:
        return _safe_name(_node_text(source, node))
    if node.type == "string":
        return _safe_name(_string_literal_value(source, node))
    return None
def _string_literal_value(source: bytes, node: Any) -> str | None:
    text = _node_text(source, node).strip()
    if len(text) < 2:
        return None
    if text[0] not in {"'", '"'} or text[-1] != text[0]:
        return None
    return text[1:-1]
def _iter_nodes(node: Any):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))
def _node_text(source: bytes, node: Any | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")
def _node_line(node: Any) -> int:
    return int(node.start_point[0]) + 1
