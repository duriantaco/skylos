from __future__ import annotations

from typing import Any

from skylos.rules.ai_defect.js_api_reference_model import (
    JsApiReference,
    NamespaceBinding,
    make_reference,
    node_line,
)
from skylos.visitors.languages.typescript.core import TypeScriptCore


def collect_namespace_member_references(
    core: TypeScriptCore,
    namespaces: dict[str, NamespaceBinding],
    references: list[JsApiReference],
) -> None:
    if not namespaces or core.root_node is None:
        return
    for node in core._iter_nodes(core.root_node):
        if node.type in {"member_expression", "subscript_expression"}:
            _collect_namespace_member(core, node, namespaces, references)


def _collect_namespace_member(
    core: TypeScriptCore,
    node: Any,
    namespaces: dict[str, NamespaceBinding],
    references: list[JsApiReference],
) -> None:
    object_node = node.child_by_field_name("object")
    if object_node is None or object_node.type != "identifier":
        return
    alias = core._get_text(object_node)
    binding = namespaces.get(alias)
    if binding is None or _namespace_is_shadowed(core, node, alias, binding):
        return
    if node.type == "subscript_expression":
        references.append(
            make_reference(
                binding.source,
                None,
                "computed_namespace_member",
                node,
                binding.source_line,
                type_only=binding.type_only,
                skip_reason="computed_namespace_member",
            )
        )
        return
    property_node = node.child_by_field_name("property")
    if property_node is None or property_node.type != "property_identifier":
        return
    references.append(
        make_reference(
            binding.source,
            core._get_text(property_node),
            binding.kind,
            property_node,
            binding.source_line,
            type_only=binding.type_only,
        )
    )


def _namespace_is_shadowed(
    core: TypeScriptCore,
    node: Any,
    alias: str,
    binding: NamespaceBinding,
) -> bool:
    child = node
    parent = node.parent
    while parent is not None:
        if _function_parameter_shadows(core, parent, alias):
            return True
        if _scope_statement_shadows(core, parent, child, alias, binding):
            return True
        child = parent
        parent = parent.parent
    return False


def _function_parameter_shadows(core: TypeScriptCore, parent: Any, alias: str) -> bool:
    function_types = {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
    if parent.type not in function_types:
        return False
    parameters = parent.child_by_field_name("parameters")
    parameter = parent.child_by_field_name("parameter")
    return alias in _binding_names(core, parameters or parameter)


def _scope_statement_shadows(
    core: TypeScriptCore,
    parent: Any,
    child: Any,
    alias: str,
    binding: NamespaceBinding,
) -> bool:
    if parent.type not in {"program", "statement_block"}:
        return False
    for sibling in parent.named_children:
        if sibling == child or node_line(sibling) == binding.source_line:
            continue
        if _statement_declares_name(core, sibling, alias):
            return True
    return False


def _statement_declares_name(core: TypeScriptCore, node: Any, alias: str) -> bool:
    if node.type == "import_statement":
        return False
    if node.type in {"function_declaration", "class_declaration"}:
        name_node = node.child_by_field_name("name")
        return name_node is not None and core._get_text(name_node) == alias
    if node.type in {"lexical_declaration", "variable_declaration"}:
        return _declaration_contains_name(core, node, alias)
    return False


def _declaration_contains_name(core: TypeScriptCore, node: Any, alias: str) -> bool:
    for declarator in node.named_children:
        if declarator.type != "variable_declarator":
            continue
        if alias in _binding_names(core, declarator.child_by_field_name("name")):
            return True
    return False


def _binding_names(core: TypeScriptCore, node: Any | None) -> set[str]:
    if node is None:
        return set()
    direct_types = {
        "identifier",
        "shorthand_property_identifier_pattern",
    }
    if node.type in direct_types:
        return {core._get_text(node)}
    names: set[str] = set()
    for child in node.named_children:
        names.update(_binding_names(core, child))
    return names
