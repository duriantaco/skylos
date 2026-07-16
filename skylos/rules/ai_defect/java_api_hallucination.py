from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Sequence

from skylos.core.java_api_surface import (
    JavaParsedFile,
    JavaSurfaceIndex,
    build_java_surface_index,
    iter_nodes,
    node_text,
    parse_java_file,
    safe_java_files,
)
from skylos.rules.ai_defect.java_api_hallucination_resolution import (
    JavaScanState as _JavaScanState,
    JavaTypeBinding as _JavaTypeBinding,
    last_identifier as _last_identifier,
    nested_type_owner as _nested_type_owner,
    resolve_surface as _resolve_surface,
    safe_root as _safe_root,
    surface_ownership_reason as _surface_ownership_reason,
    type_name_is_shadowed as _type_name_is_shadowed,
    verify_surface_member as _verify_surface_member,
)
from skylos.rules.ai_defect.java_api_hallucination_reporting import (
    JAVA_API_CHECK_ID as JAVA_API_CHECK_ID,
    coverage_check as _coverage_check,
    deduplicate_findings as _deduplicate_findings,
    failed_java_api_check,
    not_applicable_check as _not_applicable_check,
    skipped_java_api_check as skipped_java_api_check,
)


def scan_java_local_api_hallucinations(
    project_root: str | Path,
    files: Iterable[str | Path],
    *,
    discover_workspace: bool = True,
    exclude_folders: Sequence[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _safe_root(project_root)
    if root is None:
        return [], failed_java_api_check("invalid_project_root")
    java_files = safe_java_files(root, files)
    if not java_files:
        return [], _not_applicable_check()

    index = build_java_surface_index(
        root,
        java_files,
        discover_workspace=discover_workspace,
        exclude_folders=exclude_folders,
    )
    state = _JavaScanState()
    for reason in index.global_reasons:
        if reason not in {"excluded_workspace_paths", "source_file_limit"}:
            continue
        state.references += 1
        state.skip(reason)
    for importer in java_files:
        _scan_java_importer(root, importer, index, state)

    findings = _deduplicate_findings(state.findings)
    return findings, _coverage_check(
        applicable_files=len(java_files),
        references=state.references,
        verified=state.verified,
        skipped=state.skipped,
        findings=len(findings),
        reasons=state.reasons,
    )


def _scan_java_importer(
    root: Path,
    importer: Path,
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    parsed, parse_reason = parse_java_file(importer, root=root)
    if parsed is None:
        state.references += 1
        state.skip(parse_reason or "parse_error")
        return
    bindings = _type_bindings(parsed, index, state)
    local_instances = _local_instance_names(parsed, bindings, index)
    for node in iter_nodes(parsed.root_node):
        if node.type == "method_invocation":
            _inspect_method_invocation(
                parsed, node, bindings, local_instances, index, state
            )
        elif node.type == "method_reference":
            _inspect_method_reference(
                parsed,
                node,
                bindings,
                local_instances,
                index,
                state,
            )
        elif node.type == "field_access":
            _inspect_field_access(parsed, node, bindings, index, state)


def _type_bindings(
    parsed: JavaParsedFile,
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> dict[str, _JavaTypeBinding]:
    bindings = _same_package_bindings(parsed, index)
    for node in parsed.root_node.named_children:
        if node.type != "import_declaration":
            continue
        _apply_import(parsed, node, index, bindings, state)
    return bindings


def _same_package_bindings(
    parsed: JavaParsedFile,
    index: JavaSurfaceIndex,
) -> dict[str, _JavaTypeBinding]:
    bindings = {}
    for qualified_name, surface in index.types.items():
        if surface.package_name != parsed.package_name:
            continue
        ownership_reason = _surface_ownership_reason(parsed, surface)
        if ownership_reason:
            continue
        bindings[surface.simple_name] = _JavaTypeBinding(
            surface.simple_name,
            qualified_name,
            surface,
        )
    return bindings


def _apply_import(
    parsed: JavaParsedFile,
    node: Any,
    index: JavaSurfaceIndex,
    bindings: dict[str, _JavaTypeBinding],
    state: _JavaScanState,
) -> None:
    import_text = " ".join(node_text(parsed, node).replace(";", "").split())
    if not import_text.startswith("import "):
        return
    value = import_text[7:]
    is_static = value.startswith("static ")
    if is_static:
        value = value[7:]
        _verify_static_import(parsed, node, value, index, state)
        return
    if value.endswith(".*"):
        package_name = value[:-2]
        if index.package_is_local(package_name):
            state.references += 1
            state.skip("wildcard_import")
        return
    _bind_explicit_type_import(parsed, value, index, bindings, state)


def _verify_static_import(
    parsed: JavaParsedFile,
    node: Any,
    value: str,
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    wildcard = value.endswith(".*")
    type_name = value[:-2] if wildcard else value.rsplit(".", 1)[0]
    surface = index.type_surface(type_name)
    if surface is None:
        package_name = type_name.rsplit(".", 1)[0] if "." in type_name else ""
        if index.package_is_local(package_name):
            state.references += 1
            _missing_or_incomplete_type(type_name, index, state)
        return
    state.references += 1
    ownership_reason = _surface_ownership_reason(parsed, surface)
    if ownership_reason:
        state.skip(ownership_reason)
        return
    if wildcard:
        state.skip("static_wildcard_import")
        return
    reason = index.proof_reason(surface)
    if reason:
        state.skip(f"surface_{reason}")
        return
    member_name = value.rsplit(".", 1)[-1]
    name_node = _last_identifier(node)
    _verify_surface_member(
        parsed,
        name_node or node,
        surface,
        member_name,
        expected_kind="member",
        state=state,
    )


def _bind_explicit_type_import(
    parsed: JavaParsedFile,
    qualified_name: str,
    index: JavaSurfaceIndex,
    bindings: dict[str, _JavaTypeBinding],
    state: _JavaScanState,
) -> None:
    surface = index.type_surface(qualified_name)
    package_name, _, simple_name = qualified_name.rpartition(".")
    if surface is None:
        owner_surface = _nested_type_owner(qualified_name, index)
        if owner_surface is not None:
            state.references += 1
            ownership_reason = _surface_ownership_reason(parsed, owner_surface)
            state.skip(ownership_reason or "nested_type_import_unsupported")
            return
        if index.package_is_local(package_name):
            state.references += 1
            _missing_or_incomplete_type(qualified_name, index, state)
        return
    ownership_reason = _surface_ownership_reason(parsed, surface)
    if ownership_reason:
        state.references += 1
        state.skip(ownership_reason)
        return
    binding = _JavaTypeBinding(simple_name, qualified_name, surface)
    existing = bindings.get(simple_name)
    if existing is not None and existing.qualified_name != qualified_name:
        state.references += 1
        state.skip("ambiguous_type_import")
        bindings.pop(simple_name, None)
        return
    bindings[simple_name] = binding


def _missing_or_incomplete_type(
    qualified_name: str,
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    reason = index.proof_reason()
    if qualified_name in index.ambiguous_types:
        reason = "ambiguous_type"
    if reason:
        state.skip(f"surface_{reason}")
        return
    state.skip("local_type_ownership_uncertain")


def _inspect_method_invocation(
    parsed: JavaParsedFile,
    node: Any,
    bindings: dict[str, _JavaTypeBinding],
    local_instances: set[str],
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    object_node = node.child_by_field_name("object")
    name_node = node.child_by_field_name("name")
    if object_node is None or name_node is None:
        return
    if _nested_local_type_qualifier(parsed, object_node, bindings, index):
        state.references += 1
        state.skip("nested_type_member_unsupported")
        return
    if object_node.type == "identifier":
        object_name = node_text(parsed, object_node)
        if object_name in local_instances:
            state.references += 1
            state.skip("instance_type_inference_unsupported")
            return
    _inspect_qualified_member(
        parsed, node, object_node, name_node, bindings, index, state
    )


def _inspect_method_reference(
    parsed: JavaParsedFile,
    node: Any,
    bindings: dict[str, _JavaTypeBinding],
    local_instances: set[str],
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    if len(node.named_children) < 2:
        return
    qualifier_node = node.named_children[0]
    member_node = node.named_children[-1]
    qualifier = node_text(parsed, qualifier_node)
    if qualifier_node.type == "identifier" and qualifier in local_instances:
        state.references += 1
        state.skip("instance_method_reference_unsupported")
        return
    surface, binding = _resolve_surface(parsed, qualifier, bindings, index)
    if surface is None:
        return
    state.references += 1
    ownership_reason = _surface_ownership_reason(parsed, surface)
    if ownership_reason:
        state.skip(ownership_reason)
        return
    if binding is not None and _type_name_is_shadowed(parsed, node, qualifier):
        state.skip("type_name_shadowed")
        return
    reason = index.proof_reason(surface)
    if reason:
        state.skip(f"surface_{reason}")
        return
    member_name = node_text(parsed, member_node)
    if member_name not in surface.members:
        state.skip("method_reference_unsupported")
        return
    _verify_surface_member(
        parsed,
        member_node,
        surface,
        member_name,
        expected_kind="method",
        state=state,
    )


def _inspect_field_access(
    parsed: JavaParsedFile,
    node: Any,
    bindings: dict[str, _JavaTypeBinding],
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    object_node = node.child_by_field_name("object")
    field_node = node.child_by_field_name("field")
    if object_node is None or field_node is None:
        return
    if _nested_local_type_qualifier(parsed, object_node, bindings, index):
        state.references += 1
        state.skip("nested_type_member_unsupported")
        return
    qualifier = node_text(parsed, object_node)
    surface, _binding = _resolve_surface(parsed, qualifier, bindings, index)
    if surface is not None:
        member_name = node_text(parsed, field_node)
        if any(
            member.kind == "type" for member in surface.members.get(member_name, ())
        ):
            state.references += 1
            state.skip("nested_type_member_unsupported")
            return
    _inspect_qualified_member(
        parsed,
        node,
        object_node,
        field_node,
        bindings,
        index,
        state,
        expected_kind="field",
    )


def _inspect_qualified_member(
    parsed: JavaParsedFile,
    owner: Any,
    qualifier_node: Any,
    member_node: Any,
    bindings: dict[str, _JavaTypeBinding],
    index: JavaSurfaceIndex,
    state: _JavaScanState,
    *,
    expected_kind: str = "method",
) -> None:
    qualifier = node_text(parsed, qualifier_node)
    surface, binding = _resolve_surface(parsed, qualifier, bindings, index)
    if surface is None:
        _inspect_missing_qualified_local_type(
            qualifier,
            index,
            state,
        )
        return
    state.references += 1
    ownership_reason = _surface_ownership_reason(parsed, surface)
    if ownership_reason:
        state.skip(ownership_reason)
        return
    if binding is not None and _type_name_is_shadowed(parsed, owner, qualifier):
        state.skip("type_name_shadowed")
        return
    reason = index.proof_reason(surface)
    if reason:
        state.skip(f"surface_{reason}")
        return
    member_name = node_text(parsed, member_node)
    _verify_surface_member(
        parsed,
        member_node,
        surface,
        member_name,
        expected_kind=expected_kind,
        state=state,
    )


def _inspect_missing_qualified_local_type(
    qualifier: str,
    index: JavaSurfaceIndex,
    state: _JavaScanState,
) -> None:
    package_name, separator, simple_name = qualifier.rpartition(".")
    if not separator or not simple_name[:1].isupper():
        return
    if not index.package_is_local(package_name):
        return
    state.references += 1
    _missing_or_incomplete_type(qualifier, index, state)


def _local_instance_names(
    parsed: JavaParsedFile,
    bindings: dict[str, _JavaTypeBinding],
    index: JavaSurfaceIndex,
) -> set[str]:
    names: set[str] = set()
    for node in iter_nodes(parsed.root_node):
        if node.type not in {
            "formal_parameter",
            "local_variable_declaration",
            "field_declaration",
        }:
            continue
        type_node = node.child_by_field_name("type")
        if type_node is None:
            continue
        type_name = node_text(parsed, type_node).split("<", 1)[0].rstrip("[]")
        if type_name == "var":
            names.update(_inferred_local_instance_names(parsed, node, bindings, index))
            continue
        surface, _binding = _resolve_surface(parsed, type_name, bindings, index)
        if surface is None or _surface_ownership_reason(parsed, surface):
            continue
        for name_node in node.children_by_field_name("name"):
            names.add(node_text(parsed, name_node))
        for child in node.named_children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    names.add(node_text(parsed, name_node))
    return names


def _inferred_local_instance_names(
    parsed: JavaParsedFile,
    declaration: Any,
    bindings: dict[str, _JavaTypeBinding],
    index: JavaSurfaceIndex,
) -> set[str]:
    names: set[str] = set()
    for child in declaration.named_children:
        if child.type != "variable_declarator":
            continue
        value_node = child.child_by_field_name("value")
        name_node = child.child_by_field_name("name")
        if value_node is None or name_node is None:
            continue
        if value_node.type != "object_creation_expression":
            continue
        type_node = value_node.child_by_field_name("type")
        if type_node is None:
            continue
        type_name = node_text(parsed, type_node)
        surface, _binding = _resolve_surface(parsed, type_name, bindings, index)
        if surface is None or _surface_ownership_reason(parsed, surface):
            continue
        names.add(node_text(parsed, name_node))
    return names


def _nested_local_type_qualifier(
    parsed: JavaParsedFile,
    node: Any,
    bindings: dict[str, _JavaTypeBinding],
    index: JavaSurfaceIndex,
) -> bool:
    qualifier = node_text(parsed, node)
    if "." not in qualifier:
        return False
    segments = qualifier.split(".")
    if segments[0] in bindings:
        return True
    for end in range(len(segments) - 1, 0, -1):
        surface, _binding = _resolve_surface(
            parsed,
            ".".join(segments[:end]),
            bindings,
            index,
        )
        if surface is not None and not _surface_ownership_reason(parsed, surface):
            return True
    return False
