from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.core.java_api_surface import (
    JavaMemberSurface,
    JavaParsedFile,
    JavaSurfaceIndex,
    JavaTypeSurface,
    iter_nodes,
    java_module_roots_compatible,
    java_source_sets_compatible,
    node_text,
)
from skylos.rules.ai_defect.java_api_hallucination_reporting import (
    inaccessible_java_member_finding,
    invalid_java_member_kind_finding,
    missing_java_member_finding,
)


@dataclass(frozen=True)
class JavaTypeBinding:
    simple_name: str
    qualified_name: str
    surface: JavaTypeSurface


@dataclass
class JavaScanState:
    reasons: Counter[str] = field(default_factory=Counter)
    findings: list[dict[str, Any]] = field(default_factory=list)
    references: int = 0
    verified: int = 0
    skipped: int = 0

    def skip(self, reason: str) -> None:
        self.reasons[reason] += 1
        self.skipped += 1


def resolve_surface(
    parsed: JavaParsedFile,
    qualifier: str,
    bindings: dict[str, JavaTypeBinding],
    index: JavaSurfaceIndex,
) -> tuple[JavaTypeSurface | None, JavaTypeBinding | None]:
    binding = bindings.get(qualifier)
    if binding is not None:
        return binding.surface, binding
    surface = index.type_surface(qualifier)
    if surface is None and "." not in qualifier and parsed.package_name:
        surface = index.type_surface(f"{parsed.package_name}.{qualifier}")
    return surface, None


def surface_ownership_reason(
    parsed: JavaParsedFile,
    surface: JavaTypeSurface,
) -> str | None:
    if not java_source_sets_compatible(parsed.source_set, surface.source_set):
        return "source_set_ownership_uncertain"
    if not java_module_roots_compatible(parsed.module_root, surface.module_root):
        return "module_ownership_uncertain"
    return None


def nested_type_owner(
    qualified_name: str,
    index: JavaSurfaceIndex,
) -> JavaTypeSurface | None:
    segments = qualified_name.split(".")
    for end in range(len(segments) - 1, 0, -1):
        surface = index.type_surface(".".join(segments[:end]))
        if surface is not None:
            return surface
    return None


def verify_surface_member(
    parsed: JavaParsedFile,
    member_node: Any,
    surface: JavaTypeSurface,
    member_name: str,
    *,
    expected_kind: str,
    state: JavaScanState,
) -> None:
    members = list(surface.members.get(member_name, ()))
    if not members:
        state.findings.append(
            missing_java_member_finding(
                parsed,
                member_node,
                surface,
                member_name,
                expected_kind=expected_kind,
            )
        )
        return
    kind_matches = (
        members
        if expected_kind == "member"
        else [member for member in members if member.kind == expected_kind]
    )
    if not kind_matches:
        state.findings.append(
            invalid_java_member_kind_finding(
                parsed,
                member_node,
                surface,
                member_name,
                expected_kind=expected_kind,
                actual_kinds=[member.kind for member in members],
            )
        )
        return
    access_states = [
        _member_access_state(parsed, surface, member) for member in kind_matches
    ]
    if "accessible" in access_states:
        state.verified += 1
        return
    if "uncertain" in access_states:
        state.skip("member_visibility_uncertain")
        return
    state.findings.append(
        inaccessible_java_member_finding(
            parsed,
            member_node,
            surface,
            member_name,
            visibility=kind_matches[0].visibility,
        )
    )


def type_name_is_shadowed(parsed: JavaParsedFile, owner: Any, name: str) -> bool:
    function = _enclosing_method(owner)
    if function is None:
        return False
    for node in iter_nodes(function):
        if node.start_byte >= owner.start_byte or node.type != "identifier":
            continue
        if node_text(parsed, node) != name:
            continue
        parent = node.parent
        if parent is not None and parent.type in {
            "formal_parameter",
            "variable_declarator",
        }:
            if node in parent.children_by_field_name("name"):
                return True
    return False


def last_identifier(node: Any) -> Any | None:
    identifiers = [
        child
        for child in iter_nodes(node)
        if child.type in {"identifier", "type_identifier"}
    ]
    return identifiers[-1] if identifiers else None


def safe_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    return root if root.is_dir() else None


def _member_access_state(
    parsed: JavaParsedFile,
    surface: JavaTypeSurface,
    member: JavaMemberSurface,
) -> str:
    if member.visibility == "public":
        return "accessible"
    if member.visibility == "private":
        return "accessible" if parsed.path == surface.file else "inaccessible"
    if member.visibility == "package":
        return (
            "accessible"
            if parsed.package_name == surface.package_name
            else "inaccessible"
        )
    if member.visibility == "protected":
        return (
            "accessible" if parsed.package_name == surface.package_name else "uncertain"
        )
    return "uncertain"


def _enclosing_method(node: Any) -> Any | None:
    current = node.parent
    while current is not None:
        if current.type in {
            "constructor_declaration",
            "lambda_expression",
            "method_declaration",
        }:
            return current
        current = current.parent
    return None
