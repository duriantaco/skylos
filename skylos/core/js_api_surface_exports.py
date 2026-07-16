from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.core.js_api_surface_members import (
    _add_export_member,
    _default_export_kind,
    _export_source_literal,
    _export_statement_is_star_export,
    _export_statement_is_type_only,
    _exported_ambient_member_pairs,
    _exported_direct_member_pairs,
    _exported_function_signature_names,
    _exported_namespace_names,
    _member_chain,
    _module_scope_exportable_bindings,
    _named_export_clause_pairs,
    _namespace_export_name,
    _node_line,
    _node_text,
    _object_export_members,
    _value_kind,
)
from skylos.core.js_api_surface_utils import (
    MAX_JS_API_REEXPORT_DEPTH,
    MAX_JS_API_SURFACE_SOURCE_BYTES,
    resolve_entrypoint_target as _resolve_entrypoint_target,
    safe_name as _safe_name,
)
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.visitors.languages.typescript import is_minified_js_source
from skylos.visitors.languages.typescript.core import TypeScriptCore


def collect_js_exports_from_file(
    root: Path,
    file_path: Path,
    members: dict[str, dict[str, Any]],
    visited: set[Path],
    *,
    depth: int,
    diagnostics: set[str] | None = None,
) -> None:
    if depth > MAX_JS_API_REEXPORT_DEPTH:
        _add_diagnostic(diagnostics, "reexport_depth_limit")
        return
    if file_path in visited:
        return
    visited.add(file_path)

    source_text = read_text_no_symlink(
        file_path,
        max_bytes=MAX_JS_API_SURFACE_SOURCE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source_text is None:
        _add_diagnostic(diagnostics, "source_unreadable")
        return
    source = source_text.encode("utf-8", "ignore")
    if is_minified_js_source(str(file_path), source):
        _add_diagnostic(diagnostics, "minified_source")
        return

    core = TypeScriptCore(str(file_path), source)
    core.scan()
    if core.root_node is None or _has_blocking_parse_error(core):
        _add_diagnostic(diagnostics, "parse_error")
        return
    local_bindings = _module_scope_exportable_bindings(source, core.root_node)
    if _has_conditional_commonjs_export(core, source):
        _add_diagnostic(diagnostics, "conditional_commonjs_export")

    commonjs_exports_alias_valid = True
    ambiguous_star_exports: set[str] = set()
    for node in core.root_node.named_children:
        if node.type == "export_statement":
            _collect_export_statement(
                root,
                file_path,
                source,
                node,
                members,
                visited,
                depth,
                local_bindings,
                ambiguous_star_exports,
                diagnostics,
            )
        assignment = _top_level_assignment_expression(node)
        if assignment is not None:
            if not _commonjs_assignment_is_static(source, assignment):
                _add_diagnostic(diagnostics, "dynamic_commonjs_export")
            commonjs_exports_alias_valid = _collect_commonjs_assignment(
                root,
                file_path,
                source,
                assignment,
                members,
                exports_alias_valid=commonjs_exports_alias_valid,
            )
        elif _expression_may_mutate_commonjs_exports(source, node):
            _add_diagnostic(diagnostics, "dynamic_commonjs_export")
def _collect_export_statement(
    root: Path,
    file_path: Path,
    source: bytes,
    node: Any,
    members: dict[str, dict[str, Any]],
    visited: set[Path],
    depth: int,
    local_bindings: dict[str, str],
    ambiguous_star_exports: set[str],
    diagnostics: set[str] | None,
) -> None:
    text = _node_text(source, node).strip()
    source_literal = _export_source_literal(source, node)
    type_only_export = _export_statement_is_type_only(text)

    _collect_static_export_members(root, file_path, source, node, members, text)
    _collect_default_export(root, file_path, node, members, text)

    resolved = _resolved_reexport_source(root, file_path, source_literal)
    if source_literal is not None and resolved is None:
        if source_literal.startswith("."):
            _add_diagnostic(diagnostics, "unresolved_local_reexport")
        else:
            _add_diagnostic(diagnostics, "external_reexport")
        return

    reexport_members = _reexport_members(
        root,
        resolved,
        visited,
        depth,
        diagnostics,
    )
    if _collect_namespace_reexport(
        root,
        file_path,
        source,
        node,
        members,
        source_literal,
        type_only_export,
    ):
        return

    _collect_named_export_members(
        root,
        file_path,
        source,
        node,
        members,
        local_bindings,
        reexport_members,
        source_literal,
        type_only_export,
        ambiguous_star_exports,
    )
    if resolved is not None and _export_statement_is_star_export(text):
        _collect_star_reexport_members(
            members,
            reexport_members,
            source_literal,
            type_only_export,
            ambiguous_star_exports,
        )


def _collect_static_export_members(
    root: Path,
    file_path: Path,
    source: bytes,
    node: Any,
    members: dict[str, dict[str, Any]],
    text: str,
) -> None:
    for exported_name, member_kind in _exported_direct_member_pairs(source, node, text):
        _add_export_member(
            root,
            members,
            exported_name,
            member_kind,
            file_path,
            _node_line(node),
            source="static_export",
        )
    for exported_name in _exported_function_signature_names(source, node):
        _add_export_member(
            root,
            members,
            exported_name,
            "function",
            file_path,
            _node_line(node),
            source="static_export",
        )
    for exported_name, member_kind in _exported_ambient_member_pairs(source, node):
        _add_export_member(
            root,
            members,
            exported_name,
            member_kind,
            file_path,
            _node_line(node),
            source="static_export",
        )
    for namespace_name in _exported_namespace_names(source, node):
        _add_export_member(
            root,
            members,
            namespace_name,
            "namespace",
            file_path,
            _node_line(node),
            source="static_export",
        )


def _collect_default_export(
    root: Path,
    file_path: Path,
    node: Any,
    members: dict[str, dict[str, Any]],
    text: str,
) -> None:
    if text.startswith("export default"):
        _add_export_member(
            root,
            members,
            "default",
            _default_export_kind(node),
            file_path,
            _node_line(node),
            source="default_export",
        )


def _resolved_reexport_source(
    root: Path,
    file_path: Path,
    source_literal: str | None,
) -> Path | None:
    if source_literal is None or not source_literal.startswith("."):
        return None
    return _resolve_relative_source(root, file_path.parent, source_literal)


def _reexport_members(
    root: Path,
    resolved: Path | None,
    visited: set[Path],
    depth: int,
    diagnostics: set[str] | None,
) -> dict[str, dict[str, Any]]:
    if resolved is None:
        return {}
    return _collect_resolved_reexport_members(
        root,
        resolved,
        visited,
        depth,
        diagnostics,
    )


def _collect_namespace_reexport(
    root: Path,
    file_path: Path,
    source: bytes,
    node: Any,
    members: dict[str, dict[str, Any]],
    source_literal: str | None,
    type_only_export: bool,
) -> bool:
    namespace_name = _namespace_export_name(source, node)
    if namespace_name is None:
        return False
    _add_export_member(
        root,
        members,
        namespace_name,
        "type" if type_only_export else "namespace",
        file_path,
        _node_line(node),
        source="namespace_reexport",
        target=source_literal,
    )
    return True


def _collect_named_export_members(
    root: Path,
    file_path: Path,
    source: bytes,
    node: Any,
    members: dict[str, dict[str, Any]],
    local_bindings: dict[str, str],
    reexport_members: dict[str, dict[str, Any]],
    source_literal: str | None,
    type_only_export: bool,
    ambiguous_star_exports: set[str],
) -> None:
    for original_name, exported_name, specifier_type_only in _named_export_clause_pairs(
        source,
        node,
    ):
        member_kind = _named_export_member_kind(
            original_name,
            local_bindings,
            reexport_members,
            reexported=source_literal is not None,
            type_only=type_only_export or specifier_type_only,
        )
        if member_kind is None:
            continue
        ambiguous_star_exports.discard(exported_name)
        _add_export_member(
            root,
            members,
            exported_name,
            member_kind,
            file_path,
            _node_line(node),
            source="named_reexport" if source_literal else "named_export",
            target=source_literal,
        )


def _named_export_member_kind(
    original_name: str,
    local_bindings: dict[str, str],
    reexport_members: dict[str, dict[str, Any]],
    *,
    reexported: bool,
    type_only: bool,
) -> str | None:
    if not reexported:
        member_kind = local_bindings.get(original_name)
        return "type" if member_kind is not None and type_only else member_kind
    reexported_member = reexport_members.get(original_name)
    if not isinstance(reexported_member, dict):
        return None
    if type_only:
        return "type"
    member_kind = reexported_member.get("kind")
    return member_kind if isinstance(member_kind, str) else "reexport"


def _collect_star_reexport_members(
    members: dict[str, dict[str, Any]],
    reexport_members: dict[str, dict[str, Any]],
    source_literal: str | None,
    type_only_export: bool,
    ambiguous_star_exports: set[str],
) -> None:
    for name, member in reexport_members.items():
        _copy_star_reexport_member(
            members,
            name,
            member,
            source_literal,
            type_only_export,
            ambiguous_star_exports,
        )


def _copy_star_reexport_member(
    members: dict[str, dict[str, Any]],
    name: str,
    member: dict[str, Any],
    source_literal: str | None,
    type_only_export: bool,
    ambiguous_star_exports: set[str],
) -> None:
    if name == "default":
        return
    safe_name = _safe_name(name)
    if safe_name is None or safe_name in ambiguous_star_exports:
        return
    existing = members.get(safe_name)
    if isinstance(existing, dict) and existing.get("source") == "star_reexport":
        del members[safe_name]
        ambiguous_star_exports.add(safe_name)
        return
    if safe_name in members:
        return
    copied = dict(member)
    copied["source"] = "star_reexport"
    copied["target"] = source_literal
    if type_only_export:
        copied["kind"] = "type"
    members[safe_name] = copied
def _collect_resolved_reexport_members(
    root: Path,
    resolved: Path,
    visited: set[Path],
    depth: int,
    diagnostics: set[str] | None,
) -> dict[str, dict[str, Any]]:
    members: dict[str, dict[str, Any]] = {}
    collect_js_exports_from_file(
        root,
        resolved,
        members,
        set(visited),
        depth=depth + 1,
        diagnostics=diagnostics,
    )
    return members


def _commonjs_assignment_is_static(source: bytes, node: Any) -> bool:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None:
        return True

    chain = _member_chain(source, left)
    if len(chain) >= 3 and chain[:2] == ["module", "exports"]:
        return True
    if len(chain) == 2 and chain[0] == "exports":
        return True
    if chain == ["module", "exports"]:
        return right is not None and right.type == "object"
    if "exports" not in _node_text(source, left):
        return True
    return False


def _expression_may_mutate_commonjs_exports(source: bytes, node: Any) -> bool:
    if node.type != "expression_statement":
        return False
    text = _node_text(source, node)
    if "exports" not in text:
        return False
    return "Object.assign" in text or "Object.defineProperty" in text


def _has_blocking_parse_error(core: TypeScriptCore) -> bool:
    if core.root_node is None or not core.root_node.has_error:
        return False
    for node in core._iter_nodes(core.root_node):
        if not node.is_error and not node.is_missing:
            continue
        parent = node.parent
        if (
            node.type == "ERROR"
            and core._get_text(node) == "type"
            and parent is not None
            and parent.type == "export_statement"
            and core._get_text(parent).lstrip().startswith("export type *")
        ):
            continue
        return True
    return False


def _add_diagnostic(diagnostics: set[str] | None, reason: str) -> None:
    if diagnostics is not None:
        diagnostics.add(reason)
def _collect_commonjs_assignment(
    root: Path,
    file_path: Path,
    source: bytes,
    node: Any,
    members: dict[str, dict[str, Any]],
    *,
    exports_alias_valid: bool,
) -> bool:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None:
        return exports_alias_valid

    chain = _member_chain(source, left)
    if len(chain) >= 2 and chain[:2] == ["module", "exports"]:
        _add_export_member(
            root,
            members,
            "default",
            "commonjs",
            file_path,
            _node_line(node),
            source="commonjs_default_facade",
        )
        if len(chain) == 2:
            _remove_commonjs_members(members)
            for name, kind in _object_export_members(source, right):
                _add_export_member(
                    root,
                    members,
                    name,
                    kind,
                    file_path,
                    _node_line(node),
                    source="commonjs_export",
                )
            return False
        _add_export_member(
            root,
            members,
            chain[2],
            _value_kind(right),
            file_path,
            _node_line(node),
            source="commonjs_export",
        )
        return exports_alias_valid

    if len(chain) == 2 and chain[0] == "exports" and exports_alias_valid:
        _add_export_member(
            root,
            members,
            "default",
            "commonjs",
            file_path,
            _node_line(node),
            source="commonjs_default_facade",
        )
        _add_export_member(
            root,
            members,
            chain[1],
            _value_kind(right),
            file_path,
            _node_line(node),
            source="commonjs_export",
        )
    return exports_alias_valid
def _remove_commonjs_members(members: dict[str, dict[str, Any]]) -> None:
    for name in list(members):
        member = members.get(name)
        if isinstance(member, dict) and member.get("source") == "commonjs_export":
            del members[name]
def _top_level_assignment_expression(node: Any) -> Any | None:
    if node.type != "expression_statement":
        return None
    for child in node.named_children:
        if child.type == "assignment_expression":
            return child
    return None


def _has_conditional_commonjs_export(core: TypeScriptCore, source: bytes) -> bool:
    if core.root_node is None:
        return False
    for node in core._iter_nodes(core.root_node):
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if (
                left is not None
                and _targets_commonjs_exports(source, left)
                and not _is_top_level_expression(node)
            ):
                return True
        if (
            node.type == "call_expression"
            and _call_mutates_commonjs_exports(source, node)
            and not _is_top_level_expression(node)
        ):
            return True
    return False


def _targets_commonjs_exports(source: bytes, node: Any) -> bool:
    chain = _member_chain(source, node)
    if len(chain) >= 2 and chain[:2] == ["module", "exports"]:
        return True
    return bool(chain) and chain[0] == "exports"


def _call_mutates_commonjs_exports(source: bytes, node: Any) -> bool:
    function = node.child_by_field_name("function")
    if function is None or _node_text(source, function) not in {
        "Object.assign",
        "Object.defineProperty",
    }:
        return False
    arguments = node.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return False
    return _targets_commonjs_exports(source, arguments.named_children[0])


def _is_top_level_expression(node: Any) -> bool:
    parent = node.parent
    if parent is None or parent.type != "expression_statement":
        return False
    grandparent = parent.parent
    return grandparent is not None and grandparent.type == "program"


def _resolve_relative_source(root: Path, base_dir: Path, source: str) -> Path | None:
    if not source.startswith("."):
        return None
    return _resolve_entrypoint_target(root, base_dir, source)
