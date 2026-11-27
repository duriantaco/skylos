"""Conservative external visibility of Rust free functions in Cargo modules."""

from __future__ import annotations

import re
from itertools import chain

from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

from .project_model import allows_dead_code


def _literal_module_path(node):
    # The project model resolves this literal form relative to the containing
    # source file. Inline-module overrides and escaped paths need more context.
    following = node.next_named_sibling
    while following is not None and following.type.endswith("comment"):
        following = following.next_named_sibling
    return (
        node.type == "attribute_item"
        and node.parent.type == "source_file"
        and following is not None
        and following.type == "mod_item"
        and following.child_by_field_name("body") is None
        and re.fullmatch(rb'#\[\s*path\s*=\s*"[^"\\]+"\s*\]', node.text) is not None
    )


def _closed_source(root):
    # Attribute/procedural macros, cfg-selected source, and include! can add
    # callers and exports absent from the syntax tree. Do not guess what they
    # expand to. Accept only recognized inert attributes.
    if root.has_error:
        return False
    pending = [root]
    while pending:
        node = pending.pop()
        kind = node.type
        if kind in {"macro_invocation", "macro_definition"}:
            return False
        if kind in {"inner_attribute_item", "attribute_item"}:
            attribute = next(
                (n for n in node.named_children if n.type == "attribute"), None
            )
            if attribute is None or not attribute.named_children:
                return False
            name = attribute.named_children[0].text
            value = attribute.child_by_field_name("value")
            if (
                name == b"doc"
                and value is not None
                and value.type
                in {
                    "string_literal",
                    "raw_string_literal",
                }
            ):
                continue
            if name == b"path" and _literal_module_path(node):
                continue
            if name not in {
                b"allow",
                b"expect",
                b"warn",
                b"deny",
                b"forbid",
                b"inline",
                b"cold",
                b"must_use",
                b"deprecated",
            }:
                return False
        if kind == "mod_item" and node.parent.type not in {
            "source_file",
            "declaration_list",
        }:
            return False
        pending.extend(node.named_children)
    return True


def complete_module_tree(project, crate):
    """Whether this Cargo target's declared modules and source are all known."""
    if not project.complete or crate.package is None or crate.root is None:
        return False
    checked_files = set()
    pending = [crate.root]
    while pending:
        module = pending.pop()
        if module.file not in checked_files:
            checked_files.add(module.file)
            parsed = project.source_tree(module.file)
            if parsed is None or not _closed_source(parsed):
                return False
        for items in module.items.values():
            for item in items:
                if item.kind == "mod":
                    if item.target is None:
                        return False
                    pending.append(item.target)
    return True


def complete_target_set(project):
    """Cache whether all known Cargo targets have fully observed source."""
    if project.complete_target_set is None:
        project.complete_target_set = (
            project.complete
            and project.all_targets_scanned
            and bool(project.crates)
            and all(complete_module_tree(project, crate) for crate in project.crates)
        )
    return project.complete_target_set


def _external_functions(project, crate):
    """Follow outward-visible modules and re-exports, including public globs."""
    visible = set()
    visited = set()
    pending = [crate.root]
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        visited.add(module)
        for items in chain(module.items.values(), (module.globs,)):
            for item in items:
                if not item.public:
                    continue
                if item.kind == "mod":
                    pending.append(item.target)
                elif item.kind == "fn":
                    visible.add(item)
                elif item.kind in {"use", "glob"}:
                    for target in project.resolve_use(item):
                        if target[0] == "module" and target[1].crate is crate:
                            pending.append(target[1])
                        elif target[0] in {"item", "member"}:
                            visible.add(target[1])
                        else:
                            # Unresolved/re-exported external names can shadow
                            # local aliases. Keep the existing public roots.
                            return None
    return visible


def apply_effective_visibility(definitions, project, scope, errors):
    if (
        errors
        or project is None
        or not project.complete
        or scope.get("kind")
        not in ("repository_root", "repository_root_with_exclusions")
        or scope.get("changed_files_only")
        or scope.get("scan_path") != str(project.root)
        or not set(scope.get("excluded_folders", ())).issubset(DEFAULT_EXCLUDE_FOLDERS)
    ):
        return
    # A sibling target can include this very source under a different module
    # path, making a function public even if this target hides it.
    if not complete_target_set(project):
        return
    surfaces = {}
    for definition in definitions.values():
        if (
            definition.type != "function"
            or not definition.is_exported
            or not str(definition.filename).endswith(".rs")
            or definition.decorators
            or definition.simple_name == "main"
            or definition.simple_name.startswith("test_")
        ):
            continue
        items = project.items_at(
            definition.filename, definition.line, definition.simple_name
        )
        if not items or not all(
            item.kind == "fn"
            and item.public
            and item.owner is None
            and item.module.parent is not None
            and item.module.crate.package is not None
            and not allows_dead_code(item.lints)
            for item in items
        ):
            continue
        for item in items:
            crate = item.module.crate
            if crate not in surfaces:
                surfaces[crate] = _external_functions(project, crate)
            if surfaces[crate] is None or item in surfaces[crate]:
                break
        else:
            definition.is_exported = False
