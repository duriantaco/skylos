"""Private Rust enum variants with no spelling outside their declaration."""

from collections import Counter
from itertools import chain

from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.deadcode.confidence import CONFIDENCE_CAPS

from .effective_visibility import complete_target_set
from .project_model import allows_dead_code

RULE_ID = "SKY-U009"


def _observed_enums(project):
    possible = {
        item
        for items in project.items_by_location.values()
        for item in items
        if item.kind == "enum"
        and item.module.crate.kind == "bin"
        and not item.public
        and not allows_dead_code(item.lints)
        and len(item.variants) > 1
    }
    seen = set()
    if possible:
        names = {name for item in possible for name in item.variants}
        for ref in project.path_refs:
            if len(ref.segments) < 2 or ref.segments[-1] not in names:
                continue
            for target in project.resolve(ref.module, ref.segments, local=ref.local):
                if (
                    target[0] == "member"
                    and target[1] in possible
                    and target[2] in target[1].variants
                ):
                    seen.add(target[1])
    return seen


def _source_evidence(project, candidates):
    names = {name.removeprefix("r#") for item in candidates for name in item.variants}
    spellings = Counter()
    declarations = []
    opaque = set()
    for path, modules in project.modules_by_file.items():
        crates = {module.crate for module in modules if module.crate.package}
        if not crates:
            continue
        pending = [project.source_tree(path)]
        while pending:
            node = pending.pop()
            if node.type in {"unsafe_block", "foreign_mod_item", "extern_modifier"} or (
                node.type in {"function_modifiers", "impl_item", "trait_item"}
                and any(child.type == "unsafe" for child in node.children)
            ):
                opaque.update(crates)
            if node.type.endswith("identifier") and not node.named_child_count:
                name = node.text.decode("utf-8").removeprefix("r#")
                if name in names:
                    spellings[name] += 1
            elif (
                node.type == "enum_item"
                and len(crates) == 1
                and not any(
                    c.type == "visibility_modifier" for c in node.named_children
                )
            ):
                name = node.child_by_field_name("name")
                items = project.items_at(
                    path, name.start_point[0] + 1, name.text.decode("utf-8")
                )
                if len(items) == 1 and items[0] in candidates:
                    declarations.append((items[0], node.child_by_field_name("body")))
            pending.extend(node.named_children)
    return spellings, declarations, opaque


def find_unused_variants(project, scope, errors):
    if (
        project is None
        or errors
        or scope.get("kind")
        not in {"repository_root", "repository_root_with_exclusions"}
        or scope.get("changed_files_only")
        or scope.get("scan_path") != str(project.root)
        or not set(scope.get("excluded_folders", ())).issubset(DEFAULT_EXCLUDE_FOLDERS)
        or not complete_target_set(project)
    ):
        return []
    candidates = _observed_enums(project)
    if not candidates:
        return []
    spellings, declarations, opaque = _source_evidence(project, candidates)
    findings = []
    for item, body in declarations:
        if item.module.crate in opaque or body is None:
            continue
        # An attribute can suppress a variant, change its representation, or
        # tell code generation how to construct it. Leave its enum alone.
        if any(child.type == "attribute_item" for child in body.named_children):
            continue
        for variant in body.named_children:
            if variant.type != "enum_variant":
                continue
            name = variant.child_by_field_name("name")
            member = name.text.decode("utf-8")
            if spellings[member.removeprefix("r#")] != 1:
                continue
            full_name = "::".join(chain(item.module.path, (item.name, member)))
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "type": "enum_variant",
                    "name": full_name,
                    "full_name": full_name,
                    "simple_name": member,
                    "enum": item.name,
                    "file": str(item.file),
                    "line": name.start_point[0] + 1,
                    "confidence": CONFIDENCE_CAPS["experimental_language"],
                    "confidence_factors": ["experimental_language"],
                    "severity": "LOW",
                    "category": "DEAD_CODE",
                    "references": 0,
                    "message": f"Private Rust enum variant '{full_name}' is never named outside its declaration.",
                }
            )
    return findings
