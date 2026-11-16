"""Unused members of local and closed private TypeScript enums.

Library exports and escaping enum objects remain opaque. Direct named imports
may narrow a private package's enum only with a complete source inventory.
Computed keys, reflection, mutation, parse failures and nonliteral initializers
decline member narrowing. This pass does not infer compiler types or edit enums.
"""

from __future__ import annotations

import os
import json
from collections import defaultdict
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink

from .core import TypeScriptCore
from .namespace_references import namespace_member_reads

RULE_ID = "SKY-U007"
MAX_FILES = 5000
MAX_SOURCE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_WALK_ENTRIES = 100_000
_SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_COMPONENT_SUFFIXES = {".vue", ".svelte", ".astro", ".html", ".htm", ".mdx", ".marko"}
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__"}
_LITERAL_INITIALIZERS = {
    "number", "string", "true", "false", "null", "unary_expression",
    "binary_expression", "parenthesized_expression", "identifier",
    "property_identifier", "string_fragment", "escape_sequence",
}


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _text(source, node):
    return source[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _members(enum, source):
    body = enum.child_by_field_name("body")
    if body is None:
        return None
    members = []
    names = set()
    referenced = set()
    for node in body.named_children:
        if node.type == "comment":
            continue
        if node.type in {"property_identifier", "string"}:
            name_node = node
        elif node.type == "enum_assignment":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if value is None:
                return None
            for part in _walk(value):
                if part.type not in _LITERAL_INITIALIZERS:
                    return None
                if part.type in {"identifier", "property_identifier"}:
                    referenced.add(_text(source, part))
        else:
            return None
        if name_node is None:
            return None
        raw = _text(source, name_node)
        if "\\" in raw:
            return None
        name = raw[1:-1] if name_node.type == "string" else raw
        if not name or name in names:
            return None
        names.add(name)
        members.append((name, name_node.start_point[0] + 1))
    return members, referenced


def _closed_source_graph(files, root, cores, resolver):
    """Prove source inventory, package ownership and direct import identities."""
    from skylos.core.js_ast import iter_import_clause_bindings
    from .analysis import resolve_ts_module
    from .resolve import MonorepoResolver

    root = Path(root).resolve()
    selected = {Path(path).absolute() for path in files if Path(path).suffix in _SOURCE_SUFFIXES}
    if len(selected) > MAX_FILES:
        return {}, {}, [{"kind": "source_file_budget"}]
    issues, manifests, walked = [], {}, 0

    def unreadable(error):
        issues.append({"kind": "unreadable_source_directory", "file": str(error.filename)})

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=unreadable):
        walked += 1 + len(dirs) + len(names)
        if walked > MAX_WALK_ENTRIES:
            issues.append({"kind": "source_inventory_budget"})
            break
        for name in dirs:
            if name not in _SKIP_DIRS and (Path(directory) / name).is_symlink():
                issues.append({"kind": "symlink_source_directory", "file": str(Path(directory) / name)})
        dirs[:] = [name for name in dirs if name not in _SKIP_DIRS and not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            if path.suffix in _COMPONENT_SUFFIXES:
                issues.append({"kind": "unparsed_component_consumer", "file": str(path)})
            if path.suffix in _SOURCE_SUFFIXES and path not in selected:
                issues.append({"kind": "unselected_source", "file": str(path)})
            if name == "package.json":
                text = read_project_text_no_symlink(root, path, max_bytes=MAX_SOURCE_BYTES)
                try:
                    data = json.loads(text) if text is not None else None
                except (ValueError, TypeError, RecursionError):
                    data = None
                if isinstance(data, dict):
                    manifests[path.parent] = data
                else:
                    issues.append({"kind": "unreadable_package_manifest", "file": str(path)})
    total_bytes = 0
    for path in sorted(selected):
        if path not in cores:
            text = read_project_text_no_symlink(root, path, max_bytes=MAX_SOURCE_BYTES)
            if text is None:
                issues.append({"kind": "unreadable_source", "file": str(path)})
                continue
            cores[path] = TypeScriptCore(str(path), text.encode("utf-8"))
        core = cores[path]
        total_bytes += len(core.source)
        if total_bytes > MAX_TOTAL_BYTES:
            issues.append({"kind": "source_byte_budget"})
            break
        if core.root_node is None or core.root_node.has_error:
            issues.append({"kind": "source_parse_error", "file": str(path)})
    if issues:
        return manifests, {}, issues
    resolver = resolver or MonorepoResolver(str(root))
    consumers = defaultdict(list)
    for path in sorted(selected):
        core = cores[path]
        source, tree = core.source, core.root_node
        reads = namespace_member_reads(tree, source, include_named_imports=True, include_local_enums=True)
        for node in _walk(tree):
            if node.type == "identifier" and _text(source, node) == "require":
                if node.parent is not None and node.parent.type not in {"call_expression", "member_expression"}:
                    issues.append({"kind": "escaped_module_loader", "file": str(path)})
            if node.type == "new_expression" and _text(source, node.child_by_field_name("constructor")) == "Function":
                issues.append({"kind": "opaque_module_loader", "file": str(path)})
            if node.type == "call_expression":
                function = node.child_by_field_name("function")
                name = _text(source, function)
                args = node.child_by_field_name("arguments")
                if name in {"eval", "Function", "createRequire", "import.meta.glob", "import.meta.globEager"} or name.endswith((".createRequire", ".require")):
                    issues.append({"kind": "opaque_module_loader", "file": str(path)})
                if (function is not None and function.type == "import") or name in {"require", "require.resolve"}:
                    arg = args.named_children[0] if args is not None and args.named_children else None
                    literal = _text(source, arg)
                    if arg is None or arg.type != "string" or "\\" in literal:
                        issues.append({"kind": "dynamic_module_load", "file": str(path)})
                        continue
                    specifier = literal[1:-1]
                    target = resolve_ts_module(specifier, str(path), resolver)
                    if target is not None:
                        consumers[Path(target).absolute()].append((None, None))
                    elif specifier.startswith((".", "/", "#")) or resolver.claims_local_source(specifier, str(path)):
                        issues.append({"kind": "unresolved_local_import", "file": str(path)})
            if node.type not in {"import_statement", "export_statement"}:
                continue
            source_node = node.child_by_field_name("source")
            if source_node is None:
                continue
            raw = _text(source, source_node)
            if source_node.type != "string" or "\\" in raw:
                issues.append({"kind": "unresolved_module_specifier", "file": str(path)})
                continue
            specifier = raw[1:-1]
            if specifier in {"module", "node:module"}:
                issues.append({"kind": "module_loader_capability", "file": str(path)})
            target = resolve_ts_module(specifier, str(path), resolver)
            if target is None:
                if specifier.startswith((".", "/", "#")) or resolver.claims_local_source(specifier, str(path)):
                    issues.append({"kind": "unresolved_local_import", "file": str(path)})
                continue
            target = Path(target).absolute()
            if target not in selected:
                issues.append({"kind": "unparsed_import_provider", "file": str(target)})
                continue
            if node.type == "export_statement":
                consumers[target].append((None, None))
                continue
            clause = next((part for part in node.named_children if part.type == "import_clause"), None)
            if clause is None:
                continue
            for binding in iter_import_clause_bindings(source, clause):
                if binding.kind != "named":
                    consumers[target].append((None, None))
                else:
                    consumers[target].append((binding.imported, reads.get(binding.local)))
    return manifests, consumers, issues


def _exported_enum_findings(exported, files, project_root, cores, resolver, receipt):
    manifests, consumers, issues = _closed_source_graph(files, project_root, cores, resolver)
    receipt["exported_scope_reasons"] = issues
    findings = []
    for path, core, enum in exported:
        name = _text(core.source, enum.child_by_field_name("name"))
        owners = [owner for owner in manifests if path.is_relative_to(owner)]
        owner = max(owners, key=lambda value: len(value.parts)) if owners else None
        reason = None
        if owner is None or manifests[owner].get("private") is not True:
            reason = "public_package_enum"
        elif issues:
            reason = "incomplete_project_source_graph"
        members = _members(enum, core.source)
        if members is None:
            reason = reason or "unsupported_enum_initializer_or_members"
        consumed = namespace_member_reads(core.root_node, core.source, include_local_enums=True).get(name)
        if consumed is None:
            reason = reason or "opaque_enum_use"
        else:
            consumed = set(consumed)
            for imported, demand in consumers.get(path, ()):
                if imported is None or imported == name and demand is None:
                    reason = reason or "opaque_or_indirect_enum_import"
                elif imported == name:
                    consumed.update(demand)
        if reason:
            receipt["abstained_enums"].append({"file": str(path), "name": name, "reason": reason})
            continue
        receipt["checked_enums"] += 1
        if not consumed:
            receipt["grouped_enums"] += 1
            continue
        entries, initializers = members
        for member, line in entries:
            if member in consumed or member in initializers:
                continue
            full_name = f"{name}.{member}"
            findings.append({
                "rule_id": RULE_ID, "name": full_name, "simple_name": member,
                "full_name": full_name, "enum": name, "type": "enum_member",
                "file": str(path), "line": line, "confidence": 100,
                "severity": "LOW", "category": "DEAD_CODE", "references": 0,
                "message": f"Enum member '{full_name}' is never read in the closed private source graph.",
            })
    return findings


def find_unused_ts_enum_members(files, *, project_root, analysis_errors=(), resolver=None, workspace_inventory=None, coverage=None):
    """Return enum-member findings in source modules; uncertain enums stay live.

    Direct named imports may narrow exported enums only when the full source
    graph is closed and their owning npm package explicitly has private:true.
    """
    receipt = coverage if coverage is not None else {}
    receipt.update(scope="local_and_closed_private_enums", status="complete", complete=True, analysed_files=0, checked_enums=0, grouped_enums=0, abstained_enums=[], reasons=[])

    def abstain(path, name, reason):
        receipt["abstained_enums"].append({"file": str(path), "name": name, "reason": reason})

    def finish(findings):
        receipt["abstained_count"] = len(receipt["abstained_enums"])
        if receipt["reasons"]:
            receipt.update(status="incomplete", complete=False)
        elif receipt["abstained_enums"]:
            receipt.update(status="bounded", complete=False)
        return findings

    paths = sorted({Path(path).absolute() for path in files if str(path).endswith((".ts", ".tsx", ".mts", ".cts")) and not str(path).endswith((".d.ts", ".d.mts", ".d.cts"))})
    if len(paths) > MAX_FILES:
        receipt["reasons"].append({"kind": "source_file_budget"})
        return finish([])
    errors = {os.path.abspath(str(error.get("file"))) for error in analysis_errors if isinstance(error, dict) and error.get("file")}
    findings, exported, cores, total_bytes = [], [], {}, 0
    for path in paths:
        if str(path) in errors:
            receipt["reasons"].append({"kind": "source_analysis_error", "file": str(path)})
            continue
        text = read_project_text_no_symlink(project_root, path, max_bytes=MAX_SOURCE_BYTES)
        if text is None:
            receipt["reasons"].append({"kind": "unreadable_source", "file": str(path)})
            continue
        source = text.encode("utf-8")
        total_bytes += len(source)
        if total_bytes > MAX_TOTAL_BYTES:
            receipt["reasons"].append({"kind": "source_byte_budget"})
            return finish([])
        receipt["analysed_files"] += 1
        if b"enum" not in source:
            continue
        core = TypeScriptCore(str(path), source)
        cores[path] = core
        tree = core.root_node
        if tree is None or tree.has_error:
            receipt["reasons"].append({"kind": "source_parse_error", "file": str(path)})
            continue
        all_enums = [node for node in _walk(tree) if node.type == "enum_declaration"]
        # A classic-script enum may be consumed by another source file without
        # an import. Only an explicit module boundary closes that namespace.
        if not any(node.type in {"import_statement", "export_statement"} for node in tree.named_children):
            for enum in all_enums:
                abstain(path, _text(source, enum.child_by_field_name("name")), "classic_script_or_ambient_scope")
            continue
        enums = [node for node in tree.named_children if node.type == "enum_declaration"]
        local_ids = {node.id for node in enums}
        for enum in all_enums:
            if enum.id not in local_ids:
                if enum.parent is not None and enum.parent.type == "export_statement" and enum.parent.parent == tree:
                    exported.append((path, core, enum))
                else:
                    abstain(path, _text(source, enum.child_by_field_name("name")), "exported_ambient_or_nested_enum")
        if not enums:
            continue
        reads = namespace_member_reads(tree, source, include_local_enums=True)
        for enum in enums:
            name = _text(source, enum.child_by_field_name("name"))
            members = _members(enum, source)
            consumed = reads.get(name)
            if members is None:
                abstain(path, name, "unsupported_enum_initializer_or_members")
                continue
            if consumed is None:
                abstain(path, name, "opaque_enum_use")
                continue
            receipt["checked_enums"] += 1
            entries, initializers = members
            if not consumed:
                # Let the existing unused-enum/class finding group the owner.
                receipt["grouped_enums"] += 1
                continue
            for member, line in entries:
                if member in consumed or member in initializers:
                    continue
                full_name = f"{name}.{member}"
                findings.append({
                    "rule_id": RULE_ID, "name": full_name, "simple_name": member,
                    "full_name": full_name, "enum": name, "type": "enum_member",
                    "file": str(path), "line": line, "confidence": 100,
                    "severity": "LOW", "category": "DEAD_CODE", "references": 0,
                    "message": f"Enum member '{full_name}' is never read in this module.",
                })
    if exported:
        findings.extend(_exported_enum_findings(exported, files, project_root, cores, resolver, receipt))
    return finish(findings)
