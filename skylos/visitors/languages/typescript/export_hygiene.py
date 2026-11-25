"""Export hygiene of internal TS/JS modules on one shared export surface.

- SKY-E004 (``type``/``interface``): an exported type no project file
  requests from its module. A type named in the shape of a requested value
  export (its signature, or its body when the return type is inferred, and
  module-local declarations reached from there) stays silent, as does a type
  merged with a value of the same name. A requested type holds nothing.
- SKY-E005: one binding exported under two names (``export const B = A``
  and ``export default A``), limited to bindings that cannot be reassigned.
  Public modules are checked too; internal modules an importer uses whole
  stay silent.
- SKY-U008: an exported namespace's variable or type member that no file
  reads, when every read of the namespace names its members.

Types and namespace members use the E004 notion of an internal module:
public modules (package entries, tool and framework entries, files named by
path, modules nothing imports) and wholly consumed modules stay silent, and
so do the type exports of modules a types-only wildcard export publishes.
"""

from __future__ import annotations

import os

from skylos.deadcode.confidence import export_finding_confidence

from .export_facts import is_reported_member_kind
from .framework import is_framework_loaded_file
from .text_fixtures import is_text_fixture
from .unused_reexports import (
    _ALL,
    _STAR,
    _VALUES,
    build_ts_export_surface,
    reexport_findings,
)

_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
DUPLICATE_RULE_ID = "SKY-E005"
NAMESPACE_MEMBER_RULE_ID = "SKY-U008"
NAMESPACE_SCOPE = "internal_module_namespaces"
_TYPESCRIPT_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")


def find_ts_export_hygiene(
    files,
    raw_imports,
    *,
    project_root,
    resolver=None,
    workspace_inventory=None,
    exclude_folders=None,
    browser_entry_points=(),
    analysis_errors=(),
    framework_reexport_reads=None,
):
    """Return export findings, namespace member findings, their receipt and the surface."""
    receipt = {
        "scope": NAMESPACE_SCOPE,
        "status": "complete",
        "complete": True,
        "checked_namespaces": 0,
        "abstained_namespaces": [],
        "reasons": [],
    }
    surface = build_ts_export_surface(
        files,
        raw_imports,
        project_root=project_root,
        resolver=resolver,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
        browser_entry_points=browser_entry_points,
        analysis_errors=analysis_errors,
        framework_reexport_reads=framework_reexport_reads,
    )
    if surface is None:
        receipt.update(
            status="not_run",
            complete=False,
            reasons=[{"kind": "export_surface_unavailable"}],
        )
        return {
            "exports": [],
            "namespace_members": [],
            "namespace_receipt": receipt,
            "surface": None,
        }
    reexports = reexport_findings(surface, _held_import_locals(surface))
    exports = [
        *reexports,
        *unused_type_export_findings(surface),
        *duplicate_export_findings(surface, reexports),
    ]
    members = namespace_member_findings(surface, receipt)
    receipt["abstained_count"] = len(receipt["abstained_namespaces"])
    if receipt["abstained_namespaces"]:
        receipt.update(status="bounded", complete=False)
    return {
        "exports": exports,
        "namespace_members": members,
        "namespace_receipt": receipt,
        "surface": surface,
    }


def _requested(names, name):
    return name in names or (_STAR in names and name != "default")


def _value_requested(names, name):
    return _VALUES in names or _requested(names, name)


def _held_statements(facts, names, expanded=None):
    """Statements in the type shape of a requested value export.

    A requested value export (function, class, variable, enum, namespace,
    default) keeps the types its shape names, and so do tagged exports and
    global/module augmentations. A requested *type* does not:
    removing ``export`` from a type it mentions breaks no consumer. The walk
    follows module-local declarations but stops at other exported types,
    which are judged on their own. ``expanded`` collects the statements
    whose shapes were followed.
    """
    kinds = {}
    for entries in facts.declarations.values():
        for index, kind in entries:
            kinds.setdefault(index, set()).add(kind)
    exported_types = {
        index
        for indices in facts.exported_statements.values()
        for index in indices
        if kinds.get(index) and kinds[index] <= {"type", "interface"}
    }
    queue = list(facts.augmentation_statements)
    for name, indices in facts.exported_statements.items():
        if name in facts.tagged_exports:
            queue.extend(indices)
        elif _value_requested(names, name):
            queue.extend(index for index in indices if index not in exported_types)
    held = set()
    while queue:
        index = queue.pop()
        if index in held:
            continue
        held.add(index)
        if expanded is not None:
            expanded.add(index)
        for ref in facts.statement_shape_refs[index]:
            for other, _kind in facts.declarations.get(ref, ()):
                if other in held:
                    continue
                if other in exported_types:
                    held.add(other)
                else:
                    queue.append(other)
    return held


def _held_import_locals(surface):
    """Names in the shapes of requested value exports, per internal module."""
    held_locals = {}
    for path in surface.internal:
        module = surface.modules[path]
        if module.facts is None or not any(
            entry.import_local for entry in module.entries
        ):
            continue
        expanded = set()
        _held_statements(module.facts, surface.demand[path], expanded)
        held_locals[path] = {
            name
            for index in expanded
            for name in module.facts.statement_shape_refs[index]
        }
    return held_locals


def unused_type_export_findings(surface):
    findings = []
    for path in sorted(surface.internal):
        facts = surface.modules[path].facts
        if facts is None or not facts.type_exports:
            continue
        if not path.endswith(_TYPESCRIPT_SUFFIXES):
            continue
        if path in surface.types_public:
            continue
        names = surface.demand[path]
        held = None
        seen = set()
        for item in facts.type_exports:
            if item.name in seen:
                continue
            seen.add(item.name)
            if item.tagged or item.name in facts.tagged_exports:
                continue
            if _requested(names, item.name):
                continue
            declarations = facts.declarations.get(item.local, ())
            # Declaration merging: the name also has a value meaning.
            if not declarations or any(
                kind not in {"type", "interface"} for _index, kind in declarations
            ):
                continue
            own = {index for index, _kind in declarations}
            if held is None:
                held = _held_statements(facts, names)
            if own & held:
                continue
            used_here = any(
                item.local in refs
                for index, refs in enumerate(facts.statement_refs)
                if index not in own and index not in facts.clause_statements
            )
            findings.append(
                _type_finding(surface.spelled.get(path, path), item, used_here)
            )
    return findings


def _type_finding(path, item, used_here):
    confidence, factors = export_finding_confidence()
    if used_here:
        message = (
            f"Unnecessary `export` on {item.kind} `{item.name}` "
            "(used in this file but not imported by any other file)"
        )
    else:
        message = (
            f"Unused exported {item.kind} `{item.name}` "
            "(no file imports it from this module)"
        )
    return {
        "rule_id": "SKY-E004",
        "confidence": confidence,
        "confidence_factors": factors,
        "name": item.name,
        "message": message,
        "file": path,
        "line": item.line,
        "type": item.kind,
        "severity": "LOW",
        "category": "DEAD_CODE",
    }


def duplicate_export_findings(surface, reexports=()):
    """One finding per binding exported under several names.

    A public module (package entry, test, ``export *`` target) is checked
    too: the second name is redundant wherever the module is consumed. An
    internal module an importer uses whole (``Object.keys(ns)``,
    ``import()``) may observe both names and stays silent, as do declaration
    files, text fixtures and files a framework or tool loads (every export of
    a story or config is read). A name the re-export check already reports
    as an unused alias is left to that finding, so a group collapses when
    fewer than two names remain.
    """
    reported = {(str(item.get("file")), item.get("name")) for item in reexports}
    findings = []
    for path in sorted(surface.modules):
        facts = surface.modules[path].facts
        if facts is None or not facts.duplicates:
            continue
        if path in surface.enumerated:
            continue
        if path.endswith(_DECLARATION_SUFFIXES) or is_text_fixture(path):
            continue
        if is_framework_loaded_file(path) or _is_tool_or_story(path):
            continue
        # A runtime enumeration of an internal module observes every name.
        if path in surface.internal and _VALUES in surface.demand[path]:
            continue
        spelled = surface.spelled.get(path, path)
        for group in facts.duplicates:
            names = [name for name, _line in group]
            if sum((spelled, name) not in reported for name in names) < 2:
                continue
            confidence, factors = export_finding_confidence()
            listed = ", ".join(f"`{name}`" for name in names[1:])
            findings.append(
                {
                    "rule_id": DUPLICATE_RULE_ID,
                    "confidence": confidence,
                    "confidence_factors": factors,
                    "name": "|".join(names),
                    "duplicate_names": names,
                    "message": (
                        f"Duplicate export: `{names[0]}` is also exported as "
                        f"{listed} (one binding under several names; keep one)"
                    ),
                    "file": spelled,
                    "line": group[1][1],
                    "type": "duplicate_export",
                    "severity": "LOW",
                    "category": "DEAD_CODE",
                }
            )
    return findings


def _mark_read(namespace, tail, read):
    key = ""
    for part in tail:
        key = f"{key}.{part}" if key else str(part)
        if key in namespace.leaves:
            read.add(key)
            return
        if key not in namespace.containers:
            return
    prefix = key + "."
    read.update(leaf for leaf in namespace.leaves if leaf.startswith(prefix))


def namespace_member_findings(surface, receipt):
    findings = []
    for path in sorted(surface.modules):
        facts = surface.modules[path].facts
        if facts is None or not facts.namespaces:
            continue
        spelled = surface.spelled.get(path, path)
        paths = surface.demand_paths.get(path, ())
        for namespace in facts.namespaces:
            reason = _namespace_abstention(surface, path, facts, namespace, paths)
            if reason:
                receipt["abstained_namespaces"].append(
                    {"file": spelled, "name": namespace.name, "reason": reason}
                )
                continue
            read = set()
            for request in paths:
                if request[0] == namespace.name:
                    _mark_read(namespace, request[1:], read)
            for local in facts.namespace_reads.get(namespace.name) or ():
                _mark_read(
                    namespace, local if isinstance(local, tuple) else (local,), read
                )
            for key in namespace.leaves:
                if key.rsplit(".", 1)[-1] in namespace.body_names:
                    read.add(key)
            receipt["checked_namespaces"] += 1
            for key, (line, kind, tagged) in sorted(
                namespace.leaves.items(), key=lambda item: item[1][0]
            ):
                if key in read or tagged or not is_reported_member_kind(kind):
                    continue
                full_name = f"{namespace.name}.{key}"
                findings.append(
                    {
                        "rule_id": NAMESPACE_MEMBER_RULE_ID,
                        "name": full_name,
                        "simple_name": key.rsplit(".", 1)[-1],
                        "full_name": full_name,
                        "namespace": namespace.name,
                        "member_kind": kind,
                        "type": "namespace_member",
                        "file": spelled,
                        "line": line,
                        "confidence": 100,
                        "severity": "LOW",
                        "category": "DEAD_CODE",
                        "references": 0,
                        "message": (
                            f"Namespace member '{full_name}' is never read "
                            "(no project file reads it from this namespace)"
                        ),
                    }
                )
    return findings


def _namespace_abstention(surface, path, facts, namespace, paths):
    if path not in surface.internal:
        return "public_module"
    if path in surface.types_public:
        return "public_type_declarations"
    if namespace.tagged:
        return "public_api_tag"
    if namespace.unsupported:
        return namespace.unsupported
    if len(facts.declarations.get(namespace.name, ())) != 1:
        return "merged_declaration"
    if any(request[0] in {_ALL, _STAR, _VALUES} for request in paths):
        return "escaping_namespace"
    requests = [request for request in paths if request[0] == namespace.name]
    if not requests:
        return "unrequested_namespace"
    if any(len(request) == 1 for request in requests):
        return "escaping_namespace"
    if facts.namespace_reads.get(namespace.name) is None:
        return "opaque_namespace_use"
    return None


def _is_tool_or_story(path):
    from .analysis import _CONFIG_FILES, _STORYBOOK_FILE_RE

    return os.path.basename(path) in _CONFIG_FILES or bool(_STORYBOOK_FILE_RE.search(path))
