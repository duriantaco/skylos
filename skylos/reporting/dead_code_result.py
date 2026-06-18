from __future__ import annotations

from pathlib import Path


def _primary_path(path):
    if not isinstance(path, (list, tuple)):
        return path

    for item in path:
        return item

    return "."


def _sorted_values(values):
    if not values:
        return []
    return sorted(values)


def dead_code_evidence(analyzer, path, pyproject_entrypoint_qnames):
    evidence_root = getattr(analyzer, "_project_root", None)
    if evidence_root is None:
        evidence_root = Path(_primary_path(path))
        if evidence_root.is_file():
            evidence_root = evidence_root.parent

    from skylos.deadcode.evidence import build_dead_code_evidence

    ledger = build_dead_code_evidence(
        analyzer.defs,
        project_root=evidence_root,
        pyproject_entrypoint_qnames=pyproject_entrypoint_qnames,
    )
    return ledger, ledger.to_dict(evidence_root)


def _evidence_by_name(dead_code_evidence_payload):
    by_name = {}
    for entry in dead_code_evidence_payload.get("symbols", []):
        by_name[entry["qualified_name"]] = entry
    return by_name


def _attach_evidence(target: dict, definition, evidence_by_name) -> None:
    entry = evidence_by_name.get(getattr(definition, "name", ""))
    if not entry:
        return
    target["dead_code_classification"] = entry["classification"]
    target["dead_code_evidence"] = list(entry.get("evidence") or [])


def _is_dead_definition(definition, thr):
    if definition.references != 0:
        return False
    if definition.is_exported:
        return False
    if definition.confidence <= 0:
        return False
    return definition.confidence >= thr


def _dead_class_keys(analyzer, thr):
    keys = set()
    for key, definition in analyzer.defs.items():
        if definition.type not in ("class", "type"):
            continue
        if _is_dead_definition(definition, thr):
            keys.add(key)
    return keys


def _class_key_by_name_file(analyzer):
    by_name_file = {}
    for key, definition in analyzer.defs.items():
        if definition.type not in ("class", "type"):
            continue
        filename = str(Path(definition.filename).resolve())
        by_name_file[(definition.name, filename)] = key
    return by_name_file


def _method_owner_key(definition, class_keys):
    if definition.type != "method":
        return None
    if "." not in definition.name:
        return None
    owner = definition.name.rsplit(".", 1)[0]
    filename = str(Path(definition.filename).resolve())
    return class_keys.get((owner, filename))


def unused_definitions(analyzer, thr, dead_code_evidence_payload):
    evidence_by_name = _evidence_by_name(dead_code_evidence_payload)
    unused = []
    dead_classes = _dead_class_keys(analyzer, thr)
    class_keys = _class_key_by_name_file(analyzer)
    for definition in analyzer.defs.values():
        if not _is_dead_definition(definition, thr):
            continue
        owner_key = _method_owner_key(definition, class_keys)
        if owner_key in dead_classes:
            continue
        item = definition.to_dict()
        _attach_evidence(item, definition, evidence_by_name)
        unused.append(item)
    return unused


def _definition_loc(definition):
    node = getattr(definition, "node", None)
    if node is None:
        return 1
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is None or end is None:
        return 1
    return max(1, end - start + 1)


def _context_entry(definition, thr, evidence_by_name):
    entry = {
        "name": definition.name,
        "file": str(definition.filename),
        "line": definition.line,
        "type": definition.type,
        "loc": _definition_loc(definition),
        "complexity": getattr(definition, "complexity", 1),
        "calls": _sorted_values(definition.calls),
        "called_by": _sorted_values(definition.called_by),
        "dead": _is_dead_definition(definition, thr),
    }
    _attach_evidence(entry, definition, evidence_by_name)
    return entry


def definition_context(analyzer, thr, dead_code_evidence_payload):
    evidence_by_name = _evidence_by_name(dead_code_evidence_payload)
    context = {}
    for name, definition in analyzer.defs.items():
        if definition.type not in ("class", "function", "method"):
            continue
        if name.startswith("_"):
            continue
        context[name] = _context_entry(definition, thr, evidence_by_name)
    return context


def whitelisted_definitions(analyzer, all_suppressed):
    whitelisted = []
    for definition in analyzer.defs.values():
        reason = getattr(definition, "skip_reason", None)
        if not reason:
            continue
        entry = _whitelist_entry(definition)
        whitelisted.append(entry)
        if reason == "inline ignore comment":
            all_suppressed.append(entry)
    return whitelisted


def _whitelist_entry(definition):
    return {
        "name": definition.simple_name,
        "file": str(definition.filename),
        "line": definition.line,
        "reason": definition.skip_reason,
        "category": "dead_code",
        "suppression_code": getattr(definition, "suppression_code", None),
        "folder_role": getattr(definition, "folder_role", None),
    }
