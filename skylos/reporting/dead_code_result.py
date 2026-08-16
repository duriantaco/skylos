from __future__ import annotations

from pathlib import Path


REPORTABLE_DEAD_CODE_CLASSIFICATIONS = {
    "dead",
    "likely_dead",
    "validated_dead",
}


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


def dead_code_evidence(analyzer, path, pyproject_entrypoint_qnames, threshold=None):
    evidence_root = getattr(analyzer, "_project_root", None)
    if evidence_root is None:
        evidence_root = Path(_primary_path(path))
        if evidence_root.is_file():
            evidence_root = evidence_root.parent

    from skylos.deadcode.evidence import (
        EvidenceEvent,
        EvidenceKind,
        SymbolKey,
        build_dead_code_evidence,
    )

    ledger = build_dead_code_evidence(
        analyzer.defs,
        project_root=evidence_root,
        pyproject_entrypoint_qnames=pyproject_entrypoint_qnames,
        threshold=threshold,
    )
    for finding in getattr(analyzer, "_grep_verify_incomplete_candidates", ()):
        ledger.add(
            SymbolKey.from_finding(finding),
            EvidenceEvent(
                kind=EvidenceKind.UNCERTAINTY,
                reason="grep verification did not complete",
                source="grep_verify",
            ),
        )
    return ledger, ledger.to_dict(
        evidence_root,
        definitions=analyzer.defs,
        threshold=threshold,
    )


def _evidence_by_name(dead_code_evidence_payload):
    by_name = {}
    for entry in dead_code_evidence_payload.get("symbols", []):
        by_name.setdefault(entry["qualified_name"], []).append(entry)
    return by_name


def _evidence_for_definition(evidence_by_name, definition):
    candidates = evidence_by_name.get(getattr(definition, "name", ""), [])
    if not candidates:
        return None

    definition_file = _normalized_file(getattr(definition, "filename", ""))
    file_matches = [
        entry
        for entry in candidates
        if _files_identify_same_source(entry.get("file"), definition_file)
    ]
    definition_line = getattr(definition, "line", 0) or 0
    definition_kind = str(getattr(definition, "type", ""))

    if len(candidates) == 1:
        entry = candidates[0]
        if entry.get("file") and not file_matches:
            return None
        if entry.get("kind") and str(entry["kind"]) != definition_kind:
            return None
        if (
            entry.get("line")
            and definition_line
            and entry["line"] != definition_line
        ):
            return None
        return entry

    narrowed = file_matches
    if not narrowed:
        return None
    exact_matches = [
        entry
        for entry in narrowed
        if (entry.get("line", 0) or 0) == definition_line
        and str(entry.get("kind", "")) == definition_kind
    ]
    if len(exact_matches) == 1:
        return exact_matches[0]
    return None


def _normalized_file(value):
    return Path(str(value or "")).as_posix().removeprefix("./")


def _files_identify_same_source(entry_file, definition_file):
    entry_path = _normalized_file(entry_file)
    if not entry_path or not definition_file:
        return False
    if entry_path == definition_file:
        return True
    if not Path(entry_path).is_absolute():
        return definition_file.endswith(f"/{entry_path}")
    return False


def _attach_evidence(target: dict, definition, evidence_by_name) -> None:
    entry = _evidence_for_definition(evidence_by_name, definition)
    if not entry:
        return
    target["dead_code_classification"] = entry["classification"]
    target["dead_code_evidence"] = list(entry.get("evidence") or [])
    decision = entry.get("decision") or {}
    if isinstance(decision, dict):
        target["dead_code_decision"] = dict(decision)
        target["dead_code_reason"] = decision.get("primary_reason")
        target["dead_code_reason_tags"] = list(decision.get("reason_tags") or [])


def _candidate_disposition(definition, thr, evidence_by_name):
    if not _is_dead_definition(definition, thr):
        return None

    entry = _evidence_for_definition(evidence_by_name, definition)
    if not isinstance(entry, dict):
        return "reported"

    classification = str(entry.get("classification") or "")
    if classification == "alive":
        return "rescued"
    if classification == "uncertain":
        return "abstained"
    if classification in REPORTABLE_DEAD_CODE_CLASSIFICATIONS:
        return "reported"

    # Unknown evidence states must not become destructive dead-code findings.
    return "abstained"


def _is_dead_definition(definition, thr):
    if definition.references != 0:
        return False
    if definition.is_exported:
        return False
    if definition.confidence <= 0:
        return False
    return definition.confidence >= thr


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
    reported, _, _ = dead_code_candidate_decisions(
        analyzer,
        thr,
        dead_code_evidence_payload,
    )
    return reported


def dead_code_candidate_decisions(analyzer, thr, dead_code_evidence_payload):
    evidence_by_name = _evidence_by_name(dead_code_evidence_payload)
    scoped_keys = getattr(analyzer, "_dead_code_scope_keys", None)
    dispositions = {}
    for key, definition in analyzer.defs.items():
        if scoped_keys is not None and key not in scoped_keys:
            dispositions[key] = None
            continue
        dispositions[key] = _candidate_disposition(
            definition,
            thr,
            evidence_by_name,
        )

    reported = []
    rescued = []
    abstained = []
    reported_classes = {
        key
        for key, definition in analyzer.defs.items()
        if definition.type in ("class", "type")
        and dispositions.get(key) == "reported"
    }
    class_keys = _class_key_by_name_file(analyzer)
    for key, definition in analyzer.defs.items():
        disposition = dispositions.get(key)
        if disposition is None:
            continue
        owner_key = _method_owner_key(definition, class_keys)
        if disposition == "reported" and owner_key in reported_classes:
            continue
        item = definition.to_dict()
        _attach_evidence(item, definition, evidence_by_name)
        item["dead_code_disposition"] = disposition
        if disposition == "reported":
            reported.append(item)
        elif disposition == "rescued":
            rescued.append(item)
        else:
            abstained.append(item)
    return reported, rescued, abstained


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
