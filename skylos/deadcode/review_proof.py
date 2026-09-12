"""Bounded, analyzer-owned proof snapshots for reusable dead-code reviews."""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from skylos.core.review_context import review_config_projection
from skylos.deadcode.evidence import CLASSIFICATION_POLICY


PROOF_SCHEMA = "skylos.dead-code-review-proof-v1"
_MAX_SLICE_NODES = 4_096
_MAX_SLICE_EDGES = 16_384
_MAX_SLICE_REFERENCES = 16_384
_MAX_INDEX_ITEMS = 2_000_000


@dataclass(frozen=True)
class DeadCodeReviewProofContext:
    report: Any | None
    root: Path | None
    reverse_edges: Mapping[str, frozenset[str]]
    references_by_node: Mapping[str, tuple[dict[str, Any], ...]]
    incomplete_reason: str | None = None


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _strings(values: Any, *, maximum: int = 1_024) -> list[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    result = sorted({str(value)[:500] for value in values})
    return result[:maximum]


def _mapping(value: Any, *, maximum: int = 1_024) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(value, key=lambda item: str(item))[:maximum]:
        item = value[key]
        if item is None or isinstance(item, (bool, int, float, str)):
            result[str(key)[:500]] = item if not isinstance(item, str) else item[:2_000]
    return result


def _relative_path(value: Any, root: Path) -> str | None:
    try:
        path = Path(str(value)).resolve(strict=False)
        return path.relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def prepare_dead_code_review_proofs(analyzer: Any) -> DeadCodeReviewProofContext:
    """Index shared graph inputs once for all findings in an analysis."""
    report = getattr(analyzer, "_python_reachability_report", None)
    if report is None:
        return DeadCodeReviewProofContext(None, None, {}, {})
    try:
        root = Path(report.project_root).resolve()
    except (OSError, RuntimeError, ValueError):
        return DeadCodeReviewProofContext(
            report, None, {}, {}, "invalid_project_root"
        )

    reverse: dict[str, set[str]] = defaultdict(set)
    edge_count = 0
    for edge_map in (report.graph.edges, report.graph.uncertain_edges):
        for owner, destinations in edge_map.items():
            for destination in destinations:
                edge_count += 1
                if edge_count > _MAX_INDEX_ITEMS:
                    return DeadCodeReviewProofContext(
                        report, root, {}, {}, "proof_graph_limit_exceeded"
                    )
                reverse[str(destination)].add(str(owner))

    references_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reference_count = 0
    for (path, _line), references in report.graph.references.items():
        relative = _relative_path(path, root)
        if relative is None:
            return DeadCodeReviewProofContext(
                report, root, {}, {}, "invalid_reference_path"
            )
        for reference in references:
            target = getattr(reference, "target", None)
            owner = getattr(reference, "owner", None)
            record = {
                # Line numbers are deliberately omitted so formatting-only
                # movement leaves the ownership/resolution proof unchanged.
                "file": relative,
                "name": str(getattr(reference, "name", ""))[:500],
                "target": str(target) if target is not None else None,
                "owner": str(owner) if owner is not None else None,
            }
            for node in {record["target"], record["owner"]} - {None}:
                references_by_node[str(node)].append(record)
            reference_count += 1
            if reference_count > _MAX_INDEX_ITEMS:
                return DeadCodeReviewProofContext(
                    report,
                    root,
                    {},
                    {},
                    "proof_reference_index_limit_exceeded",
                )

    return DeadCodeReviewProofContext(
        report=report,
        root=root,
        reverse_edges={key: frozenset(value) for key, value in reverse.items()},
        references_by_node={
            key: tuple(value) for key, value in references_by_node.items()
        },
    )


def _inbound_slice(
    context: DeadCodeReviewProofContext, target: str
) -> tuple[set[str], bool]:

    nodes = {target}
    pending = deque([target])
    while pending:
        destination = pending.popleft()
        for owner in context.reverse_edges.get(destination, ()):
            if owner in nodes:
                continue
            nodes.add(owner)
            if len(nodes) > _MAX_SLICE_NODES:
                return set(), False
            pending.append(owner)
    return nodes, True


def _edge_records(edge_map: Any, nodes: set[str]) -> list[list[str]] | None:
    records: list[list[str]] = []
    for owner in sorted(nodes):
        for destination in sorted(edge_map.get(owner, ())):
            if destination in nodes:
                records.append([owner, str(destination)])
                if len(records) > _MAX_SLICE_EDGES:
                    return None
    return records


def _reference_records(
    context: DeadCodeReviewProofContext, nodes: set[str]
) -> list[dict[str, Any]] | None:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for node in nodes:
        for record in context.references_by_node.get(node, ()):
            key = (
                record["file"],
                record["name"],
                record["target"] or "",
                record["owner"] or "",
            )
            unique[key] = record
            if len(unique) > _MAX_SLICE_REFERENCES:
                return None
    records = list(unique.values())
    records.sort(
        key=lambda item: (
            item["file"],
            item["name"],
            item["target"] or "",
            item["owner"] or "",
        )
    )
    return records


def build_dead_code_review_proof(
    analyzer: Any,
    key: str,
    definition: Any,
    evidence_entry: Mapping[str, Any] | None,
    *,
    threshold: int,
    context: DeadCodeReviewProofContext | None = None,
    review_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Snapshot the exact Python graph facts used for one reported symbol.

    Unsupported languages or incomplete graphs receive ``complete: false``;
    the review layer can then use a conservative repository fallback or refuse
    to persist the decision.
    """
    context = context or prepare_dead_code_review_proofs(analyzer)
    report = context.report
    suffix = Path(str(getattr(definition, "filename", ""))).suffix.lower()
    reasons: list[str] = []
    if suffix not in {".py", ".pyi", ".pyw"}:
        reasons.append("language_has_no_review_proof_slice")
    if report is None:
        reasons.append("python_reachability_unavailable")
    elif context.incomplete_reason:
        reasons.append(context.incomplete_reason)
    elif not bool(getattr(report, "complete", False)):
        reasons.extend(
            str(reason)[:500]
            for reason in getattr(report, "incomplete_reasons", ())
        )
    elif key not in getattr(report.index, "candidates", {}):
        reasons.append("definition_not_in_reachability_graph")
    if reasons:
        return {
            "schema": PROOF_SCHEMA,
            "complete": False,
            "reasons": sorted(set(reasons)),
        }

    nodes, bounded = _inbound_slice(context, key)
    proven_edges = _edge_records(report.graph.edges, nodes) if bounded else None
    uncertain_edges = (
        _edge_records(report.graph.uncertain_edges, nodes) if bounded else None
    )
    root = context.root
    references = _reference_records(context, nodes) if bounded else None
    if (
        not bounded
        or root is None
        or proven_edges is None
        or uncertain_edges is None
        or references is None
    ):
        return {
            "schema": PROOF_SCHEMA,
            "complete": False,
            "reasons": ["proof_slice_limit_exceeded"],
        }

    decision = evidence_entry.get("decision") if isinstance(evidence_entry, Mapping) else None
    analysis_scope = getattr(analyzer, "_analysis_scope", None)
    normalized_scope: dict[str, Any] = {}
    if isinstance(analysis_scope, Mapping):
        scan_path = _relative_path(analysis_scope.get("scan_path"), root)
        normalized_scope = {
            "kind": str(analysis_scope.get("kind") or "")[:120],
            "scan_path": scan_path,
            "complete_repository": bool(
                analysis_scope.get("complete_repository", False)
            ),
            "changed_files_only": bool(
                analysis_scope.get("changed_files_only", False)
            ),
            "excluded_folders": _strings(
                analysis_scope.get("excluded_folders", ())
            ),
        }
    try:
        dead_code_config = review_config_projection(
            dict(review_config) if isinstance(review_config, Mapping) else {},
            "dead_code",
        )
    except (MemoryError, RecursionError, TypeError, ValueError):
        return {
            "schema": PROOF_SCHEMA,
            "complete": False,
            "reasons": ["review_config_not_canonical"],
        }

    payload = {
        "schema": PROOF_SCHEMA,
        "policy": CLASSIFICATION_POLICY,
        "definition": {
            "key": str(key),
            "name": str(getattr(definition, "name", "")),
            "kind": str(getattr(definition, "type", "")),
            "file": _relative_path(getattr(definition, "filename", ""), root),
            "references": int(getattr(definition, "references", 0) or 0),
            "exported": bool(getattr(definition, "is_exported", False)),
            "confidence": int(getattr(definition, "confidence", 0) or 0),
            "threshold": int(threshold),
            "calls": _strings(getattr(definition, "calls", ())),
            "called_by": _strings(getattr(definition, "called_by", ())),
            "decorators": _strings(getattr(definition, "decorators", ())),
            "heuristic_refs": _mapping(
                getattr(definition, "heuristic_refs", {})
            ),
            "dynamic_signals": _strings(
                getattr(definition, "dynamic_signals", ())
            ),
            "framework_signals": _strings(
                getattr(definition, "framework_signals", ())
            ),
            "uncertainty": _strings(
                getattr(definition, "why_confidence_reduced", ())
            ),
        },
        "decision": decision if isinstance(decision, Mapping) else {},
        "analysis": {
            "scope": normalized_scope,
            "config": dead_code_config,
            "dead_code_liveness": str(
                os.environ.get("SKYLOS_DEAD_CODE_LIVENESS", "1")
            )[:40],
        },
        "graph": {
            "nodes": sorted(nodes),
            "proven_edges": proven_edges,
            "uncertain_edges": uncertain_edges,
            "roots": sorted(nodes.intersection(report.graph.roots)),
            "uncertain_roots": sorted(
                nodes.intersection(report.graph.uncertain_roots)
            ),
            "opaque_owners": sorted(nodes.intersection(report.graph.opaque_owners)),
            "reachable": sorted(nodes.intersection(report.reachable_keys)),
            "proven_reachable": sorted(
                nodes.intersection(report.proven_reachable_keys)
            ),
            "protected": sorted(nodes.intersection(report.protected_keys)),
            "protected_callbacks": sorted(
                nodes.intersection(report.protected_callback_keys)
            ),
            "unreachable": sorted(nodes.intersection(report.unreachable_keys)),
            "references": references,
        },
    }
    try:
        digest = _canonical_digest(payload)
    except (MemoryError, RecursionError, TypeError, ValueError):
        return {
            "schema": PROOF_SCHEMA,
            "complete": False,
            "reasons": ["proof_payload_not_canonical"],
        }
    return {"schema": PROOF_SCHEMA, "complete": True, "digest": digest}
