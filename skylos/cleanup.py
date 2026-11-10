"""Build a read-only cleanup queue from Skylos's existing finding evidence.

This is a report projection, not a detector or an alternative quality gate.
Task IDs identify report observations; they are not reusable review waivers.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from skylos.analysis.errors import analysis_result_incomplete
from skylos.reporting.advice_policy import prepare_advice_view
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.rules.catalog import get_rule_name
from skylos.core.safe_cache_io import read_project_text_no_symlink

_SCOPE = ("quality", "ai_defects", "dead_code")
_SEVERITIES = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARN": 2, "LOW": 3, "INFO": 4}
_DEAD_RULES = {
    "unused_functions": "SKY-U001",
    "unused_imports": "SKY-U002",
    "unused_variables": "SKY-U003",
    "unused_classes": "SKY-U004",
    "unused_parameters": "SKY-U006",
}


def build_cleanup_plan(
    result: dict[str, Any],
    *,
    project_root: str | Path,
    top: int | None = 10,
    all_advice: bool = False,
) -> dict[str, Any]:
    """Rank concrete defects/review work separately from maintainability advice.

    Preserve upstream listing decisions, severity, evidence and coverage. A
    bounded queue is never a claim that omitted findings have been resolved.
    """
    if top is not None and (type(top) is not int or top < 1):
        raise ValueError("top must be a positive integer")
    _validate_report(result)
    root = Path(project_root).resolve()
    # Legacy visibility preparation may annotate nested data. Never mutate the
    # caller's report, including when it has no versioned listing decisions.
    raw = deepcopy(result)
    view, _visibility = prepare_advice_view(
        raw, project_root=root, all_advice=all_advice
    )
    visible = {(category, id(row)) for category, row in _iter_cleanup_findings(view)}
    defaults = {
        id(row): rule
        for section, rule in _DEAD_RULES.items()
        for row in raw.get(section, [])
    }
    observed = []
    anchor_cache, source_hashes = {}, {}
    for category, finding in _iter_cleanup_findings(raw):
        if category not in _SCOPE:
            continue
        item = _task(
            finding,
            category,
            root,
            defaults.get(id(finding), ""),
            anchor_cache,
            source_hashes,
        )
        observed.append((item, (category, id(finding)) in visible))
    identities = {}
    for item, _visible in observed:
        identities.setdefault(item["id"], []).append(item)
    for base_id, duplicates in identities.items():
        if len(duplicates) > 1:
            for ordinal, item in enumerate(
                sorted(duplicates, key=lambda row: (row["file"], row["line"]))
            ):
                item["id"] = sha256(f"{base_id}:{ordinal}".encode()).hexdigest()
    tasks, advisories = [], []
    for item, is_visible in observed:
        if is_visible:
            (advisories if item["finding_type"] == "advice" else tasks).append(item)
    for rows in (tasks, advisories):
        rows.sort(key=_priority)
    limitations = _limitations(raw)
    eligible = len(observed)
    total = len(tasks) + len(advisories)
    limit = total if top is None else top
    return {
        "schema_version": 1,
        "tool": "cleanup",
        "status": "incomplete" if limitations else "ready" if total else "clear",
        "project_root": str(root),
        "scope": list(_SCOPE),
        "counts": {
            "tasks": len(tasks),
            "advisories": len(advisories),
            "shown_tasks": min(limit, len(tasks)),
            "shown_advisories": min(limit, len(advisories)),
            "optional_advice": eligible - total,
        },
        "tasks": tasks[:limit],
        "advisories": advisories[:limit],
        "groups": _groups(tasks + advisories),
        # Reconciliation observes detector inventory before presentation choices.
        # Keep only local task metadata, never source or full finding evidence.
        "_inventory": [
            {
                key: item[key]
                for key in ("id", "rule_id", "file", "name", "source_sha256")
            }
            for item, _visible in observed
        ],
        "limitations": limitations,
        "analysis_errors": deepcopy(raw["analysis_errors"]),
        "analysis_summary": deepcopy(raw["analysis_summary"]),
        "next_step": (
            "Review one task and its evidence, make a focused change, then rerun "
            "skylos cleanup on the same scope. Check behavior with the project's "
            "relevant tests before accepting the change."
        ),
    }


def _validate_report(result):
    if not isinstance(result, dict):
        raise ValueError("expected a Skylos analyzer JSON object")
    summary = result.get("analysis_summary")
    if (
        not isinstance(summary, dict)
        or type(summary.get("total_files")) is not int
        or summary["total_files"] < 0
    ):
        raise ValueError("report is missing valid analysis_summary.total_files")
    if not isinstance(result.get("analysis_errors"), list):
        raise ValueError("report is missing an analysis_errors list")
    # The canonical iterator intentionally tolerates bad rows for rendering.
    # A work queue must not silently turn malformed evidence into a clear run.
    from skylos.reporting.rollups import FINDING_SECTIONS

    for section in (
        *dict(FINDING_SECTIONS),
        "code_health",
        "circular_dependencies",
        "publisher_change_findings",
    ):
        if section not in result:
            continue
        rows = result[section]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"report has an invalid {section} findings list")
    metrics = result.get("architecture_metrics")
    if metrics is not None:
        if not isinstance(metrics, dict):
            raise ValueError("report has invalid architecture_metrics")
        if not isinstance(metrics.get("advisories", []), list):
            raise ValueError("report has invalid architecture advisories")
        for group in metrics.get("advisories", []):
            if not isinstance(group, dict) or not isinstance(
                group.get("signals"), list
            ):
                raise ValueError("report has invalid architecture advisory signals")
            if any(not isinstance(row, dict) for row in group["signals"]):
                raise ValueError("report has invalid architecture advisory signals")


def _limitations(result):
    summary = result["analysis_summary"]
    reasons = []
    if summary["total_files"] == 0:
        reasons.append("No supported source files were analyzed.")
    if analysis_result_incomplete(result):
        reasons.append(
            "Source analysis was incomplete; inspect the original scan diagnostics."
        )
    categories = summary.get("grade_categories")
    if not isinstance(categories, list):
        reasons.append("The report does not record which analyzers ran.")
    else:
        missing = [category for category in _SCOPE if category not in categories]
        if missing:
            reasons.append(
                "Analyzers not enabled in this report: " + ", ".join(missing) + "."
            )
    coverage = summary.get("ai_verification")
    if not isinstance(coverage, dict) or coverage.get("state") not in {
        "complete",
        "incomplete",
    }:
        reasons.append(
            "AI API verification coverage is missing or invalid in this report."
        )
    elif coverage["state"] != "complete":
        reasons.append(
            "AI API verification has incomplete coverage; inspect analysis_summary.ai_verification."
        )
    return reasons


def _calls_identity(finding):
    # Native call metadata is serialized from a set. Only this top-level list
    # is unordered; evidence, traces and other lists retain their full order.
    calls = finding.get("calls")
    if isinstance(calls, list) and all(isinstance(call, str) for call in calls):
        return {**finding, "calls": sorted(calls)}
    return finding


def _iter_cleanup_findings(result):
    """Match report mirrors using call-set order, then yield original rows."""
    from skylos.reporting.rollups import FINDING_SECTIONS

    projected = dict(result)
    originals = {}

    def rows(values):
        projected_rows = []
        for finding in values:
            normalized = _calls_identity(finding)
            originals[id(normalized)] = finding
            projected_rows.append(normalized)
        return projected_rows

    for section in (
        *dict(FINDING_SECTIONS),
        "circular_dependencies",
        "publisher_change_findings",
        "code_health",
    ):
        if section in result:
            projected[section] = rows(result[section])
    metrics = result.get("architecture_metrics")
    if isinstance(metrics, dict):
        projected["architecture_metrics"] = {
            **metrics,
            "advisories": [
                {**group, "signals": rows(group["signals"])}
                for group in metrics.get("advisories", [])
            ],
        }
    for category, finding in iter_result_findings(projected):
        yield category, originals[id(finding)]


def _task(finding, category, root, default_rule, anchor_cache, source_hashes):
    rule = str(finding.get("rule_id") or finding.get("id") or default_rule)
    file = str(finding.get("file") or finding.get("file_path") or "?")
    if Path(file).is_absolute():
        try:
            file = Path(file).relative_to(root).as_posix()
        except ValueError:
            pass
    line = finding.get("line") or finding.get("lineno") or 0
    try:
        line = max(0, int(line))
    except (ValueError, TypeError):
        line = 0
    name = str(finding.get("name") or finding.get("simple_name") or "")
    purpose = get_finding_type(finding, category)
    message = str(
        finding.get("message") or get_rule_name(rule, "Review unused code: " + name)
    )
    severity = str(finding.get("severity") or "LOW").upper()
    # Full observation content distinguishes evidence variants at one location.
    # IDs remain stable across repeated reads of the same report and JSON order.
    from skylos.cleanup_identity import source_anchor_digest

    source_anchor = source_anchor_digest(finding, root, cache=anchor_cache)
    if file not in source_hashes:
        source = read_project_text_no_symlink(
            root, file, max_bytes=2_000_000, newline=""
        )
        source_hashes[file] = (
            sha256(source.encode("utf-8")).hexdigest() if source is not None else None
        )
    source_sha256 = source_hashes[file]
    identity = {
        "finding": _calls_identity(finding),
        "file": file,
        "category": category,
    }
    if source_anchor:
        identity = {
            "file": file,
            "category": category,
            "rule": rule,
            "name": name,
            "anchor": source_anchor,
            "evidence": _identity_evidence(finding.get("evidence")),
        }
    anchor = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=True,
    )
    item = {
        "id": sha256(anchor.encode("utf-8")).hexdigest(),
        "rule_id": rule,
        "category": category,
        "file": file,
        "line": line,
        "name": name,
        "severity": severity,
        "finding_type": purpose,
        "message": message,
        "action": _action(category, purpose),
        "finding": deepcopy(finding),
        "source_anchor": source_anchor,
        "source_sha256": source_sha256,
    }
    if "evidence" in finding:
        item["evidence"] = deepcopy(finding["evidence"])
    return item


def _identity_evidence(value):
    if isinstance(value, dict):
        return {
            key: _identity_evidence(item)
            for key, item in value.items()
            if key not in {"line", "end_line", "col", "column", "module_import_line"}
        }
    if isinstance(value, list):
        return [_identity_evidence(item) for item in value]
    return value


def _groups(items):
    grouped = {}
    for task in items:
        key = (task["rule_id"], str(Path(task["file"]).parent))
        group = grouped.setdefault(
            key,
            {"rule_id": key[0], "directory": key[1], "task_ids": [], "files": set()},
        )
        group["task_ids"].append(task["id"])
        group["files"].add(task["file"])
    return [
        {**group, "files": sorted(group["files"]), "count": len(group["task_ids"])}
        for _, group in sorted(
            grouped.items(), key=lambda pair: (-len(pair[1]["task_ids"]), pair[0])
        )
    ]


def _action(category, purpose):
    if category == "dead_code":
        return "Check entry points, callers and dynamic use before removing this code; preserve public contracts."
    if purpose == "advice":
        return "Assess the maintainability tradeoff and preserve behavior if simplifying this code."
    if purpose == "defect":
        return "Inspect the reported defect and its evidence; fix the cause and check the affected behavior."
    return "Review the evidence in its calling context and confirm the intended behavior before changing it."


def _priority(item):
    return (
        _SEVERITIES.get(item["severity"], 5),
        0 if item["finding_type"] == "defect" else 1,
        item["file"],
        item["line"],
        item["rule_id"],
        item["id"],
    )
