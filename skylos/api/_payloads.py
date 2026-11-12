from pathlib import Path
from typing import Any
import json

from skylos.deadcode.finding_evidence import dead_code_finding_evidence_payload


__all__ = [
    "_build_legacy_payload",
    "_build_report_scan_summary",
    "_coerce_debt_snapshot_dict",
    "_compact_finding_metadata",
    "_compact_upload_finding",
    "_extract_workspace_upload_metadata",
    "_infer_upload_project_root",
    "_int_upload_value",
    "_json_size_bytes",
    "_truncate_upload_text",
]


def _json_size_bytes(payload: Any) -> int:
    return len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _coerce_debt_snapshot_dict(debt_report) -> dict[str, Any]:
    if isinstance(debt_report, dict):
        return dict(debt_report)
    to_dict = getattr(debt_report, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, dict):
            return dict(payload)
    raise TypeError("Debt report must be a dict or expose to_dict().")


def _infer_upload_project_root(payload, git_root) -> str | None:
    if not isinstance(payload, dict):
        return None

    candidates = []
    for key in ("project_root", "repo_subpath"):
        if key in payload:
            candidates.append(payload.get(key))
    summary = payload.get("analysis_summary")
    if isinstance(summary, dict) and "project_root" in summary:
        candidates.append(summary.get("project_root"))
    if "project" in payload:
        candidates.append(payload.get("project"))

    try:
        from skylos.cloud.project_context import (
            normalize_repo_subpath,
            repo_subpath_for_project,
        )
    except ImportError:
        return None

    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, str):
            if candidate.strip() == "":
                return ""
            if Path(candidate).is_absolute():
                return repo_subpath_for_project(candidate, git_root)
            normalized = normalize_repo_subpath(candidate)
            if normalized is not None:
                return normalized
    return None


def _extract_workspace_upload_metadata(payload) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    workspace_data = payload.get("workspaces")
    if not isinstance(workspace_data, dict):
        return None
    if not _has_workspace_report(workspace_data):
        return None

    root_package = _compact_workspace_package(workspace_data.get("root_package"))
    packages = _compact_workspace_packages(workspace_data.get("packages", []))
    diagnostics = _compact_workspace_diagnostics(workspace_data.get("diagnostics", []))

    return {
        "is_monorepo": bool(workspace_data.get("is_monorepo")),
        "package_count": int(workspace_data.get("package_count") or len(packages)),
        "total_packages": int(
            workspace_data.get("total_packages")
            or len(packages) + (1 if root_package else 0)
        ),
        "diagnostic_count": int(
            workspace_data.get("diagnostic_count") or len(diagnostics)
        ),
        "root_package": root_package,
        "packages": packages,
        "diagnostics": diagnostics[:20],
        "declared_patterns": _string_list(workspace_data.get("declared_patterns", [])),
        "tsconfig_references": _string_list(
            workspace_data.get("tsconfig_references", [])
        ),
    }


def _has_workspace_report(workspace_data: dict[str, Any]) -> bool:
    return bool(
        workspace_data.get("root_package")
        or workspace_data.get("packages")
        or workspace_data.get("diagnostics")
    )


def _compact_workspace_package(pkg) -> dict[str, Any] | None:
    if not isinstance(pkg, dict):
        return None
    out = {
        "name": pkg.get("name"),
        "relative_path": pkg.get("relative_path"),
        "is_root": bool(pkg.get("is_root")),
        "is_internal_dependency": bool(pkg.get("is_internal_dependency")),
        "has_package_json": bool(pkg.get("has_package_json", True)),
    }
    sources = pkg.get("discovered_from")
    if isinstance(sources, list):
        out["discovered_from"] = [str(item) for item in sources]
    return out


def _compact_workspace_packages(packages) -> list[dict[str, Any]]:
    return [
        pkg
        for pkg in (_compact_workspace_package(item) for item in packages)
        if pkg is not None
    ]


def _compact_workspace_diagnostics(diagnostics) -> list[dict[str, Any]]:
    return [
        {
            "kind": diag.get("kind"),
            "relative_path": diag.get("relative_path"),
            "message": diag.get("message"),
        }
        for diag in diagnostics
        if isinstance(diag, dict)
    ]


def _string_list(items) -> list[str]:
    return [str(item) for item in items]


def _truncate_upload_text(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= max_len else text[:max_len] + "..."


_VERIFICATION_LEVELS = {"traced", "ai_verified", "refuted", "unverified"}


def _compact_verification(value: Any) -> dict[str, Any] | None:
    """The evidence level record from `skylos.llm.finding_verification`, bounded."""
    if not isinstance(value, dict) or value.get("level") not in _VERIFICATION_LEVELS:
        return None
    votes = value.get("votes") if isinstance(value.get("votes"), dict) else {}
    compact: dict[str, Any] = {
        "level": value["level"],
        "runs": _int_upload_value(value.get("runs")),
        "votes": {
            key: _int_upload_value(votes.get(key))
            for key in ("supported", "refuted", "uncertain")
        },
    }
    if value.get("disputed") is True:
        compact["disputed"] = True
    for key, limit in (("reason", 500), ("proof_kind", 64), ("model", 128)):
        text = _truncate_upload_text(value.get(key), limit)
        if text:
            compact[key] = text
    lines = value.get("proof_lines")
    if isinstance(lines, list):
        compact["proof_lines"] = [
            line for line in lines if isinstance(line, int) and line > 0
        ][:20]
    return compact


_PROVENANCE_KEYS = ("sql_provenance", "redirect_provenance", "path_provenance")
_PROVENANCE_CHAIN_KINDS = ("untrusted", "unknown", "incomplete", "operator")
_PROVENANCE_CHAIN_LIMIT = 3
_PROVENANCE_STEP_LIMIT = 16
_PROVENANCE_TEXT_LIMIT = 300
_REACHABILITY_KEYS = (
    "reachability_verdict",
    "reachability_reason",
    "reachability_tier",
    "reachability_imported_as",
)
_REACHABILITY_TEXT_LIMIT = 300
_COMPACT_SNIPPET_LIMIT = 2000


def _compact_provenance(record: Any) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    compact: dict[str, Any] = {}
    for key in ("version", "status", "complete_project", "safety_proven"):
        value = record.get(key)
        if isinstance(value, (bool, int)):
            compact[key] = value
        elif isinstance(value, str) and value:
            compact[key] = _truncate_upload_text(value, 64)
    function = record.get("function")
    if isinstance(function, str) and function:
        compact["function"] = _truncate_upload_text(function, _PROVENANCE_TEXT_LIMIT)
    for kind in _PROVENANCE_CHAIN_KINDS:
        chains = record.get(kind)
        if not isinstance(chains, list):
            continue
        kept = []
        for chain in chains[:_PROVENANCE_CHAIN_LIMIT]:
            if not isinstance(chain, list):
                continue
            kept.append(
                [
                    _truncate_upload_text(step, _PROVENANCE_TEXT_LIMIT)
                    for step in chain[:_PROVENANCE_STEP_LIMIT]
                    if isinstance(step, str)
                ]
            )
        if kept:
            compact[kind] = kept
    return compact or None


def _trace_step_locations(trace: Any) -> Any:
    if not isinstance(trace, dict) or not isinstance(trace.get("steps"), list):
        return trace
    steps = []
    for step in trace["steps"]:
        if isinstance(step, dict) and "snippet" in step:
            step = {key: value for key, value in step.items() if key != "snippet"}
        steps.append(step)
    return {**trace, "steps": steps}


def _compact_finding_metadata(metadata: Any) -> dict[str, Any] | None:
    if not isinstance(metadata, dict):
        return None

    keep_keys = {
        "source",
        "confidence",
        "llm_verdict",
        "llm_challenged",
        "ai_review",
        "needs_review",
        "blame_email",
        "package_name",
        "package_version",
        "version_spec",
        "exact",
        "dependency_section",
        "dependency_optional",
        "peer_dependency_optional",
        "ecosystem",
        "vuln_id",
        "display_id",
        "affected_range",
        "fixed_version",
        "cvss_score",
        "fingerprint_version",
        "stable_fingerprint",
        "context_hash",
        "rule_revision",
        "language",
        "symbol",
        "review_decision",
        "listing",
        "security_evidence",
        "security_trace",
        "receiver_resolution",
        "source_status",
    }
    compact = {key: metadata[key] for key in keep_keys if key in metadata}
    for key in _PROVENANCE_KEYS:
        provenance = _compact_provenance(metadata.get(key))
        if provenance is not None:
            compact[key] = provenance
    for key in _REACHABILITY_KEYS:
        value = metadata.get(key)
        if isinstance(value, (bool, int)):
            compact[key] = value
        elif isinstance(value, str) and value:
            compact[key] = _truncate_upload_text(value, _REACHABILITY_TEXT_LIMIT)
    from skylos.rules.sca.threat_intel import finding_cves, normalize_risk_context

    risk_context = normalize_risk_context(
        metadata.get("risk_context"), allowed_cves=finding_cves({"metadata": metadata})
    )
    if risk_context is not None:
        compact["risk_context"] = risk_context
    if (
        metadata.get("ecosystem") == "npm"
        and metadata.get("vuln_id")
        and metadata.get("malicious") is not True
        and "import_usage" in metadata
    ):
        from skylos.rules.sca.npm_import_usage import normalize_npm_import_usage

        import_usage = normalize_npm_import_usage(metadata["import_usage"])
        if import_usage is not None:
            compact["import_usage"] = import_usage
    verification = _compact_verification(metadata.get("verification"))
    if verification:
        compact["verification"] = verification
    aliases = metadata.get("aliases")
    if isinstance(aliases, list):
        compact["aliases"] = aliases[:5]
        if risk_context:
            compact["aliases"] = list(compact["aliases"])
            for row in risk_context["cves"]:
                if row["cve_id"] not in compact["aliases"]:
                    compact["aliases"].append(row["cve_id"])
    return compact or None


def _int_upload_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _compact_file_path(finding: dict[str, Any]) -> str:
    # An empty file_path is the upload pre-flight's "no location"; keep it
    # empty instead of inventing an "unknown" file.
    if finding.get("file_path") == "":
        return ""
    return str(finding.get("file_path") or finding.get("file") or "unknown")


_UPLOAD_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


def _upload_severity(value: Any) -> str:
    severity = str(value or "").strip().upper()
    if severity in _UPLOAD_SEVERITIES:
        return severity
    return "MEDIUM"


def _compact_upload_finding(
    finding: dict[str, Any],
    *,
    include_snippet: bool,
) -> dict[str, Any]:
    compact = {
        "rule_id": str(finding.get("rule_id") or "UNKNOWN")[:100],
        "file_path": _compact_file_path(finding),
        "line_number": _int_upload_value(
            finding.get("line_number") or finding.get("line") or 0
        ),
        "message": _truncate_upload_text(finding.get("message"), 500),
        "severity": _upload_severity(finding.get("severity")),
        "category": str(finding.get("category") or "QUALITY").upper(),
    }
    tool_rule_id = finding.get("tool_rule_id")
    if finding.get("kind") == "repo_policy" and finding.get("rule_id") in {
        "SKY-R101",
        "SKY-R102",
        "SKY-R103",
        "SKY-R104",
    }:
        compact["kind"] = "repo_policy"
    if tool_rule_id:
        compact["tool_rule_id"] = str(tool_rule_id)[:100]
    if include_snippet and compact["category"] != "SECRET":
        snippet = finding.get("snippet")
        if isinstance(snippet, str) and snippet:
            compact["snippet"] = snippet[:_COMPACT_SNIPPET_LIMIT]
    metadata = _compact_finding_metadata(finding.get("metadata"))
    if metadata is not None and not include_snippet and "security_trace" in metadata:
        metadata["security_trace"] = _trace_step_locations(metadata["security_trace"])
    if compact["category"] == "QUALITY":
        from skylos.reporting.sarif import finding_measure

        measure = finding_measure(finding)
        if measure is not None:
            if metadata is None:
                metadata = {}
            metadata["measure"] = measure
    from skylos.reporting.listing import listing_decision

    listing = listing_decision(finding)
    if listing is not None:
        compact["listing"] = dict(listing)
    dead_code_evidence = dead_code_finding_evidence_payload(
        finding,
        max_events=8,
    )
    if dead_code_evidence is not None:
        if metadata is None:
            metadata = {}
        metadata["dead_code_evidence"] = dead_code_evidence
    if metadata:
        compact["metadata"] = metadata
    return compact


def _build_legacy_payload(core_payload, definitions) -> dict[str, Any]:
    legacy_payload = dict(core_payload)
    legacy_payload["definitions"] = definitions
    return legacy_payload


def _build_report_scan_summary(
    all_findings: list[dict], core_payload: dict[str, Any], definitions
) -> dict[str, int]:
    runs = core_payload.get("runs") or []
    summary = {
        "finding_count": len(all_findings),
        "sarif_result_count": sum(len(run.get("results") or []) for run in runs),
        "sarif_rule_count": sum(
            len((run.get("tool") or {}).get("driver", {}).get("rules") or [])
            for run in runs
        ),
        "definitions_count": len(definitions or {}),
    }
    from skylos.reporting.listing import is_listed, listing_decision

    if any(listing_decision(row) is not None for row in all_findings):
        summary["listing_policy_version"] = 1
        summary["listed_finding_count"] = sum(
            is_listed(row, row.get("category")) for row in all_findings
        )
        summary["unlisted_finding_count"] = (
            len(all_findings) - summary["listed_finding_count"]
        )
    return summary
