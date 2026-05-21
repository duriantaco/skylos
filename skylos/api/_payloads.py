from pathlib import Path
from typing import Any
import json


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


def _compact_finding_metadata(metadata: Any) -> dict[str, Any] | None:
    if not isinstance(metadata, dict):
        return None

    keep_keys = {
        "source",
        "confidence",
        "llm_verdict",
        "llm_challenged",
        "needs_review",
        "blame_email",
        "package_name",
        "package_version",
        "ecosystem",
        "vuln_id",
        "display_id",
        "affected_range",
        "fixed_version",
        "cvss_score",
    }
    compact = {key: metadata[key] for key in keep_keys if key in metadata}
    aliases = metadata.get("aliases")
    if isinstance(aliases, list):
        compact["aliases"] = aliases[:5]
    return compact or None


def _int_upload_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _compact_upload_finding(
    finding: dict[str, Any],
    *,
    include_snippet: bool,
) -> dict[str, Any]:
    compact = {
        "rule_id": str(finding.get("rule_id") or "UNKNOWN")[:100],
        "file_path": str(finding.get("file_path") or finding.get("file") or "unknown"),
        "line_number": _int_upload_value(
            finding.get("line_number") or finding.get("line") or 0
        ),
        "message": _truncate_upload_text(finding.get("message"), 500),
        "severity": str(finding.get("severity") or "MEDIUM").upper(),
        "category": str(finding.get("category") or "QUALITY").upper(),
    }
    tool_rule_id = finding.get("tool_rule_id")
    if tool_rule_id:
        compact["tool_rule_id"] = str(tool_rule_id)[:100]
    if include_snippet and compact["category"] != "SECRET":
        snippet = _truncate_upload_text(finding.get("snippet"), 240)
        if snippet:
            compact["snippet"] = snippet
    metadata = _compact_finding_metadata(finding.get("metadata"))
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
    return {
        "finding_count": len(all_findings),
        "sarif_result_count": sum(len(run.get("results") or []) for run in runs),
        "sarif_rule_count": sum(
            len((run.get("tool") or {}).get("driver", {}).get("rules") or [])
            for run in runs
        ),
        "definitions_count": len(definitions or {}),
    }
