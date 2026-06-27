from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from rich.progress import SpinnerColumn, TextColumn


_DEAD_CODE_CATEGORIES = (
    "unused_functions",
    "unused_imports",
    "unused_classes",
    "unused_variables",
    "unused_parameters",
)

_DEFENSE_NOTE = (
    "AI defense currently scans Python and TypeScript direct SDK integrations."
)


def _empty_defense_payload(project_path: str) -> dict[str, Any]:
    from skylos.defend.owasp import compute_owasp_coverage, normalize_owasp_selection

    owasp_framework, owasp_version = normalize_owasp_selection()
    return {
        "version": "1.0",
        "project": project_path,
        "owasp_framework": owasp_framework,
        "owasp_version": owasp_version,
        "summary": {
            "integrations_found": 0,
            "files_scanned": 0,
            "total_checks": 0,
            "passed": 0,
            "failed": 0,
            "weighted_score": 0,
            "weighted_max": 0,
            "score_pct": 100,
            "risk_rating": "SECURE",
            "by_severity": {
                sev: {"passed": 0, "failed": 0, "weight": weight}
                for sev, weight in {
                    "critical": 10,
                    "high": 7,
                    "medium": 4,
                    "low": 1,
                }.items()
            },
        },
        "integrations": [],
        "findings": [],
        "owasp_coverage": compute_owasp_coverage(
            [],
            framework=owasp_framework,
            version=owasp_version,
        ),
        "ops_score": {
            "passed": 0,
            "total": 0,
            "score_pct": 100,
            "rating": "EXCELLENT",
        },
        "note": _DEFENSE_NOTE,
    }


def _static_summary(static_result: dict[str, Any]) -> dict[str, int]:
    return {
        "dead_code": sum(
            len(static_result.get(category, []) or [])
            for category in _DEAD_CODE_CATEGORIES
        ),
        "security": len(static_result.get("danger", []) or []),
        "ai_defects": len(static_result.get("ai_defects", []) or []),
        "secrets": len(static_result.get("secrets", []) or []),
        "quality": len(static_result.get("quality", []) or []),
        "dependencies": len(static_result.get("dependency_vulnerabilities", []) or []),
    }


def _annotatable_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    categories = [
        "danger",
        "ai_defects",
        "quality",
        "secrets",
        "custom_rules",
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
        "unused_parameters",
        "dependency_vulnerabilities",
    ]
    items: list[dict[str, Any]] = []
    for category in categories:
        findings = result.get(category) or []
        for finding in findings:
            finding.setdefault("category", category)
            items.append(finding)
    return items


def _format_provenance_lines(provenance: dict[str, Any]) -> list[str]:
    if not provenance.get("enabled", True):
        return ["AI Provenance", "  Disabled"]
    if not provenance.get("available", False):
        message = provenance.get("error") or "Unavailable"
        return ["AI Provenance", f"  {message}"]

    summary = provenance.get("summary") or {}
    ai_stats = provenance.get("ai_security_stats") or {}
    return [
        "AI Provenance",
        (
            "  "
            f"AI-authored files: {summary.get('agent_count', 0)}/"
            f"{summary.get('total_files', 0)}"
        ),
        (
            "  "
            f"AI-authored findings: {ai_stats.get('ai_authored_findings', 0)} "
            f"({ai_stats.get('ai_authored_pct', 0)}%)"
        ),
    ]


def format_suite_table(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    static_summary = summary.get("static") or {}
    debt = report.get("debt") or {}
    debt_score = debt.get("score") or {}
    defense = report.get("defense") or {}
    defense_summary = defense.get("summary") or {}

    lines = [
        "",
        "Skylos Suite",
        f"Project: {report.get('project', '.')}",
        (
            "Scanned: "
            f"{summary.get('files_scanned', 0)} files | "
            f"LOC: {summary.get('total_loc', 0)}"
        ),
        "",
        "Static Analysis",
        f"  Dead code: {static_summary.get('dead_code', 0)}",
        f"  Security: {static_summary.get('security', 0)}",
        f"  Secrets: {static_summary.get('secrets', 0)}",
        f"  Quality: {static_summary.get('quality', 0)}",
        f"  Dependencies: {static_summary.get('dependencies', 0)}",
        "",
        "Technical Debt",
        (
            "  "
            f"Score: {debt_score.get('score_pct', 100)}% "
            f"({debt_score.get('risk_rating', 'LOW')})"
        ),
        f"  Hotspots: {len(debt.get('hotspots', []) or [])}",
        "",
        "AI Defense",
        f"  Integrations: {defense_summary.get('integrations_found', 0)}",
        (
            "  "
            f"Score: {defense_summary.get('score_pct', 100)}% "
            f"({defense_summary.get('risk_rating', 'SECURE')})"
        ),
        f"  Failed checks: {defense_summary.get('failed', 0)}",
        f"  Coverage: {defense.get('note', _DEFENSE_NOTE)}",
        "",
    ]

    lines.extend(_format_provenance_lines(report.get("provenance") or {}))
    lines.append("")
    return "\n".join(lines)


def format_suite_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)


def run_suite(
    target: str | Path,
    *,
    conf: int,
    exclude_folders: list[str] | set[str] | None,
    run_analyze_func,
    progress_factory,
    console,
    output_json: bool,
    no_provenance: bool = False,
    diff_base: str | None = None,
    get_git_root_func=None,
) -> dict[str, Any]:
    """
    Build the combined static, debt, defense, and provenance suite report.

    Calls: skylos/debt/__init__.py build_debt_snapshot;
        skylos/discover/detector.py detect_integrations;
        skylos/defend/engine.py run_defense_checks;
        skylos/reporting/provenance.py analyze_provenance.
        
    Called from: skylos/commands/suite_cmd.py run_suite_command.
    """
    target_path = Path(target).resolve()
    exclude = set(exclude_folders or [])

    from skylos.debt import build_debt_snapshot
    from skylos.defend.engine import run_defense_checks
    from skylos.defend.policy import compute_owasp_coverage
    from skylos.defend.report import format_defense_json
    from skylos.discover.detector import _collect_ai_files, detect_integrations

    analyzer_logger = logging.getLogger("Skylos")
    original_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.ERROR)
    try:
        with progress_factory(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
            disable=output_json,
        ) as progress:
            progress.add_task("Running static analysis...", total=None)
            static_raw = run_analyze_func(
                str(target_path),
                conf=conf,
                enable_secrets=True,
                enable_danger=True,
                enable_quality=True,
                exclude_folders=sorted(exclude),
            )
    finally:
        analyzer_logger.setLevel(original_level)

    static_result = (
        json.loads(static_raw) if isinstance(static_raw, str) else static_raw
    )

    try:
        from skylos.rules.sca.vulnerability_scanner import scan_dependencies

        sca_findings = scan_dependencies(target_path)
        if sca_findings:
            try:
                from skylos.rules.sca.reachability import enrich_with_reachability

                sca_findings = enrich_with_reachability(sca_findings, target_path)
            except Exception:
                pass
            static_result["dependency_vulnerabilities"] = sca_findings
            static_result.setdefault("analysis_summary", {})["sca_count"] = len(
                sca_findings
            )
    except Exception:
        pass

    debt_snapshot = build_debt_snapshot(static_result, project_root=target_path)
    try:
        from skylos.cloud.project_context import project_context_for_upload

        git_root = get_git_root_func() if get_git_root_func else None
        upload_context = project_context_for_upload(target_path, git_root)
        static_result["project_root"] = upload_context["project_root"]
        static_result.setdefault("analysis_summary", {})["project_root"] = (
            upload_context["project_root"]
        )
    except Exception:
        upload_context = {"project_root": ""}

    provenance_section: dict[str, Any] = {
        "enabled": not no_provenance,
        "available": False,
        "summary": None,
        "ai_security_stats": None,
    }
    static_result["provenance"] = None
    if not no_provenance:
        try:
            from skylos.core.file_discovery import find_git_root
            from skylos.reporting.provenance import (
                analyze_provenance,
                annotate_findings_with_provenance,
                compute_ai_security_stats,
            )

            git_root = str(find_git_root(target_path) or "")
            if not git_root and get_git_root_func is not None:
                git_root = get_git_root_func() or ""
            if not git_root:
                raise RuntimeError("not a git repository")
            with progress_factory(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
                disable=output_json,
            ) as progress:
                progress.add_task("Analyzing AI provenance...", total=None)
                provenance_report = analyze_provenance(git_root, base_ref=diff_base)

            annotatable = _annotatable_findings(static_result)
            annotate_findings_with_provenance(annotatable, provenance_report)
            ai_stats = compute_ai_security_stats(annotatable)
            static_result["ai_security_stats"] = ai_stats
            static_result["provenance_summary"] = provenance_report.summary
            static_result["provenance"] = provenance_report.to_dict()
            provenance_section.update(
                {
                    "available": True,
                    "summary": provenance_report.summary,
                    "ai_security_stats": ai_stats,
                }
            )
        except Exception as exc:
            provenance_section["error"] = str(exc)

    policy = None

    with progress_factory(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
        disable=output_json,
    ) as progress:
        progress.add_task("Scanning AI defenses...", total=None)
        files = _collect_ai_files(target_path, exclude)
        integrations, graph = detect_integrations(target_path, exclude_folders=exclude)

    if integrations:
        results, score, ops_score = run_defense_checks(
            integrations,
            graph,
            policy=policy,
            min_severity=None,
            owasp_filter=None,
        )
        owasp_coverage = compute_owasp_coverage(results)
        defense_report = json.loads(
            format_defense_json(
                results,
                score,
                len(integrations),
                len(files),
                str(target_path),
                owasp_coverage,
                ops_score,
                integrations=integrations,
                owasp_framework="llm",
                owasp_version="2025",
            )
        )
        defense_report["note"] = _DEFENSE_NOTE
    else:
        defense_report = _empty_defense_payload(str(target_path))

    static_summary = _static_summary(static_result)
    return {
        "version": "1.0",
        "project": str(target_path),
        "project_root": upload_context["project_root"],
        "summary": {
            "files_scanned": int(
                (static_result.get("analysis_summary") or {}).get("total_files") or 0
            ),
            "total_loc": int(
                (static_result.get("analysis_summary") or {}).get("total_loc") or 0
            ),
            "static": static_summary,
            "debt_score_pct": debt_snapshot.score.score_pct,
            "debt_hotspots": len(debt_snapshot.hotspots),
            "defense_score_pct": int(
                (defense_report.get("summary") or {}).get("score_pct") or 0
            ),
            "integrations_found": int(
                (defense_report.get("summary") or {}).get("integrations_found") or 0
            ),
            "provenance_available": provenance_section.get("available", False),
        },
        "static": static_result,
        "debt": debt_snapshot.to_dict(),
        "defense": defense_report,
        "provenance": provenance_section,
    }
