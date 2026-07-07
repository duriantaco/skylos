from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from skylos.defend.result import DefenseResult, DefenseScore, OpsScore
from skylos.defend.scoring import compute_defense_score, SEVERITY_WEIGHTS
from skylos.defend.owasp import (
    DEFAULT_OWASP_FRAMEWORK,
    normalize_owasp_selection,
    owasp_report_label,
)


def format_defense_table(
    results: list[DefenseResult],
    score: DefenseScore,
    integrations_count: int = 0,
    files_scanned: int = 0,
    owasp_coverage: dict | None = None,
    ops_score: OpsScore | None = None,
    owasp_framework: str | None = DEFAULT_OWASP_FRAMEWORK,
    owasp_version: str | int | None = None,
) -> str:
    lines = []

    width = 74
    lines.append("")
    lines.append("┌" + "─" * width + "┐")
    lines.append(f"│ {'Skylos AI Defense Report':<{width - 1}}│")
    summary = (
        f"Scanned: {files_scanned} files | "
        f"Found: {integrations_count} LLM integration(s) | "
        f"Score: {score.score_pct}% ({score.risk_rating})"
    )
    lines.append(f"│ {summary:<{width - 1}}│")
    lines.append("├" + "─" * width + "┤")

    by_integration: dict[str, list[DefenseResult]] = defaultdict(list)
    for r in results:
        by_integration[r.integration_location].append(r)

    idx = 0
    for integ_loc, integ_results in by_integration.items():
        idx += 1
        integ_score = compute_defense_score(integ_results)

        lines.append("")
        lines.append(f"Integration {idx}: {integ_loc}")
        lines.append(
            f"  Weighted Score: {integ_score.weighted_score}/{integ_score.weighted_max} "
            f"({integ_score.score_pct}%) — {integ_score.risk_rating} RISK"
        )

        sorted_results = sorted(integ_results, key=lambda r: (r.passed, -r.weight))

        for r in sorted_results:
            mark = "✓" if r.passed else "✗"
            weight_str = f"[+{r.weight}]" if r.passed else f"[-{r.weight}]"
            lines.append(f"  {mark} {r.plugin_id:<24} {r.message:<40} {weight_str}")

    lines.append("")
    lines.append("─" * 74)
    lines.append("")
    lines.append(f"AI Defense Score: {score.score_pct}% ({score.risk_rating})")
    lines.append(
        f"  {score.weighted_score}/{score.weighted_max} weighted points | "
        f"{score.passed}/{score.total} checks passing"
    )

    if ops_score and ops_score.total > 0:
        lines.append("")
        lines.append(f"AI Ops Score: {ops_score.score_pct}% ({ops_score.rating})")
        lines.append(f"  {ops_score.passed}/{ops_score.total} ops checks passing")

    if owasp_coverage:
        lines.append("")
        lines.append(f"{owasp_report_label(owasp_framework, owasp_version)} Coverage:")
        for owasp_id, info in owasp_coverage.items():
            if info["status"] == "not_applicable":
                continue
            status_icon = {
                "covered": "✓",
                "partial": "◐",
                "uncovered": "✗",
            }.get(info["status"], "?")
            if info["coverage_pct"] is not None:
                pct_str = f"{info['coverage_pct']}%"
            else:
                pct_str = "N/A"
            lines.append(
                f"  {status_icon} {owasp_id} {info['name']:<35} {pct_str:>5} "
                f"({info['passed']}/{info['total']})"
            )

    lines.append("")
    return "\n".join(lines)


def format_defense_json(
    results: list[DefenseResult],
    score: DefenseScore,
    integrations_count: int = 0,
    files_scanned: int = 0,
    project_path: str = ".",
    owasp_coverage: dict | None = None,
    ops_score: OpsScore | None = None,
    integrations: list | None = None,
    owasp_framework: str | None = DEFAULT_OWASP_FRAMEWORK,
    owasp_version: str | int | None = None,
    attestation: dict | None = None,
    framework_evidence: dict | None = None,
) -> str:
    from skylos import __version__ as skylos_version

    owasp_framework, owasp_version = normalize_owasp_selection(
        owasp_framework,
        owasp_version,
    )
    by_severity: dict[str, dict[str, int]] = {}
    for sev in ("critical", "high", "medium", "low"):
        sev_results: list[DefenseResult] = []
        for result in results:
            if result.severity != sev:
                continue
            sev_results.append(result)

        passed = 0
        failed = 0
        for result in sev_results:
            if result.passed:
                passed += 1
            else:
                failed += 1

        by_severity[sev] = {
            "passed": passed,
            "failed": failed,
            "weight": SEVERITY_WEIGHTS[sev],
        }

    by_integration: dict[str, list[DefenseResult]] = defaultdict(list)
    for r in results:
        by_integration[r.integration_location].append(r)

    integrations_data = []
    if integrations:
        for integ in integrations:
            if hasattr(integ, "location"):
                loc = integ.location
            else:
                loc = str(integ)

            integ_results = by_integration.get(loc, [])
            integ_score = compute_defense_score(integ_results)
            if hasattr(integ, "to_dict"):
                integ_dict = integ.to_dict()
            else:
                integ_dict = {"location": loc}

            integ_dict["weighted_score"] = integ_score.weighted_score
            integ_dict["weighted_max"] = integ_score.weighted_max
            integ_dict["score_pct"] = integ_score.score_pct
            integ_dict["risk_rating"] = integ_score.risk_rating
            integrations_data.append(integ_dict)

    findings = []
    for result in results:
        findings.append(result.to_dict())

    data: dict[str, Any] = {
        "version": "1.1",
        "skylos_version": skylos_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project": project_path,
        "owasp_framework": owasp_framework,
        "owasp_version": owasp_version,
        "summary": {
            "integrations_found": integrations_count,
            "files_scanned": files_scanned,
            "total_checks": score.total,
            "passed": score.passed,
            "failed": score.total - score.passed,
            "weighted_score": score.weighted_score,
            "weighted_max": score.weighted_max,
            "score_pct": score.score_pct,
            "risk_rating": score.risk_rating,
            "by_severity": by_severity,
        },
        "integrations": integrations_data,
        "findings": findings,
    }

    if owasp_coverage is not None:
        data["owasp_coverage"] = owasp_coverage

    if framework_evidence is not None:
        data["framework_evidence"] = framework_evidence

    if ops_score:
        data["ops_score"] = ops_score.to_dict()

    if attestation is not None:
        data["attestation"] = attestation

    return json.dumps(data, indent=2)


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _split_location(location: str) -> tuple[str, int]:
    path, sep, tail = str(location).rpartition(":")
    if sep and tail.isdigit():
        return path, int(tail)
    return str(location), 1


def _md_owasp_coverage_section(
    framework: str,
    version: str | int,
    coverage: dict,
) -> list[str]:
    lines = [f"### {owasp_report_label(framework, version)}", ""]
    lines.append("| ID | Name | Status | Coverage | Passed/Total |")
    lines.append("|---|---|---|---|---|")
    for owasp_id, info in coverage.items():
        if info["status"] == "not_applicable":
            continue
        pct = f"{info['coverage_pct']}%" if info["coverage_pct"] is not None else "N/A"
        lines.append(
            f"| {owasp_id} | {_md_escape(info['name'])} | {info['status']} "
            f"| {pct} | {info['passed']}/{info['total']} |"
        )
    lines.append("")
    return lines


def _md_report_header(generated_at: str) -> list[str]:
    from skylos import __version__ as skylos_version

    return [
        "# Skylos Agent Verification Report",
        "",
        (
            f"> Static pre-deployment verification of AI-agent guardrails — "
            f"Skylos v{skylos_version}, generated {generated_at}"
        ),
        "",
    ]


def _md_executive_summary_section(
    score: DefenseScore,
    *,
    integrations_count: int,
    files_scanned: int,
    target: str,
    ops_score: OpsScore | None,
    policy_path: str | None,
    gate: dict | None,
) -> list[str]:
    lines = ["## Executive Summary", ""]
    lines.append(
        f"Defense score **{score.score_pct}% ({score.risk_rating})** across "
        f"{integrations_count} LLM integration(s) in {files_scanned} scanned file(s); "
        f"{score.passed}/{score.total} defense checks passing."
    )
    lines.extend(["", "| Item | Value |", "|---|---|"])
    lines.append(f"| Target | {_md_escape(target)} |")
    lines.append(f"| Files scanned | {files_scanned} |")
    lines.append(f"| LLM integrations | {integrations_count} |")
    lines.append(
        f"| Defense score | {score.score_pct}% ({score.risk_rating}) — "
        f"{score.weighted_score}/{score.weighted_max} weighted points |"
    )
    if ops_score and ops_score.total > 0:
        lines.append(
            f"| Ops score | {ops_score.score_pct}% ({ops_score.rating}) — "
            f"{ops_score.passed}/{ops_score.total} ops checks |"
        )
    lines.append(f"| Policy | {_md_escape(policy_path) if policy_path else 'none'} |")
    if gate is not None:
        lines.append(_md_gate_row(gate))
    lines.append("")
    return lines


def _md_gate_row(gate: dict) -> str:
    gate_terms = []
    if gate.get("fail_on"):
        gate_terms.append(f"fail-on={gate['fail_on']}")
    if gate.get("min_score") is not None:
        gate_terms.append(f"min-score={gate['min_score']}")
    gate_label = "PASS" if gate.get("passed") else "FAIL"
    return f"| Gate ({', '.join(gate_terms)}) | {gate_label} |"


def _group_results_by_integration(
    results: list[DefenseResult],
) -> dict[str, list[DefenseResult]]:
    by_integration: dict[str, list[DefenseResult]] = defaultdict(list)
    for result in results:
        by_integration[result.integration_location].append(result)
    return by_integration


def _md_inventory_and_results_sections(
    results: list[DefenseResult],
    integrations: list,
) -> list[str]:
    if not integrations:
        return []

    by_integration = _group_results_by_integration(results)
    lines = ["## AI Integration Inventory", ""]
    lines.extend(_md_integration_inventory_rows(integrations, by_integration))
    lines.extend(_md_verification_result_rows(by_integration))
    return lines


def _md_integration_inventory_rows(
    integrations: list,
    by_integration: dict[str, list[DefenseResult]],
) -> list[str]:
    lines = ["| Location | Provider | Type | Model | Score |", "|---|---|---|---|---|"]
    for integ in integrations:
        loc = getattr(integ, "location", str(integ))
        integ_score = compute_defense_score(by_integration.get(loc, []))
        model = getattr(integ, "model_value", None) or "unknown"
        pinned = " (pinned)" if getattr(integ, "model_pinned", False) else ""
        lines.append(
            f"| {_md_escape(loc)} | {_md_escape(getattr(integ, 'provider', 'unknown'))} "
            f"| {_md_escape(getattr(integ, 'integration_type', 'unknown'))} "
            f"| {_md_escape(model)}{pinned} "
            f"| {integ_score.score_pct}% ({integ_score.risk_rating}) |"
        )
    lines.append("")
    return lines


def _md_verification_result_rows(
    by_integration: dict[str, list[DefenseResult]],
) -> list[str]:
    lines = ["## Verification Results", ""]
    for loc, integ_results in by_integration.items():
        integ_score = compute_defense_score(integ_results)
        lines.append(
            f"### Integration: {_md_escape(loc)} — "
            f"{integ_score.score_pct}% ({integ_score.risk_rating})"
        )
        lines.extend(["", "| Check | Status | Severity | OWASP | Evidence |"])
        lines.append("|---|---|---|---|---|")
        for result in sorted(integ_results, key=lambda r: (r.passed, -r.weight)):
            status = "PASS" if result.passed else "FAIL"
            lines.append(
                f"| {result.plugin_id} | {status} | {result.severity} "
                f"| {result.owasp_llm or '—'} | {_md_escape(result.message)} |"
            )
        lines.append("")
    return lines


def _md_owasp_coverages_sections(
    coverages: list[tuple[str, str | int, dict]] | None,
) -> list[str]:
    if not coverages:
        return []

    lines = ["## OWASP Coverage", ""]
    for framework, version, coverage in coverages:
        lines.extend(_md_owasp_coverage_section(framework, version, coverage))
    return lines


def _md_framework_evidence_section(framework_evidence: dict | None) -> list[str]:
    if not framework_evidence:
        return []

    from skylos.defend.frameworks import FRAMEWORK_NON_CLAIMS

    lines = ["## Regulatory Framework Evidence", ""]
    lines.extend([f"> {framework_evidence.get('disclaimer', '')}", ""])
    frameworks = framework_evidence.get("frameworks", {})
    for framework in frameworks.values():
        controls = framework.get("controls", [])
        if not controls:
            continue
        lines.append(f"### {framework['label']}")
        lines.extend(["", "| Control | Name | Evidence | Checks |"])
        lines.append("|---|---|---|---|")
        for control in controls:
            check_ids = sorted({check["plugin_id"] for check in control["checks"]})
            lines.append(
                f"| {_md_escape(control['control_id'])} "
                f"| {_md_escape(control['control_name'])} "
                f"| {control['status']} | {', '.join(check_ids)} |"
            )
        lines.append("")

    lines.extend(["### Not addressed by static verification", ""])
    for framework_key, non_claims in FRAMEWORK_NON_CLAIMS.items():
        label = frameworks.get(framework_key, {}).get("label", framework_key)
        for item in non_claims:
            lines.append(f"- {label}: {item}")
    lines.append("")
    return lines


def _md_remediation_section(results: list[DefenseResult]) -> list[str]:
    failed = [result for result in results if not result.passed]
    if not failed:
        return []

    lines = ["## Remediation Appendix", ""]
    for severity in ("critical", "high", "medium", "low"):
        sev_failed = [result for result in failed if result.severity == severity]
        if not sev_failed:
            continue
        lines.extend(_md_remediation_severity_section(severity, sev_failed))
    return lines


def _md_remediation_severity_section(
    severity: str,
    results: list[DefenseResult],
) -> list[str]:
    lines = [f"### {severity.capitalize()}", ""]
    by_plugin: dict[str, list[DefenseResult]] = defaultdict(list)
    for result in results:
        by_plugin[result.plugin_id].append(result)
    for plugin_id, plugin_results in by_plugin.items():
        remediation = plugin_results[0].remediation or "See documentation."
        locations = ", ".join(sorted({result.location for result in plugin_results}))
        lines.append(f"- **{plugin_id}** — {remediation}")
        lines.append(f"  - Affected: {locations}")
    lines.append("")
    return lines


def _md_attestation_section(attestation: dict | None) -> list[str]:
    if not attestation:
        return []

    inputs = attestation.get("inputs", {})
    policy_hash = inputs.get("policy_hash")
    lines = ["## Attestation", "", "| Field | Value |", "|---|---|"]
    lines.append(f"| Algorithm | {attestation.get('algorithm', 'sha256')} |")
    lines.append(f"| Digest | `{attestation.get('digest', '')}` |")
    lines.append(f"| Generated at | {attestation.get('generated_at', '')} |")
    lines.append(f"| Files hashed | {inputs.get('files_hashed', 0)} |")
    lines.append(f"| Files digest | `{inputs.get('files_digest', '')}` |")
    lines.append(f"| Policy hash | {'`' + policy_hash + '`' if policy_hash else 'none'} |")
    lines.append(f"| Plugin set | {', '.join(inputs.get('plugin_set', []))} |")
    lines.append(
        f"| OWASP selection | {inputs.get('owasp_framework', '')} "
        f"{inputs.get('owasp_version', '')} |"
    )
    lines.extend(
        [
            "",
            (
                "To re-verify: re-run `skylos defend <path> --format json` on the "
                "same tree with the same flags; `attestation.digest` must match."
            ),
            "",
        ]
    )
    return lines


def _md_methodology_section() -> list[str]:
    return [
        "## Methodology & Disclaimer",
        "",
        (
            "This report is produced by deterministic static analysis (AST-based, "
            "no model in the loop) run locally against the target tree. It verifies "
            "the presence of guardrail code patterns at LLM integration points before "
            "deployment. It does not observe runtime behavior and is a complement to — "
            "not a replacement for — runtime controls such as gateways, policy "
            "engines, and human approval flows. Framework mappings indicate static "
            "evidence toward the referenced controls only; they are not a compliance "
            "determination, certification, or legal advice."
        ),
        "",
    ]


def format_defense_markdown(
    results: list[DefenseResult],
    score: DefenseScore,
    *,
    integrations: list | None = None,
    files_scanned: int = 0,
    target: str = ".",
    owasp_coverages: list[tuple[str, str | int, dict]] | None = None,
    ops_score: OpsScore | None = None,
    framework_evidence: dict | None = None,
    attestation: dict | None = None,
    policy_path: str | None = None,
    gate: dict | None = None,
) -> str:
    """
    Render the auditor-facing agent verification evidence report.

    Called from: skylos/commands/defend_cmd.py _format_defend_output.
    """
    integrations = integrations or []
    generated_at = datetime.now(timezone.utc).isoformat()

    lines: list[str] = []
    lines.extend(_md_report_header(generated_at))
    lines.extend(
        _md_executive_summary_section(
            score,
            integrations_count=len(integrations),
            files_scanned=files_scanned,
            target=target,
            ops_score=ops_score,
            policy_path=policy_path,
            gate=gate,
        )
    )
    lines.extend(_md_inventory_and_results_sections(results, integrations))
    lines.extend(_md_owasp_coverages_sections(owasp_coverages))
    lines.extend(_md_framework_evidence_section(framework_evidence))
    lines.extend(_md_remediation_section(results))
    lines.extend(_md_attestation_section(attestation))
    lines.extend(_md_methodology_section())

    return "\n".join(lines)


def format_defense_sarif(
    results: list[DefenseResult],
    *,
    attestation: dict | None = None,
    path_prefix: str = "",
) -> str:
    """
    Render failed defense checks as a SARIF 2.1.0 log for code scanning.

    Called from: skylos/commands/defend_cmd.py _format_defend_output.
    """
    import posixpath

    from skylos import __version__ as skylos_version
    from skylos.defend.plugins import ALL_PLUGINS
    from skylos.reporting.sarif import SarifExporter

    plugin_names = {plugin.id: plugin.name for plugin in ALL_PLUGINS}

    findings = []
    for result in results:
        if result.passed or result.category != "defense":
            continue

        file_path, line = _split_location(result.location)
        if path_prefix:
            file_path = posixpath.join(path_prefix, file_path)

        findings.append(
            {
                "rule_id": result.plugin_id,
                "title": plugin_names.get(result.plugin_id, result.plugin_id),
                "message": result.message,
                "severity": result.severity,
                "category": "ai-defense",
                "file_path": file_path,
                "line": line,
                "help_uri": f"https://docs.skylos.dev/ai-defense#{result.plugin_id}",
                "metadata": {
                    "remediation": result.remediation,
                    "owasp_llm": result.owasp_llm,
                    "integration_location": result.integration_location,
                },
            }
        )

    exporter = SarifExporter(
        findings,
        tool_name="Skylos Defend",
        version=skylos_version,
    )
    sarif_log = exporter.generate()

    if attestation is not None:
        run = sarif_log["runs"][0]
        run.setdefault("properties", {})["skylos_attestation"] = attestation

    return json.dumps(sarif_log, indent=2)


def format_defense_github_summary(
    results: list[DefenseResult],
    score: DefenseScore,
    ops_score: OpsScore | None = None,
    owasp_coverage: dict | None = None,
    *,
    gate_passed: bool | None = None,
    attestation: dict | None = None,
    owasp_framework: str | None = DEFAULT_OWASP_FRAMEWORK,
    owasp_version: str | int | None = None,
) -> str:
    """
    Render the compact markdown summary appended to $GITHUB_STEP_SUMMARY.

    Called from: skylos/commands/defend_cmd.py _write_defend_github_summary.
    """
    lines: list[str] = []
    lines.append("## Skylos Agent Verification")
    lines.append("")
    lines.append(
        f"**Defense score:** {score.score_pct}% ({score.risk_rating}) — "
        f"{score.passed}/{score.total} checks passing"
    )
    if ops_score and ops_score.total > 0:
        lines.append(
            f"**Ops score:** {ops_score.score_pct}% ({ops_score.rating})"
        )
    lines.append("")

    failed = [
        r for r in results if not r.passed and r.category == "defense"
    ]
    if failed:
        lines.append("| Failed check | Severity | Location |")
        lines.append("|---|---|---|")
        sorted_failed = sorted(
            failed,
            key=lambda r: (
                -getattr(r, "weight", 0),
                str(getattr(r, "plugin_id", "")),
            ),
        )
        for r in sorted_failed:
            lines.append(
                f"| {getattr(r, 'plugin_id', 'unknown')} "
                f"| {getattr(r, 'severity', '')} "
                f"| {_md_escape(getattr(r, 'location', ''))} |"
            )
        lines.append("")

    if owasp_coverage:
        counts = {"covered": 0, "partial": 0, "uncovered": 0}
        for info in owasp_coverage.values():
            if info["status"] in counts:
                counts[info["status"]] += 1
        lines.append(
            f"**{owasp_report_label(owasp_framework, owasp_version)}:** "
            f"{counts['covered']} covered, {counts['partial']} partial, "
            f"{counts['uncovered']} uncovered"
        )
        lines.append("")

    if gate_passed is not None:
        gate_label = "PASS ✅" if gate_passed else "FAIL ❌"
        lines.append(f"**Gate:** {gate_label}")
        lines.append("")

    if attestation:
        digest = attestation.get("digest", "")
        lines.append(f"**Attestation:** `sha256:{digest[:16]}…`")
        lines.append("")

    return "\n".join(lines)
