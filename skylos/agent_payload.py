from __future__ import annotations

from typing import Any


def severity_score(severity: str) -> int:
    normalized = str(severity).upper()
    if normalized == "CRITICAL":
        return 5
    if normalized == "HIGH":
        return 4
    if normalized in {"MEDIUM", "WARN"}:
        return 3
    if normalized == "LOW":
        return 2
    return 1


def build_action_title(finding: dict[str, Any]) -> str:
    if finding["category"] == "dead_code":
        return f"Clean up {finding['message']}"
    if finding["category"] == "debt":
        dimension = str(finding.get("primary_dimension") or "debt")
        return f"Refactor {dimension} hotspot"
    return f"Review {finding['severity']} {finding['rule_id']}"


def build_action_subtitle(finding: dict[str, Any]) -> str:
    location = f"{finding['file']}:{finding['line']}"
    return f"{finding['message']} ({location})"


def build_action_reason(finding: dict[str, Any]) -> str:
    reasons = []
    if finding.get("is_new_vs_baseline") and finding.get("category") != "debt":
        reasons.append("new vs baseline")
    if finding.get("category") == "debt":
        baseline_status = str(finding.get("baseline_status") or "").strip().lower()
        if baseline_status == "new":
            reasons.append("new vs debt baseline")
        elif baseline_status == "worsened":
            reasons.append("worsened vs debt baseline")
        elif baseline_status == "improved":
            reasons.append("improved vs debt baseline")
    if finding.get("is_new_since_last_scan"):
        reasons.append("new since last scan")
    if finding.get("is_in_changed_file"):
        reasons.append("in changed file")
    if not reasons:
        reasons.append("ranked by severity")
    return ", ".join(reasons)


def infer_action_type(finding: dict[str, Any]) -> str:
    if finding["category"] == "dead_code":
        return "cleanup"
    if finding["category"] == "debt":
        return "plan_refactor"
    if finding["severity"] in {"CRITICAL", "HIGH"}:
        return "inspect_now"
    return "review"


def infer_safe_fix(finding: dict[str, Any]) -> str | None:
    if finding["category"] != "dead_code":
        return None
    if finding["rule_id"] == "SKY-U002":
        return "remove_import"
    if finding["rule_id"] == "SKY-U001":
        return "remove_function"
    return None


def build_ranked_actions(
    findings: list[dict[str, Any]], changed_files: list[str]
) -> list[dict[str, Any]]:
    changed = set(changed_files)
    actions: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("is_dismissed") or finding.get("is_snoozed"):
            continue
        score = float(severity_score(finding["severity"]) * 100)
        if finding.get("is_new_vs_baseline") and finding["category"] != "debt":
            score += 220
        if finding.get("is_new_since_last_scan") and finding["category"] != "debt":
            score += 140
        if finding["file"] in changed and finding["category"] != "debt":
            score += 160
        if finding["category"] in {"security", "secrets"}:
            score += 60
        if finding["category"] == "debt":
            score += (
                float(
                    finding.get("priority_score") or finding.get("hotspot_score") or 0.0
                )
                * 3.0
            )
        if finding["category"] == "dead_code":
            score -= 75
        if finding.get("confidence") is not None:
            score += min(int(finding["confidence"]), 100)

        actions.append(
            {
                "id": finding["fingerprint"],
                "title": build_action_title(finding),
                "subtitle": build_action_subtitle(finding),
                "reason": build_action_reason(finding),
                "file": finding["file"],
                "absolute_file": finding["absolute_file"],
                "line": finding["line"],
                "severity": finding["severity"],
                "category": finding["category"],
                "score": score,
                "action_type": infer_action_type(finding),
                "command_hint": f"open:{finding['absolute_file']}:{finding['line']}",
                "rule_id": finding["rule_id"],
                "message": finding["message"],
                "safe_fix": infer_safe_fix(finding),
                "hotspot_score": finding.get("hotspot_score"),
                "priority_score": finding.get("priority_score"),
                "signal_count": finding.get("signal_count"),
                "primary_dimension": finding.get("primary_dimension"),
                "baseline_status": finding.get("baseline_status"),
            }
        )

    actions.sort(
        key=lambda item: (
            -float(item["score"]),
            -float(item.get("priority_score") or 0.0),
            item["file"],
            int(item["line"]),
            item["title"],
        )
    )
    return actions


def build_headline(
    *,
    critical: int,
    high: int,
    new_total: int,
    changed_total: int,
    baseline_present: bool,
    total: int,
) -> str:
    urgent = critical + high
    if urgent > 0 and changed_total > 0:
        return f"{urgent} urgent finding(s) need attention in changed code"
    if urgent > 0:
        return f"{urgent} urgent finding(s) need attention"
    if baseline_present and new_total > 0:
        return f"{new_total} new finding(s) since baseline"
    if changed_total > 0:
        return f"{changed_total} finding(s) in files you changed"
    if total > 0:
        return f"{total} tracked finding(s) in repository"
    return "No active findings"


def build_summary(
    findings: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    changed_files: list[str],
    baseline_present: bool,
    *,
    triage_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    critical = sum(
        1 for item in findings if str(item["severity"]).upper() == "CRITICAL"
    )
    high = sum(1 for item in findings if str(item["severity"]).upper() == "HIGH")
    medium = sum(
        1 for item in findings if str(item["severity"]).upper() in {"MEDIUM", "WARN"}
    )
    new_total = sum(1 for item in findings if item.get("is_new_vs_baseline"))
    changed_total = sum(1 for item in findings if item.get("is_in_changed_file"))
    debt_total = sum(1 for item in findings if item.get("category") == "debt")
    changed_file_count = len(
        {item["file"] for item in findings if item.get("is_in_changed_file")}
    )
    dismissed = int((triage_counts or {}).get("dismissed", 0))
    snoozed = int((triage_counts or {}).get("snoozed", 0))

    headline = build_headline(
        critical=critical,
        high=high,
        new_total=new_total,
        changed_total=changed_total,
        baseline_present=baseline_present,
        total=len(findings),
    )

    subtitle_parts = []
    if changed_file_count:
        subtitle_parts.append(
            f"{changed_total} finding(s) in {changed_file_count} changed file(s)"
        )
    if baseline_present:
        subtitle_parts.append(f"{new_total} new vs baseline")
    if debt_total:
        subtitle_parts.append(f"{debt_total} debt hotspot(s)")
    if actions:
        subtitle_parts.append(f"{len(actions)} ranked action(s)")
    if snoozed:
        subtitle_parts.append(f"{snoozed} snoozed")
    if dismissed:
        subtitle_parts.append(f"{dismissed} dismissed")
    subtitle = " | ".join(subtitle_parts) if subtitle_parts else "No active actions"

    return {
        "headline": headline,
        "subtitle": subtitle,
        "total_findings": len(findings),
        "new_findings": new_total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "debt": debt_total,
        "changed_file_count": changed_file_count,
        "changed_files": changed_files,
        "dismissed": dismissed,
        "snoozed": snoozed,
    }


def render_status_table(state: dict[str, Any], *, limit: int = 10) -> dict[str, Any]:
    summary = state.get("summary") or {}
    actions = state.get("actions") or []
    return {
        "headline": summary.get("headline", "No active findings"),
        "subtitle": summary.get("subtitle", ""),
        "actions": actions[:limit],
    }


def command_center_payload(state: dict[str, Any], *, limit: int = 10) -> dict[str, Any]:
    payload = dict(state.get("command_center") or {})
    payload["items"] = list((payload.get("items") or [])[:limit])
    return payload
