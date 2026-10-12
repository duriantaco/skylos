"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readAssessment = readAssessment;
exports.riskSummary = riskSummary;
exports.readGate = readGate;
exports.assessmentRows = assessmentRows;
exports.coverageText = coverageText;
exports.measurementRows = measurementRows;
exports.groupAdvice = groupAdvice;
const RISK_COLORS = {
    critical: "#ef4444", high: "#fb923c", medium: "#facc15", low: "#60a5fa",
    none: "#4ade80", unknown: "#888", not_assessed: "#888",
};
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "INFO"];
const record = (value) => !!value && typeof value === "object" && !Array.isArray(value);
const count = (value) => typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value >= 0;
const strings = (value) => Array.isArray(value) && value.every(item => typeof item === "string");
const nullableNumber = (value) => value === null || (typeof value === "number" && Number.isFinite(value));
function readAssessment(value) {
    if (!record(value) || value.version !== 1 || value.scope !== "all_analyzed_findings")
        return undefined;
    if (!record(value.risk) || !record(value.coverage) || !record(value.maintainability) || !record(value.dead_code))
        return undefined;
    if (typeof value.risk.status !== "string" || !(value.risk.status in RISK_COLORS))
        return undefined;
    if (!count(value.risk.finding_count) || !strings(value.scanned_checks))
        return undefined;
    if (!["complete", "partial", "incomplete", "unknown"].includes(String(value.coverage.status)))
        return undefined;
    if (!strings(value.coverage.not_assessed) || !strings(value.coverage.incomplete_checks) || !strings(value.coverage.reasons))
        return undefined;
    if (!["measured", "not_assessed"].includes(String(value.maintainability.status)))
        return undefined;
    if (!["advice_count", "rule_count", "affected_files"].every(key => count(value.maintainability[key])))
        return undefined;
    if (!Array.isArray(value.maintainability.checks) || !value.maintainability.checks.every(check => record(check) && typeof check.rule_id === "string" && typeof check.unit === "string" && count(check.affected_units) && nullableNumber(check.analyzed_units) && nullableNumber(check.affected_percent) && nullableNumber(check.max_value) && nullableNumber(check.max_threshold) && nullableNumber(check.max_excess_ratio)))
        return undefined;
    if (!["review", "none", "unknown", "not_assessed"].includes(String(value.dead_code.status)) || !count(value.dead_code.candidate_count))
        return undefined;
    return value;
}
function riskSummary(assessment, findings) {
    const observations = findings.filter(f => f.category !== "dead_code" && f.findingType !== "advice");
    const observed = SEVERITIES.find(severity => observations.some(f => !f.severityUnknown && f.severity === severity));
    let status = assessment?.risk.status ?? "unknown";
    // Optional AI/agent observations and focused-file overlays can add findings
    // after the CLI report. They must never be diluted by its older summary.
    const normalized = observed === "WARN" ? "medium" : observed === "INFO" ? "low" : observed?.toLowerCase();
    if (normalized && (status === "none" || status === "unknown" || status === "not_assessed" || SEVERITIES.indexOf(normalized.toUpperCase()) < SEVERITIES.indexOf(status.toUpperCase()))) {
        status = normalized;
    }
    if ((status === "none" || status === "not_assessed") && observations.some(f => f.severityUnknown)) {
        status = "unknown";
    }
    const label = status === "none" ? "No risk findings" : status === "not_assessed" ? "Not assessed" : status.toUpperCase();
    return { status, label, color: RISK_COLORS[status] ?? "#888", findingCount: Math.max(assessment?.risk.finding_count ?? 0, observations.length) };
}
function readGate(value) {
    if (!record(value) || typeof value.passed !== "boolean" || typeof value.forced !== "boolean" || !strings(value.reasons))
        return undefined;
    if (!["local_configured_policy", "local_strict_policy"].includes(String(value.scope)) || !["evaluated", "incomplete"].includes(String(value.status)))
        return undefined;
    return value;
}
function gateText(gate) {
    if (!gate)
        return "Not evaluated · run skylos . --gate";
    const policy = gate.scope === "local_strict_policy" ? "local strict policy" : "local configured policy";
    const outcome = gate.status === "incomplete" ? "INCOMPLETE" : gate.passed ? "PASS" : "FAIL";
    return [outcome, policy, gate.forced ? "forced continuation" : "", ...gate.reasons].filter(Boolean).join(" · ");
}
function assessmentRows(assessment, findings = [], gate) {
    const observedRisk = riskSummary(assessment, findings);
    const observedRiskText = ["critical", "high", "medium", "low"].includes(observedRisk.status) ? `${observedRisk.label} · ${observedRisk.findingCount} unresolved finding${observedRisk.findingCount === 1 ? "" : "s"}` : undefined;
    if (!assessment)
        return [
            ["Risk", observedRiskText ?? "Unknown · assessment unavailable; inspect known findings"],
            ["Maintainability", "Not assessed"],
            ["Dead code", "Not assessed"],
            ["Gate", gateText(gate)],
        ];
    const risk = assessment.risk;
    const status = observedRisk.status;
    const riskText = status === "none" ? "No risk findings in assessed checks" : status === "unknown" ? "Unknown · coverage or finding severity is unavailable" : status === "not_assessed" ? "Not assessed" : `${observedRisk.label} · ${observedRisk.findingCount} unresolved finding${observedRisk.findingCount === 1 ? "" : "s"}`;
    const maintenance = assessment.maintainability;
    const maintenanceText = maintenance.status === "measured" ? `${maintenance.advice_count} advice · ${maintenance.rule_count} check${maintenance.rule_count === 1 ? "" : "s"} · ${maintenance.affected_files} affected file${maintenance.affected_files === 1 ? "" : "s"}` : "Not assessed";
    const dead = assessment.dead_code;
    const deadText = dead.status === "review" ? `${dead.candidate_count} candidates to review before removal` : dead.status === "none" ? "No candidates in assessed code" : dead.status === "unknown" ? "Unknown · checks are incomplete" : "Not assessed";
    const unknown = Math.max(risk.severity_counts?.UNKNOWN ?? 0, findings.filter(f => f.category !== "dead_code" && f.findingType !== "advice" && f.severityUnknown).length);
    const unknownNote = count(unknown) && unknown > 0 && observedRiskText ? ` · ${unknown} with unknown severity` : "";
    return [["Risk", (observedRiskText ?? riskText) + unknownNote], ["Maintainability", maintenanceText], ["Dead code", deadText], ["Gate", gateText(gate)]];
}
function coverageText(assessment) {
    if (!assessment)
        return "Coverage: unknown; no complete current assessment is available.";
    const coverage = assessment.coverage;
    const parts = [`Coverage: ${coverage.status}`];
    if (coverage.not_assessed.length)
        parts.push(`not assessed: ${coverage.not_assessed.join(", ")}`);
    if (coverage.incomplete_checks.length)
        parts.push(`incomplete: ${coverage.incomplete_checks.join(", ")}`);
    if (coverage.status !== "complete")
        parts.push("absence of findings does not establish a clean repository");
    return parts.join("; ");
}
function measurementRows(assessment) {
    return (assessment?.maintainability.checks ?? []).map(check => {
        const label = [check.rule_id, check.language, check.name].filter(Boolean).join(" · ");
        let spread = `${check.affected_units} ${check.unit}${check.affected_units === 1 ? "" : "s"}`;
        if (check.analyzed_units === null)
            spread += " · denominator unavailable";
        else if (check.analyzed_units === 0)
            spread = `No eligible ${check.unit}s checked`;
        else
            spread = `${check.affected_units}/${check.analyzed_units} ${check.unit}${check.analyzed_units === 1 ? "" : "s"}`;
        if (check.analyzed_units !== null && check.analyzed_units > 0 && check.affected_percent !== null)
            spread += ` (${check.affected_percent}%)`;
        let magnitude = "Not measured";
        if (check.max_value !== null && check.max_threshold !== null) {
            magnitude = `max ${check.max_value} · limit ${check.max_threshold}`;
            if (check.max_excess_ratio !== null)
                magnitude += ` · ${check.max_excess_ratio}× limit`;
        }
        return [label, spread, magnitude];
    });
}
function groupAdvice(findings) {
    const groups = new Map();
    for (const finding of findings) {
        if (finding.findingType !== "advice")
            continue;
        const rows = groups.get(finding.ruleId) ?? [];
        rows.push(finding);
        groups.set(finding.ruleId, rows);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
}
