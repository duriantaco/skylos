"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sortReviewQueue = sortReviewQueue;
exports.reviewScore = reviewScore;
exports.priorityReasons = priorityReasons;
exports.ciImpact = ciImpact;
exports.fixPlan = fixPlan;
exports.evidenceLines = evidenceLines;
exports.hasEvidence = hasEvidence;
exports.isLikelyCiBlocker = isLikelyCiBlocker;
exports.severityRank = severityRank;
const provenanceCore_1 = require("./provenanceCore");
function sortReviewQueue(findings, context = {}) {
    return [...findings].sort((a, b) => reviewScore(b, context) - reviewScore(a, context)
        || a.file.localeCompare(b.file)
        || a.line - b.line
        || a.message.localeCompare(b.message));
}
function reviewScore(finding, context = {}) {
    let score = severityRank(finding.severity) * 10000;
    if (finding.file === context.currentFile)
        score += 100000;
    else if (context.visibleFiles && new Set(context.visibleFiles).has(finding.file))
        score += 50000;
    if (finding.ciBlocking === true)
        score += 70000;
    if ((0, provenanceCore_1.isCorroborated)(finding))
        score += 65000;
    if (finding.isNew || finding.baselineStatus === "new")
        score += 45000;
    if (finding.category === "secrets")
        score += 9000;
    if (finding.category === "security")
        score += 7000;
    if (finding.fixPatch)
        score += 3000;
    if (hasEvidence(finding))
        score += 750;
    if (finding.source === "cli")
        score += 500;
    if (finding.confidence !== undefined)
        score += Math.min(100, Math.max(0, finding.confidence));
    return score;
}
function priorityReasons(finding, context = {}) {
    const reasons = [];
    if (finding.file === context.currentFile)
        reasons.push("In the active editor");
    else if (context.visibleFiles && new Set(context.visibleFiles).has(finding.file))
        reasons.push("In an open editor");
    if ((0, provenanceCore_1.isCorroborated)(finding))
        reasons.push(`Confirmed by ${(0, provenanceCore_1.sourceSummary)(finding)}`);
    if (finding.ciBlocking === true)
        reasons.push("Marked as CI-blocking by Skylos");
    if (finding.isNew || finding.baselineStatus === "new") {
        reasons.push(context.diffBase ? `New against ${context.diffBase}` : "New against the configured baseline");
    }
    if (finding.severity === "CRITICAL" || finding.severity === "HIGH") {
        reasons.push(`${finding.severity.toLowerCase()} severity`);
    }
    if (finding.category === "secrets")
        reasons.push("Secret exposure risk");
    else if (finding.category === "security")
        reasons.push("Security finding");
    if (finding.fixPatch)
        reasons.push("Deterministic patch is available");
    if (hasEvidence(finding))
        reasons.push("Evidence is attached");
    if (finding.reviewReason)
        reasons.push(finding.reviewReason);
    if (finding.confidence !== undefined)
        reasons.push(`${finding.confidence}% confidence`);
    if (reasons.length === 0)
        reasons.push("Ranked by severity, category, and location");
    return unique(reasons).slice(0, 6);
}
function ciImpact(findings, context = {}) {
    const blockers = findings.filter(isLikelyCiBlocker);
    const attention = findings.filter((finding) => !isLikelyCiBlocker(finding) && needsAttention(finding));
    const scope = context.diffBase ? `new issues against ${context.diffBase}` : "the current review queue";
    if (blockers.length > 0) {
        const reasons = summarizeCounts(blockers);
        return {
            status: "blocking",
            headline: `Likely CI block: ${blockers.length} blocker(s) in ${scope}`,
            blockerCount: blockers.length,
            attentionCount: attention.length,
            reasons,
        };
    }
    if (attention.length > 0) {
        return {
            status: "attention",
            headline: `CI risk: ${attention.length} issue(s) need review in ${scope}`,
            blockerCount: 0,
            attentionCount: attention.length,
            reasons: summarizeCounts(attention),
        };
    }
    return {
        status: "clean",
        headline: findings.length === 0 ? "No Skylos issues in scope" : "No likely CI blockers in scope",
        blockerCount: 0,
        attentionCount: 0,
        reasons: [],
    };
}
function fixPlan(finding) {
    if (finding.fixPatch) {
        return {
            mode: "engine",
            title: "Preview the deterministic engine patch first",
            steps: [
                "Open the generated diff and verify the exact lines being changed.",
                "Apply the patch only if the diff matches the finding and preserves behavior.",
                "Rerun Skylos and the nearest tests after applying it.",
            ],
        };
    }
    if (finding.safeFix) {
        return {
            mode: "safe-fix",
            title: "Use the safe-fix guidance",
            steps: [
                finding.safeFix,
                "Review the local code path before editing.",
                "Rerun Skylos after the change.",
            ],
        };
    }
    if (finding.suggestion) {
        return {
            mode: "ai",
            title: "Use the suggested remediation as a starting point",
            steps: [
                finding.suggestion,
                "Ask AI for a patch only after checking the affected code path.",
                "Verify with the project test or lint command.",
            ],
        };
    }
    if (finding.category === "secrets") {
        return {
            mode: "manual",
            title: "Rotate and remove the exposed secret",
            steps: [
                "Remove the secret from source control and replace it with a runtime secret source.",
                "Rotate the leaked credential if it may have been committed or shared.",
                "Rerun Skylos secrets scanning.",
            ],
        };
    }
    if (finding.category === "security") {
        return {
            mode: "manual",
            title: "Fix the vulnerable data path",
            steps: [
                "Open the finding and inspect the source, sink, and validation path.",
                "Add validation, sanitization, authorization, or safer APIs according to the rule.",
                "Add or update a regression test for the dangerous path.",
            ],
        };
    }
    if (finding.category === "dead_code") {
        return {
            mode: "manual",
            title: "Confirm reachability before removing code",
            steps: [
                "Check dynamic references, exports, framework hooks, and tests before deleting.",
                "Remove the unused item or mark it intentionally retained.",
                "Rerun Skylos dead-code analysis.",
            ],
        };
    }
    return {
        mode: "manual",
        title: "Review and fix locally",
        steps: [
            "Open the code at the reported line.",
            "Apply the smallest behavior-preserving change that satisfies the rule.",
            "Rerun Skylos and the closest relevant tests.",
        ],
    };
}
function evidenceLines(finding) {
    const lines = [];
    if (finding.explanation)
        lines.push(finding.explanation);
    if (finding.reviewReason)
        lines.push(finding.reviewReason);
    for (const item of finding.evidence ?? [])
        lines.push(item);
    if (finding.sourceSymbol || finding.sinkSymbol) {
        const source = finding.sourceSymbol ? `source ${finding.sourceSymbol}` : "source unknown";
        const sink = finding.sinkSymbol ? `sink ${finding.sinkSymbol}` : "sink unknown";
        lines.push(`Data path: ${source} -> ${sink}`);
    }
    for (const step of finding.trace ?? []) {
        const location = step.file ? `${step.file}${step.line ? `:${step.line}` : ""}` : undefined;
        const message = step.message ?? step.label ?? step.symbol;
        if (location && message)
            lines.push(`${location} - ${message}`);
        else if (location)
            lines.push(location);
        else if (message)
            lines.push(message);
    }
    const security = summarizeSecurityEvidence(finding.securityEvidence);
    lines.push(...security);
    return unique(lines.filter((line) => line.trim().length > 0)).slice(0, 8);
}
function hasEvidence(finding) {
    return Boolean(finding.snippet
        || finding.explanation
        || finding.reviewReason
        || finding.sourceSymbol
        || finding.sinkSymbol
        || (finding.evidence && finding.evidence.length > 0)
        || (finding.trace && finding.trace.length > 0)
        || (finding.securityEvidence && Object.keys(finding.securityEvidence).length > 0));
}
function isLikelyCiBlocker(finding) {
    if (finding.ciBlocking === true)
        return true;
    if (finding.severity === "CRITICAL")
        return true;
    if (finding.category === "secrets")
        return finding.severity !== "INFO" && finding.severity !== "LOW";
    return finding.category === "security" && finding.severity === "HIGH";
}
function severityRank(severity) {
    switch (severity.toUpperCase()) {
        case "CRITICAL":
            return 5;
        case "HIGH":
            return 4;
        case "MEDIUM":
        case "WARN":
            return 3;
        case "LOW":
            return 2;
        case "INFO":
        default:
            return 1;
    }
}
function needsAttention(finding) {
    return finding.severity === "HIGH"
        || finding.severity === "MEDIUM"
        || finding.severity === "WARN"
        || finding.isNew === true
        || finding.baselineStatus === "new";
}
function summarizeCounts(findings) {
    const counts = new Map();
    for (const finding of findings) {
        const key = `${finding.severity} ${finding.category}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([key, count]) => `${count} ${key}`);
}
function summarizeSecurityEvidence(value) {
    if (!value)
        return [];
    const lines = [];
    const contractId = stringValue(value.contract_id);
    const handler = stringValue(value.handler);
    const missingGuards = stringArrayValue(value.missing_guards);
    if (contractId)
        lines.push(`Security contract: ${contractId}`);
    if (handler)
        lines.push(`Handler: ${handler}`);
    if (missingGuards.length > 0)
        lines.push(`Missing guards: ${missingGuards.join(", ")}`);
    if (lines.length === 0)
        lines.push(`Security evidence fields: ${Object.keys(value).slice(0, 6).join(", ")}`);
    return lines;
}
function stringValue(value) {
    return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}
function stringArrayValue(value) {
    if (!Array.isArray(value))
        return [];
    return value.filter((item) => typeof item === "string" && item.trim().length > 0);
}
function unique(values) {
    return [...new Set(values)];
}
