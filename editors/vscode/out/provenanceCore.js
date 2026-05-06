"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mergeCorrelatedFindings = mergeCorrelatedFindings;
exports.correlationKey = correlationKey;
exports.sourceSummary = sourceSummary;
exports.provenanceLabel = provenanceLabel;
exports.sourceLabel = sourceLabel;
exports.diagnosticSource = diagnosticSource;
exports.isCorroborated = isCorroborated;
exports.matchesSourceFilter = matchesSourceFilter;
exports.getSources = getSources;
const SOURCE_ORDER = ["cli", "agent", "ai"];
function mergeCorrelatedFindings(findings) {
    const byKey = new Map();
    for (const finding of findings) {
        const key = correlationKey(finding);
        const existing = byKey.get(key);
        byKey.set(key, existing ? mergePair(existing, finding) : withNormalizedSources(finding));
    }
    return [...byKey.values()];
}
function correlationKey(finding) {
    const file = finding.file.replace(/\\/g, "/");
    const line = Math.max(1, Math.floor(finding.line || 1));
    const rule = finding.ruleId.trim().toUpperCase();
    const subject = correlationSubject(finding);
    if (rule && rule !== "AI" && rule !== "SKYLOS" && rule !== "SKY-ACTIVE") {
        return `${file}:${line}:rule:${rule}:${subject}`;
    }
    return `${file}:${line}:${finding.category}:${subject}`;
}
function sourceSummary(finding) {
    return getSources(finding).map(sourceLabel).join(" + ");
}
function provenanceLabel(finding) {
    return isCorroborated(finding) ? `Confirmed by ${sourceSummary(finding)}` : sourceSummary(finding);
}
function sourceLabel(source) {
    if (source === "cli")
        return "Static";
    if (source === "agent")
        return "Automation";
    return "AI Assist";
}
function diagnosticSource(finding) {
    return `skylos ${sourceSummary(finding).toLowerCase().replace(/\s+/g, "-").replace(/-\+-/g, "+")}`;
}
function isCorroborated(finding) {
    return getSources(finding).length > 1;
}
function matchesSourceFilter(finding, source) {
    if (source === "confirmed")
        return isCorroborated(finding);
    return getSources(finding).includes(source);
}
function getSources(finding) {
    const sources = finding.sources && finding.sources.length > 0 ? finding.sources : [finding.source];
    return uniqueSources(sources).sort((a, b) => SOURCE_ORDER.indexOf(a) - SOURCE_ORDER.indexOf(b));
}
function correlationSubject(finding) {
    const explicit = finding.sinkSymbol ?? finding.sourceSymbol ?? finding.itemName;
    if (explicit && explicit.trim())
        return normalizeSubject(explicit);
    return normalizeSubject(finding.message).slice(0, 80);
}
function normalizeSubject(value) {
    return value.toLowerCase().replace(/[^a-z0-9.]+/g, " ").trim();
}
function mergePair(a, b) {
    const primary = choosePrimary(a, b);
    const secondary = primary === a ? b : a;
    const merged = {
        ...primary,
        severity: higherSeverity(a.severity, b.severity),
        confidence: maxNumber(a.confidence, b.confidence),
        safeFix: primary.safeFix ?? secondary.safeFix,
        fixPatch: primary.fixPatch ?? secondary.fixPatch,
        evidence: mergeStrings(a.evidence, b.evidence),
        trace: mergeTrace(a.trace, b.trace),
        reviewReason: primary.reviewReason ?? secondary.reviewReason,
        ciBlocking: a.ciBlocking === true || b.ciBlocking === true ? true : primary.ciBlocking ?? secondary.ciBlocking,
        baselineStatus: primary.baselineStatus ?? secondary.baselineStatus,
        isNew: a.isNew === true || b.isNew === true ? true : primary.isNew ?? secondary.isNew,
        sources: uniqueSources([...getSources(a), ...getSources(b)]),
    };
    return merged;
}
function withNormalizedSources(finding) {
    return {
        ...finding,
        sources: getSources(finding),
    };
}
function choosePrimary(a, b) {
    const sourceDelta = SOURCE_ORDER.indexOf(a.source) - SOURCE_ORDER.indexOf(b.source);
    if (sourceDelta !== 0)
        return sourceDelta < 0 ? a : b;
    return severityRank(a.severity) >= severityRank(b.severity) ? a : b;
}
function higherSeverity(a, b) {
    return severityRank(a) >= severityRank(b) ? a : b;
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
        default:
            return 1;
    }
}
function maxNumber(a, b) {
    if (a === undefined)
        return b;
    if (b === undefined)
        return a;
    return Math.max(a, b);
}
function mergeStrings(a, b) {
    const values = [...(a ?? []), ...(b ?? [])].filter((value) => value.trim().length > 0);
    return values.length > 0 ? [...new Set(values)] : undefined;
}
function mergeTrace(a, b) {
    const values = [...(a ?? []), ...(b ?? [])];
    return values.length > 0 ? values : undefined;
}
function uniqueSources(sources) {
    return [...new Set(sources)];
}
