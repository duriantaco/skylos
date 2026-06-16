"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeReportCore = normalizeReportCore;
exports.canonicalRuleId = canonicalRuleId;
exports.isDeadCodeRule = isDeadCodeRule;
exports.normalizeSeverity = normalizeSeverity;
exports.makeFingerprint = makeFingerprint;
const crypto = __importStar(require("crypto"));
const path = __importStar(require("path"));
const DEAD_CODE_RULES = {
    unused_functions: { ruleId: "SKY-U001", legacyRuleId: "DEAD-FUNC", itemType: "function", label: "function" },
    unused_imports: { ruleId: "SKY-U002", legacyRuleId: "DEAD-IMPORT", itemType: "import", label: "import" },
    unused_variables: { ruleId: "SKY-U003", legacyRuleId: "DEAD-VAR", itemType: "variable", label: "variable" },
    unused_classes: { ruleId: "SKY-U004", legacyRuleId: "DEAD-CLASS", itemType: "class", label: "class" },
    unused_parameters: { ruleId: "SKY-U005", legacyRuleId: "DEAD-PARAM", itemType: "parameter", label: "parameter" },
};
const LEGACY_RULE_ALIASES = {
    "DEAD-FUNC": "SKY-U001",
    "DEAD-IMPORT": "SKY-U002",
    "DEAD-VAR": "SKY-U003",
    "DEAD-CLASS": "SKY-U004",
    "DEAD-PARAM": "SKY-U005",
    "SKY-DC001": "SKY-U001",
    "SKY-DC002": "SKY-U002",
};
let findingCounter = 0;
function normalizeReportCore(report, options) {
    const findings = [];
    mapUnused(findings, report.unused_functions, "unused_functions", options);
    mapUnused(findings, report.unused_imports, "unused_imports", options);
    mapUnused(findings, report.unused_classes, "unused_classes", options);
    mapUnused(findings, report.unused_variables, "unused_variables", options);
    mapUnused(findings, report.unused_parameters, "unused_parameters", options);
    for (const secret of report.secrets ?? []) {
        const finding = rawFindingToCore(secret, "secrets", options);
        if (finding)
            findings.push(finding);
    }
    for (const danger of report.danger ?? []) {
        const finding = rawFindingToCore(danger, "security", options);
        if (finding)
            findings.push(finding);
    }
    for (const quality of report.quality ?? []) {
        const finding = rawQualityFindingToCore(quality, options);
        if (finding)
            findings.push(finding);
    }
    return findings.filter((finding) => {
        if (finding.category !== "dead_code")
            return true;
        if (!options.deadCodeEnabled)
            return false;
        if (finding.ruleId === "SKY-U005" && !options.showDeadParams)
            return false;
        if (finding.confidence !== undefined && finding.confidence < options.confidenceThreshold)
            return false;
        return true;
    });
}
function canonicalRuleId(ruleId) {
    return LEGACY_RULE_ALIASES[ruleId] ?? ruleId;
}
function isDeadCodeRule(ruleId) {
    return canonicalRuleId(ruleId).startsWith("SKY-U");
}
function normalizeSeverity(value) {
    const normalized = String(value ?? "").toUpperCase();
    if (normalized === "CRITICAL")
        return "CRITICAL";
    if (normalized === "HIGH")
        return "HIGH";
    if (normalized === "MEDIUM")
        return "MEDIUM";
    if (normalized === "LOW")
        return "LOW";
    if (normalized === "WARN" || normalized === "WARNING")
        return "WARN";
    return "INFO";
}
function makeFingerprint(input) {
    const material = [
        canonicalRuleId(input.ruleId),
        input.relativePath.replace(/\\/g, "/"),
        String(input.line),
        input.subject ?? "",
        input.message,
    ].join("\0");
    const hash = crypto.createHash("sha1").update(material).digest("hex").slice(0, 20);
    return `vsce:${hash}`;
}
function mapUnused(findings, items, key, options) {
    const meta = DEAD_CODE_RULES[key];
    for (const item of items ?? []) {
        if (!item.file)
            continue;
        const paths = normalizePaths(item.file, options.wsRoot);
        const name = item.name ?? item.simple_name ?? "";
        const line = positiveLine(item.line ?? item.lineno);
        const message = `Unused ${meta.label}: ${name}`;
        const ruleId = canonicalRuleId(item.rule_id ?? meta.ruleId);
        const fingerprint = item.fingerprint ?? makeFingerprint({
            ruleId,
            relativePath: paths.relativePath,
            line,
            message,
            subject: name,
        });
        findings.push({
            id: nextId(),
            fingerprint,
            ruleId,
            legacyRuleId: meta.legacyRuleId,
            category: "dead_code",
            severity: "INFO",
            message,
            file: paths.absolutePath,
            relativePath: paths.relativePath,
            workspaceRoot: options.wsRoot,
            line,
            col: 0,
            confidence: item.confidence,
            itemType: meta.itemType,
            itemName: name,
            source: "cli",
            baselineStatus: item.baseline_status,
            isNew: item.is_new,
        });
    }
}
function rawFindingToCore(raw, category, options) {
    if (!raw.file)
        return undefined;
    const paths = normalizePaths(raw.file, options.wsRoot);
    const line = positiveLine(raw.line);
    const ruleId = canonicalRuleId(raw.rule_id ?? "SKYLOS");
    const message = raw.message ?? `Skylos ${category} finding`;
    const fingerprint = raw.fingerprint ?? makeFingerprint({
        ruleId,
        relativePath: paths.relativePath,
        line,
        message,
    });
    const metadata = objectValue(raw.metadata);
    return {
        id: nextId(),
        fingerprint,
        ruleId,
        category,
        severity: normalizeSeverity(raw.severity),
        message,
        file: paths.absolutePath,
        relativePath: paths.relativePath,
        workspaceRoot: options.wsRoot,
        line,
        col: zeroBasedCol(raw.col),
        endLine: positiveOptional(raw.end_line ?? raw.endLine),
        endCol: zeroBasedOptional(raw.end_col ?? raw.endCol ?? raw.end_column ?? raw.endColumn),
        confidence: raw.confidence,
        source: "cli",
        ruleUrl: raw.rule_url ?? raw.ruleUrl,
        safeFix: raw.safe_fix ?? raw.safeFix,
        fixPatch: raw.fix_patch ?? raw.fixPatch ?? raw.patch,
        baselineStatus: raw.baseline_status ?? raw.baselineStatus,
        isNew: raw.is_new ?? raw.isNew,
        snippet: stringValue(raw.snippet ?? raw.code_snippet ?? raw.codeSnippet ?? raw.vulnerable_code),
        explanation: stringValue(raw.explanation),
        suggestion: stringValue(raw.suggestion),
        evidence: evidenceList(raw.evidence ?? metadata?.evidence),
        trace: traceSteps(raw.trace ?? raw.dataflow ?? metadata?.trace ?? metadata?.dataflow),
        sourceSymbol: stringValue(raw.source_symbol ?? raw.sourceSymbol ?? metadata?.source_symbol ?? metadata?.sourceSymbol),
        sinkSymbol: stringValue(raw.sink_symbol ?? raw.sinkSymbol ?? metadata?.sink_symbol ?? metadata?.sinkSymbol),
        securityEvidence: objectValue(raw._security_evidence
            ?? raw.security_evidence
            ?? metadata?.security_evidence
            ?? metadata?._security_evidence),
        reviewReason: stringValue(raw._review_reason ?? raw.review_reason ?? metadata?.review_reason ?? metadata?._review_reason),
        ciBlocking: booleanValue(raw._ci_blocking ?? raw.ci_blocking ?? metadata?.ci_blocking ?? metadata?._ci_blocking),
    };
}
function rawQualityFindingToCore(raw, options) {
    const message = raw.message ?? `Quality issue (${raw.kind ?? raw.metric ?? "quality"})`;
    return rawFindingToCore({ ...raw, message, rule_id: raw.rule_id ?? "SKY-Q000" }, "quality", options);
}
function normalizePaths(filePath, wsRoot) {
    const absolutePath = path.normalize(path.isAbsolute(filePath) ? filePath : path.join(wsRoot, filePath));
    const relativePath = path.relative(wsRoot, absolutePath).replace(/\\/g, "/") || path.basename(absolutePath);
    return { absolutePath, relativePath };
}
function positiveLine(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 1)
        return 1;
    return Math.floor(value);
}
function positiveOptional(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 1)
        return undefined;
    return Math.floor(value);
}
function zeroBasedCol(value) {
    if (typeof value !== "number" || !Number.isFinite(value))
        return 0;
    return Math.max(0, Math.floor(value));
}
function zeroBasedOptional(value) {
    if (typeof value !== "number" || !Number.isFinite(value))
        return undefined;
    return Math.max(0, Math.floor(value));
}
function stringValue(value) {
    return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}
function booleanValue(value) {
    return typeof value === "boolean" ? value : undefined;
}
function objectValue(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return undefined;
    return value;
}
function evidenceList(value) {
    if (!Array.isArray(value)) {
        const single = stringValue(value);
        return single ? [single] : undefined;
    }
    const items = value.filter((item) => typeof item === "string" && item.trim().length > 0);
    return items.length > 0 ? items : undefined;
}
function traceSteps(value) {
    if (!Array.isArray(value))
        return undefined;
    const steps = [];
    for (const item of value) {
        if (typeof item === "string" && item.trim().length > 0) {
            steps.push({ message: item });
            continue;
        }
        const obj = objectValue(item);
        if (!obj)
            continue;
        const step = {
            file: stringValue(obj.file ?? obj.path ?? obj.filename),
            line: typeof obj.line === "number" && Number.isFinite(obj.line) ? Math.max(1, Math.floor(obj.line)) : undefined,
            label: stringValue(obj.label ?? obj.kind),
            message: stringValue(obj.message ?? obj.detail),
            symbol: stringValue(obj.symbol ?? obj.name),
        };
        if (step.file || step.line || step.label || step.message || step.symbol)
            steps.push(step);
    }
    return steps.length > 0 ? steps : undefined;
}
function nextId() {
    findingCounter += 1;
    return `f-${findingCounter}`;
}
