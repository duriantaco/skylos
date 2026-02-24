"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.out = void 0;
exports.cancelScan = cancelScan;
exports.scanWorkspace = scanWorkspace;
exports.scanFile = scanFile;
exports.normalizeReport = normalizeReport;
const vscode = require("vscode");
const child_process_1 = require("child_process");
const path = require("path");
const config_1 = require("./config");
exports.out = vscode.window.createOutputChannel("Skylos");
let activeProcess = null;
function cancelScan() {
    if (activeProcess) {
        activeProcess.kill();
        activeProcess = null;
    }
}
async function scanWorkspace(token, diffBase) {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) {
        vscode.window.showWarningMessage("Skylos: open a folder to scan.");
        return { findings: [] };
    }
    return runScan(ws.uri.fsPath, ws.uri.fsPath, token, diffBase);
}
async function scanFile(filePath, token) {
    const ws = vscode.workspace.workspaceFolders?.[0];
    const wsRoot = ws?.uri.fsPath ?? path.dirname(filePath);
    return runScan(filePath, wsRoot, token);
}
async function runScan(target, wsRoot, token, diffBase) {
    cancelScan();
    const bin = (0, config_1.getSkylosBin)();
    const conf = (0, config_1.getConfidenceThreshold)();
    const excludes = (0, config_1.getExcludeFolders)();
    const args = [target, "--json", "-c", String(conf)];
    excludes.forEach((f) => args.push("--exclude-folder", f));
    if ((0, config_1.isFeatureEnabled)("secrets"))
        args.push("--secrets");
    if ((0, config_1.isFeatureEnabled)("danger"))
        args.push("--danger");
    if ((0, config_1.isFeatureEnabled)("quality"))
        args.push("--quality");
    if (diffBase)
        args.push("--diff-base", diffBase);
    exports.out.appendLine("=".repeat(60));
    exports.out.appendLine(`Running: ${bin} ${args.join(" ")}`);
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(bin, args, { cwd: wsRoot });
        activeProcess = proc;
        let stdout = "";
        let stderr = "";
        proc.stdout.on("data", (data) => {
            stdout += data.toString();
        });
        proc.stderr.on("data", (data) => {
            stderr += data.toString();
        });
        token?.onCancellationRequested(() => {
            proc.kill();
            reject(new Error("Scan cancelled"));
        });
        proc.on("close", () => {
            activeProcess = null;
            if (stderr) {
                exports.out.appendLine(`stderr: ${stderr}`);
            }
            let report;
            try {
                report = JSON.parse(stdout || "{}");
            }
            catch {
                exports.out.appendLine("Invalid JSON from CLI");
                reject(new Error("Skylos returned invalid JSON."));
                return;
            }
            const findings = normalizeReport(report, wsRoot);
            printReport(findings, wsRoot);
            resolve({
                findings,
                grade: report.grade,
                summary: report.analysis_summary,
                circularDeps: report.circular_dependencies,
                depVulns: report.dependency_vulnerabilities,
            });
        });
        proc.on("error", (err) => {
            activeProcess = null;
            reject(err);
        });
    });
}
function resolvePath(filePath, wsRoot) {
    if (path.isAbsolute(filePath))
        return filePath;
    return path.join(wsRoot, filePath);
}
let findingCounter = 0;
function nextId() {
    return `f-${++findingCounter}`;
}
function normalizeReport(report, wsRoot) {
    const findings = [];
    const mapUnused = (items, itemType, ruleId) => {
        for (const u of items ?? []) {
            if (!u.file)
                continue;
            const name = u.name ?? u.simple_name ?? "";
            findings.push({
                id: nextId(),
                ruleId,
                category: "dead_code",
                severity: "INFO",
                message: `Unused ${itemType}: ${name}`,
                file: resolvePath(u.file, wsRoot),
                line: u.line ?? u.lineno ?? 1,
                col: 0,
                confidence: u.confidence,
                itemType,
                itemName: name,
                source: "cli",
            });
        }
    };
    mapUnused(report.unused_functions, "function", "DEAD-FUNC");
    mapUnused(report.unused_imports, "import", "DEAD-IMPORT");
    mapUnused(report.unused_classes, "class", "DEAD-CLASS");
    mapUnused(report.unused_variables, "variable", "DEAD-VAR");
    mapUnused(report.unused_parameters, "parameter", "DEAD-PARAM");
    for (const s of report.secrets ?? []) {
        if (!s.file)
            continue;
        findings.push(cliFindingToSkylos(s, "secrets", wsRoot));
    }
    for (const d of report.danger ?? []) {
        if (!d.file)
            continue;
        findings.push(cliFindingToSkylos(d, "security", wsRoot));
    }
    for (const q of report.quality ?? []) {
        if (!q.file)
            continue;
        const sev = normalizeSeverity(q.severity);
        const ruleId = q.rule_id ?? "SKY-Q000";
        const msg = q.message ?? `Quality issue (${q.kind ?? q.metric ?? "quality"})`;
        findings.push({
            id: nextId(),
            ruleId,
            category: "quality",
            severity: sev,
            message: msg,
            file: resolvePath(q.file, wsRoot),
            line: q.line ?? 1,
            col: 0,
            source: "cli",
        });
    }
    const deadCodeOn = (0, config_1.isDeadCodeEnabled)();
    const deadParamsOn = (0, config_1.isShowDeadParams)();
    const confThreshold = (0, config_1.getConfidenceThreshold)();
    return findings.filter((f) => {
        if (f.category === "dead_code") {
            if (!deadCodeOn)
                return false;
            if (f.ruleId === "DEAD-PARAM" && !deadParamsOn)
                return false;
            if (f.confidence !== undefined && f.confidence < confThreshold)
                return false;
        }
        return true;
    });
}
function cliFindingToSkylos(f, category, wsRoot) {
    const sev = normalizeSeverity(f.severity);
    const ruleId = f.rule_id ?? "SKYLOS";
    return {
        id: nextId(),
        ruleId,
        category,
        severity: sev,
        message: f.message,
        file: resolvePath(f.file, wsRoot),
        line: f.line ?? 1,
        col: f.col ?? 0,
        source: "cli",
    };
}
function normalizeSeverity(s) {
    const t = (s ?? "").toUpperCase();
    if (t === "CRITICAL")
        return "CRITICAL";
    if (t === "HIGH")
        return "HIGH";
    if (t === "MEDIUM")
        return "MEDIUM";
    if (t === "LOW")
        return "LOW";
    if (t === "WARN" || t === "WARNING")
        return "WARN";
    return "INFO";
}
function printReport(findings, wsRoot) {
    if (findings.length === 0) {
        exports.out.appendLine("No issues found.");
        return;
    }
    exports.out.appendLine("");
    exports.out.appendLine("=".repeat(60));
    exports.out.appendLine("DETAILED RESULTS");
    exports.out.appendLine("=".repeat(60));
    const byCategory = new Map();
    for (const f of findings) {
        const list = byCategory.get(f.category) ?? [];
        list.push(f);
        byCategory.set(f.category, list);
    }
    for (const [category, catFindings] of byCategory) {
        exports.out.appendLine("");
        exports.out.appendLine(category.toUpperCase());
        exports.out.appendLine("-".repeat(60));
        for (const f of catFindings) {
            const relPath = path.relative(wsRoot, f.file);
            const loc = `${relPath}:${f.line}${f.col ? `:${f.col}` : ""}`;
            const prefix = f.ruleId !== "SKYLOS" ? `[${f.ruleId}] ` : "";
            exports.out.appendLine(`  ${f.severity.padEnd(8)} ${prefix}${f.message}`);
            exports.out.appendLine(`           ${loc}`);
        }
    }
    exports.out.appendLine("");
    exports.out.appendLine("=".repeat(60));
    exports.out.appendLine(`Total: ${findings.length} issue(s)`);
}
