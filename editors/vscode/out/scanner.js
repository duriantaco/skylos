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
exports.SkylosScanError = exports.buildScanErrorMessage = exports.out = void 0;
exports.cancelScan = cancelScan;
exports.scanWorkspace = scanWorkspace;
exports.scanFile = scanFile;
exports.doctorSkylos = doctorSkylos;
exports.normalizeReport = normalizeReport;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
const config_1 = require("./config");
const scanCore_1 = require("./scanCore");
const findingCore_1 = require("./findingCore");
exports.out = vscode.window.createOutputChannel("Skylos");
var scanCore_2 = require("./scanCore");
Object.defineProperty(exports, "buildScanErrorMessage", { enumerable: true, get: function () { return scanCore_2.buildScanErrorMessage; } });
Object.defineProperty(exports, "SkylosScanError", { enumerable: true, get: function () { return scanCore_2.SkylosScanError; } });
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
async function doctorSkylos() {
    const bin = (0, config_1.getSkylosBin)();
    const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const args = ["--version"];
    const command = (0, scanCore_1.formatCommand)(bin, args);
    exports.out.appendLine("=".repeat(60));
    exports.out.appendLine("Skylos Doctor");
    exports.out.appendLine(`Workspace: ${wsRoot ?? "(none)"}`);
    exports.out.appendLine(`Configured binary: ${bin}`);
    exports.out.appendLine(`Version command: ${command}`);
    return new Promise((resolve) => {
        const proc = (0, child_process_1.spawn)(bin, args, { cwd: wsRoot });
        let stdout = "";
        let stderr = "";
        proc.stdout.on("data", (data) => {
            stdout += data.toString();
        });
        proc.stderr.on("data", (data) => {
            stderr += data.toString();
        });
        proc.on("close", (code) => {
            const ok = code === 0;
            if (stdout.trim())
                exports.out.appendLine(`stdout: ${stdout.trim()}`);
            if (stderr.trim())
                exports.out.appendLine(`stderr: ${stderr.trim()}`);
            exports.out.appendLine(ok ? "Doctor result: OK" : `Doctor result: failed with exit code ${code}`);
            resolve({
                ok,
                command,
                bin,
                workspaceRoot: wsRoot,
                stdout,
                stderr,
                error: ok ? undefined : `Version command exited with code ${code}`,
            });
        });
        proc.on("error", (err) => {
            const errno = err.code;
            const error = errno === "ENOENT"
                ? "Skylos executable was not found. Set `skylos.path` or install the Skylos CLI."
                : err.message;
            exports.out.appendLine(`Doctor result: ${error}`);
            resolve({
                ok: false,
                command,
                bin,
                workspaceRoot: wsRoot,
                stdout,
                stderr,
                error,
            });
        });
    });
}
async function runScan(target, wsRoot, token, diffBase) {
    cancelScan();
    const bin = (0, config_1.getSkylosBin)();
    const command = (0, scanCore_1.buildScanCommand)(bin, {
        target,
        confidence: (0, config_1.getConfidenceThreshold)(),
        excludeFolders: (0, config_1.getExcludeFolders)(),
        enableSecrets: (0, config_1.isFeatureEnabled)("secrets"),
        enableDanger: (0, config_1.isFeatureEnabled)("danger"),
        enableQuality: (0, config_1.isFeatureEnabled)("quality"),
        diffBase,
    });
    exports.out.appendLine("=".repeat(60));
    exports.out.appendLine(`Running: ${command.display}`);
    const startedAt = Date.now();
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(bin, command.args, { cwd: wsRoot });
        activeProcess = proc;
        let stdout = "";
        let stderr = "";
        let cancelled = false;
        let settled = false;
        const fail = (error) => {
            if (settled)
                return;
            settled = true;
            reject(error);
        };
        const succeed = (result) => {
            if (settled)
                return;
            settled = true;
            resolve(result);
        };
        proc.stdout.on("data", (data) => {
            stdout += data.toString();
        });
        proc.stderr.on("data", (data) => {
            stderr += data.toString();
        });
        token?.onCancellationRequested(() => {
            cancelled = true;
            proc.kill();
            fail(new scanCore_1.SkylosScanError("cancelled", "Scan cancelled", { command: command.display }));
        });
        proc.on("close", (code) => {
            activeProcess = null;
            if (cancelled)
                return;
            if (stderr) {
                exports.out.appendLine(`stderr: ${stderr}`);
            }
            let report;
            try {
                report = JSON.parse(stdout || "{}");
            }
            catch {
                exports.out.appendLine("Invalid JSON from CLI");
                fail(new scanCore_1.SkylosScanError(code === 0 ? "invalid_json" : "nonzero_exit", code === 0 ? "Skylos returned invalid JSON." : `Skylos exited with code ${code}.`, { command: command.display, exitCode: code, stderr, stdout }));
                return;
            }
            if (code !== 0) {
                exports.out.appendLine(`Skylos exited with code ${code} but returned parseable JSON; showing parsed findings.`);
            }
            const findings = normalizeReport(report, wsRoot);
            printReport(findings, wsRoot);
            succeed({
                findings,
                grade: report.grade,
                summary: report.analysis_summary,
                circularDeps: report.circular_dependencies,
                depVulns: report.dependency_vulnerabilities,
                metadata: {
                    command: command.display,
                    target,
                    workspaceRoot: wsRoot,
                    diffBase,
                    durationMs: Date.now() - startedAt,
                    exitCode: code,
                    stderr,
                },
            });
        });
        proc.on("error", (err) => {
            activeProcess = null;
            const errno = err.code;
            const kind = errno === "ENOENT" ? "missing_binary" : "unknown";
            fail(new scanCore_1.SkylosScanError(kind, err.message, { command: command.display, stderr }));
        });
    });
}
function normalizeReport(report, wsRoot) {
    return (0, findingCore_1.normalizeReportCore)(report, {
        wsRoot,
        deadCodeEnabled: (0, config_1.isDeadCodeEnabled)(),
        showDeadParams: (0, config_1.isShowDeadParams)(),
        confidenceThreshold: (0, config_1.getConfidenceThreshold)(),
    });
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
