"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildVerifyArgs = buildVerifyArgs;
exports.buildVerifyManifest = buildVerifyManifest;
exports.buildVerifyCommandDisplay = buildVerifyCommandDisplay;
exports.runSkylosVerify = runSkylosVerify;
exports.normalizeVerifyIssues = normalizeVerifyIssues;
const child_process_1 = require("child_process");
const scanCore_1 = require("./scanCore");
function buildVerifyArgs(request) {
    const args = [
        "verify",
        request.workspaceRoot,
        "--stdin",
        "--no-fail",
        "--confidence",
        String(request.confidence),
    ];
    return args;
}
function buildVerifyManifest(request) {
    const manifest = {
        path: request.workspaceRoot,
        file: request.filePath,
        code: request.code,
    };
    if (request.lineRange) {
        manifest.range = request.lineRange;
    }
    return manifest;
}
function buildVerifyCommandDisplay(request) {
    return (0, scanCore_1.formatCommand)(request.bin, buildVerifyArgs(request));
}
async function runSkylosVerify(request) {
    const args = buildVerifyArgs(request);
    const manifest = buildVerifyManifest(request);
    const manifestText = JSON.stringify(manifest);
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(request.bin, args, { cwd: request.workspaceRoot });
        let stdout = "";
        let stderr = "";
        proc.stdout.on("data", (data) => {
            stdout += data.toString();
        });
        proc.stderr.on("data", (data) => {
            stderr += data.toString();
        });
        proc.on("close", (code) => {
            if (code !== 0) {
                reject(new Error(`skylos verify exited with code ${code}: ${stderr}`));
                return;
            }
            try {
                const payload = JSON.parse(stdout);
                resolve(normalizeVerifyIssues(payload));
            }
            catch {
                reject(new Error("skylos verify returned invalid JSON"));
            }
        });
        proc.on("error", (error) => {
            reject(error);
        });
        proc.stdin.write(manifestText);
        proc.stdin.end();
    });
}
function normalizeVerifyIssues(payload) {
    const findings = payload.findings;
    if (!Array.isArray(findings)) {
        return [];
    }
    const issues = [];
    for (const finding of findings) {
        const issue = normalizeVerifyIssue(finding);
        if (issue) {
            issues.push(issue);
        }
    }
    return issues;
}
function normalizeVerifyIssue(finding) {
    const message = finding.message;
    if (!message) {
        return undefined;
    }
    return {
        line: verifyIssueLine(finding),
        message,
        severity: verifyIssueSeverity(finding),
    };
}
function verifyIssueLine(finding) {
    const startLine = finding.range?.start_line;
    if (typeof startLine === "number") {
        if (startLine > 0) {
            return startLine;
        }
    }
    return 1;
}
function verifyIssueSeverity(finding) {
    const severity = optionalString(finding.severity).toUpperCase();
    if (severity === "CRITICAL") {
        return "error";
    }
    if (severity === "HIGH") {
        return "error";
    }
    const likelihood = optionalString(finding.ai_likelihood).toLowerCase();
    if (likelihood === "high") {
        return "error";
    }
    return "warning";
}
function optionalString(value) {
    if (typeof value === "string") {
        return value;
    }
    return "";
}
