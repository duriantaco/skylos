"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiagnosticsManager = void 0;
const vscode = require("vscode");
class DiagnosticsManager {
    constructor(store) {
        this.store = store;
        this.disposables = [];
        this.cliCollection = vscode.languages.createDiagnosticCollection("skylos");
        this.aiCollection = vscode.languages.createDiagnosticCollection("skylos-ai");
        this.disposables.push(this.cliCollection, this.aiCollection, store.onDidChange(() => this.refreshCLI()), store.onDidChangeAI(() => this.refreshAI()));
    }
    refreshCLI() {
        this.cliCollection.clear();
        const files = this.store.getFilesWithFindings();
        for (const file of files) {
            const findings = this.store.getCLIFindingsForFile(file);
            if (findings.length === 0)
                continue;
            const uri = vscode.Uri.file(file);
            this.cliCollection.set(uri, findings.map(toDiagnostic));
        }
    }
    refreshAI() {
        this.aiCollection.clear();
        const files = this.store.getFilesWithFindings();
        for (const file of files) {
            const findings = this.store.getAIFindingsForFile(file);
            if (findings.length === 0)
                continue;
            const uri = vscode.Uri.file(file);
            this.aiCollection.set(uri, findings.map(toDiagnostic));
        }
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
function toDiagnostic(f) {
    const line = Math.max(0, f.line - 1);
    const col = Math.max(0, f.col);
    const start = new vscode.Position(line, col);
    const range = new vscode.Range(start, start);
    const severity = mapSeverity(f.severity);
    const prefix = f.source === "ai" ? "[AI] " : f.ruleId !== "SKYLOS" ? `[${f.ruleId}] ` : "";
    const diag = new vscode.Diagnostic(range, `${prefix}${f.message}`, severity);
    diag.source = f.source === "ai" ? "skylos-ai" : "skylos";
    diag.code = f.ruleId;
    return diag;
}
function mapSeverity(s) {
    switch (s) {
        case "CRITICAL":
        case "HIGH":
            return vscode.DiagnosticSeverity.Error;
        case "MEDIUM":
        case "WARN":
            return vscode.DiagnosticSeverity.Warning;
        case "LOW":
            return vscode.DiagnosticSeverity.Hint;
        case "INFO":
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}
