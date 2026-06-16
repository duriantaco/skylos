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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
const config_1 = require("./config");
const diagnosticCore_1 = require("./diagnosticCore");
const provenanceCore_1 = require("./provenanceCore");
class DiagnosticsManager {
    constructor(store) {
        this.store = store;
        this.disposables = [];
        this.collection = vscode.languages.createDiagnosticCollection("skylos");
        this.disposables.push(this.collection, store.onDidChange(() => this.refresh()), store.onDidChangeAI(() => this.refresh()));
    }
    refresh() {
        this.collection.clear();
        const findings = this.store.getVisibleFindings((0, config_1.getMaxProblems)(), {
            includeDeadCode: (0, config_1.isShowDeadCodeInProblems)(),
            maxPerFile: (0, config_1.getMaxProblemsPerFile)(),
        });
        this.publish(this.collection, findings);
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
    publish(collection, findings) {
        const byFile = new Map();
        for (const finding of findings) {
            const list = byFile.get(finding.file) ?? [];
            list.push(finding);
            byFile.set(finding.file, list);
        }
        for (const [file, items] of byFile) {
            const uri = vscode.Uri.file(file);
            collection.set(uri, items.map(toDiagnostic));
        }
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
function toDiagnostic(f) {
    const rangeFields = (0, diagnosticCore_1.getDiagnosticRange)(f);
    const range = new vscode.Range(rangeFields.startLine, rangeFields.startCol, rangeFields.endLine, rangeFields.endCol);
    const severity = mapSeverity(f.severity);
    const provenance = (0, provenanceCore_1.provenanceLabel)(f);
    const prefix = f.ruleId !== "SKYLOS" ? `[${provenance}] [${f.ruleId}] ` : `[${provenance}] `;
    const diag = new vscode.Diagnostic(range, `${prefix}${f.message}`, severity);
    diag.source = (0, provenanceCore_1.diagnosticSource)(f);
    diag.code = f.ruleUrl
        ? { value: f.ruleId, target: vscode.Uri.parse(f.ruleUrl) }
        : f.ruleId;
    diag.relatedInformation = relatedInformation(f);
    return diag;
}
function relatedInformation(f) {
    const related = [];
    for (const step of f.trace ?? []) {
        if (!step.file)
            continue;
        const line = Math.max(0, (step.line ?? 1) - 1);
        related.push(new vscode.DiagnosticRelatedInformation(new vscode.Location(vscode.Uri.file(step.file), new vscode.Position(line, 0)), step.message ?? step.label ?? step.symbol ?? "Related Skylos evidence"));
    }
    return related.length > 0 ? related : undefined;
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
