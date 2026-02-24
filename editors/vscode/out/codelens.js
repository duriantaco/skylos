"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosCodeLensProvider = void 0;
const vscode = require("vscode");
const types_1 = require("./types");
class SkylosCodeLensProvider {
    constructor(store) {
        this.store = store;
        this._onDidChangeCodeLenses = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
        this.disposables = [];
        this.disposables.push(store.onDidChange(() => this._onDidChangeCodeLenses.fire()), store.onDidChangeAI(() => this._onDidChangeCodeLenses.fire()));
    }
    refresh() {
        this._onDidChangeCodeLenses.fire();
    }
    provideCodeLenses(document) {
        const lenses = [];
        const findings = this.store.getFindingsForFile(document.uri.fsPath);
        for (const f of findings) {
            const line = Math.max(0, f.line - 1);
            if (line >= document.lineCount)
                continue;
            const range = new vscode.Range(line, 0, line, 0);
            if (f.category === "security" || f.category === "ai") {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Fix with AI",
                    command: "skylos.fix",
                    arguments: [document.uri.fsPath, range, f.message, false],
                }));
            }
            if (f.ruleId === "DEAD-IMPORT") {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Remove Import",
                    command: "skylos.removeImport",
                    arguments: [document.uri, line],
                }));
            }
            if (f.ruleId === "DEAD-FUNC") {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Remove Function",
                    command: "skylos.removeFunction",
                    arguments: [document.uri, line],
                }));
            }
            if (f.ruleId.startsWith("DEAD-")) {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Ignore",
                    command: "skylos.addToWhitelist",
                    arguments: [f.message],
                }));
            }
            if (f.source === "ai") {
                lenses.push(new vscode.CodeLens(range, {
                    title: "\u2715 Dismiss",
                    command: "skylos.dismissIssue",
                    arguments: [document.uri.fsPath, f.line],
                }));
            }
        }
        return lenses;
    }
    register() {
        return vscode.languages.registerCodeLensProvider((0, types_1.getDocumentFilters)(), this);
    }
    dispose() {
        this._onDidChangeCodeLenses.dispose();
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosCodeLensProvider = SkylosCodeLensProvider;
