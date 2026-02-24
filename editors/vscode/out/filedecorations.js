"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosFileDecorationProvider = void 0;
const vscode = require("vscode");
class SkylosFileDecorationProvider {
    constructor(store) {
        this.store = store;
        this._onDidChangeFileDecorations = new vscode.EventEmitter();
        this.onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;
        this.disposables = [];
        this.disposables.push(this._onDidChangeFileDecorations, store.onDidChange(() => this._onDidChangeFileDecorations.fire(undefined)), store.onDidChangeAI(() => this._onDidChangeFileDecorations.fire(undefined)));
    }
    provideFileDecoration(uri) {
        const findings = this.store.getFindingsForFile(uri.fsPath);
        if (findings.length === 0)
            return undefined;
        let hasCritical = false;
        let hasHigh = false;
        let hasMedium = false;
        for (const f of findings) {
            const s = f.severity.toUpperCase();
            if (s === "CRITICAL")
                hasCritical = true;
            else if (s === "HIGH")
                hasHigh = true;
            else if (s === "MEDIUM" || s === "WARN")
                hasMedium = true;
        }
        if (hasCritical) {
            return {
                badge: `${findings.length}`,
                tooltip: `Skylos: ${findings.length} issue(s) — CRITICAL`,
                color: new vscode.ThemeColor("errorForeground"),
            };
        }
        if (hasHigh) {
            return {
                badge: `${findings.length}`,
                tooltip: `Skylos: ${findings.length} issue(s) — HIGH`,
                color: new vscode.ThemeColor("editorWarning.foreground"),
            };
        }
        if (hasMedium) {
            return {
                badge: `${findings.length}`,
                tooltip: `Skylos: ${findings.length} issue(s)`,
                color: new vscode.ThemeColor("editorWarning.foreground"),
            };
        }
        return {
            badge: `${findings.length}`,
            tooltip: `Skylos: ${findings.length} issue(s)`,
            color: new vscode.ThemeColor("editorInfo.foreground"),
        };
    }
    register() {
        return vscode.window.registerFileDecorationProvider(this);
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosFileDecorationProvider = SkylosFileDecorationProvider;
