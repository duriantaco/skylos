"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosStatusBar = void 0;
const vscode = require("vscode");
const dashboard_1 = require("./dashboard");
class SkylosStatusBar {
    constructor(store) {
        this.store = store;
        this.disposables = [];
        this.scanning = false;
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.item.command = "skylos.dashboard";
        this.item.text = "$(shield) Skylos";
        this.item.tooltip = "Click to open Security Dashboard";
        this.item.show();
        this.disposables.push(this.item, store.onDidChange(() => this.refresh()), store.onDidChangeAI(() => this.refresh()));
    }
    setScanning(scanning) {
        this.scanning = scanning;
        if (scanning) {
            this.item.text = "$(sync~spin) Scanning...";
            this.item.backgroundColor = undefined;
        }
        else {
            this.refresh();
        }
    }
    refresh() {
        if (this.scanning)
            return;
        const counts = this.store.countBySeverity();
        const total = Object.values(counts).reduce((s, n) => s + n, 0);
        if (total === 0) {
            this.item.text = "$(shield) Skylos";
            this.item.backgroundColor = undefined;
            this.item.color = undefined;
            this.item.tooltip = "No issues found — Click to open Security Dashboard";
            return;
        }
        const { grade, color } = (0, dashboard_1.computeSecurityScore)(this.store);
        this.item.text = `$(shield) ${grade}`;
        this.item.color = color;
        const critical = counts["CRITICAL"] ?? 0;
        const high = counts["HIGH"] ?? 0;
        const medium = (counts["MEDIUM"] ?? 0) + (counts["WARN"] ?? 0);
        const low = (counts["LOW"] ?? 0) + (counts["INFO"] ?? 0);
        if (grade === "D" || grade === "F") {
            this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
        }
        else if (grade === "C") {
            this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
        }
        else {
            this.item.backgroundColor = undefined;
        }
        this.item.tooltip = `Critical: ${critical} | High: ${high} | Medium: ${medium} | Low: ${low}\nClick to open Security Dashboard`;
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosStatusBar = SkylosStatusBar;
