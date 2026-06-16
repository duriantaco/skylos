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
exports.SkylosStatusBar = void 0;
const vscode = __importStar(require("vscode"));
const dashboard_1 = require("./dashboard");
const config_1 = require("./config");
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
        const summary = this.store.getVisibleSummary((0, config_1.getMaxProblems)());
        const lastError = this.store.lastError;
        if (lastError) {
            this.item.text = "$(warning) Skylos";
            this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            this.item.color = undefined;
            this.item.tooltip = `Last Skylos scan failed: ${lastError.message}\nClick to open Security Dashboard`;
            return;
        }
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
        const scopeLine = summary.visibleTotal < summary.workingTotal
            ? `Showing top ${summary.visibleTotal} of ${summary.workingTotal} findings in editor surfaces\n`
            : "";
        const scanLine = this.store.lastScan?.diffBase
            ? `Mode: new issues vs ${this.store.lastScan.diffBase}\n`
            : "";
        this.item.tooltip = `${scanLine}${scopeLine}Critical: ${critical} | High: ${high} | Medium: ${medium} | Low: ${low}\nClick to open Security Dashboard`;
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosStatusBar = SkylosStatusBar;
