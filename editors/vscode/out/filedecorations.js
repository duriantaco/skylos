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
exports.SkylosFileDecorationProvider = void 0;
const vscode = __importStar(require("vscode"));
const config_1 = require("./config");
class SkylosFileDecorationProvider {
    constructor(store) {
        this.store = store;
        this._onDidChangeFileDecorations = new vscode.EventEmitter();
        this.onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;
        this.disposables = [];
        this.disposables.push(this._onDidChangeFileDecorations, store.onDidChange(() => this._onDidChangeFileDecorations.fire(undefined)), store.onDidChangeAI(() => this._onDidChangeFileDecorations.fire(undefined)));
    }
    provideFileDecoration(uri) {
        const findings = this.store.getFindingsForFile(uri.fsPath, { max: (0, config_1.getMaxDecorationsPerFile)() });
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
