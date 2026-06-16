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
exports.FindingNavigator = void 0;
const vscode = __importStar(require("vscode"));
const config_1 = require("./config");
class FindingNavigator {
    constructor(store) {
        this.store = store;
        this.findings = [];
        this.index = -1;
        this.disposables = [];
        this.flashDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: "rgba(250, 204, 21, 0.25)",
            isWholeLine: true,
        });
        this.disposables.push(this.flashDecoration, store.onDidChange(() => this.rebuild()), store.onDidChangeAI(() => this.rebuild()));
        this.rebuild();
    }
    rebuild() {
        this.findings = this.store
            .getVisibleFindings((0, config_1.getMaxTreeFindings)(), { maxPerFile: (0, config_1.getMaxTreeFindingsPerFile)() })
            .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
        if (this.findings.length === 0) {
            this.index = -1;
        }
        else if (this.index >= this.findings.length) {
            this.index = 0;
        }
    }
    async next() {
        if (this.findings.length === 0) {
            vscode.window.setStatusBarMessage("No findings to navigate", 3000);
            return;
        }
        this.index = (this.index + 1) % this.findings.length;
        await this.goTo(this.index);
    }
    async prev() {
        if (this.findings.length === 0) {
            vscode.window.setStatusBarMessage("No findings to navigate", 3000);
            return;
        }
        this.index = (this.index - 1 + this.findings.length) % this.findings.length;
        await this.goTo(this.index);
    }
    async goTo(idx) {
        const f = this.findings[idx];
        if (!f)
            return;
        const uri = vscode.Uri.file(f.file);
        const line = Math.max(0, f.line - 1);
        const range = new vscode.Range(line, 0, line, 0);
        const editor = await vscode.window.showTextDocument(uri, {
            selection: range,
            preserveFocus: false,
        });
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
        const flashRange = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
        editor.setDecorations(this.flashDecoration, [flashRange]);
        setTimeout(() => {
            editor.setDecorations(this.flashDecoration, []);
        }, 1500);
        const shortFile = f.file.split("/").pop() ?? f.file;
        vscode.window.setStatusBarMessage(`Finding ${idx + 1}/${this.findings.length}: [${f.ruleId}] ${f.message} in ${shortFile}`, 5000);
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.FindingNavigator = FindingNavigator;
