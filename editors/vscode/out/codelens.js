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
exports.SkylosCodeLensProvider = void 0;
const vscode = __importStar(require("vscode"));
const types_1 = require("./types");
const config_1 = require("./config");
const findingCore_1 = require("./findingCore");
class SkylosCodeLensProvider {
    constructor(store) {
        this.store = store;
        this._onDidChangeCodeLenses = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
        this.disposables = [];
        this.disposables.push(store.onDidChange(() => this._onDidChangeCodeLenses.fire()), store.onDidChangeAI(() => this._onDidChangeCodeLenses.fire()), vscode.window.onDidChangeTextEditorSelection(() => {
            if ((0, config_1.getCodeLensMode)() === "activeLine") {
                this._onDidChangeCodeLenses.fire();
            }
        }));
    }
    refresh() {
        this._onDidChangeCodeLenses.fire();
    }
    provideCodeLenses(document) {
        const lenses = [];
        const mode = (0, config_1.getCodeLensMode)();
        if (mode === "off")
            return lenses;
        const findings = this.store.getFindingsForFile(document.uri.fsPath, { max: (0, config_1.getMaxDecorationsPerFile)() });
        const activeEditor = vscode.window.activeTextEditor;
        const activeLine = activeEditor?.document.uri.fsPath === document.uri.fsPath
            ? activeEditor.selection.active.line
            : undefined;
        for (const f of findings) {
            const line = Math.max(0, f.line - 1);
            if (line >= document.lineCount)
                continue;
            const isActiveLine = activeLine === line;
            if (mode === "activeLine" && !isActiveLine) {
                continue;
            }
            const range = new vscode.Range(line, 0, line, 0);
            const showAllActions = mode === "all" || mode === "activeLine";
            const showHighValueActions = showAllActions || mode === "highValue";
            if (showHighValueActions && (f.category === "security" || f.category === "ai")) {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Fix with AI Assist",
                    command: "skylos.fix",
                    arguments: [document.uri.fsPath, range, f.message, false],
                }));
            }
            if (showHighValueActions && f.fixPatch) {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Preview Engine Fix",
                    command: "skylos.previewSafeFix",
                    arguments: [f],
                }));
            }
            if (showAllActions && (0, findingCore_1.isDeadCodeRule)(f.ruleId)) {
                lenses.push(new vscode.CodeLens(range, {
                    title: "Ignore",
                    command: "skylos.addToWhitelist",
                    arguments: [f.message],
                }));
            }
            if (showHighValueActions && f.source === "ai") {
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
