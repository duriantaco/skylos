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
exports.SkylosQuickFixProvider = void 0;
const vscode = __importStar(require("vscode"));
const types_1 = require("./types");
const findingCore_1 = require("./findingCore");
class SkylosQuickFixProvider {
    constructor(store) {
        this.store = store;
    }
    provideCodeActions(document, _range, context) {
        const actions = [];
        for (const diag of context.diagnostics) {
            if (!diag.source?.startsWith("skylos"))
                continue;
            const line = diag.range.start.line;
            const lineText = document.lineAt(line).text;
            const ruleId = getRuleId(diag.code);
            const langId = document.languageId;
            const finding = this.store.getFindingsForFile(document.uri.fsPath)
                .find((candidate) => candidate.line === line + 1
                && (candidate.ruleId === ruleId || candidate.legacyRuleId === ruleId));
            const ignoreComment = getIgnoreComment(langId);
            if (!lineText.includes(ignoreComment)) {
                const ignoreAction = new vscode.CodeAction(`Skylos: Ignore on this line`, vscode.CodeActionKind.QuickFix);
                ignoreAction.edit = new vscode.WorkspaceEdit();
                ignoreAction.edit.replace(document.uri, new vscode.Range(line, 0, line, lineText.length), lineText + "  " + ignoreComment);
                ignoreAction.diagnostics = [diag];
                actions.push(ignoreAction);
            }
            const fileIgnore = new vscode.CodeAction(`Skylos: Ignore entire file`, vscode.CodeActionKind.QuickFix);
            fileIgnore.edit = new vscode.WorkspaceEdit();
            const fileComment = getFileIgnoreComment(langId);
            fileIgnore.edit.insert(document.uri, new vscode.Position(0, 0), fileComment + "\n");
            fileIgnore.diagnostics = [diag];
            actions.push(fileIgnore);
            if (finding?.fixPatch) {
                const previewFix = new vscode.CodeAction("Skylos: Preview engine fix", vscode.CodeActionKind.QuickFix);
                previewFix.command = {
                    title: "Preview engine fix",
                    command: "skylos.previewSafeFix",
                    arguments: [finding],
                };
                previewFix.diagnostics = [diag];
                actions.push(previewFix);
            }
            if ((0, findingCore_1.isDeadCodeRule)(ruleId)) {
                const whitelist = new vscode.CodeAction(`Add to whitelist`, vscode.CodeActionKind.QuickFix);
                whitelist.command = {
                    title: "Add to whitelist",
                    command: "skylos.addToWhitelist",
                    arguments: [diag.message],
                };
                whitelist.diagnostics = [diag];
                actions.push(whitelist);
            }
            if (diag.source.includes("ai-assist") || ruleId.startsWith("SKY-D") || ruleId.startsWith("SKY-S")) {
                const fixAI = new vscode.CodeAction(`Fix with AI Assist`, vscode.CodeActionKind.QuickFix);
                fixAI.command = {
                    title: "Fix with AI Assist",
                    command: "skylos.fix",
                    arguments: [
                        document.uri.fsPath,
                        diag.range,
                        diag.message,
                        false,
                    ],
                };
                fixAI.diagnostics = [diag];
                actions.push(fixAI);
            }
        }
        return actions;
    }
    register() {
        return vscode.languages.registerCodeActionsProvider((0, types_1.getDocumentFilters)(), this, {
            providedCodeActionKinds: SkylosQuickFixProvider.providedCodeActionKinds,
        });
    }
}
exports.SkylosQuickFixProvider = SkylosQuickFixProvider;
SkylosQuickFixProvider.providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
function getRuleId(code) {
    if (typeof code === "string" || typeof code === "number") {
        return String(code);
    }
    if (code && typeof code === "object" && "value" in code) {
        return String(code.value);
    }
    return "";
}
function getIgnoreComment(langId) {
    if (langId === "python")
        return "# pragma: no skylos";
    return "// skylos-ignore";
}
function getFileIgnoreComment(langId) {
    if (langId === "python")
        return "# skylos-ignore-file";
    return "// skylos-ignore-file";
}
