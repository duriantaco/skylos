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
exports.SkylosHoverProvider = void 0;
const vscode = __importStar(require("vscode"));
const rules_1 = require("./rules");
const types_1 = require("./types");
const config_1 = require("./config");
const provenanceCore_1 = require("./provenanceCore");
class SkylosHoverProvider {
    constructor(store) {
        this.store = store;
    }
    provideHover(document, position) {
        const findings = this.store.getFindingsForFile(document.uri.fsPath, { max: (0, config_1.getMaxDecorationsPerFile)() });
        const lineFindings = findings.filter((f) => Math.max(0, f.line - 1) === position.line);
        if (lineFindings.length === 0)
            return undefined;
        const parts = [];
        for (const f of lineFindings) {
            const md = new vscode.MarkdownString();
            md.supportHtml = false;
            md.isTrusted = false;
            const sevEmoji = getSeverityEmoji(f.severity);
            const meta = (0, rules_1.getRuleMeta)(f.ruleId);
            const ruleName = meta?.name ?? f.ruleId;
            md.appendMarkdown(`### ${sevEmoji} `);
            md.appendText(f.ruleId);
            md.appendMarkdown(" — ");
            md.appendText(ruleName);
            md.appendMarkdown("\n\n");
            md.appendMarkdown("**Severity:** ");
            md.appendText(f.severity);
            md.appendMarkdown("\n\n");
            md.appendMarkdown("**Source:** ");
            md.appendText((0, provenanceCore_1.provenanceLabel)(f));
            md.appendMarkdown("\n\n");
            md.appendText(f.message);
            md.appendMarkdown("\n\n");
            if (meta?.description) {
                md.appendMarkdown("*");
                md.appendText(meta.description);
                md.appendMarkdown("*\n\n");
            }
            if (f.confidence !== undefined) {
                md.appendMarkdown(`**Confidence:** ${f.confidence}%\n\n`);
            }
            const refs = [];
            if (meta?.owasp)
                refs.push(`OWASP ${meta.owasp}`);
            if (meta?.cwe)
                refs.push(meta.cwe);
            if (meta?.pciDss)
                refs.push(`PCI DSS ${meta.pciDss}`);
            if (refs.length > 0) {
                md.appendMarkdown("**References:** ");
                md.appendText(refs.join(" | "));
                md.appendMarkdown("\n\n");
            }
            if (meta?.fix) {
                md.appendMarkdown("**Fix:** ");
                md.appendText(meta.fix);
                md.appendMarkdown("\n\n");
            }
            md.appendMarkdown("---\n");
            parts.push(md);
        }
        return new vscode.Hover(parts);
    }
    register() {
        return vscode.languages.registerHoverProvider((0, types_1.getDocumentFilters)(), this);
    }
}
exports.SkylosHoverProvider = SkylosHoverProvider;
function getSeverityEmoji(severity) {
    switch (severity.toUpperCase()) {
        case "CRITICAL":
            return "\u{1F6A8}";
        case "HIGH":
            return "\u{1F534}";
        case "MEDIUM":
            return "\u{1F7E1}";
        case "WARN":
            return "\u{1F7E1}";
        case "LOW":
            return "\u{1F535}";
        default:
            return "\u{2139}\u{FE0F}";
    }
}
