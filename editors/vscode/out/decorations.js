"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DecorationsManager = void 0;
const vscode = require("vscode");
const deadCodeType = () => ({
    isWholeLine: true,
    opacity: "0.45",
    textDecoration: "line-through rgba(120, 160, 220, 0.5)",
    overviewRulerColor: "rgba(80, 160, 255, 0.4)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
        margin: "0 0 0 4ch",
        color: "rgba(100, 160, 240, 0.55)",
        fontStyle: "italic",
    },
});
const criticalType = () => ({
    isWholeLine: true,
    backgroundColor: "rgba(255, 50, 50, 0.08)",
    borderWidth: "0 0 0 3px",
    borderStyle: "solid",
    borderColor: "#ef4444",
    overviewRulerColor: "rgba(255, 60, 60, 0.9)",
    overviewRulerLane: vscode.OverviewRulerLane.Full,
    after: {
        margin: "0 0 0 3ch",
        color: "#ef4444",
        fontWeight: "600",
    },
});
const highType = () => ({
    isWholeLine: true,
    backgroundColor: "rgba(251, 146, 60, 0.06)",
    borderWidth: "0 0 0 3px",
    borderStyle: "solid",
    borderColor: "#fb923c",
    overviewRulerColor: "rgba(255, 140, 40, 0.8)",
    overviewRulerLane: vscode.OverviewRulerLane.Full,
    after: {
        margin: "0 0 0 3ch",
        color: "#fb923c",
        fontWeight: "500",
    },
});
const mediumType = () => ({
    isWholeLine: true,
    borderWidth: "0 0 1px 0",
    borderStyle: "dotted",
    borderColor: "rgba(250, 204, 21, 0.4)",
    overviewRulerColor: "rgba(255, 220, 40, 0.6)",
    overviewRulerLane: vscode.OverviewRulerLane.Center,
    after: {
        margin: "0 0 0 3ch",
        color: "rgba(234, 179, 8, 0.7)",
        fontStyle: "italic",
    },
});
const lowType = () => ({
    isWholeLine: true,
    overviewRulerColor: "rgba(80, 160, 255, 0.4)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
        margin: "0 0 0 4ch",
        color: "rgba(100, 170, 255, 0.5)",
        fontStyle: "italic",
    },
});
const aiType = () => ({
    isWholeLine: true,
    backgroundColor: "rgba(168, 85, 247, 0.06)",
    borderWidth: "0 0 0 2px",
    borderStyle: "solid",
    borderColor: "rgba(168, 85, 247, 0.5)",
    overviewRulerColor: "rgba(168, 85, 247, 0.6)",
    overviewRulerLane: vscode.OverviewRulerLane.Center,
    after: {
        margin: "0 0 0 3ch",
        color: "rgba(192, 132, 252, 0.8)",
        fontStyle: "italic",
    },
});
const GUTTER_SEVERITY = {
    CRITICAL: "red",
    HIGH: "red",
    MEDIUM: "yellow",
    WARN: "yellow",
    LOW: "blue",
    INFO: "blue",
};
function classifyFinding(f) {
    if (f.source === "ai")
        return "ai";
    if (f.category === "dead_code")
        return "dead";
    const sev = f.severity.toUpperCase();
    if (sev === "CRITICAL")
        return "critical";
    if (sev === "HIGH")
        return "high";
    if (sev === "MEDIUM" || sev === "WARN")
        return "medium";
    return "low";
}
function formatInlineMessage(f, cat) {
    const maxLen = 70;
    const ruleTag = f.ruleId !== "SKYLOS" ? `${f.ruleId} ` : "";
    if (cat === "dead") {
        const name = f.itemName ?? f.message.replace(/^Unused \w+:\s*/, "");
        const pct = f.confidence !== undefined ? ` (${f.confidence}%)` : "";
        return `  unused — ${name}${pct}`;
    }
    if (cat === "ai") {
        const msg = f.message.length > maxLen ? f.message.slice(0, maxLen - 3) + "..." : f.message;
        return `  AI: ${msg}`;
    }
    if (cat === "critical" || cat === "high") {
        const sevLabel = f.severity.toUpperCase();
        const msg = f.message.length > (maxLen - 15) ? f.message.slice(0, maxLen - 18) + "..." : f.message;
        return `  ${sevLabel} ${ruleTag}— ${msg}`;
    }
    const msg = f.message.length > maxLen ? f.message.slice(0, maxLen - 3) + "..." : f.message;
    return `  ${ruleTag}${msg}`;
}
class DecorationsManager {
    constructor(store, context) {
        this.store = store;
        this.decoTypes = new Map();
        this.gutterTypes = new Map();
        this.disposables = [];
        const typeMap = [
            ["dead", deadCodeType()],
            ["critical", criticalType()],
            ["high", highType()],
            ["medium", mediumType()],
            ["low", lowType()],
            ["ai", aiType()],
        ];
        for (const [key, opts] of typeMap) {
            const dt = vscode.window.createTextEditorDecorationType(opts);
            this.decoTypes.set(key, dt);
            this.disposables.push(dt);
        }
        for (const color of ["red", "yellow", "blue"]) {
            const iconPath = vscode.Uri.joinPath(context.extensionUri, "media", `gutter-${color}.svg`);
            const gt = vscode.window.createTextEditorDecorationType({
                gutterIconPath: iconPath,
                gutterIconSize: "80%",
            });
            this.gutterTypes.set(color, gt);
            this.disposables.push(gt);
        }
        this.disposables.push(store.onDidChange(() => this.refresh()), store.onDidChangeAI(() => this.refresh()), vscode.window.onDidChangeVisibleTextEditors(() => this.refresh()));
    }
    refresh() {
        for (const editor of vscode.window.visibleTextEditors) {
            this.applyToEditor(editor);
        }
    }
    applyToEditor(editor) {
        const filePath = editor.document.uri.fsPath;
        const findings = this.store.getFindingsForFile(filePath);
        const byCat = new Map();
        for (const key of this.decoTypes.keys()) {
            byCat.set(key, []);
        }
        const byGutter = new Map();
        for (const color of ["red", "yellow", "blue"]) {
            byGutter.set(color, []);
        }
        for (const f of findings) {
            const line = Math.max(0, f.line - 1);
            if (line >= editor.document.lineCount)
                continue;
            const range = new vscode.Range(line, 0, line, 0);
            const cat = classifyFinding(f);
            const inlineMsg = formatInlineMessage(f, cat);
            const sevKey = f.severity.toUpperCase();
            const list = byCat.get(cat);
            list.push({
                range,
                hoverMessage: f.message,
                renderOptions: {
                    after: { contentText: inlineMsg },
                },
            });
            if (cat !== "dead") {
                const gutterColor = GUTTER_SEVERITY[sevKey] ?? "blue";
                byGutter.get(gutterColor).push({ range });
            }
        }
        for (const [cat, decos] of byCat) {
            const dt = this.decoTypes.get(cat);
            if (dt)
                editor.setDecorations(dt, decos);
        }
        for (const [color, decos] of byGutter) {
            const gt = this.gutterTypes.get(color);
            if (gt)
                editor.setDecorations(gt, decos);
        }
    }
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.DecorationsManager = DecorationsManager;
