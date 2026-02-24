"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StreamingDecorationManager = exports.StreamingJsonParser = void 0;
const vscode = require("vscode");
/**
 * Parses streaming LLM output to extract complete JSON issue objects
 * as they arrive chunk by chunk.
 */
class StreamingJsonParser {
    constructor(onIssue) {
        this.buffer = "";
        this.onIssue = onIssue;
    }
    feed(chunk) {
        this.buffer += chunk;
        this.extractObjects();
    }
    extractObjects() {
        // Strip markdown code fences
        let text = this.buffer.replace(/```json?\s*/g, "").replace(/```/g, "");
        let searchFrom = 0;
        while (searchFrom < text.length) {
            const start = text.indexOf("{", searchFrom);
            if (start === -1)
                break;
            let braceCount = 0;
            let end = -1;
            for (let i = start; i < text.length; i++) {
                if (text[i] === "{")
                    braceCount++;
                if (text[i] === "}")
                    braceCount--;
                if (braceCount === 0) {
                    end = i;
                    break;
                }
            }
            if (end === -1) {
                // Incomplete object — keep buffer from this point
                this.buffer = text.slice(start);
                return;
            }
            const jsonStr = text.slice(start, end + 1);
            try {
                const obj = JSON.parse(jsonStr);
                if (typeof obj.line === "number" && typeof obj.message === "string") {
                    this.onIssue({
                        line: obj.line,
                        message: obj.message,
                        severity: obj.severity === "error" ? "error" : "warning",
                    });
                }
            }
            catch {
                // Not valid JSON yet, skip
            }
            searchFrom = end + 1;
            // Update buffer to remove consumed content
            text = text.slice(end + 1);
            searchFrom = 0;
        }
        this.buffer = text;
    }
    reset() {
        this.buffer = "";
    }
}
exports.StreamingJsonParser = StreamingJsonParser;
/**
 * Manages streaming inline decorations: "analyzing..." placeholders
 * and character-by-character issue text reveal.
 */
class StreamingDecorationManager {
    constructor() {
        this.activeTimers = [];
        this.currentStreamDecorations = new Map();
        this.analyzingDecorationType = vscode.window.createTextEditorDecorationType({
            after: {
                contentText: "  analyzing...",
                color: "rgba(150, 150, 150, 0.5)",
                fontStyle: "italic",
                margin: "0 0 0 2ch",
            },
        });
        this.streamingDecorationType = vscode.window.createTextEditorDecorationType({
            after: {
                color: "rgba(80, 160, 255, 0.85)",
                fontStyle: "italic",
                margin: "0 0 0 2ch",
            },
        });
    }
    /** Show "analyzing..." ghost text on function start lines */
    showAnalyzing(editor, lines) {
        const decos = lines
            .filter((l) => l >= 0 && l < editor.document.lineCount)
            .map((l) => ({
            range: new vscode.Range(l, editor.document.lineAt(l).text.length, l, editor.document.lineAt(l).text.length),
        }));
        editor.setDecorations(this.analyzingDecorationType, decos);
    }
    /** Drip-feed an issue message character by character on a line */
    streamIssueText(editor, line, fullMessage) {
        // Clear analyzing decoration for this line by rebuilding without it
        const msg = fullMessage.length > 80 ? fullMessage.slice(0, 77) + "..." : fullMessage;
        let charIndex = 0;
        const timer = setInterval(() => {
            charIndex = Math.min(charIndex + 2, msg.length);
            const partial = msg.slice(0, charIndex);
            if (line >= 0 && line < editor.document.lineCount) {
                this.currentStreamDecorations.set(line, {
                    range: new vscode.Range(line, editor.document.lineAt(line).text.length, line, editor.document.lineAt(line).text.length),
                    renderOptions: {
                        after: { contentText: `  [AI] ${partial}` },
                    },
                });
                editor.setDecorations(this.streamingDecorationType, [...this.currentStreamDecorations.values()]);
            }
            if (charIndex >= msg.length) {
                clearInterval(timer);
            }
        }, 15);
        this.activeTimers.push(timer);
    }
    /** Remove all streaming decorations */
    clearAll() {
        for (const timer of this.activeTimers) {
            clearInterval(timer);
        }
        this.activeTimers = [];
        this.currentStreamDecorations.clear();
        for (const editor of vscode.window.visibleTextEditors) {
            editor.setDecorations(this.analyzingDecorationType, []);
            editor.setDecorations(this.streamingDecorationType, []);
        }
    }
    dispose() {
        this.clearAll();
        this.analyzingDecorationType.dispose();
        this.streamingDecorationType.dispose();
    }
}
exports.StreamingDecorationManager = StreamingDecorationManager;
