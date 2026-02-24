"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingsStore = void 0;
const vscode = require("vscode");
class FindingsStore {
    constructor() {
        this.cliFindingsByFile = new Map();
        this.aiFindingsByFile = new Map();
        this._circularDeps = [];
        this._depVulns = [];
        this._deltaMode = false;
        this._onDidChange = new vscode.EventEmitter();
        this.onDidChange = this._onDidChange.event;
        this._onDidChangeAI = new vscode.EventEmitter();
        this.onDidChangeAI = this._onDidChangeAI.event;
    }
    setCLIFindings(findings) {
        this.cliFindingsByFile.clear();
        for (const f of findings) {
            const list = this.cliFindingsByFile.get(f.file) ?? [];
            list.push(f);
            this.cliFindingsByFile.set(f.file, list);
        }
        this._onDidChange.fire();
    }
    setEngineMetadata(grade, summary, circularDeps, depVulns) {
        this._grade = grade;
        this._summary = summary;
        this._circularDeps = circularDeps ?? [];
        this._depVulns = depVulns ?? [];
    }
    get grade() { return this._grade; }
    get summary() { return this._summary; }
    get circularDeps() { return this._circularDeps; }
    get depVulns() { return this._depVulns; }
    get deltaMode() { return this._deltaMode; }
    set deltaMode(v) { this._deltaMode = v; }
    setAIFindings(filePath, findings) {
        if (findings.length === 0) {
            this.aiFindingsByFile.delete(filePath);
        }
        else {
            this.aiFindingsByFile.set(filePath, findings);
        }
        this._onDidChangeAI.fire();
    }
    getFindingsForFile(filePath) {
        const cli = this.cliFindingsByFile.get(filePath) ?? [];
        const ai = this.aiFindingsByFile.get(filePath) ?? [];
        return [...cli, ...ai];
    }
    getCLIFindingsForFile(filePath) {
        return this.cliFindingsByFile.get(filePath) ?? [];
    }
    getAIFindingsForFile(filePath) {
        return this.aiFindingsByFile.get(filePath) ?? [];
    }
    getAllFindings() {
        const all = [];
        for (const list of this.cliFindingsByFile.values())
            all.push(...list);
        for (const list of this.aiFindingsByFile.values())
            all.push(...list);
        return all;
    }
    getFilesWithFindings() {
        const files = new Set();
        for (const k of this.cliFindingsByFile.keys())
            files.add(k);
        for (const k of this.aiFindingsByFile.keys())
            files.add(k);
        return [...files].sort();
    }
    countBySeverity() {
        const counts = {};
        for (const f of this.getAllFindings()) {
            counts[f.severity] = (counts[f.severity] ?? 0) + 1;
        }
        return counts;
    }
    countByCategory() {
        const counts = {};
        for (const f of this.getAllFindings()) {
            counts[f.category] = (counts[f.category] ?? 0) + 1;
        }
        return counts;
    }
    removeFindingAtLine(filePath, line) {
        const cli = this.cliFindingsByFile.get(filePath);
        if (cli) {
            const filtered = cli.filter((f) => f.line !== line);
            if (filtered.length === 0) {
                this.cliFindingsByFile.delete(filePath);
            }
            else {
                this.cliFindingsByFile.set(filePath, filtered);
            }
        }
        const ai = this.aiFindingsByFile.get(filePath);
        if (ai) {
            const filtered = ai.filter((f) => f.line !== line);
            if (filtered.length === 0) {
                this.aiFindingsByFile.delete(filePath);
            }
            else {
                this.aiFindingsByFile.set(filePath, filtered);
            }
        }
        this._onDidChange.fire();
        this._onDidChangeAI.fire();
    }
    dismissAIFinding(filePath, line) {
        const existing = this.aiFindingsByFile.get(filePath);
        if (!existing)
            return;
        const filtered = existing.filter((f) => f.line !== line);
        if (filtered.length === 0) {
            this.aiFindingsByFile.delete(filePath);
        }
        else {
            this.aiFindingsByFile.set(filePath, filtered);
        }
        this._onDidChangeAI.fire();
    }
    clear() {
        this.cliFindingsByFile.clear();
        this.aiFindingsByFile.clear();
        this._grade = undefined;
        this._summary = undefined;
        this._circularDeps = [];
        this._depVulns = [];
        this._onDidChange.fire();
        this._onDidChangeAI.fire();
    }
    dispose() {
        this._onDidChange.dispose();
        this._onDidChangeAI.dispose();
    }
}
exports.FindingsStore = FindingsStore;
