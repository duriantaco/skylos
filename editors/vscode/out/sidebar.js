"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosTreeProvider = exports.FindingNode = void 0;
const vscode = require("vscode");
const path = require("path");
class CategoryNode {
    constructor(category, label, findings) {
        this.category = category;
        this.label = label;
        this.findings = findings;
    }
}
class FileNode {
    constructor(filePath, findings) {
        this.filePath = filePath;
        this.findings = findings;
    }
}
class FindingNode {
    constructor(finding) {
        this.finding = finding;
    }
}
exports.FindingNode = FindingNode;
const CATEGORY_LABELS = {
    dead_code: "Dead Code",
    security: "Security",
    secrets: "Secrets",
    quality: "Quality",
    ai: "AI Analysis",
};
const CATEGORY_ICONS = {
    dead_code: "trash",
    security: "shield",
    secrets: "key",
    quality: "beaker",
    ai: "sparkle",
};
class SkylosTreeProvider {
    constructor(store) {
        this.store = store;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.disposables = [];
        this.disposables.push(store.onDidChange(() => this._onDidChangeTreeData.fire()), store.onDidChangeAI(() => this._onDidChangeTreeData.fire()));
    }
    getTreeItem(element) {
        if (element instanceof CategoryNode) {
            const item = new vscode.TreeItem(`${element.label} (${element.findings.length})`, vscode.TreeItemCollapsibleState.Expanded);
            item.iconPath = new vscode.ThemeIcon(CATEGORY_ICONS[element.category]);
            return item;
        }
        if (element instanceof FileNode) {
            const fileName = path.basename(element.filePath);
            const item = new vscode.TreeItem(`${fileName} (${element.findings.length})`, vscode.TreeItemCollapsibleState.Collapsed);
            item.iconPath = vscode.ThemeIcon.File;
            item.description = path.dirname(element.filePath);
            item.resourceUri = vscode.Uri.file(element.filePath);
            return item;
        }
        const f = element.finding;
        const item = new vscode.TreeItem(`L${f.line}: ${f.message}`, vscode.TreeItemCollapsibleState.None);
        item.iconPath = getSeverityIcon(f.severity);
        item.tooltip = `[${f.ruleId}] ${f.message}`;
        item.contextValue = "skylosFinding";
        item.command = {
            title: "Go to finding",
            command: "vscode.open",
            arguments: [
                vscode.Uri.file(f.file),
                { selection: new vscode.Range(Math.max(0, f.line - 1), 0, Math.max(0, f.line - 1), 0) },
            ],
        };
        return item;
    }
    getChildren(element) {
        if (!element) {
            const all = this.store.getAllFindings();
            const byCategory = new Map();
            for (const f of all) {
                const list = byCategory.get(f.category) ?? [];
                list.push(f);
                byCategory.set(f.category, list);
            }
            const nodes = [];
            const order = ["security", "secrets", "dead_code", "quality", "ai"];
            for (const cat of order) {
                const findings = byCategory.get(cat);
                if (findings && findings.length > 0) {
                    nodes.push(new CategoryNode(cat, CATEGORY_LABELS[cat], findings));
                }
            }
            return nodes;
        }
        if (element instanceof CategoryNode) {
            const byFile = new Map();
            for (const f of element.findings) {
                const list = byFile.get(f.file) ?? [];
                list.push(f);
                byFile.set(f.file, list);
            }
            return [...byFile.entries()]
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([filePath, findings]) => new FileNode(filePath, findings));
        }
        if (element instanceof FileNode) {
            return element.findings
                .sort((a, b) => a.line - b.line)
                .map((f) => new FindingNode(f));
        }
        return [];
    }
    dispose() {
        this._onDidChangeTreeData.dispose();
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosTreeProvider = SkylosTreeProvider;
function getSeverityIcon(severity) {
    const s = severity.toUpperCase();
    if (s === "CRITICAL" || s === "HIGH") {
        return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    }
    if (s === "MEDIUM" || s === "WARN") {
        return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    }
    return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
}
