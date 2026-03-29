"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosTreeProvider = exports.FindingNode = void 0;
const vscode = require("vscode");
const path = require("path");
const config_1 = require("./config");
class SummaryNode {
    constructor(workingTotal, visibleTotal, rawTotal, filterActive) {
        this.workingTotal = workingTotal;
        this.visibleTotal = visibleTotal;
        this.rawTotal = rawTotal;
        this.filterActive = filterActive;
    }
}
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
    debt: "Technical Debt",
    ai: "AI Analysis",
};
const CATEGORY_ICONS = {
    dead_code: "trash",
    security: "shield",
    secrets: "key",
    quality: "beaker",
    debt: "wrench",
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
        if (element instanceof SummaryNode) {
            const item = new vscode.TreeItem(element.workingTotal === 0
                ? (element.filterActive ? "No findings match the current filter" : "No findings in scope")
                : `Showing ${element.visibleTotal} of ${element.workingTotal} findings`, vscode.TreeItemCollapsibleState.None);
            item.iconPath = new vscode.ThemeIcon("filter");
            if (element.rawTotal !== element.workingTotal) {
                item.description = `${element.rawTotal} total in repo`;
            }
            else if (element.workingTotal > element.visibleTotal) {
                item.description = "Refine with filters or open Dashboard";
            }
            else if (element.filterActive) {
                item.description = "Filter active";
            }
            item.command = {
                title: "Filter findings",
                command: element.filterActive ? "skylos.clearFilter" : "skylos.filterFindings",
            };
            return item;
        }
        if (element instanceof CategoryNode) {
            const item = new vscode.TreeItem(`${element.label} (${element.findings.length})`, vscode.TreeItemCollapsibleState.Collapsed);
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
            const summary = this.store.getVisibleSummary((0, config_1.getMaxTreeFindings)(), {
                maxPerFile: (0, config_1.getMaxTreeFindingsPerFile)(),
            });
            const all = this.store.getVisibleFindings((0, config_1.getMaxTreeFindings)(), {
                maxPerFile: (0, config_1.getMaxTreeFindingsPerFile)(),
            });
            const byCategory = new Map();
            for (const f of all) {
                const list = byCategory.get(f.category) ?? [];
                list.push(f);
                byCategory.set(f.category, list);
            }
            const nodes = [];
            const order = ["security", "secrets", "debt", "dead_code", "quality", "ai"];
            for (const cat of order) {
                const findings = byCategory.get(cat);
                if (findings && findings.length > 0) {
                    nodes.push(new CategoryNode(cat, CATEGORY_LABELS[cat], findings));
                }
            }
            return [new SummaryNode(summary.workingTotal, summary.visibleTotal, summary.rawTotal, this.store.hasActiveFilter), ...nodes];
        }
        if (element instanceof SummaryNode) {
            return [];
        }
        if (element instanceof CategoryNode) {
            const byFile = new Map();
            for (const f of element.findings) {
                const list = byFile.get(f.file) ?? [];
                list.push(f);
                byFile.set(f.file, list);
            }
            return [...byFile.entries()]
                .sort((a, b) => compareFileBuckets(a[1], b[1]))
                .map(([filePath, findings]) => new FileNode(filePath, findings));
        }
        if (element instanceof FileNode) {
            return element.findings
                .sort(compareFindingsInTree)
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
function compareFileBuckets(a, b) {
    const severityDelta = maxSeverityRank(b) - maxSeverityRank(a);
    if (severityDelta !== 0)
        return severityDelta;
    return b.length - a.length || a[0].file.localeCompare(b[0].file);
}
function compareFindingsInTree(a, b) {
    const severityDelta = severityRank(b.severity) - severityRank(a.severity);
    if (severityDelta !== 0)
        return severityDelta;
    return a.line - b.line || a.message.localeCompare(b.message);
}
function maxSeverityRank(findings) {
    return findings.reduce((max, finding) => Math.max(max, severityRank(finding.severity)), 0);
}
function severityRank(severity) {
    switch (severity.toUpperCase()) {
        case "CRITICAL":
            return 5;
        case "HIGH":
            return 4;
        case "MEDIUM":
        case "WARN":
            return 3;
        case "LOW":
            return 2;
        case "INFO":
        default:
            return 1;
    }
}
