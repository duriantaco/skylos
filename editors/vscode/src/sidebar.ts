import * as vscode from "vscode";
import * as path from "path";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Category } from "./types";
import { getMaxTreeFindings, getMaxTreeFindingsPerFile } from "./config";

type TreeNode = SummaryNode | CategoryNode | FileNode | FindingNode;

class SummaryNode {
  constructor(
    public readonly workingTotal: number,
    public readonly visibleTotal: number,
    public readonly rawTotal: number,
    public readonly filterActive: boolean,
  ) {}
}

class CategoryNode {
  constructor(
    public readonly category: Category,
    public readonly label: string,
    public readonly findings: SkylosFinding[],
  ) {}
}

class FileNode {
  constructor(
    public readonly filePath: string,
    public readonly findings: SkylosFinding[],
  ) {}
}

export class FindingNode {
  constructor(public readonly finding: SkylosFinding) {}
}

const CATEGORY_LABELS: Record<Category, string> = {
  dead_code: "Dead Code",
  security: "Security",
  secrets: "Secrets",
  quality: "Quality",
  debt: "Technical Debt",
  ai: "AI Analysis",
};

const CATEGORY_ICONS: Record<Category, string> = {
  dead_code: "trash",
  security: "shield",
  secrets: "key",
  quality: "beaker",
  debt: "wrench",
  ai: "sparkle",
};

export class SkylosTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {
    this.disposables.push(
      store.onDidChange(() => this._onDidChangeTreeData.fire()),
      store.onDidChangeAI(() => this._onDidChangeTreeData.fire()),
    );
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element instanceof SummaryNode) {
      const item = new vscode.TreeItem(
        element.workingTotal === 0
          ? (element.filterActive ? "No findings match the current filter" : "No findings in scope")
          : `Showing ${element.visibleTotal} of ${element.workingTotal} findings`,
        vscode.TreeItemCollapsibleState.None,
      );
      item.iconPath = new vscode.ThemeIcon("filter");
      if (element.rawTotal !== element.workingTotal) {
        item.description = `${element.rawTotal} total in repo`;
      } else if (element.workingTotal > element.visibleTotal) {
        item.description = "Refine with filters or open Dashboard";
      } else if (element.filterActive) {
        item.description = "Filter active";
      }
      item.command = {
        title: "Filter findings",
        command: element.filterActive ? "skylos.clearFilter" : "skylos.filterFindings",
      };
      return item;
    }

    if (element instanceof CategoryNode) {
      const item = new vscode.TreeItem(
        `${element.label} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
      );
      item.iconPath = new vscode.ThemeIcon(CATEGORY_ICONS[element.category]);
      return item;
    }

    if (element instanceof FileNode) {
      const fileName = path.basename(element.filePath);
      const item = new vscode.TreeItem(
        `${fileName} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
      );
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

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      const summary = this.store.getVisibleSummary(getMaxTreeFindings(), {
        maxPerFile: getMaxTreeFindingsPerFile(),
      });
      const all = this.store.getVisibleFindings(getMaxTreeFindings(), {
        maxPerFile: getMaxTreeFindingsPerFile(),
      });
      const byCategory = new Map<Category, SkylosFinding[]>();
      for (const f of all) {
        const list = byCategory.get(f.category) ?? [];
        list.push(f);
        byCategory.set(f.category, list);
      }

      const nodes: CategoryNode[] = [];
      const order: Category[] = ["security", "secrets", "debt", "dead_code", "quality", "ai"];
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
      const byFile = new Map<string, SkylosFinding[]>();
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

  dispose(): void {
    this._onDidChangeTreeData.dispose();
    this.disposables.forEach((d) => d.dispose());
  }
}

function getSeverityIcon(severity: string): vscode.ThemeIcon {
  const s = severity.toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") {
    return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
  }
  if (s === "MEDIUM" || s === "WARN") {
    return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
  }
  return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
}

function compareFileBuckets(a: SkylosFinding[], b: SkylosFinding[]): number {
  const severityDelta = maxSeverityRank(b) - maxSeverityRank(a);
  if (severityDelta !== 0) return severityDelta;
  return b.length - a.length || a[0].file.localeCompare(b[0].file);
}

function compareFindingsInTree(a: SkylosFinding, b: SkylosFinding): number {
  const severityDelta = severityRank(b.severity) - severityRank(a.severity);
  if (severityDelta !== 0) return severityDelta;
  return a.line - b.line || a.message.localeCompare(b.message);
}

function maxSeverityRank(findings: SkylosFinding[]): number {
  return findings.reduce((max, finding) => Math.max(max, severityRank(finding.severity)), 0);
}

function severityRank(severity: string): number {
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
