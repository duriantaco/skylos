import * as vscode from "vscode";
import * as path from "path";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Category } from "./types";

type TreeNode = CategoryNode | FileNode | FindingNode;

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
  ai: "AI Analysis",
};

const CATEGORY_ICONS: Record<Category, string> = {
  dead_code: "trash",
  security: "shield",
  secrets: "key",
  quality: "beaker",
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
    if (element instanceof CategoryNode) {
      const item = new vscode.TreeItem(
        `${element.label} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Expanded,
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
      const all = this.store.getAllFindings();
      const byCategory = new Map<Category, SkylosFinding[]>();
      for (const f of all) {
        const list = byCategory.get(f.category) ?? [];
        list.push(f);
        byCategory.set(f.category, list);
      }

      const nodes: CategoryNode[] = [];
      const order: Category[] = ["security", "secrets", "dead_code", "quality", "ai"];
      for (const cat of order) {
        const findings = byCategory.get(cat);
        if (findings && findings.length > 0) {
          nodes.push(new CategoryNode(cat, CATEGORY_LABELS[cat], findings));
        }
      }
      return nodes;
    }

    if (element instanceof CategoryNode) {
      const byFile = new Map<string, SkylosFinding[]>();
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
