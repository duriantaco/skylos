import * as vscode from "vscode";
import * as path from "path";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Category, ScanFailureMetadata, ScanMetadata } from "./types";
import { getMaxTreeFindings, getMaxTreeFindingsPerFile, isRealtimeAIEnabled } from "./config";
import {
  ciImpact,
  hasEvidence,
  isLikelyCiBlocker,
  priorityReasons,
  sortReviewQueue,
  type CiImpact,
  type ReviewContext,
} from "./reviewCore";
import { isCorroborated, sourceSummary } from "./provenanceCore";

type TreeNode = SummaryNode | SectionNode | FindingNode | InfoNode;

class SummaryNode {
  constructor(
    public readonly workingTotal: number,
    public readonly visibleTotal: number,
    public readonly rawTotal: number,
    public readonly filterActive: boolean,
    public readonly lastScan?: ScanMetadata,
    public readonly lastError?: ScanFailureMetadata,
    public readonly impact?: CiImpact,
  ) {}
}

class SectionNode {
  constructor(
    public readonly findings: SkylosFinding[],
    public readonly label: string,
    public readonly description?: string,
    public readonly icon = "list-ordered",
  ) {}
}

class InfoNode {
  constructor(public readonly label: string, public readonly description?: string, public readonly command?: string) {}
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
  ai: "AI Assist",
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
          ? (element.filterActive ? "No matching Skylos issues" : "No Skylos issues in scope")
          : `${element.workingTotal} issue(s) to review`,
        vscode.TreeItemCollapsibleState.None,
      );
      item.iconPath = element.lastError
        ? new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"))
        : new vscode.ThemeIcon("shield");
      if (element.lastError) {
        item.description = "Last scan failed";
      } else if (element.impact?.status === "blocking") {
        item.description = `${element.impact.blockerCount} likely CI blocker(s)`;
      } else if (element.impact?.status === "attention") {
        item.description = `${element.impact.attentionCount} need review`;
      } else if (element.lastScan?.diffBase) {
        item.description = `New issues vs ${element.lastScan.diffBase}`;
      } else if (element.rawTotal !== element.workingTotal) {
        item.description = `${element.rawTotal} total in repo`;
      } else if (element.lastScan?.durationMs !== undefined) {
        item.description = `Last scan ${Math.round(element.lastScan.durationMs / 100) / 10}s`;
      } else if (element.workingTotal > element.visibleTotal) {
        item.description = `Top ${element.visibleTotal} shown`;
      } else if (element.filterActive) {
        item.description = "Filter active";
      }
      item.tooltip = buildSummaryTooltip(element);
      item.command = {
        title: "Filter findings",
        command: element.filterActive ? "skylos.clearFilter" : "skylos.filterFindings",
      };
      return item;
    }

    if (element instanceof SectionNode) {
      const item = new vscode.TreeItem(
        `${element.label} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      item.iconPath = new vscode.ThemeIcon(element.icon);
      item.description = element.description;
      return item;
    }

    if (element instanceof InfoNode) {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(element.command ? "play" : "info");
      item.description = element.description;
      if (element.command) {
        item.command = { title: element.label, command: element.command };
      }
      return item;
    }

    const f = element.finding;
    const item = new vscode.TreeItem(buildFindingLabel(f), vscode.TreeItemCollapsibleState.None);
    item.iconPath = getSeverityIcon(f.severity);
    item.description = buildFindingDescription(f, getReviewContext(this.store.lastScan));
    item.tooltip = buildFindingTooltip(f, getReviewContext(this.store.lastScan));
    item.contextValue = f.fixPatch ? "skylosFindingSafeFix" : "skylosFinding";
    item.resourceUri = vscode.Uri.file(f.file);
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
      const context = getReviewContext(this.store.lastScan);
      const findings = sortReviewQueue(this.store.getVisibleFindings(getMaxTreeFindings(), {
        maxPerFile: getMaxTreeFindingsPerFile(),
      }), context);
      const allFindings = this.store.getAllFindings();
      const impact = ciImpact(allFindings, context);
      const nodes: TreeNode[] = [
        new SummaryNode(
          summary.workingTotal,
          summary.visibleTotal,
          summary.rawTotal,
          this.store.hasActiveFilter,
          this.store.lastScan,
          this.store.lastError,
          impact,
        ),
      ];
      nodes.push(buildStatusNode(this.store.lastScan, this.store.lastError, allFindings));

      if (findings.length === 0) {
        if (this.store.lastError) {
          nodes.push(new InfoNode("Run Doctor", "Check the Skylos CLI setup", "skylos.doctor"));
        } else {
          nodes.push(new InfoNode("Scan Workspace", "Populate the Skylos review queue", "skylos.scan"));
        }
        return nodes;
      }

      nodes.push(...buildReviewSections(findings, context));
      return nodes;
    }

    if (element instanceof SummaryNode || element instanceof InfoNode) {
      return [];
    }

    if (element instanceof SectionNode) {
      return element.findings.map((f) => new FindingNode(f));
    }

    return [];
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
    this.disposables.forEach((d) => d.dispose());
  }
}

function buildStatusNode(
  lastScan: ScanMetadata | undefined,
  lastError: ScanFailureMetadata | undefined,
  findings: SkylosFinding[],
): InfoNode {
  const staticLabel = lastError ? "Static scan failed" : lastScan ? "Static scan complete" : "Static scan pending";
  const automationOn = findings.some((finding) => (finding.sources ?? [finding.source]).includes("agent"));
  const aiOn = isRealtimeAIEnabled();
  return new InfoNode(
    staticLabel,
    `Automation: ${automationOn ? "On" : "Off"} · AI Assist: ${aiOn ? "On" : "Off"}`,
    lastError ? "skylos.doctor" : undefined,
  );
}

function buildReviewSections(findings: SkylosFinding[], context: ReviewContext): SectionNode[] {
  const blockers = findings.filter((finding) => isBlockerFinding(finding, context));
  const blockerKeys = new Set(blockers.map(findingKey));
  const needsReview = findings.filter((finding) =>
    !blockerKeys.has(findingKey(finding)) && isNeedsReviewFinding(finding, context),
  );
  const reviewKeys = new Set(needsReview.map(findingKey));
  const safeFixes = findings.filter((finding) =>
    finding.fixPatch && !blockerKeys.has(findingKey(finding)) && !reviewKeys.has(findingKey(finding)),
  );
  const used = new Set([...blockers, ...needsReview, ...safeFixes].map(findingKey));
  const later = findings.filter((finding) => !used.has(findingKey(finding)));

  const sections: SectionNode[] = [];
  if (blockers.length > 0) {
    sections.push(new SectionNode(
      blockers,
      "Blockers",
      "Likely to fail CI or expose security risk",
      "flame",
    ));
  }
  if (needsReview.length > 0) {
    sections.push(new SectionNode(
      needsReview,
      "Needs Review",
      "Important findings without a safe automatic fix",
      "eye",
    ));
  }
  if (safeFixes.length > 0) {
    sections.push(new SectionNode(
      safeFixes,
      "Fixable",
      "Engine-backed patch available",
      "diff",
    ));
  }
  if (later.length > 0) {
    sections.push(new SectionNode(
      later,
      sections.length === 0 ? "Review Queue" : "Review Later",
      "Lower-risk quality and dead-code findings",
      "list-ordered",
    ));
  }
  return sections;
}

function isBlockerFinding(finding: SkylosFinding, context: ReviewContext): boolean {
  const severity = finding.severity.toUpperCase();
  return isLikelyCiBlocker(finding)
    || severity === "CRITICAL"
    || finding.category === "secrets"
    || (finding.category === "security" && severity === "HIGH")
    || (isCorroborated(finding) && (severity === "HIGH" || severity === "CRITICAL"));
}

function isNeedsReviewFinding(finding: SkylosFinding, context: ReviewContext): boolean {
  const severity = finding.severity.toUpperCase();
  return finding.file === context.currentFile
    || finding.isNew === true
    || finding.baselineStatus === "new"
    || isCorroborated(finding)
    || severity === "HIGH"
    || finding.category === "security"
    || severity === "MEDIUM"
    || severity === "WARN";
}

function findingKey(finding: SkylosFinding): string {
  return finding.fingerprint ?? `${finding.ruleId}:${finding.file}:${finding.line}:${finding.message}`;
}

function buildFindingLabel(finding: SkylosFinding): string {
  return `${finding.severity} ${finding.ruleId}: ${shorten(finding.message, 72)}`;
}

function buildFindingDescription(finding: SkylosFinding, context: ReviewContext): string {
  const file = `${path.basename(finding.file)}:${finding.line}`;
  const badges = buildFindingBadges(finding, context);
  return badges.length > 0 ? `${file}  ${badges.join(" ")}` : file;
}

function buildFindingBadges(finding: SkylosFinding, context: ReviewContext): string[] {
  const badges: string[] = [];
  if (finding.file === context.currentFile) badges.push("current");
  if (isCorroborated(finding)) badges.push("Confirmed");
  if (isLikelyCiBlocker(finding)) badges.push("ci");
  if (finding.isNew || finding.baselineStatus === "new") badges.push("new");
  if (finding.fixPatch) badges.push("fix");
  if (hasEvidence(finding)) badges.push("evidence");
  if (finding.confidence !== undefined) badges.push(`${finding.confidence}%`);
  badges.push(sourceSummary(finding));
  badges.push(CATEGORY_LABELS[finding.category] ?? finding.category);
  return badges;
}

function buildFindingTooltip(finding: SkylosFinding, context: ReviewContext): string {
  const lines = [
    `[${finding.ruleId}] ${finding.message}`,
    `Severity: ${finding.severity}`,
    `Category: ${CATEGORY_LABELS[finding.category] ?? finding.category}`,
    `Source: ${isCorroborated(finding) ? `Confirmed by ${sourceSummary(finding)}` : sourceSummary(finding)}`,
    `Location: ${finding.relativePath ?? finding.file}:${finding.line}`,
    "",
    "Why ranked here:",
    ...priorityReasons(finding, context).map((reason) => `- ${reason}`),
  ];
  if (finding.confidence !== undefined) lines.push(`Confidence: ${finding.confidence}%`);
  if (finding.isNew || finding.baselineStatus) lines.push(`Baseline: ${finding.baselineStatus ?? "new"}`);
  if (finding.fixPatch) lines.push("Engine fix: preview available");
  if (hasEvidence(finding)) lines.push("Evidence: attached");
  return lines.join("\n");
}

function buildSummaryTooltip(node: SummaryNode): string {
  const lines = [
    `Visible: ${node.visibleTotal}`,
    `In current scope: ${node.workingTotal}`,
    `Raw total: ${node.rawTotal}`,
  ];
  if (node.impact) {
    lines.push("", node.impact.headline);
    for (const reason of node.impact.reasons) lines.push(`- ${reason}`);
  }
  if (node.lastScan) {
    lines.push(`Last command: ${node.lastScan.command}`);
    if (node.lastScan.durationMs !== undefined) {
      lines.push(`Duration: ${Math.round(node.lastScan.durationMs / 100) / 10}s`);
    }
  }
  if (node.lastError) {
    lines.push(`Last error: ${node.lastError.message}`);
  }
  return lines.join("\n");
}

function getReviewContext(lastScan?: ScanMetadata): ReviewContext {
  return {
    currentFile: vscode.window.activeTextEditor?.document.uri.fsPath,
    visibleFiles: vscode.window.visibleTextEditors.map((editor) => editor.document.uri.fsPath),
    diffBase: lastScan?.diffBase,
  };
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

function shorten(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1)).trimEnd()}...`;
}
