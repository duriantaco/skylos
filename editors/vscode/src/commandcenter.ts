import * as fs from "fs/promises";
import * as path from "path";
import { spawn } from "child_process";
import * as vscode from "vscode";
import {
  getCommandCenterLimit,
  getCommandCenterStateFile,
  getSkylosBin,
  isCommandCenterRefreshOnOpen,
} from "./config";
import { out } from "./scanner";
import type {
  AgentCenterFinding,
  AgentCommandCenterItem,
  AgentCommandCenterState,
  SkylosFinding,
} from "./types";

type CommandCenterNode = SummaryNode | InfoNode | ActionNode | EmptyNode;

class SummaryNode {
  constructor(public readonly state: AgentCommandCenterState) {}
}

class InfoNode {
  constructor(
    public readonly label: string,
    public readonly description?: string,
    public readonly icon?: string,
    public readonly command?: string,
  ) {}
}

export class ActionNode {
  constructor(public readonly action: AgentCommandCenterItem) {}
}

class EmptyNode {
  constructor(public readonly label: string, public readonly description?: string) {}
}

export class SkylosCommandCenterProvider implements vscode.TreeDataProvider<CommandCenterNode>, vscode.Disposable {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private _onDidUpdateState = new vscode.EventEmitter<void>();
  readonly onDidUpdateState = this._onDidUpdateState.event;

  private state: AgentCommandCenterState | undefined;
  private watcher: vscode.FileSystemWatcher | undefined;
  private disposables: vscode.Disposable[] = [];
  private watcherDisposables: vscode.Disposable[] = [];
  private refreshing = false;
  private pendingRefresh = false;
  private refreshTimer: NodeJS.Timeout | undefined;

  constructor() {
    this.disposables.push(this._onDidChangeTreeData, this._onDidUpdateState);
    this.updateWatcher();
    this.disposables.push(
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        this.updateWatcher();
        void this.loadState();
      }),
    );
  }

  async initialize(): Promise<void> {
    await this.loadState();
    if (isCommandCenterRefreshOnOpen()) {
      void this.refresh();
    }
  }

  get actionCount(): number {
    return this.getActions().length;
  }

  get triagedCount(): number {
    return Object.keys(this.state?.triage ?? {}).length;
  }

  getTriagedEntries(): Array<{ id: string; entry: { status: string; updated_at?: string; snoozed_until?: string } }> {
    return Object.entries(this.state?.triage ?? {})
      .map(([id, entry]) => ({ id, entry }))
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  scheduleRefresh(delayMs = 1200): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => {
      void this.refresh();
    }, delayMs);
  }

  async refresh(): Promise<void> {
    const root = this.getWorkspaceRoot();
    if (!root) {
      vscode.window.showWarningMessage("Skylos: open a folder to use Command Center.");
      return;
    }

    if (this.refreshing) {
      this.pendingRefresh = true;
      return;
    }

    this.refreshing = true;
    this._onDidChangeTreeData.fire();
    vscode.window.setStatusBarMessage("Skylos: refreshing Command Center...", 3000);

    try {
      await this.runCommandCenterRefresh(root);
      await this.loadState();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      vscode.window.showErrorMessage(`Skylos Command Center refresh failed: ${msg}`);
    } finally {
      this.refreshing = false;
      this._onDidChangeTreeData.fire();
      if (this.pendingRefresh) {
        this.pendingRefresh = false;
        void this.refresh();
      }
    }
  }

  async handleConfigurationChanged(): Promise<void> {
    this.updateWatcher();
    await this.loadState();
  }

  getFindingForAction(action: AgentCommandCenterItem): AgentCenterFinding | undefined {
    return (this.state?.findings ?? []).find((finding) => finding.fingerprint === action.id);
  }

  getFindingById(actionId: string): AgentCenterFinding | undefined {
    return (this.state?.findings ?? []).find((finding) => finding.fingerprint === actionId);
  }

  toSkylosFinding(action: AgentCommandCenterItem): SkylosFinding | undefined {
    const finding = this.getFindingForAction(action);
    const absoluteFile = action.absolute_file || finding?.absolute_file || resolveActionPath(action.file);
    if (!absoluteFile) return undefined;

    return {
      id: action.id,
      ruleId: action.rule_id || finding?.rule_id || "SKY-ACTIVE",
      category: normalizeCategory(action.category || finding?.category),
      severity: normalizeSeverity(action.severity || finding?.severity),
      message: action.message || finding?.message || action.title,
      file: absoluteFile,
      line: Number(action.line || finding?.line || 1),
      col: 1,
      confidence: finding?.confidence,
      source: "cli",
    };
  }

  async dismissAction(action: AgentCommandCenterItem): Promise<void> {
    await this.runTriagingCommand(["dismiss", this.requireWorkspaceRoot(), action.id]);
  }

  async snoozeAction(action: AgentCommandCenterItem, hours: number): Promise<void> {
    await this.runTriagingCommand(["snooze", this.requireWorkspaceRoot(), action.id, "--hours", String(hours)]);
  }

  async restoreAction(actionId: string): Promise<void> {
    await this.runTriagingCommand(["restore", this.requireWorkspaceRoot(), actionId]);
  }

  getTreeItem(element: CommandCenterNode): vscode.TreeItem {
    if (element instanceof SummaryNode) {
      const summary = element.state.summary;
      const item = new vscode.TreeItem(
        summary?.headline ?? "Command Center",
        vscode.TreeItemCollapsibleState.None,
      );
      item.iconPath = new vscode.ThemeIcon("pulse");
      item.description = summary?.subtitle ?? describeState(element.state);
      item.tooltip = buildSummaryTooltip(element.state);
      return item;
    }

    if (element instanceof InfoNode) {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(element.icon ?? "info");
      item.description = element.description;
      if (element.command) {
        item.command = { title: element.label, command: element.command };
      }
      return item;
    }

    if (element instanceof EmptyNode) {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(this.refreshing ? "sync~spin" : "circle-slash");
      item.description = element.description;
      if (!this.refreshing) {
        item.command = { title: "Refresh Command Center", command: "skylos.refreshCommandCenter" };
      }
      return item;
    }

    const action = element.action;
    const line = Math.max(0, Number(action.line || 1) - 1);
    const absoluteFile = action.absolute_file || resolveActionPath(action.file);
    const item = new vscode.TreeItem(
      action.title,
      vscode.TreeItemCollapsibleState.None,
    );
    item.description = `${action.file}:${action.line}`;
    item.tooltip = buildActionTooltip(action);
    item.iconPath = getActionIcon(action.severity);
    item.contextValue = action.safe_fix ? "skylosCommandCenterActionSafeFix" : "skylosCommandCenterAction";
    if (absoluteFile) {
      item.command = {
        title: "Open action target",
        command: "vscode.open",
        arguments: [
          vscode.Uri.file(absoluteFile),
          { selection: new vscode.Range(line, 0, line, 0) },
        ],
      };
    }
    return item;
  }

  getChildren(element?: CommandCenterNode): CommandCenterNode[] {
    if (element) {
      return [];
    }

    if (this.refreshing && !this.state) {
      return [new EmptyNode("Refreshing Command Center...", "Running repo-level agent analysis")];
    }

    if (!this.getWorkspaceRoot()) {
      return [new EmptyNode("Open a workspace folder to use Command Center")];
    }

    if (!this.state) {
      return [
        new EmptyNode(
          "No Command Center state yet",
          "Run Refresh Command Center or `skylos agent watch .`",
        ),
      ];
    }

    const nodes: CommandCenterNode[] = [new SummaryNode(this.state)];
    const generatedAt = this.state.generated_at ? formatGeneratedAt(this.state.generated_at) : undefined;
    if (generatedAt) {
      nodes.push(new InfoNode("Last updated", generatedAt));
    }
    if (this.state.baseline_present !== undefined) {
      nodes.push(new InfoNode("Baseline", this.state.baseline_present ? "On" : "Off"));
    }
    const newFindings = this.state.summary?.new_findings ?? 0;
    if (newFindings > 0) {
      nodes.push(new InfoNode("New issues", String(newFindings)));
    }
    const changedFiles = this.state.changed_files?.length ?? this.state.summary?.changed_file_count ?? 0;
    if (changedFiles > 0) {
      nodes.push(new InfoNode("Changed files in scope", String(changedFiles)));
    }
    if ((this.state.summary?.snoozed ?? 0) > 0) {
      nodes.push(new InfoNode("Snoozed", String(this.state.summary?.snoozed ?? 0)));
    }
    if ((this.state.summary?.dismissed ?? 0) > 0) {
      nodes.push(new InfoNode("Dismissed", String(this.state.summary?.dismissed ?? 0)));
    }

    const actions = this.getActions();
    if (actions.length === 0) {
      nodes.push(new EmptyNode("No ranked actions", "The repo agent did not surface anything urgent"));
      return nodes;
    }

    nodes.push(new InfoNode("Preview dead code removal", "Run LLM-verified fix generation", "trash", "skylos.fixDeadCode"));
    nodes.push(...actions.map((action) => new ActionNode(action)));
    return nodes;
  }

  dispose(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.watcher?.dispose();
    this.disposeWatcherDisposables();
    this.disposables.forEach((d) => d.dispose());
  }

  private async loadState(): Promise<void> {
    const statePath = this.getStatePath();
    if (!statePath) {
      this.state = undefined;
      this.fireStateChanged();
      return;
    }

    try {
      const raw = await fs.readFile(statePath, "utf-8");
      this.state = JSON.parse(raw) as AgentCommandCenterState;
    } catch {
      this.state = undefined;
    }

    this.fireStateChanged();
  }

  private fireStateChanged(): void {
    this._onDidChangeTreeData.fire();
    this._onDidUpdateState.fire();
  }

  private getActions(): AgentCommandCenterItem[] {
    const actions = this.state?.actions ?? this.state?.command_center?.items ?? [];
    return actions.slice(0, getCommandCenterLimit());
  }

  private getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  }

  private requireWorkspaceRoot(): string {
    const root = this.getWorkspaceRoot();
    if (!root) {
      throw new Error("Open a workspace folder to use Command Center.");
    }
    return root;
  }

  private getStatePath(): string | undefined {
    const root = this.getWorkspaceRoot();
    if (!root) return undefined;

    const configured = getCommandCenterStateFile();
    if (!configured) {
      return path.join(root, ".skylos", "agent_state.json");
    }
    return path.isAbsolute(configured) ? configured : path.join(root, configured);
  }

  private updateWatcher(): void {
    this.watcher?.dispose();
    this.watcher = undefined;
    this.disposeWatcherDisposables();

    const root = vscode.workspace.workspaceFolders?.[0];
    if (!root) return;

    const configured = getCommandCenterStateFile();
    let relative = ".skylos/agent_state.json";
    if (configured) {
      const absolute = path.isAbsolute(configured) ? configured : path.join(root.uri.fsPath, configured);
      if (!absolute.startsWith(root.uri.fsPath)) {
        return;
      }
      relative = path.relative(root.uri.fsPath, absolute).replace(/\\/g, "/");
    }

    this.watcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(root.uri, relative));
    this.watcherDisposables.push(this.watcher);
    this.watcherDisposables.push(
      this.watcher.onDidCreate(() => void this.loadState()),
      this.watcher.onDidChange(() => void this.loadState()),
      this.watcher.onDidDelete(() => {
        this.state = undefined;
        this.fireStateChanged();
      }),
    );
  }

  private runCommandCenterRefresh(root: string): Promise<void> {
    const args = ["command-center", root, "--refresh", "--limit", String(getCommandCenterLimit())];
    const stateFile = getCommandCenterStateFile();
    if (stateFile) {
      args.push("--state-file", stateFile);
    }
    return this.runAgentCommand(root, args);
  }

  private async runTriagingCommand(args: string[]): Promise<void> {
    await this.runAgentCommand(this.requireWorkspaceRoot(), args);
    await this.loadState();
  }

  private disposeWatcherDisposables(): void {
    for (const disposable of this.watcherDisposables) {
      disposable.dispose();
    }
    this.watcherDisposables = [];
  }

  private runAgentCommand(root: string, args: string[]): Promise<void> {
    const bin = getSkylosBin();
    const fullArgs = ["agent", ...args];
    const stateFile = getCommandCenterStateFile();
    if (stateFile && !fullArgs.includes("--state-file")) {
      fullArgs.push("--state-file", stateFile);
    }

    out.appendLine(`Running Command Center command: ${bin} ${fullArgs.join(" ")}`);

    return new Promise<void>((resolve, reject) => {
      const proc = spawn(bin, fullArgs, { cwd: root });
      let stderr = "";

      proc.stdout.on("data", () => {
        // Consume output to avoid blocking; state is read from the JSON file.
      });
      proc.stderr.on("data", (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on("close", (code) => {
        if (stderr.trim()) {
          out.appendLine(`Command Center stderr: ${stderr.trim()}`);
        }
        if (code === 0) {
          resolve();
          return;
        }
        reject(new Error(stderr.trim() || `Command Center exited with code ${code}`));
      });

      proc.on("error", (err) => reject(err));
    });
  }
}

function getActionIcon(severity: string): vscode.ThemeIcon {
  const normalized = severity.toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH") {
    return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
  }
  if (normalized === "MEDIUM" || normalized === "WARN") {
    return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
  }
  return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
}

function buildSummaryTooltip(state: AgentCommandCenterState): string {
  const lines: string[] = [];
  if (state.summary?.headline) lines.push(state.summary.headline);
  if (state.summary?.subtitle) lines.push(state.summary.subtitle);
  if (state.generated_at) lines.push(`Updated: ${formatGeneratedAt(state.generated_at)}`);
  return lines.join("\n");
}

function buildActionTooltip(action: AgentCommandCenterItem): string {
  const parts = [
    `[${action.severity}] ${action.title}`,
    action.subtitle,
  ].filter(Boolean);
  if (action.reason) parts.push(`Why now: ${action.reason}`);
  if (action.score !== undefined) parts.push(`Score: ${action.score}`);
  return parts.join("\n");
}

function describeState(state: AgentCommandCenterState): string {
  const parts: string[] = [];
  if (state.summary?.new_findings !== undefined) {
    parts.push(`${state.summary.new_findings} new`);
  }
  if (state.summary?.critical) {
    parts.push(`${state.summary.critical} critical`);
  }
  if (state.summary?.high) {
    parts.push(`${state.summary.high} high`);
  }
  return parts.join(" | ");
}

function formatGeneratedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function resolveActionPath(file: string): string | undefined {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!root) return undefined;
  return path.isAbsolute(file) ? file : path.join(root, file);
}

function normalizeCategory(value: string | undefined): SkylosFinding["category"] {
  if (value === "security" || value === "secrets" || value === "dead_code" || value === "quality" || value === "debt" || value === "ai") {
    return value;
  }
  return "quality";
}

function normalizeSeverity(value: string | undefined): SkylosFinding["severity"] {
  const normalized = String(value || "INFO").toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH" || normalized === "MEDIUM" || normalized === "LOW" || normalized === "INFO" || normalized === "WARN") {
    return normalized;
  }
  return "INFO";
}
