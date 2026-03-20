"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosCommandCenterProvider = exports.ActionNode = void 0;
const fs = require("fs/promises");
const path = require("path");
const child_process_1 = require("child_process");
const vscode = require("vscode");
const config_1 = require("./config");
const scanner_1 = require("./scanner");
class SummaryNode {
    constructor(state) {
        this.state = state;
    }
}
class InfoNode {
    constructor(label, description) {
        this.label = label;
        this.description = description;
    }
}
class ActionNode {
    constructor(action) {
        this.action = action;
    }
}
exports.ActionNode = ActionNode;
class EmptyNode {
    constructor(label, description) {
        this.label = label;
        this.description = description;
    }
}
class SkylosCommandCenterProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this._onDidUpdateState = new vscode.EventEmitter();
        this.onDidUpdateState = this._onDidUpdateState.event;
        this.disposables = [];
        this.watcherDisposables = [];
        this.refreshing = false;
        this.pendingRefresh = false;
        this.disposables.push(this._onDidChangeTreeData, this._onDidUpdateState);
        this.updateWatcher();
        this.disposables.push(vscode.workspace.onDidChangeWorkspaceFolders(() => {
            this.updateWatcher();
            void this.loadState();
        }));
    }
    async initialize() {
        await this.loadState();
        if ((0, config_1.isCommandCenterRefreshOnOpen)()) {
            void this.refresh();
        }
    }
    get actionCount() {
        return this.getActions().length;
    }
    get triagedCount() {
        return Object.keys(this.state?.triage ?? {}).length;
    }
    getTriagedEntries() {
        return Object.entries(this.state?.triage ?? {})
            .map(([id, entry]) => ({ id, entry }))
            .sort((a, b) => a.id.localeCompare(b.id));
    }
    scheduleRefresh(delayMs = 1200) {
        if (this.refreshTimer)
            clearTimeout(this.refreshTimer);
        this.refreshTimer = setTimeout(() => {
            void this.refresh();
        }, delayMs);
    }
    async refresh() {
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
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            vscode.window.showErrorMessage(`Skylos Command Center refresh failed: ${msg}`);
        }
        finally {
            this.refreshing = false;
            this._onDidChangeTreeData.fire();
            if (this.pendingRefresh) {
                this.pendingRefresh = false;
                void this.refresh();
            }
        }
    }
    async handleConfigurationChanged() {
        this.updateWatcher();
        await this.loadState();
    }
    getFindingForAction(action) {
        return (this.state?.findings ?? []).find((finding) => finding.fingerprint === action.id);
    }
    getFindingById(actionId) {
        return (this.state?.findings ?? []).find((finding) => finding.fingerprint === actionId);
    }
    toSkylosFinding(action) {
        const finding = this.getFindingForAction(action);
        const absoluteFile = action.absolute_file || finding?.absolute_file || resolveActionPath(action.file);
        if (!absoluteFile)
            return undefined;
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
    async dismissAction(action) {
        await this.runTriagingCommand(["dismiss", this.requireWorkspaceRoot(), action.id]);
    }
    async snoozeAction(action, hours) {
        await this.runTriagingCommand(["snooze", this.requireWorkspaceRoot(), action.id, "--hours", String(hours)]);
    }
    async restoreAction(actionId) {
        await this.runTriagingCommand(["restore", this.requireWorkspaceRoot(), actionId]);
    }
    getTreeItem(element) {
        if (element instanceof SummaryNode) {
            const summary = element.state.summary;
            const item = new vscode.TreeItem(summary?.headline ?? "Command Center", vscode.TreeItemCollapsibleState.None);
            item.iconPath = new vscode.ThemeIcon("pulse");
            item.description = summary?.subtitle ?? describeState(element.state);
            item.tooltip = buildSummaryTooltip(element.state);
            return item;
        }
        if (element instanceof InfoNode) {
            const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
            item.iconPath = new vscode.ThemeIcon("info");
            item.description = element.description;
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
        const item = new vscode.TreeItem(action.title, vscode.TreeItemCollapsibleState.None);
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
    getChildren(element) {
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
                new EmptyNode("No Command Center state yet", "Run Refresh Command Center or `skylos agent watch .`"),
            ];
        }
        const nodes = [new SummaryNode(this.state)];
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
        nodes.push(...actions.map((action) => new ActionNode(action)));
        return nodes;
    }
    dispose() {
        if (this.refreshTimer)
            clearTimeout(this.refreshTimer);
        this.watcher?.dispose();
        this.disposeWatcherDisposables();
        this.disposables.forEach((d) => d.dispose());
    }
    async loadState() {
        const statePath = this.getStatePath();
        if (!statePath) {
            this.state = undefined;
            this.fireStateChanged();
            return;
        }
        try {
            const raw = await fs.readFile(statePath, "utf-8");
            this.state = JSON.parse(raw);
        }
        catch {
            this.state = undefined;
        }
        this.fireStateChanged();
    }
    fireStateChanged() {
        this._onDidChangeTreeData.fire();
        this._onDidUpdateState.fire();
    }
    getActions() {
        const actions = this.state?.actions ?? this.state?.command_center?.items ?? [];
        return actions.slice(0, (0, config_1.getCommandCenterLimit)());
    }
    getWorkspaceRoot() {
        return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    }
    requireWorkspaceRoot() {
        const root = this.getWorkspaceRoot();
        if (!root) {
            throw new Error("Open a workspace folder to use Command Center.");
        }
        return root;
    }
    getStatePath() {
        const root = this.getWorkspaceRoot();
        if (!root)
            return undefined;
        const configured = (0, config_1.getCommandCenterStateFile)();
        if (!configured) {
            return path.join(root, ".skylos", "agent_state.json");
        }
        return path.isAbsolute(configured) ? configured : path.join(root, configured);
    }
    updateWatcher() {
        this.watcher?.dispose();
        this.watcher = undefined;
        this.disposeWatcherDisposables();
        const root = vscode.workspace.workspaceFolders?.[0];
        if (!root)
            return;
        const configured = (0, config_1.getCommandCenterStateFile)();
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
        this.watcherDisposables.push(this.watcher.onDidCreate(() => void this.loadState()), this.watcher.onDidChange(() => void this.loadState()), this.watcher.onDidDelete(() => {
            this.state = undefined;
            this.fireStateChanged();
        }));
    }
    runCommandCenterRefresh(root) {
        const args = ["command-center", root, "--refresh", "--limit", String((0, config_1.getCommandCenterLimit)())];
        const stateFile = (0, config_1.getCommandCenterStateFile)();
        if (stateFile) {
            args.push("--state-file", stateFile);
        }
        return this.runAgentCommand(root, args);
    }
    async runTriagingCommand(args) {
        await this.runAgentCommand(this.requireWorkspaceRoot(), args);
        await this.loadState();
    }
    disposeWatcherDisposables() {
        for (const disposable of this.watcherDisposables) {
            disposable.dispose();
        }
        this.watcherDisposables = [];
    }
    runAgentCommand(root, args) {
        const bin = (0, config_1.getSkylosBin)();
        const fullArgs = ["agent", ...args];
        const stateFile = (0, config_1.getCommandCenterStateFile)();
        if (stateFile && !fullArgs.includes("--state-file")) {
            fullArgs.push("--state-file", stateFile);
        }
        scanner_1.out.appendLine(`Running Command Center command: ${bin} ${fullArgs.join(" ")}`);
        return new Promise((resolve, reject) => {
            const proc = (0, child_process_1.spawn)(bin, fullArgs, { cwd: root });
            let stderr = "";
            proc.stdout.on("data", () => {
                // Consume output to avoid blocking; state is read from the JSON file.
            });
            proc.stderr.on("data", (data) => {
                stderr += data.toString();
            });
            proc.on("close", (code) => {
                if (stderr.trim()) {
                    scanner_1.out.appendLine(`Command Center stderr: ${stderr.trim()}`);
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
exports.SkylosCommandCenterProvider = SkylosCommandCenterProvider;
function getActionIcon(severity) {
    const normalized = severity.toUpperCase();
    if (normalized === "CRITICAL" || normalized === "HIGH") {
        return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    }
    if (normalized === "MEDIUM" || normalized === "WARN") {
        return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    }
    return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
}
function buildSummaryTooltip(state) {
    const lines = [];
    if (state.summary?.headline)
        lines.push(state.summary.headline);
    if (state.summary?.subtitle)
        lines.push(state.summary.subtitle);
    if (state.generated_at)
        lines.push(`Updated: ${formatGeneratedAt(state.generated_at)}`);
    return lines.join("\n");
}
function buildActionTooltip(action) {
    const parts = [
        `[${action.severity}] ${action.title}`,
        action.subtitle,
    ].filter(Boolean);
    if (action.reason)
        parts.push(`Why now: ${action.reason}`);
    if (action.score !== undefined)
        parts.push(`Score: ${action.score}`);
    return parts.join("\n");
}
function describeState(state) {
    const parts = [];
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
function formatGeneratedAt(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleString();
}
function resolveActionPath(file) {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!root)
        return undefined;
    return path.isAbsolute(file) ? file : path.join(root, file);
}
function normalizeCategory(value) {
    if (value === "security" || value === "secrets" || value === "dead_code" || value === "quality" || value === "ai") {
        return value;
    }
    return "quality";
}
function normalizeSeverity(value) {
    const normalized = String(value || "INFO").toUpperCase();
    if (normalized === "CRITICAL" || normalized === "HIGH" || normalized === "MEDIUM" || normalized === "LOW" || normalized === "INFO" || normalized === "WARN") {
        return normalized;
    }
    return "INFO";
}
