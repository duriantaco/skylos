import * as vscode from "vscode";
import { FindingsStore } from "./store";
import { scanWorkspace, scanFile, cancelScan, out, doctorSkylos, buildScanErrorMessage, SkylosScanError } from "./scanner";
import { DiagnosticsManager } from "./diagnostics";
import { DecorationsManager } from "./decorations";
import { SkylosTreeProvider, FindingNode } from "./sidebar";
import { SkylosHoverProvider } from "./hover";
import { SkylosCodeLensProvider } from "./codelens";
import { SkylosQuickFixProvider } from "./quickfix";
import { AIAnalyzer, fixWithAI } from "./ai";
import { SkylosStatusBar } from "./statusbar";
import { StreamingDecorationManager } from "./streaming";
import { SkylosChatViewProvider } from "./chatview";
import { AutoRemediator } from "./autoremediate";
import { SkylosDashboard } from "./dashboard";
import { FindingNavigator } from "./navigator";
import { FindingDetailPanel } from "./detail";
import { SkylosFileDecorationProvider } from "./filedecorations";
import { exportReport } from "./export";
import { ActionNode, SkylosCommandCenterProvider } from "./commandcenter";
import {
  isRunOnSave,
  isScanOnOpen,
  getIdleMs,
  isLanguageSupported,
  isShowPopup,
  getDiffBase,
  getAIProvider,
  getLocalBaseUrl,
  getSkylosBin,
  getMaxTreeFindings,
  getMaxTreeFindingsPerFile,
  isCommandCenterRefreshOnSave,
  isRealtimeAIEnabled,
} from "./config";
import { shouldWarnMissingLocalAI } from "./configCore";
import type { AutoFixOptions, Category, Severity, SkylosFinding } from "./types";

export function activate(context: vscode.ExtensionContext) {
  out.appendLine("Skylos extension activated");

  const store = new FindingsStore();
  const diagnostics = new DiagnosticsManager(store);
  const decorations = new DecorationsManager(store, context);
  const statusBar = new SkylosStatusBar(store);
  const treeProvider = new SkylosTreeProvider(store);
  const hoverProvider = new SkylosHoverProvider(store);
  const codeLensProvider = new SkylosCodeLensProvider(store);
  const quickFixProvider = new SkylosQuickFixProvider(store);
  const aiAnalyzer = new AIAnalyzer(store);

  // streaming inline decorations
  const streamingManager = new StreamingDecorationManager();
  aiAnalyzer.setStreamingManager(streamingManager);

  // chat view
  const chatProvider = new SkylosChatViewProvider(context);

  // auto-remediation
  const autoRemediator = new AutoRemediator(store);

  const dashboard = new SkylosDashboard(store);
  const navigator = new FindingNavigator(store);
  const detailPanel = new FindingDetailPanel();
  const fileDecoProvider = new SkylosFileDecorationProvider(store);
  const commandCenterProvider = new SkylosCommandCenterProvider();

  const treeView = vscode.window.createTreeView("skylosFindings", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });
  const commandCenterView = vscode.window.createTreeView("skylosCommandCenter", {
    treeDataProvider: commandCenterProvider,
    showCollapseAll: false,
  });

  const updateTreeBadge = () => {
    const summary = store.getVisibleSummary(getMaxTreeFindings(), {
      maxPerFile: getMaxTreeFindingsPerFile(),
    });
    treeView.badge = summary.workingTotal > 0
      ? {
          value: summary.workingTotal,
          tooltip: summary.visibleTotal < summary.workingTotal
            ? `Showing ${summary.visibleTotal} of ${summary.workingTotal} issue(s)`
            : `${summary.workingTotal} issue(s)`,
        }
      : undefined;
  };
  store.onDidChange(updateTreeBadge);
  store.onDidChangeAI(updateTreeBadge);
  updateTreeBadge();

  const updateCommandCenterBadge = () => {
    const total = commandCenterProvider.actionCount;
    commandCenterView.badge = total > 0
      ? {
          value: total,
          tooltip: commandCenterProvider.triagedCount > 0
            ? `${total} ranked action(s), ${commandCenterProvider.triagedCount} triaged`
            : `${total} ranked action(s)`,
        }
      : undefined;
  };
  commandCenterProvider.onDidUpdateState(() => {
    store.setAgentFindings(commandCenterProvider.getQueueFindings());
    updateCommandCenterBadge();
  });
  updateCommandCenterBadge();

  context.subscriptions.push(
    store, diagnostics, decorations, statusBar,
    treeProvider, codeLensProvider, treeView,
    commandCenterProvider, commandCenterView,
    hoverProvider.register(),
    codeLensProvider.register(),
    quickFixProvider.register(),
    streamingManager,
    dashboard,
    navigator,
    detailPanel,
    fileDecoProvider,
    fileDecoProvider.register(),
    out,
  );

  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(SkylosChatViewProvider.viewType, chatProvider),
  );
  void commandCenterProvider.initialize();

  function recordScanFailure(err: unknown): string {
    const message = buildScanErrorMessage(err);
    if (err instanceof SkylosScanError) {
      store.setLastError({
        kind: err.kind,
        message,
        command: err.details.command,
        exitCode: err.details.exitCode,
        stderr: err.details.stderr,
      });
    } else {
      store.setLastError({
        kind: "unknown",
        message,
      });
    }
    return message;
  }

  async function doWorkspaceScan(diffBase?: string): Promise<void> {
    statusBar.setScanning(true);
    try {
      const result = await scanWorkspace(undefined, diffBase);
      store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
      if (result.metadata) store.setLastScan(result.metadata);
      store.setWorkspaceCLIFindings(result.findings);
      const total = result.findings.length;
      const criticalOrHigh = result.findings.filter((finding) =>
        finding.severity === "CRITICAL" || finding.severity === "HIGH",
      ).length;
      const scopeSummary = store.getVisibleSummary(getMaxTreeFindings(), {
        maxPerFile: getMaxTreeFindingsPerFile(),
      });

      if (criticalOrHigh > 0 && isShowPopup()) {
        const action = await vscode.window.showWarningMessage(
          scopeSummary.visibleTotal < total
            ? `Skylos found ${criticalOrHigh} critical/high issue(s) (${total} total, showing top ${scopeSummary.visibleTotal} in editor)`
            : `Skylos found ${criticalOrHigh} critical/high issue(s) (${total} total)`,
          "Open Dashboard",
          "Dismiss",
        );
        if (action === "Open Dashboard") dashboard.show();
      } else if (total > 0) {
        vscode.window.setStatusBarMessage(`Skylos: ${total} issue(s) in workspace`, 5000);
      } else if (total === 0) {
        vscode.window.setStatusBarMessage("Skylos: no issues", 5000);
      }
    } catch (err) {
      const msg = recordScanFailure(err);
      if (msg !== "Scan cancelled") {
        vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
      }
    } finally {
      statusBar.setScanning(false);
    }
  }

  async function scanSingleFile(filePath: string, announce = true): Promise<void> {
    statusBar.setScanning(true);
    try {
      const result = await scanFile(filePath);
      if (result.metadata) store.setLastScan(result.metadata);
      const fileFindings = result.findings.filter((finding) => finding.file === filePath);
      store.setFocusedCLIFindings(filePath, fileFindings);
      if (announce) {
        const fileName = filePath.split("/").pop() ?? filePath;
        const total = fileFindings.length;
        vscode.window.setStatusBarMessage(
          total > 0 ? `Skylos: ${total} issue(s) in ${fileName}` : `Skylos: no issues in ${fileName}`,
          4000,
        );
      }
    } catch (err) {
      const msg = recordScanFailure(err);
      if (msg !== "Scan cancelled") {
        vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
      }
    } finally {
      statusBar.setScanning(false);
    }
  }

  async function scanEditorFile(editor?: vscode.TextEditor, announce = true): Promise<void> {
    if (!editor) return;
    await scanSingleFile(editor.document.uri.fsPath, announce);
  }

  async function openCommandCenterDetail(node: ActionNode): Promise<void> {
    const finding = commandCenterProvider.toSkylosFinding(node.action);
    if (!finding) {
      vscode.window.showWarningMessage("Skylos: this Automation action has no file target.");
      return;
    }
    detailPanel.show(finding);
  }

  async function applyCommandCenterSafeFix(node: ActionNode): Promise<void> {
    const finding = commandCenterProvider.toSkylosFinding(node.action);
    if (!finding) {
      vscode.window.showInformationMessage("Skylos: no safe fix is available for this action.");
      return;
    }

    await previewSafeFix(finding);
  }

  function resolveFinding(candidate?: SkylosFinding | FindingNode): SkylosFinding | undefined {
    if (!candidate) return undefined;
    if (candidate instanceof FindingNode) return candidate.finding;
    return candidate;
  }

  async function previewSafeFix(candidate?: SkylosFinding | FindingNode): Promise<void> {
    const finding = resolveFinding(candidate);
    if (!finding?.fixPatch) {
      vscode.window.showInformationMessage(
        "Skylos: no engine-backed patch is available for this finding yet.",
      );
      return;
    }

    const patchDoc = await vscode.workspace.openTextDocument({
      language: "diff",
      content: finding.fixPatch,
    });
    await vscode.window.showTextDocument(patchDoc, { preview: true });
  }

  async function snoozeCommandCenterAction(node: ActionNode): Promise<void> {
    const pick = await vscode.window.showQuickPick(
      [
        { label: "4 hours", hours: 4 },
        { label: "24 hours", hours: 24 },
        { label: "72 hours", hours: 72 },
      ],
      { placeHolder: "Snooze this action for..." },
    );
    if (!pick) return;

    await commandCenterProvider.snoozeAction(node.action, pick.hours);
    updateCommandCenterBadge();
    vscode.window.setStatusBarMessage(`Skylos: snoozed for ${pick.label}`, 3000);
  }

  async function restoreTriagedCommandCenterAction(): Promise<void> {
    const triaged = commandCenterProvider.getTriagedEntries();
    if (triaged.length === 0) {
      vscode.window.showInformationMessage("Skylos: there are no snoozed or dismissed Automation actions.");
      return;
    }

    const pick = await vscode.window.showQuickPick(
      triaged.map(({ id, entry }) => {
        const finding = commandCenterProvider.getFindingById(id);
        return {
          label: finding?.message || id,
          detail: finding ? `${finding.file}:${finding.line}` : id,
        description: entry.status === "snoozed" && entry.snoozed_until
          ? `snoozed until ${new Date(entry.snoozed_until).toLocaleString()}`
          : entry.status,
          id,
        };
      }),
      { placeHolder: "Restore a snoozed or dismissed action" },
    );
    if (!pick) return;

    await commandCenterProvider.restoreAction(pick.id);
    updateCommandCenterBadge();
    vscode.window.setStatusBarMessage("Skylos: restored Automation action", 3000);
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("skylos.scan", () => {
      const diffBase = store.deltaMode ? getDiffBase() : undefined;
      doWorkspaceScan(diffBase);
    }),

    vscode.commands.registerCommand("skylos.doctor", async () => {
      const result = await doctorSkylos();
      out.show(true);
      if (result.ok) {
        vscode.window.showInformationMessage("Skylos Doctor: CLI is reachable.");
      } else {
        vscode.window.showWarningMessage(`Skylos Doctor: ${result.error ?? "CLI check failed."}`);
      }
    }),

    vscode.commands.registerCommand("skylos.scanFile", async (uri?: vscode.Uri) => {
      const targetUri = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!targetUri) {
        vscode.window.showWarningMessage("Skylos: no active file to scan.");
        return;
      }
      await scanSingleFile(targetUri.fsPath);
    }),

    vscode.commands.registerCommand("skylos.toggleDelta", () => {
      store.deltaMode = !store.deltaMode;
      const label = store.deltaMode ? "Delta mode ON — showing new issues only" : "Delta mode OFF — showing all issues";
      vscode.window.setStatusBarMessage(`Skylos: ${label}`, 4000);
      void vscode.commands.executeCommand("skylos.scan");
    }),

    vscode.commands.registerCommand("skylos.fix", fixWithAI),

    vscode.commands.registerCommand("skylos.previewSafeFix", async (finding?: SkylosFinding | FindingNode) => {
      await previewSafeFix(finding);
    }),

    vscode.commands.registerCommand("skylos.dismissIssue", (filePath: string, line: number) => {
      store.dismissAIFinding(filePath, line);
    }),

    vscode.commands.registerCommand("skylos.removeImport", async () => {
      vscode.window.showInformationMessage(
        "Skylos: direct line-delete cleanup is disabled. Use an engine-backed fix preview when available.",
      );
    }),

    vscode.commands.registerCommand("skylos.removeFunction", async () => {
      vscode.window.showInformationMessage(
        "Skylos: direct line-delete cleanup is disabled. Use an engine-backed fix preview when available.",
      );
    }),

    vscode.commands.registerCommand("skylos.addToWhitelist", async (message: string) => {
      const match = message.match(/Unused \w+:\s*(.+)/);
      const name = match?.[1]?.trim();
      if (!name) {
        vscode.window.showErrorMessage("Could not extract name from finding.");
        return;
      }

      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws)
        return;

      const configPath = vscode.Uri.joinPath(ws.uri, ".skylosignore");
      try {
        const doc = await vscode.workspace.openTextDocument(configPath);
        const edit = new vscode.WorkspaceEdit();
        edit.insert(configPath, new vscode.Position(doc.lineCount, 0), `\n${name}`);
        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage(`Added "${name}" to .skylosignore`);
      } catch {
        const edit = new vscode.WorkspaceEdit();
        edit.createFile(configPath, { overwrite: false, ignoreIfExists: true });
        await vscode.workspace.applyEdit(edit);
        const edit2 = new vscode.WorkspaceEdit();
        edit2.insert(configPath, new vscode.Position(0, 0), `${name}\n`);
        await vscode.workspace.applyEdit(edit2);
        vscode.window.showInformationMessage(`Created .skylosignore and added "${name}"`);
      }
    }),

    vscode.commands.registerCommand("skylos.statusBarClick", () => {
      dashboard.show();
    }),

    vscode.commands.registerCommand("skylos.dashboard", () => {
      dashboard.show();
    }),

    vscode.commands.registerCommand("skylos.nextFinding", () => {
      navigator.next();
    }),

    vscode.commands.registerCommand("skylos.prevFinding", () => {
      navigator.prev();
    }),

    vscode.commands.registerCommand("skylos.exportReport", () => {
      exportReport(store);
    }),

    vscode.commands.registerCommand("skylos.showFindingDetail", (node: FindingNode) => {
      if (node?.finding) {
        detailPanel.show(node.finding);
      }
    }),

    vscode.commands.registerCommand("skylos.refresh", () => {
      void vscode.commands.executeCommand("skylos.scan");
    }),

    vscode.commands.registerCommand("skylos.refreshCommandCenter", async () => {
      await commandCenterProvider.refresh();
    }),

    vscode.commands.registerCommand("skylos.commandCenterOpenDetail", async (node: ActionNode) => {
      await openCommandCenterDetail(node);
    }),

    vscode.commands.registerCommand("skylos.commandCenterApplySafeFix", async (node: ActionNode) => {
      await applyCommandCenterSafeFix(node);
    }),

    vscode.commands.registerCommand("skylos.commandCenterDismiss", async (node: ActionNode) => {
      await commandCenterProvider.dismissAction(node.action);
      updateCommandCenterBadge();
      vscode.window.setStatusBarMessage("Skylos: dismissed Automation action", 3000);
    }),

    vscode.commands.registerCommand("skylos.commandCenterSnooze", async (node: ActionNode) => {
      await snoozeCommandCenterAction(node);
    }),

    vscode.commands.registerCommand("skylos.commandCenterRestoreTriaged", async () => {
      await restoreTriagedCommandCenterAction();
    }),

    vscode.commands.registerCommand("skylos.clear", () => {
      store.clear();
    }),

    // chat about a finding from sidebar
    vscode.commands.registerCommand("skylos.chatAboutFinding", async (node: FindingNode) => {
      if (node && node.finding) {
        await chatProvider.setFindingContext(node.finding);
        vscode.commands.executeCommand("skylosChatPanel.focus");
      }
    }),

    // clear chat history
    vscode.commands.registerCommand("skylos.clearChat", () => {
      chatProvider.clearHistory();
    }),

    // auto fix all
    vscode.commands.registerCommand("skylos.fixAll", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: "Fix Errors Only", description: "CRITICAL + HIGH", severity: "HIGH" as const },
          { label: "Fix Errors + Warnings", description: "+ MEDIUM", severity: "MEDIUM" as const },
          { label: "Fix All", description: "All severities", severity: "LOW" as const },
        ],
        { placeHolder: "Select severity level to fix" },
      );
      if (!pick) 
        return;

      const options: AutoFixOptions = {
        minSeverity: pick.severity,
        dryRun: false,
      };
      await autoRemediator.fixAll(options);
    }),

    // auto fix dry run
    vscode.commands.registerCommand("skylos.fixAllDryRun", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: "Preview Errors Only", description: "CRITICAL + HIGH", severity: "HIGH" as const },
          { label: "Preview Errors + Warnings", description: "+ MEDIUM", severity: "MEDIUM" as const },
          { label: "Preview All", description: "All severities", severity: "LOW" as const },
        ],
        { placeHolder: "Select severity level to preview" },
      );
      if (!pick) 
        return;

      const options: AutoFixOptions = {
        minSeverity: pick.severity,
        dryRun: true,
      };
      await autoRemediator.fixAll(options);
    }),

    vscode.commands.registerCommand("skylos.filterFindings", async () => {
      const filterType = await vscode.window.showQuickPick(
          [
            { label: "$(warning) By Severity", value: "severity" },
            { label: "$(symbol-class) By Category", value: "category" },
            { label: "$(source-control) By Source", value: "source" },
            { label: "$(file) By File Name", value: "file" },
        ],
        { placeHolder: "Filter findings by..." },
      );
      if (!filterType) return;

      if (filterType.value === "severity") {
        const sev = await vscode.window.showQuickPick(
          ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARN"],
          { placeHolder: "Show only this severity" },
        );
        if (sev) store.filter = { ...store.filter, severity: sev as Severity };
      } else if (filterType.value === "category") {
        const cat = await vscode.window.showQuickPick(
          [
            { label: "Security", value: "security" },
            { label: "Secrets", value: "secrets" },
            { label: "Technical Debt", value: "debt" },
            { label: "Dead Code", value: "dead_code" },
            { label: "Quality", value: "quality" },
            { label: "AI Assist", value: "ai" },
          ].map((c) => ({ ...c, description: c.value })),
          { placeHolder: "Show only this category" },
        );
        if (cat) store.filter = { ...store.filter, category: cat.value as Category };
      } else if (filterType.value === "source") {
        const src = await vscode.window.showQuickPick(
          [
            { label: "Static scan", value: "cli" as const },
            { label: "Automation", value: "agent" as const },
            { label: "AI Assist (optional real-time)", value: "ai" as const },
            { label: "Confirmed findings", value: "confirmed" as const },
          ],
          { placeHolder: "Show only this source" },
        );
        if (src) store.filter = { ...store.filter, source: src.value };
      } else if (filterType.value === "file") {
        const pattern = await vscode.window.showInputBox({
          placeHolder: "e.g. auth.py, src/utils",
          prompt: "Filter by file path (substring match)",
        });
        if (pattern) store.filter = { ...store.filter, filePattern: pattern };
      }

      vscode.commands.executeCommand("setContext", "skylos.filterActive", store.hasActiveFilter);
      const label = store.hasActiveFilter ? "Filter active" : "No filter";
      vscode.window.setStatusBarMessage(`Skylos: ${label}`, 3000);
    }),

    vscode.commands.registerCommand("skylos.clearFilter", () => {
      store.filter = {};
      vscode.commands.executeCommand("setContext", "skylos.filterActive", false);
      vscode.window.setStatusBarMessage("Skylos: Filter cleared", 3000);
    }),

    vscode.commands.registerCommand("skylos.fixDeadCode", async () => {
      const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!root) {
        vscode.window.showWarningMessage("Skylos: Open a folder first.");
        return;
      }
      if (!vscode.workspace.isTrusted) {
        vscode.window.showWarningMessage("Skylos: Trust this workspace before previewing dead code removal.");
        return;
      }

      const skylosBin = getSkylosBin();
      const { spawn: spawnProc } = await import("child_process");

      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "Skylos: Generating dead code removal plan..." },
        () =>
          new Promise<void>((resolve, reject) => {
            const args = ["agent", "verify", root, "--fix", "--format", "json", "--quiet"];
            const proc = spawnProc(skylosBin, args, { cwd: root });
            let stdout = "";
            let stderr = "";
            proc.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
            proc.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
            proc.on("close", async (code) => {
              if (code !== 0) {
                vscode.window.showErrorMessage(`Skylos fix failed: ${stderr || `exit ${code}`}`);
                reject(new Error(stderr));
                return;
              }
              try {
                // Extract the diff from JSON output
                const result = JSON.parse(stdout);
                const diff = result?.diff || result?.unified_diff || "";
                if (!diff) {
                  vscode.window.showInformationMessage("Skylos: No dead code patches to preview.");
                  resolve();
                  return;
                }
                // Show diff in VS Code diff editor via untitled documents
                const originalDoc = await vscode.workspace.openTextDocument({ content: "", language: "diff" });
                const patchDoc = await vscode.workspace.openTextDocument({ content: diff, language: "diff" });
                await vscode.commands.executeCommand("vscode.diff", originalDoc.uri, patchDoc.uri, "Skylos: Dead Code Removal Preview");
                resolve();
              } catch (e) {
                vscode.window.showErrorMessage(`Skylos: Failed to parse fix output: ${e}`);
                reject(e);
              }
            });
          }),
      );
    }),
  );

  if (isRunOnSave()) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        if (isLanguageSupported(doc.languageId)) {
          void scanSingleFile(doc.uri.fsPath, false);
          if (isCommandCenterRefreshOnSave()) {
            commandCenterProvider.scheduleRefresh();
          }
        }
      }),
    );
  }

  let aiDebounceTimer: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || event.document !== editor.document)
        return;
      if (!isLanguageSupported(event.document.languageId))
        return;
      if (event.contentChanges.length === 0)
        return;
      if (!isRealtimeAIEnabled())
        return;

      if (aiDebounceTimer) clearTimeout(aiDebounceTimer);
      aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(event.document), getIdleMs());
    }),
  );

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && isRealtimeAIEnabled() && isLanguageSupported(editor.document.languageId)) {
        if (aiDebounceTimer) clearTimeout(aiDebounceTimer);
        aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(editor.document), 1000);
      }
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("skylos")) {
        store.refreshViews();
        void commandCenterProvider.handleConfigurationChanged();
      }
    }),
  );

  if (shouldWarnMissingLocalAI({
    realtimeAIEnabled: isRealtimeAIEnabled(),
    provider: getAIProvider(),
    localBaseUrl: getLocalBaseUrl(),
  })) {
    vscode.window.showWarningMessage(
      'Skylos: AI Assist is enabled but not configured. Static scanning is still running locally. Configure skylos.localBaseUrl.',
      "Open Settings",
    ).then((action) => {
      if (action === "Open Settings") {
        vscode.commands.executeCommand("workbench.action.openSettings", "skylos.localBaseUrl");
      }
    });
  }

  let initialOpenScanDone = false;
  const maybeRunInitialOpenScan = (editor?: vscode.TextEditor) => {
    if (initialOpenScanDone || !isScanOnOpen() || !editor) return;
    if (!isLanguageSupported(editor.document.languageId)) return;
    initialOpenScanDone = true;
    void scanEditorFile(editor, false);
  };

  maybeRunInitialOpenScan(vscode.window.activeTextEditor);

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      maybeRunInitialOpenScan(editor);
    }),
  );
}

export function deactivate() {
  cancelScan();
}
