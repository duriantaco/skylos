import * as vscode from "vscode";
import { FindingsStore } from "./store";
import { scanWorkspace, scanFile, cancelScan, out } from "./scanner";
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
import { isRunOnSave, isScanOnOpen, getIdleMs, isLanguageSupported, isShowPopup } from "./config";
import type { AutoFixOptions } from "./types";

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

  const treeView = vscode.window.createTreeView("skylosFindings", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  store.onDidChange(() => {
    const total = store.getAllFindings().length;
    treeView.badge = total > 0 ? { value: total, tooltip: `${total} issue(s)` } : undefined;
  });
  store.onDidChangeAI(() => {
    const total = store.getAllFindings().length;
    treeView.badge = total > 0 ? { value: total, tooltip: `${total} issue(s)` } : undefined;
  });

  context.subscriptions.push(
    store, diagnostics, decorations, statusBar,
    treeProvider, codeLensProvider, treeView,
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

  // run full workspace scan and store results
  async function doScan(diffBase?: string): Promise<void> {
    statusBar.setScanning(true);
    try {
      const result = await scanWorkspace(undefined, diffBase);
      store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
      store.setCLIFindings(result.findings);
      const total = result.findings.length;
      if (total > 0 && isShowPopup()) {
        const action = await vscode.window.showWarningMessage(
          `Skylos found ${total} issue(s)`,
          "Show Details",
          "Dismiss",
        );
        if (action === "Show Details") out.show();
      } else if (total === 0) {
        vscode.window.setStatusBarMessage("Skylos: no issues", 5000);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg !== "Scan cancelled") {
        vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
      }
    } finally {
      statusBar.setScanning(false);
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("skylos.scan", () => {
      const diffBase = store.deltaMode ? "origin/main" : undefined;
      doScan(diffBase);
    }),

    vscode.commands.registerCommand("skylos.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("Skylos: no active file to scan.");
        return;
      }
      statusBar.setScanning(true);
      try {
        const result = await scanFile(editor.document.uri.fsPath);
        store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
        store.setCLIFindings(result.findings);
        const total = result.findings.length;
        vscode.window.setStatusBarMessage(
          total > 0 ? `Skylos: ${total} issue(s) in ${editor.document.fileName.split("/").pop()}` : "Skylos: no issues",
          5000,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg !== "Scan cancelled") {
          vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
        }
      } finally {
        statusBar.setScanning(false);
      }
    }),

    vscode.commands.registerCommand("skylos.toggleDelta", () => {
      store.deltaMode = !store.deltaMode;
      const label = store.deltaMode ? "Delta mode ON — showing new issues only" : "Delta mode OFF — showing all issues";
      vscode.window.setStatusBarMessage(`Skylos: ${label}`, 4000);
      vscode.commands.executeCommand("skylos.scan");
    }),

    vscode.commands.registerCommand("skylos.fix", fixWithAI),

    vscode.commands.registerCommand("skylos.dismissIssue", (filePath: string, line: number) => {
      store.dismissAIFinding(filePath, line);
    }),

    vscode.commands.registerCommand("skylos.removeImport", async (uri: vscode.Uri, line: number) => {
      const doc = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(doc);
      await editor.edit((eb) => {
        eb.delete(new vscode.Range(line, 0, line + 1, 0));
      });
      store.removeFindingAtLine(uri.fsPath, line + 1);
    }),

    vscode.commands.registerCommand("skylos.removeFunction", async (uri: vscode.Uri, line: number) => {
      const doc = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(doc);
      const langId = doc.languageId;

      let endLine = line;
      if (langId === "python") {
        const startText = doc.lineAt(line).text;
        const indent = startText.match(/^(\s*)/)?.[1].length ?? 0;
        for (let j = line + 1; j < doc.lineCount; j++) {
          const nextLine = doc.lineAt(j).text;
          if (nextLine.trim() === "") { endLine = j;
            continue; }
          const nextIndent = nextLine.match(/^(\s*)/)?.[1].length ?? 0;
          if (nextIndent <= indent && nextLine.trim() !== "")
            break;
          endLine = j;
        }
      } else {
        let braceCount = 0;
        let foundBrace = false;
        for (let j = line; j < doc.lineCount; j++) {
          for (const ch of doc.lineAt(j).text) {
            if (ch === "{") { braceCount++; foundBrace = true; }
            if (ch === "}") braceCount--;
          }
          endLine = j;
          if (foundBrace && braceCount <= 0)
            break;
        }
      }

      await editor.edit((eb) => {
        eb.delete(new vscode.Range(line, 0, endLine + 1, 0));
      });
      store.removeFindingAtLine(uri.fsPath, line + 1);
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
      vscode.commands.executeCommand("skylos.scan");
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
  );

  if (isRunOnSave()) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        if (isLanguageSupported(doc.languageId)) {
          vscode.commands.executeCommand("skylos.scan");
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

      if (aiDebounceTimer) clearTimeout(aiDebounceTimer);
      aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(event.document), getIdleMs());
    }),
  );

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && isLanguageSupported(editor.document.languageId)) {
        if (aiDebounceTimer) clearTimeout(aiDebounceTimer);
        aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(editor.document), 1000);
      }
    }),
  );

  if (isScanOnOpen()) {
    vscode.commands.executeCommand("skylos.scan");
  }
}

export function deactivate() {
  cancelScan();
}
