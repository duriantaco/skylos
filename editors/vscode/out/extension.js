"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const store_1 = require("./store");
const scanner_1 = require("./scanner");
const diagnostics_1 = require("./diagnostics");
const decorations_1 = require("./decorations");
const sidebar_1 = require("./sidebar");
const hover_1 = require("./hover");
const codelens_1 = require("./codelens");
const quickfix_1 = require("./quickfix");
const ai_1 = require("./ai");
const statusbar_1 = require("./statusbar");
const streaming_1 = require("./streaming");
const chatview_1 = require("./chatview");
const autoremediate_1 = require("./autoremediate");
const dashboard_1 = require("./dashboard");
const navigator_1 = require("./navigator");
const detail_1 = require("./detail");
const filedecorations_1 = require("./filedecorations");
const export_1 = require("./export");
const config_1 = require("./config");
function activate(context) {
    scanner_1.out.appendLine("Skylos extension activated");
    const store = new store_1.FindingsStore();
    const diagnostics = new diagnostics_1.DiagnosticsManager(store);
    const decorations = new decorations_1.DecorationsManager(store, context);
    const statusBar = new statusbar_1.SkylosStatusBar(store);
    const treeProvider = new sidebar_1.SkylosTreeProvider(store);
    const hoverProvider = new hover_1.SkylosHoverProvider(store);
    const codeLensProvider = new codelens_1.SkylosCodeLensProvider(store);
    const quickFixProvider = new quickfix_1.SkylosQuickFixProvider(store);
    const aiAnalyzer = new ai_1.AIAnalyzer(store);
    // streaming inline decorations
    const streamingManager = new streaming_1.StreamingDecorationManager();
    aiAnalyzer.setStreamingManager(streamingManager);
    // chat view
    const chatProvider = new chatview_1.SkylosChatViewProvider(context);
    // auto-remediation
    const autoRemediator = new autoremediate_1.AutoRemediator(store);
    const dashboard = new dashboard_1.SkylosDashboard(store);
    const navigator = new navigator_1.FindingNavigator(store);
    const detailPanel = new detail_1.FindingDetailPanel();
    const fileDecoProvider = new filedecorations_1.SkylosFileDecorationProvider(store);
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
    context.subscriptions.push(store, diagnostics, decorations, statusBar, treeProvider, codeLensProvider, treeView, hoverProvider.register(), codeLensProvider.register(), quickFixProvider.register(), streamingManager, dashboard, navigator, detailPanel, fileDecoProvider, fileDecoProvider.register(), scanner_1.out);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider(chatview_1.SkylosChatViewProvider.viewType, chatProvider));
    // run full workspace scan and store results
    async function doScan(diffBase) {
        statusBar.setScanning(true);
        try {
            const result = await (0, scanner_1.scanWorkspace)(undefined, diffBase);
            store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
            store.setCLIFindings(result.findings);
            const total = result.findings.length;
            if (total > 0 && (0, config_1.isShowPopup)()) {
                const action = await vscode.window.showWarningMessage(`Skylos found ${total} issue(s)`, "Show Details", "Dismiss");
                if (action === "Show Details")
                    scanner_1.out.show();
            }
            else if (total === 0) {
                vscode.window.setStatusBarMessage("Skylos: no issues", 5000);
            }
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg !== "Scan cancelled") {
                vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
            }
        }
        finally {
            statusBar.setScanning(false);
        }
    }
    context.subscriptions.push(vscode.commands.registerCommand("skylos.scan", () => {
        const diffBase = store.deltaMode ? "origin/main" : undefined;
        doScan(diffBase);
    }), vscode.commands.registerCommand("skylos.scanFile", async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage("Skylos: no active file to scan.");
            return;
        }
        statusBar.setScanning(true);
        try {
            const result = await (0, scanner_1.scanFile)(editor.document.uri.fsPath);
            store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
            store.setCLIFindings(result.findings);
            const total = result.findings.length;
            vscode.window.setStatusBarMessage(total > 0 ? `Skylos: ${total} issue(s) in ${editor.document.fileName.split("/").pop()}` : "Skylos: no issues", 5000);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg !== "Scan cancelled") {
                vscode.window.showErrorMessage(`Skylos scan failed: ${msg}`);
            }
        }
        finally {
            statusBar.setScanning(false);
        }
    }), vscode.commands.registerCommand("skylos.toggleDelta", () => {
        store.deltaMode = !store.deltaMode;
        const label = store.deltaMode ? "Delta mode ON — showing new issues only" : "Delta mode OFF — showing all issues";
        vscode.window.setStatusBarMessage(`Skylos: ${label}`, 4000);
        vscode.commands.executeCommand("skylos.scan");
    }), vscode.commands.registerCommand("skylos.fix", ai_1.fixWithAI), vscode.commands.registerCommand("skylos.dismissIssue", (filePath, line) => {
        store.dismissAIFinding(filePath, line);
    }), vscode.commands.registerCommand("skylos.removeImport", async (uri, line) => {
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        await editor.edit((eb) => {
            eb.delete(new vscode.Range(line, 0, line + 1, 0));
        });
        store.removeFindingAtLine(uri.fsPath, line + 1);
    }), vscode.commands.registerCommand("skylos.removeFunction", async (uri, line) => {
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        const langId = doc.languageId;
        let endLine = line;
        if (langId === "python") {
            const startText = doc.lineAt(line).text;
            const indent = startText.match(/^(\s*)/)?.[1].length ?? 0;
            for (let j = line + 1; j < doc.lineCount; j++) {
                const nextLine = doc.lineAt(j).text;
                if (nextLine.trim() === "") {
                    endLine = j;
                    continue;
                }
                const nextIndent = nextLine.match(/^(\s*)/)?.[1].length ?? 0;
                if (nextIndent <= indent && nextLine.trim() !== "")
                    break;
                endLine = j;
            }
        }
        else {
            let braceCount = 0;
            let foundBrace = false;
            for (let j = line; j < doc.lineCount; j++) {
                for (const ch of doc.lineAt(j).text) {
                    if (ch === "{") {
                        braceCount++;
                        foundBrace = true;
                    }
                    if (ch === "}")
                        braceCount--;
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
    }), vscode.commands.registerCommand("skylos.addToWhitelist", async (message) => {
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
        }
        catch {
            const edit = new vscode.WorkspaceEdit();
            edit.createFile(configPath, { overwrite: false, ignoreIfExists: true });
            await vscode.workspace.applyEdit(edit);
            const edit2 = new vscode.WorkspaceEdit();
            edit2.insert(configPath, new vscode.Position(0, 0), `${name}\n`);
            await vscode.workspace.applyEdit(edit2);
            vscode.window.showInformationMessage(`Created .skylosignore and added "${name}"`);
        }
    }), vscode.commands.registerCommand("skylos.statusBarClick", () => {
        dashboard.show();
    }), vscode.commands.registerCommand("skylos.dashboard", () => {
        dashboard.show();
    }), vscode.commands.registerCommand("skylos.nextFinding", () => {
        navigator.next();
    }), vscode.commands.registerCommand("skylos.prevFinding", () => {
        navigator.prev();
    }), vscode.commands.registerCommand("skylos.exportReport", () => {
        (0, export_1.exportReport)(store);
    }), vscode.commands.registerCommand("skylos.showFindingDetail", (node) => {
        if (node?.finding) {
            detailPanel.show(node.finding);
        }
    }), vscode.commands.registerCommand("skylos.refresh", () => {
        vscode.commands.executeCommand("skylos.scan");
    }), vscode.commands.registerCommand("skylos.clear", () => {
        store.clear();
    }), 
    // chat about a finding from sidebar
    vscode.commands.registerCommand("skylos.chatAboutFinding", async (node) => {
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
        const pick = await vscode.window.showQuickPick([
            { label: "Fix Errors Only", description: "CRITICAL + HIGH", severity: "HIGH" },
            { label: "Fix Errors + Warnings", description: "+ MEDIUM", severity: "MEDIUM" },
            { label: "Fix All", description: "All severities", severity: "LOW" },
        ], { placeHolder: "Select severity level to fix" });
        if (!pick)
            return;
        const options = {
            minSeverity: pick.severity,
            dryRun: false,
        };
        await autoRemediator.fixAll(options);
    }), 
    // auto fix dry run
    vscode.commands.registerCommand("skylos.fixAllDryRun", async () => {
        const pick = await vscode.window.showQuickPick([
            { label: "Preview Errors Only", description: "CRITICAL + HIGH", severity: "HIGH" },
            { label: "Preview Errors + Warnings", description: "+ MEDIUM", severity: "MEDIUM" },
            { label: "Preview All", description: "All severities", severity: "LOW" },
        ], { placeHolder: "Select severity level to preview" });
        if (!pick)
            return;
        const options = {
            minSeverity: pick.severity,
            dryRun: true,
        };
        await autoRemediator.fixAll(options);
    }));
    if ((0, config_1.isRunOnSave)()) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
            if ((0, config_1.isLanguageSupported)(doc.languageId)) {
                vscode.commands.executeCommand("skylos.scan");
            }
        }));
    }
    let aiDebounceTimer;
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || event.document !== editor.document)
            return;
        if (!(0, config_1.isLanguageSupported)(event.document.languageId))
            return;
        if (event.contentChanges.length === 0)
            return;
        if (aiDebounceTimer)
            clearTimeout(aiDebounceTimer);
        aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(event.document), (0, config_1.getIdleMs)());
    }));
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor && (0, config_1.isLanguageSupported)(editor.document.languageId)) {
            if (aiDebounceTimer)
                clearTimeout(aiDebounceTimer);
            aiDebounceTimer = setTimeout(() => aiAnalyzer.maybeAnalyze(editor.document), 1000);
        }
    }));
    if ((0, config_1.isScanOnOpen)()) {
        vscode.commands.executeCommand("skylos.scan");
    }
}
function deactivate() {
    (0, scanner_1.cancelScan)();
}
