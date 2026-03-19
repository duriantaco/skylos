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
const commandcenter_1 = require("./commandcenter");
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
    const commandCenterProvider = new commandcenter_1.SkylosCommandCenterProvider();
    const treeView = vscode.window.createTreeView("skylosFindings", {
        treeDataProvider: treeProvider,
        showCollapseAll: true,
    });
    const commandCenterView = vscode.window.createTreeView("skylosCommandCenter", {
        treeDataProvider: commandCenterProvider,
        showCollapseAll: false,
    });
    const updateTreeBadge = () => {
        const summary = store.getVisibleSummary((0, config_1.getMaxTreeFindings)(), {
            maxPerFile: (0, config_1.getMaxTreeFindingsPerFile)(),
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
    commandCenterProvider.onDidUpdateState(updateCommandCenterBadge);
    updateCommandCenterBadge();
    context.subscriptions.push(store, diagnostics, decorations, statusBar, treeProvider, codeLensProvider, treeView, commandCenterProvider, commandCenterView, hoverProvider.register(), codeLensProvider.register(), quickFixProvider.register(), streamingManager, dashboard, navigator, detailPanel, fileDecoProvider, fileDecoProvider.register(), scanner_1.out);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider(chatview_1.SkylosChatViewProvider.viewType, chatProvider));
    void commandCenterProvider.initialize();
    async function doWorkspaceScan(diffBase) {
        statusBar.setScanning(true);
        try {
            const result = await (0, scanner_1.scanWorkspace)(undefined, diffBase);
            store.setEngineMetadata(result.grade, result.summary, result.circularDeps, result.depVulns);
            store.setWorkspaceCLIFindings(result.findings);
            const total = result.findings.length;
            const criticalOrHigh = result.findings.filter((finding) => finding.severity === "CRITICAL" || finding.severity === "HIGH").length;
            const scopeSummary = store.getVisibleSummary((0, config_1.getMaxTreeFindings)(), {
                maxPerFile: (0, config_1.getMaxTreeFindingsPerFile)(),
            });
            if (criticalOrHigh > 0 && (0, config_1.isShowPopup)()) {
                const action = await vscode.window.showWarningMessage(scopeSummary.visibleTotal < total
                    ? `Skylos found ${criticalOrHigh} critical/high issue(s) (${total} total, showing top ${scopeSummary.visibleTotal} in editor)`
                    : `Skylos found ${criticalOrHigh} critical/high issue(s) (${total} total)`, "Open Dashboard", "Dismiss");
                if (action === "Open Dashboard")
                    dashboard.show();
            }
            else if (total > 0) {
                vscode.window.setStatusBarMessage(`Skylos: ${total} issue(s) in workspace`, 5000);
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
    async function scanSingleFile(filePath, announce = true) {
        statusBar.setScanning(true);
        try {
            const result = await (0, scanner_1.scanFile)(filePath);
            const fileFindings = result.findings.filter((finding) => finding.file === filePath);
            store.setFocusedCLIFindings(filePath, fileFindings);
            if (announce) {
                const fileName = filePath.split("/").pop() ?? filePath;
                const total = fileFindings.length;
                vscode.window.setStatusBarMessage(total > 0 ? `Skylos: ${total} issue(s) in ${fileName}` : `Skylos: no issues in ${fileName}`, 4000);
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
    async function scanEditorFile(editor, announce = true) {
        if (!editor)
            return;
        await scanSingleFile(editor.document.uri.fsPath, announce);
    }
    async function openCommandCenterDetail(node) {
        const finding = commandCenterProvider.toSkylosFinding(node.action);
        if (!finding) {
            vscode.window.showWarningMessage("Skylos: this command-center action has no file target.");
            return;
        }
        detailPanel.show(finding);
    }
    async function applyCommandCenterSafeFix(node) {
        const finding = commandCenterProvider.toSkylosFinding(node.action);
        const safeFix = node.action.safe_fix;
        if (!finding || !safeFix) {
            vscode.window.showInformationMessage("Skylos: no safe fix is available for this action.");
            return;
        }
        const uri = vscode.Uri.file(finding.file);
        const line = Math.max(0, finding.line - 1);
        if (safeFix === "remove_import") {
            await vscode.commands.executeCommand("skylos.removeImport", uri, line);
        }
        else if (safeFix === "remove_function") {
            await vscode.commands.executeCommand("skylos.removeFunction", uri, line);
        }
        else {
            vscode.window.showInformationMessage("Skylos: no safe fix is available for this action.");
            return;
        }
        await scanSingleFile(finding.file, false);
        commandCenterProvider.scheduleRefresh(250);
    }
    async function snoozeCommandCenterAction(node) {
        const pick = await vscode.window.showQuickPick([
            { label: "4 hours", hours: 4 },
            { label: "24 hours", hours: 24 },
            { label: "72 hours", hours: 72 },
        ], { placeHolder: "Snooze this action for..." });
        if (!pick)
            return;
        await commandCenterProvider.snoozeAction(node.action, pick.hours);
        updateCommandCenterBadge();
        vscode.window.setStatusBarMessage(`Skylos: snoozed for ${pick.label}`, 3000);
    }
    async function restoreTriagedCommandCenterAction() {
        const triaged = commandCenterProvider.getTriagedEntries();
        if (triaged.length === 0) {
            vscode.window.showInformationMessage("Skylos: there are no snoozed or dismissed command-center actions.");
            return;
        }
        const pick = await vscode.window.showQuickPick(triaged.map(({ id, entry }) => {
            const finding = commandCenterProvider.getFindingById(id);
            return {
                label: finding?.message || id,
                detail: finding ? `${finding.file}:${finding.line}` : id,
                description: entry.status === "snoozed" && entry.snoozed_until
                    ? `snoozed until ${new Date(entry.snoozed_until).toLocaleString()}`
                    : entry.status,
                id,
            };
        }), { placeHolder: "Restore a snoozed or dismissed action" });
        if (!pick)
            return;
        await commandCenterProvider.restoreAction(pick.id);
        updateCommandCenterBadge();
        vscode.window.setStatusBarMessage("Skylos: restored command-center action", 3000);
    }
    context.subscriptions.push(vscode.commands.registerCommand("skylos.scan", () => {
        const diffBase = store.deltaMode ? (0, config_1.getDiffBase)() : undefined;
        doWorkspaceScan(diffBase);
    }), vscode.commands.registerCommand("skylos.scanFile", async (uri) => {
        const targetUri = uri ?? vscode.window.activeTextEditor?.document.uri;
        if (!targetUri) {
            vscode.window.showWarningMessage("Skylos: no active file to scan.");
            return;
        }
        await scanSingleFile(targetUri.fsPath);
    }), vscode.commands.registerCommand("skylos.toggleDelta", () => {
        store.deltaMode = !store.deltaMode;
        const label = store.deltaMode ? "Delta mode ON — showing new issues only" : "Delta mode OFF — showing all issues";
        vscode.window.setStatusBarMessage(`Skylos: ${label}`, 4000);
        void vscode.commands.executeCommand("skylos.scan");
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
        void vscode.commands.executeCommand("skylos.scan");
    }), vscode.commands.registerCommand("skylos.refreshCommandCenter", async () => {
        await commandCenterProvider.refresh();
    }), vscode.commands.registerCommand("skylos.commandCenterOpenDetail", async (node) => {
        await openCommandCenterDetail(node);
    }), vscode.commands.registerCommand("skylos.commandCenterApplySafeFix", async (node) => {
        await applyCommandCenterSafeFix(node);
    }), vscode.commands.registerCommand("skylos.commandCenterDismiss", async (node) => {
        await commandCenterProvider.dismissAction(node.action);
        updateCommandCenterBadge();
        vscode.window.setStatusBarMessage("Skylos: dismissed command-center action", 3000);
    }), vscode.commands.registerCommand("skylos.commandCenterSnooze", async (node) => {
        await snoozeCommandCenterAction(node);
    }), vscode.commands.registerCommand("skylos.commandCenterRestoreTriaged", async () => {
        await restoreTriagedCommandCenterAction();
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
    }), vscode.commands.registerCommand("skylos.filterFindings", async () => {
        const filterType = await vscode.window.showQuickPick([
            { label: "$(warning) By Severity", value: "severity" },
            { label: "$(symbol-class) By Category", value: "category" },
            { label: "$(source-control) By Source (CLI vs AI)", value: "source" },
            { label: "$(file) By File Name", value: "file" },
        ], { placeHolder: "Filter findings by..." });
        if (!filterType)
            return;
        if (filterType.value === "severity") {
            const sev = await vscode.window.showQuickPick(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARN"], { placeHolder: "Show only this severity" });
            if (sev)
                store.filter = { ...store.filter, severity: sev };
        }
        else if (filterType.value === "category") {
            const cat = await vscode.window.showQuickPick([
                { label: "Security", value: "security" },
                { label: "Secrets", value: "secrets" },
                { label: "Dead Code", value: "dead_code" },
                { label: "Quality", value: "quality" },
                { label: "AI Analysis", value: "ai" },
            ].map((c) => ({ ...c, description: c.value })), { placeHolder: "Show only this category" });
            if (cat)
                store.filter = { ...store.filter, category: cat.value };
        }
        else if (filterType.value === "source") {
            const src = await vscode.window.showQuickPick([
                { label: "CLI (static analysis)", value: "cli" },
                { label: "AI (real-time analysis)", value: "ai" },
            ], { placeHolder: "Show only this source" });
            if (src)
                store.filter = { ...store.filter, source: src.value };
        }
        else if (filterType.value === "file") {
            const pattern = await vscode.window.showInputBox({
                placeHolder: "e.g. auth.py, src/utils",
                prompt: "Filter by file path (substring match)",
            });
            if (pattern)
                store.filter = { ...store.filter, filePattern: pattern };
        }
        vscode.commands.executeCommand("setContext", "skylos.filterActive", store.hasActiveFilter);
        const label = store.hasActiveFilter ? "Filter active" : "No filter";
        vscode.window.setStatusBarMessage(`Skylos: ${label}`, 3000);
    }), vscode.commands.registerCommand("skylos.clearFilter", () => {
        store.filter = {};
        vscode.commands.executeCommand("setContext", "skylos.filterActive", false);
        vscode.window.setStatusBarMessage("Skylos: Filter cleared", 3000);
    }));
    if ((0, config_1.isRunOnSave)()) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
            if ((0, config_1.isLanguageSupported)(doc.languageId)) {
                void scanSingleFile(doc.uri.fsPath, false);
                if ((0, config_1.isCommandCenterRefreshOnSave)()) {
                    commandCenterProvider.scheduleRefresh();
                }
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
    context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration("skylos")) {
            store.refreshViews();
            void commandCenterProvider.handleConfigurationChanged();
        }
    }));
    if ((0, config_1.getAIProvider)() === "local" && !(0, config_1.getOpenAIBaseUrl)()) {
        vscode.window.showWarningMessage('Skylos: AI provider is "local" but no server URL set. Configure skylos.localBaseUrl (e.g. http://localhost:11434 for Ollama).', "Open Settings").then((action) => {
            if (action === "Open Settings") {
                vscode.commands.executeCommand("workbench.action.openSettings", "skylos.localBaseUrl");
            }
        });
    }
    let initialOpenScanDone = false;
    const maybeRunInitialOpenScan = (editor) => {
        if (initialOpenScanDone || !(0, config_1.isScanOnOpen)() || !editor)
            return;
        if (!(0, config_1.isLanguageSupported)(editor.document.languageId))
            return;
        initialOpenScanDone = true;
        void scanEditorFile(editor, false);
    };
    maybeRunInitialOpenScan(vscode.window.activeTextEditor);
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor((editor) => {
        maybeRunInitialOpenScan(editor);
    }));
}
function deactivate() {
    (0, scanner_1.cancelScan)();
}
