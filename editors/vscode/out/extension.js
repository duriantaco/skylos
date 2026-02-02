"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const child_process_1 = require("child_process");
const path = require("path");
const crypto = require("crypto");
const collection = vscode.languages.createDiagnosticCollection("skylos");
const aiCollection = vscode.languages.createDiagnosticCollection("skylos-ai");
const out = vscode.window.createOutputChannel("skylos");
const skylosDecorationType = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(255, 255, 0, 0.18)",
    overviewRulerColor: "rgba(255, 255, 0, 0.8)",
    overviewRulerLane: vscode.OverviewRulerLane.Full,
    after: {
        margin: "0 0 0 3ch",
        color: new vscode.ThemeColor("editor.foreground"),
        fontStyle: "italic",
    },
});
let statusBarItem;
let latestByFile = null;
let aiDebounceTimer;
let aiAnalysisInFlight = false;
const findingsCache = new Map();
const shownPopups = new Set();
let lastPopupTime = 0;
const prevDocState = new Map();
function activate(context) {
    context.subscriptions.push(collection);
    context.subscriptions.push(aiCollection);
    context.subscriptions.push(skylosDecorationType);
    out.appendLine("Skylos extension activated");
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = "skylos.scan";
    statusBarItem.text = "$(shield) Skylos";
    statusBarItem.tooltip = "Click to scan with Skylos";
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    context.subscriptions.push(vscode.commands.registerCommand("skylos.scan", runSkylos));
    context.subscriptions.push(vscode.commands.registerCommand("skylos.fix", fixIssueWithAI));
    if (vscode.workspace.getConfiguration().get("skylos.runOnSave")) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
            if (doc.languageId === "python")
                runSkylos();
        }));
    }
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(event => {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        if (event.document !== editor.document)
            return;
        if (event.document.languageId !== "python")
            return;
        if (event.contentChanges.length === 0)
            return;
        const cfg = vscode.workspace.getConfiguration("skylos");
        const idleMs = cfg.get("idleMs", 2000);
        if (aiDebounceTimer)
            clearTimeout(aiDebounceTimer);
        aiDebounceTimer = setTimeout(() => aiMaybeAnalyze(event.document), idleMs);
    }));
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && latestByFile) {
            applyDecorations(latestByFile);
        }
        if (editor?.document.languageId === "python") {
            if (aiDebounceTimer)
                clearTimeout(aiDebounceTimer);
            aiDebounceTimer = setTimeout(() => aiMaybeAnalyze(editor.document), 1000);
        }
    }));
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider({ language: "python" }, new IgnoreLineQuickFix(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
}
function deactivate() {
    collection.clear();
    collection.dispose();
    aiCollection.clear();
    aiCollection.dispose();
    skylosDecorationType.dispose();
}
async function runSkylos() {
    collection.clear();
    out.clear();
    out.appendLine("=".repeat(60));
    out.appendLine("Starting Skylos scan...");
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) {
        vscode.window.showWarningMessage("Skylos: open a folder to scan.");
        return;
    }
    const cfg = vscode.workspace.getConfiguration();
    const bin = cfg.get("skylos.path", "skylos");
    const conf = cfg.get("skylos.confidence", 60);
    const excludes = cfg.get("skylos.excludeFolders", []);
    const enableSecrets = cfg.get("skylos.enableSecrets", true);
    const enableDanger = cfg.get("skylos.enableDanger", true);
    const enableQuality = cfg.get("skylos.enableQuality", true);
    const args = [ws.uri.fsPath, "--json", "-c", String(conf)];
    excludes.forEach(f => args.push("--exclude-folder", f));
    if (enableSecrets)
        args.push("--secrets");
    if (enableDanger)
        args.push("--danger");
    if (enableQuality)
        args.push("--quality");
    let stdout;
    try {
        const result = await runCommand(bin, args, { cwd: ws.uri.fsPath, encoding: "utf8" });
        stdout = result.stdout;
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Skylos failed: ${msg}`);
        return;
    }
    let report;
    try {
        report = JSON.parse(stdout || "{}");
    }
    catch {
        vscode.window.showErrorMessage("Skylos returned invalid JSON.");
        return;
    }
    const byFile = toDiagnostics(report);
    const absMap = new Map();
    for (const [reportedPath, diags] of byFile) {
        const filePath = path.isAbsolute(reportedPath)
            ? reportedPath
            : path.join(ws.uri.fsPath, reportedPath);
        const uri = vscode.Uri.file(filePath);
        collection.set(uri, diags);
        absMap.set(filePath, diags);
    }
    latestByFile = absMap;
    applyDecorations(absMap);
    printDetailedReport(report, ws.uri.fsPath);
    const total = [...byFile.values()].reduce((n, d) => n + d.length, 0);
    if (total > 0) {
        statusBarItem.text = `$(alert) Skylos: ${total}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        vscode.window.setStatusBarMessage(`Skylos: ${total} findings`, 5000);
        const action = await vscode.window.showWarningMessage(`Skylos found ${total} issue(s)`, "Show Details", "Dismiss");
        if (action === "Show Details") {
            out.show();
        }
    }
    else {
        statusBarItem.text = "$(check) Skylos";
        statusBarItem.backgroundColor = undefined;
        vscode.window.setStatusBarMessage("Skylos: no issues", 5000);
        vscode.window.showInformationMessage("Skylos found no issues.");
    }
}
async function aiMaybeAnalyze(document) {
    const cfg = vscode.workspace.getConfiguration("skylos");
    const apiKey = cfg.get("openaiApiKey");
    if (!apiKey) {
        return;
    }
    const currentContent = document.getText();
    const filePath = document.uri.fsPath;
    const prevContent = prevDocState.get(filePath);
    if (prevContent === currentContent) {
        return;
    }
    prevDocState.set(filePath, currentContent);
    const functions = extractFunctions(currentContent);
    const changedFunctions = functions.filter(fn => {
        const cached = findingsCache.get(fn.hash);
        return !cached || (Date.now() - cached.timestamp > 60000);
    });
    if (changedFunctions.length === 0) {
        return;
    }
    await aiAnalyzeChangedFunctions(document, changedFunctions);
}
function extractFunctions(code) {
    const lines = code.split("\n");
    const functions = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const match = line.match(/^(\s*)(async\s+)?def\s+(\w+)\s*\(/);
        if (match) {
            const indent = match[1].length;
            const name = match[3];
            const startLine = i;
            let endLine = i;
            for (let j = i + 1; j < lines.length; j++) {
                const nextLine = lines[j];
                if (nextLine.trim() === "") {
                    endLine = j;
                    continue;
                }
                const nextIndent = nextLine.match(/^(\s*)/)?.[1].length ?? 0;
                if (nextIndent <= indent && nextLine.trim() !== "" && !nextLine.trim().startsWith("#")) {
                    break;
                }
                endLine = j;
            }
            const content = lines.slice(startLine, endLine + 1).join("\n");
            const hash = crypto.createHash("md5").update(content).digest("hex");
            functions.push({ name, startLine, endLine, content, hash });
            i = endLine + 1;
        }
        else {
            i++;
        }
    }
    return functions;
}
async function aiAnalyzeChangedFunctions(document, functions) {
    if (aiAnalysisInFlight)
        return;
    if (functions.length === 0)
        return;
    const cfg = vscode.workspace.getConfiguration("skylos");
    const apiKey = cfg.get("openaiApiKey");
    if (!apiKey)
        return;
    aiAnalysisInFlight = true;
    const prevText = statusBarItem.text;
    statusBarItem.text = "$(eye~spin) Skylos AI...";
    try {
        const codeToAnalyze = functions
            .map(fn => `# Function: ${fn.name} (line ${fn.startLine + 1})\n${fn.content}`)
            .join("\n\n---\n\n");
        const issues = await callLLMForIssues(apiKey, codeToAnalyze);
        const now = Date.now();
        for (const fn of functions) {
            const fnIssues = issues.filter(i => i.line >= fn.startLine + 1 && i.line <= fn.endLine + 1);
            findingsCache.set(fn.hash, { issues: fnIssues, timestamp: now });
        }
        const diagnostics = issues.map(issue => {
            const line = Math.max(0, issue.line - 1);
            const range = new vscode.Range(line, 0, line, 1000);
            const severity = issue.severity === "error"
                ? vscode.DiagnosticSeverity.Error
                : vscode.DiagnosticSeverity.Warning;
            const diag = new vscode.Diagnostic(range, `[AI] ${issue.message}`, severity);
            diag.source = "skylos-ai";
            return diag;
        });
        aiCollection.set(document.uri, diagnostics);
        if (issues.length > 0) {
            statusBarItem.text = `$(eye) AI: ${issues.length}`;
            const critical = issues.find(i => i.severity === "error");
            if (critical) {
                aiMaybeShowPopup(document, critical);
            }
        }
        else {
            statusBarItem.text = prevText.includes("Skylos:") ? prevText : "$(eye) Skylos";
        }
    }
    catch (err) {
        out.appendLine(`AI Error: ${err}`);
        statusBarItem.text = prevText;
    }
    finally {
        aiAnalysisInFlight = false;
    }
}
function aiMaybeShowPopup(document, issue) {
    const cfg = vscode.workspace.getConfiguration("skylos");
    const cooldown = cfg.get("popupCooldownMs", 15000);
    const now = Date.now();
    out.appendLine(`[AI] aiMaybeShowPopup called for: ${issue.message}`);
    out.appendLine(`[AI] Time since last popup: ${now - lastPopupTime}ms, cooldown: ${cooldown}ms`);
    if (now - lastPopupTime < cooldown) {
        out.appendLine(`[AI] Popup blocked by cooldown`);
        return;
    }
    const fingerprint = `${document.uri.fsPath}:${issue.line}:${issue.message.slice(0, 50)}`;
    if (shownPopups.has(fingerprint)) {
        out.appendLine(`[AI] Popup blocked by fingerprint (already shown)`);
        return;
    }
    out.appendLine(`[AI] Showing popup!`);
    shownPopups.add(fingerprint);
    lastPopupTime = now;
    vscode.window.showWarningMessage(`🚨 AI: ${issue.message}`, "Fix it", "Show me", "Dismiss").then(action => {
        if (action === "Show me") {
            const line = Math.max(0, issue.line - 1);
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                editor.selection = new vscode.Selection(line, 0, line, 0);
                editor.revealRange(new vscode.Range(line, 0, line, 0));
            }
        }
        else if (action === "Fix it") {
            const line = Math.max(0, issue.line - 1);
            vscode.commands.executeCommand("skylos.fix", document.uri.fsPath, new vscode.Range(line, 0, line, 0), issue.message, false);
        }
    });
}
async function callLLMForIssues(apiKey, code) {
    const cfg = vscode.workspace.getConfiguration("skylos");
    const model = cfg.get("openaiModel", "gpt-4o-mini");
    const resp = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
            model,
            messages: [
                {
                    role: "system",
                    content: `You analyze Python code for bugs. Return ONLY a JSON array.

Each issue: {"line": <number>, "message": "<brief>", "severity": "error"|"warning"}
If no issues: []

Only report REAL bugs:
- Crashes / exceptions
- Security issues  
- Logic errors
- Undefined variables
- Type errors

Do NOT report: style, missing docs, naming conventions.`
                },
                { role: "user", content: code }
            ],
            temperature: 0,
            max_tokens: 1000,
        }),
    });
    if (!resp.ok) {
        throw new Error(`API error: ${resp.status}`);
    }
    const data = await resp.json();
    const content = data.choices?.[0]?.message?.content ?? "[]";
    try {
        const cleaned = content.replace(/```json?/g, "").replace(/```/g, "").trim();
        return JSON.parse(cleaned);
    }
    catch {
        return [];
    }
}
async function fixIssueWithAI(filePath, range, errorMsg, previewOnly) {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
    const editor = await vscode.window.showTextDocument(doc, { preview: false });
    const content = doc.getText();
    const functions = extractFunctions(content);
    const targetFn = functions.find(fn => range.start.line >= fn.startLine && range.start.line <= fn.endLine);
    if (!targetFn) {
        vscode.window.showErrorMessage("Could not find function to fix.");
        return;
    }
    const cfg = vscode.workspace.getConfiguration("skylos");
    const apiKey = cfg.get("openaiApiKey");
    const model = cfg.get("openaiModel", "gpt-4o");
    if (!apiKey) {
        vscode.window.showErrorMessage("Set skylos.openaiApiKey first.");
        return;
    }
    statusBarItem.text = "$(sync~spin) Fixing...";
    try {
        const resp = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model,
                messages: [
                    {
                        role: "user",
                        content: `Fix this Python function.\nProblem: ${errorMsg}\n\nReturn ONLY the fixed function. No markdown.\n\n${targetFn.content}`
                    }
                ],
                temperature: 0,
            }),
        });
        const data = await resp.json();
        let fixed = data.choices?.[0]?.message?.content ?? "";
        fixed = fixed.replace(/```python/g, "").replace(/```/g, "").trim();
        if (!fixed) {
            vscode.window.showErrorMessage("No fix returned.");
            return;
        }
        // Show diff
        const fixedDoc = await vscode.workspace.openTextDocument({ language: "python", content: fixed });
        await vscode.commands.executeCommand("vscode.diff", doc.uri, fixedDoc.uri, "Fix Preview");
        if (previewOnly)
            return;
        const confirm = await vscode.window.showWarningMessage("Apply fix?", "Apply", "Cancel");
        if (confirm !== "Apply")
            return;
        const blockRange = new vscode.Range(targetFn.startLine, 0, targetFn.endLine, doc.lineAt(targetFn.endLine).text.length);
        await editor.edit(eb => eb.replace(blockRange, fixed));
        vscode.window.showInformationMessage("Fix applied!");
        findingsCache.delete(targetFn.hash);
    }
    catch (e) {
        vscode.window.showErrorMessage(`Fix failed: ${e}`);
    }
    finally {
        statusBarItem.text = "$(shield) Skylos";
    }
}
function toDiagnostics(report) {
    const map = new Map();
    const add = (f) => {
        const key = normalizePath(f.file);
        const start = new vscode.Position(Math.max(0, (f.line ?? 1) - 1), Math.max(0, (f.col ?? 0)));
        const range = new vscode.Range(start, start);
        const sev = toSeverity(f.severity);
        const msg = f.rule_id ? `[${f.rule_id}] ${f.message}` : f.message;
        const diag = new vscode.Diagnostic(range, msg, sev);
        diag.source = "skylos";
        diag.code = f.rule_id || "SKYLOS";
        const list = map.get(key) || [];
        list.push(diag);
        map.set(key, list);
    };
    const mapUnusedList = (arr) => {
        (arr || []).forEach(u => {
            if (!u?.file)
                return;
            add({
                message: `Unused ${u.type ?? "item"}: ${u.name ?? u.simple_name ?? ""}`,
                file: u.file,
                line: u.line ?? u.lineno ?? 1
            });
        });
    };
    mapUnusedList(report.unused_functions);
    mapUnusedList(report.unused_imports);
    mapUnusedList(report.unused_classes);
    mapUnusedList(report.unused_variables);
    mapUnusedList(report.unused_parameters);
    (report.secrets || []).forEach(add);
    (report.danger || []).forEach(add);
    return map;
}
function toSeverity(s) {
    const t = (s || "").toUpperCase();
    if (t === "HIGH" || t === "CRITICAL")
        return vscode.DiagnosticSeverity.Error;
    if (t === "MEDIUM")
        return vscode.DiagnosticSeverity.Warning;
    return vscode.DiagnosticSeverity.Information;
}
function normalizePath(p) {
    return p.replace(/\\/g, "/");
}
function runCommand(cmd, args, opts) {
    return new Promise((resolve, reject) => {
        (0, child_process_1.execFile)(cmd, args, opts, (err, stdout, stderr) => {
            if (err)
                return reject(err);
            resolve({ stdout, stderr });
        });
    });
}
function printDetailedReport(report, workspaceRoot) {
    out.appendLine("");
    out.appendLine("=".repeat(60));
    out.appendLine("DETAILED RESULTS");
    out.appendLine("=".repeat(60));
    const allFindings = [];
    (report.danger || []).forEach(f => allFindings.push({ category: "SECURITY", finding: f }));
    (report.secrets || []).forEach(f => allFindings.push({ category: "SECRETS", finding: f }));
    (report.quality || []).forEach((q) => {
        if (!q?.file)
            return;
        allFindings.push({
            category: "QUALITY",
            finding: {
                message: q.message || `Quality issue (${q.kind || q.metric || "quality"})`,
                file: q.file,
                line: q.line ?? 1,
                severity: q.severity || "MEDIUM",
                rule_id: q.rule_id,
            },
        });
    });
    const addUnused = (arr, type) => {
        (arr || []).forEach(u => {
            if (u?.file) {
                allFindings.push({
                    category: "DEAD CODE",
                    finding: {
                        message: `Unused ${type}: ${u.name ?? u.simple_name ?? ""}`,
                        file: u.file,
                        line: u.line ?? u.lineno ?? 1,
                        severity: "INFO"
                    }
                });
            }
        });
    };
    addUnused(report.unused_functions || [], "function");
    addUnused(report.unused_imports || [], "import");
    addUnused(report.unused_classes || [], "class");
    addUnused(report.unused_variables || [], "variable");
    addUnused(report.unused_parameters || [], "parameter");
    if (allFindings.length === 0) {
        out.appendLine("No issues found.");
        return;
    }
    const byCategory = new Map();
    allFindings.forEach(({ category, finding }) => {
        const severity = finding.severity?.toUpperCase() || "INFO";
        if (!byCategory.has(category)) {
            byCategory.set(category, new Map());
        }
        const catMap = byCategory.get(category);
        if (!catMap.has(severity)) {
            catMap.set(severity, []);
        }
        catMap.get(severity).push(finding);
    });
    const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    for (const [category, severityMap] of byCategory) {
        out.appendLine("");
        out.appendLine(`${category}`);
        out.appendLine("-".repeat(60));
        const sorted = [...severityMap.keys()].sort((a, b) => severityOrder.indexOf(a) - severityOrder.indexOf(b));
        for (const severity of sorted) {
            const findings = severityMap.get(severity) || [];
            out.appendLine("");
            out.appendLine(`  ${severity} (${findings.length})`);
            findings.forEach((f, idx) => {
                const relPath = path.relative(workspaceRoot, f.file);
                const ruleId = f.rule_id ? `[${f.rule_id}] ` : "";
                const location = `${relPath}:${f.line}${f.col ? `:${f.col}` : ""}`;
                out.appendLine(` ${idx + 1}. ${ruleId}${f.message}`);
                out.appendLine(` File: ${location}`);
            });
        }
    }
    out.appendLine("");
    out.appendLine("=".repeat(60));
    out.appendLine(`Total: ${allFindings.length} issue(s)`);
}
function applyDecorations(byFileAbs) {
    const editors = vscode.window.visibleTextEditors;
    for (const editor of editors) {
        const diags = byFileAbs.get(editor.document.uri.fsPath) || [];
        const decorations = [];
        for (const d of diags) {
            const line = d.range.start.line;
            const range = new vscode.Range(line, 0, line, 0);
            decorations.push({
                range,
                hoverMessage: d.message,
                renderOptions: {
                    after: {
                        contentText: d.message,
                    },
                },
            });
        }
        editor.setDecorations(skylosDecorationType, decorations);
    }
}
class IgnoreLineQuickFix {
    provideCodeActions(doc, _range, ctx) {
        const actions = [];
        for (const d of ctx.diagnostics) {
            if (d.source !== "skylos" && d.source !== "skylos-ai")
                continue;
            const action = new vscode.CodeAction("Skylos: ignore on this line", vscode.CodeActionKind.QuickFix);
            const line = d.range.start.line;
            const text = doc.lineAt(line).text;
            const already = text.includes("# pragma: no skylos");
            const updated = already ? text : text + "  # pragma: no skylos";
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(doc.uri, new vscode.Range(line, 0, line, text.length), updated);
            action.diagnostics = [d];
            actions.push(action);
        }
        return actions;
    }
}
