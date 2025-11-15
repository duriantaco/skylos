"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const child_process_1 = require("child_process");
const path = require("path");
const collection = vscode.languages.createDiagnosticCollection("skylos");
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
function activate(context) {
    context.subscriptions.push(collection);
    context.subscriptions.push(skylosDecorationType);
    out.appendLine("Skylos extension activated");
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = "skylos.scan";
    // statusBarItem.text = "$(shield) Skylos";
    statusBarItem.text = "$(shield) Skylos-TEST";
    statusBarItem.tooltip = "Click to scan with Skylos";
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    context.subscriptions.push(vscode.commands.registerCommand("skylos.scan", runSkylos));
    if (vscode.workspace.getConfiguration().get("skylos.runOnSave")) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
            if (doc.languageId === "python")
                runSkylos();
        }));
    }
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && latestByFile) {
            applyDecorations(latestByFile);
        }
    }));
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider({ language: "python" }, new IgnoreLineQuickFix(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
}
function deactivate() {
    collection.clear();
    collection.dispose();
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
    // console.log(`Running skylos with args: ${args.join(" ")}`);
    // console.log(`Working directory: ${ws.uri.fsPath}`);
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
        // console.log("Parsed report keys:", Object.keys(report));
    }
    catch {
        vscode.window.showErrorMessage("Skylos returned invalid JSON.");
        return;
    }
    const byFile = toDiagnostics(report);
    // console.log(`Processing diagnostics for ${byFile.size} files`);
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
    out.appendLine(`Skylos: applyDecorations called, visible editors = ${editors.length}`);
    for (const editor of editors) {
        const fsPath = editor.document.uri.fsPath;
        const diags = byFileAbs.get(fsPath) || [];
        out.appendLine(`Skylos: editor=${fsPath}, diags=${diags.length}`);
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
        out.appendLine(`Skylos: setting ${decorations.length} decoration(s) on ${fsPath}`);
        editor.setDecorations(skylosDecorationType, decorations);
    }
}
class IgnoreLineQuickFix {
    provideCodeActions(doc, _range, ctx) {
        const actions = [];
        for (const d of ctx.diagnostics) {
            if (d.source !== "skylos")
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
            // kiv .. add "ignore entire file" action
        }
        return actions;
    }
}
