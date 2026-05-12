"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingDetailPanel = void 0;
const vscode = require("vscode");
const rules_1 = require("./rules");
const reviewCore_1 = require("./reviewCore");
const provenanceCore_1 = require("./provenanceCore");
const webviewSecurity_1 = require("./webviewSecurity");
class FindingDetailPanel {
    show(finding) {
        this.currentFinding = finding;
        if (this.panel) {
            this.panel.reveal();
        }
        else {
            this.panel = vscode.window.createWebviewPanel("skylosFindingDetail", "Finding Detail", vscode.ViewColumn.Beside, { enableScripts: true, localResourceRoots: [] });
            this.messageDisposable = this.panel.webview.onDidReceiveMessage((msg) => this.handleMessage(msg));
            this.panel.onDidDispose(() => {
                this.panel = undefined;
                this.currentFinding = undefined;
                this.messageDisposable?.dispose();
                this.messageDisposable = undefined;
            });
        }
        this.panel.title = `[${finding.ruleId}] Detail`;
        this.panel.webview.html = this.getHtml(this.panel.webview, finding);
    }
    handleMessage(msg) {
        const command = getDetailCommand(msg);
        const finding = this.currentFinding;
        if (!command || !finding)
            return;
        switch (command) {
            case "fix":
                vscode.commands.executeCommand("skylos.fix", finding.file, new vscode.Range(Math.max(0, finding.line - 1), 0, Math.max(0, finding.line - 1), 0), finding.message, false);
                break;
            case "dismiss":
                vscode.commands.executeCommand("skylos.dismissIssue", finding.file, finding.line);
                this.panel?.dispose();
                break;
            case "previewFix":
                vscode.commands.executeCommand("skylos.previewSafeFix", finding);
                break;
            case "openFile":
                vscode.commands.executeCommand("vscode.open", vscode.Uri.file(finding.file), {
                    selection: new vscode.Range(Math.max(0, finding.line - 1), 0, Math.max(0, finding.line - 1), 0),
                });
                break;
        }
    }
    getHtml(webview, f) {
        const nonce = (0, webviewSecurity_1.createWebviewNonce)();
        const csp = (0, webviewSecurity_1.webviewCsp)(webview, nonce);
        const meta = (0, rules_1.getRuleMeta)(f.ruleId);
        const shortFile = f.file.split("/").slice(-2).join("/");
        const sevColor = getSevColor(f.severity);
        const reviewContext = {
            currentFile: vscode.window.activeTextEditor?.document.uri.fsPath,
        };
        const reasons = (0, reviewCore_1.priorityReasons)(f, reviewContext);
        const evidence = (0, reviewCore_1.evidenceLines)(f);
        const plan = (0, reviewCore_1.fixPlan)(f);
        const provenance = (0, provenanceCore_1.provenanceLabel)(f);
        const summary = getFindingSummary(f, provenance);
        const ciCopy = f.ciBlocking === true
            ? "Skylos marked this finding as CI-blocking."
            : (0, reviewCore_1.isLikelyCiBlocker)(f)
                ? "This is likely to block a strict Skylos quality gate."
                : "This is not a likely blocker by default, but it can still matter for review quality.";
        const decisionRows = [
            ["Rule", f.ruleId],
            ["Category", f.category],
            ["Source", provenance],
            ["Location", `${f.relativePath ?? shortFile}:${f.line}`],
            ...(f.confidence !== undefined ? [["Confidence", `${f.confidence}%`]] : []),
            ...(f.baselineStatus || f.isNew ? [["Baseline", f.baselineStatus ?? "new"]] : []),
            ["Engine fix", f.fixPatch ? "Preview available" : "No deterministic patch available"],
        ];
        const tags = [];
        if (meta?.owasp)
            tags.push(`<span class="tag owasp">OWASP ${(0, webviewSecurity_1.escapeHtml)(meta.owasp)}</span>`);
        if (meta?.cwe)
            tags.push(`<span class="tag cwe">${(0, webviewSecurity_1.escapeHtml)(meta.cwe)}</span>`);
        if (meta?.pciDss)
            tags.push(`<span class="tag pci">PCI-DSS ${(0, webviewSecurity_1.escapeHtml)(meta.pciDss)}</span>`);
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta http-equiv="Content-Security-Policy" content="${(0, webviewSecurity_1.escapeHtml)(csp)}"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:24px;line-height:1.6}
h1{font-size:18px;margin-bottom:4px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;opacity:.6;margin:20px 0 8px}
.severity{display:inline-block;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:700;color:#fff;background:${sevColor}}
.location{margin:12px 0;font-family:var(--vscode-editor-font-family);font-size:13px;cursor:pointer;color:var(--vscode-textLink-foreground)}
.location:hover{text-decoration:underline}
.desc{font-size:14px;opacity:.9;margin:8px 0}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0}
.tag{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:600}
.owasp{background:rgba(239,68,68,.15);color:#ef4444}
.cwe{background:rgba(251,146,60,.15);color:#fb923c}
.pci{background:rgba(96,165,250,.15);color:#60a5fa}
.fix-box{margin:16px 0;padding:14px;border-radius:8px;background:var(--vscode-input-background);border-left:3px solid #4ade80}
.fix-box h3{font-size:13px;color:#4ade80;margin-bottom:6px}
.fix-box p{font-size:13px;opacity:.85}
.actions{display:flex;gap:8px;margin-top:20px}
.btn{padding:7px 16px;border:none;border-radius:6px;font-size:13px;cursor:pointer;font-family:inherit}
.btn:hover{opacity:.85}
.btn-primary{background:var(--vscode-button-background);color:var(--vscode-button-foreground)}
.btn-secondary{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground)}
.section{margin-top:16px;padding:14px;border-radius:8px;background:var(--vscode-input-background)}
.section p{font-size:13px;opacity:.85}
.list{margin:0;padding-left:18px;font-size:13px}
.list li{margin:4px 0}
.snippet{margin-top:10px;padding:10px;border-radius:6px;overflow:auto;background:var(--vscode-textCodeBlock-background,var(--vscode-editor-background));font-family:var(--vscode-editor-font-family);font-size:12px;line-height:1.45;white-space:pre-wrap}
.impact{border-left:3px solid ${(0, reviewCore_1.isLikelyCiBlocker)(f) ? "#ef4444" : "#60a5fa"}}
.decision{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin-top:14px;padding:12px;border:1px solid var(--vscode-widget-border,rgba(255,255,255,.12));border-radius:8px}
.decision .k{font-size:12px;opacity:.6}
.decision .v{font-size:12px;font-family:var(--vscode-editor-font-family)}
hr{border:none;border-top:1px solid var(--vscode-widget-border,rgba(255,255,255,.1));margin:16px 0}
</style>
</head>
<body>
<span class="severity">${f.severity}</span>
<h1>${(0, webviewSecurity_1.escapeHtml)(meta?.name ?? f.ruleId)}</h1>
<div class="location" data-command="openFile" role="button" tabindex="0">${(0, webviewSecurity_1.escapeHtml)(shortFile)}:${f.line}</div>

<p class="desc"><strong>${(0, webviewSecurity_1.escapeHtml)(summary)}</strong></p>
<p class="desc">${(0, webviewSecurity_1.escapeHtml)(f.message)}</p>

${tags.length > 0 ? `<div class="tags">${tags.join("")}</div>` : ""}

<div class="decision">
  ${decisionRows.map(([key, value]) => `<div class="k">${(0, webviewSecurity_1.escapeHtml)(key)}</div><div class="v">${(0, webviewSecurity_1.escapeHtml)(String(value))}</div>`).join("")}
</div>

<h2>Why This Is Here</h2>
<div class="section">
  <ul class="list">${reasons.map((reason) => `<li>${(0, webviewSecurity_1.escapeHtml)(reason)}</li>`).join("")}</ul>
</div>

<h2>Evidence</h2>
<div class="section">
  ${evidence.length > 0
            ? `<ul class="list">${evidence.map((line) => `<li>${(0, webviewSecurity_1.escapeHtml)(line)}</li>`).join("")}</ul>`
            : f.snippet
                ? `<p>Code snippet attached; no separate trace metadata was provided.</p>`
                : `<p>No evidence trace was provided by this finding.</p>`}
  ${f.snippet ? `<pre class="snippet">${(0, webviewSecurity_1.escapeHtml)(f.snippet)}</pre>` : ""}
</div>

<h2>CI Impact</h2>
<div class="section impact"><p>${(0, webviewSecurity_1.escapeHtml)(ciCopy)}</p></div>

<h2>Fix Plan</h2>
<div class="fix-box">
  <h3>${(0, webviewSecurity_1.escapeHtml)(plan.title)}</h3>
  <ul class="list">${plan.steps.map((step) => `<li>${(0, webviewSecurity_1.escapeHtml)(step)}</li>`).join("")}</ul>
</div>

${meta?.description ? `
<h2>Description</h2>
<div class="section"><p>${(0, webviewSecurity_1.escapeHtml)(meta.description)}</p></div>
` : ""}

${meta?.fix ? `
<div class="fix-box">
  <h3>Rule Guidance</h3>
  <p>${(0, webviewSecurity_1.escapeHtml)(meta.fix)}</p>
</div>
` : ""}

<hr/>
<div class="actions">
  ${f.fixPatch ? `<button class="btn btn-primary" type="button" data-command="previewFix">Preview Engine Fix</button>` : ""}
  <button class="btn btn-primary" type="button" data-command="fix">Fix with AI Assist</button>
  <button class="btn btn-secondary" type="button" data-command="dismiss">Dismiss</button>
  <button class="btn btn-secondary" type="button" data-command="openFile">Go to File</button>
</div>

<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
const allowedCommands = new Set(['fix', 'dismiss', 'previewFix', 'openFile']);
function postCommandFromElement(target) {
  if (!(target instanceof HTMLElement)) return;
  const command = target.dataset.command;
  if (allowedCommands.has(command)) {
    vscode.postMessage({ command });
  }
}
document.body.addEventListener('click', (event) => postCommandFromElement(event.target));
document.body.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  postCommandFromElement(event.target);
});
</script>
</body>
</html>`;
    }
    dispose() {
        this.panel?.dispose();
    }
}
exports.FindingDetailPanel = FindingDetailPanel;
function getSevColor(sev) {
    switch (sev.toUpperCase()) {
        case "CRITICAL":
            return "#ef4444";
        case "HIGH":
            return "#fb923c";
        case "MEDIUM":
        case "WARN":
            return "#eab308";
        case "LOW":
        case "INFO":
            return "#60a5fa";
        default:
            return "#888";
    }
}
function getFindingSummary(finding, provenance) {
    if (finding.source === "ai" && !finding.sources?.some((source) => source !== "ai")) {
        return "AI Assist suggestion";
    }
    if (provenance.startsWith("Confirmed")) {
        return `${provenance} finding`;
    }
    return `${provenance} finding`;
}
function getDetailCommand(msg) {
    if (!(0, webviewSecurity_1.isRecord)(msg))
        return undefined;
    switch (msg.command) {
        case "fix":
        case "dismiss":
        case "previewFix":
        case "openFile":
            return msg.command;
        default:
            return undefined;
    }
}
