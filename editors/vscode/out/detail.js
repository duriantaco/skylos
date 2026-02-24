"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingDetailPanel = void 0;
const vscode = require("vscode");
const rules_1 = require("./rules");
class FindingDetailPanel {
    show(finding) {
        if (this.panel) {
            this.panel.reveal();
        }
        else {
            this.panel = vscode.window.createWebviewPanel("skylosFindingDetail", "Finding Detail", vscode.ViewColumn.Beside, { enableScripts: true });
            this.panel.onDidDispose(() => { this.panel = undefined; });
        }
        this.panel.title = `[${finding.ruleId}] Detail`;
        this.panel.webview.html = this.getHtml(finding);
        this.panel.webview.onDidReceiveMessage((msg) => {
            switch (msg.command) {
                case "fix":
                    vscode.commands.executeCommand("skylos.fix", finding.file, finding.line, finding.message, finding.ruleId);
                    break;
                case "dismiss":
                    vscode.commands.executeCommand("skylos.dismissIssue", finding.file, finding.line);
                    this.panel?.dispose();
                    break;
                case "openFile":
                    vscode.commands.executeCommand("vscode.open", vscode.Uri.file(finding.file), {
                        selection: new vscode.Range(Math.max(0, finding.line - 1), 0, Math.max(0, finding.line - 1), 0),
                    });
                    break;
            }
        });
    }
    getHtml(f) {
        const meta = (0, rules_1.getRuleMeta)(f.ruleId);
        const shortFile = f.file.split("/").slice(-2).join("/");
        const sevColor = getSevColor(f.severity);
        const tags = [];
        if (meta?.owasp)
            tags.push(`<span class="tag owasp">OWASP ${meta.owasp}</span>`);
        if (meta?.cwe)
            tags.push(`<span class="tag cwe">${meta.cwe}</span>`);
        if (meta?.pciDss)
            tags.push(`<span class="tag pci">PCI-DSS ${meta.pciDss}</span>`);
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
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
hr{border:none;border-top:1px solid var(--vscode-widget-border,rgba(255,255,255,.1));margin:16px 0}
</style>
</head>
<body>
<span class="severity">${f.severity}</span>
<h1>${meta?.name ?? f.ruleId}</h1>
<div class="location" onclick="post('openFile')">${shortFile}:${f.line}</div>

<p class="desc">${f.message}</p>

${tags.length > 0 ? `<div class="tags">${tags.join("")}</div>` : ""}

${meta?.description ? `
<h2>Description</h2>
<div class="section"><p>${meta.description}</p></div>
` : ""}

${meta?.fix ? `
<div class="fix-box">
  <h3>Recommended Fix</h3>
  <p>${meta.fix}</p>
</div>
` : ""}

${f.confidence !== undefined ? `<p style="font-size:12px;opacity:.5;margin-top:8px">Confidence: ${f.confidence}%</p>` : ""}

<hr/>
<div class="actions">
  <button class="btn btn-primary" onclick="post('fix')">&#9889; Fix with AI</button>
  <button class="btn btn-secondary" onclick="post('dismiss')">Dismiss</button>
  <button class="btn btn-secondary" onclick="post('openFile')">Go to File</button>
</div>

<script>
const vscode = acquireVsCodeApi();
function post(cmd){vscode.postMessage({command:cmd})}
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
