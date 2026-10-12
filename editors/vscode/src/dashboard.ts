import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import { getMaxProblems } from "./config";
import { createWebviewNonce, escapeHtml, isRecord, webviewCsp } from "./webviewSecurity";
import { assessmentRows, coverageText, groupAdvice, measurementRows, riskSummary } from "./assessmentCore";
import type { SkylosFinding } from "./types";

export function getRiskSummary(store: FindingsStore) {
  return riskSummary(store.assessment, store.getAllRawFindings());
}

function findingsTable(findings: SkylosFinding[]): string {
  return `<table><tr><th>Type</th><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr>${findings.map(f => `<tr><td>${escapeHtml(f.findingType ?? "review")}</td><td>${escapeHtml(f.severityUnknown ? "UNKNOWN" : f.severity)}</td><td>${escapeHtml(f.ruleId)}</td><td>${escapeHtml(f.relativePath ?? f.file)}:${f.line}</td><td>${escapeHtml(f.message)}</td></tr>`).join("")}</table>`;
}

export class SkylosDashboard {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {}

  show(): void {
    if (this.panel) {
      this.panel.reveal();
      this.update();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      "skylosDashboard",
      "Skylos Security Dashboard",
      vscode.ViewColumn.One,
      { enableScripts: true, localResourceRoots: [] },
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    this.panel.webview.onDidReceiveMessage((msg: unknown) => {
      const command = getDashboardCommand(msg);
      if (!command) return;

      switch (command) {
        case "scan":
          vscode.commands.executeCommand("skylos.scan");
          break;
        case "fixAll":
          vscode.commands.executeCommand("skylos.fixAll");
          break;
        case "export":
          vscode.commands.executeCommand("skylos.exportReport");
          break;
      }
    }, null, this.disposables);

    this.disposables.push(
      this.store.onDidChange(() => this.update()),
      this.store.onDidChangeAI(() => this.update()),
    );

    this.update();
  }

  private update(): void {
    if (!this.panel) 
      return;
    this.panel.webview.html = this.getHtml(this.panel.webview);
  }

  private getHtml(webview: vscode.Webview): string {
    const nonce = createWebviewNonce();
    const csp = webviewCsp(webview, nonce);
    const { label: riskLabel, color } = getRiskSummary(this.store);
    const counts = this.store.countBySeverity();
    const catCounts = this.store.countByCategory();
    const allFindings = this.store.getAllFindings();
    const total = allFindings.length;
    const rawTotal = this.store.getAllRawFindings().length;
    const visibleSummary = this.store.getVisibleSummary(getMaxProblems());
    const summary = this.store.summary;
    const circularDeps = this.store.circularDeps;
    const depVulns = this.store.depVulns;

    const critical = counts["CRITICAL"] ?? 0;
    const high = counts["HIGH"] ?? 0;
    const medium = (counts["MEDIUM"] ?? 0) + (counts["WARN"] ?? 0);
    const low = (counts["LOW"] ?? 0) + (counts["INFO"] ?? 0);
    const maxBar = Math.max(critical, high, medium, low, 1);

    const fileCounts = new Map<string, { total: number; critical: number }>();
    for (const f of allFindings) {
      const entry = fileCounts.get(f.file) ?? { total: 0, critical: 0 };
      entry.total++;
      if (f.severity === "CRITICAL" || f.severity === "HIGH") entry.critical++;
      fileCounts.set(f.file, entry);
    }
    const topFiles = [...fileCounts.entries()]
      .sort((a, b) => b[1].critical - a[1].critical || b[1].total - a[1].total)
      .slice(0, 5);

    const assessment = this.store.assessment;
    const fullFindings = this.store.getAllRawFindings();
    const assessmentHtml = `<table>${assessmentRows(assessment, fullFindings, this.store.gate).map(([area, detail]) => `<tr><th>${escapeHtml(area)}</th><td>${escapeHtml(detail)}</td></tr>`).join("")}</table><p>${escapeHtml(coverageText(assessment))}</p>`;
    const measurements = measurementRows(assessment);
    const measurementsHtml = measurements.length ? `<div class="card full"><h3>Maintainability measurements</h3><table><tr><th>Check</th><th>Spread</th><th>Magnitude</th></tr>${measurements.map(row => `<tr>${row.map(cell => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`).join("")}</table></div>` : "";
    const advice = groupAdvice(allFindings);
    const adviceHtml = advice.length ? `<div class="card full"><h3>Advice</h3><p>Expand a check for every displayed location. Exports retain complete records.</p>${advice.map(([rule, rows]) => `<details><summary>${escapeHtml(rule)} · ${rows.length} advice · ${new Set(rows.map(f => f.file)).size} files</summary>${findingsTable(rows)}</details>`).join("")}</div>` : "";
    const actionable = allFindings.filter(f => f.findingType !== "advice");
    const findingsHtml = actionable.length ? `<div class="card full"><h3>Defect and Review</h3>${findingsTable(actionable)}</div>` : "";

    const catIcons: Record<string, string> = {
      security: "&#128274;",
      dead_code: "&#128465;",
      secrets: "&#128273;",
      quality: "&#128736;",
      debt: "&#128295;",
      ai: "&#129302;",
    };

    const legacy = !assessment && this.store.grade?.overall;
    const legacyHtml = legacy ? `<p>Legacy score: ${escapeHtml(legacy.letter)} (${escapeHtml(legacy.score)}/100). Historical result; not a current risk assessment.</p>` : "";

    let summaryHtml = "";
    if (summary) {
      const parts: string[] = [];
      if (summary.total_files) parts.push(`<span>${summary.total_files} files</span>`);
      if (summary.total_loc) parts.push(`<span>${summary.total_loc.toLocaleString()} LOC</span>`);
      if (summary.languages) {
        const langs = Object.entries(summary.languages)
          .map(([l, n]) => `${escapeHtml(l)}: ${escapeHtml(n)}`)
          .join(", ");
        parts.push(`<span>${langs}</span>`);
      }
      if (parts.length > 0) {
        summaryHtml = `<div class="summary-bar">${parts.join('<span class="sep">|</span>')}</div>`;
      }
    }

    const scopeParts: string[] = [];
    if (rawTotal !== total) {
      scopeParts.push(`${total} finding(s) in current filter`);
      scopeParts.push(`${rawTotal} total in repo`);
    }
    if (visibleSummary.visibleTotal < visibleSummary.workingTotal) {
      scopeParts.push(`editor surfaces show top ${visibleSummary.visibleTotal}`);
    }
    const scopeHtml = scopeParts.length > 0
      ? `<div class="scope-bar">${scopeParts.join('<span class="sep">|</span>')}</div>`
      : "";

    let circularHtml = "";
    if (circularDeps.length > 0) {
      circularHtml = `
  <div class="card full">
    <h3>&#128260; Circular Dependencies (${circularDeps.length})</h3>
    <div class="circ-list">
      ${circularDeps.slice(0, 10).map((d) => {
        const chain = d.cycle.map((m) => escapeHtml(m.split("/").pop() ?? m)).join(" &#8594; ");
        return `<div class="circ-item">${chain}</div>`;
      }).join("")}
      ${circularDeps.length > 10 ? `<p style="opacity:.5;font-size:12px;margin-top:8px">...and ${circularDeps.length - 10} more</p>` : ""}
    </div>
  </div>`;
    }

    let depVulnHtml = "";
    if (depVulns.length > 0) {
      depVulnHtml = `
  <div class="card full">
    <h3>&#128027; Dependency Vulnerabilities (${depVulns.length})</h3>
    <table>
      <tr><th>Package</th><th>Severity</th><th>Summary</th><th>Fix</th></tr>
      ${depVulns.slice(0, 10).map((v) => {
        const sevColor = v.severity?.toUpperCase() === "CRITICAL" ? "#ef4444" : v.severity?.toUpperCase() === "HIGH" ? "#fb923c" : "#facc15";
        return `<tr>
          <td class="mono">${escapeHtml(v.package)}${v.version ? `@${escapeHtml(v.version)}` : ""}</td>
          <td><span style="color:${sevColor}">${escapeHtml(v.severity ?? "?")}</span></td>
          <td>${escapeHtml(v.summary ?? v.vulnerability_id ?? "")}</td>
          <td class="mono">${escapeHtml(v.fix_version ?? "-")}</td>
        </tr>`;
      }).join("")}
    </table>
  </div>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta http-equiv="Content-Security-Policy" content="${escapeHtml(csp)}"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:24px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
.card{background:var(--vscode-editor-background);border:1px solid var(--vscode-widget-border,rgba(255,255,255,.1));border-radius:12px;padding:20px;backdrop-filter:blur(12px);transition:transform .2s,box-shadow .2s}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.2)}
.card h3{margin-bottom:12px;font-size:13px;text-transform:uppercase;letter-spacing:.8px;opacity:.7}
.full{grid-column:1/-1}

.summary-bar{display:flex;gap:12px;align-items:center;font-size:12px;opacity:.6;margin-top:8px;flex-wrap:wrap}
.scope-bar{display:flex;gap:12px;align-items:center;font-size:12px;margin-top:10px;flex-wrap:wrap;padding:10px 12px;border-radius:8px;background:var(--vscode-input-background);opacity:.8}
.sep{opacity:.3}

.score-wrap{display:flex;align-items:center;gap:32px}
.donut{position:relative;width:140px;height:140px;border-radius:50%;border:4px solid ${color}}
.donut::after{content:"";position:absolute;inset:20px;border-radius:50%;background:var(--vscode-editor-background)}
.donut-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:1}
.donut-grade{font-size:36px;font-weight:700;color:${color}}
.donut-score{font-size:12px;opacity:.6}

.score-stats{display:flex;flex-direction:column;gap:8px}
.stat-row{display:flex;align-items:center;gap:10px;font-size:13px}
.stat-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

.cat-grades{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}
.cat-grade-item{display:flex;flex-direction:column;align-items:center;gap:2px}
.cat-grade-letter{font-size:20px;font-weight:700}
.cat-grade-label{font-size:10px;text-transform:uppercase;opacity:.5}

.bar-wrap{margin-bottom:10px}
.bar-label{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}
.bar-track{height:8px;border-radius:4px;background:var(--vscode-widget-border,rgba(255,255,255,.08));overflow:hidden}
.bar-fill{height:100%;border-radius:4px;animation:bar-grow .8s ease-out forwards;transform-origin:left}
@keyframes bar-grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}

.cat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.cat-item{display:flex;align-items:center;gap:8px;padding:10px;border-radius:8px;background:var(--vscode-input-background);font-size:13px}
.cat-icon{font-size:20px}
.cat-count{font-weight:700;margin-left:auto}

.circ-list{display:flex;flex-direction:column;gap:4px}
.circ-item{font-family:var(--vscode-editor-font-family);font-size:12px;padding:6px 10px;border-radius:4px;background:var(--vscode-input-background)}

table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--vscode-widget-border,rgba(255,255,255,.1));opacity:.6;font-weight:600}
td{padding:8px 6px;border-bottom:1px solid var(--vscode-widget-border,rgba(255,255,255,.05))}
.mono{font-family:var(--vscode-editor-font-family);font-size:12px}

.actions{display:flex;gap:10px;margin-top:20px}
.btn{padding:8px 18px;border:none;border-radius:6px;font-size:13px;cursor:pointer;font-family:inherit;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn-primary{background:var(--vscode-button-background);color:var(--vscode-button-foreground)}
.btn-secondary{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground)}
</style>
</head>
<body>
<h2>Security Dashboard</h2>
${summaryHtml}
${scopeHtml}

<div class="grid">
  <div class="card">
    <h3>Scan assessment</h3>
    <p style="color:${color};font-weight:700">Risk: ${escapeHtml(riskLabel)}</p>
    ${assessmentHtml}
    <p>Assessment includes the complete scan; finding filters change this view.</p>
    ${legacyHtml}
  </div>

  <div class="card">
    <h3>Severity Breakdown</h3>
    <div class="bar-wrap">
      <div class="bar-label"><span>Critical</span><span>${critical}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(critical / maxBar) * 100}%;background:#ef4444"></div></div>
    </div>
    <div class="bar-wrap">
      <div class="bar-label"><span>High</span><span>${high}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(high / maxBar) * 100}%;background:#fb923c"></div></div>
    </div>
    <div class="bar-wrap">
      <div class="bar-label"><span>Medium</span><span>${medium}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(medium / maxBar) * 100}%;background:#facc15"></div></div>
    </div>
    <div class="bar-wrap">
      <div class="bar-label"><span>Low / Info</span><span>${low}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(low / maxBar) * 100}%;background:#60a5fa"></div></div>
    </div>
  </div>

  <div class="card">
    <h3>Categories</h3>
    <div class="cat-grid">
      ${Object.entries(catCounts)
        .map(([cat, count]) => `<div class="cat-item"><span class="cat-icon">${catIcons[cat] ?? "&#128196;"}</span>${escapeHtml(cat)}<span class="cat-count">${count}</span></div>`)
        .join("")}
    </div>
  </div>

  <div class="card">
    <h3>Top 5 Riskiest Files</h3>
    ${topFiles.length === 0 ? "<p style='opacity:.5'>No findings yet.</p>" : `
    <table>
      <tr><th>File</th><th>Critical/High</th><th>Total</th></tr>
      ${topFiles.map(([file, c]) => {
        const short = file.split("/").slice(-2).join("/");
        return `<tr><td class="mono">${escapeHtml(short)}</td><td>${c.critical}</td><td>${c.total}</td></tr>`;
      }).join("")}
    </table>`}
  </div>

  ${circularHtml}
  ${depVulnHtml}
  ${measurementsHtml}
  ${findingsHtml}
  ${adviceHtml}
</div>

<div class="actions">
  <button class="btn btn-primary" type="button" data-command="scan">&#8635; Scan</button>
  <button class="btn btn-secondary" type="button" data-command="fixAll">&#9889; Fix All</button>
  <button class="btn btn-secondary" type="button" data-command="export">&#128196; Export</button>
</div>

<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
document.querySelector('.actions')?.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const command = target.dataset.command;
  if (command === 'scan' || command === 'fixAll' || command === 'export') {
    vscode.postMessage({ command });
  }
});
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    this.disposables.forEach((d) => d.dispose());
  }
}

function getDashboardCommand(msg: unknown): "scan" | "fixAll" | "export" | undefined {
  if (!isRecord(msg)) return undefined;
  switch (msg.command) {
    case "scan":
    case "fixAll":
    case "export":
      return msg.command;
    default:
      return undefined;
  }
}
