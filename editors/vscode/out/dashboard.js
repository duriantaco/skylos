"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosDashboard = void 0;
exports.computeSecurityScore = computeSecurityScore;
const vscode = require("vscode");
const GRADE_COLOR = {
    "A+": "#4ade80", "A": "#4ade80", "A-": "#4ade80",
    "B+": "#60a5fa", "B": "#60a5fa", "B-": "#60a5fa",
    "C+": "#facc15", "C": "#facc15", "C-": "#facc15",
    "D+": "#fb923c", "D": "#fb923c", "D-": "#fb923c",
    "F": "#ef4444",
};
const FALLBACK_GRADE_MAP = [
    { min: 97, grade: "A+", color: "#4ade80" },
    { min: 90, grade: "A", color: "#4ade80" },
    { min: 80, grade: "B", color: "#60a5fa" },
    { min: 70, grade: "C", color: "#facc15" },
    { min: 60, grade: "D", color: "#fb923c" },
    { min: 0, grade: "F", color: "#ef4444" },
];
const SEVERITY_PENALTY = {
    CRITICAL: 15, HIGH: 8, MEDIUM: 3, WARN: 3, LOW: 1, INFO: 1,
};
function computeSecurityScore(store) {
    const engineGrade = store.grade;
    if (engineGrade) {
        const letter = engineGrade.overall.letter;
        const score = engineGrade.overall.score;
        const color = GRADE_COLOR[letter] ?? "#888";
        return { score, grade: letter, color };
    }
    const counts = store.countBySeverity();
    let score = 100;
    for (const [sev, count] of Object.entries(counts)) {
        score -= (SEVERITY_PENALTY[sev] ?? 1) * count;
    }
    score = Math.max(0, score);
    for (const entry of FALLBACK_GRADE_MAP) {
        if (score >= entry.min) {
            return { score, grade: entry.grade, color: entry.color };
        }
    }
    return { score, grade: "F", color: "#ef4444" };
}
class SkylosDashboard {
    constructor(store) {
        this.store = store;
        this.disposables = [];
    }
    show() {
        if (this.panel) {
            this.panel.reveal();
            this.update();
            return;
        }
        this.panel = vscode.window.createWebviewPanel("skylosDashboard", "Skylos Security Dashboard", vscode.ViewColumn.One, { enableScripts: true });
        this.panel.onDidDispose(() => {
            this.panel = undefined;
        }, null, this.disposables);
        this.panel.webview.onDidReceiveMessage((msg) => {
            switch (msg.command) {
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
        this.disposables.push(this.store.onDidChange(() => this.update()), this.store.onDidChangeAI(() => this.update()));
        this.update();
    }
    update() {
        if (!this.panel)
            return;
        this.panel.webview.html = this.getHtml();
    }
    getHtml() {
        const { score, grade, color } = computeSecurityScore(this.store);
        const counts = this.store.countBySeverity();
        const catCounts = this.store.countByCategory();
        const allFindings = this.store.getAllFindings();
        const total = allFindings.length;
        const summary = this.store.summary;
        const circularDeps = this.store.circularDeps;
        const depVulns = this.store.depVulns;
        const critical = counts["CRITICAL"] ?? 0;
        const high = counts["HIGH"] ?? 0;
        const medium = (counts["MEDIUM"] ?? 0) + (counts["WARN"] ?? 0);
        const low = (counts["LOW"] ?? 0) + (counts["INFO"] ?? 0);
        const maxBar = Math.max(critical, high, medium, low, 1);
        const fileCounts = new Map();
        for (const f of allFindings) {
            const entry = fileCounts.get(f.file) ?? { total: 0, critical: 0 };
            entry.total++;
            if (f.severity === "CRITICAL" || f.severity === "HIGH")
                entry.critical++;
            fileCounts.set(f.file, entry);
        }
        const topFiles = [...fileCounts.entries()]
            .sort((a, b) => b[1].critical - a[1].critical || b[1].total - a[1].total)
            .slice(0, 5);
        const donutPct = Math.round(score);
        const donutDeg = Math.round((score / 100) * 360);
        const catIcons = {
            security: "&#128274;",
            dead_code: "&#128465;",
            secrets: "&#128273;",
            quality: "&#128736;",
            ai: "&#129302;",
        };
        const engineGrade = this.store.grade;
        let catGradesHtml = "";
        if (engineGrade?.categories) {
            const entries = Object.entries(engineGrade.categories);
            if (entries.length > 0) {
                catGradesHtml = `<div class="cat-grades">${entries.map(([cat, g]) => {
                    const c = GRADE_COLOR[g.letter] ?? "#888";
                    return `<div class="cat-grade-item"><span class="cat-grade-letter" style="color:${c}">${g.letter}</span><span class="cat-grade-label">${cat}</span></div>`;
                }).join("")}</div>`;
            }
        }
        let summaryHtml = "";
        if (summary) {
            const parts = [];
            if (summary.total_files)
                parts.push(`<span>${summary.total_files} files</span>`);
            if (summary.total_loc)
                parts.push(`<span>${summary.total_loc.toLocaleString()} LOC</span>`);
            if (summary.languages) {
                const langs = Object.entries(summary.languages).map(([l, n]) => `${l}: ${n}`).join(", ");
                parts.push(`<span>${langs}</span>`);
            }
            if (parts.length > 0) {
                summaryHtml = `<div class="summary-bar">${parts.join('<span class="sep">|</span>')}</div>`;
            }
        }
        let circularHtml = "";
        if (circularDeps.length > 0) {
            circularHtml = `
  <div class="card full">
    <h3>&#128260; Circular Dependencies (${circularDeps.length})</h3>
    <div class="circ-list">
      ${circularDeps.slice(0, 10).map((d) => {
                const chain = d.cycle.map((m) => m.split("/").pop()).join(" &#8594; ");
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
          <td class="mono">${v.package}${v.version ? `@${v.version}` : ""}</td>
          <td><span style="color:${sevColor}">${v.severity ?? "?"}</span></td>
          <td>${v.summary ?? v.vulnerability_id ?? ""}</td>
          <td class="mono">${v.fix_version ?? "-"}</td>
        </tr>`;
            }).join("")}
    </table>
  </div>`;
        }
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
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
.sep{opacity:.3}

.score-wrap{display:flex;align-items:center;gap:32px}
.donut{position:relative;width:140px;height:140px;border-radius:50%;background:conic-gradient(${color} 0deg,${color} var(--fill),var(--vscode-widget-border,rgba(255,255,255,.1)) var(--fill));animation:ring-fill 1s ease-out forwards}
.donut::after{content:"";position:absolute;inset:20px;border-radius:50%;background:var(--vscode-editor-background)}
.donut-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:1}
.donut-grade{font-size:36px;font-weight:700;color:${color}}
.donut-score{font-size:12px;opacity:.6}
@keyframes ring-fill{from{--fill:0deg}to{--fill:${donutDeg}deg}}
@property --fill{syntax:"<angle>";initial-value:0deg;inherits:false}

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

<div class="grid">
  <div class="card">
    <h3>Security Score</h3>
    <div class="score-wrap">
      <div class="donut">
        <div class="donut-label">
          <span class="donut-grade">${grade}</span>
          <span class="donut-score">${donutPct}/100</span>
        </div>
      </div>
      <div class="score-stats">
        <div class="stat-row"><span class="stat-dot" style="background:#ef4444"></span>Critical: ${critical}</div>
        <div class="stat-row"><span class="stat-dot" style="background:#fb923c"></span>High: ${high}</div>
        <div class="stat-row"><span class="stat-dot" style="background:#facc15"></span>Medium: ${medium}</div>
        <div class="stat-row"><span class="stat-dot" style="background:#60a5fa"></span>Low: ${low}</div>
        <div class="stat-row" style="margin-top:4px;font-weight:600">Total: ${total}</div>
      </div>
    </div>
    ${catGradesHtml}
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
            .map(([cat, count]) => `<div class="cat-item"><span class="cat-icon">${catIcons[cat] ?? "&#128196;"}</span>${cat}<span class="cat-count">${count}</span></div>`)
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
            return `<tr><td class="mono">${short}</td><td>${c.critical}</td><td>${c.total}</td></tr>`;
        }).join("")}
    </table>`}
  </div>

  ${circularHtml}
  ${depVulnHtml}
</div>

<div class="actions">
  <button class="btn btn-primary" onclick="post('scan')">&#8635; Scan</button>
  <button class="btn btn-secondary" onclick="post('fixAll')">&#9889; Fix All</button>
  <button class="btn btn-secondary" onclick="post('export')">&#128196; Export</button>
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
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.SkylosDashboard = SkylosDashboard;
