const assert = require("node:assert/strict");
const test = require("node:test");
const { assessmentRows, coverageText, groupAdvice, measurementRows, readAssessment, readGate, riskSummary } = require("../out/assessmentCore");

function assessment() {
  return {
    version: 1, scope: "all_analyzed_findings", scanned_checks: ["security", "quality", "dead_code"],
    coverage: { status: "partial", not_assessed: ["secrets"], incomplete_checks: [], reasons: [] },
    risk: { status: "critical", highest_severity: "CRITICAL", finding_count: 1 },
    maintainability: { status: "measured", advice_count: 30, rule_count: 1, affected_files: 5, affected_functions: 30, checks: [{ rule_id: "SKY-Q301", name: "Complexity", language: "Python", count: 30, affected_units: 30, unit: "function", analyzed_units: 200, affected_percent: 15, max_value: 45, max_threshold: 10, max_excess_ratio: 4.5 }] },
    dead_code: { status: "review", candidate_count: 2, confidence_range: [60, 95] },
    finding_counts: { defect: 0, review: 3, advice: 30, advice_groups: 1 },
  };
}

const finding = (changes = {}) => ({ id: "1", ruleId: "SKY-D211", category: "security", findingType: "review", severity: "CRITICAL", message: "Review SQL flow", file: "/repo/app.py", line: 1, col: 0, source: "cli", ...changes });

test("critical Review remains critical regardless of finding filters or Advice volume", () => {
  const payload = assessment();
  const advice = Array.from({ length: 10000 }, (_, i) => finding({ id: String(i), findingType: "advice", category: "quality", severity: "HIGH", ruleId: "SKY-Q301" }));
  assert.equal(riskSummary(payload, []).status, "critical");
  assert.equal(riskSummary(payload, advice).status, "critical");
  assert.equal(riskSummary(undefined, [finding()]).status, "critical");
  assert.equal(riskSummary(undefined, []).status, "unknown");
});

test("assessment measurements show spread and magnitude without a grade", () => {
  const payload = assessment();
  assert.equal(readAssessment(payload), payload);
  const rows = new Map(assessmentRows(payload));
  assert.match(rows.get("Risk"), /CRITICAL/);
  assert.match(rows.get("Gate"), /Not evaluated/);
  assert.deepEqual(measurementRows(payload), [["SKY-Q301 · Python · Complexity", "30/200 functions (15%)", "max 45 · limit 10 · 4.5× limit"]]);
  assert.match(coverageText(payload), /not assessed: secrets/);
  assert.ok(!JSON.stringify([...rows]).includes("A+"));
});

test("missing denominator stays unknown and incomplete empty checks do not appear clean", () => {
  const payload = assessment();
  Object.assign(payload.maintainability.checks[0], { analyzed_units: null, affected_percent: null });
  Object.assign(payload.risk, { status: "unknown", highest_severity: null, finding_count: 0 });
  Object.assign(payload.dead_code, { status: "unknown", candidate_count: 0 });
  Object.assign(payload.coverage, { status: "incomplete", incomplete_checks: ["security", "dead_code"] });
  assert.match(measurementRows(payload)[0][1], /denominator unavailable/);
  const rows = new Map(assessmentRows(payload));
  assert.match(rows.get("Risk"), /Unknown/);
  assert.match(rows.get("Dead code"), /Unknown/);
  assert.match(coverageText(payload), /incomplete: security, dead_code/);
});

test("normalizer's legacy INFO fallback cannot lower an unknown severity assessment", () => {
  const { normalizeReportCore } = require("../out/findingCore");
  const rows = normalizeReportCore({ danger: [{ file: "app.py", line: 1, rule_id: "SKY-UNKNOWN", severity: "unrecognized", message: "Severity unavailable" }] }, { wsRoot: "/repo", deadCodeEnabled: true, showDeadParams: false, confidenceThreshold: 80 });
  const payload = assessment();
  Object.assign(payload.risk, { status: "unknown", finding_count: 1, severity_counts: { UNKNOWN: 1 } });
  assert.equal(rows[0].severityUnknown, true);
  assert.equal(riskSummary(payload, rows).status, "unknown");
  assert.match(new Map(assessmentRows(payload, rows)).get("Risk"), /Unknown/);
});

test("empty eligible inventory displays no checked functions instead of 0/0 or 0%", () => {
  const payload = assessment();
  Object.assign(payload.maintainability.checks[0], { affected_units: 0, analyzed_units: 0, affected_percent: 0 });
  assert.equal(measurementRows(payload)[0][1], "No eligible functions checked");
});

test("additional optional observations cannot be diluted by an older clear assessment", () => {
  const payload = assessment();
  Object.assign(payload.risk, { status: "none", highest_severity: null, finding_count: 0 });
  assert.equal(riskSummary(payload, [finding({ source: "ai" })]).status, "critical");
  assert.match(new Map(assessmentRows(payload, [finding()])).get("Risk"), /CRITICAL/);
});

test("unknown-severity agent overlays invalidate a previous clear risk assessment", () => {
  const { FindingsStore, SkylosDashboard, buildMarkdown } = loadConsumers();
  const overlay = finding({ source: "ai", severity: "MEDIUM", severityUnknown: true });
  for (const status of ["none", "not_assessed"]) {
    const payload = assessment();
    Object.assign(payload.risk, { status, highest_severity: null, finding_count: 0 });
    const store = new FindingsStore();
    store.setWorkspaceCLIFindings([]);
    store.setEngineMetadata(undefined, undefined, [], [], payload);
    store.setAgentFindings([overlay]);
    const summary = riskSummary(store.assessment, store.getAllRawFindings());
    assert.equal(summary.status, "unknown");
    assert.equal(summary.findingCount, 1);
    assert.notEqual(summary.color, "#4ade80");
    assert.match(new Map(assessmentRows(store.assessment, store.getAllRawFindings())).get("Risk"), /Unknown/);
    const html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
    assert.doesNotMatch(html, /No risk findings/);
    assert.doesNotMatch(buildMarkdown(store), /No risk findings/);
  }
  assert.equal(riskSummary(assessment(), [overlay]).status, "critical");
});

test("explicit local gate outcome stays separate from critical risk and unknown severity", () => {
  const payload = assessment();
  payload.risk.severity_counts = { CRITICAL: 1, UNKNOWN: 2 };
  const gate = { passed: true, reasons: [], scope: "local_configured_policy", status: "evaluated", forced: false };
  assert.equal(readGate(gate), gate);
  const rows = new Map(assessmentRows(payload, [], gate));
  assert.match(rows.get("Risk"), /CRITICAL.*2 with unknown severity/);
  assert.equal(rows.get("Gate"), "PASS · local configured policy");
  assert.match(new Map(assessmentRows(payload, [], { ...gate, status: "incomplete" })).get("Gate"), /^INCOMPLETE/);
  assert.equal(readGate({ passed: true }), undefined);
  assert.equal(readGate({ ...gate, scope: "cloud_policy" }), undefined);
});

test("Advice groups retain every full record while Defect and Review remain separate", () => {
  const rows = [finding(), finding({ id: "2", ruleId: "SKY-Q301", category: "quality", findingType: "advice", message: "first" }), finding({ id: "3", ruleId: "SKY-Q301", category: "quality", findingType: "advice", message: "second", line: 5 })];
  const before = JSON.stringify(rows);
  const groups = groupAdvice(rows);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0][1].map(f => f.message), ["first", "second"]);
  assert.equal(JSON.stringify(rows), before);
});

test("malformed or unsupported assessment payloads do not fabricate clean measurements", () => {
  assert.equal(readAssessment({ version: 1, scope: "all_analyzed_findings" }), undefined);
  const payload = assessment();
  payload.version = 99;
  assert.equal(readAssessment(payload), undefined);
  payload.version = 1;
  payload.maintainability.checks[0].analyzed_units = "200";
  assert.equal(readAssessment(payload), undefined);
});

test("store filters preserve full assessment and focused updates invalidate it", () => {
  const { FindingsStore } = loadConsumers();
  const store = new FindingsStore();
  store.setWorkspaceCLIFindings([finding()]);
  store.setEngineMetadata(undefined, undefined, [], [], assessment(), { assessment: assessment() });
  store.filter = { category: "dead_code" };
  assert.equal(store.getAllFindings().length, 0);
  assert.equal(riskSummary(store.assessment, store.getAllRawFindings()).status, "critical");
  store.setFocusedCLIFindings("/repo/other.py", []);
  assert.equal(store.assessment, undefined);
  assert.equal(store.report, undefined);
  assert.equal(store.gate, undefined);
  assert.equal(store.getAllRawFindings().length, 1);
  assert.equal(riskSummary(store.assessment, store.getAllRawFindings()).status, "critical");
  store.setEngineMetadata(undefined, undefined, [], [], assessment());
  store.setLastError({ kind: "nonzero_exit", message: "Engine failed" });
  assert.equal(store.assessment, undefined);
  assert.equal(store.getAllRawFindings().length, 1);
});

function loadConsumers() {
  const Module = require("node:module");
  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === "vscode") return {
      EventEmitter: class { event() {} fire() {} dispose() {} },
      window: { visibleTextEditors: [] },
      workspace: {
        workspaceFolders: [{ name: "Test project", uri: { fsPath: "/repo" } }],
        getConfiguration: () => ({ get: (_key, fallback) => fallback }),
      },
    };
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return { ...require("../out/store"), ...require("../out/dashboard"), ...require("../out/export") };
  } finally { Module._load = originalLoad; }
}

test("rendered dashboard keeps critical risk while filters hide its row and expands full Advice", () => {
  const { FindingsStore, SkylosDashboard } = loadConsumers();
  const store = new FindingsStore();
  const payload = assessment();
  payload.maintainability.checks[0].name = '<img src=x onerror="alert(1)">';
  store.setWorkspaceCLIFindings([
    finding(),
    finding({ id: "2", category: "quality", findingType: "advice", ruleId: "SKY-Q301", severity: "HIGH", message: "First full advice record" }),
    finding({ id: "3", category: "quality", findingType: "advice", ruleId: "SKY-Q301", severity: "HIGH", message: '<img src=x onerror="alert(2)">', line: 3 }),
  ]);
  store.setEngineMetadata(undefined, undefined, [], [], payload);
  store.filter = { category: "quality" };
  const html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
  assert.match(html, /CRITICAL · 1 unresolved finding/);
  assert.match(html, /<details><summary>SKY-Q301 · 2 advice/);
  assert.match(html, /First full advice record/);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(2\)&quot;&gt;/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /<th>Type<\/th><th>Severity<\/th>/);
  assert.match(html, /30\/200 functions \(15%\)/);
  assert.match(html, /4\.5× limit/);
  assert.match(html, /Content-Security-Policy/);
  assert.doesNotMatch(html, /Legacy score:|Security Score|A\+/);
});

test("exports preserve the full assessment and every finding despite the display filter", () => {
  const { FindingsStore, buildMarkdown, buildJson, buildSarif } = loadConsumers();
  const store = new FindingsStore();
  const payload = assessment();
  const records = [finding({ evidence: ["source reaches sink"] }), finding({ id: "2", category: "quality", findingType: "advice", ruleId: "SKY-Q301", message: "Full advice" })];
  const gate = { passed: false, reasons: ["One critical finding exceeds limit"], scope: "local_configured_policy", status: "evaluated", forced: false };
  const raw = { assessment: payload, gate, danger: [{ message: "raw finding", arbitrary_evidence: { retained: true } }] };
  store.setWorkspaceCLIFindings(records);
  store.setEngineMetadata(undefined, undefined, [], [], payload, raw);
  store.filter = { category: "dead_code" };
  const exported = JSON.parse(buildJson(store)).report;
  assert.deepEqual(exported.assessment, payload);
  assert.deepEqual(exported.raw_cli_report, raw);
  assert.deepEqual(exported.gate, gate);
  assert.equal(exported.findings.length, 2);
  assert.deepEqual(exported.findings.find(f => f.finding_type === "review").evidence, ["source reaches sink"]);
  assert.ok(!("score" in exported));
  assert.ok(!("legacy_score" in exported));
  const sarif = JSON.parse(buildSarif(store)).runs[0];
  assert.deepEqual(sarif.properties.assessment, payload);
  assert.deepEqual(sarif.properties.gate, gate);
  assert.equal(sarif.results.length, 2);
  assert.deepEqual(sarif.results.map(f => f.properties.finding_type), ["review", "advice"]);
  const md = buildMarkdown(store);
  assert.match(md, /CRITICAL · 1 unresolved finding/);
  assert.match(md, /FAIL · local configured policy · One critical finding exceeds limit/);
  assert.match(md, /Full advice/);
  assert.doesNotMatch(md, /A\+|Security Score|Legacy score/);
});

test("code health and architecture Advice evidence reaches dashboard and exports", () => {
  const { FindingsStore, SkylosDashboard, buildMarkdown, buildJson, buildSarif } = loadConsumers();
  const { normalizeReportCore } = require("../out/findingCore");
  const report = {
    code_health: [{ file: "app.py", line: 2, rule_id: "SKY-Q301", severity: "MEDIUM", finding_type: "advice", message: "Code health evidence", evidence: ["measured complexity"] }],
    architecture_metrics: { advisories: [{ signals: [{ file: "app.py", line: 3, rule_id: "SKY-C301", severity: "MEDIUM", finding_type: "advice", message: "Architecture signal evidence", evidence: ["measured coupling"] }] }] },
  };
  const rows = normalizeReportCore(report, { wsRoot: "/repo", deadCodeEnabled: true, showDeadParams: true, confidenceThreshold: 0 });
  const store = new FindingsStore();
  store.setWorkspaceCLIFindings(rows);
  const html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
  const markdown = buildMarkdown(store);
  for (const text of ["Code health evidence", "Architecture signal evidence"]) {
    assert.ok(html.includes(text));
    assert.ok(markdown.includes(text));
  }
  const exported = JSON.parse(buildSarif(store)).runs[0].results;
  assert.equal(exported.length, 2);
  assert.deepEqual(exported.map(row => row.message.text), ["Code health evidence", "Architecture signal evidence"]);
  const records = JSON.parse(buildJson(store)).report.findings;
  assert.deepEqual(records.map(row => row.evidence), [["measured complexity"], ["measured coupling"]]);
});

test("missing assessments render Unknown and label incoming historical grades explicitly", () => {
  const { FindingsStore, SkylosDashboard, buildMarkdown } = loadConsumers();
  const store = new FindingsStore();
  let html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
  assert.match(html, /Unknown · assessment unavailable/);
  assert.match(html, /Coverage: unknown/);
  assert.doesNotMatch(html, /A\+|100\/100/);
  store.setEngineMetadata({ overall: { letter: "A+", score: 100 } }, undefined, [], []);
  html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
  assert.match(html, /Legacy score: A\+ \(100\/100\)/);
  assert.match(html, /not a current risk assessment/);
  assert.match(buildMarkdown(store), /Legacy score: A\+ \(100\/100\)/);
});


test("updated editor accepts old CLI grades as Legacy and keeps missing coverage unknown", () => {
  const { FindingsStore, SkylosDashboard, buildMarkdown, buildJson } = loadConsumers();
  const legacy = { overall: { score: 100, letter: "A+" }, categories: {}, scanned_categories: ["security", "quality"] };
  const store = new FindingsStore();
  store.setWorkspaceCLIFindings([]);
  store.setEngineMetadata(legacy, { total_files: 1 });
  const html = new SkylosDashboard(store).getHtml({ cspSource: "vscode-webview://test" });
  const markdown = buildMarkdown(store);
  assert.match(html, /Legacy score: A\+ \(100\/100\)/);
  assert.match(html, /Coverage: unknown/);
  assert.doesNotMatch(html, /No risk findings in assessed checks|Security Score/);
  assert.match(markdown, /Legacy score: A\+ \(100\/100\)/);
  assert.match(markdown, /Unknown · assessment unavailable/);
  assert.deepEqual(JSON.parse(buildJson(store)).report.legacy_score, legacy);
  store.setWorkspaceCLIFindings([finding()]);
  assert.equal(riskSummary(store.assessment, store.getAllRawFindings()).status, "critical");
});
