const assert = require("node:assert/strict");
const test = require("node:test");

const {
  diagnosticSource,
  isCorroborated,
  matchesSourceFilter,
  mergeCorrelatedFindings,
  sourceSummary,
} = require("../out/provenanceCore");

function finding(overrides = {}) {
  return {
    id: overrides.id ?? "f",
    ruleId: "SKY-D216",
    category: "security",
    severity: "HIGH",
    message: "Possible SSRF",
    file: "/repo/app.py",
    line: 10,
    source: "cli",
    ...overrides,
  };
}

test("mergeCorrelatedFindings merges static and agent findings on the same rule location", () => {
  const merged = mergeCorrelatedFindings([
    finding({ id: "static", source: "cli", confidence: 80 }),
    finding({ id: "agent", source: "agent", severity: "CRITICAL", confidence: 95, reviewReason: "Hot path" }),
  ]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].id, "static");
  assert.equal(merged[0].source, "cli");
  assert.deepEqual(merged[0].sources, ["cli", "agent"]);
  assert.equal(merged[0].severity, "CRITICAL");
  assert.equal(merged[0].confidence, 95);
  assert.equal(merged[0].reviewReason, "Hot path");
  assert.equal(sourceSummary(merged[0]), "Static + Automation");
  assert.equal(diagnosticSource(merged[0]), "skylos static+automation");
  assert.equal(isCorroborated(merged[0]), true);
});

test("mergeCorrelatedFindings keeps unrelated sources as separate findings", () => {
  const merged = mergeCorrelatedFindings([
    finding({ id: "static", line: 10, source: "cli" }),
    finding({ id: "agent", line: 11, source: "agent" }),
  ]);

  assert.equal(merged.length, 2);
  assert.deepEqual(merged.map((item) => sourceSummary(item)).sort(), ["Automation", "Static"]);
});

test("mergeCorrelatedFindings does not confirm different findings on the same rule line", () => {
  const merged = mergeCorrelatedFindings([
    finding({ id: "static", source: "cli", message: "Possible SSRF in requests.get" }),
    finding({ id: "agent", source: "agent", message: "Possible SSRF in httpx.get" }),
  ]);

  assert.equal(merged.length, 2);
  assert.equal(merged.some(isCorroborated), false);
});

test("mergeCorrelatedFindings confirms same subject even when messages differ", () => {
  const merged = mergeCorrelatedFindings([
    finding({ id: "static", source: "cli", message: "Possible SSRF", sinkSymbol: "requests.get" }),
    finding({ id: "agent", source: "agent", message: "Network sink with tainted input", sinkSymbol: "requests.get" }),
  ]);

  assert.equal(merged.length, 1);
  assert.equal(sourceSummary(merged[0]), "Static + Automation");
});

test("matchesSourceFilter handles confirmed and secondary sources", () => {
  const confirmed = finding({ source: "cli", sources: ["cli", "agent"] });
  assert.equal(matchesSourceFilter(confirmed, "confirmed"), true);
  assert.equal(matchesSourceFilter(confirmed, "cli"), true);
  assert.equal(matchesSourceFilter(confirmed, "agent"), true);
  assert.equal(matchesSourceFilter(confirmed, "ai"), false);
});
