const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");

const {
  canonicalRuleId,
  isDeadCodeRule,
  makeFingerprint,
  normalizeReportCore,
} = require("../out/findingCore");

const wsRoot = path.join(path.sep, "repo");

test("normalizeReportCore maps dead code to canonical SKY-U rule ids with stable fingerprints", () => {
  const findings = normalizeReportCore({
    unused_imports: [
      { file: "src/app.py", line: 4, name: "os", confidence: 92 },
    ],
  }, {
    wsRoot,
    deadCodeEnabled: true,
    showDeadParams: false,
    confidenceThreshold: 80,
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "SKY-U002");
  assert.equal(findings[0].legacyRuleId, "DEAD-IMPORT");
  assert.equal(findings[0].file, path.join(wsRoot, "src/app.py"));
  assert.equal(findings[0].relativePath, "src/app.py");
  assert.match(findings[0].fingerprint, /^vsce:[a-f0-9]{20}$/);
});

test("normalizeReportCore filters hidden dead params and low-confidence dead code", () => {
  const findings = normalizeReportCore({
    unused_parameters: [
      { file: "src/app.py", line: 10, name: "request", confidence: 99 },
    ],
    unused_functions: [
      { file: "src/app.py", line: 20, name: "helper", confidence: 20 },
    ],
  }, {
    wsRoot,
    deadCodeEnabled: true,
    showDeadParams: false,
    confidenceThreshold: 80,
  });

  assert.equal(findings.length, 0);
});

test("normalizeReportCore maps security, secrets, and quality findings", () => {
  const findings = normalizeReportCore({
    danger: [
      { file: "src/app.py", line: 2, rule_id: "SKY-D203", severity: "critical", message: "os.system" },
    ],
    secrets: [
      { file: "src/keys.py", line: 1, rule_id: "SKY-S101", severity: "HIGH", message: "secret" },
    ],
    quality: [
      { file: "src/q.py", line: 5, rule_id: "SKY-Q301", severity: "warn", message: "complex" },
    ],
  }, {
    wsRoot,
    deadCodeEnabled: true,
    showDeadParams: false,
    confidenceThreshold: 80,
  });

  assert.deepEqual(findings.map((finding) => finding.category), ["secrets", "security", "quality"]);
  assert.deepEqual(findings.map((finding) => finding.severity), ["HIGH", "CRITICAL", "WARN"]);
});

test("normalizeReportCore preserves evidence metadata for review details", () => {
  const findings = normalizeReportCore({
    danger: [
      {
        file: "src/app.py",
        line: 12,
        rule_id: "SKY-D216",
        severity: "critical",
        message: "Possible SSRF",
        snippet: "requests.get(url)",
        explanation: "User-controlled URL reaches outbound request.",
        suggestion: "Validate URL scheme and host before fetching.",
        evidence: ["url parameter flows into requests.get"],
        trace: [{ file: "src/app.py", line: 10, message: "url from request" }],
        source_symbol: "url",
        sink_symbol: "requests.get",
        metadata: {
          ci_blocking: true,
          review_reason: "Network sink with tainted input",
          security_evidence: { contract_id: "route-auth", missing_guards: ["auth"] },
        },
      },
    ],
  }, {
    wsRoot,
    deadCodeEnabled: true,
    showDeadParams: false,
    confidenceThreshold: 80,
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].snippet, "requests.get(url)");
  assert.equal(findings[0].suggestion, "Validate URL scheme and host before fetching.");
  assert.deepEqual(findings[0].evidence, ["url parameter flows into requests.get"]);
  assert.equal(findings[0].trace.length, 1);
  assert.equal(findings[0].trace[0].file, "src/app.py");
  assert.equal(findings[0].trace[0].line, 10);
  assert.equal(findings[0].trace[0].message, "url from request");
  assert.equal(findings[0].sourceSymbol, "url");
  assert.equal(findings[0].sinkSymbol, "requests.get");
  assert.equal(findings[0].ciBlocking, true);
  assert.equal(findings[0].reviewReason, "Network sink with tainted input");
  assert.equal(findings[0].securityEvidence.contract_id, "route-auth");
});

test("canonicalRuleId preserves current ids and aliases legacy dead-code ids", () => {
  assert.equal(canonicalRuleId("DEAD-FUNC"), "SKY-U001");
  assert.equal(canonicalRuleId("SKY-D203"), "SKY-D203");
  assert.equal(isDeadCodeRule("DEAD-IMPORT"), true);
});

test("makeFingerprint is deterministic", () => {
  const input = {
    ruleId: "SKY-D203",
    relativePath: "src/app.py",
    line: 10,
    message: "danger",
  };
  assert.equal(makeFingerprint(input), makeFingerprint(input));
});
