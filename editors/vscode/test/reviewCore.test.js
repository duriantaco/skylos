const assert = require("node:assert/strict");
const test = require("node:test");

const {
  ciImpact,
  evidenceLines,
  fixPlan,
  priorityReasons,
  sortReviewQueue,
} = require("../out/reviewCore");

function finding(overrides = {}) {
  return {
    id: "f",
    fingerprint: "fp",
    ruleId: "SKY-Q001",
    category: "quality",
    severity: "INFO",
    message: "Issue",
    file: "/repo/src/app.py",
    relativePath: "src/app.py",
    workspaceRoot: "/repo",
    line: 1,
    col: 0,
    source: "cli",
    ...overrides,
  };
}

test("sortReviewQueue prioritizes active-file, new, CI-blocking security findings", () => {
  const lowCurrent = finding({ id: "current", file: "/repo/src/current.py", severity: "LOW" });
  const blocker = finding({
    id: "blocker",
    category: "security",
    severity: "CRITICAL",
    file: "/repo/src/api.py",
    isNew: true,
    ciBlocking: true,
  });
  const ordered = sortReviewQueue([lowCurrent, blocker], { currentFile: "/repo/src/current.py", diffBase: "origin/main" });

  assert.equal(ordered[0].id, "blocker");
  assert.equal(ordered[1].id, "current");

  const reasons = priorityReasons(blocker, { diffBase: "origin/main" });
  assert.ok(reasons.includes("Marked as CI-blocking by Skylos"));
  assert.ok(reasons.includes("New against origin/main"));
  assert.ok(reasons.includes("critical severity"));
});

test("ciImpact reports likely blockers and attention-only queues separately", () => {
  const impact = ciImpact([
    finding({ category: "secrets", severity: "HIGH" }),
    finding({ category: "quality", severity: "MEDIUM" }),
  ], { diffBase: "origin/main" });

  assert.equal(impact.status, "blocking");
  assert.equal(impact.blockerCount, 1);
  assert.match(impact.headline, /Likely CI block/);

  const attention = ciImpact([
    finding({ category: "quality", severity: "MEDIUM" }),
  ]);
  assert.equal(attention.status, "attention");
  assert.equal(attention.blockerCount, 0);
  assert.equal(attention.attentionCount, 1);
});

test("evidenceLines summarizes trace and security contract metadata", () => {
  const lines = evidenceLines(finding({
    explanation: "User input reaches a network sink.",
    trace: [{ file: "src/app.py", line: 42, message: "requests.get(url)" }],
    sourceSymbol: "url",
    sinkSymbol: "requests.get",
    securityEvidence: { contract_id: "route-auth", handler: "fetch", missing_guards: ["auth", "scope"] },
  }));

  assert.ok(lines.includes("User input reaches a network sink."));
  assert.ok(lines.includes("Data path: source url -> sink requests.get"));
  assert.ok(lines.includes("src/app.py:42 - requests.get(url)"));
  assert.ok(lines.includes("Security contract: route-auth"));
  assert.ok(lines.includes("Missing guards: auth, scope"));
});

test("fixPlan prefers deterministic patches before AI or manual guidance", () => {
  assert.equal(fixPlan(finding({ fixPatch: "--- a\n+++ b" })).mode, "engine");
  assert.equal(fixPlan(finding({ suggestion: "Use a parameterized query." })).mode, "ai");
  assert.equal(fixPlan(finding({ category: "security", severity: "HIGH" })).mode, "manual");
});
