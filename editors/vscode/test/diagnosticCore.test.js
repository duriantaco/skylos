const assert = require("node:assert/strict");
const test = require("node:test");

const { getDiagnosticRange, severityRank } = require("../out/diagnosticCore");

test("getDiagnosticRange converts one-based line to non-zero VS Code range", () => {
  assert.deepEqual(getDiagnosticRange({ line: 7, col: 0 }), {
    startLine: 6,
    startCol: 0,
    endLine: 6,
    endCol: 1,
  });
});

test("getDiagnosticRange respects explicit end locations", () => {
  assert.deepEqual(getDiagnosticRange({ line: 3, col: 2, endLine: 5, endCol: 8 }), {
    startLine: 2,
    startCol: 2,
    endLine: 4,
    endCol: 8,
  });
});

test("severityRank orders critical above informational findings", () => {
  assert.equal(severityRank("CRITICAL") > severityRank("INFO"), true);
  assert.equal(severityRank("WARN"), severityRank("MEDIUM"));
});

