const assert = require("node:assert/strict");
const test = require("node:test");

const {
  buildVerifyArgs,
  buildVerifyCommandDisplay,
  buildVerifyManifest,
  normalizeVerifyIssues,
} = require("../out/verifyCore");

function request(overrides = {}) {
  return {
    bin: "skylos",
    workspaceRoot: "/repo",
    filePath: "/repo/src/app.py",
    code: "def handler():\n    return validate_token(token)\n",
    lineRange: "1:2",
    confidence: 75,
    ...overrides,
  };
}

test("buildVerifyArgs uses stdin verifier with no-fail", () => {
  assert.deepEqual(buildVerifyArgs(request()), [
    "verify",
    "/repo",
    "--stdin",
    "--no-fail",
    "--confidence",
    "75",
  ]);
});

test("buildVerifyManifest includes file code and optional range", () => {
  assert.deepEqual(buildVerifyManifest(request()), {
    path: "/repo",
    file: "/repo/src/app.py",
    code: "def handler():\n    return validate_token(token)\n",
    range: "1:2",
  });

  const withoutRange = buildVerifyManifest(request({ lineRange: undefined }));
  assert.equal(Object.hasOwn(withoutRange, "range"), false);
});

test("buildVerifyCommandDisplay quotes verifier args", () => {
  const display = buildVerifyCommandDisplay(request({ workspaceRoot: "/repo with space" }));

  assert.equal(display, "skylos verify '/repo with space' --stdin --no-fail --confidence 75");
});

test("normalizeVerifyIssues maps verifier findings to AI issues", () => {
  const issues = normalizeVerifyIssues({
    findings: [
      {
        rule_id: "SKY-L012",
        ai_likelihood: "high",
        severity: "MEDIUM",
        message: "validate_token is undefined",
        range: { start_line: 2 },
      },
      {
        rule_id: "SKY-L026",
        ai_likelihood: "medium",
        severity: "LOW",
        message: "Generated stub left behind",
        range: { start_line: 7 },
      },
    ],
  });

  assert.deepEqual(issues, [
    { line: 2, message: "validate_token is undefined", severity: "error" },
    { line: 7, message: "Generated stub left behind", severity: "warning" },
  ]);
});

test("normalizeVerifyIssues ignores malformed findings", () => {
  assert.deepEqual(normalizeVerifyIssues({}), []);
  assert.deepEqual(normalizeVerifyIssues({ findings: [{ range: { start_line: 3 } }] }), []);
});
