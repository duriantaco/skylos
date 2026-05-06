const assert = require("node:assert/strict");
const test = require("node:test");

const { normalizeAutomationLine } = require("../out/automationCore");

test("normalizeAutomationLine accepts numeric and string line values", () => {
  assert.equal(normalizeAutomationLine(7), 7);
  assert.equal(normalizeAutomationLine("8"), 8);
  assert.equal(normalizeAutomationLine(3.8), 3);
});

test("normalizeAutomationLine falls back to line 1 for malformed values", () => {
  assert.equal(normalizeAutomationLine(undefined), 1);
  assert.equal(normalizeAutomationLine("not-a-line"), 1);
  assert.equal(normalizeAutomationLine(0), 1);
  assert.equal(normalizeAutomationLine(-4), 1);
});
