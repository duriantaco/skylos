const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

function readHoverSource() {
  return fs.readFileSync(path.join(__dirname, "..", "src", "hover.ts"), "utf8");
}

test("hover markdown does not trust repo-controlled finding text", () => {
  const source = readHoverSource();

  assert.doesNotMatch(source, /md\.isTrusted\s*=\s*true/);
  assert.match(source, /md\.isTrusted\s*=\s*false/);
  assert.match(source, /md\.supportHtml\s*=\s*false/);
  assert.doesNotMatch(source, /appendMarkdown\(`\$\{f\.message\}/);
  assert.doesNotMatch(source, /appendMarkdown\([^)]*f\.message/);
  assert.match(source, /md\.appendText\(f\.message\)/);
});
