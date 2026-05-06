const assert = require("node:assert/strict");
const test = require("node:test");

const {
  buildScanArgs,
  buildScanCommand,
  buildScanErrorMessage,
  SkylosScanError,
} = require("../out/scanCore");

test("buildScanArgs includes enabled features, excludes, confidence, and diff base", () => {
  const args = buildScanArgs({
    target: "/repo",
    confidence: 80,
    excludeFolders: [".venv", "node_modules"],
    enableSecrets: true,
    enableDanger: false,
    enableQuality: true,
    diffBase: "origin/main",
  });

  assert.deepEqual(args, [
    "/repo",
    "--json",
    "-c",
    "80",
    "--exclude-folder",
    ".venv",
    "--exclude-folder",
    "node_modules",
    "--secrets",
    "--quality",
    "--diff-base",
    "origin/main",
  ]);
});

test("buildScanCommand shell-quotes display command without changing args", () => {
  const command = buildScanCommand("/path with spaces/skylos", {
    target: "/repo with spaces",
    confidence: 75,
    excludeFolders: [],
    enableSecrets: false,
    enableDanger: true,
    enableQuality: false,
  });

  assert.equal(command.args[0], "/repo with spaces");
  assert.match(command.display, /^'\/path with spaces\/skylos' '\/repo with spaces'/);
});

test("buildScanErrorMessage gives actionable missing binary message", () => {
  const message = buildScanErrorMessage(new SkylosScanError("missing_binary", "spawn ENOENT"));
  assert.match(message, /executable was not found/);
});

