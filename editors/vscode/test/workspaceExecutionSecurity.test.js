const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

function readPackageJson() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
}

function readConfigSource() {
  return fs.readFileSync(path.join(__dirname, "..", "src", "config.ts"), "utf8");
}

test("executable configuration is not workspace-scoped", () => {
  const pkg = readPackageJson();
  const pathConfig = pkg.contributes.configuration.properties["skylos.path"];

  assert.equal(pathConfig.scope, "machine");
});

test("scan-on-open is opt-in and not workspace-scoped", () => {
  const pkg = readPackageJson();
  const scanOnOpenConfig = pkg.contributes.configuration.properties["skylos.scanOnOpen"];

  assert.equal(scanOnOpenConfig.scope, "machine");
  assert.equal(scanOnOpenConfig.default, false);
});

test("workspace trust limits automatic scan execution", () => {
  const pkg = readPackageJson();
  const trust = pkg.capabilities.untrustedWorkspaces;

  assert.equal(trust.supported, "limited");
  assert.ok(trust.restrictedConfigurations.includes("skylos.path"));
  assert.ok(trust.restrictedConfigurations.includes("skylos.runOnSave"));
  assert.ok(trust.restrictedConfigurations.includes("skylos.scanOnOpen"));
});

test("runtime ignores workspace executable settings", () => {
  const source = readConfigSource();

  assert.match(source, /inspect<string>\("path"\)/);
  assert.match(source, /inspect<boolean>\("scanOnOpen"\)/);
  assert.doesNotMatch(source, /get<string>\("path",\s*"skylos"\)/);
  assert.doesNotMatch(source, /get<boolean>\("scanOnOpen",\s*true\)/);
  assert.match(source, /vscode\.workspace\.isTrusted/);
});
