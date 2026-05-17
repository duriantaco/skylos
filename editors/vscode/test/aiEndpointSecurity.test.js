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

test("AI endpoint and key settings are not workspace-scoped", () => {
  const pkg = readPackageJson();
  const props = pkg.contributes.configuration.properties;

  for (const key of [
    "skylos.aiProvider",
    "skylos.enableRealtimeAI",
    "skylos.openaiBaseUrl",
    "skylos.openaiApiKey",
    "skylos.localBaseUrl",
    "skylos.anthropicApiKey",
  ]) {
    assert.equal(props[key].scope, "machine", `${key} should be machine-scoped`);
  }
});

test("Workspace Trust restricts AI endpoint and key settings", () => {
  const pkg = readPackageJson();
  const trust = pkg.capabilities.untrustedWorkspaces;

  assert.equal(trust.supported, "limited");
  for (const key of [
    "skylos.aiProvider",
    "skylos.enableRealtimeAI",
    "skylos.openaiBaseUrl",
    "skylos.openaiApiKey",
    "skylos.localBaseUrl",
    "skylos.anthropicApiKey",
  ]) {
    assert.ok(trust.restrictedConfigurations.includes(key), `${key} should be restricted`);
  }
});

test("runtime resolves AI endpoints and keys from trusted config only", () => {
  const source = readConfigSource();

  assert.match(source, /trustedOpenAIBaseUrl\(cfg\(\)\.inspect<string>\("openaiBaseUrl"\)\)/);
  assert.match(source, /trustedLocalBaseUrl\(cfg\(\)\.inspect<string>\("localBaseUrl"\)\)/);
  assert.match(source, /trustedConfigString\(cfg\(\)\.inspect<string>\("openaiApiKey"\)\)/);
  assert.match(source, /trustedConfigString\(cfg\(\)\.inspect<string>\("anthropicApiKey"\)\)/);
  assert.match(source, /return "local";/);
  assert.doesNotMatch(source, /cfg\(\)\.get<string>\("openaiBaseUrl"/);
  assert.doesNotMatch(source, /cfg\(\)\.get<string>\("localBaseUrl"/);
  assert.doesNotMatch(source, /cfg\(\)\.get<string>\("openaiApiKey"/);
});
