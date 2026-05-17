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

test("workspace trust limits automatic scan execution", () => {
  const pkg = readPackageJson();
  const trust = pkg.capabilities.untrustedWorkspaces;

  assert.equal(trust.supported, "limited");
  assert.match(trust.description, /command-triggered workspace execution/);
  assert.ok(trust.restrictedConfigurations.includes("skylos.path"));
  assert.ok(trust.restrictedConfigurations.includes("skylos.runOnSave"));
  assert.ok(trust.restrictedConfigurations.includes("skylos.scanOnOpen"));
});

test("runtime ignores workspace executable settings", () => {
  const source = readConfigSource();

  assert.match(source, /inspect<string>\("path"\)/);
  assert.doesNotMatch(source, /get<string>\("path",\s*"skylos"\)/);
  assert.match(source, /vscode\.workspace\.isTrusted/);
});

test("dead-code preview command is gated by workspace trust", () => {
  const pkg = readPackageJson();
  const command = pkg.contributes.commands.find((entry) => entry.command === "skylos.fixDeadCode");
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "extension.ts"), "utf8");
  const commandCenter = fs.readFileSync(path.join(__dirname, "..", "src", "commandcenter.ts"), "utf8");

  assert.equal(command.enablement, "isWorkspaceTrusted");
  assert.match(source, /Skylos: Trust this workspace before previewing dead code removal\./);
  assert.match(commandCenter, /if \(vscode\.workspace\.isTrusted\) \{\s*nodes\.push\(new InfoNode\("Preview dead code removal"/);

  const guardIndex = source.indexOf("Skylos: Trust this workspace before previewing dead code removal.");
  const spawnIndex = source.indexOf("spawnProc(skylosBin");
  assert.ok(guardIndex >= 0);
  assert.ok(spawnIndex > guardIndex);
});
