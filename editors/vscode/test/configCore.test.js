const assert = require("node:assert/strict");
const test = require("node:test");

const {
  resolveTrustedExecutablePath,
  shouldRunWorkspaceAutomation,
  shouldWarnMissingLocalAI,
} = require("../out/configCore");

test("shouldWarnMissingLocalAI only warns for enabled local AI without base URL", () => {
  assert.equal(shouldWarnMissingLocalAI({
    realtimeAIEnabled: true,
    provider: "local",
    localBaseUrl: "",
  }), true);
  assert.equal(shouldWarnMissingLocalAI({
    realtimeAIEnabled: true,
    provider: "local",
    localBaseUrl: "http://localhost:11434",
  }), false);
  assert.equal(shouldWarnMissingLocalAI({
    realtimeAIEnabled: false,
    provider: "local",
    localBaseUrl: "",
  }), false);
  assert.equal(shouldWarnMissingLocalAI({
    realtimeAIEnabled: true,
    provider: "openai",
    localBaseUrl: "",
  }), false);
});

test("resolveTrustedExecutablePath ignores workspace executable values", () => {
  assert.equal(resolveTrustedExecutablePath({
    defaultValue: "skylos",
    globalValue: "/usr/local/bin/skylos",
    workspaceValue: "./malicious-tool",
    workspaceFolderValue: "./folder-tool",
  }), "/usr/local/bin/skylos");

  assert.equal(resolveTrustedExecutablePath({
    defaultValue: "skylos",
    workspaceValue: "./malicious-tool",
  }), "skylos");
});

test("shouldRunWorkspaceAutomation requires workspace trust", () => {
  assert.equal(shouldRunWorkspaceAutomation(true, true), true);
  assert.equal(shouldRunWorkspaceAutomation(false, true), false);
  assert.equal(shouldRunWorkspaceAutomation(true, false), false);
});
