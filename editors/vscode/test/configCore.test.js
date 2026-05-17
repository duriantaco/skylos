const assert = require("node:assert/strict");
const test = require("node:test");

const {
  DEFAULT_OPENAI_BASE_URL,
  resolveTrustedExecutablePath,
  shouldRunWorkspaceAutomation,
  shouldWarnMissingLocalAI,
  trustedAIProvider,
  trustedConfigString,
  trustedLocalBaseUrl,
  trustedOpenAIBaseUrl,
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

test("trustedConfigString ignores workspace values", () => {
  assert.equal(trustedConfigString({
    defaultValue: "default",
    globalValue: "user-value",
    workspaceValue: "workspace-value",
    workspaceFolderValue: "folder-value",
  }), "user-value");

  assert.equal(trustedConfigString({
    defaultValue: "default",
    workspaceValue: "workspace-value",
  }), "default");
});

test("trustedAIProvider ignores workspace provider overrides", () => {
  assert.equal(trustedAIProvider({
    defaultValue: "openai",
    workspaceValue: "local",
  }), "openai");
  assert.equal(trustedAIProvider({
    defaultValue: "openai",
    globalValue: "local",
  }), "local");
});

test("trustedOpenAIBaseUrl only allows the official OpenAI API host", () => {
  assert.equal(trustedOpenAIBaseUrl({
    defaultValue: "https://api.openai.com",
    workspaceValue: "https://attacker.example",
  }), DEFAULT_OPENAI_BASE_URL);

  assert.equal(trustedOpenAIBaseUrl({
    defaultValue: "https://api.openai.com",
    globalValue: "https://attacker.example",
  }), DEFAULT_OPENAI_BASE_URL);

  assert.equal(trustedOpenAIBaseUrl({
    defaultValue: "https://api.openai.com",
    globalValue: "https://api.openai.com/v1",
  }), DEFAULT_OPENAI_BASE_URL);
});

test("trustedLocalBaseUrl only accepts user-configured loopback endpoints", () => {
  assert.equal(trustedLocalBaseUrl({
    defaultValue: "",
    workspaceValue: "https://attacker.example",
  }), "");

  assert.equal(trustedLocalBaseUrl({
    defaultValue: "",
    globalValue: "https://attacker.example",
  }), "");

  assert.equal(trustedLocalBaseUrl({
    defaultValue: "",
    globalValue: "http://localhost:11434/api",
  }), "http://localhost:11434");

  assert.equal(trustedLocalBaseUrl({
    defaultValue: "",
    globalValue: "http://127.0.0.1:1234",
  }), "http://127.0.0.1:1234");
});
