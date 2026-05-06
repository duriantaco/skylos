const assert = require("node:assert/strict");
const test = require("node:test");

const { shouldWarnMissingLocalAI } = require("../out/configCore");

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
