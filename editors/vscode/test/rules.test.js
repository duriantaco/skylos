const assert = require("node:assert/strict");
const test = require("node:test");

const { getRuleMeta } = require("../out/rules");

const TYPESCRIPT_SECURITY_RULES = {
  "SKY-D280": {
    name: "Next.js mutating API route missing authentication",
    severity: "HIGH",
    category: "security",
    description:
      "A mutating Next.js API route can perform protected side effects without a proven route-local authentication guard.",
    owasp: "A01:2021",
    fix: "Authenticate the route and enforce the result before any protected side effect.",
    language: "typescript",
  },
  "SKY-D281": {
    name: "Next.js server action SQL injection",
    severity: "CRITICAL",
    category: "security",
    description:
      "Request-controlled data reaches SQL constructed in a Next.js server action.",
    owasp: "A03:2021",
    cwe: "CWE-89",
    fix: "Use parameterized queries instead of building SQL with string interpolation.",
    language: "typescript",
  },
  "SKY-D282": {
    name: "Webhook signature verification issue",
    severity: "HIGH",
    category: "security",
    description:
      "A webhook handler can perform event side effects before provider signature verification is proven.",
    cwe: "CWE-347",
    fix: "Verify the exact raw request body and provider signature before any event side effect.",
    language: "typescript",
  },
  "SKY-S102": {
    name: "Client-side secret exposure",
    severity: "HIGH",
    category: "secrets",
    description:
      "A hardcoded secret or sensitive-looking environment value is exposed through client-side code or a publicly served asset.",
    cwe: "CWE-200",
    fix: "Move confirmed secrets to server-only code and rotate them; expose only non-sensitive public configuration.",
    language: "typescript",
  },
};

test("TypeScript security rule metadata stays available in the editor", () => {
  for (const [ruleId, expected] of Object.entries(TYPESCRIPT_SECURITY_RULES)) {
    assert.deepEqual(getRuleMeta(ruleId), expected, ruleId);
  }
});
