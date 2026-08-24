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

const TYPESCRIPT_TYPE_SAFETY_RULES = {
  "SKY-T103": {
    name: "Suspicious chained type assertion",
    severity: "MEDIUM",
    category: "quality",
    description:
      "A chained assertion uses a broad bridge type to force a value into a precise type.",
    cwe: "CWE-704",
    fix: "Validate or narrow the value instead of casting through any, unknown, object, or {}.",
    language: "typescript",
  },
  "SKY-T104": {
    name: "TypeScript compiler suppression directive",
    severity: "MEDIUM",
    category: "quality",
    description:
      "An effective @ts-ignore hides one line; file-wide @ts-nocheck is reported as HIGH.",
    cwe: "CWE-710",
    fix: "Fix the type error, or use @ts-expect-error with a specific reason for a narrow exception.",
    language: "typescript",
  },
  "SKY-T105": {
    name: "Unvalidated JSON type assertion",
    severity: "MEDIUM",
    category: "quality",
    description: "Unvalidated JSON data is asserted directly as a domain type.",
    cwe: "CWE-704",
    fix: "Validate or parse the JSON value at runtime before using the domain type.",
    language: "typescript",
  },
  "SKY-T106": {
    name: "Unsafe exported API type",
    severity: "MEDIUM",
    category: "quality",
    description:
      "An exported API exposes exact any, Record<string, any>, or an any-valued index signature.",
    cwe: "CWE-704",
    fix: "Use a precise type or unknown with runtime validation.",
    language: "typescript",
  },
};

const GENERATED_CODE_QUALITY_RULES = {
  "SKY-L007": {
    name: "Empty error handler",
    severity: "MEDIUM",
    category: "quality",
    description: "An empty error handler silently discards an error.",
    cwe: "CWE-391",
    fix: "Handle or report the error, or document why ignoring it is safe.",
    language: "python, typescript, javascript",
  },
  "SKY-L026": {
    name: "Unfinished code or placeholder default",
    severity: "MEDIUM",
    category: "quality",
    description:
      "A function body or default value is still an unfinished placeholder.",
    cwe: "CWE-1164",
    fix: "Finish the implementation or replace the placeholder with a real value.",
    language: "python, typescript, javascript",
  },
  "SKY-L034": {
    name: "Repeated mutable alias",
    severity: "MEDIUM",
    category: "quality",
    description:
      "Sequence multiplication reuses mutable elements by reference across repetitions.",
    cwe: "CWE-665",
    fix: "Use a comprehension to create one independent value per slot.",
    language: "python",
  },
  "SKY-L035": {
    name: "Blanket ESLint disable",
    severity: "HIGH",
    category: "quality",
    description:
      "A leading bare eslint-disable comment turns off every ESLint rule for the file.",
    cwe: "CWE-710",
    fix: "Name only the needed rule and keep the suppression narrow.",
    language: "typescript, javascript",
  },
  "SKY-Q405": {
    name: "Async Promise executor",
    severity: "HIGH",
    category: "quality",
    description:
      "The Promise constructor ignores the async result returned by its executor.",
    cwe: "CWE-755",
    fix: "Move async work outside the Promise constructor.",
    language: "typescript, javascript",
  },
  "SKY-Q406": {
    name: "Async Array.forEach callback",
    severity: "HIGH",
    category: "quality",
    description: "Built-in Array.forEach does not await an async callback.",
    cwe: "CWE-252",
    fix: "Use for...of or await Promise.all(array.map(...)).",
    language: "typescript, javascript",
  },
  "SKY-Q407": {
    name: "Discarded async Array.map result",
    severity: "HIGH",
    category: "quality",
    description: "The promises returned by Array.map(async ...) are discarded.",
    cwe: "CWE-252",
    fix: "Await Promise.all(...) or return the mapped promises.",
    language: "typescript, javascript",
  },
};

test("TypeScript security rule metadata stays available in the editor", () => {
  for (const [ruleId, expected] of Object.entries(TYPESCRIPT_SECURITY_RULES)) {
    assert.deepEqual(getRuleMeta(ruleId), expected, ruleId);
  }
});

test("TypeScript type-safety rule metadata stays available in the editor", () => {
  for (const [ruleId, expected] of Object.entries(TYPESCRIPT_TYPE_SAFETY_RULES)) {
    assert.deepEqual(getRuleMeta(ruleId), expected, ruleId);
  }
});

test("generated-code quality rule metadata stays available in the editor", () => {
  for (const [ruleId, expected] of Object.entries(GENERATED_CODE_QUALITY_RULES)) {
    assert.deepEqual(getRuleMeta(ruleId), expected, ruleId);
  }
});
