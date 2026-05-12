const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { createWebviewNonce, escapeHtml, webviewCsp } = require("../out/webviewSecurity");

const WEBVIEW_SOURCE_FILES = [
  "chatview.ts",
  "dashboard.ts",
  "detail.ts",
];

function readSource(fileName) {
  return fs.readFileSync(path.join(__dirname, "..", "src", fileName), "utf8");
}

test("createWebviewNonce returns CSP-safe random tokens", () => {
  const first = createWebviewNonce();
  const second = createWebviewNonce();

  assert.match(first, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(first, second);
});

test("webviewCsp restricts scripts to the generated nonce", () => {
  const csp = webviewCsp({ cspSource: "vscode-webview://extension-id" }, "abc123");

  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.match(csp, /script-src 'nonce-abc123'/);
  assert.doesNotMatch(csp, /script-src[^;]*'unsafe-inline'/);
  assert.match(csp, /connect-src 'none'/);
});

test("escapeHtml escapes text for generated webview HTML", () => {
  assert.equal(
    escapeHtml(`<img src=x onerror="alert('x')">`),
    "&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt;",
  );
});

test("script-enabled webviews use CSP nonces and no local resource roots", () => {
  for (const fileName of WEBVIEW_SOURCE_FILES) {
    const source = readSource(fileName);

    assert.match(source, /enableScripts:\s*true/, `${fileName} should explicitly enable scripts`);
    assert.match(source, /localResourceRoots:\s*\[\]/, `${fileName} should not expose local resources`);
    assert.match(source, /Content-Security-Policy/, `${fileName} should set a CSP meta tag`);
    assert.match(source, /webviewCsp\(webview,\s*nonce\)/, `${fileName} should use shared CSP generation`);
    assert.match(source, /<script nonce="\$\{nonce\}">/, `${fileName} should nonce its script block`);
  }
});

test("webview templates do not use inline event handlers or un-nonced scripts", () => {
  const combined = WEBVIEW_SOURCE_FILES.map(readSource).join("\n");

  assert.doesNotMatch(combined, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(combined, /javascript:/i);
  assert.doesNotMatch(combined, /<script>/i);
  assert.doesNotMatch(combined, /<script(?!\s+nonce=)/i);
});

test("dashboard escapes scan-originated strings before rendering HTML", () => {
  const source = readSource("dashboard.ts");

  assert.match(source, /escapeHtml\(g\.letter\)/);
  assert.match(source, /escapeHtml\(cat\)/);
  assert.match(source, /escapeHtml\(l\)/);
  assert.match(source, /escapeHtml\(v\.package\)/);
  assert.match(source, /escapeHtml\(v\.summary \?\? v\.vulnerability_id \?\? ""\)/);
  assert.match(source, /escapeHtml\(short\)/);
});

test("detail panel registers one message listener and uses current finding state", () => {
  const source = readSource("detail.ts");
  const listenerCount = source.match(/onDidReceiveMessage/g)?.length ?? 0;

  assert.equal(listenerCount, 1);
  assert.match(source, /currentFinding/);
  assert.match(source, /getDetailCommand\(msg\)/);
});

test("chat webview validates inbound messages before invoking extension actions", () => {
  const source = readSource("chatview.ts");

  assert.match(source, /isUserMessage\(msg\)/);
  assert.match(source, /isApplyFixMessage\(msg\)/);
  assert.match(source, /MAX_CHAT_TEXT_LENGTH/);
  assert.match(source, /MAX_FIX_CODE_LENGTH/);
});
