"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createWebviewNonce = createWebviewNonce;
exports.webviewCsp = webviewCsp;
exports.escapeHtml = escapeHtml;
exports.isRecord = isRecord;
const crypto_1 = require("crypto");
function createWebviewNonce() {
    return (0, crypto_1.randomBytes)(16)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}
function webviewCsp(webview, nonce) {
    return [
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        `img-src ${webview.cspSource} https: data:`,
        `font-src ${webview.cspSource}`,
        `style-src ${webview.cspSource} 'unsafe-inline'`,
        `script-src 'nonce-${nonce}'`,
        "connect-src 'none'",
    ].join("; ");
}
function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
function isRecord(value) {
    return typeof value === "object" && value !== null;
}
