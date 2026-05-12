import { randomBytes } from "crypto";
import type * as vscode from "vscode";

export function createWebviewNonce(): string {
  return randomBytes(16)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function webviewCsp(webview: vscode.Webview, nonce: string): string {
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

export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
