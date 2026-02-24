import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import { getRuleMeta } from "./rules";
import { getDocumentFilters } from "./types";


export class SkylosHoverProvider implements vscode.HoverProvider {
  constructor(private store: FindingsStore) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const findings = this.store.getFindingsForFile(document.uri.fsPath);
    const lineFindings = findings.filter((f) => Math.max(0, f.line - 1) === position.line);

    if (lineFindings.length === 0) 
      return undefined;

    const parts: vscode.MarkdownString[] = [];

    for (const f of lineFindings) {
      const md = new vscode.MarkdownString();
      md.supportHtml = true;
      md.isTrusted = true;

      const sevEmoji = getSeverityEmoji(f.severity);
      const meta = getRuleMeta(f.ruleId);
      const ruleName = meta?.name ?? f.ruleId;

      md.appendMarkdown(`### ${sevEmoji} ${f.ruleId} — ${ruleName}\n\n`);
      md.appendMarkdown(`**Severity:** \`${f.severity}\`\n\n`);
      md.appendMarkdown(`${f.message}\n\n`);

      if (meta?.description) {
        md.appendMarkdown(`*${meta.description}*\n\n`);
      }

      if (f.confidence !== undefined) {
        md.appendMarkdown(`**Confidence:** ${f.confidence}%\n\n`);
      }

      const refs: string[] = [];
      if (meta?.owasp) refs.push(`OWASP ${meta.owasp}`);
      if (meta?.cwe) refs.push(meta.cwe);
      if (meta?.pciDss) refs.push(`PCI DSS ${meta.pciDss}`);
      if (refs.length > 0) {
        md.appendMarkdown(`**References:** ${refs.join(" | ")}\n\n`);
      }

      if (meta?.fix) {
        md.appendMarkdown(`**Fix:** ${meta.fix}\n\n`);
      }

      md.appendMarkdown("---\n");
      parts.push(md);
    }

    return new vscode.Hover(parts);
  }

  register(): vscode.Disposable {
    return vscode.languages.registerHoverProvider(getDocumentFilters(), this);
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL": 
      return "\u{1F6A8}";
    case "HIGH": 
      return "\u{1F534}";
    case "MEDIUM": 
      return "\u{1F7E1}";
    case "WARN": 
      return "\u{1F7E1}";
    case "LOW": 
      return "\u{1F535}";
    default: 
      return "\u{2139}\u{FE0F}";
  }
}
