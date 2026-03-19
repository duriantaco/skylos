import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Severity } from "./types";
import { getMaxProblems, getMaxProblemsPerFile, isShowDeadCodeInProblems } from "./config";

export class DiagnosticsManager {
  private cliCollection: vscode.DiagnosticCollection;
  private aiCollection: vscode.DiagnosticCollection;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {
    this.cliCollection = vscode.languages.createDiagnosticCollection("skylos");
    this.aiCollection = vscode.languages.createDiagnosticCollection("skylos-ai");

    this.disposables.push(
      this.cliCollection,
      this.aiCollection,
      store.onDidChange(() => this.refreshCLI()),
      store.onDidChangeAI(() => this.refreshAI()),
    );
  }

  private refreshCLI(): void {
    this.cliCollection.clear();
    const findings = this.store.getVisibleFindings(getMaxProblems(), {
      source: "cli",
      includeDeadCode: isShowDeadCodeInProblems(),
      maxPerFile: getMaxProblemsPerFile(),
    });
    this.publish(this.cliCollection, findings);
  }

  private refreshAI(): void {
    this.aiCollection.clear();
    const findings = this.store.getVisibleFindings(getMaxProblems(), {
      source: "ai",
      maxPerFile: getMaxProblemsPerFile(),
    });
    this.publish(this.aiCollection, findings);
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }

  private publish(collection: vscode.DiagnosticCollection, findings: SkylosFinding[]): void {
    const byFile = new Map<string, SkylosFinding[]>();
    for (const finding of findings) {
      const list = byFile.get(finding.file) ?? [];
      list.push(finding);
      byFile.set(finding.file, list);
    }

    for (const [file, items] of byFile) {
      const uri = vscode.Uri.file(file);
      collection.set(uri, items.map(toDiagnostic));
    }
  }
}

function toDiagnostic(f: SkylosFinding): vscode.Diagnostic {
  const line = Math.max(0, f.line - 1);
  const col = Math.max(0, f.col);
  const start = new vscode.Position(line, col);
  const range = new vscode.Range(start, start);
  const severity = mapSeverity(f.severity);
  const prefix = f.source === "ai" ? "[AI] " : f.ruleId !== "SKYLOS" ? `[${f.ruleId}] ` : "";
  const diag = new vscode.Diagnostic(range, `${prefix}${f.message}`, severity);
  diag.source = f.source === "ai" ? "skylos-ai" : "skylos";
  diag.code = f.ruleId;
  return diag;
}

function mapSeverity(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;

    case "MEDIUM":
    case "WARN":
      return vscode.DiagnosticSeverity.Warning;

    case "LOW":
      return vscode.DiagnosticSeverity.Hint;
      
    case "INFO":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}
