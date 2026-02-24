import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Severity } from "./types";

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
    const files = this.store.getFilesWithFindings();
    for (const file of files) {
      const findings = this.store.getCLIFindingsForFile(file);
      if (findings.length === 0) 
        continue;
      const uri = vscode.Uri.file(file);
      this.cliCollection.set(uri, findings.map(toDiagnostic));
    }
  }

  private refreshAI(): void {
    this.aiCollection.clear();
    const files = this.store.getFilesWithFindings();
    for (const file of files) {
      const findings = this.store.getAIFindingsForFile(file);
      if (findings.length === 0) 
        continue;
      const uri = vscode.Uri.file(file);
      this.aiCollection.set(uri, findings.map(toDiagnostic));
    }
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
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
