import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import type { SkylosFinding, Severity } from "./types";
import { getMaxProblems, getMaxProblemsPerFile, isShowDeadCodeInProblems } from "./config";
import { getDiagnosticRange } from "./diagnosticCore";
import { diagnosticSource, provenanceLabel } from "./provenanceCore";

export class DiagnosticsManager {
  private collection: vscode.DiagnosticCollection;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {
    this.collection = vscode.languages.createDiagnosticCollection("skylos");

    this.disposables.push(
      this.collection,
      store.onDidChange(() => this.refresh()),
      store.onDidChangeAI(() => this.refresh()),
    );
  }

  private refresh(): void {
    this.collection.clear();
    const findings = this.store.getVisibleFindings(getMaxProblems(), {
      includeDeadCode: isShowDeadCodeInProblems(),
      maxPerFile: getMaxProblemsPerFile(),
    });
    this.publish(this.collection, findings);
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
  const rangeFields = getDiagnosticRange(f);
  const range = new vscode.Range(
    rangeFields.startLine,
    rangeFields.startCol,
    rangeFields.endLine,
    rangeFields.endCol,
  );
  const severity = mapSeverity(f.severity);
  const provenance = provenanceLabel(f);
  const prefix = f.ruleId !== "SKYLOS" ? `[${provenance}] [${f.ruleId}] ` : `[${provenance}] `;
  const diag = new vscode.Diagnostic(range, `${prefix}${f.message}`, severity);
  diag.source = diagnosticSource(f);
  diag.code = f.ruleUrl
    ? { value: f.ruleId, target: vscode.Uri.parse(f.ruleUrl) }
    : f.ruleId;
  diag.relatedInformation = relatedInformation(f);
  return diag;
}

function relatedInformation(f: SkylosFinding): vscode.DiagnosticRelatedInformation[] | undefined {
  const related: vscode.DiagnosticRelatedInformation[] = [];
  for (const step of f.trace ?? []) {
    if (!step.file) continue;
    const line = Math.max(0, (step.line ?? 1) - 1);
    related.push(new vscode.DiagnosticRelatedInformation(
      new vscode.Location(vscode.Uri.file(step.file), new vscode.Position(line, 0)),
      step.message ?? step.label ?? step.symbol ?? "Related Skylos evidence",
    ));
  }
  return related.length > 0 ? related : undefined;
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
