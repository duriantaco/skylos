import * as vscode from "vscode";
import type { SkylosFinding, CLIGrade, AnalysisSummary, CircularDependency, DependencyVulnerability } from "./types";


export class FindingsStore {
  private cliFindingsByFile = new Map<string, SkylosFinding[]>();
  private aiFindingsByFile = new Map<string, SkylosFinding[]>();

  private _grade: CLIGrade | undefined;
  private _summary: AnalysisSummary | undefined;
  private _circularDeps: CircularDependency[] = [];
  private _depVulns: DependencyVulnerability[] = [];
  private _deltaMode = false;

  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  private _onDidChangeAI = new vscode.EventEmitter<void>();
  readonly onDidChangeAI = this._onDidChangeAI.event;

  setCLIFindings(findings: SkylosFinding[]): void {
    this.cliFindingsByFile.clear();
    for (const f of findings) {
      const list = this.cliFindingsByFile.get(f.file) ?? [];
      list.push(f);
      this.cliFindingsByFile.set(f.file, list);
    }
    this._onDidChange.fire();
  }

  setEngineMetadata(
    grade?: CLIGrade,
    summary?: AnalysisSummary,
    circularDeps?: CircularDependency[],
    depVulns?: DependencyVulnerability[],
  ): void {
    this._grade = grade;
    this._summary = summary;
    this._circularDeps = circularDeps ?? [];
    this._depVulns = depVulns ?? [];
  }

  get grade(): CLIGrade | undefined { return this._grade; }
  get summary(): AnalysisSummary | undefined { return this._summary; }
  get circularDeps(): CircularDependency[] { return this._circularDeps; }
  get depVulns(): DependencyVulnerability[] { return this._depVulns; }

  get deltaMode(): boolean { return this._deltaMode; }
  set deltaMode(v: boolean) { this._deltaMode = v; }

  setAIFindings(filePath: string, findings: SkylosFinding[]): void {
    if (findings.length === 0) {
      this.aiFindingsByFile.delete(filePath);
    } else {
      this.aiFindingsByFile.set(filePath, findings);
    }
    this._onDidChangeAI.fire();
  }

  getFindingsForFile(filePath: string): SkylosFinding[] {
    const cli = this.cliFindingsByFile.get(filePath) ?? [];
    const ai = this.aiFindingsByFile.get(filePath) ?? [];
    return [...cli, ...ai];
  }

  getCLIFindingsForFile(filePath: string): SkylosFinding[] {
    return this.cliFindingsByFile.get(filePath) ?? [];
  }

  getAIFindingsForFile(filePath: string): SkylosFinding[] {
    return this.aiFindingsByFile.get(filePath) ?? [];
  }

  getAllFindings(): SkylosFinding[] {
    const all: SkylosFinding[] = [];
    for (const list of this.cliFindingsByFile.values()) all.push(...list);
    for (const list of this.aiFindingsByFile.values()) all.push(...list);
    return all;
  }

  getFilesWithFindings(): string[] {
    const files = new Set<string>();
    for (const k of this.cliFindingsByFile.keys()) files.add(k);
    for (const k of this.aiFindingsByFile.keys()) files.add(k);
    return [...files].sort();
  }

  countBySeverity(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of this.getAllFindings()) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  }

  countByCategory(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of this.getAllFindings()) {
      counts[f.category] = (counts[f.category] ?? 0) + 1;
    }
    return counts;
  }

  removeFindingAtLine(filePath: string, line: number): void {
    const cli = this.cliFindingsByFile.get(filePath);
    if (cli) {
      const filtered = cli.filter((f) => f.line !== line);
      if (filtered.length === 0) {
        this.cliFindingsByFile.delete(filePath);
      } else {
        this.cliFindingsByFile.set(filePath, filtered);
      }
    }
    const ai = this.aiFindingsByFile.get(filePath);
    if (ai) {
      const filtered = ai.filter((f) => f.line !== line);
      if (filtered.length === 0) {
        this.aiFindingsByFile.delete(filePath);
      } else {
        this.aiFindingsByFile.set(filePath, filtered);
      }
    }
    this._onDidChange.fire();
    this._onDidChangeAI.fire();
  }

  dismissAIFinding(filePath: string, line: number): void {
    const existing = this.aiFindingsByFile.get(filePath);
    if (!existing) return;
    const filtered = existing.filter((f) => f.line !== line);
    if (filtered.length === 0) {
      this.aiFindingsByFile.delete(filePath);
    } else {
      this.aiFindingsByFile.set(filePath, filtered);
    }
    this._onDidChangeAI.fire();
  }

  clear(): void {
    this.cliFindingsByFile.clear();
    this.aiFindingsByFile.clear();
    this._grade = undefined;
    this._summary = undefined;
    this._circularDeps = [];
    this._depVulns = [];
    this._onDidChange.fire();
    this._onDidChangeAI.fire();
  }

  dispose(): void {
    this._onDidChange.dispose();
    this._onDidChangeAI.dispose();
  }
}
