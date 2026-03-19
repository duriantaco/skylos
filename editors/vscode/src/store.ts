import * as vscode from "vscode";
import type {
  SkylosFinding,
  CLIGrade,
  AnalysisSummary,
  CircularDependency,
  DependencyVulnerability,
  FindingsFilter,
} from "./types";

type FindingsScope = "raw" | "working";

export class FindingsStore {
  private workspaceCliFindingsByFile = new Map<string, SkylosFinding[]>();
  private focusedCliFindingsByFile = new Map<string, SkylosFinding[]>();
  private aiFindingsByFile = new Map<string, SkylosFinding[]>();

  private _grade: CLIGrade | undefined;
  private _summary: AnalysisSummary | undefined;
  private _circularDeps: CircularDependency[] = [];
  private _depVulns: DependencyVulnerability[] = [];
  private _deltaMode = false;
  private _filter: FindingsFilter = {};

  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  private _onDidChangeAI = new vscode.EventEmitter<void>();
  readonly onDidChangeAI = this._onDidChangeAI.event;

  setWorkspaceCLIFindings(findings: SkylosFinding[]): void {
    this.workspaceCliFindingsByFile.clear();
    this.focusedCliFindingsByFile.clear();
    for (const f of findings) {
      const list = this.workspaceCliFindingsByFile.get(f.file) ?? [];
      list.push(f);
      this.workspaceCliFindingsByFile.set(f.file, list);
    }
    this._onDidChange.fire();
  }

  setFocusedCLIFindings(filePath: string, findings: SkylosFinding[]): void {
    this.focusedCliFindingsByFile.set(filePath, findings);
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

  get filter(): FindingsFilter { return this._filter; }
  set filter(f: FindingsFilter) {
    this._filter = f;
    this._onDidChange.fire();
    this._onDidChangeAI.fire();
  }

  get hasActiveFilter(): boolean {
    return !!(this._filter.severity || this._filter.category || this._filter.source || this._filter.filePattern);
  }

  setAIFindings(filePath: string, findings: SkylosFinding[]): void {
    if (findings.length === 0) {
      this.aiFindingsByFile.delete(filePath);
    } else {
      this.aiFindingsByFile.set(filePath, findings);
    }
    this._onDidChangeAI.fire();
  }

  getFindingsForFile(
    filePath: string,
    options?: {
      source?: "cli" | "ai";
      includeDeadCode?: boolean;
      max?: number;
    },
  ): SkylosFinding[] {
    let findings = this.getQueriedFindings(options).filter((f) => f.file === filePath);
    findings = sortFindingsInFile(findings);
    if (options?.max !== undefined) {
      return findings.slice(0, options.max);
    }
    return findings;
  }

  getAllRawFindings(): SkylosFinding[] {
    return [...this.getCurrentCLIFindings(), ...this.getAIFindings()];
  }

  getAllFindings(): SkylosFinding[] {
    return this.getFindingsByScope("working");
  }

  getVisibleFindings(
    maxTotal: number,
    options?: {
      source?: "cli" | "ai";
      includeDeadCode?: boolean;
      maxPerFile?: number;
    },
  ): SkylosFinding[] {
    const findings = sortFindingsForDisplay(this.getQueriedFindings(options));
    return limitFindings(findings, maxTotal, options?.maxPerFile);
  }

  getVisibleSummary(
    maxTotal: number,
    options?: {
      source?: "cli" | "ai";
      includeDeadCode?: boolean;
      maxPerFile?: number;
    },
  ): { rawTotal: number; workingTotal: number; visibleTotal: number } {
    const working = this.getQueriedFindings(options);
    const visible = limitFindings(sortFindingsForDisplay(working), maxTotal, options?.maxPerFile);
    return {
      rawTotal: this.getAllRawFindings().length,
      workingTotal: working.length,
      visibleTotal: visible.length,
    };
  }

  countBySeverity(scope: FindingsScope = "working"): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of this.getFindingsByScope(scope)) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  }

  countByCategory(scope: FindingsScope = "working"): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of this.getFindingsByScope(scope)) {
      counts[f.category] = (counts[f.category] ?? 0) + 1;
    }
    return counts;
  }

  removeFindingAtLine(filePath: string, line: number): void {
    const cliMap = this.focusedCliFindingsByFile.has(filePath)
      ? this.focusedCliFindingsByFile
      : this.workspaceCliFindingsByFile;
    const cli = cliMap.get(filePath);
    if (cli) {
      const filtered = cli.filter((f) => f.line !== line);
      if (cliMap === this.focusedCliFindingsByFile) {
        this.focusedCliFindingsByFile.set(filePath, filtered);
      } else if (filtered.length === 0) {
        this.workspaceCliFindingsByFile.delete(filePath);
      } else {
        this.workspaceCliFindingsByFile.set(filePath, filtered);
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
    this.workspaceCliFindingsByFile.clear();
    this.focusedCliFindingsByFile.clear();
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

  refreshViews(): void {
    this._onDidChange.fire();
    this._onDidChangeAI.fire();
  }

  private getFindingsByScope(scope: FindingsScope): SkylosFinding[] {
    if (scope === "raw") {
      return this.getAllRawFindings();
    }
    return this.getQueriedFindings();
  }

  private getQueriedFindings(options?: {
    source?: "cli" | "ai";
    includeDeadCode?: boolean;
  }): SkylosFinding[] {
    let findings = this.getAllRawFindings();
    if (options?.source) {
      findings = findings.filter((f) => f.source === options.source);
    }
    if (options?.includeDeadCode === false) {
      findings = findings.filter((f) => f.category !== "dead_code");
    }
    return findings.filter((f) => this.matchesFilter(f));
  }

  private matchesFilter(finding: SkylosFinding): boolean {
    const f = this._filter;
    if (f.severity && finding.severity !== f.severity) return false;
    if (f.category && finding.category !== f.category) return false;
    if (f.source && finding.source !== f.source) return false;
    if (f.filePattern && !finding.file.toLowerCase().includes(f.filePattern.toLowerCase())) return false;
    return true;
  }

  private getCurrentCLIFindings(): SkylosFinding[] {
    const files = new Set<string>();
    for (const file of this.workspaceCliFindingsByFile.keys()) files.add(file);
    for (const file of this.focusedCliFindingsByFile.keys()) files.add(file);

    const all: SkylosFinding[] = [];
    for (const file of files) {
      all.push(...this.getCurrentCLIFindingsForFile(file));
    }
    return all;
  }

  private getCurrentCLIFindingsForFile(filePath: string): SkylosFinding[] {
    if (this.focusedCliFindingsByFile.has(filePath)) {
      return this.focusedCliFindingsByFile.get(filePath) ?? [];
    }
    return this.workspaceCliFindingsByFile.get(filePath) ?? [];
  }

  private getAIFindings(): SkylosFinding[] {
    const all: SkylosFinding[] = [];
    for (const list of this.aiFindingsByFile.values()) all.push(...list);
    return all;
  }
}

function sortFindingsForDisplay(findings: SkylosFinding[]): SkylosFinding[] {
  const activeFile = vscode.window.activeTextEditor?.document.uri.fsPath;
  const visibleFiles = new Set(vscode.window.visibleTextEditors.map((editor) => editor.document.uri.fsPath));

  return [...findings].sort((a, b) => {
    const scoreDelta = getDisplayScore(b, activeFile, visibleFiles) - getDisplayScore(a, activeFile, visibleFiles);
    if (scoreDelta !== 0) return scoreDelta;
    return a.file.localeCompare(b.file) || a.line - b.line || a.message.localeCompare(b.message);
  });
}

function sortFindingsInFile(findings: SkylosFinding[]): SkylosFinding[] {
  return [...findings].sort((a, b) => {
    const sevDelta = severityRank(b.severity) - severityRank(a.severity);
    if (sevDelta !== 0) return sevDelta;
    return a.line - b.line || a.message.localeCompare(b.message);
  });
}

function getDisplayScore(
  finding: SkylosFinding,
  activeFile: string | undefined,
  visibleFiles: Set<string>,
): number {
  let score = severityRank(finding.severity) * 100;

  if (finding.file === activeFile) {
    score += 100000;
  } else if (visibleFiles.has(finding.file)) {
    score += 50000;
  }

  if (finding.category === "security" || finding.category === "secrets") {
    score += 500;
  }
  if (finding.source === "cli") {
    score += 50;
  }
  if (finding.confidence !== undefined) {
    score += Math.min(99, finding.confidence);
  }

  return score;
}

function severityRank(severity: string): number {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return 5;
    case "HIGH":
      return 4;
    case "MEDIUM":
    case "WARN":
      return 3;
    case "LOW":
      return 2;
    case "INFO":
    default:
      return 1;
  }
}

function limitFindings(findings: SkylosFinding[], maxTotal: number, maxPerFile?: number): SkylosFinding[] {
  if (!Number.isFinite(maxTotal) || maxTotal <= 0) {
    return [];
  }

  const results: SkylosFinding[] = [];
  const perFileCounts = new Map<string, number>();
  const perFileLimit = maxPerFile ?? Number.MAX_SAFE_INTEGER;

  for (const finding of findings) {
    if (results.length >= maxTotal) break;

    const currentCount = perFileCounts.get(finding.file) ?? 0;
    if (currentCount >= perFileLimit) continue;

    perFileCounts.set(finding.file, currentCount + 1);
    results.push(finding);
  }

  return results;
}
