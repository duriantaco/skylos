import * as vscode from "vscode";
import { spawn, type ChildProcess } from "child_process";
import * as path from "path";
import type { SkylosFinding, CLIReport, UnusedItem, CLIFinding, QualityFinding, Severity, Category, CLIGrade, AnalysisSummary, CircularDependency, DependencyVulnerability } from "./types";
import { getSkylosBin, getConfidenceThreshold, getExcludeFolders, isFeatureEnabled, isDeadCodeEnabled, isShowDeadParams } from "./config";

export const out = vscode.window.createOutputChannel("Skylos");

let activeProcess: ChildProcess | null = null;

export function cancelScan(): void {
  if (activeProcess) {
    activeProcess.kill();
    activeProcess = null;
  }
}

export interface ScanResult {
  findings: SkylosFinding[];
  grade?: CLIGrade;
  summary?: AnalysisSummary;
  circularDeps?: CircularDependency[];
  depVulns?: DependencyVulnerability[];
}

export async function scanWorkspace(token?: vscode.CancellationToken, diffBase?: string): Promise<ScanResult> {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) {
    vscode.window.showWarningMessage("Skylos: open a folder to scan.");
    return { findings: [] };
  }

  return runScan(ws.uri.fsPath, ws.uri.fsPath, token, diffBase);
}

export async function scanFile(filePath: string, token?: vscode.CancellationToken): Promise<ScanResult> {
  const ws = vscode.workspace.workspaceFolders?.[0];
  const wsRoot = ws?.uri.fsPath ?? path.dirname(filePath);
  return runScan(filePath, wsRoot, token);
}

async function runScan(target: string, wsRoot: string, token?: vscode.CancellationToken, diffBase?: string): Promise<ScanResult> {
  cancelScan();

  const bin = getSkylosBin();
  const conf = getConfidenceThreshold();
  const excludes = getExcludeFolders();

  const args = [target, "--json", "-c", String(conf)];
  excludes.forEach((f) => args.push("--exclude-folder", f));
  if (isFeatureEnabled("secrets"))
    args.push("--secrets");
  if (isFeatureEnabled("danger"))
    args.push("--danger");
  if (isFeatureEnabled("quality"))
    args.push("--quality");
  if (diffBase)
    args.push("--diff-base", diffBase);

  out.appendLine("=".repeat(60));
  out.appendLine(`Running: ${bin} ${args.join(" ")}`);

  return new Promise<ScanResult>((resolve, reject) => {
    const proc = spawn(bin, args, { cwd: wsRoot });
    activeProcess = proc;

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    token?.onCancellationRequested(() => {
      proc.kill();
      reject(new Error("Scan cancelled"));
    });

    proc.on("close", () => {
      activeProcess = null;

      if (stderr) {
        out.appendLine(`stderr: ${stderr}`);
      }

      let report: CLIReport;
      try {
        report = JSON.parse(stdout || "{}");
      } catch {
        out.appendLine("Invalid JSON from CLI");
        reject(new Error("Skylos returned invalid JSON."));
        return;
      }

      const findings = normalizeReport(report, wsRoot);
      printReport(findings, wsRoot);

      resolve({
        findings,
        grade: report.grade,
        summary: report.analysis_summary,
        circularDeps: report.circular_dependencies,
        depVulns: report.dependency_vulnerabilities,
      });
    });

    proc.on("error", (err) => {
      activeProcess = null;
      reject(err);
    });
  });
}

function resolvePath(filePath: string, wsRoot: string): string {
  if (path.isAbsolute(filePath))
    return filePath;
  return path.join(wsRoot, filePath);
}

let findingCounter = 0;
function nextId(): string {
  return `f-${++findingCounter}`;
}

export function normalizeReport(report: CLIReport, wsRoot: string): SkylosFinding[] {
  const findings: SkylosFinding[] = [];

  const mapUnused = (items: UnusedItem[] | undefined, itemType: string, ruleId: string) => {
    for (const u of items ?? []) {
      if (!u.file)
        continue;
      const name = u.name ?? u.simple_name ?? "";
      findings.push({
        id: nextId(),
        ruleId,
        category: "dead_code",
        severity: "INFO",
        message: `Unused ${itemType}: ${name}`,
        file: resolvePath(u.file, wsRoot),
        line: u.line ?? u.lineno ?? 1,
        col: 0,
        confidence: u.confidence,
        itemType,
        itemName: name,
        source: "cli",
      });
    }
  };

  mapUnused(report.unused_functions, "function", "DEAD-FUNC");
  mapUnused(report.unused_imports, "import", "DEAD-IMPORT");
  mapUnused(report.unused_classes, "class", "DEAD-CLASS");
  mapUnused(report.unused_variables, "variable", "DEAD-VAR");
  mapUnused(report.unused_parameters, "parameter", "DEAD-PARAM");

  for (const s of report.secrets ?? []) {
    if (!s.file)
      continue;
    findings.push(cliFindingToSkylos(s, "secrets", wsRoot));
  }

  for (const d of report.danger ?? []) {
    if (!d.file)
      continue;
    findings.push(cliFindingToSkylos(d, "security", wsRoot));
  }

  for (const q of report.quality ?? []) {
    if (!q.file)
      continue;
    const sev = normalizeSeverity(q.severity);
    const ruleId = q.rule_id ?? "SKY-Q000";
    const msg = q.message ?? `Quality issue (${q.kind ?? q.metric ?? "quality"})`;
    findings.push({
      id: nextId(),
      ruleId,
      category: "quality",
      severity: sev,
      message: msg,
      file: resolvePath(q.file, wsRoot),
      line: q.line ?? 1,
      col: 0,
      source: "cli",
    });
  }

  const deadCodeOn = isDeadCodeEnabled();
  const deadParamsOn = isShowDeadParams();
  const confThreshold = getConfidenceThreshold();

  return findings.filter((f) => {
    if (f.category === "dead_code") {
      if (!deadCodeOn) return false;
      if (f.ruleId === "DEAD-PARAM" && !deadParamsOn) return false;
      if (f.confidence !== undefined && f.confidence < confThreshold) return false;
    }
    return true;
  });
}

function cliFindingToSkylos(f: CLIFinding, category: Category, wsRoot: string): SkylosFinding {
  const sev = normalizeSeverity(f.severity);
  const ruleId = f.rule_id ?? "SKYLOS";
  return {
    id: nextId(),
    ruleId,
    category,
    severity: sev,
    message: f.message,
    file: resolvePath(f.file, wsRoot),
    line: f.line ?? 1,
    col: f.col ?? 0,
    source: "cli",
  };
}

function normalizeSeverity(s?: string): Severity {
  const t = (s ?? "").toUpperCase();
  if (t === "CRITICAL")
    return "CRITICAL";

  if (t === "HIGH")
    return "HIGH";

  if (t === "MEDIUM")
    return "MEDIUM";

  if (t === "LOW")
    return "LOW";

  if (t === "WARN" || t === "WARNING")
    return "WARN";
  return "INFO";
}

function printReport(findings: SkylosFinding[], wsRoot: string): void {
  if (findings.length === 0) {
    out.appendLine("No issues found.");
    return;
  }

  out.appendLine("");
  out.appendLine("=".repeat(60));
  out.appendLine("DETAILED RESULTS");
  out.appendLine("=".repeat(60));

  const byCategory = new Map<string, SkylosFinding[]>();
  for (const f of findings) {
    const list = byCategory.get(f.category) ?? [];
    list.push(f);
    byCategory.set(f.category, list);
  }

  for (const [category, catFindings] of byCategory) {
    out.appendLine("");
    out.appendLine(category.toUpperCase());
    out.appendLine("-".repeat(60));

    for (const f of catFindings) {
      const relPath = path.relative(wsRoot, f.file);
      const loc = `${relPath}:${f.line}${f.col ? `:${f.col}` : ""}`;
      const prefix = f.ruleId !== "SKYLOS" ? `[${f.ruleId}] ` : "";
      out.appendLine(`  ${f.severity.padEnd(8)} ${prefix}${f.message}`);
      out.appendLine(`           ${loc}`);
    }
  }

  out.appendLine("");
  out.appendLine("=".repeat(60));
  out.appendLine(`Total: ${findings.length} issue(s)`);
}
