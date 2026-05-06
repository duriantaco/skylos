import * as vscode from "vscode";
import { spawn, type ChildProcess } from "child_process";
import * as path from "path";
import type { SkylosFinding, CLIReport, CLIGrade, AnalysisSummary, CircularDependency, DependencyVulnerability, ScanMetadata } from "./types";
import { getSkylosBin, getConfidenceThreshold, getExcludeFolders, isFeatureEnabled, isDeadCodeEnabled, isShowDeadParams } from "./config";
import { buildScanCommand, formatCommand, SkylosScanError } from "./scanCore";
import { normalizeReportCore } from "./findingCore";

export const out = vscode.window.createOutputChannel("Skylos");
export { buildScanErrorMessage, SkylosScanError } from "./scanCore";

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
  metadata?: ScanMetadata;
}

export interface DoctorResult {
  ok: boolean;
  command: string;
  bin: string;
  workspaceRoot?: string;
  stdout?: string;
  stderr?: string;
  error?: string;
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

export async function doctorSkylos(): Promise<DoctorResult> {
  const bin = getSkylosBin();
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const args = ["--version"];
  const command = formatCommand(bin, args);

  out.appendLine("=".repeat(60));
  out.appendLine("Skylos Doctor");
  out.appendLine(`Workspace: ${wsRoot ?? "(none)"}`);
  out.appendLine(`Configured binary: ${bin}`);
  out.appendLine(`Version command: ${command}`);

  return new Promise<DoctorResult>((resolve) => {
    const proc = spawn(bin, args, { cwd: wsRoot });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      const ok = code === 0;
      if (stdout.trim()) out.appendLine(`stdout: ${stdout.trim()}`);
      if (stderr.trim()) out.appendLine(`stderr: ${stderr.trim()}`);
      out.appendLine(ok ? "Doctor result: OK" : `Doctor result: failed with exit code ${code}`);
      resolve({
        ok,
        command,
        bin,
        workspaceRoot: wsRoot,
        stdout,
        stderr,
        error: ok ? undefined : `Version command exited with code ${code}`,
      });
    });

    proc.on("error", (err) => {
      const errno = (err as NodeJS.ErrnoException).code;
      const error = errno === "ENOENT"
        ? "Skylos executable was not found. Set `skylos.path` or install the Skylos CLI."
        : err.message;
      out.appendLine(`Doctor result: ${error}`);
      resolve({
        ok: false,
        command,
        bin,
        workspaceRoot: wsRoot,
        stdout,
        stderr,
        error,
      });
    });
  });
}

async function runScan(target: string, wsRoot: string, token?: vscode.CancellationToken, diffBase?: string): Promise<ScanResult> {
  cancelScan();

  const bin = getSkylosBin();
  const command = buildScanCommand(bin, {
    target,
    confidence: getConfidenceThreshold(),
    excludeFolders: getExcludeFolders(),
    enableSecrets: isFeatureEnabled("secrets"),
    enableDanger: isFeatureEnabled("danger"),
    enableQuality: isFeatureEnabled("quality"),
    diffBase,
  });

  out.appendLine("=".repeat(60));
  out.appendLine(`Running: ${command.display}`);
  const startedAt = Date.now();

  return new Promise<ScanResult>((resolve, reject) => {
    const proc = spawn(bin, command.args, { cwd: wsRoot });
    activeProcess = proc;

    let stdout = "";
    let stderr = "";
    let cancelled = false;
    let settled = false;

    const fail = (error: SkylosScanError) => {
      if (settled) return;
      settled = true;
      reject(error);
    };

    const succeed = (result: ScanResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    token?.onCancellationRequested(() => {
      cancelled = true;
      proc.kill();
      fail(new SkylosScanError("cancelled", "Scan cancelled", { command: command.display }));
    });

    proc.on("close", (code) => {
      activeProcess = null;
      if (cancelled) return;

      if (stderr) {
        out.appendLine(`stderr: ${stderr}`);
      }

      let report: CLIReport;
      try {
        report = JSON.parse(stdout || "{}");
      } catch {
        out.appendLine("Invalid JSON from CLI");
        fail(new SkylosScanError(
          code === 0 ? "invalid_json" : "nonzero_exit",
          code === 0 ? "Skylos returned invalid JSON." : `Skylos exited with code ${code}.`,
          { command: command.display, exitCode: code, stderr, stdout },
        ));
        return;
      }

      if (code !== 0) {
        out.appendLine(`Skylos exited with code ${code} but returned parseable JSON; showing parsed findings.`);
      }

      const findings = normalizeReport(report, wsRoot);
      printReport(findings, wsRoot);

      succeed({
        findings,
        grade: report.grade,
        summary: report.analysis_summary,
        circularDeps: report.circular_dependencies,
        depVulns: report.dependency_vulnerabilities,
        metadata: {
          command: command.display,
          target,
          workspaceRoot: wsRoot,
          diffBase,
          durationMs: Date.now() - startedAt,
          exitCode: code,
          stderr,
        },
      });
    });

    proc.on("error", (err) => {
      activeProcess = null;
      const errno = (err as NodeJS.ErrnoException).code;
      const kind = errno === "ENOENT" ? "missing_binary" : "unknown";
      fail(new SkylosScanError(kind, err.message, { command: command.display, stderr }));
    });
  });
}

export function normalizeReport(report: CLIReport, wsRoot: string): SkylosFinding[] {
  return normalizeReportCore(report, {
    wsRoot,
    deadCodeEnabled: isDeadCodeEnabled(),
    showDeadParams: isShowDeadParams(),
    confidenceThreshold: getConfidenceThreshold(),
  }) as SkylosFinding[];
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
