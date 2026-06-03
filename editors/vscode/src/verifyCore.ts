import { spawn } from "child_process";
import type { AIIssue } from "./types";
import { formatCommand } from "./scanCore";

export interface VerifyRequest {
  bin: string;
  workspaceRoot: string;
  filePath: string;
  code: string;
  lineRange?: string;
  confidence: number;
}

interface VerifyFindingRange {
  start_line?: number;
  end_line?: number;
}

interface VerifyFinding {
  rule_id?: string;
  ai_likelihood?: string;
  severity?: string;
  message?: string;
  range?: VerifyFindingRange;
}

interface VerifyPayload {
  findings?: VerifyFinding[];
}

export function buildVerifyArgs(request: VerifyRequest): string[] {
  const args = [
    "verify",
    request.workspaceRoot,
    "--stdin",
    "--no-fail",
    "--confidence",
    String(request.confidence),
  ];
  return args;
}

export function buildVerifyManifest(request: VerifyRequest): Record<string, unknown> {
  const manifest: Record<string, unknown> = {
    path: request.workspaceRoot,
    file: request.filePath,
    code: request.code,
  };
  if (request.lineRange) {
    manifest.range = request.lineRange;
  }
  return manifest;
}

export function buildVerifyCommandDisplay(request: VerifyRequest): string {
  return formatCommand(request.bin, buildVerifyArgs(request));
}

export async function runSkylosVerify(request: VerifyRequest): Promise<AIIssue[]> {
  const args = buildVerifyArgs(request);
  const manifest = buildVerifyManifest(request);
  const manifestText = JSON.stringify(manifest);

  return new Promise<AIIssue[]>((resolve, reject) => {
    const proc = spawn(request.bin, args, { cwd: request.workspaceRoot });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });
    proc.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`skylos verify exited with code ${code}: ${stderr}`));
        return;
      }

      try {
        const payload = JSON.parse(stdout);
        resolve(normalizeVerifyIssues(payload));
      } catch {
        reject(new Error("skylos verify returned invalid JSON"));
      }
    });
    proc.on("error", (error) => {
      reject(error);
    });
    proc.stdin.write(manifestText);
    proc.stdin.end();
  });
}

export function normalizeVerifyIssues(payload: VerifyPayload): AIIssue[] {
  const findings = payload.findings;
  if (!Array.isArray(findings)) {
    return [];
  }

  const issues: AIIssue[] = [];
  for (const finding of findings) {
    const issue = normalizeVerifyIssue(finding);
    if (issue) {
      issues.push(issue);
    }
  }
  return issues;
}

function normalizeVerifyIssue(finding: VerifyFinding): AIIssue | undefined {
  const message = finding.message;
  if (!message) {
    return undefined;
  }

  return {
    line: verifyIssueLine(finding),
    message,
    severity: verifyIssueSeverity(finding),
  };
}

function verifyIssueLine(finding: VerifyFinding): number {
  const startLine = finding.range?.start_line;
  if (typeof startLine === "number") {
    if (startLine > 0) {
      return startLine;
    }
  }
  return 1;
}

function verifyIssueSeverity(finding: VerifyFinding): "error" | "warning" {
  const severity = optionalString(finding.severity).toUpperCase();
  if (severity === "CRITICAL") {
    return "error";
  }
  if (severity === "HIGH") {
    return "error";
  }

  const likelihood = optionalString(finding.ai_likelihood).toLowerCase();
  if (likelihood === "high") {
    return "error";
  }
  return "warning";
}

function optionalString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return "";
}
