import type { CoreSeverity } from "./findingCore";

export interface DiagnosticRangeInput {
  line: number;
  col?: number;
  endLine?: number;
  endCol?: number;
}

export interface CoreDiagnosticRange {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
}

export function getDiagnosticRange(input: DiagnosticRangeInput): CoreDiagnosticRange {
  const startLine = Math.max(0, Math.floor((input.line || 1) - 1));
  const startCol = Math.max(0, Math.floor(input.col ?? 0));

  const hasExplicitEnd = input.endLine !== undefined || input.endCol !== undefined;
  if (hasExplicitEnd) {
    const endLine = Math.max(startLine, Math.floor((input.endLine ?? input.line ?? 1) - 1));
    const endCol = Math.max(endLine === startLine ? startCol + 1 : 0, Math.floor(input.endCol ?? startCol + 1));
    return { startLine, startCol, endLine, endCol };
  }

  return {
    startLine,
    startCol,
    endLine: startLine,
    endCol: startCol + 1,
  };
}

export function severityRank(severity: CoreSeverity): number {
  switch (severity) {
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

