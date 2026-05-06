import * as crypto from "crypto";
import * as path from "path";

export type CoreSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARN";
export type CoreCategory = "dead_code" | "security" | "secrets" | "quality" | "debt" | "ai";

interface RawUnusedItem {
  name?: string;
  simple_name?: string;
  type?: string;
  file?: string;
  line?: number;
  lineno?: number;
  confidence?: number;
  module?: string;
  rule_id?: string;
  fingerprint?: string;
  baseline_status?: string;
  is_new?: boolean;
}

interface RawFinding {
  message?: string;
  file?: string;
  line?: number;
  col?: number;
  rule_id?: string;
  severity?: string;
  confidence?: number;
  fingerprint?: string;
  rule_url?: string;
  ruleUrl?: string;
  end_line?: number;
  endLine?: number;
  end_col?: number;
  endCol?: number;
  end_column?: number;
  endColumn?: number;
  safe_fix?: string;
  safeFix?: string;
  fix_patch?: string;
  fixPatch?: string;
  patch?: string;
  baseline_status?: string;
  baselineStatus?: string;
  is_new?: boolean;
  isNew?: boolean;
  snippet?: string;
  code_snippet?: string;
  codeSnippet?: string;
  vulnerable_code?: string;
  explanation?: string;
  suggestion?: string;
  evidence?: unknown;
  trace?: unknown;
  dataflow?: unknown;
  source_symbol?: string;
  sourceSymbol?: string;
  sink_symbol?: string;
  sinkSymbol?: string;
  _security_evidence?: Record<string, unknown>;
  security_evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  _review_reason?: string;
  review_reason?: string;
  _ci_blocking?: boolean;
  ci_blocking?: boolean;
}

interface RawQualityFinding extends RawFinding {
  kind?: string;
  metric?: string;
  value?: number;
  threshold?: number;
}

export interface RawCLIReport {
  unused_functions?: RawUnusedItem[];
  unused_imports?: RawUnusedItem[];
  unused_classes?: RawUnusedItem[];
  unused_variables?: RawUnusedItem[];
  unused_parameters?: RawUnusedItem[];
  secrets?: RawFinding[];
  danger?: RawFinding[];
  quality?: RawQualityFinding[];
}

export interface NormalizeReportOptions {
  wsRoot: string;
  deadCodeEnabled: boolean;
  showDeadParams: boolean;
  confidenceThreshold: number;
}

export interface CoreFinding {
  id: string;
  fingerprint: string;
  ruleId: string;
  legacyRuleId?: string;
  category: CoreCategory;
  severity: CoreSeverity;
  message: string;
  file: string;
  relativePath: string;
  workspaceRoot: string;
  line: number;
  col: number;
  endLine?: number;
  endCol?: number;
  confidence?: number;
  itemType?: string;
  itemName?: string;
  source: "cli" | "ai";
  ruleUrl?: string;
  safeFix?: string;
  fixPatch?: string;
  baselineStatus?: string;
  isNew?: boolean;
  snippet?: string;
  explanation?: string;
  suggestion?: string;
  evidence?: string[];
  trace?: CoreTraceStep[];
  sourceSymbol?: string;
  sinkSymbol?: string;
  securityEvidence?: Record<string, unknown>;
  reviewReason?: string;
  ciBlocking?: boolean;
}

export interface CoreTraceStep {
  file?: string;
  line?: number;
  label?: string;
  message?: string;
  symbol?: string;
}

const DEAD_CODE_RULES: Record<string, { ruleId: string; legacyRuleId: string; itemType: string; label: string }> = {
  unused_functions: { ruleId: "SKY-U001", legacyRuleId: "DEAD-FUNC", itemType: "function", label: "function" },
  unused_imports: { ruleId: "SKY-U002", legacyRuleId: "DEAD-IMPORT", itemType: "import", label: "import" },
  unused_variables: { ruleId: "SKY-U003", legacyRuleId: "DEAD-VAR", itemType: "variable", label: "variable" },
  unused_classes: { ruleId: "SKY-U004", legacyRuleId: "DEAD-CLASS", itemType: "class", label: "class" },
  unused_parameters: { ruleId: "SKY-U005", legacyRuleId: "DEAD-PARAM", itemType: "parameter", label: "parameter" },
};

const LEGACY_RULE_ALIASES: Record<string, string> = {
  "DEAD-FUNC": "SKY-U001",
  "DEAD-IMPORT": "SKY-U002",
  "DEAD-VAR": "SKY-U003",
  "DEAD-CLASS": "SKY-U004",
  "DEAD-PARAM": "SKY-U005",
  "SKY-DC001": "SKY-U001",
  "SKY-DC002": "SKY-U002",
};

let findingCounter = 0;

export function normalizeReportCore(report: RawCLIReport, options: NormalizeReportOptions): CoreFinding[] {
  const findings: CoreFinding[] = [];

  mapUnused(findings, report.unused_functions, "unused_functions", options);
  mapUnused(findings, report.unused_imports, "unused_imports", options);
  mapUnused(findings, report.unused_classes, "unused_classes", options);
  mapUnused(findings, report.unused_variables, "unused_variables", options);
  mapUnused(findings, report.unused_parameters, "unused_parameters", options);

  for (const secret of report.secrets ?? []) {
    const finding = rawFindingToCore(secret, "secrets", options);
    if (finding) findings.push(finding);
  }

  for (const danger of report.danger ?? []) {
    const finding = rawFindingToCore(danger, "security", options);
    if (finding) findings.push(finding);
  }

  for (const quality of report.quality ?? []) {
    const finding = rawQualityFindingToCore(quality, options);
    if (finding) findings.push(finding);
  }

  return findings.filter((finding) => {
    if (finding.category !== "dead_code") return true;
    if (!options.deadCodeEnabled) return false;
    if (finding.ruleId === "SKY-U005" && !options.showDeadParams) return false;
    if (finding.confidence !== undefined && finding.confidence < options.confidenceThreshold) return false;
    return true;
  });
}

export function canonicalRuleId(ruleId: string): string {
  return LEGACY_RULE_ALIASES[ruleId] ?? ruleId;
}

export function isDeadCodeRule(ruleId: string): boolean {
  return canonicalRuleId(ruleId).startsWith("SKY-U");
}

export function isUnusedImportRule(ruleId: string): boolean {
  return canonicalRuleId(ruleId) === "SKY-U002";
}

export function isUnusedFunctionRule(ruleId: string): boolean {
  return canonicalRuleId(ruleId) === "SKY-U001";
}

export function normalizeSeverity(value?: string): CoreSeverity {
  const normalized = String(value ?? "").toUpperCase();
  if (normalized === "CRITICAL") return "CRITICAL";
  if (normalized === "HIGH") return "HIGH";
  if (normalized === "MEDIUM") return "MEDIUM";
  if (normalized === "LOW") return "LOW";
  if (normalized === "WARN" || normalized === "WARNING") return "WARN";
  return "INFO";
}

export function makeFingerprint(input: {
  ruleId: string;
  relativePath: string;
  line: number;
  message: string;
  subject?: string;
}): string {
  const material = [
    canonicalRuleId(input.ruleId),
    input.relativePath.replace(/\\/g, "/"),
    String(input.line),
    input.subject ?? "",
    input.message,
  ].join("\0");
  const hash = crypto.createHash("sha1").update(material).digest("hex").slice(0, 20);
  return `vsce:${hash}`;
}

function mapUnused(
  findings: CoreFinding[],
  items: RawUnusedItem[] | undefined,
  key: keyof typeof DEAD_CODE_RULES,
  options: NormalizeReportOptions,
): void {
  const meta = DEAD_CODE_RULES[key];
  for (const item of items ?? []) {
    if (!item.file) continue;
    const paths = normalizePaths(item.file, options.wsRoot);
    const name = item.name ?? item.simple_name ?? "";
    const line = positiveLine(item.line ?? item.lineno);
    const message = `Unused ${meta.label}: ${name}`;
    const ruleId = canonicalRuleId(item.rule_id ?? meta.ruleId);
    const fingerprint = item.fingerprint ?? makeFingerprint({
      ruleId,
      relativePath: paths.relativePath,
      line,
      message,
      subject: name,
    });

    findings.push({
      id: nextId(),
      fingerprint,
      ruleId,
      legacyRuleId: meta.legacyRuleId,
      category: "dead_code",
      severity: "INFO",
      message,
      file: paths.absolutePath,
      relativePath: paths.relativePath,
      workspaceRoot: options.wsRoot,
      line,
      col: 0,
      confidence: item.confidence,
      itemType: meta.itemType,
      itemName: name,
      source: "cli",
      baselineStatus: item.baseline_status,
      isNew: item.is_new,
    });
  }
}

function rawFindingToCore(
  raw: RawFinding,
  category: CoreCategory,
  options: NormalizeReportOptions,
): CoreFinding | undefined {
  if (!raw.file) return undefined;
  const paths = normalizePaths(raw.file, options.wsRoot);
  const line = positiveLine(raw.line);
  const ruleId = canonicalRuleId(raw.rule_id ?? "SKYLOS");
  const message = raw.message ?? `Skylos ${category} finding`;
  const fingerprint = raw.fingerprint ?? makeFingerprint({
    ruleId,
    relativePath: paths.relativePath,
    line,
    message,
  });
  const metadata = objectValue(raw.metadata);

  return {
    id: nextId(),
    fingerprint,
    ruleId,
    category,
    severity: normalizeSeverity(raw.severity),
    message,
    file: paths.absolutePath,
    relativePath: paths.relativePath,
    workspaceRoot: options.wsRoot,
    line,
    col: zeroBasedCol(raw.col),
    endLine: positiveOptional(raw.end_line ?? raw.endLine),
    endCol: zeroBasedOptional(raw.end_col ?? raw.endCol ?? raw.end_column ?? raw.endColumn),
    confidence: raw.confidence,
    source: "cli",
    ruleUrl: raw.rule_url ?? raw.ruleUrl,
    safeFix: raw.safe_fix ?? raw.safeFix,
    fixPatch: raw.fix_patch ?? raw.fixPatch ?? raw.patch,
    baselineStatus: raw.baseline_status ?? raw.baselineStatus,
    isNew: raw.is_new ?? raw.isNew,
    snippet: stringValue(raw.snippet ?? raw.code_snippet ?? raw.codeSnippet ?? raw.vulnerable_code),
    explanation: stringValue(raw.explanation),
    suggestion: stringValue(raw.suggestion),
    evidence: evidenceList(raw.evidence ?? metadata?.evidence),
    trace: traceSteps(raw.trace ?? raw.dataflow ?? metadata?.trace ?? metadata?.dataflow),
    sourceSymbol: stringValue(raw.source_symbol ?? raw.sourceSymbol ?? metadata?.source_symbol ?? metadata?.sourceSymbol),
    sinkSymbol: stringValue(raw.sink_symbol ?? raw.sinkSymbol ?? metadata?.sink_symbol ?? metadata?.sinkSymbol),
    securityEvidence: objectValue(
      raw._security_evidence
      ?? raw.security_evidence
      ?? metadata?.security_evidence
      ?? metadata?._security_evidence,
    ),
    reviewReason: stringValue(raw._review_reason ?? raw.review_reason ?? metadata?.review_reason ?? metadata?._review_reason),
    ciBlocking: booleanValue(raw._ci_blocking ?? raw.ci_blocking ?? metadata?.ci_blocking ?? metadata?._ci_blocking),
  };
}

function rawQualityFindingToCore(raw: RawQualityFinding, options: NormalizeReportOptions): CoreFinding | undefined {
  const message = raw.message ?? `Quality issue (${raw.kind ?? raw.metric ?? "quality"})`;
  return rawFindingToCore({ ...raw, message, rule_id: raw.rule_id ?? "SKY-Q000" }, "quality", options);
}

function normalizePaths(filePath: string, wsRoot: string): { absolutePath: string; relativePath: string } {
  const absolutePath = path.normalize(path.isAbsolute(filePath) ? filePath : path.join(wsRoot, filePath));
  const relativePath = path.relative(wsRoot, absolutePath).replace(/\\/g, "/") || path.basename(absolutePath);
  return { absolutePath, relativePath };
}

function positiveLine(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 1) return 1;
  return Math.floor(value);
}

function positiveOptional(value: number | undefined): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 1) return undefined;
  return Math.floor(value);
}

function zeroBasedCol(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.floor(value));
}

function zeroBasedOptional(value: number | undefined): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.max(0, Math.floor(value));
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function evidenceList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    const single = stringValue(value);
    return single ? [single] : undefined;
  }
  const items = value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
  return items.length > 0 ? items : undefined;
}

function traceSteps(value: unknown): CoreTraceStep[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const steps: CoreTraceStep[] = [];
  for (const item of value) {
    if (typeof item === "string" && item.trim().length > 0) {
      steps.push({ message: item });
      continue;
    }
    const obj = objectValue(item);
    if (!obj) continue;
    const step: CoreTraceStep = {
      file: stringValue(obj.file ?? obj.path ?? obj.filename),
      line: typeof obj.line === "number" && Number.isFinite(obj.line) ? Math.max(1, Math.floor(obj.line)) : undefined,
      label: stringValue(obj.label ?? obj.kind),
      message: stringValue(obj.message ?? obj.detail),
      symbol: stringValue(obj.symbol ?? obj.name),
    };
    if (step.file || step.line || step.label || step.message || step.symbol) steps.push(step);
  }
  return steps.length > 0 ? steps : undefined;
}

function nextId(): string {
  findingCounter += 1;
  return `f-${findingCounter}`;
}
