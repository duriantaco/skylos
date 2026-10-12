import type * as vscode from "vscode";
import type { FindingSource } from "./provenanceCore";

export const SUPPORTED_LANGUAGES = [
  "python",
  "typescript",
  "typescriptreact",
  "javascript",
  "javascriptreact",
  "go",
] as const;

export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARN";
export type Category = "dead_code" | "security" | "secrets" | "quality" | "debt" | "ai";
export type FindingType = "defect" | "review" | "advice";

export interface FindingTraceStep {
  file?: string;
  line?: number;
  label?: string;
  message?: string;
  symbol?: string;
}

export interface SkylosFinding {
  id: string;
  fingerprint?: string;
  ruleId: string;
  legacyRuleId?: string;
  category: Category;
  findingType?: FindingType;
  severity: Severity;
  severityUnknown?: boolean;
  message: string;
  file: string;
  relativePath?: string;
  workspaceRoot?: string;
  line: number;
  col: number;
  endLine?: number;
  endCol?: number;
  confidence?: number;
  itemType?: string;
  itemName?: string;
  source: FindingSource;
  sources?: FindingSource[];
  ruleUrl?: string;
  safeFix?: string;
  fixPatch?: string;
  baselineStatus?: string;
  isNew?: boolean;
  snippet?: string;
  explanation?: string;
  suggestion?: string;
  evidence?: string[];
  trace?: FindingTraceStep[];
  sourceSymbol?: string;
  sinkSymbol?: string;
  securityEvidence?: Record<string, unknown>;
  reviewReason?: string;
  ciBlocking?: boolean;
}

export interface UnusedItem {
  finding_type?: FindingType;
  name?: string;
  simple_name?: string;
  type?: string;
  file: string;
  line?: number;
  lineno?: number;
  confidence?: number;
  module?: string;
  rule_id?: string;
  fingerprint?: string;
  baseline_status?: string;
  is_new?: boolean;
}

export interface CLIFinding {
  finding_type?: FindingType;
  message: string;
  file: string;
  line: number;
  col?: number;
  rule_id?: string;
  severity?: string;
  compliance_tags?: string[];
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

export interface QualityFinding {
  finding_type?: FindingType;
  rule_id?: string;
  kind?: string;
  metric?: string;
  severity?: string;
  value?: number;
  threshold?: number;
  message?: string;
  file: string;
  line?: number;
  col?: number;
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

export interface ScanMetadata {
  command: string;
  target: string;
  workspaceRoot: string;
  diffBase?: string;
  durationMs?: number;
  exitCode?: number | null;
  stderr?: string;
}

export interface ScanFailureMetadata {
  kind: string;
  message: string;
  command?: string;
  exitCode?: number | null;
  stderr?: string;
}

export interface CLIGrade {
  overall: { score: number; letter: string };
  categories?: Record<string, { score: number; letter: string }>;
}

export interface CLIAssessment {
  version: 1;
  scope: "all_analyzed_findings";
  scanned_checks: string[];
  coverage: { status: "complete" | "partial" | "incomplete" | "unknown"; not_assessed: string[]; incomplete_checks: string[]; reasons: string[] };
  risk: { status: "critical" | "high" | "medium" | "low" | "none" | "unknown" | "not_assessed"; highest_severity: string | null; finding_count: number; severity_counts?: Record<string, number> };
  maintainability: { status: "measured" | "not_assessed"; advice_count: number; rule_count: number; affected_files: number; affected_functions: number | null; checks: MaintainabilityCheck[] };
  dead_code: { status: "review" | "none" | "unknown" | "not_assessed"; candidate_count: number; confidence_range: number[] | null };
  finding_counts: { defect: number; review: number; advice: number; advice_groups: number };
}

export interface CLIGate {
  passed: boolean;
  reasons: string[];
  scope: "local_configured_policy" | "local_strict_policy";
  status: "evaluated" | "incomplete";
  forced: boolean;
}

export interface MaintainabilityCheck {
  rule_id: string;
  name: string;
  language?: string;
  count: number;
  affected_units: number;
  unit: string;
  analyzed_units: number | null;
  affected_percent: number | null;
  max_value: number | null;
  max_threshold: number | null;
  max_excess_ratio: number | null;
}

export interface AnalysisSummary {
  assessment_includes_filtered_findings?: boolean;
  total_files?: number;
  total_loc?: number;
  languages?: Record<string, number>;
  secrets_count?: number;
  danger_count?: number;
  quality_count?: number;
  sca_count?: number;
  unused_files_count?: number;
  excluded_folders?: string[];
}

export interface CircularDependency {
  cycle: string[];
}

export interface DependencyVulnerability {
  package: string;
  version?: string;
  vulnerability_id?: string;
  severity?: string;
  summary?: string;
  fix_version?: string;
  file?: string;
  line?: number;
}

export interface CLIReport {
  unused_functions?: UnusedItem[];
  unused_imports?: UnusedItem[];
  unused_classes?: UnusedItem[];
  unused_variables?: UnusedItem[];
  unused_parameters?: UnusedItem[];
  unused_files?: UnusedItem[];
  unused_exports?: UnusedItem[];
  unused_fixtures?: UnusedItem[];
  secrets?: CLIFinding[];
  danger?: CLIFinding[];
  reliability?: CLIFinding[];
  ai_defects?: CLIFinding[];
  publisher_change_findings?: CLIFinding[];
  custom_rules?: CLIFinding[];
  quality?: QualityFinding[];
  analysis_summary?: AnalysisSummary;
  grade?: CLIGrade;
  assessment?: CLIAssessment;
  gate?: CLIGate;
  circular_dependencies?: CircularDependency[];
  dependency_vulnerabilities?: DependencyVulnerability[];
  whitelisted?: string[];
  suppressed?: string[];
}

export interface AIIssue {
  line: number;
  message: string;
  severity: "error" | "warning";
}

export interface FunctionBlock {
  name: string;
  startLine: number;
  endLine: number;
  content: string;
  hash: string;
}

export type AIProvider = "openai" | "anthropic" | "local";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface FixResult {
  finding: SkylosFinding;
  status: "fixed" | "skipped" | "failed";
  originalCode?: string;
  fixedCode?: string;
  error?: string;
}

export interface AutoFixOptions {
  minSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  dryRun: boolean;
}

export interface FindingsFilter {
  severity?: Severity;
  category?: Category;
  source?: FindingSource | "confirmed";
  filePattern?: string;
}

export interface AgentCommandCenterItem {
  id: string;
  title: string;
  subtitle?: string;
  file: string;
  absolute_file?: string;
  line: number;
  severity: string;
  category: string;
  score: number;
  reason?: string;
  action_type?: string;
  command_hint?: string;
  rule_id?: string;
  message?: string;
  safe_fix?: string;
  fix_patch?: string;
  fixPatch?: string;
  patch?: string;
  hotspot_score?: number;
  priority_score?: number;
  signal_count?: number;
  primary_dimension?: string;
  baseline_status?: string;
}

export interface AgentCommandCenterSummary {
  headline: string;
  subtitle?: string;
  total_findings?: number;
  new_findings?: number;
  critical?: number;
  high?: number;
  medium?: number;
  debt?: number;
  changed_file_count?: number;
   dismissed?: number;
   snoozed?: number;
}

export interface AgentCenterFinding {
  fingerprint: string;
  rule_id: string;
  category: Category | string;
  severity: Severity | string;
  message: string;
  file: string;
  absolute_file?: string;
  line: number;
  confidence?: number;
  hotspot_score?: number;
  priority_score?: number;
  signal_count?: number;
  primary_dimension?: string;
  baseline_status?: string;
  triage_status?: string;
  snoozed_until?: string;
}

export interface AgentCommandCenterState {
  generated_at?: string;
  project_root?: string;
  baseline_present?: boolean;
  changed_files?: string[];
  summary?: AgentCommandCenterSummary;
  actions?: AgentCommandCenterItem[];
  findings?: AgentCenterFinding[];
  triage?: Record<string, { status: string; updated_at?: string; snoozed_until?: string }>;
  command_center?: {
    headline: string;
    subtitle?: string;
    items: AgentCommandCenterItem[];
  };
}

export function getDocumentFilters(): vscode.DocumentFilter[] {
  return SUPPORTED_LANGUAGES.map((lang) => ({ language: lang, scheme: "file" }));
}
