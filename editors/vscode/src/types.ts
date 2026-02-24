import * as vscode from "vscode";

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
export type Category = "dead_code" | "security" | "secrets" | "quality" | "ai";

export interface SkylosFinding {
  id: string;
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  col: number;
  confidence?: number;
  itemType?: string;
  itemName?: string;
  source: "cli" | "ai";
}

export interface UnusedItem {
  name?: string;
  simple_name?: string;
  type?: string;
  file: string;
  line?: number;
  lineno?: number;
  confidence?: number;
  module?: string;
}

export interface CLIFinding {
  message: string;
  file: string;
  line: number;
  col?: number;
  rule_id?: string;
  severity?: string;
  compliance_tags?: string[];
}

export interface QualityFinding {
  rule_id?: string;
  kind?: string;
  metric?: string;
  severity?: string;
  value?: number;
  threshold?: number;
  message?: string;
  file: string;
  line?: number;
}

export interface CLIGrade {
  overall: { score: number; letter: string };
  categories?: Record<string, { score: number; letter: string }>;
}

export interface AnalysisSummary {
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
  secrets?: CLIFinding[];
  danger?: CLIFinding[];
  quality?: QualityFinding[];
  analysis_summary?: AnalysisSummary;
  grade?: CLIGrade;
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

export type AIProvider = "openai" | "anthropic";

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

export function getDocumentFilters(): vscode.DocumentFilter[] {
  return SUPPORTED_LANGUAGES.map((lang) => ({ language: lang, scheme: "file" }));
}
