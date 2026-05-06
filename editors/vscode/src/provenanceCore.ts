export type FindingSource = "cli" | "agent" | "ai";

export interface ProvenanceFinding {
  id: string;
  fingerprint?: string;
  ruleId: string;
  category: string;
  severity: string;
  message: string;
  file: string;
  line: number;
  source: FindingSource;
  sources?: FindingSource[];
  confidence?: number;
  safeFix?: string;
  fixPatch?: string;
  evidence?: string[];
  trace?: Array<{ file?: string; line?: number; label?: string; message?: string; symbol?: string }>;
  reviewReason?: string;
  ciBlocking?: boolean;
  baselineStatus?: string;
  isNew?: boolean;
  sourceSymbol?: string;
  sinkSymbol?: string;
  itemName?: string;
}

const SOURCE_ORDER: FindingSource[] = ["cli", "agent", "ai"];

export function mergeCorrelatedFindings<T extends ProvenanceFinding>(findings: T[]): T[] {
  const byKey = new Map<string, T>();

  for (const finding of findings) {
    const key = correlationKey(finding);
    const existing = byKey.get(key);
    byKey.set(key, existing ? mergePair(existing, finding) : withNormalizedSources(finding));
  }

  return [...byKey.values()];
}

export function correlationKey(finding: ProvenanceFinding): string {
  const file = finding.file.replace(/\\/g, "/");
  const line = Math.max(1, Math.floor(finding.line || 1));
  const rule = finding.ruleId.trim().toUpperCase();
  const subject = correlationSubject(finding);
  if (rule && rule !== "AI" && rule !== "SKYLOS" && rule !== "SKY-ACTIVE") {
    return `${file}:${line}:rule:${rule}:${subject}`;
  }
  return `${file}:${line}:${finding.category}:${subject}`;
}

export function sourceSummary(finding: Pick<ProvenanceFinding, "source" | "sources">): string {
  return getSources(finding).map(sourceLabel).join(" + ");
}

export function provenanceLabel(finding: Pick<ProvenanceFinding, "source" | "sources">): string {
  return isCorroborated(finding) ? `Confirmed by ${sourceSummary(finding)}` : sourceSummary(finding);
}

export function sourceLabel(source: FindingSource): string {
  if (source === "cli") return "Static";
  if (source === "agent") return "Automation";
  return "AI Assist";
}

export function diagnosticSource(finding: Pick<ProvenanceFinding, "source" | "sources">): string {
  return `skylos ${sourceSummary(finding).toLowerCase().replace(/\s+/g, "-").replace(/-\+-/g, "+")}`;
}

export function isCorroborated(finding: Pick<ProvenanceFinding, "source" | "sources">): boolean {
  return getSources(finding).length > 1;
}

export function matchesSourceFilter(
  finding: Pick<ProvenanceFinding, "source" | "sources">,
  source: FindingSource | "confirmed",
): boolean {
  if (source === "confirmed") return isCorroborated(finding);
  return getSources(finding).includes(source);
}

export function getSources(finding: Pick<ProvenanceFinding, "source" | "sources">): FindingSource[] {
  const sources = finding.sources && finding.sources.length > 0 ? finding.sources : [finding.source];
  return uniqueSources(sources).sort((a, b) => SOURCE_ORDER.indexOf(a) - SOURCE_ORDER.indexOf(b));
}

function correlationSubject(finding: ProvenanceFinding): string {
  const explicit = finding.sinkSymbol ?? finding.sourceSymbol ?? finding.itemName;
  if (explicit && explicit.trim()) return normalizeSubject(explicit);
  return normalizeSubject(finding.message).slice(0, 80);
}

function normalizeSubject(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9.]+/g, " ").trim();
}

function mergePair<T extends ProvenanceFinding>(a: T, b: T): T {
  const primary = choosePrimary(a, b);
  const secondary = primary === a ? b : a;
  const merged: T = {
    ...primary,
    severity: higherSeverity(a.severity, b.severity) as T["severity"],
    confidence: maxNumber(a.confidence, b.confidence),
    safeFix: primary.safeFix ?? secondary.safeFix,
    fixPatch: primary.fixPatch ?? secondary.fixPatch,
    evidence: mergeStrings(a.evidence, b.evidence),
    trace: mergeTrace(a.trace, b.trace),
    reviewReason: primary.reviewReason ?? secondary.reviewReason,
    ciBlocking: a.ciBlocking === true || b.ciBlocking === true ? true : primary.ciBlocking ?? secondary.ciBlocking,
    baselineStatus: primary.baselineStatus ?? secondary.baselineStatus,
    isNew: a.isNew === true || b.isNew === true ? true : primary.isNew ?? secondary.isNew,
    sources: uniqueSources([...getSources(a), ...getSources(b)]),
  };
  return merged;
}

function withNormalizedSources<T extends ProvenanceFinding>(finding: T): T {
  return {
    ...finding,
    sources: getSources(finding),
  };
}

function choosePrimary<T extends ProvenanceFinding>(a: T, b: T): T {
  const sourceDelta = SOURCE_ORDER.indexOf(a.source) - SOURCE_ORDER.indexOf(b.source);
  if (sourceDelta !== 0) return sourceDelta < 0 ? a : b;
  return severityRank(a.severity) >= severityRank(b.severity) ? a : b;
}

function higherSeverity(a: string, b: string): string {
  return severityRank(a) >= severityRank(b) ? a : b;
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
    default:
      return 1;
  }
}

function maxNumber(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.max(a, b);
}

function mergeStrings(a: string[] | undefined, b: string[] | undefined): string[] | undefined {
  const values = [...(a ?? []), ...(b ?? [])].filter((value) => value.trim().length > 0);
  return values.length > 0 ? [...new Set(values)] : undefined;
}

function mergeTrace<T>(a: T[] | undefined, b: T[] | undefined): T[] | undefined {
  const values = [...(a ?? []), ...(b ?? [])];
  return values.length > 0 ? values : undefined;
}

function uniqueSources(sources: FindingSource[]): FindingSource[] {
  return [...new Set(sources)];
}
