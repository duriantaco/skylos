export interface ScanCommandSpec {
  target: string;
  confidence: number;
  excludeFolders: string[];
  enableSecrets: boolean;
  enableDanger: boolean;
  enableQuality: boolean;
  diffBase?: string;
}

export interface ScanCommand {
  args: string[];
  display: string;
}

export type ScanFailureKind =
  | "missing_binary"
  | "invalid_json"
  | "nonzero_exit"
  | "cancelled"
  | "unknown";

export class SkylosScanError extends Error {
  constructor(
    public readonly kind: ScanFailureKind,
    message: string,
    public readonly details: {
      command?: string;
      exitCode?: number | null;
      stderr?: string;
      stdout?: string;
    } = {},
  ) {
    super(message);
    this.name = "SkylosScanError";
  }
}

export function buildScanArgs(spec: ScanCommandSpec): string[] {
  const args = [spec.target, "--json", "-c", String(spec.confidence)];

  for (const folder of spec.excludeFolders) {
    args.push("--exclude-folder", folder);
  }
  if (spec.enableSecrets) args.push("--secrets");
  if (spec.enableDanger) args.push("--danger");
  if (spec.enableQuality) args.push("--quality");
  if (spec.diffBase) args.push("--diff-base", spec.diffBase);

  return args;
}

export function buildScanCommand(bin: string, spec: ScanCommandSpec): ScanCommand {
  const args = buildScanArgs(spec);
  return {
    args,
    display: formatCommand(bin, args),
  };
}

export function formatCommand(bin: string, args: string[]): string {
  return [bin, ...args].map(shellQuote).join(" ");
}

export function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function buildScanErrorMessage(error: unknown): string {
  if (!(error instanceof SkylosScanError)) {
    return error instanceof Error ? error.message : String(error);
  }

  switch (error.kind) {
    case "missing_binary":
      return "Skylos executable was not found. Set `skylos.path` or install the Skylos CLI.";
    case "invalid_json":
      return "Skylos returned invalid JSON. Open the Skylos output channel for the raw command output.";
    case "nonzero_exit": {
      const code = error.details.exitCode ?? "?";
      return `Skylos exited with code ${code}. Open the Skylos output channel for details.`;
    }
    case "cancelled":
      return "Scan cancelled";
    case "unknown":
    default:
      return error.message;
  }
}

