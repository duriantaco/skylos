export function shouldWarnMissingLocalAI(options: {
  realtimeAIEnabled: boolean;
  provider: string;
  localBaseUrl?: string;
}): boolean {
  return options.realtimeAIEnabled
    && options.provider === "local"
    && !String(options.localBaseUrl ?? "").trim();
}

export interface ConfigurationInspection<T> {
  defaultValue?: T;
  globalValue?: T;
}

export type TrustedAIProvider = "openai" | "anthropic" | "local";

export const DEFAULT_OPENAI_BASE_URL = "https://api.openai.com";

function trustedConfigValue<T>(
  inspection: ConfigurationInspection<T> | undefined,
  fallback: T,
): T {
  const globalValue = inspection?.globalValue;
  if (typeof globalValue === "string") {
    const trimmed = globalValue.trim();
    if (trimmed) return trimmed as T;
  } else if (globalValue !== undefined) {
    return globalValue;
  }

  const defaultValue = inspection?.defaultValue;
  if (typeof defaultValue === "string") {
    const trimmed = defaultValue.trim();
    if (trimmed) return trimmed as T;
  } else if (defaultValue !== undefined) {
    return defaultValue;
  }

  return fallback;
}

export function trustedConfigString(
  inspection: ConfigurationInspection<string> | undefined,
  fallback = "",
): string {
  return trustedConfigValue(inspection, fallback);
}

export function trustedConfigBoolean(
  inspection: ConfigurationInspection<boolean> | undefined,
  fallback = false,
): boolean {
  return trustedConfigValue(inspection, fallback);
}

export function resolveTrustedExecutablePath(
  inspection: ConfigurationInspection<string> | undefined,
  fallback = "skylos",
): string {
  return trustedConfigString(inspection, fallback);
}

export function shouldRunWorkspaceAutomation(workspaceTrusted: boolean, enabled: boolean): boolean {
  return workspaceTrusted && enabled;
}

export function trustedAIProvider(
  inspection: ConfigurationInspection<string> | undefined,
): TrustedAIProvider {
  const provider = trustedConfigString(inspection, "openai");
  if (provider === "anthropic" || provider === "local") return provider;
  return "openai";
}

export function trustedOpenAIBaseUrl(
  inspection: ConfigurationInspection<string> | undefined,
): string {
  const configured = trustedConfigString(inspection, DEFAULT_OPENAI_BASE_URL);
  try {
    const url = new URL(configured);
    if (url.protocol !== "https:" || url.hostname !== "api.openai.com") {
      return DEFAULT_OPENAI_BASE_URL;
    }
    return url.origin.replace(/\/+$/, "");
  } catch {
    return DEFAULT_OPENAI_BASE_URL;
  }
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost"
    || normalized === "::1"
    || normalized === "0:0:0:0:0:0:0:1"
    || normalized.startsWith("127.")
  );
}

export function trustedLocalBaseUrl(
  inspection: ConfigurationInspection<string> | undefined,
): string {
  const configured = trustedConfigString(inspection, "");
  if (!configured) return "";

  try {
    const url = new URL(configured);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !isLoopbackHost(url.hostname)) {
      return "";
    }
    return url.origin.replace(/\/+$/, "");
  } catch {
    return "";
  }
}
