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

export function resolveTrustedExecutablePath(
  inspection: ConfigurationInspection<string> | undefined,
  fallback = "skylos",
): string {
  const globalValue = inspection?.globalValue?.trim();
  if (globalValue) return globalValue;

  const defaultValue = inspection?.defaultValue?.trim();
  if (defaultValue) return defaultValue;

  return fallback;
}

export function shouldRunWorkspaceAutomation(workspaceTrusted: boolean, enabled: boolean): boolean {
  return workspaceTrusted && enabled;
}
