export function shouldWarnMissingLocalAI(options: {
  realtimeAIEnabled: boolean;
  provider: string;
  localBaseUrl?: string;
}): boolean {
  return options.realtimeAIEnabled
    && options.provider === "local"
    && !String(options.localBaseUrl ?? "").trim();
}
