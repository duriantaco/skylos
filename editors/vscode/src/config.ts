import * as vscode from "vscode";
import { SUPPORTED_LANGUAGES, type AIProvider } from "./types";
import {
  resolveTrustedExecutablePath,
  shouldRunWorkspaceAutomation,
  trustedAIProvider,
  trustedConfigBoolean,
  trustedConfigString,
  trustedLocalBaseUrl,
  trustedOpenAIBaseUrl,
} from "./configCore";

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("skylos");
}

export function getSkylosBin(): string {
  return resolveTrustedExecutablePath(cfg().inspect<string>("path"), "skylos");
}

export function getConfidenceThreshold(): number {
  return cfg().get<number>("confidence", 80);
}

export function getExcludeFolders(): string[] {
  return cfg().get<string[]>("excludeFolders", [
    "venv", ".venv", "build", "dist", ".git", "__pycache__", "node_modules", ".next",
  ]);
}

export function isFeatureEnabled(feature: "secrets" | "danger" | "quality"): boolean {
  const key = `enable${feature.charAt(0).toUpperCase() + feature.slice(1)}` as
    | "enableSecrets"
    | "enableDanger"
    | "enableQuality";
  return cfg().get<boolean>(key, true);
}

export function isRunOnSave(): boolean {
  return shouldRunWorkspaceAutomation(
    vscode.workspace.isTrusted,
    cfg().get<boolean>("runOnSave", true),
  );
}

export function isScanOnOpen(): boolean {
  return shouldRunWorkspaceAutomation(
    vscode.workspace.isTrusted,
    trustedConfigBoolean(cfg().inspect<boolean>("scanOnOpen"), false),
  );
}

export function isRealtimeAIEnabled(): boolean {
  return vscode.workspace.isTrusted && trustedConfigBoolean(cfg().inspect<boolean>("enableRealtimeAI"), false);
}

export function getIdleMs(): number {
  return cfg().get<number>("idleMs", 1000);
}

export function getPopupCooldownMs(): number {
  return cfg().get<number>("popupCooldownMs", 8000);
}

export function isShowPopup(): boolean {
  return cfg().get<boolean>("showPopup", true);
}

export function getMaxProblems(): number {
  return cfg().get<number>("maxProblems", 200);
}

export function getMaxProblemsPerFile(): number {
  return cfg().get<number>("maxProblemsPerFile", 50);
}

export function getMaxTreeFindings(): number {
  return cfg().get<number>("maxTreeFindings", 200);
}

export function getMaxTreeFindingsPerFile(): number {
  return cfg().get<number>("maxTreeFindingsPerFile", 25);
}

export function getMaxDecorationsPerFile(): number {
  return cfg().get<number>("maxDecorationsPerFile", 25);
}

export function getEditorSignalLevel(): "quiet" | "balanced" | "verbose" {
  return cfg().get<"quiet" | "balanced" | "verbose">("editorSignalLevel", "quiet");
}

export function getCodeLensMode(): "off" | "activeLine" | "highValue" | "all" {
  return cfg().get<"off" | "activeLine" | "highValue" | "all">("codeLensMode", "highValue");
}

export function isShowDeadCodeInProblems(): boolean {
  return cfg().get<boolean>("showDeadCodeInProblems", false);
}

export function getCommandCenterLimit(): number {
  return cfg().get<number>("commandCenterLimit", 10);
}

export function isCommandCenterRefreshOnOpen(): boolean {
  return shouldRunWorkspaceAutomation(
    vscode.workspace.isTrusted,
    cfg().get<boolean>("commandCenterRefreshOnOpen", false),
  );
}

export function isCommandCenterRefreshOnSave(): boolean {
  return shouldRunWorkspaceAutomation(
    vscode.workspace.isTrusted,
    cfg().get<boolean>("commandCenterRefreshOnSave", false),
  );
}

export function getCommandCenterStateFile(): string {
  return cfg().get<string>("commandCenterStateFile", "").trim();
}

export function getAIProvider(): AIProvider {
  return trustedAIProvider(cfg().inspect<string>("aiProvider")) as AIProvider;
}

export function getOpenAIBaseUrl(): string {
  const provider = getAIProvider();
  if (provider === "local") {
    return getLocalBaseUrl();
  }
  return trustedOpenAIBaseUrl(cfg().inspect<string>("openaiBaseUrl"));
}

export function getLocalBaseUrl(): string {
  return trustedLocalBaseUrl(cfg().inspect<string>("localBaseUrl"));
}

export function isLocalProvider(): boolean {
  return getAIProvider() === "local";
}

export function getAIApiKey(): string | undefined {
  const provider = getAIProvider();
  if (provider === "anthropic") {
    return trustedConfigString(cfg().inspect<string>("anthropicApiKey")) || undefined;
  }
  if (provider === "local") {
    const baseUrl = getLocalBaseUrl();
    if (!baseUrl) return undefined;
    return "local";
  }
  return trustedConfigString(cfg().inspect<string>("openaiApiKey")) || undefined;
}

export function getAIModel(): string {
  const provider = getAIProvider();
  if (provider === "anthropic") {
    return trustedConfigString(
      cfg().inspect<string>("anthropicModel"),
      "claude-sonnet-4-20250514",
    );
  }
  if (provider === "local") {
    return (
      trustedConfigString(cfg().inspect<string>("localModel"))
      || trustedConfigString(cfg().inspect<string>("openaiModel"), "gpt-4o")
    );
  }
  return trustedConfigString(cfg().inspect<string>("openaiModel"), "gpt-4o");
}

export function isLanguageSupported(langId: string): boolean {
  return (SUPPORTED_LANGUAGES as readonly string[]).includes(langId);
}

export function isStreamingEnabled(): boolean {
  return isRealtimeAIEnabled() && cfg().get<boolean>("streamingInline", false);
}

export function getAutoFixMaxFindings(): number {
  return cfg().get<number>("autoFixMaxFindings", 50);
}

export function isDeadCodeEnabled(): boolean {
  return cfg().get<boolean>("enableDeadCode", true);
}

export function isShowDeadParams(): boolean {
  return cfg().get<boolean>("showDeadParams", false);
}

export function getDiffBase(): string {
  return cfg().get<string>("diffBase", "origin/main");
}

export function isFixPreviewFirst(): boolean {
  return cfg().get<boolean>("fixPreviewFirst", true);
}

export function getPostFixCommand(): string {
  return cfg().get<string>("postFixCommand", "");
}
