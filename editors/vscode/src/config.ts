import * as vscode from "vscode";
import { SUPPORTED_LANGUAGES, type AIProvider } from "./types";

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("skylos");
}

export function getSkylosBin(): string {
  return cfg().get<string>("path", "skylos");
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
  return cfg().get<boolean>("runOnSave", true);
}

export function isScanOnOpen(): boolean {
  return cfg().get<boolean>("scanOnOpen", true);
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

export function getAIProvider(): AIProvider {
  return cfg().get<AIProvider>("aiProvider", "openai");
}

export function getAIApiKey(): string | undefined {
  const provider = getAIProvider();
  return provider === "anthropic"
    ? cfg().get<string>("anthropicApiKey")
    : cfg().get<string>("openaiApiKey");
}

export function getAIModel(): string {
  const provider = getAIProvider();
  return provider === "anthropic"
    ? cfg().get<string>("anthropicModel", "claude-sonnet-4-20250514")
    : cfg().get<string>("openaiModel", "gpt-4o");
}

export function isLanguageSupported(langId: string): boolean {
  return (SUPPORTED_LANGUAGES as readonly string[]).includes(langId);
}

export function isStreamingEnabled(): boolean {
  return cfg().get<boolean>("streamingInline", true);
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
