"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSkylosBin = getSkylosBin;
exports.getConfidenceThreshold = getConfidenceThreshold;
exports.getExcludeFolders = getExcludeFolders;
exports.isFeatureEnabled = isFeatureEnabled;
exports.isRunOnSave = isRunOnSave;
exports.isScanOnOpen = isScanOnOpen;
exports.getIdleMs = getIdleMs;
exports.getPopupCooldownMs = getPopupCooldownMs;
exports.isShowPopup = isShowPopup;
exports.getAIProvider = getAIProvider;
exports.getOpenAIBaseUrl = getOpenAIBaseUrl;
exports.isLocalProvider = isLocalProvider;
exports.getAIApiKey = getAIApiKey;
exports.getAIModel = getAIModel;
exports.isLanguageSupported = isLanguageSupported;
exports.isStreamingEnabled = isStreamingEnabled;
exports.getAutoFixMaxFindings = getAutoFixMaxFindings;
exports.isDeadCodeEnabled = isDeadCodeEnabled;
exports.isShowDeadParams = isShowDeadParams;
exports.getDiffBase = getDiffBase;
exports.isFixPreviewFirst = isFixPreviewFirst;
exports.getPostFixCommand = getPostFixCommand;
const vscode = require("vscode");
const types_1 = require("./types");
function cfg() {
    return vscode.workspace.getConfiguration("skylos");
}
function getSkylosBin() {
    return cfg().get("path", "skylos");
}
function getConfidenceThreshold() {
    return cfg().get("confidence", 80);
}
function getExcludeFolders() {
    return cfg().get("excludeFolders", [
        "venv", ".venv", "build", "dist", ".git", "__pycache__", "node_modules", ".next",
    ]);
}
function isFeatureEnabled(feature) {
    const key = `enable${feature.charAt(0).toUpperCase() + feature.slice(1)}`;
    return cfg().get(key, true);
}
function isRunOnSave() {
    return cfg().get("runOnSave", true);
}
function isScanOnOpen() {
    return cfg().get("scanOnOpen", true);
}
function getIdleMs() {
    return cfg().get("idleMs", 1000);
}
function getPopupCooldownMs() {
    return cfg().get("popupCooldownMs", 8000);
}
function isShowPopup() {
    return cfg().get("showPopup", true);
}
function getAIProvider() {
    return cfg().get("aiProvider", "openai");
}
function getOpenAIBaseUrl() {
    const provider = getAIProvider();
    if (provider === "local") {
        return (cfg().get("localBaseUrl", "") || "").replace(/\/+$/, "");
    }
    return cfg().get("openaiBaseUrl", "https://api.openai.com").replace(/\/+$/, "");
}
function isLocalProvider() {
    return getAIProvider() === "local";
}
function getAIApiKey() {
    const provider = getAIProvider();
    if (provider === "anthropic")
        return cfg().get("anthropicApiKey") || undefined;
    if (provider === "local") {
        const baseUrl = cfg().get("localBaseUrl", "");
        if (!baseUrl)
            return undefined;
        return cfg().get("openaiApiKey") || "local";
    }
    return cfg().get("openaiApiKey") || undefined;
}
function getAIModel() {
    const provider = getAIProvider();
    if (provider === "anthropic")
        return cfg().get("anthropicModel", "claude-sonnet-4-20250514");
    if (provider === "local")
        return cfg().get("localModel", "") || cfg().get("openaiModel", "gpt-4o");
    return cfg().get("openaiModel", "gpt-4o");
}
function isLanguageSupported(langId) {
    return types_1.SUPPORTED_LANGUAGES.includes(langId);
}
function isStreamingEnabled() {
    return cfg().get("streamingInline", true);
}
function getAutoFixMaxFindings() {
    return cfg().get("autoFixMaxFindings", 50);
}
function isDeadCodeEnabled() {
    return cfg().get("enableDeadCode", true);
}
function isShowDeadParams() {
    return cfg().get("showDeadParams", false);
}
function getDiffBase() {
    return cfg().get("diffBase", "origin/main");
}
function isFixPreviewFirst() {
    return cfg().get("fixPreviewFirst", true);
}
function getPostFixCommand() {
    return cfg().get("postFixCommand", "");
}
