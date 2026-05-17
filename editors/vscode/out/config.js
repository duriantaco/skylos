"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSkylosBin = getSkylosBin;
exports.getConfidenceThreshold = getConfidenceThreshold;
exports.getExcludeFolders = getExcludeFolders;
exports.isFeatureEnabled = isFeatureEnabled;
exports.isRunOnSave = isRunOnSave;
exports.isScanOnOpen = isScanOnOpen;
exports.isRealtimeAIEnabled = isRealtimeAIEnabled;
exports.getIdleMs = getIdleMs;
exports.getPopupCooldownMs = getPopupCooldownMs;
exports.isShowPopup = isShowPopup;
exports.getMaxProblems = getMaxProblems;
exports.getMaxProblemsPerFile = getMaxProblemsPerFile;
exports.getMaxTreeFindings = getMaxTreeFindings;
exports.getMaxTreeFindingsPerFile = getMaxTreeFindingsPerFile;
exports.getMaxDecorationsPerFile = getMaxDecorationsPerFile;
exports.getEditorSignalLevel = getEditorSignalLevel;
exports.getCodeLensMode = getCodeLensMode;
exports.isShowDeadCodeInProblems = isShowDeadCodeInProblems;
exports.getCommandCenterLimit = getCommandCenterLimit;
exports.isCommandCenterRefreshOnOpen = isCommandCenterRefreshOnOpen;
exports.isCommandCenterRefreshOnSave = isCommandCenterRefreshOnSave;
exports.getCommandCenterStateFile = getCommandCenterStateFile;
exports.getAIProvider = getAIProvider;
exports.getOpenAIBaseUrl = getOpenAIBaseUrl;
exports.getLocalBaseUrl = getLocalBaseUrl;
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
const configCore_1 = require("./configCore");
function cfg() {
    return vscode.workspace.getConfiguration("skylos");
}
function getSkylosBin() {
    return (0, configCore_1.resolveTrustedExecutablePath)(cfg().inspect("path"), "skylos");
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
    return (0, configCore_1.shouldRunWorkspaceAutomation)(vscode.workspace.isTrusted, cfg().get("runOnSave", true));
}
function isScanOnOpen() {
    return (0, configCore_1.shouldRunWorkspaceAutomation)(vscode.workspace.isTrusted, cfg().get("scanOnOpen", true));
}
function isRealtimeAIEnabled() {
    return cfg().get("enableRealtimeAI", false);
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
function getMaxProblems() {
    return cfg().get("maxProblems", 200);
}
function getMaxProblemsPerFile() {
    return cfg().get("maxProblemsPerFile", 50);
}
function getMaxTreeFindings() {
    return cfg().get("maxTreeFindings", 200);
}
function getMaxTreeFindingsPerFile() {
    return cfg().get("maxTreeFindingsPerFile", 25);
}
function getMaxDecorationsPerFile() {
    return cfg().get("maxDecorationsPerFile", 25);
}
function getEditorSignalLevel() {
    return cfg().get("editorSignalLevel", "quiet");
}
function getCodeLensMode() {
    return cfg().get("codeLensMode", "highValue");
}
function isShowDeadCodeInProblems() {
    return cfg().get("showDeadCodeInProblems", false);
}
function getCommandCenterLimit() {
    return cfg().get("commandCenterLimit", 10);
}
function isCommandCenterRefreshOnOpen() {
    return (0, configCore_1.shouldRunWorkspaceAutomation)(vscode.workspace.isTrusted, cfg().get("commandCenterRefreshOnOpen", false));
}
function isCommandCenterRefreshOnSave() {
    return (0, configCore_1.shouldRunWorkspaceAutomation)(vscode.workspace.isTrusted, cfg().get("commandCenterRefreshOnSave", false));
}
function getCommandCenterStateFile() {
    return cfg().get("commandCenterStateFile", "").trim();
}
function getAIProvider() {
    return cfg().get("aiProvider", "openai");
}
function getOpenAIBaseUrl() {
    const provider = getAIProvider();
    if (provider === "local") {
        return getLocalBaseUrl();
    }
    return cfg().get("openaiBaseUrl", "https://api.openai.com").replace(/\/+$/, "");
}
function getLocalBaseUrl() {
    return (cfg().get("localBaseUrl", "") || "").replace(/\/+$/, "");
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
    return isRealtimeAIEnabled() && cfg().get("streamingInline", false);
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
