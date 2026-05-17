"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.shouldWarnMissingLocalAI = shouldWarnMissingLocalAI;
exports.resolveTrustedExecutablePath = resolveTrustedExecutablePath;
exports.shouldRunWorkspaceAutomation = shouldRunWorkspaceAutomation;
function shouldWarnMissingLocalAI(options) {
    return options.realtimeAIEnabled
        && options.provider === "local"
        && !String(options.localBaseUrl ?? "").trim();
}
function resolveTrustedExecutablePath(inspection, fallback = "skylos") {
    const globalValue = inspection?.globalValue?.trim();
    if (globalValue)
        return globalValue;
    const defaultValue = inspection?.defaultValue?.trim();
    if (defaultValue)
        return defaultValue;
    return fallback;
}
function shouldRunWorkspaceAutomation(workspaceTrusted, enabled) {
    return workspaceTrusted && enabled;
}
