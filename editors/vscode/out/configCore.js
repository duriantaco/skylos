"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_OPENAI_BASE_URL = void 0;
exports.shouldWarnMissingLocalAI = shouldWarnMissingLocalAI;
exports.trustedConfigString = trustedConfigString;
exports.trustedConfigBoolean = trustedConfigBoolean;
exports.resolveTrustedExecutablePath = resolveTrustedExecutablePath;
exports.shouldRunWorkspaceAutomation = shouldRunWorkspaceAutomation;
exports.trustedAIProvider = trustedAIProvider;
exports.trustedOpenAIBaseUrl = trustedOpenAIBaseUrl;
exports.trustedLocalBaseUrl = trustedLocalBaseUrl;
function shouldWarnMissingLocalAI(options) {
    return options.realtimeAIEnabled
        && options.provider === "local"
        && !String(options.localBaseUrl ?? "").trim();
}
exports.DEFAULT_OPENAI_BASE_URL = "https://api.openai.com";
function trustedConfigValue(inspection, fallback) {
    const globalValue = inspection?.globalValue;
    if (typeof globalValue === "string") {
        const trimmed = globalValue.trim();
        if (trimmed)
            return trimmed;
    }
    else if (globalValue !== undefined) {
        return globalValue;
    }
    const defaultValue = inspection?.defaultValue;
    if (typeof defaultValue === "string") {
        const trimmed = defaultValue.trim();
        if (trimmed)
            return trimmed;
    }
    else if (defaultValue !== undefined) {
        return defaultValue;
    }
    return fallback;
}
function trustedConfigString(inspection, fallback = "") {
    return trustedConfigValue(inspection, fallback);
}
function trustedConfigBoolean(inspection, fallback = false) {
    return trustedConfigValue(inspection, fallback);
}
function resolveTrustedExecutablePath(inspection, fallback = "skylos") {
    return trustedConfigString(inspection, fallback);
}
function shouldRunWorkspaceAutomation(workspaceTrusted, enabled) {
    return workspaceTrusted && enabled;
}
function trustedAIProvider(inspection) {
    const provider = trustedConfigString(inspection, "openai");
    if (provider === "anthropic" || provider === "local")
        return provider;
    return "openai";
}
function trustedOpenAIBaseUrl(inspection) {
    const configured = trustedConfigString(inspection, exports.DEFAULT_OPENAI_BASE_URL);
    try {
        const url = new URL(configured);
        if (url.protocol !== "https:" || url.hostname !== "api.openai.com") {
            return exports.DEFAULT_OPENAI_BASE_URL;
        }
        return url.origin.replace(/\/+$/, "");
    }
    catch {
        return exports.DEFAULT_OPENAI_BASE_URL;
    }
}
function isLoopbackHost(hostname) {
    const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return (normalized === "localhost"
        || normalized === "::1"
        || normalized === "0:0:0:0:0:0:0:1"
        || normalized.startsWith("127."));
}
function trustedLocalBaseUrl(inspection) {
    const configured = trustedConfigString(inspection, "");
    if (!configured)
        return "";
    try {
        const url = new URL(configured);
        if ((url.protocol !== "http:" && url.protocol !== "https:") || !isLoopbackHost(url.hostname)) {
            return "";
        }
        return url.origin.replace(/\/+$/, "");
    }
    catch {
        return "";
    }
}
