"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.shouldWarnMissingLocalAI = shouldWarnMissingLocalAI;
function shouldWarnMissingLocalAI(options) {
    return options.realtimeAIEnabled
        && options.provider === "local"
        && !String(options.localBaseUrl ?? "").trim();
}
