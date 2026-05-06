"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeAutomationLine = normalizeAutomationLine;
function normalizeAutomationLine(value) {
    const line = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(line) || line < 1)
        return 1;
    return Math.floor(line);
}
