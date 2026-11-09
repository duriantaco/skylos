"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasLineIgnore = hasLineIgnore;
exports.lineIgnoreEdit = lineIgnoreEdit;
exports.fileIgnoreEdit = fileIgnoreEdit;
exports.whitelistName = whitelistName;
const findingCore_1 = require("./findingCore");
const JS_FAMILY = new Set(["typescript", "typescriptreact", "javascript", "javascriptreact"]);
const SECRET_RULE = "SKY-S101";
const RULE_ID = /^SKY-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$/;
const WHITELIST_NAME = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
function directive(ruleId) {
    if (!RULE_ID.test(ruleId) || (0, findingCore_1.isDeadCodeRule)(ruleId) || ruleId.startsWith("SKY-E")) {
        return "skylos: ignore";
    }
    return `skylos: ignore[${ruleId}]`;
}
function hasLineIgnore(lineText) {
    return /skylos\s*:\s*ignore\b(?!-)|pragma\s*:\s*no\s+skylos|noqa\s*:\s*skylos/i.test(lineText);
}
function lineIgnoreEdit(langId, ruleId, line, lineText) {
    if (langId === "python") {
        if (lineText.trimEnd().endsWith("\\"))
            return undefined;
        return { line, column: lineText.length, text: `  # ${directive(ruleId)}` };
    }
    if (JS_FAMILY.has(langId)) {
        if (!lineText.includes("//")) {
            return { line, column: lineText.length, text: `  // ${directive(ruleId)}` };
        }
        const column = lineText.length - lineText.trimStart().length;
        return { line, column, text: `/* ${directive(ruleId)} */ ` };
    }
    if (langId === "go" && ruleId === SECRET_RULE) {
        return { line, column: lineText.length, text: `  // skylos: ignore[${SECRET_RULE}]` };
    }
    return undefined;
}
function fileIgnoreEdit(langId, lines) {
    if (lines.some((text) => /skylos\s*:\s*ignore-start/i.test(text)))
        return undefined;
    let line = 0;
    if (lines[0]?.startsWith("#!"))
        line = 1;
    if (langId === "python") {
        if (/^[ \t\f]*#.*?coding[:=]/.test(lines[line] ?? ""))
            line += 1;
        return { line, column: 0, text: "# skylos: ignore-start\n" };
    }
    if (JS_FAMILY.has(langId)) {
        return { line, column: 0, text: "// skylos: ignore-start\n" };
    }
    return undefined;
}
function whitelistName(message) {
    const match = message.match(/^Unused \w+:\s*(\S+)\s*$/);
    const name = match?.[1]?.split(".").pop();
    if (!name || !WHITELIST_NAME.test(name))
        return undefined;
    return name;
}
