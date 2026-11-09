import { isDeadCodeRule } from "./findingCore";

const JS_FAMILY = new Set(["typescript", "typescriptreact", "javascript", "javascriptreact"]);
const SECRET_RULE = "SKY-S101";
const RULE_ID = /^SKY-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$/;
const WHITELIST_NAME = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

export interface IgnoreEdit {
  line: number;
  column: number;
  text: string;
}

function directive(ruleId: string): string {
  if (!RULE_ID.test(ruleId) || isDeadCodeRule(ruleId) || ruleId.startsWith("SKY-E")) {
    return "skylos: ignore";
  }
  return `skylos: ignore[${ruleId}]`;
}

export function hasLineIgnore(lineText: string): boolean {
  return /skylos\s*:\s*ignore\b(?!-)|pragma\s*:\s*no\s+skylos|noqa\s*:\s*skylos/i.test(lineText);
}

export function lineIgnoreEdit(
  langId: string,
  ruleId: string,
  line: number,
  lineText: string,
): IgnoreEdit | undefined {
  if (langId === "python") {
    if (lineText.trimEnd().endsWith("\\")) return undefined;
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

export function fileIgnoreEdit(langId: string, lines: string[]): IgnoreEdit | undefined {
  if (lines.some((text) => /skylos\s*:\s*ignore-start/i.test(text))) return undefined;
  let line = 0;
  if (lines[0]?.startsWith("#!")) line = 1;
  if (langId === "python") {
    if (/^[ \t\f]*#.*?coding[:=]/.test(lines[line] ?? "")) line += 1;
    return { line, column: 0, text: "# skylos: ignore-start\n" };
  }
  if (JS_FAMILY.has(langId)) {
    return { line, column: 0, text: "// skylos: ignore-start\n" };
  }
  return undefined;
}

export function whitelistName(message: string): string | undefined {
  const match = message.match(/^Unused \w+:\s*(\S+)\s*$/);
  const name = match?.[1]?.split(".").pop();
  if (!name || !WHITELIST_NAME.test(name)) return undefined;
  return name;
}
