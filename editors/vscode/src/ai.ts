import * as vscode from "vscode";
import * as crypto from "crypto";
import type { FindingsStore } from "./store";
import type { SkylosFinding, AIIssue, FunctionBlock, AIProvider } from "./types";
import { getAIProvider, getAIApiKey, getAIModel, getPopupCooldownMs, isStreamingEnabled } from "./config";
import { out } from "./scanner";


export class AIAnalyzer {
  private debounceTimer: NodeJS.Timeout | undefined;
  private inFlight = false;
  private findingsCache = new Map<string, { issues: AIIssue[]; timestamp: number }>();
  private prevDocState = new Map<string, string>();
  private shownPopups = new Set<string>();
  private lastPopupTime = 0;
  private statusBar: { text: string } | undefined;
  private abortController: AbortController | undefined;
  private streamingManager: { showAnalyzing(editor: vscode.TextEditor, lines: number[]): void; streamIssueText(editor: vscode.TextEditor, line: number, message: string): void; clearAll(): void } | undefined;

  constructor(private store: FindingsStore) {}

  setStreamingManager(manager: { showAnalyzing(editor: vscode.TextEditor, lines: number[]): void; streamIssueText(editor: vscode.TextEditor, line: number, message: string): void; clearAll(): void }): void {
    this.streamingManager = manager;
  }

  setStatusBar(sb: { text: string }): void {
    this.statusBar = sb;
  }

  async maybeAnalyze(document: vscode.TextDocument): Promise<void> {
    const apiKey = getAIApiKey();
    if (!apiKey) 
      return;

    const currentContent = document.getText();
    const filePath = document.uri.fsPath;

    const prevContent = this.prevDocState.get(filePath);
    if (prevContent === currentContent) return;
    this.prevDocState.set(filePath, currentContent);

    const langId = document.languageId;
    const functions = extractFunctions(currentContent, langId);
    const changedFunctions = functions.filter((fn) => {
      const cached = this.findingsCache.get(fn.hash);
      return !cached || Date.now() - cached.timestamp > 60000;
    });

    if (changedFunctions.length === 0) 
      return;

    await this.analyzeChangedFunctions(document, changedFunctions);
  }

  private async analyzeChangedFunctions(
    document: vscode.TextDocument,
    functions: FunctionBlock[],
  ): Promise<void> {
    if (this.inFlight || functions.length === 0) 
      return;

    const provider = getAIProvider();
    const apiKey = getAIApiKey();
    if (!apiKey) 
      return;

    if (this.abortController) {
      this.abortController.abort();
      this.streamingManager?.clearAll();
    }
    this.abortController = new AbortController();
    const signal = this.abortController.signal;

    this.inFlight = true;
    const prevText = this.statusBar?.text ?? "";
    if (this.statusBar) this.statusBar.text = "$(sync~spin) Skylos AI...";

    try {
      const langId = document.languageId;
      const langLabel = langId === "typescriptreact" ? "TypeScript (React)" : langId;

      const codeToAnalyze = functions
        .map((fn) => `# Function: ${fn.name} (line ${fn.startLine + 1})\n${fn.content}`)
        .join("\n\n---\n\n");

      const editor = vscode.window.activeTextEditor;
      const useStreaming = isStreamingEnabled() && editor && editor.document === document;

      let issues: AIIssue[];

      if (useStreaming) {
        const startLines = functions.map((fn) => fn.startLine);
        this.streamingManager?.showAnalyzing(editor, startLines);

        const { StreamingJsonParser } = await import("./streaming");
        const streamedIssues: AIIssue[] = [];
        const parser = new StreamingJsonParser((issue) => {
          streamedIssues.push(issue);
          if (this.streamingManager && !signal.aborted) {
            const line = Math.max(0, issue.line - 1);
            this.streamingManager.streamIssueText(editor, line, issue.message);
          }
        });

        await callLLMStreamingWithCallback(apiKey, codeToAnalyze, provider, langLabel, (chunk) => {
          parser.feed(chunk);
        }, signal);

        issues = streamedIssues;
        this.streamingManager?.clearAll();
      } else {
        issues = await callLLMForIssues(apiKey, codeToAnalyze, provider, langLabel);
      }

      if (signal.aborted) 
        return;

      const now = Date.now();
      for (const fn of functions) {
        const fnIssues = issues.filter(
          (i) => i.line >= fn.startLine + 1 && i.line <= fn.endLine + 1,
        );
        this.findingsCache.set(fn.hash, { issues: fnIssues, timestamp: now });
      }

      const findings: SkylosFinding[] = issues.map((issue, idx) => ({
        id: `ai-${Date.now()}-${idx}`,
        ruleId: "AI",
        category: "ai" as const,
        severity: issue.severity === "error" ? ("HIGH" as const) : ("MEDIUM" as const),
        message: issue.message,
        file: document.uri.fsPath,
        line: issue.line,
        col: 0,
        source: "ai" as const,
      }));

      this.store.setAIFindings(document.uri.fsPath, findings);

      if (issues.length > 0) {
        const critical = issues.find((i) => i.severity === "error");
        if (critical) this.maybeShowPopup(document, critical);
      }

      if (this.statusBar) {
        this.statusBar.text = issues.length > 0 ? `$(eye) AI: ${issues.length}` : prevText;
      }
    } catch (err) {
      if (signal.aborted) {
        this.streamingManager?.clearAll();
        return;
      }
      out.appendLine(`AI Error: ${err}`);
      if (this.statusBar) this.statusBar.text = prevText;
    } finally {
      this.inFlight = false;
    }
  }

  private maybeShowPopup(document: vscode.TextDocument, issue: AIIssue): void {
    const cooldown = getPopupCooldownMs();
    const now = Date.now();

    if (now - this.lastPopupTime < cooldown) 
      return;

    const fingerprint = `${document.uri.fsPath}:${issue.line}:${issue.message.slice(0, 50)}`;
    if (this.shownPopups.has(fingerprint)) 
      return;

    this.shownPopups.add(fingerprint);
    this.lastPopupTime = now;

    vscode.window
      .showWarningMessage(`AI: ${issue.message}`, "Fix it", "Show me", "Dismiss")
      .then((action) => {
        if (action === "Show me") {
          const line = Math.max(0, issue.line - 1);
          const editor = vscode.window.activeTextEditor;
          if (editor) {
            editor.selection = new vscode.Selection(line, 0, line, 0);
            editor.revealRange(new vscode.Range(line, 0, line, 0));
          }
        } else if (action === "Fix it") {
          const line = Math.max(0, issue.line - 1);
          vscode.commands.executeCommand(
            "skylos.fix",
            document.uri.fsPath,
            new vscode.Range(line, 0, line, 0),
            issue.message,
            false,
          );
        }
      });
  }

  dispose(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
  }
}


export function extractFunctions(code: string, langId: string): FunctionBlock[] {
  if (langId === "python") 
    return extractPythonFunctions(code);
  if (langId === "go") 
    return extractGoFunctions(code);
  return extractTSFunctions(code);
}

function extractPythonFunctions(code: string): FunctionBlock[] {
  const lines = code.split("\n");
  const functions: FunctionBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const match = line.match(/^(\s*)(async\s+)?def\s+(\w+)\s*\(/);
    if (match) {
      const indent = match[1].length;
      const name = match[3];
      const startLine = i;
      let endLine = i;

      for (let j = i + 1; j < lines.length; j++) {
        const nextLine = lines[j];
        if (nextLine.trim() === "") {
          endLine = j;
          continue;
        }
        const nextIndent = nextLine.match(/^(\s*)/)?.[1].length ?? 0;
        if (nextIndent <= indent && nextLine.trim() !== "" && !nextLine.trim().startsWith("#")) {
          break;
        }
        endLine = j;
      }

      const content = lines.slice(startLine, endLine + 1).join("\n");
      const hash = crypto.createHash("md5").update(content).digest("hex");
      functions.push({ name, startLine, endLine, content, hash });
      i = endLine + 1;
    } else {
      i++;
    }
  }
  return functions;
}

function extractTSFunctions(code: string): FunctionBlock[] {
  const lines = code.split("\n");
  const functions: FunctionBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const funcMatch = line.match(/^(\s*)(export\s+)?(async\s+)?function\s+(\w+)/);
    const arrowMatch = line.match(/^(\s*)(export\s+)?(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(/);

    const name = funcMatch?.[4] ?? arrowMatch?.[4];
    if (name) {
      const startLine = i;
      let braceCount = 0;
      let foundBrace = false;
      let endLine = i;

      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === "{") {
            braceCount++;
            foundBrace = true;
          }
          if (ch === "}") braceCount--;
        }
        endLine = j;
        if (foundBrace && braceCount <= 0) 
          break;
      }

      const content = lines.slice(startLine, endLine + 1).join("\n");
      const hash = crypto.createHash("md5").update(content).digest("hex");
      functions.push({ name, startLine, endLine, content, hash });
      i = endLine + 1;
    } else {
      i++;
    }
  }
  return functions;
}

function extractGoFunctions(code: string): FunctionBlock[] {
  const lines = code.split("\n");
  const functions: FunctionBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const match = line.match(/^func\s+(\w+)/);
    if (match) {
      const name = match[1];
      const startLine = i;
      let braceCount = 0;
      let foundBrace = false;
      let endLine = i;

      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === "{") {
            braceCount++;
            foundBrace = true;
          }
          if (ch === "}") braceCount--;
        }
        endLine = j;
        if (foundBrace && braceCount <= 0) 
          break;
      }

      const content = lines.slice(startLine, endLine + 1).join("\n");
      const hash = crypto.createHash("md5").update(content).digest("hex");
      functions.push({ name, startLine, endLine, content, hash });
      i = endLine + 1;
    } else {
      i++;
    }
  }
  return functions;
}


async function callLLMForIssues(
  apiKey: string,
  code: string,
  provider: AIProvider,
  language: string,
): Promise<AIIssue[]> {
  const systemPrompt = `You analyze ${language} code for bugs. Return ONLY a JSON array.

Each issue: {"line": <number>, "message": "<brief>", "severity": "error"|"warning"}
If no issues: []

Only report REAL bugs:
- Crashes / exceptions
- Security issues
- Logic errors
- Undefined variables
- Type errors

Do NOT report: style, missing docs, naming conventions.`;

  let content: string;

  if (provider === "anthropic") {
    const model = getAIModel();
    const resp = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        system: systemPrompt,
        messages: [{ role: "user", content: code }],
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Anthropic API error: ${resp.status} - ${errText}`);
    }

    const data: any = await resp.json();
    content = data.content?.[0]?.text ?? "[]";
  } else {
    const model = getAIModel();
    const resp = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: code },
        ],
        temperature: 0,
        max_tokens: 1000,
      }),
    });

    if (!resp.ok) {
      throw new Error(`OpenAI API error: ${resp.status}`);
    }

    const data: any = await resp.json();
    content = data.choices?.[0]?.message?.content ?? "[]";
  }

  try {
    const cleaned = content.replace(/```json?/g, "").replace(/```/g, "").trim();
    return JSON.parse(cleaned);
  } catch {
    return [];
  }
}


export async function callLLMStreamingWithCallback(
  apiKey: string,
  code: string,
  provider: AIProvider,
  language: string,
  onChunk: (chunk: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const systemPrompt = `You analyze ${language} code for bugs. Return ONLY a JSON array.

Each issue: {"line": <number>, "message": "<brief>", "severity": "error"|"warning"}
If no issues: []

Only report REAL bugs:
- Crashes / exceptions
- Security issues
- Logic errors
- Undefined variables
- Type errors

Do NOT report: style, missing docs, naming conventions.`;

  const model = getAIModel();

  if (provider === "anthropic") {
    const resp = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        system: systemPrompt,
        messages: [{ role: "user", content: code }],
        stream: true,
      }),
      signal,
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Anthropic API error: ${resp.status} - ${errText}`);
    }

    const reader = resp.body?.getReader();
    if (!reader) throw new Error("No response body");

    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) 
        break;
      const text = decoder.decode(value);
      const lines = text.split("\n").filter((l) => l.startsWith("data: "));
      for (const line of lines) {
        const json = line.slice(6);
        try {
          const parsed = JSON.parse(json);
          if (parsed.type === "content_block_delta") {
            const delta = parsed.delta?.text;
            if (delta) onChunk(delta);
          }
        } catch {}
      }
    }
  } else {
    const resp = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: code },
        ],
        temperature: 0,
        stream: true,
      }),
      signal,
    });

    if (!resp.ok) 
      throw new Error(`OpenAI API error: ${resp.status}`);

    const reader = resp.body?.getReader();
    if (!reader) 
      throw new Error("No response body");

    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) 
        break;
      const text = decoder.decode(value);
      const lines = text.split("\n").filter((l) => l.startsWith("data: "));
      for (const line of lines) {
        const json = line.slice(6);
        if (json === "[DONE]") 
          continue;
        try {
          const parsed = JSON.parse(json);
          const delta = parsed.choices?.[0]?.delta?.content;
          if (delta) onChunk(delta);
        } catch {}
      }
    }
  }
}


export async function fixWithAI(
  filePath: string,
  range: vscode.Range,
  errorMsg: string,
  previewOnly: boolean,
): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
  const editor = await vscode.window.showTextDocument(doc, { preview: false });
  const content = doc.getText();
  const langId = doc.languageId;

  const functions = extractFunctions(content, langId);
  const targetFn = functions.find(
    (fn) => range.start.line >= fn.startLine && range.start.line <= fn.endLine,
  );

  const provider = getAIProvider();
  const apiKey = getAIApiKey();
  if (!apiKey) {
    const keyName = provider === "anthropic" ? "anthropicApiKey" : "openaiApiKey";
    vscode.window.showErrorMessage(`Set skylos.${keyName} first.`);
    return;
  }

  const langLabel = langId === "typescriptreact" ? "TypeScript (React)" : langId;

  let codeBlock: string;
  let blockStartLine: number;
  let blockEndLine: number;

  if (targetFn) {
    codeBlock = targetFn.content;
    blockStartLine = targetFn.startLine;
    blockEndLine = targetFn.endLine;
  } else {
    const line = range.start.line;
    blockStartLine = Math.max(0, line - 20);
    blockEndLine = Math.min(doc.lineCount - 1, line + 20);
    const lines: string[] = [];
    for (let i = blockStartLine; i <= blockEndLine; i++) {
      lines.push(doc.lineAt(i).text);
    }
    codeBlock = lines.join("\n");
  }

  const fixPrompt = `Fix this ${langLabel} code.\nProblem: ${errorMsg}\n\nReturn ONLY the fixed code. No markdown. No explanation.\n\n${codeBlock}`;
  const model = getAIModel();

  try {
    let fixed: string;
    if (provider === "anthropic") {
      fixed = await callAnthropicStreaming(apiKey, fixPrompt, model);
    } else {
      fixed = await callOpenAIStreaming(apiKey, fixPrompt, model);
    }

    fixed = fixed.replace(/```\w*/g, "").replace(/```/g, "").trim();
    if (!fixed) {
      vscode.window.showErrorMessage("No fix returned.");
      return;
    }

    const fixedDoc = await vscode.workspace.openTextDocument({
      language: langId,
      content: fixed,
    });
    await vscode.commands.executeCommand("vscode.diff", doc.uri, fixedDoc.uri, "Fix Preview");

    if (previewOnly) 
      return;

    const confirm = await vscode.window.showWarningMessage("Apply fix?", "Apply", "Cancel");
    if (confirm !== "Apply") 
      return;

    const freshDoc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
    const freshEditor = await vscode.window.showTextDocument(freshDoc, { preview: false });

    const blockRange = new vscode.Range(
      blockStartLine,
      0,
      blockEndLine,
      freshDoc.lineAt(blockEndLine).text.length,
    );
    await freshEditor.edit((eb) => eb.replace(blockRange, fixed));
    vscode.window.showInformationMessage("Fix applied!");
  } catch (e) {
    vscode.window.showErrorMessage(`Fix failed: ${e}`);
  }
}

export async function callOpenAIStreaming(apiKey: string, prompt: string, model: string): Promise<string> {
  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
      stream: true,
    }),
  });

  if (!resp.ok) throw new Error(`OpenAI API error: ${resp.status}`);

  const reader = resp.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let result = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const text = decoder.decode(value);
    const lines = text.split("\n").filter((l) => l.startsWith("data: "));
    for (const line of lines) {
      const json = line.slice(6);
      if (json === "[DONE]") continue;
      try {
        const parsed = JSON.parse(json);
        const delta = parsed.choices?.[0]?.delta?.content;
        if (delta) result += delta;
      } catch {}
    }
  }
  return result;
}

export async function callAnthropicStreaming(
  apiKey: string,
  prompt: string,
  model: string,
): Promise<string> {
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 2048,
      messages: [{ role: "user", content: prompt }],
      stream: true,
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Anthropic API error: ${resp.status} - ${errText}`);
  }

  const reader = resp.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let result = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const text = decoder.decode(value);
    const lines = text.split("\n").filter((l) => l.startsWith("data: "));
    for (const line of lines) {
      const json = line.slice(6);
      try {
        const parsed = JSON.parse(json);
        if (parsed.type === "content_block_delta") {
          const delta = parsed.delta?.text;
          if (delta) result += delta;
        }
      } catch {}
    }
  }
  return result;
}
