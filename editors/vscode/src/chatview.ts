import * as vscode from "vscode";
import type { SkylosFinding, ChatMessage } from "./types";
import { getAIProvider, getAIApiKey, getAIModel } from "./config";
import { out } from "./scanner";

export class SkylosChatViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "skylosChatPanel";

  private view: vscode.WebviewView | undefined;
  private history: ChatMessage[] = [];
  private currentFinding: SkylosFinding | undefined;
  private currentCode = "";

  constructor(private context: vscode.ExtensionContext) {
    const saved = context.workspaceState.get<ChatMessage[]>("skylosChatHistory");
    if (saved) this.history = saved;
  }

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _ctx: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this.view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
    };

    webviewView.webview.html = this.getHtml();

    webviewView.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === "userMessage") {
        await this.handleUserMessage(msg.text);
      } else if (msg.type === "applyFix") {
        await this.applyCodeFix(msg.code, msg.language);
      }
    });

    if (this.history.length > 0) {
      webviewView.webview.postMessage({ type: "restoreHistory", messages: this.history });
    }
    if (this.currentFinding) {
      webviewView.webview.postMessage({ type: "setContext", finding: this.currentFinding });
    }
  }

  async setFindingContext(finding: SkylosFinding): Promise<void> {
    this.currentFinding = finding;

    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.file));
      const startLine = Math.max(0, finding.line - 21);
      const endLine = Math.min(doc.lineCount - 1, finding.line + 20);
      const lines: string[] = [];
      for (let i = startLine; i <= endLine; i++) {
        lines.push(doc.lineAt(i).text);
      }
      this.currentCode = lines.join("\n");
    } catch {
      this.currentCode = "";
    }

    this.view?.webview.postMessage({ type: "setContext", finding });
  }

  clearHistory(): void {
    this.history = [];
    this.currentFinding = undefined;
    this.currentCode = "";
    this.context.workspaceState.update("skylosChatHistory", undefined);
    this.view?.webview.postMessage({ type: "clearHistory" });
  }

  private async handleUserMessage(text: string): Promise<void> {
    const apiKey = getAIApiKey();
    if (!apiKey) {
      this.view?.webview.postMessage({
        type: "assistantMessage",
        text: "No API key configured. Set `skylos.openaiApiKey` or `skylos.anthropicApiKey` in settings.",
      });
      return;
    }

    this.history.push({ role: "user", content: text });

    const provider = getAIProvider();
    const model = getAIModel();

    let contextBlock = "";
    if (this.currentFinding) {
      const f = this.currentFinding;
      contextBlock = `\nCurrent context:
- File: ${f.file}
- Finding: [${f.ruleId}] ${f.message} at line ${f.line}
- Severity: ${f.severity}
- Code:\n\`\`\`\n${this.currentCode}\n\`\`\``;
    }

    const systemPrompt = `You are Skylos Security Copilot, an AI assistant for code security.
You help developers understand vulnerabilities, explain findings, and suggest fixes.
Wrap code fixes in markdown code blocks with the language specified.
Reference OWASP, CWE, PCI DSS when relevant. Be concise.${contextBlock}`;

    const recentHistory = this.history.slice(-10);

    try {
      this.view?.webview.postMessage({ type: "streamStart" });

      if (provider === "anthropic") {
        await this.streamAnthropic(apiKey, model, systemPrompt, recentHistory);
      } else {
        await this.streamOpenAI(apiKey, model, systemPrompt, recentHistory);
      }

      this.view?.webview.postMessage({ type: "streamEnd" });
      this.persistHistory();
    } catch (err) {
      out.appendLine(`Chat error: ${err}`);
      this.view?.webview.postMessage({
        type: "assistantMessage",
        text: `Error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  private async streamAnthropic(
    apiKey: string,
    model: string,
    systemPrompt: string,
    messages: ChatMessage[],
  ): Promise<void> {
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
        system: systemPrompt,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        stream: true,
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Anthropic API error: ${resp.status} - ${errText}`);
    }

    const reader = resp.body?.getReader();
    if (!reader) 
      throw new Error("No response body");

    const decoder = new TextDecoder();
    let fullResponse = "";

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
            if (delta) {
              fullResponse += delta;
              this.view?.webview.postMessage({ type: "streamChunk", text: delta });
            }
          }
        } catch {}
      }
    }

    this.history.push({ role: "assistant", content: fullResponse });
  }

  private async streamOpenAI(
    apiKey: string,
    model: string,
    systemPrompt: string,
    messages: ChatMessage[],
  ): Promise<void> {
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
          ...messages.map((m) => ({ role: m.role, content: m.content })),
        ],
        temperature: 0,
        stream: true,
      }),
    });

    if (!resp.ok) throw new Error(`OpenAI API error: ${resp.status}`);

    const reader = resp.body?.getReader();
    if (!reader) throw new Error("No response body");

    const decoder = new TextDecoder();
    let fullResponse = "";

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
          if (delta) {
            fullResponse += delta;
            this.view?.webview.postMessage({ type: "streamChunk", text: delta });
          }
        } catch {}
      }
    }

    this.history.push({ role: "assistant", content: fullResponse });
  }

  private async applyCodeFix(code: string, language?: string): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showErrorMessage("No active editor to apply fix to.");
      return;
    }

    if (!this.currentFinding) {
      await editor.edit((eb) => {
        eb.insert(editor.selection.active, code);
      });
      vscode.window.showInformationMessage("Code inserted at cursor.");
      return;
    }

    const doc = editor.document;
    const line = Math.max(0, this.currentFinding.line - 1);

    const { extractFunctions } = await import("./ai");
    const functions = extractFunctions(doc.getText(), doc.languageId);
    const targetFn = functions.find(
      (fn) => line >= fn.startLine && line <= fn.endLine,
    );

    if (targetFn) {
      const range = new vscode.Range(
        targetFn.startLine,
        0,
        targetFn.endLine,
        doc.lineAt(targetFn.endLine).text.length,
      );
      await editor.edit((eb) => eb.replace(range, code));
      vscode.window.showInformationMessage("Fix applied!");
    } else {
      await editor.edit((eb) => {
        eb.insert(new vscode.Position(line, 0), code + "\n");
      });
      vscode.window.showInformationMessage("Code inserted.");
    }
  }

  private persistHistory(): void {
    this.context.workspaceState.update("skylosChatHistory", this.history.slice(-20));
  }

  private getHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    background: var(--vscode-sideBar-background);
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  #context-bar {
    display: none;
    padding: 6px 10px;
    background: var(--vscode-editorWidget-background);
    border-bottom: 1px solid var(--vscode-widget-border);
    font-size: 11px;
  }
  #context-bar.visible { display: flex; align-items: center; gap: 6px; }
  #context-bar .severity {
    padding: 1px 6px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 10px;
  }
  .sev-critical, .sev-high { background: rgba(255,60,60,0.2); color: #ff6060; }
  .sev-medium, .sev-warn { background: rgba(255,200,40,0.2); color: #ddc030; }
  .sev-low, .sev-info { background: rgba(80,160,255,0.2); color: #60a0ff; }
  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .msg {
    max-width: 90%;
    padding: 8px 12px;
    border-radius: 8px;
    line-height: 1.4;
    word-wrap: break-word;
    white-space: pre-wrap;
  }
  .msg.user {
    align-self: flex-end;
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
  }
  .msg.assistant {
    align-self: flex-start;
    background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-widget-border);
  }
  .msg pre {
    background: var(--vscode-textCodeBlock-background);
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    margin: 6px 0;
    position: relative;
    font-family: var(--vscode-editor-font-family);
    font-size: 12px;
  }
  .msg code {
    font-family: var(--vscode-editor-font-family);
    background: var(--vscode-textCodeBlock-background);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12px;
  }
  .msg pre code { background: none; padding: 0; }
  .apply-btn {
    position: absolute;
    top: 4px;
    right: 4px;
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none;
    padding: 2px 8px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
  }
  .apply-btn:hover { background: var(--vscode-button-hoverBackground); }
  #input-area {
    padding: 8px;
    border-top: 1px solid var(--vscode-widget-border);
    display: flex;
    gap: 6px;
  }
  #input-area textarea {
    flex: 1;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border);
    border-radius: 4px;
    padding: 6px 8px;
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    resize: none;
    min-height: 32px;
    max-height: 120px;
  }
  #input-area button {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
    cursor: pointer;
    font-size: var(--vscode-font-size);
  }
  #input-area button:hover { background: var(--vscode-button-hoverBackground); }
</style>
</head>
<body>
  <div id="context-bar">
    <span class="severity" id="ctx-severity"></span>
    <span id="ctx-message"></span>
  </div>
  <div id="messages"></div>
  <div id="input-area">
    <textarea id="input" rows="1" placeholder="Ask about this finding..."></textarea>
    <button id="send">Send</button>
  </div>

<script>
  const vscode = acquireVsCodeApi();
  const messagesEl = document.getElementById('messages');
  const inputEl = document.getElementById('input');
  const sendBtn = document.getElementById('send');
  const contextBar = document.getElementById('context-bar');
  const ctxSeverity = document.getElementById('ctx-severity');
  const ctxMessage = document.getElementById('ctx-message');

  let currentAssistantBubble = null;
  let currentAssistantText = '';

  function renderMarkdown(text) {
    let html = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Code fences
    html = html.replace(/\`\`\`(\\w*)\n([\\s\\S]*?)\`\`\`/g, (_, lang, code) => {
      const langAttr = lang || '';
      return '<pre data-lang="' + langAttr + '"><button class="apply-btn" onclick="applyCode(this)">Apply Fix</button><code>' + code + '</code></pre>';
    });

    // Inline code
    html = html.replace(/\`([^\`]+)\`/g, '<code>$1</code>');

    // Bold
    html = html.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');

    // Line breaks
    html = html.replace(/\\n/g, '<br>');

    return html;
  }

  function addMessage(role, text) {
    const div = document.createElement('div');
    div.className = 'msg ' + role;
    if (role === 'assistant') {
      div.innerHTML = renderMarkdown(text);
    } else {
      div.textContent = text;
    }
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return div;
  }

  function send() {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = '';
    inputEl.style.height = '32px';
    addMessage('user', text);
    vscode.postMessage({ type: 'userMessage', text });
  }

  sendBtn.addEventListener('click', send);
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  });
  inputEl.addEventListener('input', () => {
    inputEl.style.height = '32px';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 120) + 'px';
  });

  window.applyCode = function(btn) {
    const pre = btn.parentElement;
    const code = pre.querySelector('code').textContent;
    const lang = pre.getAttribute('data-lang') || '';
    vscode.postMessage({ type: 'applyFix', code, language: lang });
  };

  window.addEventListener('message', (event) => {
    const msg = event.data;

    if (msg.type === 'streamStart') {
      currentAssistantText = '';
      currentAssistantBubble = document.createElement('div');
      currentAssistantBubble.className = 'msg assistant';
      messagesEl.appendChild(currentAssistantBubble);
    }

    if (msg.type === 'streamChunk' && currentAssistantBubble) {
      currentAssistantText += msg.text;
      currentAssistantBubble.innerHTML = renderMarkdown(currentAssistantText);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    if (msg.type === 'streamEnd') {
      currentAssistantBubble = null;
    }

    if (msg.type === 'assistantMessage') {
      addMessage('assistant', msg.text);
    }

    if (msg.type === 'setContext') {
      const f = msg.finding;
      const sevClass = 'sev-' + f.severity.toLowerCase();
      ctxSeverity.className = 'severity ' + sevClass;
      ctxSeverity.textContent = f.severity;
      ctxMessage.textContent = f.message;
      contextBar.classList.add('visible');
    }

    if (msg.type === 'restoreHistory') {
      messagesEl.innerHTML = '';
      for (const m of msg.messages) {
        addMessage(m.role, m.content);
      }
    }

    if (msg.type === 'clearHistory') {
      messagesEl.innerHTML = '';
      contextBar.classList.remove('visible');
    }
  });
</script>
</body>
</html>`;
  }
}
