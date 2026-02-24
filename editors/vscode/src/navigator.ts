import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import type { SkylosFinding } from "./types";

export class FindingNavigator {
  private findings: SkylosFinding[] = [];
  private index = -1;
  private disposables: vscode.Disposable[] = [];
  private flashDecoration: vscode.TextEditorDecorationType;

  constructor(private store: FindingsStore) {
    this.flashDecoration = vscode.window.createTextEditorDecorationType({
      backgroundColor: "rgba(250, 204, 21, 0.25)",
      isWholeLine: true,
    });

    this.disposables.push(
      this.flashDecoration,
      store.onDidChange(() => this.rebuild()),
      store.onDidChangeAI(() => this.rebuild()),
    );
    this.rebuild();
  }

  private rebuild(): void {
    this.findings = this.store
      .getAllFindings()
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    if (this.findings.length === 0) {
      this.index = -1;
    } else if (this.index >= this.findings.length) {
      this.index = 0;
    }
  }

  async next(): Promise<void> {
    if (this.findings.length === 0) {
      vscode.window.setStatusBarMessage("No findings to navigate", 3000);
      return;
    }
    this.index = (this.index + 1) % this.findings.length;
    await this.goTo(this.index);
  }

  async prev(): Promise<void> {
    if (this.findings.length === 0) {
      vscode.window.setStatusBarMessage("No findings to navigate", 3000);
      return;
    }
    this.index = (this.index - 1 + this.findings.length) % this.findings.length;
    await this.goTo(this.index);
  }

  private async goTo(idx: number): Promise<void> {
    const f = this.findings[idx];
    if (!f) return;

    const uri = vscode.Uri.file(f.file);
    const line = Math.max(0, f.line - 1);
    const range = new vscode.Range(line, 0, line, 0);

    const editor = await vscode.window.showTextDocument(uri, {
      selection: range,
      preserveFocus: false,
    });

    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

    const flashRange = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    editor.setDecorations(this.flashDecoration, [flashRange]);
    setTimeout(() => {
      editor.setDecorations(this.flashDecoration, []);
    }, 1500);

    const shortFile = f.file.split("/").pop() ?? f.file;
    vscode.window.setStatusBarMessage(
      `Finding ${idx + 1}/${this.findings.length}: [${f.ruleId}] ${f.message} in ${shortFile}`,
      5000,
    );
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }
}
