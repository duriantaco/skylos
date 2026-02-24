import * as vscode from "vscode";
import type { FindingsStore } from "./store";

export class SkylosFileDecorationProvider implements vscode.FileDecorationProvider {
  private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
  readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {
    this.disposables.push(
      this._onDidChangeFileDecorations,
      store.onDidChange(() => this._onDidChangeFileDecorations.fire(undefined)),
      store.onDidChangeAI(() => this._onDidChangeFileDecorations.fire(undefined)),
    );
  }

  provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
    const findings = this.store.getFindingsForFile(uri.fsPath);
    if (findings.length === 0) 
      return undefined;

    let hasCritical = false;
    let hasHigh = false;
    let hasMedium = false;

    for (const f of findings) {
      const s = f.severity.toUpperCase();
      if (s === "CRITICAL") hasCritical = true;
      else if (s === "HIGH") hasHigh = true;
      else if (s === "MEDIUM" || s === "WARN") hasMedium = true;
    }

    if (hasCritical) {
      return {
        badge: `${findings.length}`,
        tooltip: `Skylos: ${findings.length} issue(s) — CRITICAL`,
        color: new vscode.ThemeColor("errorForeground"),
      };
    }
    if (hasHigh) {
      return {
        badge: `${findings.length}`,
        tooltip: `Skylos: ${findings.length} issue(s) — HIGH`,
        color: new vscode.ThemeColor("editorWarning.foreground"),
      };
    }
    if (hasMedium) {
      return {
        badge: `${findings.length}`,
        tooltip: `Skylos: ${findings.length} issue(s)`,
        color: new vscode.ThemeColor("editorWarning.foreground"),
      };
    }

    return {
      badge: `${findings.length}`,
      tooltip: `Skylos: ${findings.length} issue(s)`,
      color: new vscode.ThemeColor("editorInfo.foreground"),
    };
  }

  register(): vscode.Disposable {
    return vscode.window.registerFileDecorationProvider(this);
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }
}
