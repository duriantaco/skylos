import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import { getDocumentFilters } from "./types";
import { getCodeLensMode, getMaxDecorationsPerFile } from "./config";
import { isDeadCodeRule } from "./findingCore";

export class SkylosCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
  private disposables: vscode.Disposable[] = [];

  constructor(private store: FindingsStore) {
    this.disposables.push(
      store.onDidChange(() => this._onDidChangeCodeLenses.fire()),
      store.onDidChangeAI(() => this._onDidChangeCodeLenses.fire()),
      vscode.window.onDidChangeTextEditorSelection(() => {
        if (getCodeLensMode() === "activeLine") {
          this._onDidChangeCodeLenses.fire();
        }
      }),
    );
  }

  refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const lenses: vscode.CodeLens[] = [];
    const mode = getCodeLensMode();
    if (mode === "off") return lenses;

    const findings = this.store.getFindingsForFile(document.uri.fsPath, { max: getMaxDecorationsPerFile() });
    const activeEditor = vscode.window.activeTextEditor;
    const activeLine = activeEditor?.document.uri.fsPath === document.uri.fsPath
      ? activeEditor.selection.active.line
      : undefined;

    for (const f of findings) {
      const line = Math.max(0, f.line - 1);
      if (line >= document.lineCount) 
        continue;
      const isActiveLine = activeLine === line;
      if (mode === "activeLine" && !isActiveLine) {
        continue;
      }

      const range = new vscode.Range(line, 0, line, 0);
      const showAllActions = mode === "all" || mode === "activeLine";
      const showHighValueActions = showAllActions || mode === "highValue";

      if (showHighValueActions && (f.category === "security" || f.category === "ai")) {
        lenses.push(
          new vscode.CodeLens(range, {
            title: "Fix with AI Assist",
            command: "skylos.fix",
            arguments: [document.uri.fsPath, range, f.message, false],
          }),
        );
      }

      if (showHighValueActions && f.fixPatch) {
        lenses.push(
          new vscode.CodeLens(range, {
            title: "Preview Engine Fix",
            command: "skylos.previewSafeFix",
            arguments: [f],
          }),
        );
      }

      if (showAllActions && isDeadCodeRule(f.ruleId)) {
        lenses.push(
          new vscode.CodeLens(range, {
            title: "Ignore",
            command: "skylos.addToWhitelist",
            arguments: [f.message],
          }),
        );
      }

      if (showHighValueActions && f.source === "ai") {
        lenses.push(
          new vscode.CodeLens(range, {
            title: "\u2715 Dismiss",
            command: "skylos.dismissIssue",
            arguments: [document.uri.fsPath, f.line],
          }),
        );
      }
    }

    return lenses;
  }

  register(): vscode.Disposable {
    return vscode.languages.registerCodeLensProvider(getDocumentFilters(), this);
  }

  dispose(): void {
    this._onDidChangeCodeLenses.dispose();
    this.disposables.forEach((d) => d.dispose());
  }
}
