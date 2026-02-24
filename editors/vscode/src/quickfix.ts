import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import { getDocumentFilters } from "./types";


export class SkylosQuickFixProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private store: FindingsStore) {}

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "skylos" && diag.source !== "skylos-ai") 
        continue;

      const line = diag.range.start.line;
      const lineText = document.lineAt(line).text;
      const ruleId = typeof diag.code === "string" ? diag.code : String(diag.code ?? "");
      const langId = document.languageId;

      const ignoreComment = getIgnoreComment(langId);

      if (!lineText.includes(ignoreComment)) {
        const ignoreAction = new vscode.CodeAction(
          `Skylos: Ignore on this line`,
          vscode.CodeActionKind.QuickFix,
        );
        ignoreAction.edit = new vscode.WorkspaceEdit();
        ignoreAction.edit.replace(
          document.uri,
          new vscode.Range(line, 0, line, lineText.length),
          lineText + "  " + ignoreComment,
        );
        ignoreAction.diagnostics = [diag];
        actions.push(ignoreAction);
      }

      const fileIgnore = new vscode.CodeAction(
        `Skylos: Ignore entire file`,
        vscode.CodeActionKind.QuickFix,
      );
      fileIgnore.edit = new vscode.WorkspaceEdit();
      const fileComment = getFileIgnoreComment(langId);
      fileIgnore.edit.insert(document.uri, new vscode.Position(0, 0), fileComment + "\n");
      fileIgnore.diagnostics = [diag];
      actions.push(fileIgnore);

      if (ruleId === "DEAD-IMPORT") {
        const removeAction = new vscode.CodeAction(
          `Remove unused import`,
          vscode.CodeActionKind.QuickFix,
        );
        removeAction.isPreferred = true;
        removeAction.edit = new vscode.WorkspaceEdit();
        const fullLine = new vscode.Range(line, 0, line + 1, 0);
        removeAction.edit.delete(document.uri, fullLine);
        removeAction.diagnostics = [diag];
        actions.push(removeAction);
      }

      if (ruleId === "DEAD-FUNC") {
        const removeFunc = new vscode.CodeAction(
          `Remove unused function`,
          vscode.CodeActionKind.QuickFix,
        );
        removeFunc.command = {
          title: "Remove function",
          command: "skylos.removeFunction",
          arguments: [document.uri, line],
        };
        removeFunc.diagnostics = [diag];
        actions.push(removeFunc);
      }

      if (ruleId.startsWith("DEAD-")) {
        const whitelist = new vscode.CodeAction(
          `Add to whitelist`,
          vscode.CodeActionKind.QuickFix,
        );
        whitelist.command = {
          title: "Add to whitelist",
          command: "skylos.addToWhitelist",
          arguments: [diag.message],
        };
        whitelist.diagnostics = [diag];
        actions.push(whitelist);
      }

      if (diag.source === "skylos-ai" || ruleId.startsWith("SKY-D") || ruleId.startsWith("SKY-S")) {
        const fixAI = new vscode.CodeAction(
          `Fix with AI`,
          vscode.CodeActionKind.QuickFix,
        );
        fixAI.command = {
          title: "Fix with AI",
          command: "skylos.fix",
          arguments: [
            document.uri.fsPath,
            diag.range,
            diag.message.replace("[AI] ", ""),
            false,
          ],
        };
        fixAI.diagnostics = [diag];
        actions.push(fixAI);
      }
    }

    return actions;
  }

  register(): vscode.Disposable {
    return vscode.languages.registerCodeActionsProvider(getDocumentFilters(), this, {
      providedCodeActionKinds: SkylosQuickFixProvider.providedCodeActionKinds,
    });
  }
}

function getIgnoreComment(langId: string): string {
  if (langId === "python") 
    return "# pragma: no skylos";
  return "// skylos-ignore";
}

function getFileIgnoreComment(langId: string): string {
  if (langId === "python") 
    return "# skylos-ignore-file";
  return "// skylos-ignore-file";
}
