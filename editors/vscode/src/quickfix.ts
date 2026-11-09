import * as vscode from "vscode";
import type { FindingsStore } from "./store";
import { getDocumentFilters } from "./types";
import { isDeadCodeRule } from "./findingCore";
import { fileIgnoreEdit, hasLineIgnore, lineIgnoreEdit, type IgnoreEdit } from "./suppressionCore";


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
      if (!diag.source?.startsWith("skylos"))
        continue;

      const line = diag.range.start.line;
      const lineText = document.lineAt(line).text;
      const ruleId = getRuleId(diag.code);
      const langId = document.languageId;
      const finding = this.store.getFindingsForFile(document.uri.fsPath)
        .find((candidate) =>
          candidate.line === line + 1
          && (candidate.ruleId === ruleId || candidate.legacyRuleId === ruleId),
        );

      let lineEdit: IgnoreEdit | undefined;
      if (!hasLineIgnore(lineText))
        lineEdit = lineIgnoreEdit(langId, ruleId, line, lineText);
      if (lineEdit) {
        const ignoreAction = new vscode.CodeAction(
          `Skylos: Ignore on this line`,
          vscode.CodeActionKind.QuickFix,
        );
        ignoreAction.edit = new vscode.WorkspaceEdit();
        ignoreAction.edit.insert(
          document.uri,
          new vscode.Position(lineEdit.line, lineEdit.column),
          lineEdit.text,
        );
        ignoreAction.diagnostics = [diag];
        actions.push(ignoreAction);
      }

      const firstLines = [0, 1].filter((index) => index < document.lineCount)
        .map((index) => document.lineAt(index).text);
      const fileEdit = fileIgnoreEdit(langId, firstLines);
      if (fileEdit) {
        const fileIgnore = new vscode.CodeAction(
          `Skylos: Ignore entire file`,
          vscode.CodeActionKind.QuickFix,
        );
        fileIgnore.edit = new vscode.WorkspaceEdit();
        fileIgnore.edit.insert(
          document.uri,
          new vscode.Position(fileEdit.line, fileEdit.column),
          fileEdit.text,
        );
        fileIgnore.diagnostics = [diag];
        actions.push(fileIgnore);
      }

      if (finding?.fixPatch) {
        const previewFix = new vscode.CodeAction(
          "Skylos: Preview engine fix",
          vscode.CodeActionKind.QuickFix,
        );
        previewFix.command = {
          title: "Preview engine fix",
          command: "skylos.previewSafeFix",
          arguments: [finding],
        };
        previewFix.diagnostics = [diag];
        actions.push(previewFix);
      }

      if (isDeadCodeRule(ruleId)) {
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

      if (diag.source.includes("ai-assist") || ruleId.startsWith("SKY-D") || ruleId.startsWith("SKY-S")) {
        const fixAI = new vscode.CodeAction(
          `Fix with AI Assist`,
          vscode.CodeActionKind.QuickFix,
        );
        fixAI.command = {
          title: "Fix with AI Assist",
          command: "skylos.fix",
          arguments: [
            document.uri.fsPath,
            diag.range,
            diag.message,
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

function getRuleId(code: vscode.Diagnostic["code"]): string {
  if (typeof code === "string" || typeof code === "number") {
    return String(code);
  }
  if (code && typeof code === "object" && "value" in code) {
    return String(code.value);
  }
  return "";
}
