import * as vscode from "vscode";
import { execFile, type ExecFileOptionsWithStringEncoding } from "child_process";
import * as path from "path";

type Finding = {
  message: string;
  file: string;
  line: number;
  col?: number;
  rule_id?: string;
  severity?: string;
};

type Report = {
  unused_functions?: any[];
  unused_imports?: any[];
  unused_classes?: any[];
  unused_variables?: any[];
  unused_parameters?: any[];
  secrets?: Finding[];
  danger?: Finding[];
};

const collection = vscode.languages.createDiagnosticCollection("skylos");
const out = vscode.window.createOutputChannel("skylos")

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(collection);
  out.appendLine("Skylos extension activated");

  context.subscriptions.push(
    vscode.commands.registerCommand("skylos.scan", runSkylos)
  );

  if (vscode.workspace.getConfiguration().get<boolean>("skylos.runOnSave")) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => {
        if (doc.languageId === "python") runSkylos();
      })
    );
  }

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { language: "python" },
      new IgnoreLineQuickFix(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}

export function deactivate() {
  collection.clear();
  collection.dispose();
}

async function runSkylos() {
  collection.clear();

  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) {
    vscode.window.showWarningMessage("Skylos: open a folder to scan.");
    return;
  }

  const cfg = vscode.workspace.getConfiguration();
  const bin = cfg.get<string>("skylos.path", "skylos");
  const conf = cfg.get<number>("skylos.confidence", 60);

  const excludes = cfg.get<string[]>("skylos.excludeFolders", []);
  const enableSecrets = cfg.get<boolean>("skylos.enableSecrets", true);
  const enableDanger = cfg.get<boolean>("skylos.enableDanger", true);

  const args = [ws.uri.fsPath, "--json", "-c", String(conf)];
  excludes.forEach(f => args.push("--exclude-folder", f));
  if (enableSecrets) args.push("--secrets");
  if (enableDanger) args.push("--danger");

  // console.log(`Running skylos with args: ${args.join(" ")}`);
  // console.log(`Working directory: ${ws.uri.fsPath}`);

  let stdout: string;
  try {
    const result = await runCommand(bin, args, { cwd: ws.uri.fsPath, encoding: "utf8" });
    stdout = result.stdout;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Skylos failed: ${msg}`);
  return;
}

  let report: Report;
  try {
    report = JSON.parse(stdout || "{}");
    // console.log("Parsed report keys:", Object.keys(report));
  } catch {
    vscode.window.showErrorMessage("Skylos returned invalid JSON.");
    return;
  }

  const byFile = toDiagnostics(report);
  // console.log(`Processing diagnostics for ${byFile.size} files`);

  for (const [reportedPath, diags] of byFile) {
    const filePath = path.isAbsolute(reportedPath)
      ? reportedPath
      : path.join(ws.uri.fsPath, reportedPath);
    const uri = vscode.Uri.file(filePath);
    collection.set(uri, diags);
  }

  const total = [...byFile.values()].reduce((n, d) => n + d.length, 0);
  vscode.window.setStatusBarMessage(`Skylos: ${total} findings`, 3500);

  vscode.window.showInformationMessage(
    total > 0 ? `Skylos found ${total} issue(s) (dead code, secrets, dangerous).` : "Skylos found no issues."
  );
}

function toDiagnostics(report: Report): Map<string, vscode.Diagnostic[]> {
  const map = new Map<string, vscode.Diagnostic[]>();

  const add = (f: Finding) => {
    const key = normalizePath(f.file);
    const start = new vscode.Position(Math.max(0, (f.line ?? 1) - 1), Math.max(0, (f.col ?? 0)));
    const range = new vscode.Range(start, start);
    const sev = toSeverity(f.severity);
    const msg = f.rule_id ? `[${f.rule_id}] ${f.message}` : f.message;
    const diag = new vscode.Diagnostic(range, msg, sev);
    
    diag.source = "skylos";
    diag.code = f.rule_id || "SKYLOS";

    const list = map.get(key) || [];
    list.push(diag);
    map.set(key, list);
  };

  const mapUnusedList = (arr?: any[]) => {
    (arr || []).forEach(u => {
      if (!u?.file) 
        return;
      add({
        message: `Unused ${u.type ?? "item"}: ${u.name ?? u.simple_name ?? ""}`,
        file: u.file,
        line: u.line ?? u.lineno ?? 1
      });
    });
  };

  mapUnusedList(report.unused_functions);
  mapUnusedList(report.unused_imports);
  mapUnusedList(report.unused_classes);
  mapUnusedList(report.unused_variables);
  mapUnusedList(report.unused_parameters);

  (report.secrets || []).forEach(add);
  (report.danger || []).forEach(add);

  return map;
}

function toSeverity(s?: string): vscode.DiagnosticSeverity {
  const t = (s || "").toUpperCase();
  if (t === "HIGH" || t === "CRITICAL") 
    return vscode.DiagnosticSeverity.Error;
  if (t === "MEDIUM") 
    return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function normalizePath(p: string) {
  return p.replace(/\\/g, "/");
}

function runCommand(
  cmd: string,
  args: string[],
  opts: ExecFileOptionsWithStringEncoding
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, opts, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve({ stdout, stderr });
    });
  });
}

class IgnoreLineQuickFix implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext) {
    const actions: vscode.CodeAction[] = [];
    for (const d of ctx.diagnostics) {
      if (d.source !== "skylos") 
        continue;
      
      const action = new vscode.CodeAction("Skylos: ignore on this line", vscode.CodeActionKind.QuickFix);
      const line = d.range.start.line;
      const text = doc.lineAt(line).text;
      const already = text.includes("# pragma: no skylos");
      const updated = already ? text : text + "  # pragma: no skylos";
      
      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(doc.uri, new vscode.Range(line, 0, line, text.length), updated);
      action.diagnostics = [d];
      actions.push(action);
      // kiv .. add "ignore entire file" action
    }
    return actions;
  }
}
