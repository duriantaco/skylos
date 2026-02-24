"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AutoRemediator = void 0;
const vscode = require("vscode");
const ai_1 = require("./ai");
const config_1 = require("./config");
const scanner_1 = require("./scanner");
const SEVERITY_RANK = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    WARN: 1,
    LOW: 1,
    INFO: 0,
};
class AutoRemediator {
    constructor(store) {
        this.store = store;
    }
    async fixAll(options) {
        const apiKey = (0, config_1.getAIApiKey)();
        if (!apiKey) {
            vscode.window.showErrorMessage("Set an API key (skylos.openaiApiKey or skylos.anthropicApiKey) first.");
            return;
        }
        const minRank = SEVERITY_RANK[options.minSeverity] ?? 0;
        const allFindings = this.store.getAllFindings().filter((f) => {
            if (f.category === "dead_code")
                return false;
            const rank = SEVERITY_RANK[f.severity] ?? 0;
            return rank >= minRank;
        });
        if (allFindings.length === 0) {
            vscode.window.showInformationMessage("No findings match the selected severity level.");
            return;
        }
        const maxFindings = (0, config_1.getAutoFixMaxFindings)();
        const findings = allFindings.slice(0, maxFindings);
        if (allFindings.length > maxFindings) {
            vscode.window.showWarningMessage(`Limiting to ${maxFindings} findings (of ${allFindings.length}). Adjust skylos.autoFixMaxFindings to change.`);
        }
        const confirmLabel = options.dryRun ? "Dry Run" : "Fix All";
        const confirm = await vscode.window.showWarningMessage(`${confirmLabel}: ${findings.length} finding(s) across ${new Set(findings.map((f) => f.file)).size} file(s)?`, { modal: true }, confirmLabel, "Cancel");
        if (confirm !== confirmLabel)
            return;
        const provider = (0, config_1.getAIProvider)();
        const model = (0, config_1.getAIModel)();
        const results = [];
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: options.dryRun ? "Skylos: Dry Run" : "Skylos: Auto-Fix",
            cancellable: true,
        }, async (progress, token) => {
            const byFile = new Map();
            for (const f of findings) {
                const list = byFile.get(f.file) ?? [];
                list.push(f);
                byFile.set(f.file, list);
            }
            for (const list of byFile.values()) {
                list.sort((a, b) => b.line - a.line);
            }
            let processed = 0;
            for (const [filePath, fileFindings] of byFile) {
                if (token.isCancellationRequested)
                    break;
                let doc;
                try {
                    doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
                }
                catch {
                    for (const f of fileFindings) {
                        results.push({ finding: f, status: "skipped", error: "Could not open file" });
                    }
                    continue;
                }
                const langId = doc.languageId;
                for (const finding of fileFindings) {
                    if (token.isCancellationRequested)
                        break;
                    processed++;
                    progress.report({
                        message: `${processed}/${findings.length}: ${finding.ruleId} in ${filePath.split("/").pop()}`,
                        increment: (1 / findings.length) * 100,
                    });
                    try {
                        const result = await this.fixSingleFinding(doc, finding, langId, options.dryRun, provider, model, apiKey);
                        results.push(result);
                        if (!options.dryRun && result.status === "fixed") {
                            doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
                        }
                    }
                    catch (err) {
                        results.push({
                            finding,
                            status: "failed",
                            error: err instanceof Error ? err.message : String(err),
                        });
                    }
                    await new Promise((r) => setTimeout(r, 200));
                }
            }
        });
        this.showSummary(results, options.dryRun);
        if (!options.dryRun && results.some((r) => r.status === "fixed")) {
            vscode.commands.executeCommand("skylos.scan");
        }
    }
    async fixSingleFinding(doc, finding, langId, dryRun, provider, model, apiKey) {
        const content = doc.getText();
        const functions = (0, ai_1.extractFunctions)(content, langId);
        const line = Math.max(0, finding.line - 1);
        const targetFn = functions.find((fn) => line >= fn.startLine && line <= fn.endLine);
        if (!targetFn) {
            return { finding, status: "skipped", error: "Could not find enclosing function" };
        }
        const langLabel = langId === "typescriptreact" ? "TypeScript (React)" : langId;
        const fixPrompt = `Fix this ${langLabel} function.\nProblem: [${finding.ruleId}] ${finding.message}\n\nReturn ONLY the fixed function. No markdown. No explanation.\n\n${targetFn.content}`;
        let fixed;
        if (provider === "anthropic") {
            fixed = await (0, ai_1.callAnthropicStreaming)(apiKey, fixPrompt, model);
        }
        else {
            fixed = await (0, ai_1.callOpenAIStreaming)(apiKey, fixPrompt, model);
        }
        fixed = fixed.replace(/```\w*/g, "").replace(/```/g, "").trim();
        if (!fixed) {
            return { finding, status: "failed", error: "No fix returned from LLM" };
        }
        if (dryRun) {
            return {
                finding,
                status: "fixed",
                originalCode: targetFn.content,
                fixedCode: fixed,
            };
        }
        // Apply the edit
        const edit = new vscode.WorkspaceEdit();
        const range = new vscode.Range(targetFn.startLine, 0, targetFn.endLine, doc.lineAt(targetFn.endLine).text.length);
        edit.replace(doc.uri, range, fixed);
        const applied = await vscode.workspace.applyEdit(edit);
        return {
            finding,
            status: applied ? "fixed" : "failed",
            originalCode: targetFn.content,
            fixedCode: fixed,
            error: applied ? undefined : "WorkspaceEdit failed",
        };
    }
    async showSummary(results, dryRun) {
        const fixed = results.filter((r) => r.status === "fixed").length;
        const skipped = results.filter((r) => r.status === "skipped").length;
        const failed = results.filter((r) => r.status === "failed").length;
        if (dryRun) {
            const lines = [
                "# Skylos Auto-Fix — Dry Run Report\n",
                `**${fixed}** would be fixed, **${skipped}** skipped, **${failed}** failed\n`,
                "---\n",
            ];
            for (const r of results) {
                const f = r.finding;
                lines.push(`## [${f.ruleId}] ${f.message}`);
                lines.push(`**File:** ${f.file}:${f.line} | **Severity:** ${f.severity} | **Status:** ${r.status}\n`);
                if (r.status === "fixed" && r.originalCode && r.fixedCode) {
                    lines.push("### Before");
                    lines.push("```");
                    lines.push(r.originalCode);
                    lines.push("```\n");
                    lines.push("### After");
                    lines.push("```");
                    lines.push(r.fixedCode);
                    lines.push("```\n");
                }
                else if (r.error) {
                    lines.push(`> ${r.error}\n`);
                }
                lines.push("---\n");
            }
            const doc = await vscode.workspace.openTextDocument({
                language: "markdown",
                content: lines.join("\n"),
            });
            await vscode.window.showTextDocument(doc, { preview: true });
        }
        else {
            const msg = `Auto-Fix: ${fixed} fixed, ${skipped} skipped, ${failed} failed`;
            if (failed > 0) {
                vscode.window.showWarningMessage(msg);
            }
            else {
                vscode.window.showInformationMessage(msg);
            }
            scanner_1.out.appendLine(msg);
        }
    }
}
exports.AutoRemediator = AutoRemediator;
