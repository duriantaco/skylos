"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkylosScanError = void 0;
exports.buildScanArgs = buildScanArgs;
exports.buildScanCommand = buildScanCommand;
exports.formatCommand = formatCommand;
exports.shellQuote = shellQuote;
exports.buildScanErrorMessage = buildScanErrorMessage;
class SkylosScanError extends Error {
    constructor(kind, message, details = {}) {
        super(message);
        this.kind = kind;
        this.details = details;
        this.name = "SkylosScanError";
    }
}
exports.SkylosScanError = SkylosScanError;
function buildScanArgs(spec) {
    const args = [spec.target, "--json", "-c", String(spec.confidence)];
    for (const folder of spec.excludeFolders) {
        args.push("--exclude-folder", folder);
    }
    if (spec.enableSecrets)
        args.push("--secrets");
    if (spec.enableDanger)
        args.push("--danger");
    if (spec.enableQuality)
        args.push("--quality");
    if (spec.diffBase)
        args.push("--diff-base", spec.diffBase);
    return args;
}
function buildScanCommand(bin, spec) {
    const args = buildScanArgs(spec);
    return {
        args,
        display: formatCommand(bin, args),
    };
}
function formatCommand(bin, args) {
    return [bin, ...args].map(shellQuote).join(" ");
}
function shellQuote(value) {
    if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) {
        return value;
    }
    return `'${value.replace(/'/g, "'\\''")}'`;
}
function buildScanErrorMessage(error) {
    if (!(error instanceof SkylosScanError)) {
        return error instanceof Error ? error.message : String(error);
    }
    switch (error.kind) {
        case "missing_binary":
            return "Skylos executable was not found. Set `skylos.path` or install the Skylos CLI.";
        case "invalid_json":
            return "Skylos returned invalid JSON. Open the Skylos output channel for the raw command output.";
        case "nonzero_exit": {
            const code = error.details.exitCode ?? "?";
            return `Skylos exited with code ${code}. Open the Skylos output channel for details.`;
        }
        case "cancelled":
            return "Scan cancelled";
        case "unknown":
        default:
            return error.message;
    }
}
