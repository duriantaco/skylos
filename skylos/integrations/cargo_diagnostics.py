"""Read Cargo's newline-delimited compiler diagnostics for a local comparison."""

import hashlib
import io
import json

from .shadow import (
    MAX_NORMALIZED_FINDINGS,
    UnsupportedShadowReport,
    normalize_external_report,
    read_report_text,
)

_DEAD_CODE = {
    "dead_code",
    "dead_code_pub_in_binary",
    "unused_imports",
    "unused_variables",
}
_PERMISSIONS = {
    "permissions_set_readonly_false",
    "non_octal_unix_permissions",
}
_OTHER_EVENTS = {"compiler-artifact", "build-script-executed"}


def _locations(spans):
    for span in spans:
        primary = span.get("is_primary")
        if not isinstance(primary, bool):
            raise UnsupportedShadowReport(
                "Cargo diagnostic span must identify primary locations"
            )
        if not primary:
            continue
        file = span.get("file_name")
        start, end = span.get("line_start"), span.get("line_end")
        if (
            not isinstance(file, str)
            or not file
            or type(start) is not int
            or type(end) is not int
            or not 1 <= start <= end
        ):
            raise UnsupportedShadowReport(
                "Cargo diagnostic has an invalid primary location"
            )
        yield file, start, end, span.get("column_start"), span.get("column_end")


def _findings(message):
    if not isinstance(message, dict):
        raise UnsupportedShadowReport(
            "Cargo compiler-message must contain a diagnostic object"
        )
    description = message.get("message")
    if not isinstance(description, str) or not description:
        raise UnsupportedShadowReport("Cargo diagnostic must contain a message")
    level = message.get("level")
    spans = message.get("spans")
    if (
        level
        not in (
            "error",
            "warning",
            "note",
            "help",
            "failure-note",
            "error: internal compiler error",
            "ice",
        )
        or not isinstance(spans, list)
        or any(not isinstance(span, dict) for span in spans)
    ):
        raise UnsupportedShadowReport("Cargo diagnostic must contain a level and spans")
    code = message.get("code")
    if (
        "code" not in message
        or code is not None
        and (
            not isinstance(code, dict)
            or not isinstance(code.get("code"), str)
            or not code["code"]
        )
    ):
        raise UnsupportedShadowReport("Invalid Cargo diagnostic code")
    rule = code["code"] if code is not None else ""
    # Rust compiler lints are identifiers, optionally qualified by their tool.
    # Compile errors such as E0308 and diagnostics without a lint ID are not lints.
    namespace, separator, name = rule.rpartition("::")
    if (
        level not in ("warning", "error")
        or not name.isidentifier()
        or not name.islower()
        or (separator and not namespace.isidentifier())
    ):
        return
    tool = namespace if separator else "rustc"
    category = "QUALITY"
    if not separator and name in _DEAD_CODE:
        category = "DEAD_CODE"
    elif name in _PERMISSIONS:
        category = "SECURITY"
    locations = list(_locations(spans)) or [("", 0, 0, None, None)]
    for file, start, end, col, end_col in locations:
        if any(v is not None and type(v) is not int for v in (col, end_col)):
            raise UnsupportedShadowReport(
                "Cargo diagnostic has an invalid primary column"
            )
        yield (
            (rule, file, start, end, col, end_col, description),
            {
                "rule_id": rule,
                "source_tool": tool,
                "file_path": file,
                "line_number": start,
                "end_line": end,
                "message": description,
                "category": category,
                # A crate's lint policy can turn a style warning into a build error.
                "severity": "MEDIUM",
            },
        )


def load_cargo_report(path):
    """Normalize only diagnostics actually emitted by the selected Cargo build."""
    text = read_report_text(path)
    findings = {}
    finished = None
    saw_event = False
    compiler_failed = False
    digest = hashlib.sha256(b"[")
    for number, line in enumerate(io.StringIO(text), 1):
        if not line.strip():
            continue
        if finished is not None:
            raise UnsupportedShadowReport(
                f"Unexpected record after Cargo build-finished at line {number}"
            )
        try:
            event = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise UnsupportedShadowReport(
                f"Invalid Cargo JSON at line {number}"
            ) from exc
        if not isinstance(event, dict):
            raise UnsupportedShadowReport(f"Expected a Cargo event at line {number}")
        if saw_event:
            digest.update(b",")
        digest.update(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        saw_event = True
        reason = event.get("reason")
        if not isinstance(reason, str):
            raise UnsupportedShadowReport(
                f"Expected a Cargo event reason at line {number}"
            )
        if reason == "build-finished":
            finished = event.get("success")
            if type(finished) is not bool:
                raise UnsupportedShadowReport(
                    "Cargo build-finished must contain a boolean success field"
                )
            if finished and compiler_failed:
                raise UnsupportedShadowReport(
                    "Cargo reported success after a compiler error"
                )
        elif reason == "compiler-message":
            package = event.get("package_id", "")
            if not isinstance(package, str):
                raise UnsupportedShadowReport(
                    f"Invalid Cargo package ID at line {number}"
                )
            message = event.get("message")
            for key, finding in _findings(message):
                findings[package, key] = finding
                if len(findings) > MAX_NORMALIZED_FINDINGS:
                    raise UnsupportedShadowReport(
                        "Too many Cargo diagnostics to compare"
                    )
            if message["level"] in ("error", "ice", "error: internal compiler error"):
                compiler_failed = True
        elif reason not in _OTHER_EVENTS:
            raise UnsupportedShadowReport(f"Unrecognized Cargo event at line {number}")
    if not saw_event:
        raise UnsupportedShadowReport("Cargo report is empty")
    digest.update(b"]")
    normalized = normalize_external_report(
        {
            "tool": "Cargo",
            "complete": finished is True,
            "findings": list(findings.values()),
        }
    )
    normalized["format"] = "cargo"
    normalized["execution_successful"] = finished
    for tool in sorted({row["source_tool"] for row in findings.values()}):
        if tool not in normalized["tool_versions"]:
            normalized["tools"].append(tool)
            normalized["tool_versions"][tool] = []
    normalized["canonical_json_sha256"] = digest.hexdigest()
    return normalized
