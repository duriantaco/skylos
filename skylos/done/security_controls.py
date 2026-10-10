"""Check removed security controls against complete, bounded source snapshots."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

from skylos.done.base import DoneError

if TYPE_CHECKING:
    from skylos.done.checks import CheckContext, CheckResult

RULE_ID = "SKY-L021"
_SOURCE_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".go",
    ".java",
    ".php",
    ".rs",
    ".dart",
}


def _read_sources(comparison, changed):
    before = comparison.base_text(changed.base_path)
    if changed.base_path is not None and before is None:
        raise DoneError(
            f"Could not read security controls at the base: {changed.base_path}"
        )
    if changed.status == "deleted":
        # The entire implementation is absent, rather than an open handler.
        return before, None
    after = comparison.head_text(changed.path)
    if after is None:
        raise DoneError(f"Could not read changed security controls: {changed.path}")
    return before, after


def _validate_python(before, after, path):
    for source, version in ((before, "base"), (after, "changed")):
        if source is None:
            continue
        try:
            ast.parse(source)
        except (SyntaxError, ValueError, TypeError, RecursionError) as exc:
            raise DoneError(
                f"Could not parse {version} Python security controls: {path}"
            ) from exc


def _control_findings(comparison, changed, before, after):
    from skylos.done.checks import Finding
    from skylos.rules.quality.regression import detect_security_regressions

    diff = comparison.file_diff(changed)
    if (before or "") != after and not re.search(r"^@@ -\d+", diff, re.MULTILINE):
        raise DoneError(f"Could not compare security controls: {changed.path}")
    # Preserve the original production filename when a source file moves;
    # moving it into a test directory does not waive its removed controls.
    scan_path = changed.base_path or changed.path
    detected = detect_security_regressions(
        diff,
        scan_path,
        old_source=before,
        new_source=after,
        project_root=comparison.root,
    )
    return [
        Finding(
            item.get("rule_id", RULE_ID),
            changed.path,
            item.get("line"),
            item.get("message", "A security control was removed"),
        )
        for item in detected
    ]


def check_security_controls(ctx: CheckContext) -> CheckResult:
    from skylos.done.checks import CheckResult

    comparison = ctx.comparison
    findings = []
    files_read = 0
    for changed in comparison.changed:
        suffixes = {
            PurePosixPath(path).suffix.lower()
            for path in (changed.path, changed.base_path)
            if path
        }
        if not suffixes.intersection(_SOURCE_SUFFIXES):
            continue
        before, after = _read_sources(comparison, changed)
        files_read += 1
        if after is None:
            continue
        if ".py" in suffixes:
            _validate_python(before, after, changed.path)
        findings.extend(_control_findings(comparison, changed, before, after))
    if findings:
        noun = "removal needs" if len(findings) == 1 else "removals need"
        summary = f"{len(findings)} security control {noun} attention"
    else:
        summary = f"No security control removals detected ({files_read} changed source file(s) compared)"
    return CheckResult(
        id="security_controls",
        rule=RULE_ID,
        status="fail" if findings else "pass",
        summary=summary,
        evidence={
            "files_read": files_read,
            "controls_removed": len(findings),
            "summary": summary[:120],
        },
        findings=findings,
    )
