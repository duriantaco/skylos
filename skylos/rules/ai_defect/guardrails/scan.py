"""Run the guardrail-tamper rules for ``skylos done`` and for diff-aware scans.

Both read the change the same way: ``skylos.done.base.open_comparison``
compares the merge base of the base ref (or HEAD when there is none) with
the working tree, so committed, staged, unstaged and untracked edits count,
and every Git call runs with repository-configured helpers disabled.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from skylos.rules.ai_defect.guardrails.core import (
    GUARDRAIL_CLASS,
    GUARDRAIL_KIND,
    MAX_TEXT_BYTES,
    FileChange,
    GuardrailOutcome,
)
from skylos.rules.ai_defect.guardrails.markers import (
    MARKER_HINT_RE,
    comment_style,
    detect_new_markers,
)
from skylos.rules.ai_defect.guardrails.reviewer import detect_reviewer_config_changes
from skylos.security.agent_instruction_paths import (
    is_ai_reviewer_config_path,
    is_shared_reviewer_instruction_path,
)

logger = logging.getLogger(__name__)

# Above this many changed files only reviewer files and at most this many
# code files are read for markers; the rest are counted as not read.
MAX_MARKER_FILES = 2000


# Test naming across languages (SKY-A118's own test check is Python and
# JS/TS-centred): FooTest.java, FooTests.swift, foo_spec.rb, FooSpec.scala,
# foo_test.go, foo.test.ts, foo.spec.ts, index.tst.ts (tstyche), test_foo.php;
# and test folders such as MyAppTests/ (Xcode, .NET) and spec/.
_TEST_FILE_RE = re.compile(
    r"(?:^test_|_test\.|\.test\.|\.tst\.|\.spec\.|_spec\.|_tests?\.|"
    r"(?<=[a-z0-9])(?:Tests?|Spec)\.[A-Za-z0-9]+$)"
)
_TEST_DIR_RE = re.compile(
    r"(?:^(?:tests?|specs?|__tests__|testing|e2e)$|(?<=[a-z0-9.])(?:Tests?|Specs?)$)"
)


def _is_test(path: str) -> bool:
    from skylos.done.answer_sites import _is_test_code

    if _is_test_code(path, set()):
        return True
    pure = PurePosixPath(path)
    return bool(_TEST_FILE_RE.search(pure.name)) or any(
        _TEST_DIR_RE.search(part) for part in pure.parts[:-1]
    )


def _is_generated(path: str, text: str | None) -> bool:
    from skylos.done.answer_sites import _is_generated as generated

    return generated(path, text)


def wanted(path: str | None) -> bool:
    """Whether either rule reads this path."""
    if not path:
        return False
    return (
        is_ai_reviewer_config_path(path)
        or is_shared_reviewer_instruction_path(path)
        or comment_style(path) is not None
    )


def detect_guardrail_tampering(
    changes: list[FileChange],
    *,
    is_test=_is_test,
    is_generated=_is_generated,
) -> GuardrailOutcome:
    outcome = GuardrailOutcome()
    reviewer, read, unparsed = detect_reviewer_config_changes(changes)
    reviewer_paths = {f.file for f in reviewer}
    outcome.findings.extend(reviewer)
    outcome.files_read += read
    outcome.unparsed.extend(unparsed)
    # Reviewer files are reported as a whole by A122, not marker by marker.
    code_changes = [
        change
        for change in changes
        if not is_ai_reviewer_config_path(change.path)
        and change.path not in reviewer_paths
    ]
    markers, files, in_tests = detect_new_markers(code_changes, is_test, is_generated)
    outcome.findings.extend(markers)
    outcome.files_read += files
    outcome.markers_in_tests = in_tests
    return outcome


def changes_from_comparison(
    comparison, only: set[str] | None = None
) -> list[FileChange]:
    """FileChanges for the paths either rule reads (``only``: git-root-relative
    paths to keep)."""
    changes: list[FileChange] = []
    marker_files = 0
    for changed in comparison.changed:
        paths = {p for p in (changed.path, changed.base_path) if p}
        if only is not None and not paths & only:
            continue
        if not any(wanted(p) for p in paths):
            continue
        reviewer = any(
            is_ai_reviewer_config_path(p) or is_shared_reviewer_instruction_path(p)
            for p in paths
        )
        if not reviewer:
            if changed.head_path is None:
                continue  # a deleted code file adds no marker
            marker_files += 1
            if marker_files > MAX_MARKER_FILES:
                continue
        head_text = (
            comparison.head_text(changed.head_path) if changed.head_path else None
        )
        if head_text is not None and len(head_text) > MAX_TEXT_BYTES:
            continue
        if not reviewer and not MARKER_HINT_RE.search(head_text or ""):
            continue  # no marker at head: nothing was added
        base_text = (
            comparison.base_text(changed.base_path) if changed.base_path else None
        )
        added = comparison.added_lines(changed) if changed.head_path else set()
        changes.append(
            FileChange(
                path=changed.path,
                status=changed.status,
                base_path=changed.base_path,
                base_text=base_text,
                head_text=head_text,
                added_lines=frozenset(added),
            )
        )
    return changes


# ---------------------------------------------------------------------------
# Diff-aware scans (analyzer)
# ---------------------------------------------------------------------------


def scan_git_changes(
    root: str | Path,
    changed_files,
    diff_base: str | None,
    *,
    project_ignore=(),
    scope=None,
) -> list[dict[str, Any]]:
    """AI-defect findings for the changed files of a diff-aware scan.

    ``changed_files`` None means every file the comparison changed under
    ``scope`` (the scan path or paths; default ``root``).
    """
    rules = {"SKY-A122", "SKY-A125"} - set(project_ignore or ())
    if not rules or (changed_files is not None and not changed_files):
        return []
    from skylos.done.base import DoneError, open_comparison

    project_root = Path(root).resolve()
    try:
        comparison = open_comparison(project_root, diff_base or None)
    except DoneError:
        return []
    git_root = comparison.root.resolve()
    if changed_files is None:
        targets = scope if isinstance(scope, (list, tuple)) else [scope or project_root]
        changed_files = [
            str(git_root / change.path)
            for change in comparison.changed
            for target in targets
            if _within(git_root / change.path, Path(os.path.abspath(target)))
            or (
                change.base_path
                and _within(git_root / change.base_path, Path(os.path.abspath(target)))
            )
        ]
    keep: set[str] = set()
    for item in changed_files:
        candidate = Path(item)
        if not candidate.is_absolute():
            candidate = project_root / candidate
        try:
            keep.add(Path(os.path.abspath(candidate)).relative_to(git_root).as_posix())
        except ValueError:
            continue
    changes = changes_from_comparison(comparison, only=keep)
    outcome = detect_guardrail_tampering(changes)
    findings = []
    for finding in outcome.findings:
        if finding.rule not in rules:
            continue
        absolute = git_root / finding.file
        try:
            file_label = absolute.relative_to(project_root).as_posix()
        except ValueError:
            file_label = finding.file
        findings.append(to_ai_defect(finding, file_label))
    return findings


def _within(path: Path, target: Path) -> bool:
    return path == target or (target.is_dir() and path.is_relative_to(target))


def to_ai_defect(finding, file_label: str) -> dict[str, Any]:
    return {
        "rule_id": finding.rule,
        "kind": GUARDRAIL_KIND,
        "severity": finding.severity,
        "message": finding.message,
        "file": file_label,
        "line": finding.line
        if isinstance(finding.line, int) and finding.line >= 1
        else 1,
        "col": 0,
        "category": "ai_defect",
        "defect_type": finding.kind,
        "vibe_category": GUARDRAIL_KIND,
        "metadata": {
            "guardrail_class": GUARDRAIL_CLASS[finding.rule],
            "change": finding.kind,
            "line_known": finding.line is not None,
            "signal_only": False,
            "blocking_recommended": False,
            **{
                k: v
                for k, v in finding.details.items()
                if k not in {"changed_settings"}
            },
        },
    }
