from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests
from rich.console import Console
from rich.markup import escape

from skylos.cicd.evidence import (
    EvidenceCard,
    build_evidence_card,
    build_evidence_cards,
    evidence_counts,
    evidence_label_title,
    sanitize_markdown_text,
    sanitize_untrusted_text,
)
from skylos.cicd.risk_passport import (
    build_risk_passport,
    format_risk_passport_markdown,
)
from skylos.core.file_discovery import find_git_root
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
    worktree_safe_git_command,
)
from skylos.reporting.assessment_display import (
    assessment_coverage_text,
    assessment_rows,
    maintainability_rows,
)
from skylos.rules.quality.regression import detect_security_regressions

console = Console()
logger = logging.getLogger(__name__)


def run_pr_review(
    results: dict,
    *,
    pr_number: int | None = None,
    repo: str | None = None,
    summary_only: bool = False,
    max_comments: int = 25,
    diff_base: str = "origin/main",
    grade: dict | None = None,
    previous_grade: dict | None = None,
    llm_findings: list[dict] | None = None,
    defense_report: dict | None = None,
    evidence_cards: bool = False,
) -> None:
    pr_number = pr_number or _detect_pr_number()
    repo = repo or os.environ.get("GITHUB_REPOSITORY")

    if not pr_number:
        console.print(
            "[yellow]Could not detect PR number. Use --pr to specify.[/yellow]"
        )
        return

    if not repo:
        console.print("[yellow]Could not detect repo. Use --repo to specify.[/yellow]")
        return

    if not _gh_available():
        console.print(
            "[bold red]gh CLI not found. Install: https://cli.github.com[/bold red]"
        )
        return

    try:
        review_root = _review_root_for_results(results)
    except ValueError as exc:
        console.print(f"[red]Skylos PR review unavailable: {exc}[/red]")
        raise SystemExit(2) from None

    if grade and previous_grade is None:
        previous_grade = _fetch_previous_grade(diff_base)

    if isinstance(results, dict) and diff_base:
        # Metrics the PR did not introduce or worsen are not review comments.
        from skylos.rules.quality.code_health import (
            partition_code_health,
            resolve_merge_base,
        )

        results = partition_code_health(
            dict(results),
            git_root=Path(review_root),
            base_commit=resolve_merge_base(diff_base, Path(review_root)),
        )

    all_findings = _flatten_findings(results)

    if llm_findings:
        all_findings = _merge_llm_findings(all_findings, llm_findings)

    # A deletion-only hunk has no new lines to attach an ordinary finding to.
    # Validate the diff even in summary-only mode before posting any report.
    try:
        changed_ranges = get_changed_line_ranges(
            diff_base,
            cwd=review_root,
            raise_on_error=True,
            include_deletion_anchors=False,
        )
        regression_findings = _detect_regressions_from_diff(
            diff_base, cwd=review_root, raise_on_error=True
        )
        comment_ranges = (
            get_changed_line_ranges(diff_base, cwd=review_root, raise_on_error=True)
            if regression_findings and not summary_only
            else changed_ranges
        )
    except ValueError as exc:
        console.print(f"[red]Skylos PR review unavailable: {exc}[/red]")
        raise SystemExit(2) from None

    if not summary_only:
        findings = filter_findings_to_diff(
            all_findings, changed_ranges, project_root=review_root
        )
        findings.extend(regression_findings)
    else:
        findings = all_findings + regression_findings

    all_findings.extend(regression_findings)
    provenance = _resolve_review_provenance(
        results, diff_base=diff_base, project_root=review_root
    )
    risk_passport = build_risk_passport(
        all_findings=all_findings,
        diff_findings=findings,
        provenance=provenance,
        defense_report=defense_report,
    )

    identity = _TokenIdentity()
    review_outcome = None
    if findings and not summary_only:
        review_outcome = _post_pr_review(
            findings,
            pr_number,
            repo,
            evidence_cards=evidence_cards,
            changed_ranges=comment_ranges,
            project_root=review_root,
            max_comments=max_comments,
            identity=identity,
        )
    # Past the inline-comment cap, or when posting the review failed, a
    # finding has no inline comment: the summary is where it is named.
    shown_inline = review_outcome.shown_inline if review_outcome else frozenset()
    left_unused = _left_unused_rows(
        all_findings, [f for f in findings if id(f) in shown_inline], review_root
    )

    summary_outcome = _post_summary_comment(
        all_findings,
        findings,
        pr_number,
        repo,
        grade=grade,
        previous_grade=previous_grade,
        assessment=results.get("assessment") if isinstance(results, dict) else None,
        evidence_cards=evidence_cards,
        risk_passport=risk_passport,
        identity=identity,
        left_unused=left_unused,
    )

    console.print(
        _review_outcome_line(pr_number, review_outcome, summary_outcome),
        soft_wrap=True,
    )


_LEFT_UNUSED_SCOPE = "dependency_impact"
_MAX_LEFT_UNUSED_ROWS = 20


def _left_unused_rows(
    all_findings: list[dict], inline_findings: list[dict], review_root
) -> list[tuple[str, str]]:
    """(what, where) for code the change left unused that no inline comment
    shows: its definition is off the changed lines, past the inline-comment
    cap, or the review posts no inline comments."""
    inline = {id(finding) for finding in inline_findings}
    rows = []
    for finding in all_findings:
        if finding.get("report_scope") != _LEFT_UNUSED_SCOPE or id(finding) in inline:
            continue
        file = finding.get("file", "")
        where = _project_relative_file(file, review_root) or file
        rows.append((finding.get("message", ""), f"{where}:{finding.get('line', '')}"))
    return rows


def _review_root_for_results(results: dict) -> Path:
    """Resolve Git diffs against the repository described by the scan report."""
    summary = results.get("analysis_summary")
    scope = summary.get("comparison_scope") if isinstance(summary, dict) else None
    if isinstance(scope, dict) and "repository_root" in scope:
        raw_root = scope["repository_root"]
        explicit_root = True
    elif "project_root" in results:
        raw_root = results["project_root"]
        explicit_root = True
    else:
        raw_root = Path.cwd()
        explicit_root = False

    if not isinstance(raw_root, (str, os.PathLike)) or not raw_root:
        raise ValueError("scan report has an invalid project root")
    root_path = Path(raw_root)
    if explicit_root and not root_path.is_absolute():
        raise ValueError("scan report project root must be absolute")
    try:
        target = root_path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("scan report project root is unavailable") from exc
    if not target.is_dir():
        raise ValueError("scan report project root is not a directory")
    git_root = find_git_root(target)
    if git_root is None:
        raise ValueError("scan report project root is not in a Git repository")
    return git_root


def _resolve_review_provenance(
    results: dict,
    *,
    diff_base: str,
    project_root: str | os.PathLike[str] | None = None,
) -> dict | None:
    provenance = results.get("provenance")
    if isinstance(provenance, dict):
        return provenance

    project_root = project_root or results.get("project_root") or "."
    try:
        from skylos.reporting.provenance import analyze_provenance

        return analyze_provenance(project_root, base_ref=diff_base).to_dict()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        logger.debug("Failed to resolve review provenance: %s", exc)
        return None


_UNTRACKED_WHOLE_FILE_END = 2**31 - 1


def _diff_root(cwd: str | os.PathLike[str] | None) -> Path:
    """Directory used to inspect a repository's filter configuration."""
    return Path(cwd) if cwd is not None else Path.cwd()


def _merge_base(base_ref: str, cwd) -> str | None:
    result = subprocess.run(
        read_only_git_command(["merge-base", base_ref, "HEAD"]),
        cwd=cwd,
        capture_output=True,
        text=True,
        env=read_only_git_environment(),
    )
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def get_untracked_files(cwd=None) -> list[str]:
    """Repository-relative paths of untracked, non-ignored files."""
    try:
        result = subprocess.run(
            read_only_git_command(
                ["ls-files", "--others", "--exclude-standard", "--full-name", "-z"]
            ),
            cwd=cwd,
            capture_output=True,
            text=True,
            env=read_only_git_environment(),
        )
    except FileNotFoundError:
        return []
    if result.returncode != 0:
        return []
    return [path for path in result.stdout.split("\0") if path]


def get_changed_line_ranges(
    base_ref: str = "origin/main",
    *,
    cwd: str | os.PathLike[str] | None = None,
    raise_on_error: bool = False,
    include_deletion_anchors: bool = True,
    include_working_tree: bool = False,
) -> list[dict]:
    """Changed line ranges since ``base_ref``.

    By default this compares ``base_ref...HEAD`` (committed changes only), which
    is what PR review comments need. With ``include_working_tree=True`` the
    comparison is from the merge base of ``base_ref`` and ``HEAD`` to the
    working tree, so committed, staged and unstaged edits are all included, and
    untracked (non-ignored) files count as fully changed.
    """
    try:
        if include_working_tree:
            merge_base = _merge_base(base_ref, cwd)
            if merge_base is None:
                if raise_on_error:
                    raise ValueError(
                        "Cannot compare changes: Git diff failed; check that the "
                        "base ref exists in the scanned repository"
                    )
                return []
            diff_args = ["diff", "--unified=0", merge_base]
        else:
            diff_args = ["diff", "--unified=0", f"{base_ref}...HEAD"]
        # A worktree diff hashes worktree content through the repository's
        # clean filters, so neutralize every configured filter/diff driver or
        # refuse the comparison rather than run attacker-defined commands.
        diff_cmd = worktree_safe_git_command(diff_args, _diff_root(cwd))
        if diff_cmd is None:
            if raise_on_error:
                raise ValueError(
                    "Cannot compare changes: the repository configures Git "
                    "content filters that could not be inspected safely"
                )
            return []
        result = subprocess.run(
            diff_cmd,
            cwd=cwd,
            capture_output=True,
            env=read_only_git_environment(),
            # Only file names and hunk headers are read: a changed file in
            # another encoding (or a binary git treats as text) must not
            # stop the scan.
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            if raise_on_error:
                raise ValueError(
                    "Cannot compare changes: Git diff failed; check that the "
                    "base ref exists in the scanned repository"
                )
            return []
    except FileNotFoundError as exc:
        if raise_on_error:
            raise ValueError("Cannot compare changes: git is not installed") from exc
        return []

    ranges = _parse_unified_diff(
        result.stdout, include_deletion_anchors=include_deletion_anchors
    )
    if include_working_tree:
        for path in get_untracked_files(cwd):
            ranges.append({"file": path, "start": 1, "end": _UNTRACKED_WHOLE_FILE_END})
    return ranges


def _parse_unified_diff(
    diff_output: str, *, include_deletion_anchors: bool = True
) -> list[dict]:
    entries = []
    current_file = None

    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        hunk_match = re.match(r"^@@ .+ \+(\d+)(?:,(\d+))? @@", line)
        if hunk_match and current_file:
            start = int(hunk_match.group(1))
            count = int(hunk_match.group(2) or 1)
            if count == 0 and not include_deletion_anchors:
                continue
            anchor = max(1, start)
            entries.append(
                {
                    "file": current_file,
                    "start": anchor,
                    "end": anchor if count == 0 else start + count - 1,
                }
            )

    return entries


def _get_per_file_diffs(
    base_ref: str = "origin/main",
    *,
    cwd: str | os.PathLike[str] | None = None,
    raise_on_error: bool = False,
) -> dict[str, str]:
    """Return a dict mapping file paths to their individual diff text."""
    try:
        diff_cmd = worktree_safe_git_command(
            ["diff", "--unified=3", f"{base_ref}...HEAD"], _diff_root(cwd)
        )
        if diff_cmd is None:
            if raise_on_error:
                raise ValueError(
                    "Cannot compare changes: the repository configures Git "
                    "content filters that could not be inspected safely"
                )
            return {}
        result = subprocess.run(
            diff_cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            env=read_only_git_environment(),
        )
        if result.returncode != 0:
            if raise_on_error:
                raise ValueError(
                    "Cannot compare changes: Git diff failed; check that the "
                    "base ref exists in the scanned repository"
                )
            return {}
    except FileNotFoundError as exc:
        if raise_on_error:
            raise ValueError("Cannot compare changes: git is not installed") from exc
        return {}

    file_diffs: dict[str, str] = {}
    current_file = None
    current_lines: list[str] = []

    for line in result.stdout.splitlines():
        if line.startswith("diff --git"):
            if current_file and current_lines:
                file_diffs[current_file] = "\n".join(current_lines)
            current_file = None
            current_lines = [line]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
            current_lines.append(line)
        else:
            current_lines.append(line)

    if current_file and current_lines:
        file_diffs[current_file] = "\n".join(current_lines)

    return file_diffs


def _detect_regressions_from_diff(
    base_ref: str = "origin/main",
    *,
    cwd: str | os.PathLike[str] | None = None,
    raise_on_error: bool = False,
) -> list[dict]:
    """Run security regression detection on the PR diff."""
    file_diffs = _get_per_file_diffs(base_ref, cwd=cwd, raise_on_error=raise_on_error)
    regression_findings: list[dict] = []

    for file_path, diff_text in file_diffs.items():
        findings = detect_security_regressions(diff_text, file_path)
        for f in findings:
            regression_findings.append(
                {
                    "file": f.get("file", ""),
                    "line": f.get("line", 1),
                    "message": f.get("message", ""),
                    "rule_id": f.get("rule_id", ""),
                    "severity": f.get("severity", "HIGH"),
                    "category": "security_regression",
                    "control_type": f.get("control_type", ""),
                    "kind": "security_regression",
                }
            )

    return regression_findings


def filter_findings_to_diff(
    findings: list[dict],
    changed_ranges: list[dict],
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> list[dict]:
    if not changed_ranges:
        return []

    ranges_by_file = {}
    for r in changed_ranges:
        file = (
            _project_relative_file(r["file"], project_root)
            if project_root is not None
            else r["file"]
        )
        if file is not None:
            ranges_by_file.setdefault(file, []).append((r["start"], r["end"]))

    filtered = []
    for finding in findings:
        if _location_overlaps_diff(
            finding.get("file", ""),
            finding.get("line", 0),
            finding.get("line", 0),
            ranges_by_file,
            project_root=project_root,
        ):
            filtered.append(finding)
            continue

        related_locations = finding.get("related_locations")
        if not isinstance(related_locations, list):
            continue

        for location in related_locations:
            if not isinstance(location, dict):
                continue
            if _location_overlaps_diff(
                location.get("file", ""),
                location.get("start_line", 0),
                location.get("end_line", location.get("start_line", 0)),
                ranges_by_file,
                project_root=project_root,
            ):
                filtered.append(finding)
                break

    return filtered


def _validated_location_span(
    file: object,
    start_line: object,
    end_line: object,
) -> tuple[str, int, int] | None:
    if not isinstance(file, str) or not file:
        return None
    if isinstance(start_line, bool) or not isinstance(start_line, int):
        return None
    if isinstance(end_line, bool) or not isinstance(end_line, int):
        return None
    if start_line < 1 or end_line < start_line:
        return None
    return file, start_line, end_line


def _same_location_file(left: str, right: str) -> bool:
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def _project_relative_file(
    file: str, project_root: str | os.PathLike[str]
) -> str | None:
    """Map a finding and a Git path to the same exact project-relative name."""
    if not isinstance(file, str) or not file:
        return None
    normalized = os.path.normpath(file)
    if os.path.isabs(normalized):
        try:
            normalized = os.path.relpath(normalized, os.path.abspath(project_root))
        except ValueError:
            return None
    normalized = posixpath.normpath(normalized.replace(os.sep, "/"))
    if normalized in (".", "..") or normalized.startswith("../"):
        return None
    return normalized


def _spans_overlap(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
) -> bool:
    return left_start <= right_end and right_start <= left_end


def _diff_ranges_for_file(
    file: str,
    ranges_by_file: dict[str, list[tuple[int, int]]],
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> list[tuple[int, int]]:
    if project_root is not None:
        relative_file = _project_relative_file(file, project_root)
        return ranges_by_file.get(relative_file, []) if relative_file else []
    exact = ranges_by_file.get(file)
    if exact:
        return exact
    for diff_file, ranges in ranges_by_file.items():
        if _same_location_file(file, diff_file):
            return ranges
    return []


def _location_overlaps_diff(
    file: object,
    start_line: object,
    end_line: object,
    ranges_by_file: dict[str, list[tuple[int, int]]],
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> bool:
    span = _validated_location_span(file, start_line, end_line)
    if span is None:
        return False
    normalized_file, normalized_start, normalized_end = span

    return any(
        _spans_overlap(normalized_start, normalized_end, changed_start, changed_end)
        for changed_start, changed_end in _diff_ranges_for_file(
            normalized_file, ranges_by_file, project_root=project_root
        )
    )


_SAFE_FINDING_METADATA_FIELDS = (
    "security_evidence",
    "review_verdict",
    "review_reason",
    "review_safety_proof",
    "review_proof_kind",
    "review_proof_lines",
)
_SAFE_VERIFICATION_FIELDS = ("verdict", "confidence", "reason")
_SAFE_SECURITY_EVIDENCE_TEXT_FIELDS = (
    "evidence_kind",
    "source",
    "sink",
    "confidence_reason",
    "test_hint",
    "fix_shape",
)
_SAFE_SECURITY_EVIDENCE_LIST_FIELDS = (
    "path",
    "guards_seen",
    "guards_missing",
    "analysis_diagnostics",
)
_SAFE_SECURITY_EVIDENCE_OPTIONS = frozenset({"httpOnly", "secure"})
_SAFE_SECURITY_EVIDENCE_OPTION_STATES = frozenset(
    {"absent", "false", "true", "unknown"}
)
_MAX_SECURITY_EVIDENCE_TEXT_LENGTH = 500
_MAX_SECURITY_EVIDENCE_LIST_ITEMS = 12


_DEAD_CODE_REVIEW_KINDS = {
    "unused_functions": ("SKY-U001", "Unused function"),
    "unused_imports": ("SKY-U002", "Unused import"),
    "unused_variables": ("SKY-U003", "Unused variable"),
    "unused_classes": ("SKY-U004", "Unused class"),
    "unused_parameters": ("SKY-U006", "Unused parameter"),
    "unused_files": ("SKY-E002", "Unused file"),
    "unused_fixtures": ("SKY-U000", "Unused fixture"),
    "unused_exports": ("SKY-U000", "Unused export"),
    "forgotten": ("SKY-U001", "Unused function"),
}


def _flatten_findings(results: dict) -> list[dict]:
    findings = []

    for category in (
        "danger",
        "reliability",
        "ai_defects",
        "quality",
        "secrets",
        "custom_rules",
    ):
        for f in results.get(category, []) or []:
            finding = {
                "file": f.get("file") or f.get("file_path") or "",
                "line": f.get("line") or f.get("line_number") or 1,
                "message": sanitize_untrusted_text(
                    f.get("message") or f.get("msg") or f.get("detail") or "",
                    max_length=4_000,
                    preserve_newlines=True,
                ),
                "rule_id": f.get("rule_id") or "",
                "severity": f.get("severity", "MEDIUM"),
                "category": category,
            }
            related_locations = f.get("related_locations")
            if isinstance(related_locations, list):
                finding["related_locations"] = related_locations
            _copy_safe_finding_metadata(f, finding)
            findings.append(finding)

    # "forgotten" may contain a function already listed in unused_functions.
    # Review it once, with the ordinary dead-code rule and source location.
    seen_dead_code = set()
    for section, (default_rule, label) in _DEAD_CODE_REVIEW_KINDS.items():
        for item in results.get(section, []) or []:
            if not isinstance(item, dict):
                continue
            file = item.get("file") or item.get("file_path") or ""
            line = item.get("line") or item.get("line_number") or 1
            name = item.get("name") or item.get("simple_name") or ""
            identity = (file, line, name)
            if identity in seen_dead_code:
                continue
            seen_dead_code.add(identity)
            message = (
                item.get("message")
                or item.get("msg")
                or item.get("detail")
                or (f"{label}: {name}" if name else label)
            )
            finding = {
                "file": file,
                "line": line,
                "message": sanitize_untrusted_text(
                    message, max_length=4_000, preserve_newlines=True
                ),
                "rule_id": item.get("rule_id") or default_rule,
                "severity": item.get("severity") or "LOW",
                "category": "dead_code",
            }
            if isinstance(item.get("confidence"), int):
                finding["confidence"] = item["confidence"]
            reason = item.get("dead_code_reason")
            if isinstance(reason, str) and reason:
                safe_reason = sanitize_untrusted_text(reason, max_length=1_000)
                finding["explanation"] = safe_reason
                finding["_review_reason"] = safe_reason
            # `--diff-mode impact`: in use at the base revision, unused now.
            if (
                item.get("report_scope") == _LEFT_UNUSED_SCOPE
                and item.get("change_status") == "introduced"
            ):
                finding["report_scope"] = _LEFT_UNUSED_SCOPE
            _copy_safe_finding_metadata(item, finding)
            findings.append(finding)

    return findings


def _copy_safe_finding_metadata(source: dict, target: dict) -> None:
    for key in (
        "_security_evidence",
        "_review_verdict",
        "_review_reason",
        "_review_safety_proof",
        "_review_proof_kind",
        "_review_proof_lines",
    ):
        value = source.get(key)
        if key == "_security_evidence":
            safe_evidence = _sanitize_security_evidence(value)
            if safe_evidence is not None:
                target[key] = safe_evidence
        elif isinstance(value, str):
            target[key] = sanitize_untrusted_text(value, max_length=1_000)
        elif key == "_review_proof_lines" and isinstance(value, list):
            target[key] = [
                sanitize_untrusted_text(item, max_length=500)
                for item in value[:12]
                if isinstance(item, str)
            ]

    symbol = source.get("symbol")
    if isinstance(symbol, str):
        target["symbol"] = sanitize_untrusted_text(symbol, max_length=500)

    confidence = source.get("confidence")
    if isinstance(confidence, int):
        target["confidence"] = confidence

    ai_authored = source.get("ai_authored")
    if isinstance(ai_authored, bool) or (
        "ai_authored" in source and ai_authored is None
    ):
        target["ai_authored"] = ai_authored

    if isinstance(source.get("ai_declared"), bool):
        target["ai_declared"] = source["ai_declared"]
    for key, allowed in {
        "attribution_level": {"recorded", "declared", "automation", "unknown"},
        "attribution_scope": {"line", "file", "none"},
        "evidence_source": {
            "git_ai",
            "agent_trace",
            "commit_metadata",
            "multiple",
            "none",
        },
    }.items():
        value = source.get(key)
        if isinstance(value, str) and value in allowed:
            target[key] = value

    ai_agent = source.get("ai_agent")
    if isinstance(ai_agent, str):
        target["ai_agent"] = sanitize_untrusted_text(ai_agent, max_length=120)

    verification = source.get("verification")
    if isinstance(verification, dict):
        safe_verification = {}
        for key, value in verification.items():
            if key not in _SAFE_VERIFICATION_FIELDS or not isinstance(
                value, (str, int, float, bool)
            ):
                continue
            safe_verification[key] = (
                sanitize_untrusted_text(value, max_length=1_000)
                if isinstance(value, str)
                else value
            )
        if safe_verification:
            target["verification"] = safe_verification

    metadata = source.get("metadata")
    if not isinstance(metadata, dict):
        return

    safe_metadata = {}
    for key, value in metadata.items():
        if key not in _SAFE_FINDING_METADATA_FIELDS:
            continue
        if key == "security_evidence":
            safe_evidence = _sanitize_security_evidence(value)
            if safe_evidence is not None:
                safe_metadata[key] = safe_evidence
        elif isinstance(value, str):
            safe_metadata[key] = sanitize_untrusted_text(value, max_length=1_000)
        elif key == "review_proof_lines" and isinstance(value, list):
            safe_metadata[key] = [
                sanitize_untrusted_text(item, max_length=500)
                for item in value[:12]
                if isinstance(item, str)
            ]
    if safe_metadata:
        target["metadata"] = safe_metadata
        if "security_evidence" in safe_metadata:
            target["_security_evidence"] = safe_metadata["security_evidence"]
        if "review_verdict" in safe_metadata:
            target["_review_verdict"] = safe_metadata["review_verdict"]
        if "review_reason" in safe_metadata:
            target["_review_reason"] = safe_metadata["review_reason"]
        if "review_safety_proof" in safe_metadata:
            target["_review_safety_proof"] = safe_metadata["review_safety_proof"]
        if "review_proof_kind" in safe_metadata:
            target["_review_proof_kind"] = safe_metadata["review_proof_kind"]
        if "review_proof_lines" in safe_metadata:
            target["_review_proof_lines"] = safe_metadata["review_proof_lines"]


def _sanitize_security_evidence(value: object) -> str | dict | None:
    if isinstance(value, str):
        return _sanitize_security_evidence_text(value)
    if not isinstance(value, dict):
        return None

    packet: dict = {}
    for key in _SAFE_SECURITY_EVIDENCE_TEXT_FIELDS:
        field_value = value.get(key)
        if isinstance(field_value, str):
            packet[key] = _sanitize_security_evidence_text(field_value)

    for key in _SAFE_SECURITY_EVIDENCE_LIST_FIELDS:
        field_value = value.get(key)
        if not isinstance(field_value, (list, tuple)):
            continue
        items = []
        for item in field_value[:_MAX_SECURITY_EVIDENCE_LIST_ITEMS]:
            if not isinstance(item, str):
                continue
            items.append(_sanitize_security_evidence_text(item))
        packet[key] = items

    options = value.get("options")
    if isinstance(options, dict):
        safe_options = {}
        for key in _SAFE_SECURITY_EVIDENCE_OPTIONS:
            state = options.get(key)
            if (
                isinstance(state, str)
                and state in _SAFE_SECURITY_EVIDENCE_OPTION_STATES
            ):
                safe_options[key] = state
        packet["options"] = safe_options

    analysis_complete = value.get("analysis_complete")
    if isinstance(analysis_complete, bool):
        packet["analysis_complete"] = analysis_complete

    return packet


def _sanitize_security_evidence_text(value: str) -> str:
    return sanitize_untrusted_text(
        value,
        max_length=_MAX_SECURITY_EVIDENCE_TEXT_LENGTH,
    )


def _merge_llm_findings(
    static_findings: list[dict], llm_findings: list[dict]
) -> list[dict]:
    llm_by_identity: dict[tuple[str, int, str], list[tuple[int, dict]]] = {}
    for index, finding in enumerate(llm_findings):
        identity = _review_finding_identity(finding)
        if identity is not None:
            llm_by_identity.setdefault(identity, []).append((index, finding))

    matched_indices: set[int] = set()
    for finding in static_findings:
        identity = _review_finding_identity(finding)
        candidates = llm_by_identity.get(identity, []) if identity else []
        if not candidates:
            continue
        llm_index, llm = candidates.pop(0)
        matched_indices.add(llm_index)
        for key in ("suggestion", "explanation", "vulnerable_code", "fixed_code"):
            if llm.get(key):
                finding[key] = llm[key]

    for index, llm in enumerate(llm_findings):
        if index not in matched_indices:
            category = str(llm.get("_category") or "security").strip().lower()
            if category in {"secret", "secrets", "security_regression"}:
                category = "security"
            finding = {
                "file": llm.get("file", ""),
                "line": llm.get("line", 0),
                "message": llm.get("message", ""),
                "rule_id": llm.get("rule_id", ""),
                "severity": llm.get("severity", "MEDIUM"),
                "category": category,
                "suggestion": llm.get("suggestion"),
                "explanation": llm.get("explanation"),
                "vulnerable_code": llm.get("vulnerable_code"),
                "fixed_code": llm.get("fixed_code"),
            }
            symbol = llm.get("symbol")
            if isinstance(symbol, str):
                finding["symbol"] = sanitize_untrusted_text(symbol, max_length=500)
            finding["_source"] = "llm"
            static_findings.append(finding)

    return static_findings


def _review_finding_identity(finding: object) -> tuple[str, int, str] | None:
    if not isinstance(finding, dict):
        return None
    file_path = _normalize_review_finding_path(finding.get("file"))
    rule_id = str(finding.get("rule_id") or "").strip().upper()
    line = finding.get("line")
    if isinstance(line, bool):
        return None
    try:
        line_number = int(line)
    except (TypeError, ValueError, OverflowError):
        return None
    if not file_path or not rule_id or line_number < 1:
        return None
    return file_path, line_number, rule_id


def _normalize_review_finding_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return ""
    normalized = posixpath.normpath(value.strip().replace("\\", "/"))
    cwd = posixpath.normpath(os.getcwd().replace("\\", "/"))
    if normalized.startswith(cwd + "/"):
        normalized = normalized[len(cwd) + 1 :]
    return "" if normalized in {"", "."} else normalized


_REGRESSION_SUGGESTIONS: dict[str, str] = {
    "auth": "Re-add the authentication decorator or dependency. Removing auth exposes the endpoint to unauthenticated access.",
    "csrf": "Re-enable CSRF protection. Without it, the endpoint is vulnerable to cross-site request forgery attacks.",
    "tls": "Re-enable TLS certificate verification (verify=True). Disabling it allows man-in-the-middle attacks.",
    "crypto": "Use a strong hash algorithm (SHA-256 or better). Weak hashes like MD5/SHA-1 are vulnerable to collision attacks.",
    "rate_limit": "Re-add rate limiting. Without it, the endpoint is vulnerable to brute-force and denial-of-service attacks.",
    "validation": "Re-add input validation or sanitization. Without it, the endpoint may be vulnerable to injection attacks.",
    "headers": "Re-add the security header or middleware. Security headers protect against XSS, clickjacking, and other attacks.",
    "encryption": "Re-add encryption. Removing it may expose sensitive data in plaintext.",
    "logging": "Re-add audit logging. Without it, security-relevant actions go untracked.",
    "sanitization": "Re-add output sanitization. Without it, user-supplied content may cause XSS or injection vulnerabilities.",
    "permission": "Re-add the permission check. Removing it may allow unauthorized access to restricted resources.",
}

_RULE_SUGGESTIONS: dict[str, str] = {
    "SKY-D201": "Replace `eval()` with `json.loads()`, `ast.literal_eval()`, or a safe parser. Never evaluate untrusted input.",
    "SKY-D203": "Replace `os.system()` with `subprocess.run()` with `shell=False`. Pass arguments as a list.",
    "SKY-D211": "Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE x = ?', (val,))` instead of f-strings.",
    "SKY-D212": "Sanitize input before passing to shell commands, or use `subprocess.run()` with `shell=False` and argument lists.",
    "SKY-D215": "Validate file paths against an allowed directory: `Path(path).resolve().relative_to(allowed_dir)`.",
    "SKY-D216": "Validate URLs against an allowlist of domains. Block internal IPs (`127.0.0.1`, `169.254.x.x`, `10.x.x.x`).",
    "SKY-D223": "Add the package to `requirements.txt` or `pyproject.toml`, or remove the import if unused.",
    "SKY-D290": "Avoid `pull_request_target` for untrusted code, or keep checkout/build steps isolated from privileged tokens.",
    "SKY-D291": "Declare `permissions: {}` at workflow scope, then grant minimal permissions per job.",
    "SKY-D292": "Pin third-party actions and reusable workflows to full 40-character commit SHAs.",
    "SKY-D293": "Set `persist-credentials: false` on `actions/checkout` unless the job needs to push commits.",
    "SKY-D294": "Move GitHub context values into `env:` and reference the quoted environment variable inside `run:`.",
    "SKY-D295": "Use GitHub-hosted runners, or require ephemeral isolated self-hosted runners for untrusted workflows.",
    "SKY-D296": "Pin container images by digest, for example `image@sha256:...`, instead of mutable tags.",
    "SKY-D297": "Replace `secrets: inherit` with an explicit `secrets:` map containing only required values.",
    "SKY-D298": "Reference only a specific secret name; avoid `toJSON(secrets)` and dynamic `secrets[...]` lookups.",
    "SKY-D299": "Add a job `environment:` and scope the secret to that GitHub environment.",
    "SKY-D300": "Write only static key/value pairs to `$GITHUB_ENV` or `$GITHUB_PATH`; avoid command-derived writes.",
    "SKY-D301": "Move the container registry password to a GitHub secret and reference it via `${{ secrets.NAME }}`.",
    "SKY-D302": "Add repository scoping and explicit `permission-*` inputs for `actions/create-github-app-token`.",
    "SKY-D303": "Use exact equality checks or `contains(fromJSON('[...]'), value)` instead of substring checks.",
    "SKY-D304": "Use event-specific sender IDs instead of spoofable actor-name checks for bot logic.",
    "SKY-D305": "Use an unfenced expression or a stripped block scalar such as `|-` for multiline `if:`.",
    "SKY-D306": "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS` from workflow, job, or step environment.",
    "SKY-D307": "Add a top-level `name:` to the workflow or action.",
    "SKY-D308": "Remove cache-aware actions from release workflows or disable cache restore/save in publishing jobs.",
    "SKY-D309": "Scope secrets to the individual step that needs them instead of workflow or job `env:`.",
    "SKY-D310": "Separate OIDC token issuance from repository-controlled build scripts; publish from prebuilt artifacts.",
    "SKY-D311": "Set `if-no-files-found: error` on `actions/upload-artifact` for required outputs.",
    "SKY-D312": "Use `npm ci --ignore-scripts` or an equivalent package-manager flag unless lifecycle scripts are required.",
    "SKY-D313": "Add `timeout-minutes` to privileged or release-like jobs.",
    "SKY-D350": "Add an actor gate to the agent job, for example `contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)`, or remove secrets and write permissions from it.",
    "SKY-D351": "Remove `*` from `allowed_non_write_users`, `allowed_bots` or `allow-users`; if outsiders must trigger it, keep the job read-only and give the agent no shell.",
    "SKY-D352": "Replace `Bash`, `--dangerously-skip-permissions`, `--yolo` or `danger-full-access` with a short allowlist of specific read-only commands.",
    "SKY-D353": "Stop interpolating `${{ github.event.* }}` text into the prompt; pass the issue or PR number and let the agent read the text as data.",
    "SKY-D354": "Upgrade to a fixed release: claude-code-action 1.0.74+, run-gemini-cli 0.1.22+, or Gemini CLI 0.39.1+.",
    "SKY-D314": "Pin GitLab CI `image:` and `services:` entries by digest, especially `docker:dind` services.",
    "SKY-D315": "Pin `include:project` entries to full commit SHAs and add `integrity:` to remote includes.",
    "SKY-D316": "Move literal secrets out of `.gitlab-ci.yml` and into protected, masked GitLab CI/CD variables.",
    "SKY-D317": "Do not pass merge request or ref metadata into `eval`, `sh -c`, `bash -c`, or interpreter `-c`/`-e` commands.",
    "SKY-D318": "Use TLS-enabled Docker-in-Docker, or avoid privileged Docker socket access in this job.",
    "SKY-D319": "Separate OIDC token issuance from repository-controlled scripts; publish from prebuilt artifacts.",
    "SKY-D320": "Remove cache restore from release/deploy jobs or use isolated release-only cache keys.",
    "SKY-D321": "Add `timeout:` to GitLab CI release, deploy, or OIDC jobs.",
    "SKY-D322": "Use static GitLab runner tags so untrusted refs cannot select privileged runners.",
    "SKY-D323": "Set an explicit `token:` for each GitLab CI secret when the job defines multiple `id_tokens`.",
    "SKY-D324": "Reject symlinks before writing, keep the resolved path inside the trusted root, or open with `O_NOFOLLOW`.",
    "SKY-D325": "Reject symlinks and non-regular files before reading, enforce root containment, and cap the read size.",
    "SKY-D326": "Manually validate archive members before extraction; reject absolute paths, `..`, symlinks, and hardlinks.",
    "SKY-D327": "Remove the upload of environment, token, or `.env*` data to external destinations.",
    "SKY-D328": "Download remote scripts to a file, inspect or verify them, then execute a pinned local copy only if trusted.",
    "SKY-D329": "Narrow destructive commands to explicit workspace paths and require human confirmation for broad deletes or resets.",
    "SKY-D330": "Remove `privileged: true` and grant only the specific Linux devices or capabilities the edge service requires.",
    "SKY-D331": "Avoid broad host control mounts; prefer specific read-only device mappings and never mount the Docker socket into edge services.",
    "SKY-D332": "Avoid `network_mode: host`; bind only required ports and keep robot or device control services off untrusted networks.",
    "SKY-D333": "Run the systemd unit as a dedicated non-root user and grant only the device access it needs.",
    "SKY-D334": "Move the systemd executable under a root-owned directory and lock down script permissions.",
    "SKY-D335": "Add systemd sandboxing such as `NoNewPrivileges=true`, `ProtectSystem=full`, and `PrivateTmp=true`.",
    "SKY-D336": "Reduce systemd capabilities, broad device access, or privileged container flags to the minimum required set.",
    "SKY-D337": "Use the default trusted package registry, or pin and document the approved internal registry.",
    "SKY-D338": "Do not read host credential stores or mount the host root filesystem into agent or CI commands.",
    "SKY-D339": "Avoid persistent profile, scheduler, global git, or package-manager configuration changes in agent or CI tasks.",
    "SKY-D340": "Move publish commands into an explicit release workflow with protected approvals.",
    "SKY-D341": "Pin package-managed tools and avoid auto-install execution flags such as `npx -y`.",
    "SKY-S101": "Move secrets to environment variables: `os.getenv('SECRET_KEY')`. Never hardcode credentials.",
}


def _format_review_comment(finding: dict) -> str:
    kind = finding.get("kind", "")
    raw_severity = str(finding.get("severity") or "MEDIUM").upper()
    severity = (
        raw_severity
        if raw_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        else "MEDIUM"
    )
    rule_id = finding.get("rule_id", "")
    message = sanitize_markdown_text(finding.get("message", ""), max_length=1_000)
    safe_rule_id = sanitize_markdown_text(rule_id, max_length=120)
    rule_str = f" `{safe_rule_id}`" if safe_rule_id else ""

    if kind == "security_regression":
        control_type = finding.get("control_type", "")
        control_label = (
            control_type.replace("_", " ").title() if control_type else "Unknown"
        )
        parts = [
            f"⚠️ **SECURITY REGRESSION**{rule_str} — {control_label}",
            "",
            message,
        ]
        suggestion = _REGRESSION_SUGGESTIONS.get(control_type)
        if suggestion:
            parts.extend(["", f"**Fix:** {sanitize_markdown_text(suggestion)}"])
    else:
        badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
            severity, "⚪"
        )
        parts = [f"{badge} **{severity}**{rule_str}", "", message]

        explanation = finding.get("explanation")
        if explanation:
            parts.extend(
                [
                    "",
                    f"**Why:** {sanitize_markdown_text(explanation, max_length=1_000)}",
                ]
            )

        vulnerable_code = finding.get("vulnerable_code")
        fixed_code = finding.get("fixed_code")

        if vulnerable_code and fixed_code:
            parts.extend(
                [
                    "",
                    "**Vulnerable code:**",
                    "```python",
                    sanitize_markdown_text(
                        vulnerable_code,
                        max_length=4_000,
                        preserve_newlines=True,
                    ),
                    "```",
                    "",
                    "**Fixed code:**",
                    "```python",
                    sanitize_markdown_text(
                        fixed_code,
                        max_length=4_000,
                        preserve_newlines=True,
                    ),
                    "```",
                ]
            )
        else:
            suggestion = finding.get("suggestion") or _RULE_SUGGESTIONS.get(rule_id)
            if suggestion:
                parts.extend(["", f"**Fix:** {sanitize_markdown_text(suggestion)}"])

    footer = "\n\n---\n_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • [Add to your repo](https://github.com/duriantaco/skylos#cicd)_"
    parts.append(footer)

    return "\n".join(parts)


def _format_evidence_card_comment(
    finding: dict, card: EvidenceCard | None = None
) -> str:
    card = card or build_evidence_card(finding)
    safe_rule_id = sanitize_markdown_text(card.rule_id, max_length=120)
    rule_str = f" `{safe_rule_id}`" if safe_rule_id else ""
    risk = (
        "dead code"
        if finding.get("category") == "dead_code"
        else {
            "security": "security finding",
            "security_regression": "security regression",
            "secret": "secret exposure",
            "reliability": "reliability issue",
            "quality": "quality issue",
            "dependency": "dependency issue",
            "custom": "custom rule match",
        }[card.kind]
    )
    raw_location = f"{card.file}:{card.line}" if card.file else str(card.line)
    location = sanitize_markdown_text(raw_location, max_length=600)

    parts = [
        f"**Risk: {evidence_label_title(card.label)} {risk}**{rule_str}",
        "",
        sanitize_markdown_text(card.title, max_length=120),
        "",
        f"**Location:** `{location}`",
        "",
        "**Evidence:**",
    ]

    for item in card.evidence or ("No extra evidence attached.",):
        parts.append(f"- {sanitize_markdown_text(item, max_length=500)}")

    if card.impact:
        parts.extend(
            ["", f"**Impact:** {sanitize_markdown_text(card.impact, max_length=500)}"]
        )

    if card.suggested_fix:
        parts.extend(
            [
                "",
                "**Suggested fix:** "
                f"{sanitize_markdown_text(card.suggested_fix, max_length=500)}",
            ]
        )

    parts.extend(["", f"**Confidence:** {card.confidence}%"])

    footer = "\n\n---\n_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • [Add to your repo](https://github.com/duriantaco/skylos#cicd)_"
    parts.append(footer)
    return "\n".join(parts)


def _to_relative_path(filepath: str) -> str:
    try:
        result = subprocess.run(
            read_only_git_command(["rev-parse", "--show-toplevel"]),
            capture_output=True,
            text=True,
            env=read_only_git_environment(),
        )
        if result.returncode == 0:
            root = result.stdout.strip()
            if filepath.startswith(root):
                return filepath[len(root) :].lstrip("/")
    except OSError as exc:
        logger.debug("Failed to resolve git root for review path: %s", exc)
    return filepath


# One summary comment per PR, edited in place. Inline comments carry a hidden
# per-finding key so a later run does not repeat them. Both markers are only
# trusted on comments written by a bot (GITHUB_TOKEN / GitHub App) or by the
# account the token belongs to, so a PR author cannot plant one to hijack the
# summary or hide an inline finding.
SUMMARY_MARKER = "<!-- skylos-review -->"
_SUMMARY_HEADING = "## Skylos Analysis Summary"
_SUMMARY_STATE_RE = re.compile(r"<!-- skylos-review-state: changed=(\d{1,9}) max=(\d{1,9}) -->")
_LEGACY_CHANGED_COUNT_RE = re.compile(r"\*\*(\d{1,9})\*\* issue\(s\) on changed lines")
_FINDING_KEY_RE = re.compile(r"<!-- skylos-finding:([0-9a-f]{20}) -->")
_LEGACY_INLINE_FOOTER = "Analyzed by [Skylos]"
_LEGACY_RULE_RE = re.compile(r"`(SKY-[A-Z0-9-]{1,40})`")
_GH_TIMEOUT_SECONDS = 60
_GH_PAGE_SIZE = 100
_GH_MAX_PAGES = 30


@dataclass
class _CommentOutcome:
    action: str  # created | updated | unchanged | skipped | failed
    error: str = ""
    new_inline: int = 0
    existing_inline: int = 0
    note: str = ""
    # id() of each finding with an inline comment after this run, posted now
    # or on an earlier push.
    shown_inline: frozenset = frozenset()


def _gh_error_text(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        raw = exc.stderr or exc.stdout or f"gh exited {exc.returncode}"
    elif isinstance(exc, subprocess.TimeoutExpired):
        raw = "gh timed out"
    else:
        raw = str(exc) or type(exc).__name__
    if not isinstance(raw, str):
        raw = str(raw)
    first = next((line.strip() for line in raw.splitlines() if line.strip()), "")
    return sanitize_untrusted_text(first or "unknown gh error", max_length=200)


def _gh_write(args: list[str], payload: dict | None = None):
    return subprocess.run(
        ["gh", *args],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        check=True,
        timeout=_GH_TIMEOUT_SECONDS,
    )


def _gh_list(endpoint: str) -> tuple[list[dict] | None, str]:
    """All items of a paginated GitHub list endpoint, or (None, error)."""
    items: list[dict] = []
    for page in range(1, _GH_MAX_PAGES + 1):
        try:
            result = subprocess.run(
                ["gh", "api", f"{endpoint}?per_page={_GH_PAGE_SIZE}&page={page}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=_GH_TIMEOUT_SECONDS,
            )
            batch = json.loads(result.stdout)
        except (subprocess.SubprocessError, OSError) as exc:
            return None, _gh_error_text(exc)
        except (TypeError, ValueError):
            return None, "unreadable gh api output"
        if not isinstance(batch, list):
            return None, "unexpected gh api output"
        items.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < _GH_PAGE_SIZE:
            return items, ""
    logger.debug("Stopped reading %s after %d pages", endpoint, _GH_MAX_PAGES)
    return items, ""


class _TokenIdentity:
    """Decides which existing comments Skylos may treat as its own."""

    def __init__(self) -> None:
        self._login: str | None = None
        self._looked_up = False

    def _self_login(self) -> str | None:
        if not self._looked_up:
            self._looked_up = True
            try:
                result = subprocess.run(
                    ["gh", "api", "/user"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=_GH_TIMEOUT_SECONDS,
                )
                login = json.loads(result.stdout).get("login")
                self._login = login if isinstance(login, str) and login else None
            except (subprocess.SubprocessError, OSError, TypeError, ValueError, AttributeError):
                # GITHUB_TOKEN and GitHub App tokens cannot read /user.
                self._login = None
        return self._login

    def owns(self, comment: dict) -> bool:
        user = comment.get("user")
        if not isinstance(user, dict):
            return False
        if user.get("type") == "Bot":
            return True
        login = user.get("login")
        return isinstance(login, str) and bool(login) and login == self._self_login()


def _inline_comment_key(path: str, line: int, finding: dict) -> str:
    rule_id = str(finding.get("rule_id") or "").strip().upper()
    parts = [path, str(line), rule_id]
    if not rule_id or finding.get("category") == "dead_code":
        # Several unused names can share one line and one dead-code rule.
        parts.append(" ".join(str(finding.get("message") or "").split()))
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return digest[:20]


def _existing_inline_identities(
    comments: list[dict], identity: _TokenIdentity
) -> tuple[set[str], set[tuple[str, int, str]]]:
    keys: set[str] = set()
    legacy: set[tuple[str, int, str]] = set()
    for comment in comments:
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        found_keys = _FINDING_KEY_RE.findall(body)
        is_legacy = not found_keys and _LEGACY_INLINE_FOOTER in body
        if not (found_keys or is_legacy) or not identity.owns(comment):
            continue
        keys.update(found_keys)
        if is_legacy:
            path, line = comment.get("path"), comment.get("line")
            rule = _LEGACY_RULE_RE.search(body)
            if isinstance(path, str) and isinstance(line, int) and rule:
                legacy.add((path, line, rule.group(1)))
    return keys, legacy


def _post_pr_review(
    findings: list[dict],
    pr_number: int,
    repo: str,
    *,
    evidence_cards: bool = False,
    changed_ranges: list[dict] | None = None,
    project_root: str | os.PathLike[str] | None = None,
    max_comments: int | None = None,
    identity: _TokenIdentity | None = None,
) -> _CommentOutcome:
    comments = []
    seen_keys: set[str] = set()
    finding_keys: list[tuple[int, str]] = []
    for f in findings:
        if not f.get("file") or not f.get("line"):
            continue
        comment_file, comment_line = _review_comment_location(
            f, changed_ranges, project_root=project_root
        )
        path = _to_relative_path(comment_file)
        key = _inline_comment_key(path, comment_line, f)
        finding_keys.append((id(f), key))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        body = (
            _format_evidence_card_comment(f)
            if evidence_cards
            else _format_review_comment(f)
        )
        comments.append(
            {
                "path": path,
                "line": comment_line,
                "body": f"{body}\n<!-- skylos-finding:{key} -->",
                "_key": key,
                # Legacy location/rule identities cannot distinguish unused
                # symbols on the same line. Emit keyed dead-code comments
                # once rather than treating another symbol as already shown.
                "_legacy": (
                    None
                    if f.get("category") == "dead_code"
                    else (path, comment_line, str(f.get("rule_id") or "").upper())
                ),
            }
        )

    if not comments:
        return _CommentOutcome("skipped")

    existing, list_error = _gh_list(f"/repos/{repo}/pulls/{pr_number}/comments")
    note = ""
    if existing is None:
        # Better one possible repeat than a silently missing finding.
        note = f"could not read existing inline comments ({list_error})"
        posted_keys, legacy = set(), set()
    else:
        posted_keys, legacy = _existing_inline_identities(
            existing, identity or _TokenIdentity()
        )

    new_comments = [
        c
        for c in comments
        if c["_key"] not in posted_keys and c["_legacy"] not in legacy
    ]
    already = len(comments) - len(new_comments)
    existing_keys = {c["_key"] for c in comments} - {c["_key"] for c in new_comments}

    def shown(keys) -> frozenset:
        return frozenset(fid for fid, key in finding_keys if key in keys)

    if max_comments is not None:
        # The cap is per PR, not per push: findings that already have an
        # inline comment use up slots, so an unchanged PR gets no new review.
        new_comments = new_comments[: max(0, max_comments - already)]
    if not new_comments:
        return _CommentOutcome(
            "unchanged",
            existing_inline=already,
            note=note,
            shown_inline=shown(existing_keys),
        )

    payload = {
        "body": (
            f"Skylos found {len(new_comments)} new issue(s) on changed lines.\n\n"
            "---\n"
            "_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • "
            "[Set up in 30 seconds](https://github.com/duriantaco/skylos#cicd)_"
        ),
        "event": "COMMENT",
        "comments": [
            {"path": c["path"], "line": c["line"], "body": c["body"]}
            for c in new_comments
        ],
    }

    try:
        _gh_write(
            [
                "api",
                "--method",
                "POST",
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                "--input",
                "-",
            ],
            payload,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return _CommentOutcome(
            "failed",
            error=_gh_error_text(exc),
            note=note,
            shown_inline=shown(existing_keys),
        )
    return _CommentOutcome(
        "created",
        new_inline=len(new_comments),
        existing_inline=already,
        note=note,
        shown_inline=shown(existing_keys | {c["_key"] for c in new_comments}),
    )


def _related_location_spans(finding: dict) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    related_locations = finding.get("related_locations")
    if not isinstance(related_locations, list):
        return spans
    for location in related_locations:
        if not isinstance(location, dict):
            continue
        start_line = location.get("start_line")
        span = _validated_location_span(
            location.get("file"),
            start_line,
            location.get("end_line", start_line),
        )
        if span is not None:
            spans.append(span)
    return spans


def _changed_overlap_line(
    span: tuple[str, int, int],
    changed_ranges: list[dict],
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> int | None:
    file, start_line, end_line = span
    for changed in changed_ranges:
        changed_start = changed.get("start") or 0
        changed_end = changed.get("end") or changed_start
        changed_span = _validated_location_span(
            str(changed.get("file", "")),
            changed_start,
            changed_end,
        )
        if changed_span is None:
            continue
        if project_root is not None:
            relative_file = _project_relative_file(file, project_root)
            matches_file = relative_file is not None and relative_file == (
                _project_relative_file(changed_span[0], project_root)
            )
        else:
            matches_file = _same_location_file(file, changed_span[0])
        if not matches_file:
            continue
        if _spans_overlap(start_line, end_line, changed_span[1], changed_span[2]):
            return max(start_line, changed_span[1])
    return None


def _review_comment_location(
    finding: dict,
    changed_ranges: list[dict] | None,
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> tuple[str, int]:
    primary = (str(finding.get("file", "")), int(finding.get("line") or 1))
    if not changed_ranges:
        return primary

    candidates = [(primary[0], primary[1], primary[1])]
    candidates.extend(_related_location_spans(finding))
    for candidate in candidates:
        comment_line = _changed_overlap_line(
            candidate, changed_ranges, project_root=project_root
        )
        if comment_line is not None:
            return candidate[0], comment_line
    return primary


def _post_summary_comment(
    all_findings: list[dict],
    diff_findings: list[dict],
    pr_number: int,
    repo: str,
    *,
    grade: dict | None = None,
    previous_grade: dict | None = None,
    assessment: dict | None = None,
    evidence_cards: bool = False,
    risk_passport: dict | None = None,
    identity: _TokenIdentity | None = None,
    left_unused: list[tuple[str, str]] | None = None,
) -> _CommentOutcome:
    left_unused = left_unused or []
    existing_comments, list_error = _gh_list(
        f"/repos/{repo}/issues/{pr_number}/comments"
    )
    previous = (
        _previous_summary_comment(existing_comments, identity or _TokenIdentity())
        if existing_comments is not None
        else None
    )
    previous_changed, previous_max = _previous_summary_counts(previous)
    changed_now = len(diff_findings)

    by_severity = {}
    for f in all_findings:
        sev = f.get("severity", "MEDIUM")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_category = {}
    for f in all_findings:
        cat = f.get("category", "other")
        by_category[cat] = by_category.get(cat, 0) + 1

    was = (
        f" (was {previous_changed})"
        if previous_changed is not None and previous_changed != changed_now
        else ""
    )
    lines = [SUMMARY_MARKER, _SUMMARY_HEADING, ""]
    if changed_now == 0 and previous_max > 0:
        lines.extend(
            [
                "✅ **All issues Skylos reported on this PR's changed lines are "
                f"fixed.** Earlier runs reported up to {previous_max}.",
                "",
            ]
        )
    left_unused_count = (
        f" | **{len(left_unused)}** left unused by this change" if left_unused else ""
    )
    lines.append(
        f"**{changed_now}** issue(s) on changed lines{was} | "
        f"**{len(all_findings)}** total{left_unused_count}"
    )
    lines.extend(format_risk_passport_markdown(risk_passport))
    lines.extend(
        [
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
    )

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    if by_category:
        lines.extend(
            [
                "",
                "| Category | Count |",
                "|----------|-------|",
            ]
        )
        for cat in (
            "danger",
            "reliability",
            "ai_defects",
            "quality",
            "dead_code",
            "secrets",
            "custom_rules",
            "security_regression",
        ):
            count = by_category.get(cat, 0)
            if count > 0:
                lines.append(f"| {cat} | {count} |")

    regression_findings = [
        f for f in diff_findings if f.get("kind") == "security_regression"
    ]
    if regression_findings:
        lines.extend(
            [
                "",
                "### ⚠️ Security Regressions Detected",
                "",
                "| Control | File | Message |",
                "|---------|------|---------|",
            ]
        )
        for f in regression_findings:
            control = sanitize_markdown_text(
                f.get("control_type", "unknown"), max_length=80
            )
            file = sanitize_markdown_text(
                os.path.basename(f.get("file", "")), max_length=300
            )
            msg = sanitize_markdown_text(f.get("message", ""), max_length=1_000)
            lines.append(f"| {control} | {file} | {msg} |")

    if evidence_cards:
        cards = build_evidence_cards(all_findings)
        counts = evidence_counts(cards)
        if cards:
            lines.extend(
                [
                    "",
                    "### Evidence",
                    "",
                    "| Label | Count |",
                    "|-------|-------|",
                ]
            )
            for label in ("proven", "likely", "speculative"):
                count = counts[label]
                if count > 0:
                    lines.append(f"| {evidence_label_title(label)} | {count} |")

    critical_findings = [
        f for f in diff_findings if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    if critical_findings:
        lines.extend(["", "### Top Issues", ""])
        for f in critical_findings[:5]:
            sev = f.get("severity", "MEDIUM")
            badge = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(sev, "🟡")
            safe_rule_id = sanitize_markdown_text(f.get("rule_id", ""), max_length=120)
            rule = f" `{safe_rule_id}`" if safe_rule_id else ""
            file = sanitize_markdown_text(
                os.path.basename(f.get("file", "")), max_length=300
            )
            line_no = f.get("line", "")
            loc = f" ({file}:{line_no})" if file else ""
            message = sanitize_markdown_text(f.get("message", ""), max_length=1_000)
            lines.append(f"- {badge} **{sev}**{rule}{loc}: {message}")

            vuln_code = f.get("vulnerable_code")
            fix_code = f.get("fixed_code")
            if vuln_code and fix_code:
                lines.append("")
                lines.append("  <details><summary>View fix</summary>")
                lines.append("")
                lines.append("  **Vulnerable:**")
                lines.append("  ```python")
                safe_vulnerable_code = sanitize_markdown_text(
                    vuln_code,
                    max_length=4_000,
                    preserve_newlines=True,
                )
                for code_line in safe_vulnerable_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  **Fixed:**")
                lines.append("  ```python")
                safe_fixed_code = sanitize_markdown_text(
                    fix_code,
                    max_length=4_000,
                    preserve_newlines=True,
                )
                for code_line in safe_fixed_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  </details>")
                lines.append("")
            else:
                fix = f.get("suggestion") or _RULE_SUGGESTIONS.get(f.get("rule_id", ""))
                if fix:
                    lines.append(
                        f"  - **Fix:** {sanitize_markdown_text(fix, max_length=500)}"
                    )

    if left_unused:
        lines.extend(
            [
                "",
                "### Left unused by this change",
                "",
                "In use before this change, unused after it. Delete them or "
                "restore the use.",
                "",
                "| Unused | Location |",
                "|--------|----------|",
            ]
        )
        for what, where in left_unused[:_MAX_LEFT_UNUSED_ROWS]:
            lines.append(
                f"| {sanitize_markdown_text(what, max_length=300)} "
                f"| {sanitize_markdown_text(where, max_length=300)} |"
            )
        if len(left_unused) > _MAX_LEFT_UNUSED_ROWS:
            lines.extend(
                ["", f"…and {len(left_unused) - _MAX_LEFT_UNUSED_ROWS} more."]
            )

    if isinstance(assessment, dict) and assessment:
        lines.extend(_format_assessment_markdown(assessment))
    elif grade:
        overall = grade["overall"]
        cats = grade["categories"]

        lines.extend(["", "### Legacy score", ""])

        if previous_grade:
            prev = previous_grade["overall"]
            delta = overall["score"] - prev["score"]
            arrow = "+" if delta > 0 else ""
            direction = "\u2191" if delta > 0 else ("\u2193" if delta < 0 else "\u2194")
            lines.append(
                f"**{prev['letter']} ({prev['score']}) \u2192 "
                f"{overall['letter']} ({overall['score']}) {direction}** "
                f"({arrow}{delta})"
            )
        else:
            lines.append(f"**Legacy: {overall['letter']} ({overall['score']}/100)**")

        lines.extend(
            [
                "",
                "| Category | Score | Grade | Key Issue |",
                "|----------|-------|-------|-----------|",
            ]
        )

        for cat_name in ("security", "quality", "dead_code", "dependencies", "secrets"):
            cat = cats[cat_name]
            display = cat_name.replace("_", " ").title()
            issue = sanitize_markdown_text(cat.get("key_issue") or "-", max_length=50)

            delta_str = ""
            if previous_grade and cat_name in previous_grade.get("categories", {}):
                prev_cat = previous_grade["categories"][cat_name]
                cat_delta = cat["score"] - prev_cat["score"]
                if cat_delta != 0:
                    d_arrow = "\u2191" if cat_delta > 0 else "\u2193"
                    delta_str = f" {d_arrow}{abs(cat_delta)}"

            lines.append(
                f"| {display} | {cat['score']}{delta_str} | {cat['letter']} | {issue} |"
            )
        lines.extend(["", "Historical result; this score is not a current risk assessment."])

    lines.extend(
        [
            "",
            "---",
            "_Skylos edits this comment on each push instead of adding a new "
            "one. Inline comments from earlier runs stay on the PR._",
            "<!-- skylos-review-state: "
            f"changed={changed_now} max={max(previous_max, changed_now)} -->",
        ]
    )
    body = "\n".join(lines)

    note = (
        f"could not read existing comments ({list_error})"
        if existing_comments is None
        else ""
    )
    if previous is not None:
        try:
            _gh_write(
                [
                    "api",
                    "--method",
                    "PATCH",
                    f"/repos/{repo}/issues/comments/{previous['id']}",
                    "--input",
                    "-",
                ],
                {"body": body},
            )
            return _CommentOutcome("updated")
        except (subprocess.SubprocessError, OSError) as exc:
            note = f"could not edit the earlier summary ({_gh_error_text(exc)})"

    try:
        _gh_write(
            ["pr", "comment", str(pr_number), "--body", body, "--repo", repo]
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return _CommentOutcome("failed", error=_gh_error_text(exc), note=note)
    return _CommentOutcome("created", note=note)


def _previous_summary_comment(
    comments: list[dict], identity: _TokenIdentity
) -> dict | None:
    """Newest summary Skylos itself posted: marked ones first, then legacy."""
    marked: list[dict] = []
    legacy: list[dict] = []
    for comment in comments:
        body = comment.get("body")
        if not isinstance(body, str) or not isinstance(comment.get("id"), int):
            continue
        head = body.lstrip()
        if head.startswith(SUMMARY_MARKER):
            marked.append(comment)
        elif head.startswith(_SUMMARY_HEADING):
            legacy.append(comment)
    for group in (marked, legacy):
        for comment in reversed(group):
            if identity.owns(comment):
                return comment
    return None


def _previous_summary_counts(comment: dict | None) -> tuple[int | None, int]:
    if not comment:
        return None, 0
    body = comment.get("body") or ""
    state = _SUMMARY_STATE_RE.search(body)
    if state:
        return int(state.group(1)), int(state.group(2))
    legacy = _LEGACY_CHANGED_COUNT_RE.search(body)
    if legacy:
        count = int(legacy.group(1))
        return count, count
    return None, 0


def _review_outcome_line(
    pr_number: int,
    review: object,
    summary: object,
) -> str:
    outcomes = [o for o in (review, summary) if isinstance(o, _CommentOutcome)]
    failed = [o for o in outcomes if o.action == "failed"]
    if failed:
        return (
            f"[yellow]Skylos could not post PR comments on #{pr_number} "
            f"({escape(failed[0].error)}). A read-only token, as on a fork PR, "
            "cannot comment; scan and gate results are unaffected.[/yellow]"
        )
    parts = []
    if isinstance(summary, _CommentOutcome):
        parts.append(f"summary {summary.action}")
    if isinstance(review, _CommentOutcome):
        parts.append(
            f"{review.new_inline} new inline comment(s), "
            f"{review.existing_inline} already on the PR"
        )
    notes = [o.note for o in outcomes if o.note]
    if notes:
        parts.append(escape(notes[0]))
    detail = "; ".join(parts) if parts else "done"
    return f"[green]Skylos PR review on #{pr_number}: {detail}[/green]"


def _format_assessment_markdown(assessment: dict) -> list[str]:
    lines = ["", "### Scan assessment", "", "| Area | Result |", "|------|--------|"]
    for label, detail in assessment_rows(assessment):
        safe_detail = sanitize_markdown_text(detail, max_length=500)
        lines.append(f"| {label} | {safe_detail} |")
    lines.extend(["", sanitize_markdown_text(assessment_coverage_text(assessment), max_length=1000)])
    checks = maintainability_rows(assessment)
    if checks:
        lines.extend(["", "| Check | Spread | Magnitude |", "|-------|--------|-----------|"])
        for row in checks:
            safe = [sanitize_markdown_text(value, max_length=250) for value in row]
            lines.append("| " + " | ".join(safe) + " |")
    lines.extend(["", "Risk includes Defect and Review findings; review evidence before acting."])
    return lines


def _fetch_previous_grade(base_branch: str = "origin/main") -> dict | None:
    try:
        from skylos.api import BASE_URL, get_project_token

        token = get_project_token()
        if not token:
            return None

        branch = base_branch.replace("origin/", "")
        resp = requests.get(
            f"{BASE_URL}/api/grade/latest",
            params={"branch": branch},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("grade")
    except (
        ImportError,
        OSError,
        ValueError,
        requests.exceptions.RequestException,
    ) as exc:
        logger.debug("Failed to fetch previous grade: %s", exc)
    return None


def _detect_pr_number() -> int | None:
    ref = os.environ.get("GITHUB_REF", "")
    match = re.match(r"refs/pull/(\d+)/merge", ref)
    if match:
        return int(match.group(1))
    return None


def _gh_available() -> bool:
    try:
        subprocess.run(["gh", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
