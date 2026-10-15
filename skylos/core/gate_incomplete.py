"""Say why required analysis did not finish, so an exit-2 gate explains itself.

Each reason names the analyzer that stopped, how much it could not cover and
the real option that resolves or bypasses it. Results can come from a
``skylos cicd gate --input`` file, so every field is type-checked. Reason text
holds only counts and fixed phrases; file names and parser messages go in
``details``, which renderers print literally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from skylos.core.sca_coverage import (
    NON_REGISTRY_COVERAGE_STATUS,
    valid_non_registry_sca_receipt,
)

DETAIL_LINE_LIMIT = 10
DETAIL_MESSAGE_CHARS = 160
SCA_BLOCKING_STATUSES = ("incomplete", "unavailable", "unknown")
_SAFE_ERROR_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,79}")

ANALYSIS_ERROR_HINT = (
    "Fix the files listed above and rerun, or leave their folder out of the "
    "scan with --exclude <folder> (or exclude = [...] under [tool.skylos])."
)
SCA_REQUIRED_HINT = (
    "Dependency results are required whenever --sca is on (-a includes it). "
    "To scan or gate without them, run without --sca, for example --danger "
    "--secrets --quality --ai-defects instead of -a."
)
OSV_HINT = (
    "Skylos looks up advisories at OSV.dev (https://api.osv.dev); check network "
    "or proxy access to it and rerun."
)
PARSE_ERROR_HINT = "Rerun with --verbose to see which file failed to parse and why."
SCANNER_EXCEPTION_HINT = "Rerun with SKYLOS_DEBUG=1 to print the scanner traceback."
REQUESTS_HINT = (
    "Install the requests package (pip install requests); reinstalling Skylos "
    "also installs it."
)
SYMLINK_ROOT_HINT = "Scan the directory the symlink points to instead."

_RECEIPT_REASONS = {
    "symlink_scan_root": (
        "the scan root is a symlink, so dependency files were not read",
        SYMLINK_ROOT_HINT,
    ),
    "requests_dependency_unavailable": (
        "the requests package is not installed, so OSV.dev could not be queried",
        REQUESTS_HINT,
    ),
    "scanner_returned_no_coverage_receipt": (
        "the dependency scanner returned no coverage receipt",
        None,
    ),
}
_QUERY_LIMIT_REASONS = {
    "query_pagination_not_completed": (
        "OSV.dev returned more advisory pages than Skylos reads"
    ),
    "advisory_match_limit_exceeded": (
        "OSV.dev returned more advisory matches than Skylos accepts ({matches:,})"
    ),
}
_INVENTORY_LIMIT_REASONS = {
    "directory_limit_exceeded": (
        "more than {directories:,} directories had to be searched for dependency files"
    ),
    "manifest_count_limit_exceeded": (
        "more than {manifests:,} manifests and lockfiles were found"
    ),
    "manifest_bytes_limit_exceeded": (
        "manifests and lockfiles exceed {total_mb:,} MB in total"
    ),
    "dependency_limit_exceeded": (
        "a lockfile or the project exceeds the dependency inventory limit "
        "({dependencies:,} dependencies or an oversized lockfile)"
    ),
}


@dataclass(frozen=True)
class IncompleteReason:
    """One reason analysis is incomplete: summary, literal details, next step."""

    text: str
    details: tuple[str, ...] = ()
    hint: str | None = None


# Coverage gaps: one file (or one language's files) was not analysed, or grep
# verification did not reach some dead-code candidates. Everything else was
# checked, so by default they are warnings, not exit 2. Any other analysis
# error kind blocks, so an unknown kind fails closed.
FILE_GAP_ERROR_KINDS = frozenset(
    {
        "syntax_error",
        "processing_error",
        "source_read_error",
        "worker_crash",
        "worker_error",
        "security_scan_error",
        "cpp_parse_error",
        "secret_config_read_error",
        "secret_config_too_large",
    }
)
LANGUAGE_ENGINE_ERROR_KIND = "language_engine_unavailable"
GREP_ERROR_KINDS = frozenset({"grep_budget_exhausted", "grep_verification_incomplete"})
# An Actions workflow Skylos cannot read could still run on GitHub (a parser
# differential), so its security analysis is never skipped with a warning.
BLOCKING_ERROR_COMPONENTS = frozenset({"github_actions"})

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_INCOMPLETE = "incomplete"

COVERAGE_STRICT_HINT = (
    "Findings cover everything else, and the exit code is decided on them. Use "
    "--strict (or require_complete = true under [tool.skylos.gate.coverage]) "
    "to fail with exit 2 when coverage is incomplete."
)
MOST_CODE_UNCHECKED_HINT = (
    "Most of the source files in scope could not be analysed, so this result "
    "cannot stand for the code. Fix the reasons below and rerun."
)
GREP_GAP_HINT = (
    "Unverified candidates are not reported as dead code (JSON lists them under "
    "dead_code_abstentions). Increase SKYLOS_GREP_BUDGET (seconds) and rerun to "
    "check them."
)


@dataclass(frozen=True)
class AnalysisCoverage:
    """What was not analysed, split into exit-2 blockers and warnings."""

    blocking: tuple[IncompleteReason, ...] = ()
    gaps: tuple[IncompleteReason, ...] = ()
    source_file_count: int | None = None
    unchecked_files: tuple[dict, ...] = ()
    unchecked_file_count: int = 0
    unverified_candidate_count: int = 0
    most_code_unchecked: bool = False
    diff_scoped: bool = False

    @property
    def status(self) -> str:
        if self.blocking:
            return COVERAGE_INCOMPLETE
        if self.gaps:
            return COVERAGE_PARTIAL
        return COVERAGE_COMPLETE


def incomplete_analysis_reasons(results) -> list[IncompleteReason]:
    """Every reason the analysis is not complete: blockers and coverage gaps.

    Consumers that need a complete scan (baselines, GitLab completeness) read
    this. Exit codes and gates read :func:`analysis_coverage`, which keeps
    coverage gaps apart from failures that block.
    """
    results = results if isinstance(results, dict) else {}
    summary = results.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    reasons = []

    analysis_errors = results.get("analysis_errors")
    if analysis_errors:
        reasons.append(_analysis_errors_reason(analysis_errors))

    languages = _incomplete_languages(summary.get("incomplete_languages"))
    if languages:
        reasons.append(_languages_reason(languages, summary.get("language_engines")))

    sca_reason = _blocking_sca_reason(summary.get("sca_coverage"))
    if sca_reason is not None:
        reasons.append(sca_reason)

    return reasons


def analysis_coverage(results, *, strict=False, require_complete=False):
    """Split what was not analysed into blockers (exit 2) and coverage gaps.

    A gap is a file that did not parse or could not be read, the files of a
    language whose engine is missing, or dead-code candidates that grep
    verification did not reach. A gap blocks only when ``strict`` or
    ``require_complete`` asks for complete coverage, when more than half of the
    source files in scope were not analysed (nothing meaningful ran), or for a
    diff-scoped scan, where every file error left is in the changed code.
    """
    results = results if isinstance(results, dict) else {}
    summary = results.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    diff_scoped = _is_diff_scoped(results, summary)

    raw_errors = results.get("analysis_errors")
    errors = (
        [error for error in raw_errors if isinstance(error, dict)]
        if isinstance(raw_errors, (list, tuple))
        else []
    )
    malformed = bool(raw_errors) and len(errors) != _safe_len(raw_errors)

    blocking_errors, file_gaps, language_gaps, grep_gaps = [], [], [], []
    for error in errors:
        kind = str(error.get("kind") or "")
        if kind in GREP_ERROR_KINDS:
            grep_gaps.append(error)
        elif diff_scoped or error.get("component") in BLOCKING_ERROR_COMPONENTS:
            blocking_errors.append(error)
        elif kind == LANGUAGE_ENGINE_ERROR_KIND:
            language_gaps.append(error)
        elif kind in FILE_GAP_ERROR_KINDS and error.get("file"):
            file_gaps.append(error)
        else:
            blocking_errors.append(error)

    blocking, gaps = [], []
    if malformed:
        blocking.append(_analysis_errors_reason(raw_errors))
    elif blocking_errors:
        blocking.append(_analysis_errors_reason(blocking_errors))

    languages = _incomplete_languages(summary.get("incomplete_languages"))
    language_reason = (
        _languages_reason(languages, summary.get("language_engines"))
        if languages
        else None
    )
    if language_reason is not None and (
        _languages_block_diff(results, errors)
        if diff_scoped
        # Without the per-file engine records the gap cannot be measured.
        else not language_gaps
    ):
        blocking.append(language_reason)
        language_reason = None

    source_count = _non_negative_int(summary.get("total_files"))
    unchecked_count = _unchecked_file_count(file_gaps, language_gaps)
    if source_count is not None:
        unchecked_count = min(unchecked_count, source_count)
    most_unchecked = bool(unchecked_count) and (
        not source_count or unchecked_count * 2 > source_count
    )

    source_gaps = []
    if file_gaps:
        source_gaps.append(_unchecked_files_reason(file_gaps, source_count))
    if language_reason is not None:
        source_gaps.append(language_reason)
    if most_unchecked and source_gaps:
        of_total = f" of {source_count}" if source_count else ""
        blocking.append(
            IncompleteReason(
                f"Analysis incomplete: {unchecked_count}{of_total} source "
                f"{'file' if (source_count or unchecked_count) == 1 else 'files'} "
                "could not be analysed",
                (),
                MOST_CODE_UNCHECKED_HINT,
            )
        )
        blocking.extend(source_gaps)
    else:
        gaps.extend(source_gaps)

    unverified = sum(
        _positive_int(error.get("unverified_candidate_count")) for error in grep_gaps
    )
    if grep_gaps:
        gaps.append(_grep_reason(grep_gaps))

    sca_reason = _blocking_sca_reason(summary.get("sca_coverage"))
    if sca_reason is not None:
        blocking.append(sca_reason)

    if (strict or require_complete) and gaps:
        blocking.extend(gaps)
        gaps = []

    return AnalysisCoverage(
        blocking=tuple(blocking),
        gaps=tuple(gaps),
        source_file_count=source_count,
        unchecked_files=tuple(_unchecked_files(file_gaps, language_gaps)),
        unchecked_file_count=unchecked_count,
        unverified_candidate_count=unverified,
        most_code_unchecked=most_unchecked,
        diff_scoped=diff_scoped,
    )


def coverage_record(coverage):
    """The ``analysis_summary.analysis_coverage`` JSON object."""
    return {
        "status": coverage.status,
        "exit_blocking": bool(coverage.blocking),
        "diff_scoped": coverage.diff_scoped,
        "source_file_count": coverage.source_file_count,
        "unchecked_file_count": coverage.unchecked_file_count,
        "unchecked_files": [dict(item) for item in coverage.unchecked_files],
        "unverified_dead_code_candidates": coverage.unverified_candidate_count,
        "most_code_unchecked": coverage.most_code_unchecked,
        "warnings": [reason_record(reason) for reason in coverage.gaps],
        "blocking_reasons": [reason_record(reason) for reason in coverage.blocking],
    }


def reason_record(reason):
    return {
        "message": reason.text,
        "details": list(reason.details),
        "hint": reason.hint,
    }


def _safe_len(value):
    try:
        return len(value)
    except TypeError:
        return 1


def _is_diff_scoped(results, summary):
    if summary.get("diff_scoped") is True:
        return True
    scope = summary.get("comparison_scope")
    if isinstance(scope, dict) and scope.get("changed_files_only") is True:
        return True
    warnings = results.get("analysis_warnings")
    return isinstance(warnings, list) and any(
        isinstance(warning, dict) and warning.get("outside_diff") is True
        for warning in warnings
    )


def _languages_block_diff(results, errors):
    """A missing engine blocks a diff scan unless no changed file needs it.

    Engine records for files outside the diff were moved to
    ``analysis_warnings``; one still in ``analysis_errors`` names changed code.
    """
    if any(str(e.get("kind") or "") == LANGUAGE_ENGINE_ERROR_KIND for e in errors):
        return True
    warnings = results.get("analysis_warnings")
    return not (
        isinstance(warnings, list)
        and any(
            isinstance(warning, dict)
            and warning.get("kind") == LANGUAGE_ENGINE_ERROR_KIND
            and warning.get("outside_diff") is True
            for warning in warnings
        )
    )


def _non_negative_int(value):
    return value if type(value) is int and value >= 0 else None


def _unchecked_file_count(file_gaps, language_gaps):
    count = len({str(error.get("file")) for error in file_gaps})
    for error in language_gaps:
        count += max(1, _positive_int(error.get("affected_file_count")))
    return count


def _unchecked_files(file_gaps, language_gaps):
    items, seen = [], set()
    for error in [*file_gaps, *language_gaps]:
        key = (str(error.get("file") or ""), str(error.get("kind") or ""))
        if key in seen:
            continue
        seen.add(key)
        item = {
            "file": _display_path(error.get("file")) if error.get("file") else None,
            "line": _positive_int(error.get("line")) or 1,
            "kind": key[1] or "analysis_error",
            "reason": _clip(error.get("message")) or "not analysed",
        }
        if error.get("language"):
            item["language"] = str(error["language"])
        affected = _positive_int(error.get("affected_file_count"))
        if affected > 1:
            item["affected_file_count"] = affected
        skipped = error.get("skipped_checks")
        if isinstance(skipped, list) and skipped:
            item["skipped_checks"] = [str(check) for check in skipped[:6]]
        if error.get("suggestion"):
            item["suggestion"] = _clip(error["suggestion"], 400)
        items.append(item)
    return items


def _unchecked_files_reason(file_gaps, source_count):
    file_count = len({str(error.get("file")) for error in file_gaps})
    noun = "file" if (source_count or file_count) == 1 else "files"
    of_total = f" of {source_count} source" if source_count else ""
    details = _bounded_lines(
        [_analysis_error_line(error) for error in file_gaps], len(file_gaps)
    )
    suggestions = dict.fromkeys(
        _clip(error.get("suggestion"), 400)
        for error in file_gaps
        if error.get("suggestion")
    )
    return IncompleteReason(
        f"Incomplete coverage: {file_count}{of_total} {noun} could not be analysed",
        tuple(details),
        " ".join([*suggestions, ANALYSIS_ERROR_HINT]),
    )


def _grep_reason(grep_errors):
    candidates = sum(_positive_int(e.get("candidate_count")) for e in grep_errors)
    unverified = sum(
        _positive_int(e.get("unverified_candidate_count")) for e in grep_errors
    )
    if candidates and unverified:
        verified = max(0, candidates - unverified)
        text = (
            f"Incomplete dead-code verification: grep verification checked "
            f"{verified} of {_count_noun(candidates, 'candidate')}; "
            f"{_count_noun(unverified, 'unverified candidate')} not reported"
        )
    else:
        text = (
            "Incomplete dead-code verification: grep verification did not "
            "finish; unverified candidates are not reported"
        )
    details = tuple(
        _clip(error.get("message"), 400)
        for error in grep_errors[:DETAIL_LINE_LIMIT]
        if error.get("message")
    )
    return IncompleteReason(text, details, GREP_GAP_HINT)


def _blocking_sca_reason(coverage):
    # Coverage limitations (including unresolved manifest ranges) are not
    # operational failures; only an interrupted or unavailable scan is.
    if not isinstance(coverage, dict):
        return None
    status = coverage.get("status")
    if status in SCA_BLOCKING_STATUSES or (
        status == NON_REGISTRY_COVERAGE_STATUS
        and not valid_non_registry_sca_receipt(coverage)
    ):
        return _sca_reason(coverage)
    return None


def _count_noun(count, singular, plural=None):
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def _positive_int(value):
    return value if type(value) is int and value > 0 else 0


def _display_path(path):
    raw = Path(str(path))
    if not raw.is_absolute():
        return str(path)
    try:
        return raw.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _clip(text, limit=DETAIL_MESSAGE_CHARS):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _location(item):
    file_path = item.get("file") or item.get("file_path")
    location = _display_path(file_path) if file_path else "?"
    line = item.get("line")
    return f"{location}:{line}" if _positive_int(line) else location


def _bounded_lines(lines, total):
    """At most DETAIL_LINE_LIMIT lines, then "and N more" out of ``total``."""
    shown = list(lines[:DETAIL_LINE_LIMIT])
    if total > len(shown):
        shown.append(f"and {total - len(shown)} more")
    return shown


def _analysis_errors_reason(analysis_errors):
    try:
        error_count = len(analysis_errors)
    except TypeError:
        error_count = 1
    errors = (
        [error for error in analysis_errors if isinstance(error, dict)]
        if isinstance(analysis_errors, (list, tuple))
        else []
    )
    details = _bounded_lines([_analysis_error_line(e) for e in errors], len(errors))
    suggestions = dict.fromkeys(
        _clip(error.get("suggestion"), 400)
        for error in errors
        if error.get("suggestion")
    )
    return IncompleteReason(
        f"Analysis incomplete: {error_count} analysis error(s) prevented a "
        "complete scan",
        tuple(details),
        " ".join([*suggestions, ANALYSIS_ERROR_HINT]),
    )


def _analysis_error_line(error):
    kind = str(error.get("kind") or error.get("error_type") or "analysis error")
    label = kind.replace("_", " ")
    message = _clip(error.get("message"))
    affected = _positive_int(error.get("affected_file_count"))
    suffix = f" ({affected} files)" if affected > 1 else ""
    body = f"{label}: {message}" if message else label
    return f"{_location(error)}  {body}{suffix}"


def _incomplete_languages(raw_languages):
    if isinstance(raw_languages, (list, tuple, set)):
        return sorted(
            {
                str(language).strip()
                for language in raw_languages
                if str(language).strip()
            }
        )
    if raw_languages:
        return [str(raw_languages).strip()]
    return []


def _languages_reason(languages, engines):
    engines = engines if isinstance(engines, dict) else {}
    details = []
    installs = []
    for language in languages:
        report = engines.get(language)
        report = report if isinstance(report, dict) else {}
        engine = report.get("engine")
        engine = engine if isinstance(engine, dict) else {}
        details.append(_language_detail(language, report, engine))
        install = engine.get("install")
        if isinstance(install, str) and install.strip():
            installs.append(_clip(install, 200))
    hint = "`skylos doctor` shows which language engines are available."
    if installs:
        hint = "Install the missing engine: " + "; ".join(installs) + ". " + hint
    return IncompleteReason(
        "Incomplete language engine coverage: " + ", ".join(languages),
        tuple(details),
        hint,
    )


def _language_detail(language, report, engine):
    parts = [f"{language}: {_clip(engine.get('reason')) or 'engine incomplete'}"]
    file_count = _positive_int(report.get("file_count"))
    if file_count:
        parts.append(_count_noun(file_count, "file"))
    skipped = report.get("skipped_checks")
    if isinstance(skipped, list) and skipped:
        labels = ", ".join(str(check).replace("_", " ") for check in skipped[:6])
        parts.append(f"skipped checks: {labels}")
    return "; ".join(parts)


def _scanner_limits():
    try:
        from skylos.rules.sca import vulnerability_scanner as scanner
    except ImportError:
        scanner = None
    return {
        "directories": getattr(scanner, "MAX_WALK_DIRECTORIES", 10_000),
        "manifests": getattr(scanner, "MAX_SUPPORTED_MANIFESTS", 1_000),
        "total_mb": getattr(scanner, "MAX_TOTAL_MANIFEST_BYTES", 50_000_000)
        // 1_000_000,
        "dependencies": getattr(scanner, "MAX_UNIQUE_DEPENDENCIES", 5_000),
        "matches": getattr(scanner, "MAX_OSV_MATCHES", 10_000),
    }


def _sca_reason(coverage):
    causes, details, hints = [], [], []
    limits = _scanner_limits()
    _receipt_reason_cause(coverage, causes, hints)
    _limit_reason_causes(
        coverage.get("limit_reasons"), _INVENTORY_LIMIT_REASONS, limits, causes
    )
    parse_errors = _positive_int(coverage.get("parse_error_count"))
    if parse_errors:
        causes.append(
            _count_noun(parse_errors, "dependency file")
            + " could not be read or parsed"
        )
        hints.append(PARSE_ERROR_HINT)
    _unresolved_lockfile_cause(coverage, causes, details)
    _query_causes(coverage.get("query"), limits, causes, hints)

    text = f"Dependency vulnerability scan incomplete (status: {coverage['status']})"
    if causes:
        text += ": " + "; ".join(causes)
    hint = " ".join(dict.fromkeys([*hints, SCA_REQUIRED_HINT]))
    return IncompleteReason(text, tuple(details), hint)


def _receipt_reason_cause(coverage, causes, hints):
    reason = coverage.get("reason")
    if reason == "scanner_exception":
        error_type = coverage.get("error_type")
        safe_type = (
            error_type
            if isinstance(error_type, str) and _SAFE_ERROR_TYPE.fullmatch(error_type)
            else "an error"
        )
        causes.append(f"the dependency scanner raised {safe_type}")
        hints.append(SCANNER_EXCEPTION_HINT)
    elif reason in _RECEIPT_REASONS:
        cause, hint = _RECEIPT_REASONS[reason]
        causes.append(cause)
        if hint:
            hints.append(hint)


def _limit_reason_causes(raw_reasons, phrases, limits, causes):
    if not isinstance(raw_reasons, list):
        return
    for reason in raw_reasons:
        if reason in phrases:
            causes.append(phrases[reason].format(**limits))


def _unresolved_lockfile_cause(coverage, causes, details):
    unresolved = _positive_int(coverage.get("unresolved_lockfile_dependency_count"))
    if not unresolved:
        return
    causes.append(
        _count_noun(unresolved, "lockfile entry", "lockfile entries")
        + " could not be resolved"
    )
    issues = coverage.get("lockfile_issues")
    issues = (
        [issue for issue in issues if isinstance(issue, dict)]
        if isinstance(issues, list)
        else []
    )
    details.extend(
        _bounded_lines([_lockfile_issue_line(i) for i in issues], unresolved)
    )


def _lockfile_issue_line(issue):
    reason = str(issue.get("reason") or "unresolved entry").replace("_", " ")
    name = next(
        (
            str(issue[field])
            for field in ("dependency", "package", "name", "installed_name", "section")
            if issue.get(field)
        ),
        "",
    )
    body = f"{reason}: {_clip(name, 120)}" if name else reason
    return f"{_location(issue)}  {body}"


def _query_causes(query, limits, causes, hints):
    if not isinstance(query, dict) or query.get("complete") is True:
        return
    before = len(causes)
    failed = _positive_int(query.get("failed_batches"))
    if failed:
        requested = max(_positive_int(query.get("requested_batches")), failed)
        causes.append(
            f"OSV.dev queries failed for {failed} of "
            + _count_noun(requested, "batch", "batches")
        )
    _limit_reason_causes(
        query.get("limit_reasons"), _QUERY_LIMIT_REASONS, limits, causes
    )
    _advisory_detail_causes(query, causes)
    if query.get("reason") == "query_provider_returned_no_receipt":
        causes.append("the OSV.dev query returned no receipt")
    if len(causes) == before:
        causes.append("the OSV.dev vulnerability query did not complete")
    hints.append(OSV_HINT)


def _advisory_detail_causes(query, causes):
    details = query.get("advisory_details")
    if isinstance(details, dict) and details.get("complete") is False:
        failed = _positive_int(details.get("failed_count"))
        if failed:
            total = max(_positive_int(details.get("unique_id_count")), failed)
            timed_out = (
                " before the time limit"
                if details.get("deadline_exceeded") is True
                else ""
            )
            causes.append(
                f"details for {failed} of {_count_noun(total, 'advisory', 'advisories')} "
                f"could not be fetched{timed_out}"
            )
    mismatched = _positive_int(query.get("advisory_context_error_count"))
    if mismatched:
        causes.append(
            _count_noun(mismatched, "advisory", "advisories")
            + " did not match their package"
        )
