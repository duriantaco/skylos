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


def incomplete_analysis_reasons(results) -> list[IncompleteReason]:
    """Reasons the gate cannot decide; empty when required analysis finished."""
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

    coverage = summary.get("sca_coverage")
    # Coverage limitations (including unresolved manifest ranges) are not
    # operational failures; only an interrupted or unavailable scan is.
    if isinstance(coverage, dict):
        status = coverage.get("status")
        if status in SCA_BLOCKING_STATUSES or (
            status == NON_REGISTRY_COVERAGE_STATUS
            and not valid_non_registry_sca_receipt(coverage)
        ):
            reasons.append(_sca_reason(coverage))

    return reasons


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
