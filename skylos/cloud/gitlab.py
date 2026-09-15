"""Conservative client hints for GitLab-managed uploads, not authorization."""

from __future__ import annotations

import os
from pathlib import Path

from skylos.cloud.project_context import normalize_repo_subpath


def managed_checkout_root() -> Path | None:
    """Locate the declared checkout for path normalization, not identity trust."""
    if (
        os.getenv("GITLAB_CI") != "true"
        or os.getenv("CI_SERVER_URL") != "https://gitlab.com"
    ):
        return None
    value = os.getenv("CI_PROJECT_DIR")
    if not value:
        return None
    from skylos.core.file_discovery import find_git_root

    try:
        checkout = Path(value).resolve()
        return (
            checkout
            if checkout.is_dir() and find_git_root(checkout) == checkout
            else None
        )
    except (OSError, ValueError):
        return None


def managed_project_root(git_root=None, *, cwd=None) -> str | None:
    """Return an explicit repo-relative binding, or a known Git-relative cwd."""
    explicit = os.getenv("SKYLOS_PROJECT_ROOT")
    if explicit is not None:
        raw = explicit.strip()
        if raw.startswith(("/", "\\")) or ":" in raw:
            raise ValueError("SKYLOS_PROJECT_ROOT must be repository-relative")
        normalized = normalize_repo_subpath(raw)
        if normalized is None:
            raise ValueError("SKYLOS_PROJECT_ROOT must be repository-relative")
        return normalized
    if git_root is None:
        return None
    try:
        relative = (
            Path(cwd or Path.cwd()).resolve().relative_to(Path(git_root).resolve())
        )
    except (OSError, ValueError):
        return None
    return normalize_repo_subpath(relative.as_posix())


def managed_report_paths(result, git_root, project_root):
    """Anchor analyzer paths to the checkout, never the isolated job cwd.

    Finding identity enrichment adds scan-relative ``file_path`` beside the
    original absolute ``file``. Preserve that original location when present.
    Relative-only findings are anchored to the known scanned project directory.
    This copies report sections and does not modify analyzer receipt evidence.
    """
    if not isinstance(result, dict) or not git_root:
        return result
    from skylos.core.review_decisions import FINDING_SECTIONS

    anchored = dict(result)
    for section in [item[0] for item in FINDING_SECTIONS] + ["reviewed_findings"]:
        items = result.get(section)
        if not isinstance(items, list):
            continue
        copies = []
        for item in items:
            if not isinstance(item, dict):
                copies.append(item)
                continue
            finding = dict(item)
            original = finding.get("file")
            raw = finding.get("file_path") or original
            if isinstance(original, str) and Path(original).is_absolute():
                finding["file_path"] = original
            elif isinstance(raw, str) and raw and not Path(raw).is_absolute():
                finding["file_path"] = str(Path(git_root) / (project_root or "") / raw)
            copies.append(finding)
        anchored[section] = copies
    return anchored


def cli_full_scan(args, config, project_root, *, changed_files=None) -> bool:
    """Whether this invocation is eligible to resolve old managed comments.

    Defaults are the supported scanner scope, not a claim to analyze every
    language or file. Any explicit narrowing is conservatively non-full.
    """
    if not all(
        getattr(args, key, False)
        for key in ("danger", "secrets", "quality", "ai_defects", "sca")
    ):
        return False
    if changed_files is not None or getattr(args, "confidence", 60) != 60:
        return False
    if any(
        getattr(args, key, None)
        for key in (
            "baseline",
            "baseline_ref",
            "diff",
            "diff_base",
            "select",
            "severity",
            "category",
            "file_filter",
            "exclude_folders",
            "include_folders",
            "limit",
            "trace",
            "coverage",
        )
    ):
        return False
    if any(
        config.get(key)
        for key in (
            "ignore",
            "exclude",
            "whitelist",
            "whitelist_documented",
            "whitelist_temporary",
            "lower_confidence",
            "overrides",
        )
    ):
        return False
    masking = config.get("masking", {})
    if not isinstance(masking, dict) or any(
        masking.get(key) for key in ("names", "decorators", "bases")
    ):
        return False
    paths = getattr(args, "path", [])
    if len(paths) != 1 or not Path(paths[0]).is_dir():
        return False
    from skylos.core.file_discovery import find_git_root

    root = find_git_root(project_root)
    if root is None:
        return False
    try:
        actual = Path(project_root).resolve().relative_to(root).as_posix()
        expected = managed_project_root(root, cwd=project_root)
    except (OSError, ValueError):
        return False
    return normalize_repo_subpath(actual) == expected


def scan_receipt(result, *, analyzer_owned=False, full_scan=False) -> dict[str, bool]:
    """Derive completion from analyzer evidence, never copied payload claims."""
    complete = analyzer_owned is True and isinstance(result, dict)
    summary = result.get("analysis_summary") if isinstance(result, dict) else None
    complete = complete and isinstance(summary, dict)
    if complete:
        from skylos.core.gatekeeper import _analysis_incomplete_reasons

        complete = not _analysis_incomplete_reasons(result)
        error_count = summary.get("analysis_error_count", 0)
        complete = complete and type(error_count) is int and error_count == 0
        if "sca_coverage" in summary:
            coverage = summary["sca_coverage"]
            complete = complete and isinstance(coverage, dict)
            if isinstance(coverage, dict):
                status = coverage.get("status")
                expected = {
                    "complete": True,
                    "complete_with_unresolved_versions": True,
                    "no_supported_manifests": False,
                }
                complete = complete and isinstance(status, str) and status in expected
                complete = complete and coverage.get("complete") is expected.get(status)
                complete = complete and all(
                    type(coverage.get(key, 0)) is int and coverage.get(key, 0) == 0
                    for key in (
                        "parse_error_count",
                        "unresolved_lockfile_dependency_count",
                    )
                )
                query = coverage.get("query")
                if query is not None:
                    complete = (
                        complete
                        and isinstance(query, dict)
                        and query.get("complete") is True
                    )
        grep = summary.get("grep_verify")
        if grep is not None:
            complete = complete and isinstance(grep, dict)
            if isinstance(grep, dict) and (
                "complete" in grep or grep.get("enabled") is not False
            ):
                complete = complete and grep.get("complete") is True
        engines = summary.get("language_engines", {})
        complete = complete and isinstance(engines, dict)
        if isinstance(engines, dict):
            complete = complete and all(
                isinstance(engine, dict)
                and engine.get("status") == "available"
                and engine.get("complete") is not False
                for engine in engines.values()
            )
    complete = bool(complete)
    # Missing SCA evidence cannot resolve previously reported dependencies.
    sca = summary.get("sca_coverage") if isinstance(summary, dict) else None
    sca_complete = isinstance(sca, dict) and sca.get("status") in (
        "complete",
        "no_supported_manifests",
    )
    return {
        "complete": complete,
        "full_scan": complete and full_scan is True and sca_complete,
    }


def delivery_receipt(value) -> dict:
    """Keep saved-scan success separate from confirmed MR comment delivery."""
    invalid = {
        "gitlab_delivery": {"status": "failed", "reason": "invalid_receipt"},
        "gitlab_delivery_exit_code": 2,
        "gitlab_delivery_message": (
            "Scan saved. GitLab comment delivery was not confirmed: missing or invalid "
            "delivery receipt. Check the Cloud integration deployment and setup."
        ),
    }
    if not isinstance(value, dict):
        return invalid
    status = value.get("status")
    if status not in ("published", "noop", "skipped", "partial", "failed"):
        return invalid
    counts = {
        key: value.get(key) for key in ("created", "updated", "resolved", "eligible")
    }
    if not all(
        type(number) is int and 0 <= number <= 100_000 for number in counts.values()
    ):
        return invalid
    changed = counts["created"] + counts["updated"] + counts["resolved"]
    if (status in ("noop", "skipped") and changed) or (
        status == "published" and not changed
    ):
        return invalid
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason or len(reason) > 80:
        return invalid
    known_reasons = {
        "complete",
        "partial_scope_no_resolution",
        "not_merge_request",
        "plan_required",
        "scan_incomplete",
        "invalid_context",
        "lease_busy_or_stale",
        "lease_lost",
        "stale_diff",
        "disconnected",
        "connection_replaced",
        "connection_changed",
        "delivery_unavailable",
        "comment_limit",
        "review_state_unavailable",
        "discussions_incomplete",
        "invalid_publish_response",
        "discussion_changed",
        "gitlab_invalid_request",
        "gitlab_http_error",
        "gitlab_transport_error",
        "gitlab_timeout",
        "gitlab_response_limit",
        "gitlab_invalid_response",
        "gitlab_pagination_limit",
        "gitlab_request_limit",
    }
    safe_reason = (
        reason
        if isinstance(reason, str) and reason in known_reasons
        else "unrecognized_reason"
    )
    outcome = {"status": status, "reason": safe_reason, **counts}
    summary = f"{counts['created']} created, {counts['updated']} updated, {counts['resolved']} resolved"
    exit_code = 2
    if safe_reason == "plan_required":
        message = "Scan saved. GitLab comments require an eligible Cloud plan; upgrade and check the project integration setup."
    elif status in ("published", "noop"):
        if safe_reason not in ("complete", "partial_scope_no_resolution"):
            return invalid
        message = (
            f"Scan saved. GitLab comments: {summary} ({counts['eligible']} eligible)."
        )
        if safe_reason == "partial_scope_no_resolution":
            message += " Partial scan scope; previous comments were not resolved."
        exit_code = 0
    elif status == "skipped" and safe_reason == "not_merge_request":
        message = (
            "Scan saved. GitLab comments skipped: this is not a merge-request pipeline."
        )
        exit_code = 0
    else:
        message = f"Scan saved. GitLab comment delivery {status}: {safe_reason} ({summary}). Check Cloud integration status; this delivery result does not trigger automatic re-upload."
    return {
        "gitlab_delivery": outcome,
        "gitlab_delivery_exit_code": exit_code,
        "gitlab_delivery_message": message,
    }
