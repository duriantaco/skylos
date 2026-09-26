from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable

from skylos.constants import NETWORK_TIMEOUT_SHORT, SUBPROCESS_TIMEOUT
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)
from skylos.reporting.provenance import (
    ATTRIBUTION_AI,
    GIT_LOG_FORMAT,
    classify_commit,
)

logger = logging.getLogger(__name__)


def _empty_ai_detection() -> dict:
    return {
        "detected": False,
        "indicators": [],
        "ai_files": [],
        "confidence": "low",
    }


def detect_ai_code(
    git_root=None,
    *,
    get_git_root_func: Callable[[], str | None] | None = None,
) -> dict:
    if not git_root:
        git_root = get_git_root_func() if get_git_root_func is not None else None
    if not git_root:
        return _empty_ai_detection()

    indicators = []
    ai_files = set()

    try:
        log_output = subprocess.check_output(
            read_only_git_command(
                [
                    "log",
                    f"--format={GIT_LOG_FORMAT}",
                    "-50",
                ]
            ),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")

        for line in log_output.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|", 4)
            if len(parts) < 4:
                continue

            commit_sha = parts[0]
            author_name = parts[1]
            author_email = parts[2]
            subject = parts[3]
            trailers = parts[4] if len(parts) > 4 else ""

            is_ai_commit = _append_ai_indicator(
                indicators,
                commit_sha,
                author_name,
                author_email,
                subject,
                trailers,
            )

            if is_ai_commit:
                _collect_ai_commit_files(git_root, commit_sha, ai_files)

    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to detect AI code from git log", exc_info=True)

    return {
        "detected": len(indicators) > 0,
        "indicators": indicators[:20],
        "ai_files": sorted(ai_files)[:100],
        "confidence": _confidence_for_indicators(indicators),
    }


def _append_ai_indicator(
    indicators: list[dict],
    commit_sha: str,
    author_name: str,
    author_email: str,
    subject: str,
    trailers: str,
) -> bool:
    # Only explicit agent signals count; dependency/CI bots and humans whose
    # name happens to contain an agent keyword are not AI.
    attribution = classify_commit(author_name, author_email, subject, trailers)
    if attribution is None or attribution["category"] != ATTRIBUTION_AI:
        return False
    indicators.append(
        {
            "type": attribution["type"],
            "commit": commit_sha[:7],
            "detail": attribution["detail"],
        }
    )
    return True


def _collect_ai_commit_files(
    git_root: str, commit_sha: str, ai_files: set[str]
) -> None:
    try:
        diff_output = subprocess.check_output(
            read_only_git_command(
                [
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "--no-ext-diff",
                    "--no-textconv",
                    "-r",
                    commit_sha,
                ]
            ),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=NETWORK_TIMEOUT_SHORT,
        ).decode("utf-8", errors="ignore")
        for file_path in diff_output.strip().splitlines():
            if file_path.strip():
                ai_files.add(file_path.strip())
    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to get git diff-tree for AI detection", exc_info=True)


def _confidence_for_indicators(indicators: list[dict]) -> str:
    if len(indicators) > 5:
        return "high"
    if indicators:
        return "medium"
    return "low"
