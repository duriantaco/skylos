from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable

from skylos.constants import NETWORK_TIMEOUT_SHORT, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

_AI_COAUTHOR_PATTERNS = [
    re.compile(r"copilot", re.IGNORECASE),
    re.compile(r"claude", re.IGNORECASE),
    re.compile(r"cursor", re.IGNORECASE),
    re.compile(r"codewhisperer", re.IGNORECASE),
    re.compile(r"tabnine", re.IGNORECASE),
    re.compile(r"github-actions\[bot\]", re.IGNORECASE),
    re.compile(r"devin", re.IGNORECASE),
]

_AI_EMAIL_PATTERNS = [
    re.compile(r"\[bot\]@", re.IGNORECASE),
    re.compile(r"copilot", re.IGNORECASE),
    re.compile(r"cursor", re.IGNORECASE),
    re.compile(r"claude", re.IGNORECASE),
]

_AI_MESSAGE_PATTERNS = [
    re.compile(r"generated\s+by\s+(copilot|claude|cursor|ai)", re.IGNORECASE),
    re.compile(r"ai[- ]generated", re.IGNORECASE),
    re.compile(r"co-authored-by.*copilot", re.IGNORECASE),
    re.compile(r"co-authored-by.*claude", re.IGNORECASE),
]


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
            [
                "git",
                "log",
                "--format=%H|%an|%ae|%s|%(trailers:key=Co-authored-by,valueonly,separator=%x00)",
                "-50",
            ],
            cwd=git_root,
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
    for pattern in _AI_COAUTHOR_PATTERNS:
        if pattern.search(trailers):
            indicators.append(
                {
                    "type": "co-author",
                    "commit": commit_sha[:7],
                    "detail": trailers.strip()[:100],
                }
            )
            return True

    for pattern in _AI_EMAIL_PATTERNS:
        if pattern.search(author_email):
            indicators.append(
                {
                    "type": "author-email",
                    "commit": commit_sha[:7],
                    "detail": f"{author_name} <{author_email}>",
                }
            )
            return True

    for pattern in _AI_MESSAGE_PATTERNS:
        if pattern.search(subject):
            indicators.append(
                {
                    "type": "commit-message",
                    "commit": commit_sha[:7],
                    "detail": subject[:100],
                }
            )
            return True

    return False


def _collect_ai_commit_files(git_root: str, commit_sha: str, ai_files: set[str]) -> None:
    try:
        diff_output = subprocess.check_output(
            [
                "git",
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                commit_sha,
            ],
            cwd=git_root,
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
