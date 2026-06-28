"""SKY-A102: diff-aware test impact gap detection."""

from __future__ import annotations

import re
from pathlib import Path

RULE_ID = "SKY-A102"

_SOURCE_EXTENSIONS = {
    ".cs",
    ".dart",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rs",
    ".ts",
    ".tsx",
}
_TEST_SUFFIXES = (
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    "_test.go",
    "_test.py",
    "Test.java",
    "Tests.cs",
)
_HIGH_RISK_HINTS = {
    "auth": "auth",
    "authorization": "auth",
    "authorize": "auth",
    "billing": "billing",
    "checkout": "billing",
    "csrf": "auth",
    "invoice": "billing",
    "jwt": "auth",
    "login": "auth",
    "password": "auth",
    "payment": "billing",
    "permission": "auth",
    "policy": "auth",
    "rate_limit": "rate_limit",
    "ratelimit": "rate_limit",
    "security": "security",
    "session": "auth",
    "subscription": "billing",
    "tax": "billing",
    "tenant": "multitenancy",
    "token": "auth",
    "validator": "validation",
    "validation": "validation",
    "webhook": "integration",
}
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def detect_test_impact_gaps(repo_root: Path | str, changed_files) -> list[dict]:
    """Warn when high-risk source changes have no accompanying test file change."""
    root = Path(repo_root)
    paths = [_normalize_path(root, item) for item in changed_files or []]
    if not paths or any(_is_test_path(path) for path in paths):
        return []

    findings = []
    for path in paths:
        risk_area = _risk_area(path)
        if risk_area is None:
            continue
        findings.append(_make_finding(path, risk_area))

    return findings[:10]


def _normalize_path(root: Path, item) -> str:
    path = Path(str(item))
    try:
        if path.is_absolute():
            path = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        pass
    return path.as_posix()


def _is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    basename = Path(normalized).name
    parts = {part.lower() for part in normalized.split("/")}
    return (
        "test" in parts
        or "tests" in parts
        or basename.startswith("test_")
        or any(basename.endswith(suffix) for suffix in _TEST_SUFFIXES)
    )


def _risk_area(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    suffix = Path(normalized).suffix.lower()
    if suffix not in _SOURCE_EXTENSIONS or _is_test_path(normalized):
        return None

    haystack = normalized.lower().replace("-", "_")
    tokens = {
        token
        for token in _TOKEN_SPLIT_RE.split(haystack.replace("_", "/"))
        if token
    }
    for hint, risk_area in _HIGH_RISK_HINTS.items():
        if hint in haystack or hint in tokens:
            return risk_area
    return None


def _make_finding(path: str, risk_area: str) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "test_impact",
        "severity": "LOW",
        "message": (
            "AI defect signal: high-risk code changed without any test file "
            "changed. Add or update relevant tests, or document why behavior "
            "is unchanged."
        ),
        "file": path,
        "line": 1,
        "col": 0,
        "category": "ai_defect",
        "defect_type": "test_impact_gap",
        "vibe_category": "test_impact_gap",
        "metadata": {
            "risk_area": risk_area,
            "changed_file": path,
            "test_files_changed": 0,
            "signal_only": True,
            "blocking_recommended": False,
        },
    }
