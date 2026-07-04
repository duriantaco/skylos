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
_ASSERTION_RE = re.compile(
    r"(\bassert\b|"
    r"\bself\.assert[A-Z]\w*\s*\(|"
    r"\bexpect\s*\(|"
    r"\bassert(?:Equals?|True|False|NotNull|Null|That|Throws)\s*\(|"
    r"\bassertThat\s*\(|"
    r"\bAssert\.(?:Equal|NotEqual|True|False|NotNull|Null|Throws)\s*\(|"
    r"\$this->assert[A-Z]\w*\s*\(|"
    r"\bassert(?:_eq|_ne)?!\s*\(|"
    r"\bassert\.(?:strictEqual|deepStrictEqual|equal|deepEqual|throws|ok|match)\s*\(|"
    r"\brequire\.(?:NoError|Error|Equal|NotNil|True|False)\s*\(|"
    r"\bt\.(?:Fatal|Fatalf|Error|Errorf|Fail|FailNow)\s*\(|"
    r"\bAssertions?\.)"
)
_TEST_DECL_RE = re.compile(
    r"(\bdef\s+test_[A-Za-z0-9_]+\s*\(|"
    r"\bclass\s+Test[A-Za-z0-9_]*\b|"
    r"\b(?:it|test|describe)\s*\(|"
    r"\bfunc\s+Test[A-Za-z0-9_]*\s*\(|"
    r"@\s*Test\b)"
)
_MEANINGFUL_TEST_CALL_RE = re.compile(
    r"\b(?:pytest\.raises|assertRaises|assertThrows|toThrow|throws)\s*\("
)


def detect_test_impact_gaps(
    repo_root: Path | str,
    changed_files,
    *,
    changed_file_diffs: dict[str, str] | None = None,
) -> list[dict]:
    """Warn when high-risk source changes have no accompanying test file change."""
    root = Path(repo_root)
    paths = [_normalize_path(root, item) for item in changed_files or []]
    if not paths:
        return []
    test_paths = [path for path in paths if _is_test_path(path)]
    diff_map = _normalize_diff_map(root, changed_file_diffs)
    if test_paths and any(
        _test_change_is_meaningful(root, path, diff_text=diff_map.get(path))
        for path in test_paths
    ):
        return []

    findings = []
    for path in paths:
        if not _changed_source_exists(root, path):
            continue
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


def _normalize_diff_map(
    root: Path,
    changed_file_diffs: dict[str, str] | None,
) -> dict[str, str]:
    normalized = {}
    for path, diff_text in (changed_file_diffs or {}).items():
        normalized[_normalize_path(root, path)] = str(diff_text or "")
    return normalized


def _test_change_is_meaningful(
    root: Path,
    path: str,
    *,
    diff_text: str | None = None,
) -> bool:
    if diff_text is not None:
        added_source = "\n".join(_added_lines_from_diff(diff_text))
        return _test_source_has_meaningful_signal(added_source)

    resolved = _resolve_repo_path(root, path)
    if resolved is None:
        return True
    if not resolved.exists() or not resolved.is_file():
        return False
    try:
        source = resolved.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return True
    return _test_source_has_meaningful_signal(source)


def _added_lines_from_diff(diff_text: str):
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue
        if raw_line.startswith("+"):
            yield raw_line[1:]


def _resolve_repo_path(root: Path, path: str) -> Path | None:
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_resolved / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root_resolved)
        return resolved
    except (OSError, ValueError):
        return None


def _changed_source_exists(root: Path, path: str) -> bool:
    if _is_test_path(path):
        return False
    resolved = _resolve_repo_path(root, path)
    if resolved is None:
        return False
    return resolved.is_file()


def _test_source_has_meaningful_signal(source: str) -> bool:
    code = _code_without_strings_or_comments(source)
    if _ASSERTION_RE.search(code):
        return True
    if _MEANINGFUL_TEST_CALL_RE.search(code):
        return True
    if not _TEST_DECL_RE.search(code):
        return False
    return False


def _code_without_strings_or_comments(source: str) -> str:
    chars = []
    quote = ""
    block_comment = False
    escape = False
    index = 0
    while index < len(source):
        char = source[index]
        next_two = source[index : index + 2]
        next_three = source[index : index + 3]

        if block_comment:
            if next_two == "*/":
                chars.extend("  ")
                block_comment = False
                index += 2
                continue
            chars.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if escape:
            chars.append("\n" if char == "\n" else " ")
            escape = False
            index += 1
            continue

        if quote:
            if char == "\\":
                escape = True
                chars.append(" ")
                index += 1
                continue
            if source.startswith(quote, index):
                chars.extend(" " * len(quote))
                index += len(quote)
                quote = ""
                continue
            chars.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if next_two == "/*":
            chars.extend("  ")
            block_comment = True
            index += 2
            continue

        if next_two == "//":
            index = _skip_to_line_end(source, index, chars)
            continue

        if char == "#":
            index = _skip_to_line_end(source, index, chars)
            continue

        if next_three in {"'''", '"""'}:
            quote = next_three
            chars.extend("   ")
            index += 3
            continue

        if char in {"'", '"', "`"}:
            quote = char
            chars.append(" ")
            index += 1
            continue

        chars.append(char)
        index += 1
    return "".join(chars)


def _skip_to_line_end(source: str, index: int, chars: list[str]) -> int:
    while index < len(source) and source[index] != "\n":
        chars.append(" ")
        index += 1
    return index


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
