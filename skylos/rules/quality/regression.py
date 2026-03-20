"""SKY-L021: Security Control Regression Detection.

Detects security controls being removed in diffs — auth decorators,
CSRF protection, TLS verification, crypto downgrades, rate limiting removal.
"""

from __future__ import annotations

import re

RULE_ID = "SKY-L021"

_AUTH_DECORATORS = {
    "login_required",
    "require_auth",
    "requires_auth",
    "authenticated",
    "permission_required",
    "permissions_required",
    "jwt_required",
    "token_required",
}

_AUTH_DEPENDS = {
    "get_current_user",
    "get_current_active_user",
    "require_admin",
    "verify_token",
}

_CSRF_PROTECTIONS = {
    "CsrfViewMiddleware",
    "csrf_protect",
    "CSRFProtect",
}

_RATE_LIMIT_DECORATORS = {
    "rate_limit",
    "ratelimit",
    "throttle",
    "limiter.limit",
    "slowapi",
}

_WEAK_HASHES = {"md5", "sha1"}
_STRONG_HASHES = {"sha256", "sha384", "sha512", "bcrypt", "argon2", "scrypt", "pbkdf2"}

_DECORATOR_RE = re.compile(r"^[-]\s*@(\w+(?:\.\w+)*)")
_DEPENDS_RE = re.compile(r"Depends\((\w+)\)")
_VERIFY_TRUE_RE = re.compile(r"verify\s*=\s*True")
_VERIFY_FALSE_RE = re.compile(r"verify\s*=\s*False")
_CSRF_EXEMPT_RE = re.compile(r"@csrf_exempt")
_HASH_CALL_RE = re.compile(r"(?:hashlib\.)?(\w+)\(")


def detect_security_regressions(
    diff_text: str,
    file_path: str,
) -> list[dict]:

    findings: list[dict] = []
    current_line = 0

    removed_lines: list[tuple[int, str]] = []
    added_lines: list[tuple[int, str]] = []

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw_line)
            if match:
                current_line = int(match.group(1)) - 1
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            removed_lines.append((current_line, raw_line[1:]))
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            added_lines.append((current_line, raw_line[1:]))
        else:
            current_line += 1

    for line_no, line in removed_lines:
        m = _DECORATOR_RE.match("-" + line.lstrip())
        if not m:
            stripped = line.strip()
            if stripped.startswith("@"):
                dec_name = stripped[1:].split("(")[0].strip()
            else:
                continue
        else:
            dec_name = m.group(1)

        base_name = dec_name.split(".")[-1]
        if base_name in _AUTH_DECORATORS:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"Auth decorator @{dec_name} was removed",
                )
            )

    for line_no, line in removed_lines:
        for m in _DEPENDS_RE.finditer(line):
            if m.group(1) in _AUTH_DEPENDS:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"Auth dependency Depends({m.group(1)}) was removed",
                    )
                )

    for line_no, line in removed_lines:
        for csrf_name in _CSRF_PROTECTIONS:
            if csrf_name in line:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"CSRF protection '{csrf_name}' was removed",
                    )
                )
                break

    for line_no, line in added_lines:
        if _CSRF_EXEMPT_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "csrf_exempt decorator added — disables CSRF protection",
                )
            )

    has_removed_verify_true = any(
        _VERIFY_TRUE_RE.search(line) for _, line in removed_lines
    )
    for line_no, line in added_lines:
        if _VERIFY_FALSE_RE.search(line):
            if has_removed_verify_true:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        "TLS verification downgraded from verify=True to verify=False",
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        "TLS verification disabled with verify=False",
                    )
                )

    removed_hashes = set()
    added_hashes = set()
    for _, line in removed_lines:
        for m in _HASH_CALL_RE.finditer(line):
            h = m.group(1).lower()
            if h in _STRONG_HASHES:
                removed_hashes.add(h)
    for line_no, line in added_lines:
        for m in _HASH_CALL_RE.finditer(line):
            h = m.group(1).lower()
            if h in _WEAK_HASHES and removed_hashes:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"Crypto downgraded from {', '.join(sorted(removed_hashes))} to {h}",
                    )
                )

    for line_no, line in removed_lines:
        stripped = line.strip()
        if stripped.startswith("@"):
            dec_name = stripped[1:].split("(")[0].strip()
            base_name = dec_name.split(".")[-1]
            if (
                base_name in _RATE_LIMIT_DECORATORS
                or dec_name in _RATE_LIMIT_DECORATORS
            ):
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"Rate limiting decorator @{dec_name} was removed",
                    )
                )

    return findings


def _make_finding(file_path: str, line: int, message: str) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "security_regression",
        "severity": "HIGH",
        "message": f"Security control regression: {message}",
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
    }
