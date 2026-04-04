"""SKY-L021: Security Control Regression Detection.

Detects security controls being removed in diffs — auth decorators,
CSRF protection, TLS verification, crypto downgrades, rate limiting removal,
input validation, security headers, encryption, logging/audit, sanitization,
and permission checks.
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

_VALIDATION_DECORATORS = {
    "validate",
    "validator",
    "field_validator",
    "validates",
    "validates_schema",
}

_VALIDATION_CALLS_RE = re.compile(
    r"(?:validate|sanitize|escape|html\.escape|bleach\.clean|markupsafe\.escape)\("
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
}

_SECURITY_HEADER_MIDDLEWARE_RE = re.compile(
    r"(?:SecurityMiddleware|helmet\(|secure_headers)"
)

_ENCRYPTION_CALLS_RE = re.compile(r"(?:Fernet|AES|encrypt\(|decrypt\()")

_SECRET_KEY_RE = re.compile(r"SECRET_KEY\s*=")

_AUDIT_CALLS_RE = re.compile(
    r'(?:audit_log\(|logger\.info\(["\']access|logger\.warning\(["\']auth)'
)

_AUDIT_DECORATORS = {
    "audit",
    "log_access",
}

_SANITIZATION_CALLS_RE = re.compile(
    r"(?:html\.escape\(|bleach\.clean\(|markupsafe\.escape\(|DOMPurify\.sanitize\(|"
    r"escape_string\(|parameterized\(|text\()"
)

_PERMISSION_CALLS_RE = re.compile(
    r"(?:has_permission\(|check_permission\(|has_perm\(|user_passes_test)"
)

_PERMISSION_DECORATORS = {
    "permission_classes",
    "has_role",
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
                    control_type="auth",
                )
            )

        if base_name in _VALIDATION_DECORATORS:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"Validation decorator @{dec_name} was removed",
                    control_type="validation",
                )
            )

        if base_name in _AUDIT_DECORATORS:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"Audit decorator @{dec_name} was removed",
                    control_type="logging",
                )
            )

        if base_name in _PERMISSION_DECORATORS:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"Permission decorator @{dec_name} was removed",
                    control_type="permission",
                )
            )

        if base_name in _RATE_LIMIT_DECORATORS or dec_name in _RATE_LIMIT_DECORATORS:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"Rate limiting decorator @{dec_name} was removed",
                    control_type="rate_limit",
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
                        control_type="auth",
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
                        control_type="csrf",
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
                    control_type="csrf",
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
                        control_type="tls",
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        "TLS verification disabled with verify=False",
                        control_type="tls",
                    )
                )

    removed_hashes = set()
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
                        control_type="crypto",
                    )
                )

    for line_no, line in removed_lines:
        if _VALIDATION_CALLS_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Validation/sanitization call was removed",
                    control_type="validation",
                )
            )

    for line_no, line in removed_lines:
        stripped = line.strip()
        if ("serializers." in stripped or "forms." in stripped) and (
            "validate" in stripped.lower() or "clean" in stripped.lower()
        ):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Django/DRF validator was removed",
                    control_type="validation",
                )
            )

    for line_no, line in removed_lines:
        for header in _SECURITY_HEADERS:
            if header in line:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"Security header '{header}' was removed",
                        control_type="headers",
                    )
                )
                break

    for line_no, line in removed_lines:
        if _SECURITY_HEADER_MIDDLEWARE_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Security header middleware was removed",
                    control_type="headers",
                )
            )

    for line_no, line in removed_lines:
        if _ENCRYPTION_CALLS_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Encryption call was removed",
                    control_type="encryption",
                )
            )

    for line_no, line in removed_lines:
        if _SECRET_KEY_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "SECRET_KEY assignment was removed",
                    control_type="encryption",
                )
            )

    for line_no, line in removed_lines:
        if _AUDIT_CALLS_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Audit/logging call was removed",
                    control_type="logging",
                )
            )

    for line_no, line in removed_lines:
        if _SANITIZATION_CALLS_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Sanitization call was removed",
                    control_type="sanitization",
                )
            )

    for line_no, line in removed_lines:
        if _PERMISSION_CALLS_RE.search(line):
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    "Permission check was removed",
                    control_type="permission",
                )
            )

    return findings


def _make_finding(
    file_path: str, line: int, message: str, control_type: str = "auth"
) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "security_regression",
        "severity": "HIGH",
        "message": f"Security control regression: {message}",
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
        "control_type": control_type,
    }
