"""SKY-L021: Security Control Regression Detection.

Detects security controls being removed in diffs — auth decorators,
CSRF protection, TLS verification, crypto downgrades, rate limiting removal,
input validation, security headers, encryption, logging/audit, sanitization,
and permission checks.
"""

from __future__ import annotations

import re

from skylos.constants import get_non_library_dir_kind

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
    r"(?P<control>validate|sanitize|html\.escape|bleach\.clean|markupsafe\.escape|"
    r"(?<![.\w])escape)\("
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
    r"(?P<control>html\.escape|bleach\.clean|markupsafe\.escape|DOMPurify\.sanitize|"
    r"escape_string|parameterized)\("
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
_CSRF_EXEMPT_RE = re.compile(r"^\s*@csrf_exempt\b")
_HASH_CALL_RE = re.compile(r"(?:hashlib\.)?(\w+)\(")


def _is_test_file(file_path: str) -> bool:
    return get_non_library_dir_kind(file_path) == "test"


def _looks_like_metadata_string(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(('"', "'"))


def _has_verify_setting(line: str, pattern: re.Pattern[str]) -> bool:
    if _looks_like_metadata_string(line):
        return False
    return bool(pattern.search(line))


def _control_calls(line: str, pattern: re.Pattern[str]) -> set[str]:
    if _looks_like_metadata_string(line):
        return set()
    return {match.group("control") for match in pattern.finditer(line)}


def _removed_csrf_protection(line: str) -> str | None:
    if "csrf_protect" in line:
        stripped = line.strip()
        if (
            stripped.startswith("@csrf_protect")
            or "csrf_protect(" in line
            or "import csrf_protect" in line
        ):
            return "csrf_protect"
        return None

    for csrf_name in _CSRF_PROTECTIONS - {"csrf_protect"}:
        if csrf_name in line:
            return csrf_name
    return None


def detect_security_regressions(
    diff_text: str,
    file_path: str,
) -> list[dict]:
    if _is_test_file(file_path):
        return []

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

    added_auth_depends = {
        name
        for _, line in added_lines
        for name in _auth_dependency_names(line)
    }
    for line_no, line in removed_lines:
        for m in _DEPENDS_RE.finditer(line):
            if m.group(1) in _AUTH_DEPENDS and m.group(1) not in added_auth_depends:
                findings.append(
                    _make_finding(
                        file_path,
                        line_no,
                        f"Auth dependency Depends({m.group(1)}) was removed",
                        control_type="auth",
                    )
                )

    for line_no, line in removed_lines:
        csrf_name = _removed_csrf_protection(line)
        if csrf_name:
            findings.append(
                _make_finding(
                    file_path,
                    line_no,
                    f"CSRF protection '{csrf_name}' was removed",
                    control_type="csrf",
                )
            )

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
        _has_verify_setting(line, _VERIFY_TRUE_RE) for _, line in removed_lines
    )
    for line_no, line in added_lines:
        if _has_verify_setting(line, _VERIFY_FALSE_RE):
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

    added_validation_calls = set().union(
        *(_control_calls(line, _VALIDATION_CALLS_RE) for _, line in added_lines)
    )
    for line_no, line in removed_lines:
        removed_validation_calls = _control_calls(line, _VALIDATION_CALLS_RE)
        if removed_validation_calls - added_validation_calls:
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

    added_sanitization_calls = set().union(
        *(_control_calls(line, _SANITIZATION_CALLS_RE) for _, line in added_lines)
    )
    for line_no, line in removed_lines:
        removed_sanitization_calls = _control_calls(line, _SANITIZATION_CALLS_RE)
        if removed_sanitization_calls - added_sanitization_calls:
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

    findings.extend(
        _detect_route_guard_regressions(diff_text, file_path, findings)
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


# --- Route guard regressions (FastAPI dependencies, Express middleware,
# object-level ownership checks) ---------------------------------------------

_DEPENDS_ANY_RE = re.compile(r"\b(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)")
_AUTH_DEP_NAME_RE = re.compile(
    r"(?i)(?:current_?(?:active_?)?(?:super_?)?user|superuser|admin|auth|"
    r"token|permission|role|login|jwt|verify|api_?key|require_|principal)"
)
_AUTH_ANNOTATION_RE = re.compile(
    r":\s*(?:Annotated\[[^\]]*\]|"
    r"(?P<name>[A-Z]\w*))\s*(?:=[^,)]*)?\s*[,)]?\s*(?:#.*)?$"
)
_AUTH_ANNOTATION_NAME_RE = re.compile(
    r"^(?:Current\w*|\w*(?:Superuser|SuperUser|Admin|AuthUser|Authenticated|"
    r"Principal)\w*|\w*Auth(?:Dep|Dependency)?|TokenDep)$"
)
_PARAM_LINE_RE = re.compile(r"^\s*[A-Za-z_]\w*\s*:\s*[A-Za-z_][\w\[\], .]*\s*[,)]")
_PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_JS_FUNC_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\())"
)
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@ ?(.*)$")
_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_EXPRESS_ROUTE_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*"
    r"(['\"`])([^'\"`]+)\3",
    re.DOTALL,
)
_EXPRESS_ROUTE_START_RE = re.compile(
    r"\b[A-Za-z_$][\w$]*\s*\.\s*(?:get|post|put|patch|delete|all)\s*\("
)
_EXPRESS_AUTH_RE = re.compile(
    r"(?<![\w$.])(?:auth(?!\s*\.\s*optional\b)(?:\s*\.\s*[A-Za-z_]\w*)?|"
    r"authenticate\w*|authenticated|requireAuth\w*|requiresAuth|isAuthenticated|"
    r"ensureAuthenticated|ensureLoggedIn|requireLogin|requireUser|requireAdmin|"
    r"requireRole|isAdmin|verifyToken|verifyJwt|verifyJWT|checkJwt|jwtAuth|"
    r"authMiddleware|authorize\w*|passport\s*\.\s*authenticate|withAuth|"
    r"protect|jwt\s*\()(?![\w$])"
)
_OWNERSHIP_SUBJECT_RE = re.compile(
    r"(?i)(?:owner|author|user_?id|created_?by|current_user|request\.user|"
    r"req\.(?:user|auth)|g\.user|\.user\b|is_superuser|is_admin|is_staff|"
    r"isAdmin|isOwner)"
)
_OWNERSHIP_COMPARE_RE = re.compile(r"(?:!==|===|!=|==|\bis\s+not\b|\bnot\b|!\s*[\w(])")
_IF_RE = re.compile(r"^\s*(?:\}\s*else\s+)?(?:el)?if\b")
_DENY_RE = re.compile(
    r"(?:abort\(\s*40[13]\b|HTTP_40[13]|status_code\s*=\s*40[13]\b|"
    r"PermissionDenied|\bForbidden\w*|NotAuthorized|Unauthori[sz]ed\w*\(|"
    r"status\(\s*40[13]\s*\)|sendStatus\(\s*40[13]\s*\)|"
    r"(?:raise|throw|return)\b.*\b40[13]\b|"
    r"Not enough permissions|permission denied)",
    re.IGNORECASE,
)
_GUARD_HELPER_RE = re.compile(
    r"(?i)\b(?:\w*owner\w*|\w*permission\w*|authori[sz]e\w*|can_\w+|"
    r"ensure_\w+|require_\w+|check_\w+|assert_\w+|verify_\w+)\s*\("
)


def _auth_dependency_names(line: str) -> set[str]:
    names = set()
    for m in _DEPENDS_ANY_RE.finditer(line):
        name = m.group(1)
        if name in _AUTH_DEPENDS or _AUTH_DEP_NAME_RE.search(name.split(".")[-1]):
            names.add(name)
    return names


def _auth_annotations(line: str) -> set[str]:
    if not (_PARAM_LINE_RE.match(line) or _PY_DEF_RE.match(line)):
        return set()
    found = set()
    for m in re.finditer(r":\s*([A-Z]\w*)\b", line):
        if _AUTH_ANNOTATION_NAME_RE.match(m.group(1)):
            found.add(m.group(1))
    return found


def _parse_diff_entries(diff_text: str) -> list[tuple[str, int, str, int, str]]:
    """Return (kind, new_line, text, block_id, hunk_context) for each line.

    ``new_line`` is the new-file line the entry sits at (for removed lines,
    the new-file line that follows the removal point).
    """
    entries: list[tuple[str, int, str, int, str]] = []
    new_line = 0
    block = 0
    in_change = False
    context = ""
    for raw in diff_text.splitlines():
        if raw.startswith("@@"):
            m = _HUNK_HEADER_RE.match(raw)
            if m:
                new_line = int(m.group(2))
                context = m.group(3) or ""
            block += 1
            in_change = False
            continue
        if raw.startswith(("---", "+++", "diff ", "index ")):
            continue
        if raw.startswith("-"):
            if not in_change:
                block += 1
                in_change = True
            entries.append(("-", new_line, raw[1:], block, context))
        elif raw.startswith("+"):
            if not in_change:
                block += 1
                in_change = True
            entries.append(("+", new_line, raw[1:], block, context))
            new_line += 1
        else:
            in_change = False
            text = raw[1:] if raw.startswith(" ") else raw
            entries.append((" ", new_line, text, block, context))
            new_line += 1
    return entries


def _def_name(text: str) -> str | None:
    m = _PY_DEF_RE.match(text)
    if m:
        return m.group(1)
    m = _JS_FUNC_RE.search(text)
    if m:
        return m.group(1) or m.group(2)
    return None


def _deleted_function_blocks(entries) -> set[int]:
    removed_defs: dict[str, set[int]] = {}
    added_defs: set[str] = set()
    for kind, _, text, block, _ in entries:
        name = _def_name(text)
        if not name:
            continue
        if kind == "-":
            removed_defs.setdefault(name, set()).add(block)
        elif kind == "+":
            added_defs.add(name)
    blocks: set[int] = set()
    for name, name_blocks in removed_defs.items():
        if name not in added_defs:
            blocks.update(name_blocks)
    return blocks


def _enclosing_function(entries, index: int) -> str | None:
    for back in range(index - 1, -1, -1):
        kind, _, text, _, context = entries[back]
        if kind == "+":
            continue
        name = _def_name(text)
        if name:
            return name
    context = entries[index][4]
    return _def_name(context) if context else None


def _route_guard_finding(file_path, line, message, control_type="auth") -> dict:
    return _make_finding(file_path, line, message, control_type=control_type)


def _detect_route_guard_regressions(
    diff_text: str, file_path: str, existing: list[dict]
) -> list[dict]:
    entries = _parse_diff_entries(diff_text)
    if not entries:
        return []
    deleted_blocks = _deleted_function_blocks(entries)
    already = {
        (f.get("line"), f.get("message"))
        for f in existing
        if f.get("rule_id") == RULE_ID
    }
    findings: list[dict] = []

    def add(line, message, control_type="auth"):
        finding = _route_guard_finding(file_path, line, message, control_type)
        key = (finding["line"], finding["message"])
        if key not in already:
            already.add(key)
            findings.append(finding)

    lower_path = str(file_path).lower()
    if lower_path.endswith(".py"):
        _python_dependency_regressions(entries, deleted_blocks, existing, add)
    if lower_path.endswith(_JS_SUFFIXES):
        _express_middleware_regressions(entries, add)
    if lower_path.endswith((".py", *_JS_SUFFIXES)):
        _ownership_check_regressions(entries, deleted_blocks, add)
    return findings


def _python_dependency_regressions(entries, deleted_blocks, existing, add) -> None:
    added_names: set[str] = set()
    added_annotations: set[str] = set()
    for kind, _, text, _, _ in entries:
        if kind == "+":
            added_names.update(_auth_dependency_names(text))
            added_annotations.update(_auth_annotations(text))
    reported_existing = {
        f.get("message", "")
        for f in existing
        if f.get("rule_id") == RULE_ID and "Depends(" in f.get("message", "")
    }
    for kind, line, text, block, _ in entries:
        if kind != "-" or block in deleted_blocks:
            continue
        for name in sorted(_auth_dependency_names(text)):
            if name in added_names or name in _AUTH_DEPENDS:
                # _AUTH_DEPENDS names are handled by the legacy check above.
                continue
            if any(name in message for message in reported_existing):
                continue
            where = (
                "route decorator dependencies=[...]"
                if "dependencies" in text
                else "route signature"
            )
            add(
                line,
                f"Auth dependency Depends({name}) was removed from the {where}",
            )
        for annotation in sorted(_auth_annotations(text)):
            if annotation in added_annotations:
                continue
            add(
                line,
                f"Auth-injected parameter of type {annotation} was removed "
                "from the route signature",
            )


def _collect_route_statement(entries, start: int, sides: set[str]) -> str:
    parts: list[str] = []
    seen = 0
    for index in range(start, len(entries)):
        kind, _, text, _, _ = entries[index]
        if kind not in sides:
            continue
        head = text
        stop = False
        for marker in ("=>", "function"):
            pos = head.find(marker)
            if pos >= 0:
                head = head[:pos]
                stop = True
        # Drop the handler's parameter list: "(req, res) =>".
        if stop:
            head = re.sub(r"(?:async\s*)?\([^()]*\)\s*$", "", head.rstrip())
        parts.append(head)
        seen += 1
        if stop or seen >= 8:
            break
    return "\n".join(parts)


def _express_routes(entries, sides: set[str]):
    routes = []
    for index, (kind, line, text, _, _) in enumerate(entries):
        if kind not in sides:
            continue
        if not _EXPRESS_ROUTE_START_RE.search(text):
            continue
        statement = _collect_route_statement(entries, index, sides)
        # The path may sit on the next line: router.put(\n  '/x',\n  auth, ...
        m = _EXPRESS_ROUTE_RE.search(statement)
        if not m:
            continue
        routes.append(
            {
                "key": (m.group(1), m.group(2), m.group(4)),
                "index": index,
                "line": line,
                "text": statement,
            }
        )
    return routes


def _express_middleware_regressions(entries, add) -> None:
    old_routes = _express_routes(entries, {" ", "-"})
    if not old_routes:
        return
    new_routes = {route["key"]: route for route in _express_routes(entries, {" ", "+"})}
    for route in old_routes:
        middleware = _EXPRESS_AUTH_RE.findall(route["text"].split(route["key"][2], 1)[-1])
        if not middleware:
            continue
        # The auth token must sit on a removed line to be a change.
        removed_auth = False
        for kind, _, text, _, _ in entries[route["index"] : route["index"] + 8]:
            if kind == "-" and _EXPRESS_AUTH_RE.search(text):
                removed_auth = True
                break
        if not removed_auth:
            continue
        new_route = new_routes.get(route["key"])
        if new_route is None:
            continue
        new_tail = new_route["text"].split(route["key"][2], 1)[-1]
        if _EXPRESS_AUTH_RE.search(new_tail):
            continue
        receiver, method, path = route["key"]
        name = re.sub(r"\s+", "", middleware[0])
        add(
            new_route["line"],
            f"Auth middleware '{name}' was removed from "
            f"{receiver}.{method}('{path}')",
        )


def _is_ownership_condition(text: str) -> bool:
    if not _IF_RE.match(text):
        return False
    return bool(
        _OWNERSHIP_SUBJECT_RE.search(text) and _OWNERSHIP_COMPARE_RE.search(text)
    )


def _ownership_guards(entries, kinds: set[str]):
    guards = []
    visible = [
        (index, entry) for index, entry in enumerate(entries) if entry[0] in kinds
    ]
    for pos, (index, entry) in enumerate(visible):
        kind, line, text, block, _ = entry
        if not _is_ownership_condition(text):
            continue
        window = [text] + [item[1][2] for item in visible[pos + 1 : pos + 4]]
        deny_offset = None
        for offset, candidate in enumerate(window):
            if _DENY_RE.search(candidate):
                deny_offset = offset
                break
            if offset and _IF_RE.match(candidate):
                break
        if deny_offset is None:
            continue
        span = [visible[pos + k][1] for k in range(deny_offset + 1)]
        guards.append((index, entry, span))
    return guards


def _ownership_check_regressions(entries, deleted_blocks, add) -> None:
    removed = [
        (index, entry, span)
        for index, entry, span in _ownership_guards(entries, {" ", "-"})
        if entry[0] == "-" and all(item[0] == "-" for item in span)
    ]
    if not removed:
        return
    added_guards = [g for g in _ownership_guards(entries, {"+"})]
    added_helper = any(
        kind == "+" and _GUARD_HELPER_RE.search(text)
        for kind, _, text, _, _ in entries
    )
    if added_guards or added_helper:
        return
    for index, entry, _ in removed:
        _, line, text, block, _ = entry
        if block in deleted_blocks:
            continue
        function = _enclosing_function(entries, index)
        where = f" from '{function}'" if function else ""
        add(
            line,
            f"Ownership/authorization check `{text.strip()[:80]}` was removed{where}",
            control_type="permission",
        )
