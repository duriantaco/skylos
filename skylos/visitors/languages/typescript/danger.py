from __future__ import annotations

import math
from tree_sitter import Language, Query, QueryCursor
import tree_sitter_typescript as tsts

try:
    TS_LANG: Language | None = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None

_SAFE_EXEC_OBJECTS: set[str] = {
    "regex",
    "re",
    "regexp",
    "pattern",
    "reg",
    "db",
    "stmt",
    "query",
    "statement",
    "cursor",
    "conn",
    "connection",
}

# ---------------------------------------------------------------------------
# Module-level compiled query cache
# ---------------------------------------------------------------------------
_QUERY_CACHE: dict[tuple[int, str], Query] = {}

# Simple danger patterns (no JSX — works in both TS and TSX grammars)
_SIMPLE_PATTERN = """
(call_expression function: (identifier) @eval (#eq? @eval "eval"))
(assignment_expression left: (member_expression property: (property_identifier) @innerHTML (#eq? @innerHTML "innerHTML")))
(call_expression function: (member_expression object: (identifier) @doc_obj (#eq? @doc_obj "document") property: (property_identifier) @doc_write (#eq? @doc_write "write")))
(new_expression constructor: (identifier) @new_func (#eq? @new_func "Function"))
(call_expression function: (identifier) @timeout_fn (#eq? @timeout_fn "setTimeout") arguments: (arguments (string) @timeout_str))
(call_expression function: (identifier) @interval_fn (#eq? @interval_fn "setInterval") arguments: (arguments (string) @interval_str))
(assignment_expression left: (member_expression property: (property_identifier) @outerHTML (#eq? @outerHTML "outerHTML")))
(member_expression property: (property_identifier) @proto (#eq? @proto "__proto__"))
(call_expression function: (member_expression object: (identifier) @math_random_obj (#eq? @math_random_obj "Math") property: (property_identifier) @math_random (#eq? @math_random "random")))
"""

# JSX-only pattern (may fail compilation on plain TS grammar — that's OK)
_JSX_PATTERN = '(jsx_attribute (property_identifier) @dangerously (#eq? @dangerously "dangerouslySetInnerHTML"))'

_SIMPLE_MAP: dict[str, tuple[str, str, str]] = {
    "eval": ("SKY-D201", "CRITICAL", "Use of eval() detected"),
    "innerHTML": (
        "SKY-D226",
        "HIGH",
        "Unsafe innerHTML assignment — XSS vulnerability",
    ),
    "doc_write": (
        "SKY-D226",
        "HIGH",
        "document.write() can lead to XSS vulnerabilities",
    ),
    "new_func": ("SKY-D202", "CRITICAL", "new Function() is equivalent to eval()"),
    "timeout_str": (
        "SKY-D202",
        "HIGH",
        "setTimeout() with string argument is equivalent to eval()",
    ),
    "interval_str": (
        "SKY-D202",
        "HIGH",
        "setInterval() with string argument is equivalent to eval()",
    ),
    "outerHTML": (
        "SKY-D226",
        "HIGH",
        "Unsafe outerHTML assignment — XSS vulnerability",
    ),
    "dangerously": (
        "SKY-D226",
        "HIGH",
        "dangerouslySetInnerHTML bypasses React's XSS protections",
    ),
    "proto": ("SKY-D510", "HIGH", "Prototype pollution via __proto__ access"),
    "math_random": (
        "SKY-D250",
        "MEDIUM",
        "Math.random() is not cryptographically secure. Use crypto.getRandomValues() or crypto.randomUUID().",
    ),
}

# Complex danger patterns: need post-processing logic
_COMPLEX_PATTERN = """
(call_expression function: (member_expression object: (identifier) @exec_obj property: (property_identifier) @exec_prop (#eq? @exec_prop "exec")))
(string) @string_node
(template_string) @template_node
(call_expression function: (identifier) @fetch_fn (#eq? @fetch_fn "fetch") arguments: (arguments) @fetch_args)
(call_expression function: (member_expression object: (identifier) @axios_obj (#eq? @axios_obj "axios")) arguments: (arguments) @axios_args)
(call_expression function: (member_expression property: (property_identifier) @create_hash (#eq? @create_hash "createHash")) arguments: (arguments) @hash_args)
(call_expression function: (member_expression property: (property_identifier) @redirect_prop (#eq? @redirect_prop "redirect")) arguments: (arguments) @redirect_args)
(call_expression function: (member_expression property: (property_identifier) @sql_query (#eq? @sql_query "query")) arguments: (arguments (template_string) @sql_query_tpl))
(call_expression function: (member_expression property: (property_identifier) @sql_exec_method (#eq? @sql_exec_method "exec")) arguments: (arguments (template_string) @sql_exec_tpl))
(call_expression function: (member_expression property: (property_identifier) @sql_execute (#eq? @sql_execute "execute")) arguments: (arguments (template_string) @sql_execute_tpl))
(call_expression function: (identifier) @require_fn (#eq? @require_fn "require") arguments: (arguments (identifier) @require_var_arg))
(call_expression function: (member_expression property: (property_identifier) @jwt_decode_prop (#eq? @jwt_decode_prop "decode")) arguments: (arguments) @jwt_decode_args)
(call_expression function: (identifier) @cors_fn (#eq? @cors_fn "cors") arguments: (arguments) @cors_args)
(call_expression function: (member_expression object: (identifier) @console_log_obj (#eq? @console_log_obj "console") property: (property_identifier) @console_log_method) arguments: (arguments) @console_log_args)
(call_expression function: (member_expression property: (property_identifier) @cookie_set_prop (#eq? @cookie_set_prop "cookie")) arguments: (arguments) @cookie_set_args)
(call_expression function: (member_expression object: (identifier) @ls_set_obj (#eq? @ls_set_obj "localStorage") property: (property_identifier) @ls_set_method (#eq? @ls_set_method "setItem")) arguments: (arguments) @ls_set_args)
(call_expression function: (member_expression object: (identifier) @ss_set_obj (#eq? @ss_set_obj "sessionStorage") property: (property_identifier) @ss_set_method (#eq? @ss_set_method "setItem")) arguments: (arguments) @ss_set_args)
"""

_INTERNAL_URL_PREFIXES = (
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "https://localhost",
    "https://127.0.0.1",
    "https://0.0.0.0",
)

_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)

_LOG_METHODS = {"log", "warn", "error", "info", "debug", "trace"}

_LOG_SENSITIVE_SUFFIXES = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "authorization",
    "privatekey",
    "accesstoken",
    "refreshtoken",
    "sessionid",
    "ssn",
    "creditcard",
    "cardnumber",
    "cvv",
    "pin",
)

_TIMING_SENSITIVE_SUFFIXES = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "hash",
    "digest",
    "hmac",
    "signature",
    "apikey",
)

_STORAGE_SENSITIVE_SUFFIXES = (
    "token",
    "auth",
    "jwt",
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "bearer",
    "accesstoken",
    "refreshtoken",
    "sessionid",
    "sessionkey",
    "privatekey",
)

_STORAGE_SAFE_PREFIXES = ("csrf", "xsrf")

_ERROR_DISCLOSURE_PROPS = {"stack", "sql", "sqlMessage", "sqlState"}

_RESPONSE_METHODS = {"json", "send", "write", "end"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _get_query(lang: Language, key: str, pattern: str) -> Query | None:
    cache_key = (id(lang), key)
    if cache_key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[cache_key] = Query(lang, pattern)
        except Exception:
            _QUERY_CACHE[cache_key] = None
    return _QUERY_CACHE[cache_key]


def _get_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _is_sensitive_name(name: str) -> bool:
    """Check if a variable name refers to sensitive data (for log detection)."""
    normalized = name.lower().replace("_", "")
    for suffix in _LOG_SENSITIVE_SUFFIXES:
        if normalized == suffix or normalized.endswith(suffix):
            return True
    return False


def _is_timing_sensitive(name: str) -> bool:
    """Check if a variable name is security-sensitive (for timing comparison)."""
    normalized = name.lower().replace("_", "")
    for suffix in _TIMING_SENSITIVE_SUFFIXES:
        if normalized == suffix or normalized.endswith(suffix):
            return True
    return False


def _extract_var_name(node, source_bytes: bytes) -> str | None:
    """Extract the relevant name from an identifier or member expression property."""
    if node.type == "identifier":
        return _get_text(source_bytes, node)
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop:
            return _get_text(source_bytes, prop)
    return None


_SECRET_PREFIXES = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "AKIA",
    "eyJ",
)

_SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP")


def scan_danger(
    root_node, file_path: str, lang: "Language | None" = None
) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = TS_LANG
    if not lang:
        return []

    source_bytes: bytes = root_node.text

    # Run 3 batch queries instead of 26+ individual ones
    simple_captures = _run_batch(root_node, lang, "danger_simple", _SIMPLE_PATTERN)
    jsx_captures = _run_batch(root_node, lang, "danger_jsx", _JSX_PATTERN)
    complex_captures = _run_batch(root_node, lang, "danger_complex", _COMPLEX_PATTERN)

    # Merge JSX captures into simple captures
    for k, v in jsx_captures.items():
        simple_captures.setdefault(k, []).extend(v)

    # --- Simple checks: direct capture → finding ---
    for cap_name, (rule_id, severity, message) in _SIMPLE_MAP.items():
        for node in simple_captures.get(cap_name, []):
            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- exec check (SKY-D212) ---
    for prop_node in complex_captures.get("exec_prop", []):
        call_node = prop_node.parent
        if call_node is None:
            continue
        obj_node = call_node.child_by_field_name("object")
        if obj_node is None:
            continue
        obj_name = _get_text(source_bytes, obj_node).lower()
        if obj_name in _SAFE_EXEC_OBJECTS:
            continue
        findings.append(
            {
                "rule_id": "SKY-D212",
                "severity": "HIGH",
                "message": "child_process.exec() can lead to command injection. Use execFile() instead.",
                "file": str(file_path),
                "line": prop_node.start_point[0] + 1,
                "col": 0,
            }
        )

    # --- Hardcoded secrets (SKY-S101) via batched string captures ---
    is_test_file = any(
        p in str(file_path)
        for p in ("/test/", "/tests/", "/__tests__/", ".test.", ".spec.")
    )
    for cap_name in ("string_node", "template_node"):
        for node in complex_captures.get(cap_name, []):
            text = _get_text(source_bytes, node)
            if text and text[0] in ("'", '"', "`"):
                text = text[1:]
            if text and text[-1] in ("'", '"', "`"):
                text = text[:-1]
            if len(text) >= 16:
                found_prefix = False
                for prefix in _SECRET_PREFIXES:
                    if text.startswith(prefix) or text.lower().startswith(
                        prefix.lower()
                    ):
                        findings.append(
                            {
                                "rule_id": "SKY-S101",
                                "severity": "CRITICAL",
                                "message": "Potential hardcoded secret or API key. Use environment variables instead.",
                                "file": str(file_path),
                                "line": node.start_point[0] + 1,
                                "col": 0,
                            }
                        )
                        found_prefix = True
                        break
                # Entropy-based secret detection
                if (
                    not found_prefix
                    and len(text) >= 20
                    and all(c in _BASE64_CHARS for c in text)
                    and _shannon_entropy(text) > 4.5
                ):
                    findings.append(
                        {
                            "rule_id": "SKY-S101",
                            "severity": "HIGH",
                            "message": "High-entropy string detected — possible hardcoded secret. Use environment variables instead.",
                            "file": str(file_path),
                            "line": node.start_point[0] + 1,
                            "col": 0,
                        }
                    )

            # Hardcoded internal URL (SKY-D248) — skip test files
            if not is_test_file and len(text) >= 16:
                text_lower = text.lower()
                for url_prefix in _INTERNAL_URL_PREFIXES:
                    if text_lower.startswith(url_prefix):
                        findings.append(
                            {
                                "rule_id": "SKY-D248",
                                "severity": "MEDIUM",
                                "message": "Hardcoded internal URL detected. Use environment variables for host configuration.",
                                "file": str(file_path),
                                "line": node.start_point[0] + 1,
                                "col": 0,
                            }
                        )
                        break

    # --- fetch SSRF (SKY-D216) ---
    for node in complex_captures.get("fetch_args", []):
        first_arg = _first_real_arg(node)
        if first_arg and first_arg.type == "identifier":
            findings.append(
                {
                    "rule_id": "SKY-D216",
                    "severity": "MEDIUM",
                    "message": "fetch() with variable URL — potential SSRF. Validate URL against allowlist.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- axios SSRF (SKY-D216) ---
    for node in complex_captures.get("axios_args", []):
        first_arg = _first_real_arg(node)
        if first_arg and first_arg.type == "identifier":
            findings.append(
                {
                    "rule_id": "SKY-D216",
                    "severity": "MEDIUM",
                    "message": "axios call with variable URL — potential SSRF. Validate URL against allowlist.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- Weak crypto (SKY-D207 / SKY-D208) ---
    for node in complex_captures.get("hash_args", []):
        for child in node.children:
            if child.type == "string":
                text = _get_text(source_bytes, child).strip("'\"")
                if text in ("md5", "sha1"):
                    rule = "SKY-D207" if text == "md5" else "SKY-D208"
                    findings.append(
                        {
                            "rule_id": rule,
                            "severity": "MEDIUM",
                            "message": f"Weak hash algorithm {text.upper()}. Use SHA-256 or better.",
                            "file": str(file_path),
                            "line": node.start_point[0] + 1,
                            "col": 0,
                        }
                    )
                break

    # --- Open redirect (SKY-D230) ---
    for node in complex_captures.get("redirect_args", []):
        first_arg = _first_real_arg(node)
        if first_arg and first_arg.type not in (
            "string",
            "template_string",
            "number",
        ):
            findings.append(
                {
                    "rule_id": "SKY-D230",
                    "severity": "HIGH",
                    "message": "Open redirect — res.redirect() with variable argument. Validate redirect target.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- SQL template injection (SKY-D211) ---
    for cap_name in ("sql_query_tpl", "sql_exec_tpl", "sql_execute_tpl"):
        for node in complex_captures.get(cap_name, []):
            text = _get_text(source_bytes, node).upper()
            if any(kw in text for kw in _SQL_KEYWORDS):
                findings.append(
                    {
                        "rule_id": "SKY-D211",
                        "severity": "CRITICAL",
                        "message": "SQL query built with template literal — risk of SQL injection. Use parameterized queries.",
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )

    # --- require() with variable (SKY-D245) ---
    for node in complex_captures.get("require_var_arg", []):
        findings.append(
            {
                "rule_id": "SKY-D245",
                "severity": "HIGH",
                "message": "require() with variable argument — potential code injection. Use static string paths.",
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
            }
        )

    # --- JWT decode without verify (SKY-D246) ---
    for node in complex_captures.get("jwt_decode_prop", []):
        # Check if the object is jwt-related
        member_expr = node.parent
        if member_expr is None:
            continue
        obj_node = member_expr.child_by_field_name("object")
        if obj_node is None:
            continue
        obj_text = _get_text(source_bytes, obj_node).lower()
        if obj_text in ("jwt", "jsonwebtoken", "jwtlib"):
            findings.append(
                {
                    "rule_id": "SKY-D246",
                    "severity": "HIGH",
                    "message": "jwt.decode() without verification — tokens should be verified with jwt.verify().",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- CORS wildcard (SKY-D247) ---
    for node in complex_captures.get("cors_args", []):
        # Look for cors({ origin: '*' }) or cors({ origin: true })
        first_arg = _first_real_arg(node)
        if first_arg and first_arg.type == "object":
            for child in first_arg.children:
                if child.type == "pair":
                    key_node = child.child_by_field_name("key")
                    val_node = child.child_by_field_name("value")
                    if key_node and val_node:
                        key_text = _get_text(source_bytes, key_node)
                        if key_text == "origin":
                            val_text = _get_text(source_bytes, val_node).strip("'\"")
                            if val_text in ("*", "true"):
                                findings.append(
                                    {
                                        "rule_id": "SKY-D247",
                                        "severity": "MEDIUM",
                                        "message": "CORS wildcard origin — allows requests from any domain. Restrict to specific origins.",
                                        "file": str(file_path),
                                        "line": node.start_point[0] + 1,
                                        "col": 0,
                                    }
                                )

    # --- Sensitive data in logs (SKY-D251) ---
    for args_node in complex_captures.get("console_log_args", []):
        call_node = args_node.parent
        if not call_node:
            continue
        func_node = call_node.child_by_field_name("function")
        if not func_node or func_node.type != "member_expression":
            continue
        method_node = func_node.child_by_field_name("property")
        if not method_node:
            continue
        method_name = _get_text(source_bytes, method_node)
        if method_name not in _LOG_METHODS:
            continue
        # Check arguments for sensitive variable names
        for child in args_node.children:
            if child.type in ("(", ")", ","):
                continue
            var_name = _extract_var_name(child, source_bytes)
            if var_name and _is_sensitive_name(var_name):
                findings.append(
                    {
                        "rule_id": "SKY-D251",
                        "severity": "HIGH",
                        "message": f"Sensitive data '{var_name}' passed to console.{method_name}(). Remove or mask before logging.",
                        "file": str(file_path),
                        "line": child.start_point[0] + 1,
                        "col": 0,
                    }
                )
                break  # One finding per log call
            # Template string with sensitive interpolation
            if child.type == "template_string":
                found_sensitive = False
                for sub in child.children:
                    if sub.type == "template_substitution":
                        for sub_child in sub.children:
                            if sub_child.type not in ("${", "}"):
                                var_name = _extract_var_name(sub_child, source_bytes)
                                if var_name and _is_sensitive_name(var_name):
                                    findings.append(
                                        {
                                            "rule_id": "SKY-D251",
                                            "severity": "HIGH",
                                            "message": f"Sensitive data '{var_name}' interpolated in console.{method_name}(). Remove or mask before logging.",
                                            "file": str(file_path),
                                            "line": sub_child.start_point[0] + 1,
                                            "col": 0,
                                        }
                                    )
                                    found_sensitive = True
                                    break
                    if found_sensitive:
                        break
                if found_sensitive:
                    break

    # --- Insecure cookie (SKY-D252) ---
    for args_node in complex_captures.get("cookie_set_args", []):
        children = [c for c in args_node.children if c.type not in ("(", ")", ",")]
        if len(children) < 2:
            continue  # Not a cookie set call (need at least name + value)

        missing = []
        if len(children) < 3:
            missing = ["httpOnly", "secure"]
        elif children[2].type == "object":
            has_httponly = False
            has_secure = False
            for child in children[2].children:
                if child.type == "pair":
                    key_node = child.child_by_field_name("key")
                    if key_node:
                        key_text = _get_text(source_bytes, key_node)
                        if key_text == "httpOnly":
                            has_httponly = True
                        elif key_text == "secure":
                            has_secure = True
            if not has_httponly:
                missing.append("httpOnly")
            if not has_secure:
                missing.append("secure")

        if missing:
            findings.append(
                {
                    "rule_id": "SKY-D252",
                    "severity": "MEDIUM",
                    "message": f"Cookie set without {' and '.join(missing)} flag(s). Add security options.",
                    "file": str(file_path),
                    "line": args_node.start_point[0] + 1,
                    "col": 0,
                }
            )

    # --- Timing-unsafe comparison (SKY-D253) ---
    _check_timing_comparison(root_node, source_bytes, file_path, findings)

    # --- Sensitive data in localStorage/sessionStorage (SKY-D270) ---
    for cap_name, storage_name in (
        ("ls_set_args", "localStorage"),
        ("ss_set_args", "sessionStorage"),
    ):
        for args_node in complex_captures.get(cap_name, []):
            first_arg = _first_real_arg(args_node)
            if not first_arg or first_arg.type != "string":
                continue
            key_text = _get_text(source_bytes, first_arg).strip("'\"")
            normalized = key_text.lower().replace("_", "").replace("-", "")
            # Skip CSRF/XSRF tokens — those belong in storage
            if any(normalized.startswith(p) for p in _STORAGE_SAFE_PREFIXES):
                continue
            for suffix in _STORAGE_SENSITIVE_SUFFIXES:
                if normalized == suffix or normalized.endswith(suffix):
                    findings.append(
                        {
                            "rule_id": "SKY-D270",
                            "severity": "MEDIUM",
                            "message": f"Sensitive data stored in {storage_name} (key: '{key_text}'). Use httpOnly cookies instead — localStorage is accessible to XSS.",
                            "file": str(file_path),
                            "line": args_node.start_point[0] + 1,
                            "col": 0,
                        }
                    )
                    break

    # --- Error info disclosure in HTTP responses (SKY-D271) ---
    _check_error_disclosure(root_node, source_bytes, file_path, findings)

    return findings


def _check_timing_comparison(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D253: Detect == or === comparisons with sensitive variable names."""
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "binary_expression":
            # Check if operator is == or === (or != / !==)
            has_eq = False
            for child in node.children:
                if not child.is_named and child.type in ("==", "===", "!=", "!=="):
                    has_eq = True
                    break
            if has_eq:
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                for operand in (left, right):
                    if operand is None:
                        continue
                    name = _extract_var_name(operand, source_bytes)
                    if name and _is_timing_sensitive(name):
                        findings.append(
                            {
                                "rule_id": "SKY-D253",
                                "severity": "MEDIUM",
                                "message": f"Timing-unsafe comparison of '{name}'. Use crypto.timingSafeEqual() for constant-time comparison.",
                                "file": str(file_path),
                                "line": node.start_point[0] + 1,
                                "col": 0,
                            }
                        )
                        break
        for child in node.children:
            stack.append(child)


def _check_error_disclosure(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D271: Detect error.stack/error.sql sent in HTTP response methods."""
    walk = [root_node]
    while walk:
        node = walk.pop()
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "member_expression":
                prop = func.child_by_field_name("property")
                if prop and _get_text(source_bytes, prop) in _RESPONSE_METHODS:
                    args = node.child_by_field_name("arguments")
                    if args:
                        bad_prop = _find_error_prop(args, source_bytes)
                        if bad_prop:
                            findings.append(
                                {
                                    "rule_id": "SKY-D271",
                                    "severity": "MEDIUM",
                                    "message": f"Error '{bad_prop}' sent in HTTP response — exposes internal details to attackers. Return a generic error message instead.",
                                    "file": str(file_path),
                                    "line": node.start_point[0] + 1,
                                    "col": 0,
                                }
                            )
        for child in node.children:
            walk.append(child)


def _find_error_prop(node, source_bytes: bytes) -> str | None:
    """Walk a subtree looking for .stack/.sql member access. Returns the prop name or None."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "member_expression":
            prop = n.child_by_field_name("property")
            if prop and _get_text(source_bytes, prop) in _ERROR_DISCLOSURE_PROPS:
                return _get_text(source_bytes, prop)
        for child in n.children:
            stack.append(child)
    return None


def _run_batch(root_node, lang: Language, key: str, pattern: str) -> dict[str, list]:
    query = _get_query(lang, key, pattern)
    if query is None:
        return {}
    try:
        cursor = QueryCursor(query)
        return cursor.captures(root_node)
    except Exception:
        return {}


def _first_real_arg(args_node) -> object | None:
    for child in args_node.children:
        if child.type not in ("(", ")", ","):
            return child
    return None
