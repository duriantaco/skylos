from __future__ import annotations

import math
import os
import re
from tree_sitter import Language, Query, QueryCursor
import tree_sitter_typescript as tsts

from skylos.constants import (
    ENTROPY_THRESHOLD,
    MIN_LONG_SECRET_LENGTH,
    MIN_SECRET_LENGTH,
    get_non_library_dir_kind,
)

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


_QUERY_CACHE: dict[tuple[int, str], Query] = {}

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

_WEBHOOK_PROVIDER_HINTS = (
    "stripe",
    "github",
    "clerk",
    "svix",
    "shopify",
    "supabase",
    "resend",
    "twilio",
    "slack",
    "discord",
    "linear",
    "vercel",
    "netlify",
    "paddle",
    "lemon_squeezy",
    "lemonsqueezy",
)

_WEBHOOK_BODY_HINTS = (
    ".json(",
    ".text(",
    ".arraybuffer(",
    ".formdata(",
    ".body",
    "rawbody",
    "raw_body",
)

_WEBHOOK_VERIFY_PATTERNS = (
    re.compile(r"\bconstructEvent\s*\("),
    re.compile(r"\bconstruct_event\s*\(", re.I),
    re.compile(r"\bverifySignature\s*\("),
    re.compile(r"\bverifyWebhook\s*\("),
    re.compile(r"\bvalidateSignature\s*\("),
    re.compile(r"\bvalidateWebhook\s*\("),
    re.compile(r"\bverify_signature\s*\(", re.I),
    re.compile(r"\bverify_webhook\s*\(", re.I),
    re.compile(r"\bvalidate_signature\s*\(", re.I),
    re.compile(r"\bvalidate_webhook\s*\(", re.I),
    re.compile(r"\bcrypto\.timingSafeEqual\s*\("),
    re.compile(r"\btimingSafeEqual\s*\("),
    re.compile(r"\bcreateHmac\s*\("),
    re.compile(r"\bnew\s+Webhook\s*\([^)]*\).*?\.verify\s*\(", re.S),
    re.compile(r"\bWebhook\.verify\s*\("),
)


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
    normalized = name.lower().replace("_", "")
    for suffix in _LOG_SENSITIVE_SUFFIXES:
        if normalized == suffix or normalized.endswith(suffix):
            return True
    return False


def _is_timing_sensitive(name: str) -> bool:
    normalized = name.lower().replace("_", "")
    for suffix in _TIMING_SENSITIVE_SUFFIXES:
        if normalized == suffix or normalized.endswith(suffix):
            return True
    return False


def _extract_var_name(node, source_bytes: bytes) -> str | None:
    if node.type == "identifier":
        return _get_text(source_bytes, node)
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop:
            return _get_text(source_bytes, prop)
    return None


def _string_literal_value(node, source_bytes: bytes) -> str:
    text = _get_text(source_bytes, node).strip()
    if len(text) >= 2 and text[0] in ("'", '"') and text[-1] == text[0]:
        return text[1:-1]
    return text


def _template_prefix(node, source_bytes: bytes) -> str:
    text = _get_text(source_bytes, node)
    if text.startswith("`"):
        text = text[1:]
    marker = text.find("${")
    if marker >= 0:
        return text[:marker]
    if text.endswith("`"):
        text = text[:-1]
    return text


_TS_EXPRESSION_WRAPPERS = {
    "as_expression",
    "non_null_expression",
    "parenthesized_expression",
    "satisfies_expression",
    "type_assertion",
}

_TS_TYPE_NODE_TYPES = {
    "array_type",
    "generic_type",
    "literal_type",
    "object_type",
    "predefined_type",
    "type_arguments",
    "type_annotation",
    "type_identifier",
    "union_type",
}


def _unwrap_ts_expression(node):
    if node.type not in _TS_EXPRESSION_WRAPPERS:
        return node
    for child in node.children:
        if child.type in {
            "(",
            ")",
            "<",
            ">",
            "!",
            "as",
            "satisfies",
        }:
            continue
        if child.type in _TS_TYPE_NODE_TYPES or child.type.endswith("_type"):
            continue
        return child
    return node


def _has_dynamic_url_part(node) -> bool:
    unwrapped = _unwrap_ts_expression(node)
    if unwrapped is not node:
        return _has_dynamic_url_part(unwrapped)

    if node.type in {
        "identifier",
        "member_expression",
        "subscript_expression",
        "call_expression",
        "await_expression",
    }:
        return True
    if node.type == "template_string":
        return any(child.type == "template_substitution" for child in node.children)
    if node.type == "binary_expression":
        return any(
            child.type != "+" and _has_dynamic_url_part(child)
            for child in node.children
        )
    if node.type == "parenthesized_expression":
        return any(_has_dynamic_url_part(child) for child in node.children)
    return False


def _static_prefix_until_dynamic(node, source_bytes: bytes) -> tuple[str, bool]:
    unwrapped = _unwrap_ts_expression(node)
    if unwrapped is not node:
        return _static_prefix_until_dynamic(unwrapped, source_bytes)

    if node.type == "string":
        return _string_literal_value(node, source_bytes), False
    if node.type == "template_string":
        return _template_prefix(node, source_bytes), _has_dynamic_url_part(node)
    if node.type in {"binary_expression", "parenthesized_expression"}:
        prefix = ""
        for child in node.children:
            if child.type in {"(", ")", "+"}:
                continue
            child_prefix, child_dynamic = _static_prefix_until_dynamic(
                child, source_bytes
            )
            prefix += child_prefix
            if child_dynamic:
                return prefix, True
        return prefix, False
    return "", _has_dynamic_url_part(node)


def _prefix_has_fixed_http_host(prefix: str) -> bool:
    match = re.match(r"^https?://([^/?#]+)([/?#].*)", prefix, re.IGNORECASE)
    return bool(match and match.group(1))


def _url_arg_is_ssrf_relevant(node, source_bytes: bytes) -> bool:
    if node.type == "string":
        return False
    if node.type == "template_string" and not _has_dynamic_url_part(node):
        return False

    prefix, saw_dynamic = _static_prefix_until_dynamic(node, source_bytes)
    if not saw_dynamic:
        return False

    if prefix:
        lower_prefix = prefix.lower()
        if _prefix_has_fixed_http_host(prefix):
            return False
        if lower_prefix.startswith(("http://", "https://", "//")):
            return True
        return False

    return True


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

    simple_captures = _run_batch(root_node, lang, "danger_simple", _SIMPLE_PATTERN)
    jsx_captures = _run_batch(root_node, lang, "danger_jsx", _JSX_PATTERN)
    complex_captures = _run_batch(root_node, lang, "danger_complex", _COMPLEX_PATTERN)

    for k, v in jsx_captures.items():
        simple_captures.setdefault(k, []).extend(v)

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

    # (SKY-S101) via batched string captures
    is_test_file = get_non_library_dir_kind(file_path) == "test"
    for cap_name in ("string_node", "template_node"):
        for node in complex_captures.get(cap_name, []):
            text = _get_text(source_bytes, node)
            if text and text[0] in ("'", '"', "`"):
                text = text[1:]
            if text and text[-1] in ("'", '"', "`"):
                text = text[:-1]
            if len(text) >= MIN_SECRET_LENGTH:
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
                if (
                    not found_prefix
                    and len(text) >= MIN_LONG_SECRET_LENGTH
                    and all(c in _BASE64_CHARS for c in text)
                    and _shannon_entropy(text) > ENTROPY_THRESHOLD
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

            # Hardcoded internal URL (SKY-D248)
            if not is_test_file and len(text) >= MIN_SECRET_LENGTH:
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
        if first_arg and _url_arg_is_ssrf_relevant(first_arg, source_bytes):
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
        if first_arg and _url_arg_is_ssrf_relevant(first_arg, source_bytes):
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
                break

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
            continue

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

    _check_nextjs_missing_auth(source_bytes, file_path, findings)
    _check_nextjs_client_secrets(source_bytes, file_path, findings)
    _check_nextjs_server_action_sqli(source_bytes, file_path, findings)
    _check_unverified_webhook_handler(source_bytes, file_path, findings)
    _check_archive_extraction_path_traversal(
        root_node, source_bytes, file_path, findings
    )

    return findings


_AUTH_EVIDENCE = frozenset(
    {
        "auth",
        "session",
        "getServerSession",
        "getToken",
        "cookies",
        "headers",
        "getSession",
        "withAuth",
        "requireAuth",
        "verifyToken",
        "authenticate",
        "isAuthenticated",
        "currentUser",
        "getUser",
        "clerkClient",
        "authMiddleware",
        "NextAuth",
    }
)

_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

_NEXTJS_ROUTE_PATTERNS = ("/app/", "/pages/api/")

_ARCHIVE_LIBRARY_HINTS = (
    "unzip.Parse(",
    "unzipper.Parse(",
    ".on('entry'",
    '.on("entry"',
    "yauzl",
    "AdmZip",
    "adm-zip",
    'require("unzipper")',
    "require('unzipper')",
    'require("adm-zip")',
    "require('adm-zip')",
    'from "yauzl"',
    "from 'yauzl'",
)

_ARCHIVE_ENTRY_PROPERTY_PATTERN = re.compile(
    r"\b(?:(?:entry|header|[A-Za-z_$][A-Za-z0-9_$]*Entry)\.(?:path|fileName|name))\b"
)

_ARCHIVE_ALIAS_PATTERN = re.compile(
    r"(?ms)^\s*(?:(?:const|let|var)\s+)?(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>.*?);"
)

_ARCHIVE_SINK_ARGS = {
    "fs.createWriteStream(": (0,),
    "createWriteStream(": (0,),
    "fs.writeFile(": (0,),
    "fs.writeFileSync(": (0,),
    "fs.promises.writeFile(": (0,),
    "writeFile(": (0,),
    "writeFileSync(": (0,),
}

_ARCHIVE_GUARD_TOKENS = (
    ".includes('..')",
    '.includes("..")',
    ".indexOf('..')",
    '.indexOf("..")',
)

_ARCHIVE_SCOPE_NODE_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    }
)

_ARCHIVE_CONTROL_FLOW_HINTS = ("return", "continue", "throw", "break")


def _is_test_file_path(file_path: str) -> bool:
    normalized = str(file_path).replace(os.sep, "/").lower()
    base = os.path.basename(normalized)
    return (
        get_non_library_dir_kind(file_path) == "test"
        or "/test/" in normalized
        or "/tests/" in normalized
        or ".spec." in base
        or ".test." in base
    )


def _has_webhook_provider_hint(text: str) -> bool:
    lower = text.lower()
    return any(provider in lower for provider in _WEBHOOK_PROVIDER_HINTS)


def _has_webhook_body_use(source_text: str) -> bool:
    lower = source_text.lower()
    return any(hint in lower for hint in _WEBHOOK_BODY_HINTS)


def _has_webhook_signature_verification(source_text: str) -> bool:
    return any(pattern.search(source_text) for pattern in _WEBHOOK_VERIFY_PATTERNS)


def _has_inbound_webhook_post(source_text: str) -> bool:
    post_patterns = (
        r"\bexport\s+(?:async\s+)?function\s+POST\b",
        r"\bexport\s+const\s+POST\b",
        r"\b(?:app|router|server|fastify|hono)\.post\s*\(",
        r"\b(?:req|request)\.method\s*(?:={2,3})\s*['\"]POST['\"]",
        r"\bcase\s+['\"]POST['\"]",
    )
    return any(re.search(pattern, source_text) for pattern in post_patterns)


def _webhook_finding_line(source_text: str) -> int:
    for index, line in enumerate(source_text.splitlines(), 1):
        if (
            "webhook" in line.lower()
            or re.search(r"\bPOST\b", line)
            or ".post(" in line
        ):
            return index
    return 1


def _check_unverified_webhook_handler(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    if _is_test_file_path(file_path):
        return

    source_text = source_bytes.decode("utf-8", errors="replace")
    normalized_path = str(file_path).replace(os.sep, "/")
    combined = f"{normalized_path}\n{source_text}"
    combined_lower = combined.lower()

    if "webhook" not in combined_lower and "webhooks" not in combined_lower:
        return
    if not _has_webhook_provider_hint(combined):
        return
    if not _has_inbound_webhook_post(source_text):
        return
    if not _has_webhook_body_use(source_text):
        return
    if _has_webhook_signature_verification(source_text):
        return

    findings.append(
        {
            "rule_id": "SKY-D282",
            "severity": "HIGH",
            "message": (
                "Webhook handler processes inbound events without obvious signature "
                "verification. Verify provider signatures before parsing or trusting "
                "the event body."
            ),
            "file": str(file_path),
            "line": _webhook_finding_line(source_text),
            "col": 0,
        }
    )


def _has_mutating_exported_route_handler(source_text: str) -> bool:
    for method in _MUTATING_METHODS:
        if (
            f"export async function {method}" in source_text
            or f"export function {method}" in source_text
            or f"export const {method}" in source_text
        ):
            return True
    return False


def _has_mutating_pages_api_handler(source_text: str) -> bool:
    if "export default" not in source_text:
        return False

    for method in _MUTATING_METHODS:
        quoted = rf"['\"]{method}['\"]"
        patterns = (
            rf"\breq\.method\s*===?\s*{quoted}",
            rf"\bmethod\s*===?\s*{quoted}",
            rf"\bcase\s+{quoted}",
        )
        if any(re.search(pattern, source_text) for pattern in patterns):
            return True

    if re.search(r"\[(?:[^\]]+)\]\.includes\(\s*req\.method\s*\)", source_text):
        return any(
            f"'{method}'" in source_text or f'"{method}"' in source_text
            for method in _MUTATING_METHODS
        )

    return False


def _check_nextjs_missing_auth(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D280: Detect Next.js API routes with mutating handlers missing auth checks."""
    normalized_path = str(file_path).replace(os.sep, "/")
    is_route = False
    if "/app/" in normalized_path and normalized_path.endswith(
        ("route.ts", "route.tsx", "route.js", "route.jsx")
    ):
        is_route = True
    elif "/pages/api/" in normalized_path and normalized_path.endswith(
        (".ts", ".tsx", ".js", ".jsx")
    ):
        is_route = True

    if not is_route:
        return

    source_text = source_bytes.decode("utf-8", errors="replace")

    has_mutating = _has_mutating_exported_route_handler(source_text)
    if not has_mutating and "/pages/api/" in normalized_path:
        has_mutating = _has_mutating_pages_api_handler(source_text)

    if not has_mutating:
        return

    has_auth = False
    for evidence in _AUTH_EVIDENCE:
        if evidence in source_text:
            has_auth = True
            break

    if not has_auth:
        findings.append(
            {
                "rule_id": "SKY-D280",
                "severity": "HIGH",
                "message": "Next.js API route with mutating handler (POST/PUT/DELETE/PATCH) has no authentication check. Add auth verification.",
                "file": str(file_path),
                "line": 1,
                "col": 0,
            }
        )


def _check_archive_extraction_path_traversal(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    source_text = source_bytes.decode("utf-8", errors="replace")
    if not any(hint in source_text for hint in _ARCHIVE_LIBRARY_HINTS):
        return

    for scope_lines, start_line in _iter_archive_scopes(root_node, source_text):
        scope_text = "\n".join(scope_lines)
        if not scope_text.strip():
            continue
        tainted_names: set[str] = set()
        latest_assignment: dict[str, int] = {}
        events: list[tuple[int, int, object]] = []
        events.extend(
            (
                scope_text[: match.start()].count("\n"),
                0,
                (match.group("alias"), match.group("expr")),
            )
            for match in _ARCHIVE_ALIAS_PATTERN.finditer(scope_text)
        )
        events.extend(
            (line_offset, 1, args)
            for line_offset, args in _iter_archive_sink_calls(scope_text)
        )
        events.sort(key=lambda item: (item[0], item[1]))

        for line_offset, kind, payload in events:
            if kind == 0:
                alias, expr = payload
                if _ARCHIVE_ENTRY_PROPERTY_PATTERN.search(expr) or any(
                    re.search(rf"\b{re.escape(name)}\b", expr) for name in tainted_names
                ):
                    tainted_names.add(alias)
                else:
                    tainted_names.discard(alias)
                latest_assignment[alias] = line_offset
                continue

            used_names = _archive_sink_tainted_names(payload, tainted_names)
            direct_entry = bool(_archive_sink_tainted_names(payload, set(), True))
            if not used_names and not direct_entry:
                continue

            guard_start = 0
            if used_names:
                guard_start = max(latest_assignment.get(name, 0) for name in used_names)
            if _archive_lines_have_guard(
                scope_lines[guard_start : line_offset + 1],
                used_names,
                direct_entry,
                line_offset - guard_start,
            ):
                continue

            findings.append(
                {
                    "rule_id": "SKY-D215",
                    "severity": "HIGH",
                    "message": "Archive entry path reaches a filesystem write sink without traversal validation. Reject '..' entries or normalize the output path before writing.",
                    "file": str(file_path),
                    "line": start_line + line_offset + 1,
                    "col": 0,
                }
            )
            return


def _iter_nodes(root_node):
    stack = [root_node]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _iter_archive_scopes(root_node, source_text: str) -> list[tuple[list[str], int]]:
    all_lines = source_text.splitlines()
    scopes = [root_node]
    scopes.extend(
        node
        for node in _iter_nodes(root_node)
        if node.type in _ARCHIVE_SCOPE_NODE_TYPES
    )
    return [_scope_lines_without_nested_scopes(scope, all_lines) for scope in scopes]


def _archive_guard_block_contains_sink(
    lines: list[str], guard_idx: int, sink_idx: int
) -> bool:
    depth = 0
    opened = False

    for idx in range(guard_idx, sink_idx + 1):
        line = lines[idx]
        opens = line.count("{")
        closes = line.count("}")
        if opens:
            opened = True
        depth += opens
        depth -= closes
        if idx < sink_idx and opened and depth <= 0:
            return False

    return opened and depth > 0


def _archive_guard_without_braces_contains_sink(
    lines: list[str], guard_idx: int, sink_idx: int
) -> bool:
    line = lines[guard_idx]
    if "{" in line:
        return False
    if sink_idx == guard_idx:
        return True
    for idx in range(guard_idx + 1, len(lines)):
        if not lines[idx].strip():
            continue
        return idx == sink_idx
    return False


def _archive_lines_have_guard(
    lines: list[str], names: set[str], direct_entry: bool, sink_idx: int
) -> bool:
    has_normalize = False

    for idx, line in enumerate(lines):
        if direct_entry:
            mentioned = bool(_ARCHIVE_ENTRY_PROPERTY_PATTERN.search(line))
        else:
            mentioned = any(
                re.search(rf"\b{re.escape(name)}\b", line) for name in names
            )
        if not mentioned:
            continue

        if "if" in line and any(token in line for token in _ARCHIVE_GUARD_TOKENS):
            trailing = "\n".join(lines[idx : min(len(lines), idx + 4)])
            if any(token in trailing for token in _ARCHIVE_CONTROL_FLOW_HINTS):
                return True
        if "normalize(" in line:
            has_normalize = True
        if (
            has_normalize
            and "if" in line
            and "startsWith(" in line
            and ("!" in line or "=== false" in line or "== false" in line)
        ):
            trailing = "\n".join(lines[idx : min(len(lines), idx + 4)])
            if any(token in trailing for token in _ARCHIVE_CONTROL_FLOW_HINTS):
                return True
        if (
            idx <= sink_idx
            and has_normalize
            and "if" in line
            and "startsWith(" in line
            and "!" not in line
            and "=== false" not in line
            and "== false" not in line
            and (
                _archive_guard_block_contains_sink(lines, idx, sink_idx)
                or _archive_guard_without_braces_contains_sink(lines, idx, sink_idx)
            )
        ):
            return True

    return False


def _extract_call_args(line: str, token: str) -> list[str]:
    start = line.find(token)
    if start < 0:
        return []

    idx = start + len(token)
    depth = 1
    current: list[str] = []
    args: list[str] = []

    while idx < len(line):
        ch = line[idx]
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                arg = "".join(current).strip()
                if arg:
                    args.append(arg)
                break
            current.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        idx += 1

    return args


def _archive_sink_tainted_names(
    args: list[str], names: set[str], direct_entry: bool = False
) -> set[str]:
    for arg in args:
        if direct_entry and _ARCHIVE_ENTRY_PROPERTY_PATTERN.search(arg):
            return {"__direct__"}
        matched = {name for name in names if re.search(rf"\b{re.escape(name)}\b", arg)}
        if matched:
            return matched
    return set()


def _nearest_archive_child_scopes(node) -> list:
    scopes: list = []
    stack = list(reversed(node.children))
    while stack:
        current = stack.pop()
        if current.type in _ARCHIVE_SCOPE_NODE_TYPES:
            scopes.append(current)
            continue
        stack.extend(reversed(current.children))
    return scopes


def _scope_lines_without_nested_scopes(
    node, all_lines: list[str]
) -> tuple[list[str], int]:
    start = node.start_point[0]
    end = node.end_point[0]
    scope_lines = list(all_lines[start : end + 1])

    for child in _nearest_archive_child_scopes(node):
        child_start = max(child.start_point[0] - start, 0)
        child_end = min(child.end_point[0] - start, len(scope_lines) - 1)
        for idx in range(child_start, child_end + 1):
            scope_lines[idx] = ""

    return scope_lines, start


def _iter_archive_sink_calls(text: str) -> list[tuple[int, list[str]]]:
    calls: list[tuple[int, list[str]]] = []
    seen_offsets: set[int] = set()

    for token, positions in _ARCHIVE_SINK_ARGS.items():
        search_from = 0
        while True:
            idx = text.find(token, search_from)
            if idx < 0:
                break
            if idx in seen_offsets:
                search_from = idx + 1
                continue
            seen_offsets.add(idx)

            args = _extract_call_args(text[idx:], token)
            selected_args = [args[pos] for pos in positions if pos < len(args)]
            calls.append((text[:idx].count("\n"), selected_args))
            search_from = idx + 1

    calls.sort(key=lambda item: item[0])
    return calls


def _check_nextjs_client_secrets(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-S102: Detect server-only env vars accessed in 'use client' components."""
    source_text = source_bytes.decode("utf-8", errors="replace")

    lines = source_text.split("\n")
    is_client = False
    for line in lines[:5]:
        stripped = line.strip()
        if stripped in (
            '"use client"',
            "'use client'",
            '"use client";',
            "'use client';",
        ):
            is_client = True
            break
        if stripped and not stripped.startswith(("//", "/*", "*", "import")):
            break

    if not is_client:
        return

    import re

    for match in re.finditer(r"process\.env\.([A-Z_][A-Z0-9_]*)", source_text):
        env_name = match.group(1)
        if not env_name.startswith("NEXT_PUBLIC_"):
            line_num = source_text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "SKY-S102",
                    "severity": "HIGH",
                    "message": f"Server-only env var `process.env.{env_name}` accessed in client component. Use NEXT_PUBLIC_ prefix for client-safe vars or move to a server component.",
                    "file": str(file_path),
                    "line": line_num,
                    "col": 0,
                }
            )


def _check_nextjs_server_action_sqli(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D281: Detect potential SQL injection in server actions via template literals."""
    source_text = source_bytes.decode("utf-8", errors="replace")

    lines = source_text.split("\n")
    is_server = False
    for line in lines[:5]:
        stripped = line.strip()
        if stripped in (
            '"use server"',
            "'use server'",
            '"use server";',
            "'use server';",
        ):
            is_server = True
            break
        if stripped and not stripped.startswith(("//", "/*", "*", "import")):
            break

    if not is_server:
        return

    import re

    db_methods = re.finditer(
        r"\.(query|execute|raw|sql)\s*\(\s*`([^`]*\$\{[^`]*)`",
        source_text,
        re.DOTALL,
    )
    for match in db_methods:
        template_content = match.group(2).upper()
        if any(kw in template_content for kw in _SQL_KEYWORDS):
            line_num = source_text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule_id": "SKY-D281",
                    "severity": "CRITICAL",
                    "message": f"SQL injection risk in server action — template literal with interpolation passed to .{match.group(1)}(). Use parameterized queries.",
                    "file": str(file_path),
                    "line": line_num,
                    "col": 0,
                }
            )


def _check_timing_comparison(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D253: Detect == or === comparisons with sensitive variable names."""
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "binary_expression":
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
