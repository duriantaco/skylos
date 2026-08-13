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
from skylos.rules.secrets import (
    is_client_exposure_context,
    is_public_client_env_name,
    iter_sensitive_client_env_references,
)
from skylos.security.command_guard import findings_for_command, is_external_url
from skylos.visitors.languages.statement_scan import iter_semicolon_assignments
from skylos.visitors.languages.typescript.security_flow import build_security_flow
from skylos.visitors.languages.typescript.security_proofs import (
    check_cookie_security,
    check_nextjs_missing_auth,
    check_unverified_webhooks,
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

_CHILD_PROCESS_MODULES = {"child_process", "node:child_process"}


_QUERY_CACHE: dict[tuple[int, str], Query] = {}
_NON_STRING_PROPERTY_KEY = object()
_DELETED_BINDING = object()

# Property-descriptor state lives in synthetic heap bindings so it is cloned,
# joined, and projected with the rest of the D281 abstract heap.  These tokens
# cannot collide with JavaScript identifiers and are filtered from taint
# provenance before a finding is emitted.
_PROPERTY_STATE_PREFIX = "\x00skylos-property:"
_PROPERTY_TRUE = f"{_PROPERTY_STATE_PREFIX}true"
_PROPERTY_FALSE = f"{_PROPERTY_STATE_PREFIX}false"
_PROPERTY_PRESENT = f"{_PROPERTY_STATE_PREFIX}present"
_PROPERTY_ABSENT = f"{_PROPERTY_STATE_PREFIX}absent"
_PROPERTY_DATA = f"{_PROPERTY_STATE_PREFIX}data"
_PROPERTY_ACCESSOR = f"{_PROPERTY_STATE_PREFIX}accessor"

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

_CHILD_PROCESS_ALIAS_PATTERN = """
(import_statement
  (import_clause (namespace_import (identifier) @import_alias))
  (string) @import_module)
(import_statement
  (import_clause (identifier) @import_alias)
  (string) @import_module)
(variable_declarator
  name: (identifier) @require_alias
  value: (call_expression
    function: (identifier) @require_fn (#eq? @require_fn "require")
    arguments: (arguments (string) @require_module)))
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

_HTML_EXECUTABLE_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b|"
    r"\bon[a-z0-9_-]+\s*=|"
    r"javascript\s*:",
    re.IGNORECASE,
)

_SAFE_HTML_SANITIZER_CALLEES = {
    "DOMPurify.sanitize",
    "sanitizeHtml",
    "sanitizeHTML",
}

_RANDOM_SECURITY_TERMS = (
    "token",
    "nonce",
    "csrf",
    "xsrf",
    "session",
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "privatekey",
    "jwt",
    "bearer",
    "cookie",
    "signature",
    "hmac",
    "salt",
    "otpcode",
    "otptoken",
    "otpsecret",
    "totp",
    "hotp",
    "mfacode",
    "mfatoken",
    "authorization",
    "oauth",
    "resetcode",
    "resetlink",
    "invitecode",
    "magiclink",
    "verificationcode",
)

_SERVER_PATH_HINTS = (
    "/api/",
    "/app/",
    "/pages/api/",
    "/server/",
    "/backend/",
    "/routes/",
    "/controllers/",
    "/handlers/",
    "/lambda/",
    "/functions/",
)

_BROWSER_PATH_HINTS = (
    "/public/",
    "/static/",
    "/assets/",
    "/client/",
    "/browser/",
    "/frontend/",
    "/js/",
)

_BROWSER_GLOBAL_RE = re.compile(
    r"\b(?:document|window|navigator|localStorage|sessionStorage)\b"
)

_SERVER_GLOBAL_RE = re.compile(
    r"\b(?:process\.env|require\s*\(|module\.exports|exports\.|"
    r"createServer|express\s*\(|fastify\s*\(|app\.(?:get|post|put|patch|delete))\b"
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


def _static_string_value(node, source_bytes: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        return _string_literal_value(node, source_bytes)
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return None
        text = _get_text(source_bytes, node).strip()
        if len(text) >= 2 and text[0] == "`" and text[-1] == "`":
            return text[1:-1]
    return None


def _first_static_call_arg(call_node, source_bytes: bytes) -> str | None:
    if call_node is None or call_node.type != "call_expression":
        return None
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return None
    return _static_string_value(_first_real_arg(args), source_bytes)


def _callee_name(call_node, source_bytes: bytes) -> str | None:
    if call_node is None or call_node.type != "call_expression":
        return None

    function_node = call_node.child_by_field_name("function")
    if function_node is None:
        return None
    if function_node.type == "identifier":
        return _get_text(source_bytes, function_node)
    if function_node.type != "member_expression":
        return None

    object_node = function_node.child_by_field_name("object")
    property_node = function_node.child_by_field_name("property")
    if object_node is None or property_node is None:
        return None

    object_name = _get_text(source_bytes, object_node)
    property_name = _get_text(source_bytes, property_node)
    return f"{object_name}.{property_name}"


def _is_safe_html_sanitizer_call(node, source_bytes: bytes) -> bool:
    unwrapped = _unwrap_ts_expression(node)
    if unwrapped.type != "call_expression":
        return False

    callee = _callee_name(unwrapped, source_bytes)
    return callee in _SAFE_HTML_SANITIZER_CALLEES


def _html_literal_can_execute(value: str) -> bool:
    return bool(_HTML_EXECUTABLE_RE.search(value))


def _html_assignment_rhs_requires_finding(rhs_node, source_bytes: bytes) -> bool:
    if rhs_node is None:
        return True

    unwrapped = _unwrap_ts_expression(rhs_node)
    literal_value = _static_string_value(unwrapped, source_bytes)
    if literal_value is not None:
        return _html_literal_can_execute(literal_value)

    if _is_safe_html_sanitizer_call(unwrapped, source_bytes):
        return False

    return True


def _assignment_rhs_for_property_capture(prop_node):
    member_node = prop_node.parent
    current = member_node.parent if member_node is not None else None
    while current is not None:
        if current.type == "assignment_expression":
            return current.child_by_field_name("right")
        if current.type in {
            "expression_statement",
            "call_expression",
            "statement_block",
            "program",
        }:
            return None
        current = current.parent
    return None


def _html_property_capture_requires_finding(prop_node, source_bytes: bytes) -> bool:
    rhs_node = _assignment_rhs_for_property_capture(prop_node)
    return _html_assignment_rhs_requires_finding(rhs_node, source_bytes)


def _document_write_requires_finding(prop_node, source_bytes: bytes) -> bool:
    member_node = prop_node.parent
    call_node = member_node.parent if member_node is not None else None
    if call_node is None or call_node.type != "call_expression":
        return True

    args_node = call_node.child_by_field_name("arguments")
    first_arg = _first_real_arg(args_node) if args_node is not None else None
    return _html_assignment_rhs_requires_finding(first_arg, source_bytes)


def _nearest_statement_text(node, source_bytes: bytes) -> str:
    current = node
    while current is not None:
        if current.type in {
            "expression_statement",
            "lexical_declaration",
            "variable_declaration",
            "return_statement",
            "assignment_expression",
        }:
            return _get_text(source_bytes, current)
        current = current.parent
    return _get_text(source_bytes, node)


def _text_has_random_security_context(text: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", text.lower())
    return any(term in normalized for term in _RANDOM_SECURITY_TERMS)


def _node_name_text(node, source_bytes: bytes) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return _get_text(source_bytes, name_node)
    return None


def _math_random_requires_finding(prop_node, source_bytes: bytes) -> bool:
    statement_text = _nearest_statement_text(prop_node, source_bytes)
    if _text_has_random_security_context(statement_text):
        return True

    current = prop_node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "function_expression",
            "method_definition",
            "variable_declarator",
        }:
            name = _node_name_text(current, source_bytes)
            if name and _text_has_random_security_context(name):
                return True
        current = current.parent

    return False


def _collect_static_string_bindings(root_node, source_bytes: bytes) -> dict[str, str]:
    bindings: dict[str, str] = {}
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is not None and value_node is not None:
                if name_node.type == "identifier":
                    value = _static_string_value(value_node, source_bytes)
                    if value is not None:
                        bindings[_get_text(source_bytes, name_node)] = value
        stack.extend(reversed(node.children))
    return bindings


def _child_process_aliases(root_node, lang: Language, source_bytes: bytes) -> set[str]:
    query = _get_query(
        lang, "danger_child_process_aliases", _CHILD_PROCESS_ALIAS_PATTERN
    )
    if query is None:
        return set()

    aliases: set[str] = set()
    try:
        matches = QueryCursor(query).matches(root_node)
    except Exception:
        return aliases

    for _, captures in matches:
        alias_node = None
        module_node = None
        if captures.get("import_alias") and captures.get("import_module"):
            alias_node = captures["import_alias"][0]
            module_node = captures["import_module"][0]
        elif captures.get("require_alias") and captures.get("require_module"):
            alias_node = captures["require_alias"][0]
            module_node = captures["require_module"][0]

        if alias_node is None or module_node is None:
            continue

        module_name = _string_literal_value(module_node, source_bytes)
        if module_name in _CHILD_PROCESS_MODULES:
            aliases.add(_get_text(source_bytes, alias_node).lower())

    return aliases


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
    current = node
    for _ in range(32):
        if current is None or current.type not in _TS_EXPRESSION_WRAPPERS:
            return current
        expression = None
        for child in current.children:
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
            expression = child
            break
        if expression is None or expression is current:
            return current
        current = expression
    return current


def _is_null_literal_expression(node) -> bool:
    current = node
    while current is not None:
        unwrapped = _unwrap_ts_expression(current)
        if unwrapped is current:
            return current.type == "null"
        current = unwrapped
    return False


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


def _has_server_path_hint(file_path: str) -> bool:
    normalized = str(file_path).replace(os.sep, "/").lower()
    return any(hint in normalized for hint in _SERVER_PATH_HINTS)


def _is_likely_browser_asset(file_path: str, source_bytes: bytes) -> bool:
    if _has_server_path_hint(file_path):
        return False

    normalized = str(file_path).replace(os.sep, "/").lower()
    if any(hint in normalized for hint in _BROWSER_PATH_HINTS):
        return True

    source_text = source_bytes.decode("utf-8", errors="replace")
    if _SERVER_GLOBAL_RE.search(source_text):
        return False

    return bool(_BROWSER_GLOBAL_RE.search(source_text))


def _url_arg_is_ssrf_relevant(
    node,
    source_bytes: bytes,
    file_path: str | None = None,
    static_string_bindings: dict[str, str] | None = None,
) -> bool:
    if node.type == "string":
        return False
    if node.type == "identifier" and static_string_bindings is not None:
        name = _get_text(source_bytes, node)
        if name in static_string_bindings:
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

    if file_path and _is_likely_browser_asset(file_path, source_bytes):
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

_SQL_KEYWORDS = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "TRUNCATE",
    "MERGE",
    "CALL",
    "COPY",
    "GRANT",
    "REVOKE",
    "WITH",
)

_SECURITY_FLOW_ROUTE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")
_SECURITY_FLOW_APP_ROUTE_FILES = ("route.ts", "route.tsx", "route.js", "route.jsx")
_SECURITY_FLOW_WEBHOOK_RE = re.compile(rb"webhook", re.IGNORECASE)
_SECURITY_FLOW_PROVIDER_IMPORT_RE = re.compile(
    rb"(?:from\s*|require\s*\(\s*)['\"](?:stripe|svix|@octokit/webhooks)['\"]",
    re.IGNORECASE,
)
_SECURITY_FLOW_HOOK_ROUTE_RE = re.compile(
    rb"/(?:stripe|github|clerk|svix|shopify|twilio|slack|paddle)/"
    rb"(?:events?|hooks?)",
    re.IGNORECASE,
)
_SECURITY_FLOW_SQL_TEMPLATE_RE = re.compile(
    rb"(?:\.(?:query|exec|execute)|"
    rb"\[\s*['\"](?:query|exec|execute)['\"]\s*\])\s*\(",
    re.IGNORECASE,
)


def _is_security_flow_candidate(source: bytes, file_path: str) -> bool:
    """Return whether proof-based TS security rules can apply to this file.

    This is deliberately a cheap, conservative superset. False positives only
    cost a flow build; false negatives could hide a security finding.
    """
    if b"cookie" in source:
        return True
    if b"${" in source and _SECURITY_FLOW_SQL_TEMPLATE_RE.search(source):
        return True

    normalized_path = "/" + str(file_path).replace("\\", "/").lower().lstrip("/")
    if (
        "/app/" in normalized_path
        and normalized_path.endswith(_SECURITY_FLOW_APP_ROUTE_FILES)
    ) or (
        "/pages/api/" in normalized_path
        and normalized_path.endswith(_SECURITY_FLOW_ROUTE_SUFFIXES)
    ):
        return True

    return (
        "webhook" in normalized_path
        or bool(_SECURITY_FLOW_WEBHOOK_RE.search(source))
        or bool(_SECURITY_FLOW_PROVIDER_IMPORT_RE.search(source))
        or bool(_SECURITY_FLOW_HOOK_ROUTE_RE.search(source))
    )


def _template_has_substitution(node) -> bool:
    return any(child.type == "template_substitution" for child in node.named_children)


def _sql_template_has_keyword(node, source_bytes: bytes) -> bool:
    text = _get_text(source_bytes, node)
    return any(
        re.search(rf"\b{re.escape(keyword)}\b", text, re.IGNORECASE)
        for keyword in _SQL_KEYWORDS
    )


def _resolved_flow_value(flow, name: str, before_byte: int, scope_id: int):
    seen: set[str] = set()
    for _ in range(16):
        if not name or name in seen:
            return None
        seen.add(name)
        binding = flow.resolve_unique_binding(name, before_byte, scope_id)
        if binding is None:
            return None
        value = flow.unwrap(binding.value_node)
        if value is None or value.type != "identifier":
            return value
        name = flow.node_text(value)
        before_byte = binding.symbol.decl_byte
        scope_id = binding.symbol.scope_id
    return None


def _local_console_only_member(value, method: str, source_bytes: bytes) -> bool:
    if value is None or value.type != "object":
        return False
    callable_node = None
    for child in value.named_children:
        name_node = child.child_by_field_name("name")
        key_node = child.child_by_field_name("key")
        key = _get_text(source_bytes, name_node or key_node).strip("'\"")
        if key != method:
            continue
        if child.type == "method_definition":
            callable_node = child
            break
        if child.type == "pair":
            candidate = _unwrap_ts_expression(child.child_by_field_name("value"))
            if candidate is not None and candidate.type in _TS_FUNCTION_NODE_TYPES:
                callable_node = candidate
                break
    if callable_node is None:
        return False
    allowed_calls = re.compile(
        r"^(?:console\.(?:debug|error|info|log|trace|warn)|"
        r"JSON\.stringify|String)$"
    )
    body = callable_node.child_by_field_name("body")
    stack = [body] if body is not None else []
    visited = 0
    while stack and visited < 10_000:
        visited += 1
        node = stack.pop()
        if node is not body and node.type in _TS_FUNCTION_NODE_TYPES:
            continue
        if node.type in {"call_expression", "new_expression"}:
            target = node.child_by_field_name("function") or node.child_by_field_name(
                "constructor"
            )
            target_text = _get_text(source_bytes, target).replace(" ", "")
            if not allowed_calls.fullmatch(target_text):
                return False
        stack.extend(reversed(node.named_children))
    return not stack


def _normalized_ts_member_path(text: str) -> str:
    compact = re.sub(r"\s+", "", text)
    compact = re.sub(r"\[['\"]([A-Za-z_$][A-Za-z0-9_$]*)['\"]\]", r".\1", compact)
    return compact


def _static_ts_property_name(node, source_bytes: bytes) -> str | None:
    if node is None:
        return None
    if node.type in {
        "identifier",
        "number",
        "property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _get_text(source_bytes, node)
    if node.type == "string":
        text = _get_text(source_bytes, node)
        return text[1:-1] if len(text) >= 2 else None
    if node.type == "computed_property_name":
        return _static_ts_property_name(
            next(iter(node.named_children), None), source_bytes
        )
    return None


def _member_is_mutated_for_generic_proof(
    security_flow,
    receiver_name: str,
    method: str,
    call,
    source_bytes: bytes,
) -> bool:
    expected = f"{receiver_name}.{method}"
    visited = 0
    for node in security_flow.iter_nodes():
        visited += 1
        if visited > 50_000:
            return True
        target = None
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            target = node.child_by_field_name("left")
        elif node.type == "update_expression":
            target = next(iter(node.named_children), None)
        if target is None:
            continue
        if _normalized_ts_member_path(_get_text(source_bytes, target)) != expected:
            continue
        current = node.parent
        module_level = True
        while current is not None:
            if current.type in _TS_FUNCTION_NODE_TYPES:
                module_level = False
                break
            current = current.parent
        if module_level or node.start_byte < call.start_byte:
            return True
    return False


def _generic_sql_template_is_proven_non_sql(
    template,
    source_bytes: bytes,
    security_flow,
) -> bool:
    if security_flow is None:
        return False
    arguments = template.parent
    call = arguments.parent if arguments is not None else None
    if call is None or call.type != "call_expression":
        return False
    function = _unwrap_ts_expression(call.child_by_field_name("function"))
    if function is None or function.type not in {
        "member_expression",
        "subscript_expression",
    }:
        return False
    receiver = _unwrap_ts_expression(function.child_by_field_name("object"))
    property_node = function.child_by_field_name(
        "property" if function.type == "member_expression" else "index"
    )
    method = _static_ts_property_name(property_node, source_bytes) or ""
    if receiver is None:
        return False
    if receiver.type == "regex":
        return True
    if receiver.type != "identifier":
        return False
    receiver_name = _get_text(source_bytes, receiver)
    if _member_is_mutated_for_generic_proof(
        security_flow,
        receiver_name,
        method,
        call,
        source_bytes,
    ):
        return False
    scope = security_flow.scope_for_node(call)
    value = _resolved_flow_value(
        security_flow,
        receiver_name,
        call.start_byte,
        scope.id,
    )
    if value is None:
        return False
    if value.type == "regex":
        return True
    if value.type == "new_expression":
        constructor = _unwrap_ts_expression(value.child_by_field_name("constructor"))
        return bool(
            constructor is not None
            and constructor.type == "identifier"
            and _get_text(source_bytes, constructor) == "RegExp"
            and security_flow.is_unshadowed_global_name(
                "RegExp",
                value.start_byte,
                security_flow.scope_for_node(value).id,
            )
        )
    return _local_console_only_member(value, method, source_bytes)


def _static_bracket_sql_templates(root_node, source_bytes: bytes) -> tuple[list, bool]:
    """Collect `receiver["query"](`...`)` generic SQL candidates."""
    templates = []
    stack = [root_node]
    visited = 0
    while stack and visited < 50_000:
        visited += 1
        node = stack.pop()
        if node.type == "call_expression":
            function = _unwrap_ts_expression(node.child_by_field_name("function"))
            if function is not None and function.type == "subscript_expression":
                index = function.child_by_field_name("index")
                method = _static_ts_property_name(index, source_bytes)
                arguments = node.child_by_field_name("arguments")
                first_argument = (
                    next(iter(arguments.named_children), None)
                    if arguments is not None
                    else None
                )
                if method in {"query", "exec", "execute"} and (
                    first_argument is not None
                    and first_argument.type == "template_string"
                ):
                    templates.append(first_argument)
        stack.extend(reversed(node.named_children))
    return templates, not stack


def scan_danger(
    root_node,
    file_path: str,
    lang: "Language | None" = None,
    source: bytes | None = None,
) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = TS_LANG
    if not lang:
        return []

    if source is None:
        # Tree-sitter may exclude leading extras from `root_node.text` while
        # retaining byte offsets into the original buffer. Preserve alignment
        # for direct callers that cannot provide the original source.
        prefix = (b"\n" * root_node.start_point[0]) + (b" " * root_node.start_point[1])
        missing = max(0, root_node.start_byte - len(prefix))
        source_bytes = prefix + (b" " * missing) + root_node.text
    else:
        source_bytes = source
    security_flow = None
    if _is_security_flow_candidate(source_bytes, str(file_path)):
        security_flow = build_security_flow(
            root_node,
            source_bytes,
            str(file_path),
            lang,
        )

    simple_captures = _run_batch(root_node, lang, "danger_simple", _SIMPLE_PATTERN)
    jsx_captures = _run_batch(root_node, lang, "danger_jsx", _JSX_PATTERN)
    complex_captures = _run_batch(root_node, lang, "danger_complex", _COMPLEX_PATTERN)
    child_process_aliases = _child_process_aliases(root_node, lang, source_bytes)
    static_string_bindings = _collect_static_string_bindings(root_node, source_bytes)

    for k, v in jsx_captures.items():
        simple_captures.setdefault(k, []).extend(v)

    for cap_name, (rule_id, severity, message) in _SIMPLE_MAP.items():
        for node in simple_captures.get(cap_name, []):
            if cap_name in {"innerHTML", "outerHTML"} and not (
                _html_property_capture_requires_finding(node, source_bytes)
            ):
                continue
            if cap_name == "doc_write" and not _document_write_requires_finding(
                node, source_bytes
            ):
                continue
            if cap_name == "math_random" and not _math_random_requires_finding(
                node, source_bytes
            ):
                continue
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
        member_node = prop_node.parent
        if member_node is None:
            continue
        obj_node = member_node.child_by_field_name("object")
        if obj_node is None:
            continue
        obj_name = _get_text(source_bytes, obj_node).lower()
        if obj_name in _SAFE_EXEC_OBJECTS and obj_name not in child_process_aliases:
            continue
        call_expr = member_node.parent
        command = _first_static_call_arg(call_expr, source_bytes)
        if command is not None:
            findings.extend(
                findings_for_command(
                    command,
                    file_path,
                    prop_node.start_point[0] + 1,
                )
            )
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
        if first_arg and _url_arg_is_ssrf_relevant(
            first_arg, source_bytes, str(file_path), static_string_bindings
        ):
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
        if first_arg and _url_arg_is_ssrf_relevant(
            first_arg, source_bytes, str(file_path), static_string_bindings
        ):
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
    sql_templates = []
    for cap_name in ("sql_query_tpl", "sql_exec_tpl", "sql_execute_tpl"):
        sql_templates.extend(complex_captures.get(cap_name, []))
    bracket_templates, bracket_scan_complete = _static_bracket_sql_templates(
        root_node,
        source_bytes,
    )
    sql_templates.extend(bracket_templates)
    if (
        not bracket_scan_complete
        and not re.search(rb"['\"]use\s+server['\"]", source_bytes)
        and re.search(
            rb"\[\s*['\"](?:query|exec|execute)['\"]\s*\]\s*\(",
            source_bytes,
        )
    ):
        findings.append(
            {
                "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                "severity": "HIGH",
                "kind": "processing_error",
                "message": (
                    "TypeScript bracket-access SQL analysis exceeded its bounded "
                    "work budget; a security candidate remains unresolved."
                ),
                "file": str(file_path),
                "line": 1,
                "col": 0,
            }
        )
    seen_sql_templates: set[tuple[int, int]] = set()
    for node in sql_templates:
        template_span = (node.start_byte, node.end_byte)
        if template_span in seen_sql_templates:
            continue
        seen_sql_templates.add(template_span)
        if not _template_has_substitution(node):
            continue
        if not _sql_template_has_keyword(node, source_bytes):
            continue
        if _generic_sql_template_is_proven_non_sql(
            node,
            source_bytes,
            security_flow,
        ):
            continue
        arguments = node.parent
        call = arguments.parent if arguments is not None else None
        if call is None or call.type != "call_expression":
            continue
        findings.append(
            {
                "rule_id": "SKY-D211",
                "severity": "CRITICAL",
                "message": "SQL query built with template literal — risk of SQL injection. Use parameterized queries.",
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
                "_ts_sql_sink_span": (call.start_byte, call.end_byte),
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
    if security_flow is not None:
        check_cookie_security(security_flow, findings)

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

    if security_flow is not None:
        check_nextjs_missing_auth(security_flow, findings)
    # S102 is owned by the secrets scanner. Keep the direct helper below for
    # focused callers, but do not duplicate the same finding in `danger`.
    _check_typescript_env_exfil(source_bytes, file_path, findings)
    d281_analyzer = _check_nextjs_server_action_sqli(
        source_bytes,
        file_path,
        findings,
        root_node=root_node,
    )
    if security_flow is not None:
        check_unverified_webhooks(security_flow, findings)
    _check_archive_extraction_path_traversal(
        root_node, source_bytes, file_path, findings
    )

    # D281 is the framework-specific taint proof for this exact SQL sink. Keep
    # one actionable result without hiding a different generic sink that happens
    # to share the same source line.
    if d281_analyzer is not None and d281_analyzer.seen_sinks:
        unsafe_sink_spans = d281_analyzer.seen_sinks
        findings = [
            finding
            for finding in findings
            if finding.get("rule_id") != "SKY-D211"
            or finding.get("_ts_sql_sink_span") not in unsafe_sink_spans
        ]

    if d281_analyzer is not None and d281_analyzer.result_complete:
        safe_sink_spans = d281_analyzer.safe_sink_spans
        findings = [
            finding
            for finding in findings
            if finding.get("rule_id") != "SKY-D211"
            or finding.get("_ts_sql_sink_span") not in safe_sink_spans
        ]
    for finding in findings:
        finding.pop("_ts_sql_sink_span", None)

    return findings


_SERVER_ACTION_SQL_METHODS = frozenset(
    {
        "query",
        "exec",
        "execute",
        "raw",
        "sql",
        "$queryRaw",
        "$executeRaw",
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        "queryRaw",
        "executeRaw",
        "queryRawUnsafe",
        "executeRawUnsafe",
        "prepare",
        "all",
        "any",
        "each",
        "get",
        "many",
        "none",
        "run",
        "unsafe",
    }
)
_SERVER_ACTION_SQL_METHOD_PATTERN = b"|".join(
    re.escape(method.encode())
    for method in sorted(_SERVER_ACTION_SQL_METHODS, key=len, reverse=True)
)
_SERVER_ACTION_SQL_CANDIDATE_RE = re.compile(
    rb"(?:\.\s*(?:"
    + _SERVER_ACTION_SQL_METHOD_PATTERN
    + rb")|\[\s*['\"`](?:"
    + _SERVER_ACTION_SQL_METHOD_PATTERN
    + rb")[\"'`]\s*\])\s*(?:\(|`)"
)


def _source_may_contain_server_action_sql(source: bytes) -> bool:
    """Cheap conservative gate before constructing the deep D281 analyzer."""
    return b"use server" in source and bool(
        _SERVER_ACTION_SQL_CANDIDATE_RE.search(source)
    )


_UNSAFE_SQL_TAGS = frozenset(
    {
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        "queryRawUnsafe",
        "executeRawUnsafe",
    }
)
_TS_FUNCTION_NODE_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)

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


def _check_unverified_webhook_handler(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    flow = _standalone_security_flow(source_bytes, file_path)
    if flow is not None:
        check_unverified_webhooks(flow, findings)


def _check_nextjs_missing_auth(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-D280: Detect Next.js API routes with mutating handlers missing auth checks."""
    flow = _standalone_security_flow(source_bytes, file_path)
    if flow is not None:
        check_nextjs_missing_auth(flow, findings)


def _standalone_security_flow(source_bytes: bytes, file_path: str):
    """Build the same proof facts used by the full scanner for direct rule tests."""
    if not _is_security_flow_candidate(source_bytes, file_path):
        return None

    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(str(file_path), source_bytes)
    if core.root_node is None or core.lang is None:
        return None
    return build_security_flow(
        core.root_node,
        source_bytes,
        str(file_path),
        core.lang,
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
            (line_offset, 0, (alias, expr))
            for line_offset, alias, expr in iter_semicolon_assignments(scope_text)
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
    """SKY-S102: Detect secret-like server env vars in client contexts."""
    source_text = source_bytes.decode("utf-8", errors="replace")
    lines = source_text.splitlines(keepends=True)
    if not is_client_exposure_context(str(file_path), lines):
        return

    for match, env_name in iter_sensitive_client_env_references(source_text):
        line_num = source_text.count("\n", 0, match.start()) + 1
        line_start = source_text.rfind("\n", 0, match.start()) + 1
        if is_public_client_env_name(env_name):
            detail = (
                f"Sensitive-looking public env var `{match.group(0)}` is bundled "
                "into client code. Public prefixes expose values by design; "
                "verify this is not a credential."
            )
        else:
            detail = (
                f"Server-only env var `{match.group(0)}` is referenced from "
                "client-accessible code. Move the secret to server-only code; "
                "use a framework public prefix only for non-sensitive values."
            )
        findings.append(
            {
                "rule_id": "SKY-S102",
                "severity": "HIGH",
                "message": detail,
                "file": str(file_path),
                "line": line_num,
                "col": match.start() - line_start,
                "env_name": env_name,
            }
        )


def _check_typescript_env_exfil(
    source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    source_text = source_bytes.decode("utf-8", errors="replace")
    for match in re.finditer(
        r"\b(?:fetch|axios\.(?:post|put|patch))\s*\("
        r"(?P<body>[^;]{0,600}process\.env\.[A-Za-z_][A-Za-z0-9_]*"
        r"[^;]{0,600})\)",
        source_text,
        re.S,
    ):
        body = match.group("body")
        env_match = re.search(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)", body)
        if env_match and env_match.group(1).startswith("NEXT_PUBLIC_"):
            continue
        url_match = re.search(r"['\"](?P<url>https?://[^'\"]+)['\"]", body)
        if url_match and not is_external_url(url_match.group("url")):
            continue
        findings.append(
            {
                "rule_id": "SKY-D327",
                "severity": "CRITICAL",
                "message": (
                    "HTTP request sends process.env data to an external destination."
                ),
                "file": str(file_path),
                "line": source_text[: match.start()].count("\n") + 1,
                "col": 0,
            }
        )


def _check_nextjs_server_action_sqli(
    source_bytes: bytes,
    file_path: str,
    findings: list[dict],
    *,
    root_node=None,
):
    """SKY-D281: Prove Server Action input reaches a SQL text argument."""
    if not _source_may_contain_server_action_sql(source_bytes):
        return None
    if root_node is None:
        from skylos.visitors.languages.typescript.core import TypeScriptCore

        core = TypeScriptCore(str(file_path), source_bytes)
        root_node = core.root_node
    if root_node is None:
        return None
    analyzer = _ServerActionSQLTaint(
        root_node,
        source_bytes,
        str(file_path),
    )
    findings.extend(analyzer.run())
    return analyzer


def _directive_value(statement, source_bytes: bytes) -> str | None:
    if statement.type != "expression_statement":
        return None
    expression = next(iter(statement.named_children), None)
    if expression is None or expression.type != "string":
        return None
    text = _get_text(source_bytes, expression)
    if len(text) < 2 or text[0] not in {'"', "'"} or text[-1] != text[0]:
        return None
    return text[1:-1]


def _scope_has_directive(scope, source_bytes: bytes, expected: str) -> bool:
    body = (
        scope.child_by_field_name("body")
        if scope.type in _TS_FUNCTION_NODE_TYPES
        else scope
    )
    if body is None:
        return False
    for statement in body.named_children:
        if statement.type == "comment":
            continue
        directive = _directive_value(statement, source_bytes)
        if directive is None:
            return False
        if directive == expected:
            return True
    return False


def _server_action_scopes(
    root_node,
    source_bytes: bytes,
    *,
    with_status: bool = False,
):
    inline_actions: list = []
    stack = [root_node]
    remaining = 500_000
    while stack and remaining > 0:
        remaining -= 1
        node = stack.pop()
        if node.type in _TS_FUNCTION_NODE_TYPES and _scope_has_directive(
            node, source_bytes, "use server"
        ):
            inline_actions.append(node)
        stack.extend(reversed(node.named_children))

    actions = inline_actions
    export_complete = True
    if _scope_has_directive(root_node, source_bytes, "use server"):
        actions, export_complete = _exported_server_action_functions(
            root_node,
            source_bytes,
            with_status=True,
        )
        actions.extend(inline_actions)

    unique: dict[tuple[int, int], object] = {}
    for action in actions:
        unique[(action.start_byte, action.end_byte)] = action
    result = list(unique.values())
    complete = not stack and export_complete
    return (result, complete) if with_status else result


def _exported_server_action_functions(
    root_node,
    source_bytes: bytes,
    *,
    with_status: bool = False,
):
    exported: list = []
    exported_names: set[str] = set()
    module_bindings: dict[str, object] = {}
    remaining = 200_000
    complete = True

    def consume() -> bool:
        nonlocal remaining, complete
        remaining -= 1
        if remaining >= 0:
            return True
        complete = False
        return False

    def record_declaration(declaration, *, exported_declaration: bool) -> None:
        if declaration is None:
            return
        if not consume():
            return
        value = declaration
        if declaration.type in _TS_FUNCTION_NODE_TYPES:
            name_node = declaration.child_by_field_name("name")
            if name_node is not None:
                name = _get_text(source_bytes, name_node)
                module_bindings[name] = declaration
                if exported_declaration:
                    exported_names.add(name)
            elif exported_declaration:
                exported.append(declaration)
            return
        if declaration.type not in {"lexical_declaration", "variable_declaration"}:
            value = _unwrap_ts_expression(declaration)
            if value is not None and value.type in _TS_FUNCTION_NODE_TYPES:
                exported.append(value)
            elif (
                exported_declaration
                and value is not None
                and value.type == "identifier"
            ):
                exported_names.add(_get_text(source_bytes, value))
            return
        for declarator in declaration.named_children:
            if not consume():
                return
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name_node is None or name_node.type != "identifier" or value is None:
                continue
            name = _get_text(source_bytes, name_node)
            module_bindings[name] = value
            if exported_declaration:
                exported_names.add(name)

    for statement in root_node.named_children:
        if not consume():
            break
        is_export = statement.type == "export_statement"
        if not is_export:
            record_declaration(statement, exported_declaration=False)
            continue

        declaration = statement.child_by_field_name("declaration")
        if declaration is not None:
            record_declaration(declaration, exported_declaration=True)
        else:
            value = statement.child_by_field_name("value")
            if value is None:
                value = next(
                    (
                        child
                        for child in statement.named_children
                        if child.type not in {"export_clause", "string"}
                    ),
                    None,
                )
            record_declaration(value, exported_declaration=True)

        for child in statement.named_children:
            if not consume():
                break
            if child.type != "export_clause":
                continue
            for specifier in child.named_children:
                if not consume():
                    break
                if specifier.type != "export_specifier":
                    continue
                name_node = specifier.child_by_field_name("name")
                if name_node is None:
                    name_node = next(iter(specifier.named_children), None)
                if name_node is not None:
                    exported_names.add(_get_text(source_bytes, name_node))

    for exported_name in exported_names:
        if not consume():
            break
        current = module_bindings.get(exported_name)
        seen: set[str] = set()
        for _ in range(64):
            if not consume():
                break
            current = _unwrap_ts_expression(current)
            if current is None:
                break
            if current.type in _TS_FUNCTION_NODE_TYPES:
                exported.append(current)
                break
            if current.type != "identifier":
                break
            alias = _get_text(source_bytes, current)
            if alias in seen:
                break
            seen.add(alias)
            current = module_bindings.get(alias)
    return (exported, complete) if with_status else exported


def _server_action_sql_candidate(call, source_bytes: bytes):
    function = _unwrap_ts_expression(call.child_by_field_name("function"))
    if function is None or function.type not in {
        "member_expression",
        "subscript_expression",
    }:
        return None
    property_node = function.child_by_field_name(
        "property" if function.type == "member_expression" else "index"
    )
    method = _static_ts_property_name(property_node, source_bytes) or ""
    if method not in _SERVER_ACTION_SQL_METHODS:
        return None

    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    tagged = arguments.type == "template_string"
    sql_expression = arguments if tagged else next(iter(arguments.named_children), None)
    receiver = function.child_by_field_name("object")
    return (
        (method, sql_expression, tagged, receiver)
        if sql_expression is not None
        else None
    )


class _ServerActionSQLTaint:
    """Small, bounded, fail-closed taint interpreter for SKY-D281."""

    _MAX_WORK = 1_000_000
    _MAX_CALL_DEPTH = 32
    _MAX_TRAVERSAL_DEPTH = 64
    _MAX_DEPTH_FALLBACK_NODES = 20_000
    _SAFE_PRISMA_TAGS = frozenset({"$queryRaw", "$executeRaw"})
    _MUTATING_HELPERS = frozenset(
        {
            "Object.assign",
            "Object.defineProperties",
            "Object.defineProperty",
            "Object.setPrototypeOf",
            "Reflect.defineProperty",
            "Reflect.set",
        }
    )
    _SQL_RECEIVER_HINTS = frozenset(
        {
            "db",
            "database",
            "conn",
            "connection",
            "knex",
            "mysql",
            "pg",
            "pool",
            "postgres",
            "prisma",
            "sequelize",
            "sql",
            "sqlite",
            "statement",
            "transaction",
            "tx",
        }
    )
    _NON_SQL_RECEIVER_HINTS = frozenset(
        {
            "auditlogger",
            "console",
            "documentbuilder",
            "logger",
            "pattern",
            "re",
            "regex",
            "regexp",
            "string",
        }
    )
    _SQL_DRIVER_MODULE_HINTS = (
        "@prisma/client",
        "better-sqlite3",
        "drizzle-orm",
        "knex",
        "libsql",
        "mysql",
        "pg",
        "postgres",
        "sequelize",
        "slonik",
        "sqlite",
        "typeorm",
    )

    def __init__(self, root_node, source: bytes, file_path: str) -> None:
        self.root = root_node
        self.source = source
        self.file_path = file_path
        self.remaining_work = self._MAX_WORK
        self.analysis_complete = not bool(getattr(root_node, "has_error", False))
        self.diagnostics: list[str] = []
        if not self.analysis_complete:
            self.diagnostics.append("TypeScript parser recovered from invalid syntax")
        self.frames: list[dict[str, tuple[frozenset[str], object | None]]] = []
        self.module_values: dict[str, object] = {}
        self.module_heap_values: dict[str, tuple[frozenset[str], object | None]] = {}
        self.functions: dict[str, list] = {}
        self.function_keys: dict[str, set[tuple[int, int]]] = {}
        self.import_identities: dict[str, tuple[str, str]] = {}
        self.prisma_constructors: set[str] = set()
        self.prisma_instances: set[str] = set()
        self.prisma_namespaces: set[str] = set()
        self.parameterizing_sql_tags: set[str] = set()
        self.parameterizing_sql_namespaces: set[str] = set()
        self.mutations: list[tuple[int, str, bool, tuple[int, int] | None]] = []
        self.findings: list[dict] = []
        self.seen_sinks: set[tuple[int, int]] = set()
        self.safe_sink_spans: set[tuple[int, int]] = set()
        self.accessor_getters: set[tuple[int, int]] = set()
        self.call_result_targets: dict[tuple[int, int], str] = {}
        self.call_result_alias_targets: dict[tuple[int, int], frozenset[str]] = {}
        self.generator_invocations: dict[tuple[int, int], dict] = {}
        self.generator_resume_counts: dict[tuple[int, int], int] = {}
        self.last_suspension_end: dict[tuple[int, int], int] = {}
        self.bound_builtin_captures: dict[
            tuple[int, int], tuple[str, str, list[dict]]
        ] = {}
        self.object_property_snapshots: dict[tuple[int, int], list[tuple]] = {}
        self.frozen_call_results: set[tuple[int, int]] = set()
        self.promise_result_sources: dict[tuple[int, int], frozenset[str]] = {}
        self.promise_reaction_frames: dict[tuple[int, int], list[dict]] = {}
        self.promise_reaction_effects: dict[tuple[int, int], list[dict]] = {}
        # Proven native Promises use an outcome-aware microtask model.  Keep
        # this separate from the conservative thenable fallback above: a
        # Promise object is not its eventual value, and only the selected
        # fulfillment/rejection handler executes.
        self.promise_summaries: dict[tuple[int, int], dict] = {}
        self.promise_ready_queue: list[tuple] = []
        self.promise_dependents: dict[tuple[int, int], list[tuple]] = {}
        self.promise_identity_paths: dict[tuple[int, int], set[str]] = {}
        self.promise_alias_keys: dict[tuple[int, int], tuple[int, int]] = {}
        self.promise_jobs_running: set[tuple[int, int]] = set()
        self.promise_job_order = 0
        self.promise_checkpoint_order = 0
        self.promise_root_action_key: tuple[int, int] | None = None
        self.last_suspension_promise: dict[tuple[int, int], tuple[int, int] | None] = {}
        self.result_complete = False
        self.call_stack: set[tuple[int, int]] = set()
        self.return_sources: list[frozenset[str]] = []
        self.return_alias_collectors: list[
            tuple[tuple[int, int], list[str | None]]
        ] = []
        self.return_value_collectors: list[tuple[tuple[int, int], list[dict]]] = []
        self.suspension_state_collectors: list[
            tuple[tuple[int, int], str, list[list[dict]]]
        ] = []
        self.object_alias_overrides: list[dict[str, str]] = []
        self.traversal_depth = 0
        self.path_terminated = False
        self.loop_depth = 0
        self.switch_break_collectors: list[tuple[int, list[list[dict]]]] = []
        self.label_break_collectors: list[tuple[str, list[list[dict]]]] = []
        self.label_continue_collectors: list[tuple[str, list[list[dict]]]] = []
        self.labelled_loop_continues: dict[tuple[int, int], list[list[dict]]] = {}
        self.loop_break_collectors: list[list[list[dict]]] = []
        self.loop_continue_collectors: list[list[list[dict]]] = []
        self.finally_abrupt_collectors: list[
            tuple[set[int], list[tuple[list[list[dict]], list[dict]]]]
        ] = []
        self.exception_state_collectors: list[
            tuple[int, list[list[dict]], list[dict]]
        ] = []
        self.catch_source_stack: list[frozenset[str]] = []
        self.function_context_stack: list[tuple[int, int]] = []
        self.function_node_stack: list[object] = []
        self.return_state_collectors: list[
            tuple[int, tuple[int, int], list[list[dict]]]
        ] = []
        self._collect_indexes()

    def run(self) -> list[dict]:
        actions, discovery_complete = _server_action_scopes(
            self.root,
            self.source,
            with_status=True,
        )
        if not discovery_complete:
            self.analysis_complete = False
            self.diagnostics.append("D281 action-discovery budget exhausted")
        for action in actions:
            self._reset_promise_scheduler()
            self.promise_root_action_key = (action.start_byte, action.end_byte)
            self._invoke_function(action, [], reset_scope=True)
            self.promise_root_action_key = None

        if (
            (
                not self.analysis_complete
                or not discovery_complete
                or self.remaining_work <= 0
            )
            and not self.findings
            and self._source_has_server_sql_candidate()
        ):
            self.findings.append(self._incomplete_analysis_finding())

        coalesced: list[dict] = []
        for finding in self.findings:
            span = finding.get("_d281_sink_span")
            merged = False
            if span is not None:
                for index, existing in enumerate(coalesced):
                    existing_span = existing.get("_d281_sink_span")
                    if existing_span is None:
                        continue
                    if span[0] <= existing_span[0] and span[1] >= existing_span[1]:
                        coalesced[index] = finding
                        merged = True
                        break
                    if existing_span[0] <= span[0] and existing_span[1] >= span[1]:
                        merged = True
                        break
            if not merged:
                coalesced.append(finding)
        self.findings = coalesced

        complete = self.analysis_complete and self.remaining_work > 0
        self.result_complete = complete
        diagnostics = [] if complete else list(self.diagnostics)
        if self.remaining_work <= 0 and "D281 work budget exhausted" not in diagnostics:
            diagnostics.append("D281 work budget exhausted")
        for finding in self.findings:
            finding.pop("_d281_sink_span", None)
            if finding.get("rule_id") != "SKY-D281":
                continue
            evidence = finding["metadata"]["security_evidence"]
            evidence["analysis_complete"] = complete
            evidence["analysis_diagnostics"] = diagnostics[:4]
        return self.findings

    def _source_has_server_sql_candidate(self) -> bool:
        source = self.source[:8_000_000]
        if not re.search(rb"['\"]use\s+server['\"]", source):
            return False
        return bool(_SERVER_ACTION_SQL_CANDIDATE_RE.search(source))

    def _incomplete_analysis_finding(self) -> dict:
        return {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": "processing_error",
            "message": (
                "TypeScript Server Action SQL analysis exceeded its bounded "
                "work budget; a security candidate remains unresolved."
            ),
            "file": self.file_path,
            "line": 1,
            "col": 0,
        }

    def _consume(self, amount: int = 1) -> bool:
        self.remaining_work -= amount
        if self.remaining_work >= 0:
            return True
        self.analysis_complete = False
        if "D281 work budget exhausted" not in self.diagnostics:
            self.diagnostics.append("D281 work budget exhausted")
        return False

    def _bounded_nodes(self, root):
        stack = [root]
        while stack and self._consume():
            node = stack.pop()
            yield node
            stack.extend(reversed(node.named_children))

    def _collect_indexes(self) -> None:
        for statement in self.root.named_children:
            if not self._consume():
                break
            declaration = statement
            if statement.type == "import_statement":
                self._collect_sql_import(statement)
                continue
            if statement.type == "export_statement":
                declaration = statement.child_by_field_name("declaration")
                if declaration is None:
                    declaration = next(iter(statement.named_children), None)
            if declaration is None:
                continue
            if declaration.type in _TS_FUNCTION_NODE_TYPES:
                self._record_function(declaration)
            elif declaration.type == "class_declaration":
                name_node = declaration.child_by_field_name("name")
                if name_node is not None:
                    self.module_values[_get_text(self.source, name_node)] = declaration
            elif declaration.type in {"lexical_declaration", "variable_declaration"}:
                for declarator in declaration.named_children:
                    if not self._consume():
                        break
                    if declarator.type != "variable_declarator":
                        continue
                    name_node = declarator.child_by_field_name("name")
                    value = declarator.child_by_field_name("value")
                    if name_node is not None and name_node.type == "identifier":
                        name = _get_text(self.source, name_node)
                        if value is not None:
                            self.module_values[name] = value
                            unwrapped = _unwrap_ts_expression(value)
                            if (
                                unwrapped is not None
                                and unwrapped.type in _TS_FUNCTION_NODE_TYPES
                            ):
                                self.functions.setdefault(name, []).append(unwrapped)
                    elif name_node is not None and name_node.type == "object_pattern":
                        for name, binding_node in self._object_pattern_bindings(
                            name_node
                        ):
                            self.module_values[name] = binding_node

        for node in self._bounded_nodes(self.root):
            if node.type in _TS_FUNCTION_NODE_TYPES:
                self._record_function(node)
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                left = node.child_by_field_name("left")
                if left is not None:
                    mutation_path = self._canonical_object_path(
                        left
                    ) or self._mutation_target_path(left)
                    self.mutations.append(
                        (
                            node.start_byte,
                            mutation_path,
                            self._is_module_level_node(node),
                            self._enclosing_function_key(node),
                        )
                    )
                    if self._is_module_level_node(node):
                        self.module_heap_values[mutation_path] = (
                            frozenset(),
                            node.child_by_field_name("right"),
                        )
            elif node.type == "update_expression":
                target = next(iter(node.named_children), None)
                if target is not None:
                    self.mutations.append(
                        (
                            node.start_byte,
                            self._canonical_object_path(target)
                            or self._mutation_target_path(target),
                            self._is_module_level_node(node),
                            self._enclosing_function_key(node),
                        )
                    )
            elif node.type == "unary_expression" and any(
                not child.is_named and child.type == "delete" for child in node.children
            ):
                target = next(iter(node.named_children), None)
                if target is not None:
                    self.mutations.append(
                        (
                            node.start_byte,
                            self._canonical_object_path(target)
                            or self._mutation_target_path(target),
                            self._is_module_level_node(node),
                            self._enclosing_function_key(node),
                        )
                    )
            elif node.type == "call_expression":
                function = node.child_by_field_name("function")
                path = (
                    _normalized_ts_member_path(_get_text(self.source, function))
                    if function
                    else ""
                )
                if path in self._MUTATING_HELPERS:
                    arguments = node.child_by_field_name("arguments")
                    first = (
                        next(iter(arguments.named_children), None)
                        if arguments
                        else None
                    )
                    if first is not None:
                        self.mutations.append(
                            (
                                node.start_byte,
                                self._canonical_object_path(first)
                                or _normalized_ts_member_path(
                                    _get_text(self.source, first)
                                ),
                                self._is_module_level_node(node),
                                self._enclosing_function_key(node),
                            )
                        )

    def _mutation_target_path(self, target) -> str:
        """Canonicalize static bracket keys; retain a wildcard for unknown keys."""
        node = _unwrap_ts_expression(target)
        if node is None:
            return ""
        if node.type == "identifier":
            return _get_text(self.source, node)
        if node.type not in {"member_expression", "subscript_expression"}:
            return _normalized_ts_member_path(_get_text(self.source, node))
        receiver = self._mutation_target_path(node.child_by_field_name("object"))
        if not receiver:
            return ""
        property_name = self._member_property_name(node)
        if property_name is not None:
            return f"{receiver}.{self._heap_property_segment(property_name)}"
        property_node = node.child_by_field_name(
            "property" if node.type == "member_expression" else "index"
        )
        if (
            node.type == "subscript_expression"
            and not self._computed_property_may_be_string(property_node)
        ):
            return f"{receiver}.%00non-string"
        return f"{receiver}.*"

    @staticmethod
    def _heap_property_segment(property_name: str) -> str:
        """Keep literal keys distinct from synthetic path/wildcard syntax."""
        return property_name.replace("%", "%25").replace(".", "%2E").replace("*", "%2A")

    @staticmethod
    def _heap_property_name(property_segment: str) -> str:
        """Decode a direct synthetic-heap member back to its JavaScript key."""
        return re.sub(
            r"%(?:25|2E|2A)",
            lambda match: {"%25": "%", "%2E": ".", "%2A": "*"}[match.group(0)],
            property_segment,
        )

    @staticmethod
    def _enclosing_function_key(node) -> tuple[int, int] | None:
        current = node
        while current is not None:
            if current.type in _TS_FUNCTION_NODE_TYPES:
                return current.start_byte, current.end_byte
            current = current.parent
        return None

    @staticmethod
    def _is_module_level_node(node) -> bool:
        current = node.parent
        while current is not None:
            if current.type in _TS_FUNCTION_NODE_TYPES:
                return False
            if current.type == "program":
                return True
            current = current.parent
        return False

    @staticmethod
    def _is_prisma_client_module(module: str) -> bool:
        normalized = module.replace("\\", "/").lower().rstrip("/")
        return bool(
            normalized == "@prisma/client"
            or normalized.endswith("/generated/client")
            or normalized.endswith("/generated/prisma/client")
            or "prisma/generated/client" in normalized
        )

    def _collect_sql_import(self, statement) -> None:
        source_node = statement.child_by_field_name("source")
        if source_node is None:
            source_node = next(
                (child for child in statement.named_children if child.type == "string"),
                None,
            )
        if source_node is None:
            return
        module = _get_text(self.source, source_node).strip("'\"")
        bindings: list[tuple[str, str]] = []
        for node in self._bounded_nodes(statement):
            if node.type == "import_specifier":
                imported = node.child_by_field_name("name")
                alias = node.child_by_field_name("alias")
                identifiers = [
                    child for child in node.named_children if child.type == "identifier"
                ]
                if imported is None and identifiers:
                    imported = identifiers[0]
                if imported is None:
                    continue
                exported_name = _get_text(self.source, imported)
                local = alias or (identifiers[-1] if identifiers else imported)
                bindings.append((exported_name, _get_text(self.source, local)))
            elif node.type == "namespace_import":
                local = next(
                    (
                        child
                        for child in node.named_children
                        if child.type == "identifier"
                    ),
                    None,
                )
                if local is not None:
                    bindings.append(("*", _get_text(self.source, local)))

        import_clause = next(
            (
                child
                for child in statement.named_children
                if child.type == "import_clause"
            ),
            None,
        )
        if import_clause is not None:
            default_local = next(
                (
                    child
                    for child in import_clause.named_children
                    if child.type == "identifier"
                ),
                None,
            )
            if default_local is not None:
                bindings.append(("default", _get_text(self.source, default_local)))

        prisma_module = self._is_prisma_client_module(module)
        normalized_module = module.replace("\\", "/").lower()
        for exported_name, local_name in bindings:
            self.import_identities[local_name] = (module, exported_name)
            if prisma_module and exported_name == "PrismaClient":
                self.prisma_constructors.add(local_name)
            if prisma_module and exported_name in {"Prisma", "*"}:
                self.prisma_namespaces.add(local_name)
            if (
                local_name.lower() == "prisma"
                and normalized_module.rsplit("/", 1)[-1] == "prisma"
                and not prisma_module
            ):
                self.prisma_instances.add(local_name)
            if exported_name == "sql" and normalized_module in {
                "drizzle-orm",
                "slonik",
                "@databases/sql",
            }:
                self.parameterizing_sql_tags.add(local_name)
            if exported_name == "default" and normalized_module == "@databases/sql":
                self.parameterizing_sql_tags.add(local_name)
            if exported_name == "*" and normalized_module in {
                "drizzle-orm",
                "slonik",
                "@databases/sql",
            }:
                self.parameterizing_sql_namespaces.add(local_name)

    def _record_function(self, function) -> None:
        name_node = function.child_by_field_name("name")
        if name_node is None or name_node.type != "identifier":
            return
        name = _get_text(self.source, name_node)
        bucket = self.functions.setdefault(name, [])
        key = (function.start_byte, function.end_byte)
        keys = self.function_keys.setdefault(name, set())
        if key not in keys:
            keys.add(key)
            bucket.append(function)

    def _function_parameters(self, function) -> list[str]:
        names: list[str] = []
        for pattern in self._function_parameter_patterns(function):
            names.extend(self._pattern_names(pattern))
        return names

    def _function_parameter_patterns(self, function) -> list:
        parameters = function.child_by_field_name("parameters")
        if parameters is None:
            parameters = function.child_by_field_name("parameter")
        if parameters is None:
            return []
        parameter_nodes = (
            list(parameters.named_children)
            if parameters.type == "formal_parameters"
            else [parameters]
        )
        patterns = []
        for parameter in parameter_nodes:
            pattern = parameter.child_by_field_name("pattern") or parameter
            patterns.append(pattern)
        return patterns

    def _pattern_names(self, pattern) -> list[str]:
        names: list[str] = []
        stack = [pattern] if pattern is not None else []
        visited = 0
        while stack and visited < 10_000:
            visited += 1
            current = stack.pop()
            if current.type in {
                "identifier",
                "shorthand_property_identifier_pattern",
            }:
                names.append(_get_text(self.source, current))
                continue
            if current.type in {"required_parameter", "optional_parameter"}:
                child = current.child_by_field_name("pattern")
                if child is not None:
                    stack.append(child)
                continue
            if current.type in {"assignment_pattern", "object_assignment_pattern"}:
                child = current.child_by_field_name("left")
                if child is not None:
                    stack.append(child)
                continue
            if current.type == "pair_pattern":
                child = current.child_by_field_name("value")
                if child is not None:
                    stack.append(child)
                continue
            children = []
            for child in current.named_children:
                if child.type.endswith("_type") or child.type in {
                    "type_annotation",
                    "predefined_type",
                    "type_identifier",
                }:
                    continue
                children.append(child)
            stack.extend(reversed(children))
        if stack:
            self.analysis_complete = False
            if "D281 binding-pattern budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 binding-pattern budget exhausted")
        return names

    def _object_pattern_bindings(self, pattern) -> list[tuple[str, object]]:
        bindings: list[tuple[str, object]] = []
        if pattern is None or pattern.type != "object_pattern":
            return bindings
        for child in pattern.named_children[:10_000]:
            target = child
            if child.type == "pair_pattern":
                target = child.child_by_field_name("value")
            elif child.type in {
                "assignment_pattern",
                "object_assignment_pattern",
            }:
                target = child.child_by_field_name("left")
            for name in self._pattern_names(target):
                bindings.append((name, child))
        if len(pattern.named_children) > 10_000:
            self.analysis_complete = False
            if "D281 object-pattern budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 object-pattern budget exhausted")
        return bindings

    def _static_property_name(self, node) -> str | None:
        return _static_ts_property_name(node, self.source)

    def _object_argument_property(self, argument, name: str):
        argument = _unwrap_ts_expression(argument)
        if argument is None or argument.type != "object":
            return None, False
        for child in argument.named_children:
            if child.type == "pair":
                key = self._static_property_name(child.child_by_field_name("key"))
                if key == name:
                    return child.child_by_field_name("value"), True
            elif child.type == "shorthand_property_identifier":
                if self._static_property_name(child) == name:
                    return child, True
            elif child.type == "spread_element":
                return None, False
        return None, True

    def _bind_parameter_pattern(
        self,
        pattern,
        sources: frozenset[str],
        value_node,
    ) -> None:
        if pattern is None:
            return
        if pattern.type in {"required_parameter", "optional_parameter"}:
            pattern = pattern.child_by_field_name("pattern") or pattern
        if pattern.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
        }:
            self._declare(_get_text(self.source, pattern), sources, value_node)
            return
        if pattern.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = pattern.child_by_field_name("left")
            default = pattern.child_by_field_name("right")
            if value_node is None and default is not None:
                self._bind_parameter_pattern(
                    left,
                    self._visit_expression(default),
                    default,
                )
            else:
                self._bind_parameter_pattern(left, sources, value_node)
            return
        if pattern.type == "object_pattern":
            for child in pattern.named_children:
                key_node = child
                target = child
                if child.type == "pair_pattern":
                    key_node = child.child_by_field_name("key")
                    target = child.child_by_field_name("value")
                elif child.type in {
                    "assignment_pattern",
                    "object_assignment_pattern",
                }:
                    key_node = child.child_by_field_name("left")
                name = self._static_property_name(key_node)
                property_value, object_is_known = self._object_argument_property(
                    value_node, name or ""
                )
                if property_value is not None:
                    property_sources = self._visit_expression(property_value)
                elif object_is_known:
                    property_sources = frozenset()
                else:
                    property_sources = sources
                self._bind_parameter_pattern(
                    target,
                    property_sources,
                    property_value,
                )
            return
        if pattern.type == "array_pattern":
            argument = _unwrap_ts_expression(value_node)
            values = (
                list(argument.named_children)
                if argument is not None and argument.type == "array"
                else []
            )
            for index, target in enumerate(pattern.named_children):
                item = values[index] if index < len(values) else None
                item_sources = (
                    self._visit_expression(item)
                    if item is not None
                    else (frozenset() if argument is not None else sources)
                )
                self._bind_parameter_pattern(target, item_sources, item)
            return
        for name in self._pattern_names(pattern):
            self._declare(name, sources, value_node)

    def _lookup(self, name: str) -> tuple[frozenset[str], object | None]:
        for frame in reversed(self.frames):
            if name in frame:
                return frame[name]
        return (frozenset(), self.module_values.get(name))

    def _lookup_explicit(
        self, name: str
    ) -> tuple[bool, tuple[frozenset[str], object | None]]:
        for frame in reversed(self.frames):
            if name in frame:
                return True, frame[name]
        if name in self.module_values:
            return True, (frozenset(), self.module_values[name])
        return False, (frozenset(), None)

    def _declare(
        self,
        name: str,
        sources: frozenset[str],
        value_node=None,
    ) -> None:
        if not self.frames:
            self.frames.append({})
        for member_name in [
            key for key in self.frames[-1] if key.startswith(f"{name}.")
        ]:
            self.frames[-1].pop(member_name, None)
        self.frames[-1][name] = (sources, value_node)

    def _assign(self, name: str, sources: frozenset[str], value_node=None) -> None:
        for overrides in reversed(self.object_alias_overrides):
            if name in overrides:
                overrides.pop(name, None)
                break
        for frame in reversed(self.frames):
            if name in frame:
                for member_name in [key for key in frame if key.startswith(f"{name}.")]:
                    frame.pop(member_name, None)
                frame[name] = (sources, value_node)
                return
        self._declare(name, sources, value_node)

    def _canonical_object_name(self, name: str) -> str:
        current = name
        seen = set()
        for _ in range(32):
            if current in seen:
                return current
            seen.add(current)
            for overrides in reversed(self.object_alias_overrides):
                target = overrides.get(current)
                if target is not None:
                    current = target
                    break
            else:
                target = None
            if target is not None:
                continue
            value = _unwrap_ts_expression(self._lookup(current)[1])
            if value is None or value.type != "identifier":
                return current
            target = _get_text(self.source, value)
            if target == current:
                return current
            current = target
        self.analysis_complete = False
        if "D281 object-alias depth exhausted" not in self.diagnostics:
            self.diagnostics.append("D281 object-alias depth exhausted")
        return current

    def _canonical_object_path(
        self,
        expression,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
        use_byte: int | None = None,
    ) -> str | None:
        """Resolve identifier/member aliases into a synthetic heap path."""
        if depth >= 32:
            self.analysis_complete = False
            if "D281 object-alias depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 object-alias depth exhausted")
            return None
        node = _unwrap_ts_expression(expression)
        if node is None:
            return None
        returned_target = self.call_result_targets.get((node.start_byte, node.end_byte))
        if returned_target is not None:
            return returned_target
        if use_byte is None:
            use_byte = node.start_byte
        if node.type == "identifier":
            name = _get_text(self.source, node)
            if name in seen:
                return name
            value = _unwrap_ts_expression(self._lookup(name)[1])
            if value is not None and value.type in {
                "identifier",
                "call_expression",
                "member_expression",
                "subscript_expression",
            }:
                resolved = self._canonical_object_path(
                    value,
                    seen=seen | {name},
                    depth=depth + 1,
                    use_byte=use_byte,
                )
                if resolved is not None:
                    return resolved
            return self._canonical_object_name(name)
        if node.type == "this":
            return self._canonical_object_name("this")
        if node.type == "call_expression":
            target = self._builtin_call_target(node)
            if target is None or not self._builtin_result_target_is_stable(
                node,
                target,
                use_byte,
            ):
                return None
            return self._canonical_object_path(
                target,
                seen=seen,
                depth=depth + 1,
                use_byte=use_byte,
            )
        if node.type not in {"member_expression", "subscript_expression"}:
            return None
        receiver_path = self._canonical_object_path(
            node.child_by_field_name("object"),
            seen=seen,
            depth=depth + 1,
            use_byte=use_byte,
        )
        property_name = self._member_property_name(node)
        if receiver_path is None or property_name is None:
            return None
        if receiver_path in {"global", "globalThis", "window"} and property_name in {
            "Object",
            "Reflect",
        }:
            return property_name
        return f"{receiver_path}.{self._heap_property_segment(property_name)}"

    def _static_computed_property_value(
        self,
        property_node,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> tuple[bool, str | None]:
        """Resolve a computed property key without executing target code.

        A known Symbol key returns ``(True, None)``. Unknown values return
        ``(False, None)`` because they may alias any string member.
        """
        if depth >= 32:
            self.analysis_complete = False
            if "D281 property-key alias depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 property-key alias depth exhausted")
            return False, None
        if property_node is not None and property_node.type == "computed_property_name":
            property_node = next(iter(property_node.named_children), None)
        node = _unwrap_ts_expression(property_node)
        if node is None:
            return False, None
        if node.type == "string":
            return True, self._static_property_name(node)
        if node.type in {"number", "true", "false", "null"}:
            return True, _get_text(self.source, node)
        if node.type in {"member_expression", "subscript_expression"}:
            path = _normalized_ts_member_path(_get_text(self.source, node))
            if path.startswith("Symbol.") or path.startswith("Symbol["):
                return True, None
            return False, None
        if node.type == "template_string":
            if any(
                child.type == "template_substitution" for child in node.named_children
            ):
                return False, None
            return True, "".join(
                _get_text(self.source, child)
                for child in node.named_children
                if child.type == "string_fragment"
            )
        if node.type == "binary_expression":
            has_plus = any(
                not child.is_named and child.type == "+" for child in node.children
            )
            if not has_plus:
                return False, None
            left_known, left = self._static_computed_property_value(
                node.child_by_field_name("left"),
                seen=seen,
                depth=depth + 1,
            )
            right_known, right = self._static_computed_property_value(
                node.child_by_field_name("right"),
                seen=seen,
                depth=depth + 1,
            )
            if left_known and right_known and left is not None and right is not None:
                return True, left + right
            return False, None
        if node.type != "identifier":
            return False, None
        name = _get_text(self.source, node)
        if name in seen:
            return False, None
        sources, value = self._lookup(name)
        if sources or value is None:
            return False, None
        return self._static_computed_property_value(
            value,
            seen=seen | {name},
            depth=depth + 1,
        )

    def _resolved_computed_property_name(self, property_node) -> str | None:
        known, value = self._static_computed_property_value(property_node)
        return value if known else None

    def _static_condition_value(
        self,
        expression,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> bool | None:
        if depth >= 32:
            return None
        node = _unwrap_ts_expression(expression)
        if node is None:
            return None
        if node.type == "true":
            return True
        if node.type == "false":
            return False
        if node.type in {"null", "undefined"}:
            return False
        known, primitive = self._static_number_primitive(node)
        if known and primitive is not None:
            _, value = primitive
            return bool(value) and not (isinstance(value, float) and math.isnan(value))
        if node.type == "string":
            text = _get_text(self.source, node).strip()
            if (
                len(text) >= 2
                and text[0] in {"'", '"'}
                and text[-1] == text[0]
                and "\\" not in text[1:-1]
            ):
                return bool(text[1:-1])
        if node.type in {"object", "array", "function_expression", "arrow_function"}:
            return True
        if node.type == "identifier":
            name = _get_text(self.source, node)
            if name in seen:
                return None
            sources, value = self._lookup(name)
            if sources or value is None:
                return None
            return self._static_condition_value(
                value,
                seen=seen | {name},
                depth=depth + 1,
            )
        if node.type == "unary_expression" and any(
            not child.is_named and child.type == "!" for child in node.children
        ):
            operand = next(iter(node.named_children), None)
            value = self._static_condition_value(
                operand,
                seen=seen,
                depth=depth + 1,
            )
            return None if value is None else not value
        return None

    def _static_number_primitive(
        self,
        expression,
    ) -> tuple[bool, tuple[str, object] | None]:
        """Decode a side-effect-free JavaScript Number or BigInt literal."""
        node = _unwrap_ts_expression(expression)
        sign = 1
        if node is not None and node.type == "unary_expression":
            operator = next(
                (
                    child.type
                    for child in node.children
                    if not child.is_named and child.type in {"+", "-"}
                ),
                None,
            )
            if operator is None:
                return False, None
            sign = -1 if operator == "-" else 1
            node = _unwrap_ts_expression(next(iter(node.named_children), None))
        if node is None or node.type != "number":
            return False, None
        text = _get_text(self.source, node).replace("_", "").lower()
        try:
            if text.endswith("n"):
                return True, ("bigint", sign * int(text[:-1], 0))
            if text.startswith(("0x", "0o", "0b")):
                value = float(int(text, 0))
            else:
                value = float(text)
        except ValueError:
            return False, None
        return True, ("number", sign * value)

    def _static_switch_primitive(
        self,
        expression,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> tuple[bool, tuple[str, object] | None]:
        """Decode only primitives whose strict equality is unambiguous."""
        if depth >= 32:
            return False, None
        node = _unwrap_ts_expression(expression)
        if node is None:
            return False, None
        if node.type == "string":
            text = _get_text(self.source, node).strip()
            if (
                len(text) >= 2
                and text[0] in {"'", '"'}
                and text[-1] == text[0]
                and "\\" not in text[1:-1]
            ):
                return True, ("string", text[1:-1])
            return False, None
        if node.type in {"true", "false"}:
            return True, ("boolean", node.type == "true")
        if node.type == "null":
            return True, ("null", None)
        if node.type == "undefined":
            return True, ("undefined", None)
        numeric_known, numeric = self._static_number_primitive(node)
        if numeric_known:
            return True, numeric
        if node.type == "identifier":
            name = _get_text(self.source, node)
            if name in seen:
                return False, None
            sources, value = self._lookup(name)
            if sources or value is None:
                return False, None
            return self._static_switch_primitive(
                value,
                seen=seen | {name},
                depth=depth + 1,
            )
        return False, None

    def _computed_property_may_be_string(self, property_node) -> bool:
        """Return false only when a computed key is statically known."""
        known, _ = self._static_computed_property_value(property_node)
        return not known

    def _member_property_name(self, expression) -> str | None:
        property_node = expression.child_by_field_name(
            "property" if expression.type == "member_expression" else "index"
        )
        if expression.type == "member_expression":
            return self._static_property_name(property_node)
        return self._resolved_computed_property_name(property_node)

    def _assign_member_name(
        self,
        receiver_name: str,
        property_name: str | None,
        sources: frozenset[str],
        value_node=None,
    ) -> None:
        property_segment = (
            "*" if property_name is None else self._heap_property_segment(property_name)
        )
        self._assign_member_path(
            receiver_name,
            property_segment,
            sources,
            value_node,
        )

    def _assign_member_path(
        self,
        receiver_name: str,
        property_path: str,
        sources: frozenset[str],
        value_node=None,
    ) -> None:
        """Assign an already encoded synthetic heap suffix."""
        canonical_name = self._canonical_object_name(receiver_name)
        member_name = f"{canonical_name}.{property_path}"
        # Prefer the frame that owns the canonical object.  This preserves
        # writes through aliases and through object parameters in local helper
        # calls instead of trapping the synthetic member binding in the alias
        # frame.
        for frame in reversed(self.frames):
            if canonical_name in frame:
                frame[member_name] = (sources, value_node)
                return
        for frame in reversed(self.frames):
            if receiver_name in frame:
                frame[member_name] = (sources, value_node)
                return
        if canonical_name in {"Object", "Reflect"} and self.frames:
            # These roots are ECMAScript globals. A helper assignment mutates
            # the shared object, not a block-local synthetic binding.
            self.frames[0][member_name] = (sources, value_node)
            return
        self._declare(member_name, sources, value_node)

    def _property_metadata_suffix(self, property_name: str, field: str) -> str:
        segment = self._heap_property_segment(property_name)
        return f"%00descriptor.{segment}.{field}"

    def _set_property_metadata(
        self,
        object_path: str,
        property_name: str,
        field: str,
        states: frozenset[str],
        marker_node,
    ) -> None:
        self._assign_member_path(
            object_path,
            self._property_metadata_suffix(property_name, field),
            states,
            marker_node,
        )

    def _property_metadata(
        self,
        object_path: str,
        property_name: str,
        field: str,
    ) -> tuple[frozenset[str], object | None]:
        present, binding = self._lookup_explicit(
            f"{object_path}.{self._property_metadata_suffix(property_name, field)}"
        )
        if not present:
            return frozenset(), None
        return (
            frozenset(
                source
                for source in binding[0]
                if source.startswith(_PROPERTY_STATE_PREFIX)
            ),
            binding[1],
        )

    @staticmethod
    def _property_boolean_state(states: frozenset[str]) -> bool | None:
        has_true = _PROPERTY_TRUE in states
        has_false = _PROPERTY_FALSE in states
        if has_true == has_false:
            return None
        return has_true

    def _property_exists_state(
        self,
        object_path: str,
        property_name: str,
    ) -> bool | None:
        states, _ = self._property_metadata(object_path, property_name, "exists")
        has_present = _PROPERTY_PRESENT in states
        has_absent = _PROPERTY_ABSENT in states
        if has_present != has_absent:
            return has_present
        if states:
            return None
        segment = self._heap_property_segment(property_name)
        return True if self._lookup_explicit(f"{object_path}.{segment}")[0] else None

    def _property_kind_state(
        self,
        object_path: str,
        property_name: str,
    ) -> str | None:
        states, _ = self._property_metadata(object_path, property_name, "kind")
        has_data = _PROPERTY_DATA in states
        has_accessor = _PROPERTY_ACCESSOR in states
        if has_data != has_accessor:
            return "data" if has_data else "accessor"
        if states:
            return None
        segment = self._heap_property_segment(property_name)
        present, binding = self._lookup_explicit(f"{object_path}.{segment}")
        value = binding[1] if present else None
        if (
            value is not None
            and (value.start_byte, value.end_byte) in self.accessor_getters
        ):
            return "accessor"
        return "data" if present else None

    def _property_attribute_state(
        self,
        object_path: str,
        property_name: str,
        field: str,
    ) -> bool | None:
        if field == "writable" and self._is_definitely_frozen_path(object_path):
            if self._property_kind_state(object_path, property_name) == "data":
                return False
        if field == "configurable" and self._is_definitely_frozen_path(object_path):
            return False
        states, _ = self._property_metadata(object_path, property_name, field)
        value = self._property_boolean_state(states)
        if value is not None or states:
            return value
        # Object-literal and assignment-created properties use the ordinary
        # writable/enumerable/configurable defaults.  DefineProperty writes
        # record every attribute explicitly below.
        return True if self._property_exists_state(object_path, property_name) else None

    def _property_accessor_state(
        self,
        object_path: str,
        property_name: str,
        field: str,
    ) -> tuple[bool | None, object | None]:
        states, node = self._property_metadata(object_path, property_name, field)
        has_present = _PROPERTY_PRESENT in states
        has_absent = _PROPERTY_ABSENT in states
        if has_present != has_absent:
            return has_present, node if has_present else None
        if states:
            return None, node
        if field == "getter":
            segment = self._heap_property_segment(property_name)
            present, binding = self._lookup_explicit(f"{object_path}.{segment}")
            value = binding[1] if present else None
            if (
                value is not None
                and (value.start_byte, value.end_byte) in self.accessor_getters
            ):
                return True, value
        return None, None

    def _record_data_property(
        self,
        object_path: str,
        property_name: str,
        sources: frozenset[str],
        value_node,
        marker_node,
        *,
        writable: bool | None = True,
        enumerable: bool | None = True,
        configurable: bool | None = True,
    ) -> None:
        self._assign_member_name(object_path, property_name, sources, value_node)
        self._set_property_metadata(
            object_path,
            property_name,
            "exists",
            frozenset({_PROPERTY_PRESENT}),
            marker_node,
        )
        self._set_property_metadata(
            object_path,
            property_name,
            "kind",
            frozenset({_PROPERTY_DATA}),
            marker_node,
        )
        self._set_property_metadata(
            object_path,
            property_name,
            "getter",
            frozenset({_PROPERTY_ABSENT}),
            marker_node,
        )
        self._set_property_metadata(
            object_path,
            property_name,
            "setter",
            frozenset({_PROPERTY_ABSENT}),
            marker_node,
        )
        for field, value in (
            ("writable", writable),
            ("enumerable", enumerable),
            ("configurable", configurable),
        ):
            states = (
                frozenset({_PROPERTY_TRUE if value else _PROPERTY_FALSE})
                if value is not None
                else frozenset({_PROPERTY_TRUE, _PROPERTY_FALSE})
            )
            self._set_property_metadata(
                object_path,
                property_name,
                field,
                states,
                marker_node,
            )

    def _record_accessor_property(
        self,
        object_path: str,
        property_name: str,
        marker_node,
        *,
        getter_state: bool | None,
        getter,
        setter_state: bool | None,
        setter,
        enumerable: bool | None,
        configurable: bool | None,
    ) -> None:
        existing_sources = frozenset()
        existing_value = None
        segment = self._heap_property_segment(property_name)
        present, binding = self._lookup_explicit(f"{object_path}.{segment}")
        if present:
            existing_sources, existing_value = binding
        value_node = getter if getter_state is True else None
        if getter_state is None and existing_value is not None:
            value_node = existing_value
            existing_sources = binding[0]
        self._assign_member_name(
            object_path,
            property_name,
            frozenset() if getter_state is not None else existing_sources,
            value_node,
        )
        self._set_property_metadata(
            object_path,
            property_name,
            "exists",
            frozenset({_PROPERTY_PRESENT}),
            marker_node,
        )
        self._set_property_metadata(
            object_path,
            property_name,
            "kind",
            frozenset({_PROPERTY_ACCESSOR}),
            marker_node,
        )
        for field, state, node in (
            ("getter", getter_state, getter),
            ("setter", setter_state, setter),
        ):
            states = (
                frozenset({_PROPERTY_PRESENT if state else _PROPERTY_ABSENT})
                if state is not None
                else frozenset({_PROPERTY_PRESENT, _PROPERTY_ABSENT})
            )
            self._set_property_metadata(
                object_path,
                property_name,
                field,
                states,
                node if node is not None else marker_node,
            )
        for field, value in (
            ("enumerable", enumerable),
            ("configurable", configurable),
        ):
            states = (
                frozenset({_PROPERTY_TRUE if value else _PROPERTY_FALSE})
                if value is not None
                else frozenset({_PROPERTY_TRUE, _PROPERTY_FALSE})
            )
            self._set_property_metadata(
                object_path,
                property_name,
                field,
                states,
                marker_node,
            )
        if getter_state is True and getter is not None:
            self.accessor_getters.add((getter.start_byte, getter.end_byte))

    def _assign_member_expression(
        self,
        expression,
        sources: frozenset[str],
        value_node=None,
    ) -> None:
        receiver = _unwrap_ts_expression(expression.child_by_field_name("object"))
        property_node = expression.child_by_field_name(
            "property" if expression.type == "member_expression" else "index"
        )
        property_name = self._member_property_name(expression)
        if receiver is None:
            return
        if property_name is None and not self._computed_property_may_be_string(
            property_node
        ):
            return
        alias_targets = self._result_alias_targets(receiver)
        if alias_targets:
            for target_name in alias_targets:
                self._set_property_path(
                    target_name,
                    property_name,
                    sources,
                    value_node,
                    expression,
                    failure_throws=True,
                )
                if self.path_terminated:
                    return
            return
        receiver_name = self._canonical_object_path(receiver)
        if receiver_name is None:
            return
        self._set_property_path(
            receiver_name,
            property_name,
            sources,
            value_node,
            expression,
            failure_throws=True,
        )

    def _ensure_object_identity_path(self, expression) -> str | None:
        """Give an inline object/array a stable heap identity when it escapes."""
        path = self._canonical_object_path(expression)
        if path is not None:
            return path
        value = self._resolve_value_node(expression)
        if value is None or value.type not in {"object", "array"}:
            return None
        path = f"@object:{value.start_byte}:{value.end_byte}"
        if not self._lookup_explicit(path)[0]:
            self._declare(path, frozenset(), value)
            if value.type == "object":
                self._materialize_object_members(path, value)
        self.call_result_targets[(value.start_byte, value.end_byte)] = path
        return path

    def _mark_object_frozen(self, object_path: str, marker_node) -> None:
        self._assign_member_path(
            object_path,
            "%00frozen",
            frozenset(),
            marker_node,
        )

    def _is_definitely_frozen_path(self, object_path: str) -> bool:
        present, binding = self._lookup_explicit(f"{object_path}.%00frozen")
        return bool(present and binding[1] is not None)

    def _result_alias_targets(self, expression) -> frozenset[str]:
        value = self._resolve_value_node(expression)
        if value is None:
            return frozenset()
        return self.call_result_alias_targets.get(
            (value.start_byte, value.end_byte),
            frozenset(),
        )

    def _alias_member_sources(
        self,
        aliases: frozenset[str],
        property_name: str,
    ) -> frozenset[str]:
        sources = frozenset()
        segment = self._heap_property_segment(property_name)
        for alias in aliases:
            present, binding = self._lookup_explicit(f"{alias}.{segment}")
            if present:
                sources |= binding[0]
            wildcard_present, wildcard = self._lookup_explicit(f"{alias}.*")
            if wildcard_present:
                sources |= wildcard[0]
            _, alias_value = self._lookup(alias)
            property_value, object_is_known = self._object_argument_property(
                alias_value,
                property_name,
            )
            if not present and property_value is not None:
                sources |= self._visit_expression(property_value)
            elif not present and not object_is_known:
                sources |= self._lookup(alias)[0]
        return sources

    def _bind_pattern(
        self,
        pattern,
        sources: frozenset[str],
        value_node=None,
        *,
        assign: bool = False,
    ) -> None:
        for name in self._pattern_names(pattern):
            if assign:
                self._assign(name, sources, value_node)
            else:
                self._declare(name, sources, value_node)

    def _materialize_object_members(self, name: str, value_node) -> None:
        """Keep object-literal properties distinct across branch joins."""
        value = _unwrap_ts_expression(value_node)
        if value is not None and value.type == "call_expression":
            returned_target = self._builtin_call_target(value)
            returned_value = _unwrap_ts_expression(returned_target)
            if returned_value is not None and returned_value.type == "object":
                value = returned_value
        if value is None or value.type != "object":
            return
        properties = self.object_property_snapshots.get(
            (value.start_byte, value.end_byte)
        )
        if properties is None:
            # Module-scope literals are not executed by the action interpreter.
            # Keep the old conservative fallback, but isolate it from the live
            # heap so a value expression is never executed twice.
            saved_frames = self._clone_frames()
            saved_terminated = self.path_terminated
            properties = self._evaluate_object_literal(value)
            self.frames = saved_frames
            self.path_terminated = saved_terminated
        for property_name, sources, property_value, getter, property_path in properties:
            if property_path is _NON_STRING_PROPERTY_KEY:
                continue
            if (
                property_name is None
                and property_value is not None
                and property_value.type == "spread_element"
            ):
                spread_value = next(iter(property_value.named_children), None)
                spread_properties = self._object_assign_source_properties(spread_value)
                if spread_properties is None:
                    self._assign_member_name(
                        name,
                        None,
                        sources,
                        property_value,
                    )
                    continue
                for (
                    spread_name,
                    spread_sources,
                    spread_property_value,
                    spread_getter,
                    spread_path,
                ) in spread_properties:
                    if spread_getter is not None:
                        spread_sources, getter_can_complete = self._invoke_function(
                            spread_getter,
                            [],
                            [],
                            invocation_node=property_value,
                            this_target=spread_path,
                        )
                        if not getter_can_complete:
                            self.path_terminated = True
                            return
                    if spread_name is not None:
                        self._record_data_property(
                            name,
                            spread_name,
                            spread_sources,
                            spread_property_value,
                            property_value,
                        )
                    else:
                        self._assign_member_name(
                            name,
                            None,
                            spread_sources,
                            spread_property_value,
                        )
                continue
            if property_name is None:
                self._assign_member_name(name, None, sources, property_value)
                continue
            is_accessor_getter = getter is not None
            is_accessor_setter = bool(
                property_value is not None
                and property_value.type == "method_definition"
                and any(
                    not token.is_named and token.type == "set"
                    for token in property_value.children
                )
            )
            if is_accessor_getter or is_accessor_setter:
                existing_accessor = (
                    self._property_kind_state(name, property_name) == "accessor"
                )
                current_getter_state, current_getter = self._property_accessor_state(
                    name,
                    property_name,
                    "getter",
                )
                current_setter_state, current_setter = self._property_accessor_state(
                    name,
                    property_name,
                    "setter",
                )
                setter = (
                    self._resolve_callable(property_value)
                    if is_accessor_setter
                    else current_setter
                )
                self._record_accessor_property(
                    name,
                    property_name,
                    property_value,
                    getter_state=(
                        True
                        if is_accessor_getter
                        else current_getter_state
                        if existing_accessor
                        else False
                    ),
                    getter=(
                        getter
                        if is_accessor_getter
                        else current_getter
                        if existing_accessor
                        else None
                    ),
                    setter_state=(
                        True
                        if is_accessor_setter
                        else current_setter_state
                        if existing_accessor
                        else False
                    ),
                    setter=(
                        setter
                        if is_accessor_setter
                        else current_setter
                        if existing_accessor
                        else None
                    ),
                    enumerable=True,
                    configurable=True,
                )
                continue
            self._record_data_property(
                name,
                property_name,
                sources,
                property_value,
                property_value,
            )

    def _evaluate_object_literal(self, value) -> list[tuple]:
        """Evaluate an object literal once and retain per-property results."""
        properties: list[tuple] = []
        for child in value.named_children:
            if child.type == "spread_element":
                spread_value = next(iter(child.named_children), None)
                sources = self._visit_expression(spread_value)
                spread_properties = self._object_assign_source_properties(spread_value)
                if spread_properties is None:
                    properties.append((None, sources, child, None, None))
                    continue
                for (
                    property_name,
                    property_sources,
                    property_value,
                    getter,
                    source_path,
                ) in spread_properties:
                    if getter is not None:
                        property_sources, getter_can_complete = self._invoke_function(
                            getter,
                            [],
                            [],
                            invocation_node=child,
                            this_target=source_path,
                        )
                        if not getter_can_complete:
                            self.path_terminated = True
                    properties.append(
                        (
                            property_name,
                            property_sources,
                            spread_value if getter is not None else property_value,
                            None,
                            None,
                        )
                    )
                continue
            getter = None
            key_is_known = True
            if child.type == "shorthand_property_identifier":
                property_name = self._static_property_name(child)
                property_value = child
                sources = self._visit_expression(child)
            elif child.type == "pair":
                key_node = child.child_by_field_name("key")
                if key_node is not None and key_node.type == "computed_property_name":
                    self._visit_expression(key_node)
                    key_is_known, property_name = self._static_computed_property_value(
                        key_node
                    )
                else:
                    property_name = self._static_property_name(key_node)
                    key_is_known = True
                property_value = child.child_by_field_name("value")
                sources = self._visit_expression(property_value)
            elif child.type == "method_definition":
                name_node = child.child_by_field_name("name")
                if name_node is not None and name_node.type == "computed_property_name":
                    self._visit_expression(name_node)
                    key_is_known, property_name = self._static_computed_property_value(
                        name_node
                    )
                else:
                    property_name = self._static_property_name(name_node)
                is_getter = any(
                    not token.is_named and token.type == "get"
                    for token in child.children
                )
                property_value = child
                getter = self._resolve_callable(child) if is_getter else None
                sources = frozenset()
            else:
                continue
            properties.append(
                (
                    property_name,
                    sources,
                    property_value,
                    getter,
                    _NON_STRING_PROPERTY_KEY
                    if key_is_known and property_name is None
                    else None,
                )
            )
        self.object_property_snapshots[(value.start_byte, value.end_byte)] = list(
            properties
        )
        return properties

    def _object_assign_source_properties(
        self,
        source_object,
        *,
        source_value=None,
        source_path: str | None = None,
    ):
        """Return exact enumerable source members, or ``None`` if unknown."""
        if self._expression_is_definitely_string(source_object):
            # String objects expose only numeric character indices and length;
            # they cannot overwrite a SQL/config property such as ``sql``.
            return []
        source_value = source_value or self._resolve_value_node(source_object)
        if source_value is None:
            return None
        if source_value.type == "array":
            return [
                (str(index), self._visit_expression(item), item, None, source_path)
                for index, item in self._array_indexed_elements(source_value)
                if item.type != "spread_element"
            ]
        if source_value.type in {
            "string",
            "number",
            "true",
            "false",
            "null",
            "undefined",
        }:
            return []
        if source_value.type != "object":
            return None
        if source_path is None:
            source_path = self._canonical_object_path(source_object)
        properties = self.object_property_snapshots.get(
            (source_value.start_byte, source_value.end_byte)
        )
        if properties is None:
            saved_frames = self._clone_frames()
            saved_terminated = self.path_terminated
            properties = self._evaluate_object_literal(source_value)
            self.frames = saved_frames
            self.path_terminated = saved_terminated
        expanded: list[tuple] = []
        for property_name, sources, value, getter, property_path in properties:
            if property_path is _NON_STRING_PROPERTY_KEY:
                continue
            if (
                property_name is None
                and value is not None
                and value.type == "spread_element"
            ):
                spread_value = next(iter(value.named_children), None)
                spread_properties = self._object_assign_source_properties(spread_value)
                if spread_properties is not None:
                    expanded.extend(spread_properties)
                    continue
            if source_path is not None and property_name is not None:
                if self._property_exists_state(source_path, property_name) is False:
                    continue
                if (
                    self._property_attribute_state(
                        source_path,
                        property_name,
                        "enumerable",
                    )
                    is False
                ):
                    continue
                segment = self._heap_property_segment(property_name)
                present, binding = self._lookup_explicit(f"{source_path}.{segment}")
                if present:
                    sources, current_value = binding
                    value = current_value
                    getter_state, current_getter = self._property_accessor_state(
                        source_path,
                        property_name,
                        "getter",
                    )
                    getter = current_getter if getter_state is True else None
            expanded.append((property_name, sources, value, getter, source_path))
        if source_path is None:
            source_path = f"@object:{source_value.start_byte}:{source_value.end_byte}"
            self._declare(source_path, frozenset(), source_value)
            self._materialize_object_members(source_path, source_value)
            materialized = []
            for property_name, sources, value, getter, _ in expanded:
                materialized.append(
                    (property_name, sources, value, getter, source_path)
                )
            expanded = materialized
        if source_path is not None:
            represented = {
                "*"
                if property_name is None
                else self._heap_property_segment(property_name)
                for property_name, _, _, _, _ in expanded
            }
            for property_segment, binding in self._visible_own_heap_bindings(
                source_path
            ):
                if property_segment in represented:
                    continue
                represented.add(property_segment)
                sources, current_value = binding
                expanded.append(
                    (
                        None
                        if property_segment == "*"
                        else self._heap_property_name(property_segment),
                        sources,
                        current_value,
                        current_value
                        if getattr(current_value, "start_byte", None) is not None
                        and (current_value.start_byte, current_value.end_byte)
                        in self.accessor_getters
                        else None,
                        source_path,
                    )
                )
        filtered = []
        for property_name, sources, value, getter, property_path in expanded:
            if property_name is not None and source_path is not None:
                if self._property_exists_state(source_path, property_name) is False:
                    continue
                if (
                    self._property_attribute_state(
                        source_path,
                        property_name,
                        "enumerable",
                    )
                    is False
                ):
                    continue
                getter_state, current_getter = self._property_accessor_state(
                    source_path,
                    property_name,
                    "getter",
                )
                if getter_state is True:
                    getter = current_getter
            filtered.append((property_name, sources, value, getter, property_path))
        return self._ecmascript_own_property_order(filtered)

    @staticmethod
    def _ecmascript_own_property_order(properties: list[tuple]) -> list[tuple]:
        """Order string keys like OrdinaryOwnPropertyKeys/Object.assign."""

        def array_index(property_name: str | None) -> int | None:
            if property_name is None or not re.fullmatch(
                r"0|[1-9][0-9]*", property_name
            ):
                return None
            value = int(property_name, 10)
            return value if value < 2**32 - 1 else None

        indexed: list[tuple[int, int, tuple]] = []
        strings: list[tuple] = []
        for insertion_order, property_summary in enumerate(properties):
            index = array_index(property_summary[0])
            if index is None:
                strings.append(property_summary)
            else:
                indexed.append((index, insertion_order, property_summary))
        indexed.sort(key=lambda item: (item[0], item[1]))
        return [summary for _, _, summary in indexed] + strings

    @staticmethod
    def _array_indexed_elements(array_node) -> list[tuple[int, object]]:
        """Return array elements with holes retained in their real indices."""
        index = 0
        elements: list[tuple[int, object]] = []
        for child in array_node.children:
            if not child.is_named:
                if child.type == ",":
                    index += 1
                continue
            elements.append((index, child))
        return elements

    def _expand_static_call_argument_spreads(self, arguments: list) -> list:
        """Flatten direct dense array spreads without evaluating elements twice."""
        expanded = []
        for argument in arguments:
            if argument.type != "spread_element":
                expanded.append(argument)
                continue
            spread_value = _unwrap_ts_expression(
                next(iter(argument.named_children), None)
            )
            if spread_value is None or spread_value.type != "array":
                expanded.append(argument)
                continue
            indexed_elements = self._array_indexed_elements(spread_value)
            if [index for index, _ in indexed_elements] != list(
                range(len(indexed_elements))
            ):
                expanded.append(argument)
                continue
            expanded.extend(element for _, element in indexed_elements)
        return expanded

    def _visible_own_heap_bindings(
        self,
        object_path: str,
    ) -> list[tuple[str, tuple[frozenset[str], object | None]]]:
        """Return visible direct own members added after literal creation."""
        prefix = f"{object_path}."
        visible: dict[str, tuple[frozenset[str], object | None]] = {}
        for frame in reversed(self.frames):
            for binding_name, binding in frame.items():
                if not binding_name.startswith(prefix):
                    continue
                property_segment = binding_name[len(prefix) :]
                if (
                    "." in property_segment
                    or property_segment.startswith("%00")
                    or property_segment in visible
                ):
                    continue
                visible[property_segment] = binding

        def write_order(item) -> tuple[int, str]:
            property_segment, (_, value) = item
            return (
                getattr(value, "start_byte", -1),
                property_segment,
            )

        return sorted(visible.items(), key=write_order)

    def _expression_is_definitely_string(
        self,
        expression,
        *,
        seen: frozenset[str] = frozenset(),
    ) -> bool:
        node = _unwrap_ts_expression(expression)
        if node is None:
            return False
        if node.type in {"string", "template_string"}:
            return True
        if node.type == "binary_expression" and any(
            not child.is_named and child.type == "+" for child in node.children
        ):
            return self._expression_is_definitely_string(
                node.child_by_field_name("left"),
                seen=seen,
            ) or self._expression_is_definitely_string(
                node.child_by_field_name("right"),
                seen=seen,
            )
        if node.type != "identifier":
            return False
        name = _get_text(self.source, node)
        if name in seen:
            return False
        _, value = self._lookup(name)
        resolved = _unwrap_ts_expression(value)
        if resolved is not None and not (
            resolved.type == "identifier" and _get_text(self.source, resolved) == name
        ):
            return self._expression_is_definitely_string(
                resolved,
                seen=seen | {name},
            )
        # TypeScript annotations are erased and Server Action arguments cross
        # an untrusted runtime boundary. They cannot prove Object.assign sees
        # a primitive string rather than a boxed/object-like value.
        return False

    def _project_function_exit_versions(
        self,
        saved_frames: list[dict],
        exit_versions: list[list[dict]],
        parameter_targets: dict[str, str],
        parameter_values: dict[str, object],
        invocation_node,
    ) -> list[list[dict]]:
        """Project callee heap writes onto each reachable caller exit."""
        effects_by_exit: list[
            dict[tuple[str, str], tuple[frozenset[str], object | None]]
        ] = []
        propagated_targets = (
            set(parameter_targets.values())
            | set(self.module_values)
            | set(self.import_identities)
            | {"Object", "Reflect"}
        )
        for exit_version in exit_versions:
            self.frames = [dict(frame) for frame in exit_version]
            member_effects: dict[
                tuple[str, str], tuple[frozenset[str], object | None]
            ] = {}
            for index, saved_frame in enumerate(saved_frames):
                if index >= len(self.frames):
                    break
                invoked_frame = self.frames[index]
                for member_name, binding in invoked_frame.items():
                    if "." not in member_name:
                        continue
                    previous = saved_frame.get(member_name)
                    if previous is not None and (
                        previous[0] == binding[0]
                        and self._same_value_node(previous[1], binding[1])
                    ):
                        continue
                    receiver_name, property_name = member_name.split(".", 1)
                    member_effects[(receiver_name, property_name)] = binding

            def parameter_still_aliases_target(
                parameter_name: str,
                target_name: str,
            ) -> bool:
                for current_frame in reversed(self.frames):
                    if parameter_name not in current_frame:
                        continue
                    value = _unwrap_ts_expression(current_frame[parameter_name][1])
                    if value is None:
                        return False
                    original_value = _unwrap_ts_expression(
                        parameter_values.get(parameter_name)
                    )
                    if original_value is not None and self._same_value_node(
                        value,
                        original_value,
                    ):
                        return True
                    resolved = self._canonical_object_path(value)
                    return resolved == target_name
                return False

            for frame in self.frames[len(saved_frames) :]:
                for member_name, binding in frame.items():
                    if "." not in member_name:
                        continue
                    receiver_name, property_name = member_name.split(".", 1)
                    target_name = parameter_targets.get(receiver_name, receiver_name)
                    if target_name not in propagated_targets:
                        continue
                    if receiver_name in parameter_targets and not (
                        parameter_still_aliases_target(receiver_name, target_name)
                    ):
                        continue
                    if receiver_name in set(parameter_targets.values()) and not any(
                        parameter_still_aliases_target(parameter_name, receiver_name)
                        for parameter_name, parameter_target in parameter_targets.items()
                        if parameter_target == receiver_name
                    ):
                        continue
                    member_effects[(target_name, property_name)] = binding

            effects_by_exit.append(member_effects)

        definite_effects = (
            set.intersection(*(set(effects) for effects in effects_by_exit))
            if effects_by_exit
            else set()
        )
        projected: list[list[dict]] = []
        for member_effects in effects_by_exit:
            self.frames = [dict(frame) for frame in saved_frames]
            for (receiver_name, property_path), (
                sources,
                value_node,
            ) in member_effects.items():
                resolved_value = _unwrap_ts_expression(value_node)
                if resolved_value is not None and resolved_value.type == "identifier":
                    resolved_value = parameter_values.get(
                        _get_text(self.source, resolved_value),
                        value_node,
                    )
                else:
                    resolved_value = value_node
                if (
                    not sources
                    and value_node is not None
                    and property_path.rsplit(".", 1)[-1] != "*"
                    and invocation_node is not None
                    and (receiver_name, property_path) in definite_effects
                ):
                    full_path = f"{receiver_name}.{property_path}"
                    parts = full_path.split(".")
                    has_earlier_wildcard = any(
                        self._lookup_explicit(f"{'.'.join(parts[:end])}.*")[0]
                        for end in range(1, len(parts))
                    )
                    if has_earlier_wildcard:
                        resolved_value = invocation_node
                self._assign_member_path(
                    receiver_name,
                    property_path,
                    sources,
                    resolved_value,
                )
            projected.append(self._clone_frames())
        return projected

    def _append_exception_version(
        self,
        version: list[dict],
        reason_sources: frozenset[str] | None = None,
    ) -> None:
        if not self.exception_state_collectors:
            return
        frame_depth, versions, reasons = self.exception_state_collectors[-1]
        candidate = [dict(frame) for frame in version[:frame_depth]]
        for index, existing in enumerate(versions):
            if self._same_frame_version(existing, candidate):
                reasons[index]["sources"] |= (
                    self._all_visible_sources()
                    if reason_sources is None
                    else reason_sources
                )
                reasons[index]["unknown"] |= reason_sources is None
                return
        if len(versions) >= 256:
            self.analysis_complete = False
            if "D281 exception-state budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 exception-state budget exhausted")
            return
        versions.append(candidate)
        reasons.append(
            {
                "sources": (
                    self._all_visible_sources()
                    if reason_sources is None
                    else reason_sources
                ),
                "unknown": reason_sources is None,
            }
        )

    @staticmethod
    def _translate_return_alias(
        alias: str | None,
        parameter_targets: dict[str, str],
    ) -> str | None:
        if alias is None:
            return None
        for parameter_name, target_name in sorted(
            parameter_targets.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            if alias == parameter_name:
                return target_name
            if alias.startswith(f"{parameter_name}."):
                return f"{target_name}{alias[len(parameter_name) :]}"
        return alias

    def _suspension_bindings(
        self,
        saved_frames: list[dict],
        versions: list[list[dict]],
    ) -> dict:
        """Merge callee-owned bindings captured at an async suspension."""
        local_versions: list[dict] = []
        for version in versions:
            bindings: dict = {}
            for frame in version[len(saved_frames) :]:
                bindings.update(frame)
            local_versions.append(bindings)
        if not local_versions:
            return {}
        merged: dict = {}
        names = set().union(*(set(version) for version in local_versions))
        for name in names:
            bindings = [version[name] for version in local_versions if name in version]
            sources = frozenset().union(*(binding[0] for binding in bindings))
            value = bindings[0][1]
            if len(bindings) != len(local_versions) or any(
                not self._same_value_node(value, binding[1]) for binding in bindings[1:]
            ):
                value = None
            merged[name] = (sources, value)
        return merged

    def _invoke_function(
        self,
        function,
        argument_sources: list[frozenset[str]],
        argument_values: list | None = None,
        *,
        reset_scope: bool = False,
        invocation_node=None,
        argument_targets: list[str | None] | None = None,
        async_boundary: bool = False,
        stop_at_await: bool = False,
        stop_at_yield: bool = False,
        this_target: str | None = None,
        resume_after_byte: int | None = None,
        resume_bindings: dict | None = None,
        invocation_outcome: dict | None = None,
        project_async_exceptions: bool = True,
    ) -> tuple[frozenset[str], bool]:
        key = (function.start_byte, function.end_byte)
        if stop_at_await:
            self.last_suspension_end.pop(key, None)
            self.last_suspension_promise.pop(key, None)
        if len(self.call_stack) >= self._MAX_CALL_DEPTH or key in self.call_stack:
            self.analysis_complete = False
            if "D281 call-depth limit reached" not in self.diagnostics:
                self.diagnostics.append("D281 call-depth limit reached")
            fallback_sources = (
                frozenset().union(*argument_sources)
                if argument_sources
                else frozenset()
            )
            saved_frames = self.frames
            self.frames = [dict(frame) for frame in saved_frames]
            self.frames.append({})
            for pattern in self._function_parameter_patterns(function):
                self._bind_parameter_pattern(
                    pattern,
                    fallback_sources,
                    None,
                )
            body = function.child_by_field_name("body")
            if body is not None:
                self._scan_depth_limited_subtree(body)
            self.frames = saved_frames
            return fallback_sources, True

        saved_frames = self.frames
        saved_path_terminated = self.path_terminated
        self.path_terminated = False
        values = argument_values or []
        resolved_values = [self._resolve_value_node(value) or value for value in values]
        targets = argument_targets or []
        parameter_targets: dict[str, str] = {}
        parameter_values: dict[str, object] = {}
        if not reset_scope:
            for index, pattern in enumerate(
                self._function_parameter_patterns(function)
            ):
                if index >= len(values):
                    continue
                value = _unwrap_ts_expression(resolved_values[index])
                for parameter_name in self._pattern_names(pattern):
                    parameter_values[parameter_name] = resolved_values[index]
                target_name = targets[index] if index < len(targets) else None
                if target_name is None and value is not None:
                    target_name = self._canonical_object_path(value)
                if target_name is None:
                    continue
                for parameter_name in self._pattern_names(pattern):
                    parameter_targets[parameter_name] = target_name
        self.frames = (
            [
                {
                    **{name: (frozenset(), None) for name in self.import_identities},
                    **{
                        name: (frozenset(), value)
                        for name, value in self.module_values.items()
                    },
                    **self.module_heap_values,
                }
            ]
            if reset_scope
            else [dict(frame) for frame in saved_frames]
        )
        self.frames.append({})
        parameter_patterns = self._function_parameter_patterns(function)
        if reset_scope:
            for pattern in parameter_patterns:
                for name in self._pattern_names(pattern):
                    self._declare(name, frozenset({name}))
        else:
            for index, pattern in enumerate(parameter_patterns):
                sources = (
                    argument_sources[index]
                    if index < len(argument_sources)
                    else frozenset()
                )
                value = resolved_values[index] if index < len(resolved_values) else None
                self._bind_parameter_pattern(pattern, sources, value)
        if resume_bindings:
            # A suspended async invocation owns its scalar parameters and
            # pre-await locals, while closed-over outer frames remain live and
            # are supplied by the resuming caller.
            self.frames[-1].update(
                {
                    name: (sources, value)
                    for name, (sources, value) in resume_bindings.items()
                }
            )

        alias_overrides = dict(parameter_targets)
        if this_target is not None:
            alias_overrides["this"] = this_target
        self.object_alias_overrides.append(alias_overrides)
        self.call_stack.add(key)
        self.function_context_stack.append(key)
        self.function_node_stack.append(function)
        self.return_sources.append(frozenset())
        function_return_versions: list[list[dict]] = []
        function_return_aliases: list[str | None] = []
        function_return_values: list[dict] = []
        function_exception_versions: list[list[dict]] = []
        function_exception_reasons: list[dict] = []
        suspension_versions: list[list[dict]] = []
        self.return_state_collectors.append(
            (len(self.frames), key, function_return_versions)
        )
        self.return_alias_collectors.append((key, function_return_aliases))
        self.return_value_collectors.append((key, function_return_values))
        self.exception_state_collectors.append(
            (
                len(self.frames),
                function_exception_versions,
                function_exception_reasons,
            )
        )
        suspension_kind = (
            "await" if stop_at_await else ("yield" if stop_at_yield else "")
        )
        if suspension_kind:
            self.suspension_state_collectors.append(
                (key, suspension_kind, suspension_versions)
            )
        body = function.child_by_field_name("body")
        expression_body = bool(body is not None and body.type != "statement_block")
        if body is not None:
            if not expression_body:
                self._visit_block(body, skip_through_byte=resume_after_byte)
            else:
                expression_sources = self._visit_expression(body)
                self.return_sources[-1] |= expression_sources
                if not self.path_terminated:
                    function_return_aliases.append(self._canonical_object_path(body))
                    self._record_return_value(body, expression_sources)
        if suspension_kind:
            self.suspension_state_collectors.pop()
        self.exception_state_collectors.pop()
        normal_exit_versions = list(function_return_versions)
        if not self.path_terminated:
            normal_exit_versions.append(self._clone_frames())
            if not expression_body:
                function_return_aliases.append(None)
                function_return_values.append(
                    {"sources": frozenset(), "promise_key": None}
                )
        raw_normal_exit_versions = [
            [dict(frame) for frame in version] for version in normal_exit_versions
        ]
        raw_exception_versions = [
            [dict(frame) for frame in version]
            for version in function_exception_versions
        ]
        raw_exception_reasons = [
            {"sources": reason["sources"], "unknown": reason["unknown"]}
            for reason in function_exception_reasons
        ]
        raw_suspension_versions = [
            [dict(frame) for frame in version] for version in suspension_versions
        ]
        normal_exit_versions.extend(suspension_versions)
        if async_boundary and project_async_exceptions:
            # Calling an async function always returns a Promise. Synchronous
            # throws reject it, and reaching the first await schedules the
            # continuation; neither completion is thrown into the caller.
            normal_exit_versions.extend(function_exception_versions)
        can_complete_normally = bool(normal_exit_versions)
        self.return_state_collectors.pop()
        self.return_alias_collectors.pop()
        self.return_value_collectors.pop()
        result = self.return_sources.pop()
        if invocation_outcome is not None:
            invocation_outcome.update(
                {
                    "return_sources": result,
                    "return_values": list(function_return_values),
                    "normal_versions": raw_normal_exit_versions,
                    "exception_versions": raw_exception_versions,
                    "exception_reasons": raw_exception_reasons,
                    "suspension_versions": raw_suspension_versions,
                    "suspension_end": self.last_suspension_end.get(key),
                    "suspension_promise": self.last_suspension_promise.get(key),
                    "resume_bindings": self._suspension_bindings(
                        saved_frames,
                        raw_suspension_versions,
                    ),
                    "parameter_targets": dict(parameter_targets),
                    "parameter_values": dict(parameter_values),
                }
            )
        self.function_node_stack.pop()
        self.function_context_stack.pop()
        self.call_stack.remove(key)
        projected_exit_versions = (
            self._project_function_exit_versions(
                saved_frames,
                normal_exit_versions,
                parameter_targets,
                parameter_values,
                invocation_node,
            )
            if not reset_scope
            else []
        )
        projected_exception_versions = (
            self._project_function_exit_versions(
                saved_frames,
                function_exception_versions,
                parameter_targets,
                parameter_values,
                invocation_node,
            )
            if not reset_scope
            else []
        )

        if (
            invocation_node is not None
            and not async_boundary
            and normal_exit_versions
            and function_return_aliases
            and all(alias is not None for alias in function_return_aliases)
        ):
            active_targets = {
                parameter_name: target_name
                for parameter_name, target_name in parameter_targets.items()
                if self.object_alias_overrides[-1].get(parameter_name) == target_name
            }
            translated_aliases = {
                self._translate_return_alias(alias, active_targets)
                for alias in function_return_aliases
            }
            concrete_aliases = frozenset(
                alias for alias in translated_aliases if alias is not None
            )
            if concrete_aliases:
                self.call_result_alias_targets[
                    (invocation_node.start_byte, invocation_node.end_byte)
                ] = concrete_aliases
            if len(translated_aliases) == 1:
                returned_target = translated_aliases.pop()
                if returned_target is not None:
                    self.call_result_targets[
                        (invocation_node.start_byte, invocation_node.end_byte)
                    ] = returned_target

        self.object_alias_overrides.pop()

        live_projected_versions = [
            *projected_exit_versions,
            *(projected_exception_versions if async_boundary else []),
        ]
        self.frames = (
            self._merge_frame_versions(saved_frames, live_projected_versions)
            if live_projected_versions
            else saved_frames
        )
        for index, version in enumerate(
            projected_exception_versions if not async_boundary else []
        ):
            reason = (
                raw_exception_reasons[index]
                if index < len(raw_exception_reasons)
                else {"sources": frozenset(), "unknown": True}
            )
            self._append_exception_version(
                version,
                None if reason["unknown"] else reason["sources"],
            )
        self.path_terminated = saved_path_terminated
        return result, can_complete_normally

    def _visit_block(self, block, *, skip_through_byte: int | None = None) -> None:
        if not self._consume():
            return
        self.frames.append({})
        for statement in block.named_children:
            if statement.type in _TS_FUNCTION_NODE_TYPES:
                name_node = statement.child_by_field_name("name")
                if name_node is not None:
                    self._declare(
                        _get_text(self.source, name_node), frozenset(), statement
                    )
            elif statement.type == "class_declaration":
                name_node = statement.child_by_field_name("name")
                if name_node is not None:
                    self._declare(
                        _get_text(self.source, name_node), frozenset(), statement
                    )
        for statement in block.named_children:
            if (
                skip_through_byte is not None
                and statement.end_byte <= skip_through_byte
            ):
                continue
            self._visit_statement(statement)
            if self.path_terminated or self.remaining_work <= 0:
                break
        if (
            self.promise_root_action_key is not None
            and self.function_context_stack
            and self.function_context_stack[-1] == self.promise_root_action_key
            and self.function_node_stack
            and (root_body := self.function_node_stack[-1].child_by_field_name("body"))
            is not None
            and block.start_byte == root_body.start_byte
            and block.end_byte == root_body.end_byte
        ):
            # Unawaited jobs run after the synchronous action body, but their
            # closures still own this lexical environment. Drain before the
            # block frame is discarded so deferred sinks read final bindings.
            self._drain_ready_promise_jobs()
        self.frames.pop()

    def _all_visible_sources(self) -> frozenset[str]:
        sources = frozenset()
        for frame in self.frames:
            for binding_sources, _ in frame.values():
                sources |= frozenset(
                    source
                    for source in binding_sources
                    if not source.startswith(_PROPERTY_STATE_PREFIX)
                )
        return sources

    def _mark_depth_limit(self) -> None:
        self.analysis_complete = False
        if "D281 traversal-depth limit reached" not in self.diagnostics:
            self.diagnostics.append("D281 traversal-depth limit reached")

    def _scan_depth_limited_subtree(self, root) -> None:
        stack = [root] if root is not None else []
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            node = stack.pop()
            if node.type == "call_expression":
                candidate = _server_action_sql_candidate(node, self.source)
                if candidate is not None:
                    self._check_sql_sink(node, candidate)
            stack.extend(reversed(node.named_children))
        if stack and "D281 depth-fallback budget exhausted" not in self.diagnostics:
            self.diagnostics.append("D281 depth-fallback budget exhausted")

    def _visit_switch_path_statement(self, statement) -> str:
        """Visit one switch-path statement and report abrupt completion."""
        if statement.type == "break_statement":
            if statement.child_by_field_name("label") is not None:
                self._visit_statement(statement)
                return "terminated"
            return "break"
        if statement.type == "continue_statement":
            self._visit_statement(statement)
            return "terminated"
        if statement.type == "statement_block":
            self.frames.append({})
            status = "normal"
            for child in statement.named_children:
                status = self._visit_switch_path_statement(child)
                if status != "normal" or self.remaining_work <= 0:
                    break
            self.frames.pop()
            return status

        self.path_terminated = False
        self._visit_statement(statement)
        return "terminated" if self.path_terminated else "normal"

    def _visit_switch(self, node) -> None:
        discriminant = node.child_by_field_name("value")
        self._visit_expression(discriminant)
        if self.path_terminated:
            return
        body = node.child_by_field_name("body")
        clauses = list(body.named_children) if body is not None else []
        base = self._clone_frames()
        continuing_versions = []
        promise_entry_versions: list[tuple[set[tuple[int, int]], bool]] = []
        has_default = any(clause.type == "switch_default" for clause in clauses)
        discriminant_known, discriminant_value = self._static_switch_primitive(
            discriminant
        )

        # JavaScript evaluates case tests in source order until one matches.
        # Preserve those prefix side effects for each possible selected entry;
        # the default/no-match path observes every case test.
        case_entry_versions: dict[int, list[dict]] = {}
        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        case_tests_complete = True
        definite_match = False
        for clause_index, clause in enumerate(clauses):
            if clause.type == "switch_default":
                continue
            case_value_node = clause.child_by_field_name("value")
            self._visit_expression(case_value_node)
            if self.path_terminated:
                case_tests_complete = False
                break
            case_known, case_value = self._static_switch_primitive(case_value_node)
            if discriminant_known and case_known:
                if discriminant_value != case_value:
                    continue
                case_entry_versions[clause_index] = self._clone_frames()
                definite_match = True
                case_tests_complete = False
                break
            case_entry_versions[clause_index] = self._clone_frames()
        no_match_version = (
            self._clone_frames() if case_tests_complete and not definite_match else None
        )

        # Each clause can be the selected entry. From there JavaScript executes
        # sequentially until an abrupt completion, so model fallthrough instead
        # of treating cases as independent branches.
        for entry_index, entry_clause in enumerate(clauses):
            entry_version = (
                no_match_version
                if entry_clause.type == "switch_default"
                else case_entry_versions.get(entry_index)
            )
            if entry_version is None:
                continue
            before_entry_promise_keys = set(self.promise_summaries)
            self.frames = [dict(frame) for frame in entry_version]
            self.frames.append({})  # switch-wide lexical scope
            self.path_terminated = False
            nested_break_versions: list[list[dict]] = []
            self.switch_break_collectors.append(
                (self.loop_depth, nested_break_versions)
            )
            status = "normal"
            for clause in clauses[entry_index:]:
                for child_index, child in enumerate(clause.children):
                    if clause.field_name_for_child(child_index) != "body":
                        continue
                    status = self._visit_switch_path_statement(child)
                    if status != "normal" or self.remaining_work <= 0:
                        break
                if status != "normal" or self.remaining_work <= 0:
                    break

            self.switch_break_collectors.pop()
            for break_version in nested_break_versions:
                continuing_versions.append(
                    [dict(frame) for frame in break_version[:-1]]
                )

            if status in {"normal", "break"}:
                self.frames.pop()
                continuing_versions.append(self._clone_frames())
            entry_continues = bool(nested_break_versions) or status in {
                "normal",
                "break",
            }
            promise_entry_versions.append(
                (
                    set(self.promise_summaries) - before_entry_promise_keys,
                    entry_continues,
                )
            )

        if not has_default and no_match_version is not None:
            continuing_versions.append(no_match_version)

        for keys, continues in promise_entry_versions:
            mode = (
                "merge"
                if continues and len(continuing_versions) > 1
                else "strong"
                if continues
                else "none"
            )
            self._tag_promise_branch_keys(keys, mode, node.end_byte)

        if continuing_versions:
            self.frames = self._merge_frame_versions(base, continuing_versions)
            self.path_terminated = False
        else:
            self.frames = base
            self.path_terminated = True

    def _visit_labeled_statement(self, node) -> None:
        label_node = node.child_by_field_name("label")
        body = node.child_by_field_name("body")
        if label_node is None or body is None:
            for child in node.named_children:
                self._visit_statement(child)
            return

        label = _get_text(self.source, label_node)
        base = self._clone_frames()
        break_versions: list[list[dict]] = []
        continue_versions: list[list[dict]] | None = None
        labelled_body = body
        while labelled_body.type == "labeled_statement":
            nested_body = labelled_body.child_by_field_name("body")
            if nested_body is None:
                break
            labelled_body = nested_body
        loop_key = (labelled_body.start_byte, labelled_body.end_byte)
        owns_continue_versions = False
        if labelled_body.type in {
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
        }:
            continue_versions = self.labelled_loop_continues.get(loop_key)
            if continue_versions is None:
                continue_versions = []
                self.labelled_loop_continues[loop_key] = continue_versions
                owns_continue_versions = True
            self.label_continue_collectors.append((label, continue_versions))
        self.label_break_collectors.append((label, break_versions))
        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        self._visit_statement(body)
        self.label_break_collectors.pop()
        if continue_versions is not None:
            self.label_continue_collectors.pop()
            if owns_continue_versions:
                self.labelled_loop_continues.pop(loop_key, None)

        continuing_versions = list(break_versions)
        if not self.path_terminated:
            continuing_versions.append(self._clone_frames())
        if continuing_versions:
            self.frames = self._merge_frame_versions(base, continuing_versions)
            self.path_terminated = False
        else:
            self.frames = base
            self.path_terminated = True

    def _record_possible_exception(
        self,
        reason_sources: frozenset[str] | None = None,
    ) -> None:
        if not self.exception_state_collectors:
            return
        frame_depth, versions, reasons = self.exception_state_collectors[-1]
        if len(versions) >= 256:
            self.analysis_complete = False
            if "D281 exception-state budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 exception-state budget exhausted")
            return
        candidate = [dict(frame) for frame in self.frames[:frame_depth]]
        for index, version in enumerate(versions):
            if self._same_frame_version(version, candidate):
                reasons[index]["sources"] |= (
                    self._all_visible_sources()
                    if reason_sources is None
                    else reason_sources
                )
                reasons[index]["unknown"] |= reason_sources is None
                return
        versions.append(candidate)
        reasons.append(
            {
                "sources": (
                    self._all_visible_sources()
                    if reason_sources is None
                    else reason_sources
                ),
                "unknown": reason_sources is None,
            }
        )

    def _emit_abrupt_state(
        self,
        target_versions: list[list[dict]],
        version: list[dict] | None = None,
    ) -> None:
        """Route break/continue state through each enclosing `finally` first."""
        state = self._clone_frames() if version is None else version
        if self.finally_abrupt_collectors:
            external_targets, pending = self.finally_abrupt_collectors[-1]
            if id(target_versions) in external_targets:
                if len(pending) >= 256:
                    self.analysis_complete = False
                    if "D281 abrupt-state budget exhausted" not in self.diagnostics:
                        self.diagnostics.append("D281 abrupt-state budget exhausted")
                    return
                candidate = [dict(frame) for frame in state]
                if any(
                    target is target_versions
                    and self._same_frame_version(existing, candidate)
                    for target, existing in pending
                ):
                    return
                pending.append((target_versions, candidate))
                return
        if len(target_versions) >= 256:
            self.analysis_complete = False
            if "D281 abrupt-state budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 abrupt-state budget exhausted")
            return
        candidate = [dict(frame) for frame in state]
        if any(
            self._same_frame_version(version, candidate) for version in target_versions
        ):
            return
        target_versions.append(candidate)

    def _record_return_state(self) -> None:
        if not self.return_state_collectors or not self.function_context_stack:
            return
        frame_depth, function_key, versions = self.return_state_collectors[-1]
        if function_key != self.function_context_stack[-1]:
            return
        if len(versions) >= 256:
            self.analysis_complete = False
            if "D281 return-state budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 return-state budget exhausted")
            return
        candidate = [dict(frame) for frame in self.frames[:frame_depth]]
        if any(self._same_frame_version(version, candidate) for version in versions):
            return
        versions.append(candidate)

    def _record_return_alias(self, value) -> None:
        if not self.return_alias_collectors or not self.function_context_stack:
            return
        function_key, aliases = self.return_alias_collectors[-1]
        if function_key != self.function_context_stack[-1]:
            return
        aliases.append(self._canonical_object_path(value))

    def _record_return_value(
        self,
        value,
        sources: frozenset[str],
    ) -> None:
        if not self.return_value_collectors or not self.function_context_stack:
            return
        function_key, values = self.return_value_collectors[-1]
        if function_key != self.function_context_stack[-1]:
            return
        values.append(
            {
                "sources": sources,
                "promise_key": self._promise_result_key(value),
            }
        )

    def _record_suspension_state(self, kind: str, node=None) -> bool:
        if not self.suspension_state_collectors or not self.function_context_stack:
            return False
        function_key, expected_kind, versions = self.suspension_state_collectors[-1]
        if function_key != self.function_context_stack[-1] or expected_kind != kind:
            return False
        if node is not None:
            suspension_end = node.end_byte
            function = (
                self.function_node_stack[-1] if self.function_node_stack else None
            )
            body = (
                function.child_by_field_name("body") if function is not None else None
            )
            statement = node
            while statement.parent is not None and statement.parent != body:
                statement = statement.parent
            if statement.parent == body:
                suspension_end = statement.end_byte
                if statement.type != "expression_statement":
                    self.analysis_complete = False
                    diagnostic = f"D281 complex {kind} continuation is conservative"
                    if diagnostic not in self.diagnostics:
                        self.diagnostics.append(diagnostic)
            self.last_suspension_end[function_key] = suspension_end
        candidate = self._clone_frames()
        if not any(
            self._same_frame_version(version, candidate) for version in versions
        ):
            if len(versions) >= 256:
                self.analysis_complete = False
                if "D281 suspension-state budget exhausted" not in self.diagnostics:
                    self.diagnostics.append("D281 suspension-state budget exhausted")
            else:
                versions.append(candidate)
        self.path_terminated = True
        return True

    def _visit_try(self, node) -> None:
        body = node.child_by_field_name("body")
        handler = node.child_by_field_name("handler")
        finalizer = node.child_by_field_name("finalizer")
        if handler is None:
            handler = next(
                (
                    child
                    for child in node.named_children
                    if child.type == "catch_clause"
                ),
                None,
            )

        base = self._clone_frames()
        return_sources_before = (
            self.return_sources[-1] if self.return_sources else frozenset()
        )
        return_alias_count = (
            len(self.return_alias_collectors[-1][1])
            if self.return_alias_collectors
            else 0
        )
        return_value_count = (
            len(self.return_value_collectors[-1][1])
            if self.return_value_collectors
            else 0
        )
        exceptional_versions: list[list[dict]] = []
        exceptional_reasons: list[dict] = []
        return_versions: list[list[dict]] = []
        external_abrupt_targets = {
            id(versions) for _, versions in self.switch_break_collectors
        }
        external_abrupt_targets.update(
            id(versions) for _, versions in self.label_break_collectors
        )
        external_abrupt_targets.update(
            id(versions) for versions in self.loop_break_collectors
        )
        external_abrupt_targets.update(
            id(versions) for versions in self.loop_continue_collectors
        )
        abrupt_versions: list[tuple[list[list[dict]], list[dict]]] = []
        self.finally_abrupt_collectors.append(
            (external_abrupt_targets, abrupt_versions)
        )
        self.exception_state_collectors.append(
            (len(base), exceptional_versions, exceptional_reasons)
        )
        function_key = (
            self.function_context_stack[-1] if self.function_context_stack else (-1, -1)
        )
        self.return_state_collectors.append((len(base), function_key, return_versions))
        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        self._visit_statement(body)
        normal_versions: list[list[dict]] = []
        if not self.path_terminated:
            normal_versions.append(self._clone_frames())
        self.exception_state_collectors.pop()

        continuing_versions = list(normal_versions)
        pending_exception_versions: list[list[dict]] = []
        pending_exception_reasons: list[dict] = []
        if handler is not None:
            # Exceptions thrown by the catch are not handled by this catch,
            # but its finally block must still run before they reach an outer
            # handler. Hold those states locally until finalization.
            handler_exception_versions: list[list[dict]] = []
            handler_exception_reasons: list[dict] = []
            self.exception_state_collectors.append(
                (
                    len(base),
                    handler_exception_versions,
                    handler_exception_reasons,
                )
            )
            for index, exceptional_version in enumerate(exceptional_versions):
                self.frames = [dict(frame) for frame in exceptional_version]
                self.path_terminated = False
                reason = (
                    exceptional_reasons[index]
                    if index < len(exceptional_reasons)
                    else {"sources": frozenset(), "unknown": True}
                )
                self.catch_source_stack.append(
                    reason["sources"] if not reason["unknown"] else frozenset()
                )
                self._visit_statement(handler)
                self.catch_source_stack.pop()
                if not self.path_terminated:
                    continuing_versions.append(self._clone_frames())
            self.exception_state_collectors.pop()
            pending_exception_versions.extend(handler_exception_versions)
            pending_exception_reasons.extend(handler_exception_reasons)
        else:
            pending_exception_versions.extend(exceptional_versions)
            pending_exception_reasons.extend(exceptional_reasons)

        self.finally_abrupt_collectors.pop()
        self.return_state_collectors.pop()
        if self._finally_overrides_completion(finalizer):
            if self.return_sources:
                self.return_sources[-1] = return_sources_before
            if self.return_alias_collectors:
                del self.return_alias_collectors[-1][1][return_alias_count:]
            if self.return_value_collectors:
                del self.return_value_collectors[-1][1][return_value_count:]
        continuing_after_finally: list[list[dict]] = []
        finalized_return_versions: list[list[dict]] = []
        finalized_exception_versions: list[list[dict]] = []
        finalized_exception_reasons: list[dict] = []

        def apply_finalizer(version: list[dict]) -> list[dict] | None:
            self.frames = [dict(frame) for frame in version]
            self.path_terminated = False
            if finalizer is not None:
                self._visit_statement(finalizer)
            return None if self.path_terminated else self._clone_frames()

        for version in continuing_versions:
            finalized = apply_finalizer(version)
            if finalized is not None:
                continuing_after_finally.append(finalized)

        # A finally block runs on both return and throw completions. Only the
        # post-finally heap may flow into an enclosing finally/catch.
        for version in return_versions:
            finalized = apply_finalizer(version)
            if finalized is not None:
                finalized_return_versions.append(finalized)
        for index, version in enumerate(pending_exception_versions):
            finalized = apply_finalizer(version)
            if finalized is not None:
                finalized_exception_versions.append(finalized)
                finalized_exception_reasons.append(
                    pending_exception_reasons[index]
                    if index < len(pending_exception_reasons)
                    else {"sources": frozenset(), "unknown": True}
                )
        for target_versions, version in abrupt_versions:
            finalized = apply_finalizer(version)
            if finalized is not None:
                self._emit_abrupt_state(target_versions, finalized)

        if self.return_state_collectors and finalized_return_versions:
            outer_depth, outer_key, outer_versions = self.return_state_collectors[-1]
            if outer_key == function_key:
                for version in finalized_return_versions:
                    if len(outer_versions) >= 256:
                        self.analysis_complete = False
                        if "D281 return-state budget exhausted" not in self.diagnostics:
                            self.diagnostics.append(
                                "D281 return-state budget exhausted"
                            )
                        break
                    outer_versions.append(
                        [dict(frame) for frame in version[:outer_depth]]
                    )

        if self.exception_state_collectors and finalized_exception_versions:
            for index, version in enumerate(finalized_exception_versions):
                reason = finalized_exception_reasons[index]
                self._append_exception_version(
                    version,
                    None if reason["unknown"] else reason["sources"],
                )

        if continuing_after_finally:
            self.frames = self._merge_frame_versions(
                base,
                continuing_after_finally,
            )
            self.path_terminated = False
        else:
            self.frames = base
            self.path_terminated = True

    def _statement_definitely_abrupt(self, statement) -> bool:
        """Prove that a statement cannot complete normally.

        This intentionally covers only structural cases whose JavaScript
        completion is unambiguous. Unknown conditions and complex control
        flow remain conservative.
        """
        if statement is None:
            return False
        if statement.type in {
            "return_statement",
            "throw_statement",
            "break_statement",
            "continue_statement",
        }:
            return True
        if statement.type == "statement_block":
            return any(
                self._statement_definitely_abrupt(child)
                for child in statement.named_children
            )
        if statement.type == "if_statement":
            condition = statement.child_by_field_name("condition")
            consequence = statement.child_by_field_name("consequence")
            alternative = statement.child_by_field_name("alternative")
            condition_value = self._static_condition_value(condition)
            if condition_value is True:
                return self._statement_definitely_abrupt(consequence)
            if condition_value is False:
                return self._statement_definitely_abrupt(alternative)
            return bool(
                alternative is not None
                and self._statement_definitely_abrupt(consequence)
                and self._statement_definitely_abrupt(alternative)
            )
        if statement.type == "try_statement":
            nested_finalizer = statement.child_by_field_name("finalizer")
            return self._finally_overrides_completion(nested_finalizer)
        return False

    def _finally_overrides_completion(self, finalizer) -> bool:
        if finalizer is None:
            return False
        body = next(iter(finalizer.named_children), None)
        return self._statement_definitely_abrupt(body)

    def _visit_loop_paths(
        self,
        body,
        base: list[dict],
        *,
        include_zero_iteration: bool,
        advancing_may_exit: bool = True,
        post_expressions: tuple = (),
        provided_continue_versions: list[list[dict]] | None = None,
    ) -> None:
        """Merge zero-, normal-, break-, and continue-completion loop states."""
        break_versions: list[list[dict]] = []
        continue_versions = (
            provided_continue_versions if provided_continue_versions is not None else []
        )
        self.loop_break_collectors.append(break_versions)
        self.loop_continue_collectors.append(continue_versions)
        self.loop_depth += 1
        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        try:
            self._visit_statement(body)
            normal_versions = [self._clone_frames()] if not self.path_terminated else []
        finally:
            self.loop_depth -= 1
            self.loop_continue_collectors.pop()
            self.loop_break_collectors.pop()

        exiting_versions = [
            [dict(frame) for frame in version[: len(base)]]
            for version in break_versions
        ]
        advancing_versions = normal_versions + continue_versions
        for version in advancing_versions:
            self.frames = [dict(frame) for frame in version[: len(base)]]
            self.path_terminated = False
            for expression in post_expressions:
                self._visit_expression(expression)
                if self.path_terminated:
                    break
            if not self.path_terminated and advancing_may_exit:
                exiting_versions.append(self._clone_frames())

        if include_zero_iteration:
            exiting_versions.append([dict(frame) for frame in base])
        if exiting_versions:
            self.frames = self._merge_frame_versions(base, exiting_versions)
            self.path_terminated = False
        else:
            self.frames = [dict(frame) for frame in base]
            self.path_terminated = True

    def _visit_statement(self, node) -> None:
        if node is None:
            return
        if self.traversal_depth >= self._MAX_TRAVERSAL_DEPTH:
            self._mark_depth_limit()
            self._scan_depth_limited_subtree(node)
            return
        self.traversal_depth += 1
        try:
            self._visit_statement_inner(node)
        finally:
            self.traversal_depth -= 1

    def _visit_statement_inner(self, node) -> None:
        if node is None or not self._consume():
            return
        node_type = node.type
        if node_type == "break_statement":
            label_node = node.child_by_field_name("label")
            if label_node is not None:
                label = _get_text(self.source, label_node)
                for collector_label, versions in reversed(self.label_break_collectors):
                    if collector_label == label:
                        self._emit_abrupt_state(versions)
                        self.path_terminated = True
                        return
                self.path_terminated = True
                return
            if self.switch_break_collectors:
                switch_loop_depth, versions = self.switch_break_collectors[-1]
                if self.loop_depth == switch_loop_depth:
                    self._emit_abrupt_state(versions)
                    self.path_terminated = True
                    return
            if self.loop_break_collectors:
                self._emit_abrupt_state(self.loop_break_collectors[-1])
            self.path_terminated = True
            return
        if node_type == "continue_statement":
            label_node = node.child_by_field_name("label")
            if label_node is not None:
                label = _get_text(self.source, label_node)
                for collector_label, versions in reversed(
                    self.label_continue_collectors
                ):
                    if collector_label == label:
                        self._emit_abrupt_state(versions)
                        self.path_terminated = True
                        return
                self.analysis_complete = False
                if "D281 labelled-continue target unresolved" not in self.diagnostics:
                    self.diagnostics.append("D281 labelled-continue target unresolved")
            if self.loop_continue_collectors:
                self._emit_abrupt_state(self.loop_continue_collectors[-1])
            self.path_terminated = True
            return
        if node_type == "labeled_statement":
            self._visit_labeled_statement(node)
            return
        if node_type == "statement_block":
            self._visit_block(node)
            return
        if node_type in {"lexical_declaration", "variable_declaration"}:
            self._visit_declaration(node)
            return
        if node_type == "export_statement":
            declaration = node.child_by_field_name("declaration")
            if declaration is not None:
                self._visit_statement(declaration)
            return
        if node_type in _TS_FUNCTION_NODE_TYPES or node_type in {
            "class_declaration",
            "interface_declaration",
            "type_alias_declaration",
        }:
            return
        if node_type in {"expression_statement", "return_statement", "throw_statement"}:
            sources = frozenset()
            return_value = None
            for child in node.named_children:
                sources |= self._visit_expression(child)
                if node_type == "return_statement" and return_value is None:
                    return_value = child
            if (
                node_type == "return_statement"
                and self.return_sources
                and not self.path_terminated
            ):
                self.return_sources[-1] |= sources
                self._record_return_alias(return_value)
                self._record_return_value(return_value, sources)
                self._record_return_state()
            if node_type == "throw_statement":
                self._record_possible_exception(sources)
            if node_type in {"return_statement", "throw_statement"}:
                self.path_terminated = True
            return
        if node_type == "if_statement":
            condition = node.child_by_field_name("condition")
            self._visit_expression(condition)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            self._visit_branches(consequence, alternative)
            return
        if node_type == "switch_statement":
            self._visit_switch(node)
            return
        if node_type == "try_statement":
            self._visit_try(node)
            return
        if node_type == "catch_clause":
            self.frames.append({})
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                self._bind_pattern(
                    parameter,
                    self.catch_source_stack[-1]
                    if self.catch_source_stack
                    else frozenset(),
                )
            body = node.child_by_field_name("body")
            if body is not None:
                self._visit_statement(body)
            self.frames.pop()
            return
        if node_type == "for_in_statement":
            right = node.child_by_field_name("right")
            item_sources = self._visit_expression(right)
            if self.path_terminated:
                return
            generator_invocation = self._generator_invocation_for(right)
            generator_has_value = False
            if generator_invocation is not None:
                generator_key, generator_info = generator_invocation
                (
                    generator_sources,
                    generator_can_complete,
                    generator_has_value,
                ) = self._resume_generator(
                    generator_key,
                    generator_info,
                    right,
                )
                item_sources |= generator_sources
                if not generator_can_complete:
                    self.path_terminated = True
                    return
            right_value = _unwrap_ts_expression(right)
            is_for_of = any(
                not child.is_named and child.type == "of" for child in node.children
            )
            array_text = (
                _get_text(self.source, right_value).strip()
                if right_value is not None and right_value.type == "array"
                else ""
            )
            known_empty = bool(
                is_for_of
                and right_value is not None
                and right_value.type == "array"
                and array_text == "[]"
            )
            known_nonempty = (
                bool(
                    is_for_of
                    and right_value is not None
                    and right_value.type == "array"
                    and all(
                        child.type != "spread_element"
                        for child in right_value.named_children
                    )
                    and (bool(right_value.named_children) or "," in array_text[1:-1])
                )
                or generator_has_value
            )
            if generator_invocation is not None and not generator_has_value:
                return
            if known_empty:
                return
            self.frames.append({})
            left = node.child_by_field_name("left")
            if left is not None and left.type in {
                "lexical_declaration",
                "variable_declaration",
            }:
                self._visit_declaration(left, override_sources=item_sources)
            elif left is not None:
                self._bind_pattern(left, item_sources)
            base = self._clone_frames()
            self._visit_loop_paths(
                node.child_by_field_name("body"),
                base,
                include_zero_iteration=not known_nonempty,
                provided_continue_versions=self.labelled_loop_continues.get(
                    (node.start_byte, node.end_byte)
                ),
            )
            if (
                generator_invocation is not None
                and not self._loop_body_definitely_breaks(
                    node.child_by_field_name("body")
                )
            ):
                generator_key, generator_info = generator_invocation
                for _ in range(64):
                    if generator_info.get("done"):
                        break
                    _, generator_can_complete, _ = self._resume_generator(
                        generator_key,
                        generator_info,
                        right,
                    )
                    if not generator_can_complete:
                        self.path_terminated = True
                        break
                else:
                    self.analysis_complete = False
                    if "D281 generator-resume budget exhausted" not in self.diagnostics:
                        self.diagnostics.append(
                            "D281 generator-resume budget exhausted"
                        )
            self.frames.pop()
            return
        if node_type == "for_statement":
            self.frames.append({})
            initializer = node.child_by_field_name("initializer")
            if initializer is not None:
                self._visit_statement(initializer)
            condition = node.child_by_field_name("condition")
            condition_missing = condition is None or condition.type == "empty_statement"
            if not condition_missing:
                self._visit_expression(condition)
            if self.path_terminated:
                self.frames.pop()
                return
            condition_value = (
                True if condition_missing else self._static_condition_value(condition)
            )
            base = self._clone_frames()
            if condition_value is False:
                self.frames.pop()
                return
            increment = node.child_by_field_name("increment")
            self._visit_loop_paths(
                node.child_by_field_name("body"),
                base,
                include_zero_iteration=condition_value is not True,
                advancing_may_exit=condition_value is not True,
                post_expressions=((increment,) if increment is not None else ()),
                provided_continue_versions=self.labelled_loop_continues.get(
                    (node.start_byte, node.end_byte)
                ),
            )
            self.frames.pop()
            return
        if node_type == "while_statement":
            condition = node.child_by_field_name("condition")
            self._visit_expression(condition)
            if self.path_terminated:
                return
            condition_value = self._static_condition_value(condition)
            base = self._clone_frames()
            if condition_value is False:
                return
            self._visit_loop_paths(
                node.child_by_field_name("body"),
                base,
                include_zero_iteration=condition_value is not True,
                advancing_may_exit=condition_value is not True,
                post_expressions=((condition,) if condition is not None else ()),
                provided_continue_versions=self.labelled_loop_continues.get(
                    (node.start_byte, node.end_byte)
                ),
            )
            return
        if node_type == "do_statement":
            condition = node.child_by_field_name("condition")
            condition_value = self._static_condition_value(condition)
            base = self._clone_frames()
            self._visit_loop_paths(
                node.child_by_field_name("body"),
                base,
                include_zero_iteration=False,
                advancing_may_exit=condition_value is not True,
                post_expressions=((condition,) if condition is not None else ()),
                provided_continue_versions=self.labelled_loop_continues.get(
                    (node.start_byte, node.end_byte)
                ),
            )
            return
        if node_type == "with_statement":
            for child in node.named_children:
                self._visit_statement(child)
            return
        if node_type == "finally_clause":
            body = next(iter(node.named_children), None)
            self._visit_statement(body)
            return
        if node_type.endswith("_statement") or node_type.endswith("_clause"):
            for child in node.named_children:
                self._visit_statement(child)
            return
        self._visit_expression(node)

    def _visit_declaration(
        self,
        declaration,
        *,
        override_sources: frozenset[str] | None = None,
    ) -> None:
        for declarator in declaration.named_children:
            if declarator.type != "variable_declarator":
                continue
            pattern = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            sources = (
                override_sources
                if override_sources is not None
                else self._visit_expression(value)
            )
            self._bind_pattern(pattern, sources, value)
            promise_key = self._promise_result_key(value)
            if promise_key is not None and promise_key in self.promise_summaries:
                self.promise_identity_paths.setdefault(promise_key, set()).update(
                    self._pattern_names(pattern)
                )
            for name, binding_node in self._object_pattern_bindings(pattern):
                self._assign(name, sources, binding_node)
            for name in self._pattern_names(pattern):
                self._materialize_object_members(name, value)
                resolved_value = _unwrap_ts_expression(value)
                if (
                    resolved_value is not None
                    and resolved_value.type == "call_expression"
                    and (resolved_value.start_byte, resolved_value.end_byte)
                    in self.frozen_call_results
                ):
                    self._mark_object_frozen(name, resolved_value)

    def _clone_frames(self):
        return [dict(frame) for frame in self.frames]

    def _frame_effects(
        self,
        before: list[dict],
        after: list[dict],
    ) -> list[dict]:
        """Summarize only bindings changed by a deferred computation."""
        effects: list[dict] = []
        for index in range(min(len(before), len(after))):
            frame_effects: dict = {}
            before_frame = before[index]
            after_frame = after[index]
            for name in before_frame.keys() | after_frame.keys():
                old = before_frame.get(name, _DELETED_BINDING)
                new = after_frame.get(name, _DELETED_BINDING)
                if old is _DELETED_BINDING or new is _DELETED_BINDING:
                    if old is not new:
                        frame_effects[name] = new
                    continue
                if old[0] != new[0] or not self._same_value_node(old[1], new[1]):
                    frame_effects[name] = new
            effects.append(frame_effects)
        return effects

    @staticmethod
    def _apply_frame_effects(frames: list[dict], effects: list[dict]) -> None:
        for frame, frame_effects in zip(frames, effects):
            for name, binding in frame_effects.items():
                if binding is _DELETED_BINDING:
                    frame.pop(name, None)
                else:
                    frame[name] = binding

    def _project_branch_closure_effects(
        self,
        frames: list[dict],
        effects: list[dict],
        mode: str,
    ) -> None:
        """Project a detached branch closure onto its surviving flow."""
        if mode == "none":
            return
        for frame, frame_effects in zip(frames, effects):
            for name, binding in frame_effects.items():
                owner = name.split(".", 1)[0]
                if name not in frame and owner not in frame:
                    # Do not map a popped lexical binding into an unrelated
                    # block that happens to occupy the same frame depth.
                    continue
                if mode == "strong":
                    if binding is _DELETED_BINDING:
                        frame.pop(name, None)
                    else:
                        frame[name] = binding
                    continue
                if binding is _DELETED_BINDING:
                    # Another continuing branch may retain the binding.
                    continue
                current = frame.get(name)
                if current is None:
                    frame[name] = (binding[0], None)
                    continue
                frame[name] = (
                    current[0] | binding[0],
                    current[1]
                    if self._same_value_node(current[1], binding[1])
                    else None,
                )

    def _same_value_node(self, left_value, right_value) -> bool:
        if left_value is right_value:
            return True
        if left_value is None or right_value is None:
            return False
        if (
            left_value.start_byte == right_value.start_byte
            and left_value.end_byte == right_value.end_byte
        ):
            return True
        literal_types = {
            "string",
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
        }
        return bool(
            left_value.type == right_value.type
            and left_value.type
            in literal_types
            | {
                "identifier",
                "shorthand_property_identifier",
            }
            and _get_text(self.source, left_value)
            == _get_text(self.source, right_value)
        )

    def _same_frame_version(self, left: list[dict], right: list[dict]) -> bool:
        if len(left) != len(right):
            return False
        for left_frame, right_frame in zip(left, right):
            if left_frame.keys() != right_frame.keys():
                return False
            for name, (left_sources, left_value) in left_frame.items():
                right_sources, right_value = right_frame[name]
                if left_sources != right_sources or not self._same_value_node(
                    left_value,
                    right_value,
                ):
                    return False
        return True

    def _merge_frame_versions(self, base, versions):
        merged: list[dict[str, tuple[frozenset[str], object | None]]] = []
        for index, base_frame in enumerate(base):
            branch_frames = [
                version[index] if index < len(version) else base_frame
                for version in versions
            ]
            frame: dict[str, tuple[frozenset[str], object | None]] = {}
            names = set(base_frame)
            for branch_frame in branch_frames:
                names.update(branch_frame)
            for name in names:
                bindings = [
                    branch_frame.get(
                        name,
                        base_frame.get(name, (frozenset(), None)),
                    )
                    for branch_frame in branch_frames
                ]
                sources = frozenset().union(*(binding[0] for binding in bindings))
                value = bindings[0][1]
                if not all(
                    self._same_value_node(value, binding[1]) for binding in bindings[1:]
                ):
                    value = None
                    candidates = [
                        binding[1] for binding in bindings if binding[1] is not None
                    ]
                    scopes = {
                        self._enclosing_function_key(candidate)
                        for candidate in candidates
                    }
                    if candidates and len(scopes) == 1:
                        if name.endswith(".*"):
                            # A wildcard write on any branch remains possible.
                            value = max(
                                candidates,
                                key=lambda candidate: candidate.start_byte,
                            )
                        elif "." in name and len(candidates) == len(bindings):
                            # Every branch wrote this exact member. Retain the
                            # earliest write solely as an ordering lower bound
                            # so it can mask an older wildcard write.
                            value = min(
                                candidates,
                                key=lambda candidate: candidate.start_byte,
                            )
                frame[name] = (sources, value)
            merged.append(frame)
        return merged

    def _tag_promise_branch_keys(
        self,
        keys: set[tuple[int, int]],
        mode: str,
        join_byte: int,
    ) -> None:
        for key in keys:
            summary = self.promise_summaries.get(key, {})
            for field in ("on_fulfilled", "on_rejected", "on_finally"):
                handler = summary.get(field)
                if handler is not None:
                    handler["branch_projection"] = mode
                    handler["branch_join_byte"] = join_byte

    def _visit_branches(self, first, second) -> None:
        base = self._clone_frames()
        continuing_versions = []
        base_promise_keys = set(self.promise_summaries)

        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        self._visit_statement(first)
        first_continues = not self.path_terminated
        if first_continues:
            continuing_versions.append(self._clone_frames())
        first_promise_keys = set(self.promise_summaries) - base_promise_keys

        self.frames = [dict(frame) for frame in base]
        self.path_terminated = False
        before_second_promise_keys = set(self.promise_summaries)
        self._visit_statement(second)
        second_continues = not self.path_terminated
        if second_continues:
            continuing_versions.append(self._clone_frames())
        second_promise_keys = set(self.promise_summaries) - before_second_promise_keys

        continuing_count = int(first_continues) + int(second_continues)
        join_byte = max(
            child.end_byte for child in (first, second) if child is not None
        )
        for keys, continues in (
            (first_promise_keys, first_continues),
            (second_promise_keys, second_continues),
        ):
            mode = (
                "merge"
                if continues and continuing_count > 1
                else "strong"
                if continues
                else "none"
            )
            self._tag_promise_branch_keys(keys, mode, join_byte)

        if continuing_versions:
            self.frames = self._merge_frame_versions(base, continuing_versions)
            self.path_terminated = False
        else:
            self.frames = base
            self.path_terminated = True

    def _visit_expression_branches(self, expressions, *, include_base: bool):
        base = self._clone_frames()
        versions = [base] if include_base else []
        sources = frozenset()
        promise_branches: list[tuple[set[tuple[int, int]], bool, int]] = []
        for expression in expressions:
            self.frames = [dict(frame) for frame in base]
            self.path_terminated = False
            before_keys = set(self.promise_summaries)
            sources |= self._visit_expression(expression)
            continues = not self.path_terminated
            if continues:
                versions.append(self._clone_frames())
            promise_branches.append(
                (
                    set(self.promise_summaries) - before_keys,
                    continues,
                    expression.end_byte if expression is not None else 0,
                )
            )
        continuing_count = len(versions)
        join_byte = max((branch[2] for branch in promise_branches), default=0)
        for keys, continues, _ in promise_branches:
            mode = (
                "merge"
                if continues and continuing_count > 1
                else "strong"
                if continues
                else "none"
            )
            self._tag_promise_branch_keys(keys, mode, join_byte)
        self.frames = self._merge_frame_versions(base, versions or [base])
        self.path_terminated = not bool(versions)
        return sources

    def _visit_expression(self, node) -> frozenset[str]:
        if node is None:
            return frozenset()
        if self.traversal_depth >= self._MAX_TRAVERSAL_DEPTH:
            self._mark_depth_limit()
            self._scan_depth_limited_subtree(node)
            return self._all_visible_sources()
        self.traversal_depth += 1
        try:
            return self._visit_expression_inner(node)
        finally:
            self.traversal_depth -= 1

    def _visit_expression_inner(self, node) -> frozenset[str]:
        node = _unwrap_ts_expression(node)
        if node is None or not self._consume():
            return frozenset()
        node_type = node.type
        if node_type in {"identifier", "shorthand_property_identifier"}:
            return self._lookup(_get_text(self.source, node))[0]
        if node_type == "this":
            return self._lookup("this")[0]
        if node_type in {
            "property_identifier",
            "private_property_identifier",
            "string",
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
        }:
            return frozenset()
        if node_type in _TS_FUNCTION_NODE_TYPES:
            return frozenset()
        if node_type == "object":
            properties = self._evaluate_object_literal(node)
            return (
                frozenset().union(
                    *(property[1] for property in properties),
                )
                if properties
                else frozenset()
            )
        if node_type in {"await_expression", "yield_expression"}:
            sources = frozenset()
            for child in node.named_children:
                sources |= self._visit_expression(child)
                if self.path_terminated:
                    return sources
                if node_type == "await_expression":
                    promise_key = self._promise_result_key(child)
                    if promise_key is not None:
                        if promise_key in self.promise_summaries:
                            if self._inside_synchronous_async_prefix():
                                function_key = self.function_context_stack[-1]
                                self.last_suspension_promise[function_key] = promise_key
                                # Await always suspends, even when its operand
                                # is already settled. The async continuation is
                                # queued behind jobs that were registered
                                # earlier in this turn; eager settlement here
                                # would reorder a following catch reaction.
                            else:
                                sources = self._await_promise(promise_key)
                        else:
                            promise_effects = self.promise_reaction_effects.get(
                                promise_key
                            )
                            if promise_effects is not None:
                                self._apply_frame_effects(self.frames, promise_effects)
                            sources = self.promise_result_sources.get(
                                promise_key,
                                sources,
                            )
            if self.path_terminated:
                return sources
            self._record_suspension_state(
                "await" if node_type == "await_expression" else "yield",
                node,
            )
            return sources
        if node_type == "ternary_expression":
            sources = self._visit_expression(node.child_by_field_name("condition"))
            sources |= self._visit_expression_branches(
                [
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ],
                include_base=False,
            )
            return sources
        if node_type == "binary_expression":
            operator = next(
                (
                    child.type
                    for child in node.children
                    if not child.is_named and child.type in {"&&", "||", "??"}
                ),
                None,
            )
            if operator is not None:
                sources = self._visit_expression(node.child_by_field_name("left"))
                sources |= self._visit_expression_branches(
                    [node.child_by_field_name("right")],
                    include_base=True,
                )
                return sources
        if node_type == "unary_expression" and any(
            not child.is_named and child.type == "delete" for child in node.children
        ):
            target = next(iter(node.named_children), None)
            target = _unwrap_ts_expression(target)
            if target is None or target.type not in {
                "member_expression",
                "subscript_expression",
            }:
                return self._visit_expression(target)
            receiver = target.child_by_field_name("object")
            sources = self._visit_expression(receiver)
            if target.type == "subscript_expression":
                sources |= self._visit_expression(target.child_by_field_name("index"))
            property_name = self._member_property_name(target)
            alias_targets = self._result_alias_targets(receiver)
            if alias_targets:
                for object_path in alias_targets:
                    self._delete_property_path(
                        object_path,
                        property_name,
                        node,
                        failure_throws=True,
                    )
                    if self.path_terminated:
                        break
                return sources
            object_path = self._canonical_object_path(receiver)
            if object_path is not None:
                self._delete_property_path(
                    object_path,
                    property_name,
                    node,
                    failure_throws=True,
                )
            return sources
        if (
            node_type == "assignment_expression"
            or node_type == "augmented_assignment_expression"
        ):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            left_value_sources = frozenset()
            if left is not None and left.type in {
                "member_expression",
                "subscript_expression",
            }:
                if node_type == "augmented_assignment_expression":
                    # Compound assignments read the old property value before
                    # evaluating the right-hand side.
                    left_value_sources = self._visit_expression(left)
                else:
                    # A plain property assignment still evaluates its receiver
                    # and computed key first; either can trigger a getter/Proxy
                    # exception after earlier comma-expression side effects.
                    self._visit_expression(left.child_by_field_name("object"))
                    if left.type == "subscript_expression":
                        self._visit_expression(left.child_by_field_name("index"))
            elif node_type == "augmented_assignment_expression":
                left_value_sources = self._visit_expression(left)

            sources = left_value_sources | self._visit_expression(right)
            if left is not None and left.type not in {
                "member_expression",
                "subscript_expression",
            }:
                self._bind_pattern(left, sources, right, assign=True)
                for name in self._pattern_names(left):
                    self._materialize_object_members(name, right)
            elif left is not None:
                receiver_path = self._canonical_object_path(
                    left.child_by_field_name("object")
                )
                receiver_value = (
                    _unwrap_ts_expression(self._lookup(receiver_path)[1])
                    if receiver_path is not None
                    else None
                )
                if receiver_value is None or receiver_value.type != "object":
                    # A Proxy/setter can throw after RHS side effects but before
                    # the abstract property write becomes visible.
                    self._record_possible_exception()
                self._assign_member_expression(left, sources, right)
                # A setter or Proxy trap can throw after RHS evaluation. Keep
                # both the pre-write snapshot above and the post-write state.
                self._record_possible_exception()
            return sources
        if node_type == "call_expression":
            return self._visit_call(node)
        if node_type == "new_expression":
            # Constructor lookup runs before arguments, and construction can
            # throw after every argument-side effect has completed.
            self._record_possible_exception()
            sources = self._visit_expression(node.child_by_field_name("constructor"))
            arguments = node.child_by_field_name("arguments")
            if arguments is not None:
                for argument in arguments.named_children:
                    sources |= self._visit_expression(argument)
            self._record_possible_exception()
            return sources
        if node_type in {"member_expression", "subscript_expression"}:
            receiver = _unwrap_ts_expression(node.child_by_field_name("object"))
            property_node = node.child_by_field_name(
                "property" if node_type == "member_expression" else "index"
            )
            # Member references evaluate their receiver/key before invoking a
            # possible getter or Proxy trap. Preserve that intermediate state
            # for an enclosing catch.
            evaluated_sources = self._visit_expression(receiver)
            key_sources = frozenset()
            if node_type == "subscript_expression":
                key_sources = self._visit_expression(property_node)
            self._record_possible_exception()

            property_name = self._member_property_name(node)
            object_path = self._canonical_object_path(node)
            if object_path is None or property_name is None:
                return evaluated_sources | key_sources
            parent_path = object_path.rsplit(".", 1)[0]
            if self._property_exists_state(parent_path, property_name) is False:
                # A deleted own property can still resolve through the
                # prototype chain. Prototype and unknown-key mutations are
                # represented by wildcard heap bindings, so retain those
                # without reviving the stale exact own-property binding.
                sources = key_sources
                receiver_aliases = self._result_alias_targets(receiver)
                for candidate in {parent_path, *receiver_aliases}:
                    parts = candidate.split(".")
                    for end in range(1, len(parts) + 1):
                        present, wildcard = self._lookup_explicit(
                            f"{'.'.join(parts[:end])}.*"
                        )
                        if present:
                            sources |= wildcard[0]
                return sources
            alias_sources = self._alias_member_sources(
                self._result_alias_targets(receiver),
                property_name,
            )

            parts = object_path.split(".")
            exact_bindings: list[tuple[str, tuple[frozenset[str], object | None]]] = []
            for end in range(1, len(parts) + 1):
                prefix = ".".join(parts[:end])
                present, binding = self._lookup_explicit(prefix)
                if present:
                    exact_bindings.append((prefix, binding))

            def overwritten_by_descendant(
                binding_name: str,
                binding_value,
            ) -> bool:
                if binding_value is None:
                    return False
                for descendant_name, (_, descendant_value) in exact_bindings:
                    if not descendant_name.startswith(f"{binding_name}."):
                        continue
                    if (
                        descendant_value is not None
                        and self._enclosing_function_key(descendant_value)
                        == self._enclosing_function_key(binding_value)
                        and binding_value.start_byte < descendant_value.start_byte
                    ):
                        return True
                return False

            sources = key_sources | alias_sources
            has_exact, exact_binding = self._lookup_explicit(object_path)
            if has_exact:
                # Synthetic exact-member bindings represent the current
                # property value. Object rebinding clears them, so aggregate
                # receiver taint must not be reintroduced after a definite
                # direct/helper overwrite. Unknown wildcard writes remain
                # possible unless a later same-scope exact write masks them.
                sources |= exact_binding[0]
                exact_value = exact_binding[1]
                if (
                    exact_value is not None
                    and (exact_value.start_byte, exact_value.end_byte)
                    in self.accessor_getters
                ):
                    if self._is_generator_callable(exact_value):
                        getter_sources = frozenset()
                        getter_can_complete = True
                    else:
                        async_getter = self._is_async_callable(exact_value)
                        getter_sources, getter_can_complete = self._invoke_function(
                            exact_value,
                            [],
                            [],
                            invocation_node=node,
                            this_target=".".join(parts[:-1]),
                            async_boundary=async_getter,
                            stop_at_await=async_getter,
                        )
                        if async_getter:
                            # The property value is a Promise, not its eventual
                            # fulfillment value.
                            getter_sources = frozenset()
                    sources |= getter_sources
                    if not getter_can_complete:
                        self.path_terminated = True
                for end in range(1, len(parts)):
                    prefix = ".".join(parts[:end])
                    present, wildcard_binding = self._lookup_explicit(f"{prefix}.*")
                    if not present:
                        continue
                    wildcard_value = wildcard_binding[1]
                    exact_overwrites_wildcard = bool(
                        exact_value is not None
                        and wildcard_value is not None
                        and self._enclosing_function_key(exact_value)
                        == self._enclosing_function_key(wildcard_value)
                        and wildcard_value.start_byte < exact_value.start_byte
                    )
                    if not exact_overwrites_wildcard:
                        sources |= wildcard_binding[0]
                return sources

            for binding_name, (binding_sources, binding_value) in exact_bindings:
                if not overwritten_by_descendant(binding_name, binding_value):
                    sources |= binding_sources

            for end in range(1, len(parts)):
                prefix = ".".join(parts[:end])
                present, wildcard_binding = self._lookup_explicit(f"{prefix}.*")
                if present and not overwritten_by_descendant(
                    prefix,
                    wildcard_binding[1],
                ):
                    sources |= wildcard_binding[0]

            parent_path = ".".join(parts[:-1])
            _, parent_value = self._lookup(parent_path)
            property_value, object_is_known = self._object_argument_property(
                parent_value,
                property_name,
            )
            if property_value is not None:
                return sources | self._visit_expression(property_value)
            if object_is_known:
                return sources
            return sources

        sources = frozenset()
        for child in node.named_children:
            if child.type.endswith("_type") or child.type in {
                "type_annotation",
                "predefined_type",
                "type_identifier",
            }:
                continue
            sources |= self._visit_expression(child)
        return sources

    def _resolve_value_node(
        self,
        expression,
        seen: frozenset[str] = frozenset(),
    ):
        """Resolve a statically bound value without executing target code."""
        current = _unwrap_ts_expression(expression)
        for _ in range(32):
            if current is None or current.type != "identifier":
                return current
            name = _get_text(self.source, current)
            if name in seen:
                return None
            seen |= {name}
            value = self._lookup(name)[1]
            if value is None:
                return current
            current = _unwrap_ts_expression(value)
        self.analysis_complete = False
        if "D281 callable alias depth exhausted" not in self.diagnostics:
            self.diagnostics.append("D281 callable alias depth exhausted")
        return None

    def _object_member_callable(self, value, property_name: str):
        value = self._resolve_value_node(value)
        if value is None:
            return None
        if value.type == "new_expression":
            value = self._resolve_value_node(value.child_by_field_name("constructor"))
        if value is not None and value.type == "class_declaration":
            value = value.child_by_field_name("body")
        if value is None or value.type not in {"object", "class_body"}:
            return None
        matches = []
        for child in value.named_children:
            name_node = child.child_by_field_name("name")
            key_node = child.child_by_field_name("key")
            name = self._static_property_name(name_node or key_node)
            if child.type == "method_definition" and name == property_name:
                matches.append(child)
                continue
            if child.type != "pair" or name != property_name:
                continue
            member_value = self._resolve_value_node(child.child_by_field_name("value"))
            if (
                member_value is not None
                and member_value.type in _TS_FUNCTION_NODE_TYPES
            ):
                matches.append(member_value)
        return matches[0] if len(matches) == 1 else None

    def _resolve_callable(
        self,
        expression,
        seen: frozenset[str] = frozenset(),
    ):
        current = _unwrap_ts_expression(expression)
        if current is None:
            return None
        if current.type in _TS_FUNCTION_NODE_TYPES:
            return current
        if current.type == "identifier":
            name = _get_text(self.source, current)
            if name in seen:
                return None
            value = self._lookup(name)[1]
            if value is not None:
                resolved = self._resolve_callable(value, seen | {name})
                if resolved is not None:
                    return resolved
            candidates = self.functions.get(name, [])
            return candidates[0] if len(candidates) == 1 else None
        if current.type not in {"member_expression", "subscript_expression"}:
            return None
        member_path = self._canonical_object_path(current)
        if member_path is not None:
            present, binding = self._lookup_explicit(member_path)
            if present and binding[1] is not None:
                resolved = self._resolve_callable(binding[1], seen)
                if resolved is not None:
                    return resolved
        receiver = current.child_by_field_name("object")
        property_node = current.child_by_field_name(
            "property" if current.type == "member_expression" else "index"
        )
        property_name = self._static_property_name(property_node) or ""
        if property_name in {"call", "apply"}:
            return self._resolve_callable(receiver, seen)
        return self._object_member_callable(receiver, property_name)

    def _callable_return_expressions(self, function) -> list:
        body = function.child_by_field_name("body")
        if body is None:
            return []
        if body.type != "statement_block":
            return [body]
        returns = []
        stack = list(reversed(body.named_children))
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            node = stack.pop()
            if node.type in _TS_FUNCTION_NODE_TYPES:
                continue
            if node.type == "return_statement":
                value = next(iter(node.named_children), None)
                if value is not None:
                    returns.append(value)
                continue
            stack.extend(reversed(node.named_children))
        if stack:
            self.analysis_complete = False
            if "D281 return-shape budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 return-shape budget exhausted")
        return returns

    @staticmethod
    def _callback_sources(
        method: str,
        receiver_sources: frozenset[str],
        parameter_count: int,
        callback_index: int,
        argument_sources: list[frozenset[str]],
    ) -> list[frozenset[str]] | None:
        collection_methods = {
            "map",
            "forEach",
            "filter",
            "flatMap",
            "some",
            "every",
            "find",
            "findIndex",
        }
        if method in collection_methods:
            if callback_index != 0:
                return None
            modeled = [receiver_sources, frozenset(), receiver_sources]
            return modeled[:parameter_count] + [frozenset()] * max(
                0, parameter_count - len(modeled)
            )
        if method == "reduce" and callback_index == 0:
            initial_sources = (
                argument_sources[1] if len(argument_sources) > 1 else receiver_sources
            )
            modeled = [
                receiver_sources | initial_sources,
                receiver_sources,
                frozenset(),
                receiver_sources,
            ]
            return modeled[:parameter_count] + [frozenset()] * max(
                0, parameter_count - len(modeled)
            )
        if method == "sort" and callback_index == 0:
            modeled = [receiver_sources, receiver_sources]
            return modeled[:parameter_count] + [frozenset()] * max(
                0, parameter_count - len(modeled)
            )
        if method == "from" and callback_index == 1:
            collection_sources = (
                argument_sources[0] if argument_sources else frozenset()
            )
            modeled = [collection_sources, frozenset()]
            return modeled[:parameter_count] + [frozenset()] * max(
                0, parameter_count - len(modeled)
            )
        if method == "then" and callback_index in {0, 1}:
            first = receiver_sources if callback_index == 0 else frozenset()
            return [first] + [frozenset()] * max(0, parameter_count - 1)
        if method in {"catch", "finally"} and callback_index == 0:
            return [frozenset()] * parameter_count
        return None

    @staticmethod
    def _callback_is_definitely_invoked(method: str, receiver) -> bool:
        """Prove the narrow dense-array callback case used for completion."""
        node = _unwrap_ts_expression(receiver)
        return bool(
            method == "forEach"
            and node is not None
            and node.type == "array"
            and node.named_children
            and all(child.type != "spread_element" for child in node.named_children)
        )

    @staticmethod
    def _is_generator_callable(function) -> bool:
        return bool(function is not None and "generator" in function.type)

    @staticmethod
    def _is_async_callable(function) -> bool:
        return bool(
            function is not None
            and any(child.type == "async" for child in function.children)
        )

    @staticmethod
    def _call_is_awaited(call) -> bool:
        current = call.parent
        while current is not None and current.type in {
            "parenthesized_expression",
            "as_expression",
            "satisfies_expression",
            "type_assertion",
            "non_null_expression",
        }:
            current = current.parent
        return bool(current is not None and current.type == "await_expression")

    def _inside_synchronous_async_prefix(self) -> bool:
        if not self.suspension_state_collectors or not self.function_context_stack:
            return False
        function_key, kind, _ = self.suspension_state_collectors[-1]
        return kind == "await" and function_key == self.function_context_stack[-1]

    def _reset_promise_scheduler(self) -> None:
        self.promise_summaries.clear()
        self.promise_ready_queue.clear()
        self.promise_dependents.clear()
        self.promise_identity_paths.clear()
        self.promise_alias_keys.clear()
        self.promise_jobs_running.clear()
        self.promise_job_order = 0
        self.promise_checkpoint_order = 0
        self.last_suspension_promise.clear()
        # The legacy maps remain the conservative fallback for unknown
        # thenables, but their AST keys are action-local too.
        self.promise_result_sources.clear()
        self.promise_reaction_frames.clear()
        self.promise_reaction_effects.clear()

    def _pristine_promise_static_kind(
        self,
        function,
        receiver,
        method: str,
    ) -> str | None:
        if method not in {"resolve", "reject"}:
            return None
        root = self._resolve_value_node(receiver)
        if (
            root is None
            or root.type != "identifier"
            or _get_text(self.source, root) != "Promise"
        ):
            return None
        path = f"Promise.{method}"
        return method if self._builtin_member_is_pristine(path, function) else None

    def _promise_reaction_is_pristine(
        self,
        function,
        receiver,
        method: str,
    ) -> bool:
        if method not in {"then", "catch", "finally"} or not (
            self._builtin_member_is_pristine(
                f"Promise.prototype.{method}",
                function,
            )
        ):
            return False
        receiver_path = self._canonical_object_path(receiver)
        if receiver_path is None:
            # An immediate native call chain cannot have an intervening
            # per-instance method or prototype mutation.
            return self._promise_result_key(receiver) is not None
        receiver_key = self._promise_result_key(receiver)
        identity_paths = set(
            self.promise_identity_paths.get(receiver_key, set())
            if receiver_key is not None
            else ()
        )
        identity_paths.add(receiver_path)
        if any(
            self._lookup_explicit(f"{path}.{method}")[0]
            or self._lookup_explicit(f"{path}.*")[0]
            for path in identity_paths
        ):
            return False
        capture_scope = self._enclosing_function_key(function)
        for mutation_byte, target, is_module_level, scope_key in self.mutations:
            if not any(
                self._mutation_may_affect_path(target, f"{path}.{method}")
                or target == path
                for path in identity_paths
            ):
                continue
            if is_module_level:
                if capture_scope is not None or mutation_byte < function.start_byte:
                    return False
            elif scope_key == capture_scope and mutation_byte < function.start_byte:
                return False
        return True

    def _promise_handler_snapshot(self, expression) -> tuple[bool, dict | None]:
        callback = self._resolve_callable(expression)
        if callback is not None:
            # Promise callbacks close over lexical environment records, not
            # whichever block happens to be active when the microtask runs.
            # Retain the frame objects themselves so later writes update the
            # captured cells while a popped block remains reachable.
            closure_depth = None
            for index, frame in enumerate(self.frames):
                if any(
                    value is not None and self._same_value_node(value, callback)
                    for _, value in frame.values()
                ):
                    closure_depth = index + 1
                    break
            closure_frames = list(
                self.frames if closure_depth is None else self.frames[:closure_depth]
            )
            return True, {
                "callback": callback,
                "closure_frames": closure_frames,
            }
        value = self._resolve_value_node(expression)
        if value is None or value.type in {
            "undefined",
            "null",
            "true",
            "false",
            "number",
            "string",
        }:
            return True, None
        return False, None

    def _enqueue_promise_job(self, key: tuple[int, int]) -> None:
        summary = self.promise_summaries.get(key)
        if summary is None or summary.get("queued") or summary.get("outcomes"):
            return
        if len(self.promise_ready_queue) >= 256:
            self.analysis_complete = False
            if "D281 Promise job budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 Promise job budget exhausted")
            return
        summary["queued"] = True
        self.promise_ready_queue.append(key)

    def _settle_promise_summary(
        self,
        key: tuple[int, int],
        outcomes: list[dict],
    ) -> None:
        summary = self.promise_summaries[key]
        summary["outcomes"] = outcomes
        summary["queued"] = False
        for dependent in self.promise_dependents.get(key, []):
            if dependent and dependent[0] == "await":
                self.promise_ready_queue.append(dependent)
            else:
                self._enqueue_promise_job(dependent)

    def _queue_await_marker(self, key: tuple[int, int]) -> tuple[str, int]:
        self.promise_checkpoint_order += 1
        marker = ("await", self.promise_checkpoint_order)
        summary = self.promise_summaries.get(key)
        if summary is not None and summary.get("outcomes"):
            self.promise_ready_queue.append(marker)
        else:
            self.promise_dependents.setdefault(key, []).append(marker)
        return marker

    def _register_settled_promise(
        self,
        call,
        status: str,
        sources: frozenset[str],
    ) -> tuple[int, int]:
        key = (call.start_byte, call.end_byte)
        self.promise_job_order += 1
        self.promise_summaries[key] = {
            "kind": "settled",
            "outcomes": [{"status": status, "sources": sources}],
            "queued": False,
            "order": self.promise_job_order,
        }
        return key

    def _register_forwarded_promise(
        self,
        call,
        parent_key: tuple[int, int],
    ) -> tuple[int, int]:
        key = (call.start_byte, call.end_byte)
        self.promise_job_order += 1
        parent = self.promise_summaries[parent_key]
        self.promise_summaries[key] = {
            "kind": "forward",
            "parent": parent_key,
            "outcomes": list(parent.get("outcomes", [])),
            "queued": False,
            "order": self.promise_job_order,
        }
        if not self.promise_summaries[key]["outcomes"]:
            self.promise_dependents.setdefault(parent_key, []).append(key)
        return key

    def _invocation_promise_outcomes(
        self,
        result: frozenset[str],
        outcome: dict,
    ) -> list[dict]:
        outcomes: list[dict] = []
        return_values = outcome.get("return_values", [])
        if return_values:
            for returned in return_values:
                promise_key = returned.get("promise_key")
                if promise_key is not None and promise_key in self.promise_summaries:
                    outcomes.append({"status": "adopt", "promise_key": promise_key})
                else:
                    outcomes.append(
                        {
                            "status": "fulfilled",
                            "sources": returned.get("sources", frozenset()),
                        }
                    )
        elif outcome.get("normal_versions"):
            outcomes.append({"status": "fulfilled", "sources": result})
        exception_versions = outcome.get("exception_versions", [])
        exception_reasons = outcome.get("exception_reasons", [])
        for index, _ in enumerate(exception_versions):
            reason = (
                exception_reasons[index]
                if index < len(exception_reasons)
                else {"sources": frozenset(), "unknown": True}
            )
            outcomes.append(
                {
                    "status": "rejected",
                    "sources": (
                        self._all_visible_sources()
                        if reason["unknown"]
                        else reason["sources"]
                    ),
                }
            )
        return outcomes

    def _settle_or_adopt_promise_summary(
        self,
        key: tuple[int, int],
        outcomes: list[dict],
    ) -> None:
        concrete = [outcome for outcome in outcomes if outcome["status"] != "adopt"]
        adoptions = [outcome for outcome in outcomes if outcome["status"] == "adopt"]
        if not adoptions:
            self._settle_promise_summary(key, concrete)
            return
        summary = self.promise_summaries[key]
        summary.update(
            {
                "kind": "adoption",
                "outcomes": [],
                "queued": False,
                "base_outcomes": concrete,
                "adoptions": adoptions,
            }
        )
        for adoption in adoptions:
            target_key = adoption["promise_key"]
            if target_key == key:
                adoption["self_cycle"] = True
                continue
            dependents = self.promise_dependents.setdefault(target_key, [])
            if key not in dependents:
                dependents.append(key)
        # Promise resolution adopts even an already-settled Promise in a
        # later job, preserving FIFO relative to existing microtasks.
        if all(
            adoption.get("self_cycle")
            or self.promise_summaries.get(adoption["promise_key"], {}).get("outcomes")
            for adoption in adoptions
        ):
            self._enqueue_promise_job(key)

    def _run_promise_adoption(self, key: tuple[int, int]) -> None:
        summary = self.promise_summaries[key]
        outcomes = list(summary.get("base_outcomes", []))
        for adoption in summary.get("adoptions", []):
            if adoption.get("self_cycle"):
                outcomes.append(
                    {"status": "rejected", "sources": self._all_visible_sources()}
                )
                continue
            target = self.promise_summaries.get(adoption["promise_key"])
            if target is None or not target.get("outcomes"):
                return
            fulfilled_as = adoption.get("fulfilled_as")
            for target_outcome in target["outcomes"]:
                outcomes.append(
                    fulfilled_as
                    if target_outcome["status"] == "fulfilled"
                    and fulfilled_as is not None
                    else target_outcome
                )
        self._settle_promise_summary(key, outcomes)

    def _schedule_async_continuation(
        self,
        key: tuple[int, int],
        awaited_key: tuple[int, int] | None,
    ) -> None:
        summary = self.promise_summaries[key]
        summary["waiting_on"] = awaited_key
        if awaited_key is None or awaited_key not in self.promise_summaries:
            summary["unknown_await"] = True
            self._enqueue_promise_job(key)
            return
        self.promise_dependents.setdefault(awaited_key, []).append(key)
        if self.promise_summaries[awaited_key].get("outcomes"):
            self._enqueue_promise_job(key)

    def _register_async_promise(
        self,
        call,
        function,
        argument_sources: list[frozenset[str]],
        argument_nodes: list,
        argument_targets: list[str | None],
        result: frozenset[str],
        outcome: dict,
    ) -> tuple[int, int]:
        key = (call.start_byte, call.end_byte)
        self.promise_job_order += 1
        immediate_outcomes = self._invocation_promise_outcomes(result, outcome)
        suspension_end = outcome.get("suspension_end")
        self.promise_summaries[key] = {
            "kind": "async",
            "outcomes": [],
            "partial_outcomes": immediate_outcomes
            if suspension_end is not None
            else [],
            "queued": False,
            "order": self.promise_job_order,
            "continuation": None,
        }
        if suspension_end is None:
            if not immediate_outcomes:
                immediate_outcomes = [
                    {
                        "status": "rejected",
                        "sources": self._all_visible_sources(),
                    }
                ]
            self._settle_or_adopt_promise_summary(key, immediate_outcomes)
            return key
        self.promise_summaries[key]["continuation"] = {
            "function": function,
            "sources": list(argument_sources),
            "nodes": list(argument_nodes),
            "targets": list(argument_targets),
            "invocation_node": call,
            "resume_after": suspension_end,
            "resume_bindings": outcome.get("resume_bindings", {}),
        }
        self._schedule_async_continuation(
            key,
            outcome.get("suspension_promise"),
        )
        return key

    def _register_promise_reaction(
        self,
        call,
        parent_key: tuple[int, int],
        method: str,
        arguments: list,
    ) -> tuple[int, int] | None:
        key = (call.start_byte, call.end_byte)
        consumed_arguments = arguments[:2] if method == "then" else arguments[:1]
        snapshots = [
            self._promise_handler_snapshot(argument) for argument in consumed_arguments
        ]
        if any(not known for known, _ in snapshots):
            self.analysis_complete = False
            if "D281 Promise reaction identity unresolved" not in self.diagnostics:
                self.diagnostics.append("D281 Promise reaction identity unresolved")
        self.promise_job_order += 1
        handlers = [
            handler if known else {"unknown": True} for known, handler in snapshots
        ]
        on_fulfilled = handlers[0] if method == "then" and handlers else None
        on_rejected = (
            handlers[1]
            if method == "then" and len(handlers) > 1
            else handlers[0]
            if method == "catch" and handlers
            else None
        )
        on_finally = handlers[0] if method == "finally" and handlers else None
        self.promise_summaries[key] = {
            "kind": "reaction",
            "parent": parent_key,
            "on_fulfilled": on_fulfilled,
            "on_rejected": on_rejected,
            "on_finally": on_finally,
            "outcomes": [],
            "queued": False,
            "order": self.promise_job_order,
        }
        self.promise_dependents.setdefault(parent_key, []).append(key)
        if self.promise_summaries[parent_key].get("outcomes"):
            self._enqueue_promise_job(key)
        return key

    def _invoke_promise_handler(
        self,
        handler,
        argument_sources: frozenset[str],
        invocation_node,
    ) -> list[dict] | None:
        if handler is not None and handler.get("unknown"):
            # Unknown callable identity cannot prove safe pass-through. Model
            # both normal and abrupt completion with every currently visible
            # source so unsupported .bind/factory/conditional shapes fail
            # closed instead of silently producing a safe Promise.
            sources = self._all_visible_sources() | argument_sources
            return [
                {"status": "fulfilled", "sources": sources},
                {"status": "rejected", "sources": sources},
            ]
        callback_node = handler.get("callback") if handler is not None else None
        callback = self._resolve_callable(callback_node)
        if callback is None:
            return None
        parameter_count = len(self._function_parameter_patterns(callback))
        arguments = [argument_sources] + [frozenset()] * max(0, parameter_count - 1)
        outcome: dict = {}
        caller_frames = self.frames
        closure_frames = handler.get("closure_frames") or caller_frames
        closure_before = [dict(frame) for frame in closure_frames]
        branch_join_byte = handler.get("branch_join_byte")
        if branch_join_byte is not None:
            for closure_frame, caller_frame in zip(closure_before, caller_frames):
                for name, binding in caller_frame.items():
                    marker = binding[1]
                    owner = name.split(".", 1)[0]
                    if (
                        marker is not None
                        and marker.start_byte > branch_join_byte
                        and (name in closure_frame or owner in closure_frame)
                    ):
                        # A post-join synchronous write updates the same live
                        # closure cell on every continuing branch before any
                        # queued reaction may execute.
                        closure_frame[name] = binding
        self.frames = [dict(frame) for frame in closure_before]
        saved_terminated = self.path_terminated
        self.path_terminated = False
        result, _ = self._invoke_function(
            callback,
            arguments[:parameter_count],
            [None] * parameter_count,
            invocation_node=invocation_node,
            async_boundary=True,
            invocation_outcome=outcome,
            project_async_exceptions=False,
        )
        exit_versions = [
            version[: len(closure_before)]
            for version in [
                *outcome.get("normal_versions", []),
                *outcome.get("exception_versions", []),
            ]
            if len(version) >= len(closure_before)
        ]
        closure_after = (
            self._merge_frame_versions(closure_before, exit_versions)
            if exit_versions
            else closure_before
        )
        closure_effects = self._frame_effects(closure_before, closure_after)
        self._apply_frame_effects(closure_frames, closure_effects)
        branch_projection = handler.get("branch_projection")
        if branch_projection is not None:
            self._project_branch_closure_effects(
                caller_frames,
                closure_effects,
                branch_projection,
            )
        self.frames = caller_frames
        self.path_terminated = saved_terminated
        results = self._invocation_promise_outcomes(result, outcome)
        if not results:
            # An incomplete callback summary must not become proof that the
            # Promise fulfills safely.
            self.analysis_complete = False
            if "D281 Promise callback outcome unresolved" not in self.diagnostics:
                self.diagnostics.append("D281 Promise callback outcome unresolved")
            results.append(
                {"status": "rejected", "sources": self._all_visible_sources()}
            )
        return results

    def _run_promise_reaction(self, key: tuple[int, int]) -> None:
        summary = self.promise_summaries[key]
        parent = self.promise_summaries.get(summary["parent"])
        if parent is None or not parent.get("outcomes"):
            return
        outcomes: list[dict] = []
        for parent_outcome in parent["outcomes"]:
            status = parent_outcome["status"]
            sources = parent_outcome["sources"]
            finally_handler = summary.get("on_finally")
            if finally_handler is not None:
                handler_outcomes = self._invoke_promise_handler(
                    finally_handler,
                    frozenset(),
                    finally_handler.get("callback"),
                )
                if handler_outcomes is None:
                    outcomes.append(parent_outcome)
                    continue
                for handler_outcome in handler_outcomes:
                    if handler_outcome["status"] == "adopt":
                        outcomes.append(
                            {**handler_outcome, "fulfilled_as": parent_outcome}
                        )
                    else:
                        outcomes.append(
                            parent_outcome
                            if handler_outcome["status"] == "fulfilled"
                            else handler_outcome
                        )
                continue
            callback_handler = (
                summary.get("on_fulfilled")
                if status == "fulfilled"
                else summary.get("on_rejected")
            )
            if callback_handler is None:
                outcomes.append(parent_outcome)
                continue
            handler_outcomes = self._invoke_promise_handler(
                callback_handler,
                sources,
                callback_handler.get("callback"),
            )
            if handler_outcomes is None:
                outcomes.append(parent_outcome)
            else:
                outcomes.extend(handler_outcomes)
        self._settle_or_adopt_promise_summary(key, outcomes)

    def _run_async_promise(self, key: tuple[int, int]) -> None:
        summary = self.promise_summaries[key]
        continuation = summary.get("continuation")
        if continuation is None:
            return
        outcomes = list(summary.get("partial_outcomes", []))
        waiting_on = summary.get("waiting_on")
        if waiting_on is not None:
            awaited = self.promise_summaries.get(waiting_on, {})
            awaited_outcomes = awaited.get("outcomes", [])
            outcomes.extend(
                {
                    "status": "rejected",
                    "sources": outcome["sources"],
                }
                for outcome in awaited_outcomes
                if outcome["status"] == "rejected"
            )
            if not any(
                outcome["status"] == "fulfilled" for outcome in awaited_outcomes
            ):
                self._settle_or_adopt_promise_summary(key, outcomes)
                return
        elif summary.pop("unknown_await", False):
            outcomes.append(
                {"status": "rejected", "sources": self._all_visible_sources()}
            )
        outcome: dict = {}
        saved_terminated = self.path_terminated
        self.path_terminated = False
        result, _ = self._invoke_function(
            continuation["function"],
            continuation["sources"],
            continuation["nodes"],
            invocation_node=continuation["invocation_node"],
            argument_targets=continuation["targets"],
            async_boundary=True,
            stop_at_await=True,
            resume_after_byte=continuation["resume_after"],
            resume_bindings=continuation["resume_bindings"],
            invocation_outcome=outcome,
            project_async_exceptions=False,
        )
        self.path_terminated = saved_terminated
        outcomes.extend(self._invocation_promise_outcomes(result, outcome))
        suspension_end = outcome.get("suspension_end")
        if suspension_end is not None:
            continuation["resume_after"] = suspension_end
            continuation["resume_bindings"] = outcome.get("resume_bindings", {})
            summary["partial_outcomes"] = outcomes
            summary["outcomes"] = []
            self._schedule_async_continuation(
                key,
                outcome.get("suspension_promise"),
            )
            return
        if not outcomes:
            self.analysis_complete = False
            if "D281 async continuation outcome unresolved" not in self.diagnostics:
                self.diagnostics.append("D281 async continuation outcome unresolved")
            outcomes.append(
                {"status": "rejected", "sources": self._all_visible_sources()}
            )
        self._settle_or_adopt_promise_summary(key, outcomes)

    def _drain_ready_promise_jobs(
        self,
        *,
        stop_marker: tuple[str, int] | None = None,
    ) -> bool:
        processed = 0
        marker_reached = False
        saved_terminated = self.path_terminated
        self.path_terminated = False
        while self.promise_ready_queue and processed < 256 and self._consume():
            key = self.promise_ready_queue.pop(0)
            if key and key[0] == "await":
                if key == stop_marker:
                    marker_reached = True
                    break
                continue
            summary = self.promise_summaries.get(key)
            if summary is None or summary.get("outcomes"):
                continue
            summary["queued"] = False
            if key in self.promise_jobs_running:
                self.analysis_complete = False
                if "D281 Promise reaction cycle" not in self.diagnostics:
                    self.diagnostics.append("D281 Promise reaction cycle")
                continue
            self.promise_jobs_running.add(key)
            try:
                if summary.get("kind") == "reaction":
                    self._run_promise_reaction(key)
                elif summary.get("kind") == "async":
                    self._run_async_promise(key)
                elif summary.get("kind") == "adoption":
                    self._run_promise_adoption(key)
                elif summary.get("kind") == "forward":
                    parent = self.promise_summaries.get(summary["parent"], {})
                    self._settle_promise_summary(
                        key,
                        list(parent.get("outcomes", [])),
                    )
            finally:
                self.promise_jobs_running.discard(key)
            processed += 1
        if self.promise_ready_queue and not marker_reached and processed >= 256:
            self.analysis_complete = False
            if "D281 Promise job budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 Promise job budget exhausted")
        self.path_terminated = saved_terminated
        return marker_reached

    def _await_promise(self, key: tuple[int, int]) -> frozenset[str]:
        marker = self._queue_await_marker(key)
        marker_reached = self._drain_ready_promise_jobs(stop_marker=marker)
        summary = self.promise_summaries.get(key)
        if summary is None or not marker_reached:
            self.analysis_complete = False
            if "D281 Promise settlement unresolved" not in self.diagnostics:
                self.diagnostics.append("D281 Promise settlement unresolved")
            return self._all_visible_sources()
        outcomes = summary.get("outcomes", [])
        fulfilled = [
            outcome for outcome in outcomes if outcome["status"] == "fulfilled"
        ]
        rejected = [outcome for outcome in outcomes if outcome["status"] == "rejected"]
        if rejected:
            self._record_possible_exception(
                frozenset().union(*(outcome["sources"] for outcome in rejected))
            )
        if not fulfilled:
            self.path_terminated = True
            return frozenset()
        return frozenset().union(*(outcome["sources"] for outcome in fulfilled))

    def _promise_result_key(
        self,
        expression,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> tuple[int, int] | None:
        """Resolve proven Promise identity through ordinary scalar/heap aliases."""
        if depth >= 32:
            self.analysis_complete = False
            if "D281 Promise identity depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 Promise identity depth exhausted")
            return None
        value = _unwrap_ts_expression(expression)
        if value is None:
            return None
        if value.type in {"identifier", "shorthand_property_identifier"}:
            name = _get_text(self.source, value)
            if name in seen:
                return None
            bound_value = self._lookup(name)[1]
            if bound_value is None:
                return None
            return self._promise_result_key(
                bound_value,
                seen=seen | {name},
                depth=depth + 1,
            )
        if value.type in {"member_expression", "subscript_expression"}:
            member_path = self._canonical_object_path(value)
            if member_path is not None:
                present, binding = self._lookup_explicit(member_path)
                if present and binding[1] is not None:
                    key = self._promise_result_key(
                        binding[1],
                        seen=seen,
                        depth=depth + 1,
                    )
                    if key is not None:
                        return key
            property_name = self._member_property_name(value)
            receiver = self._resolve_value_node(value.child_by_field_name("object"))
            if property_name is not None:
                property_value, object_is_known = self._object_argument_property(
                    receiver,
                    property_name,
                )
                if property_value is not None:
                    return self._promise_result_key(
                        property_value,
                        seen=seen,
                        depth=depth + 1,
                    )
                if (
                    not object_is_known
                    and receiver is not None
                    and receiver.type == "array"
                    and property_name.isdecimal()
                    and all(
                        child.type != "spread_element"
                        for child in receiver.named_children
                    )
                ):
                    index = int(property_name)
                    if index < len(receiver.named_children):
                        return self._promise_result_key(
                            receiver.named_children[index],
                            seen=seen,
                            depth=depth + 1,
                        )
            return None
        if value.type != "call_expression":
            return None
        key = (value.start_byte, value.end_byte)
        alias_key = self.promise_alias_keys.get(key)
        if alias_key is not None:
            return alias_key
        if key in self.promise_summaries:
            return key
        if key in self.promise_result_sources or key in self.promise_reaction_frames:
            return key
        return None

    def _argument_object_targets(self, argument_nodes: list) -> list[str | None]:
        return [self._canonical_object_path(argument) for argument in argument_nodes]

    def _generator_invocation_for(self, expression):
        value = self._resolve_value_node(expression)
        if value is None or value.type != "call_expression":
            return None
        key = (value.start_byte, value.end_byte)
        invocation = self.generator_invocations.get(key)
        return (key, invocation) if invocation is not None else None

    def _resume_generator(self, key, invocation: dict, invocation_node):
        if invocation.get("done"):
            return frozenset(), True, False
        function = invocation["function"]
        function_key = (function.start_byte, function.end_byte)
        self.last_suspension_end.pop(function_key, None)
        result_sources, can_complete = self._invoke_function(
            function,
            invocation["sources"],
            invocation["nodes"],
            invocation_node=invocation_node,
            argument_targets=invocation["targets"],
            stop_at_yield=True,
            resume_after_byte=invocation.get("resume_after"),
        )
        suspension_end = self.last_suspension_end.pop(function_key, None)
        suspended = suspension_end is not None
        if suspended:
            invocation["resume_after"] = suspension_end
        elif can_complete:
            invocation["done"] = True
        self.generator_resume_counts[key] = self.generator_resume_counts.get(key, 0) + 1
        return result_sources, can_complete, suspended

    @staticmethod
    def _loop_body_definitely_breaks(body) -> bool:
        body = _unwrap_ts_expression(body)
        if body is None:
            return False
        if body.type == "break_statement":
            return body.child_by_field_name("label") is None
        if body.type != "statement_block":
            return False
        first = next(iter(body.named_children), None)
        return bool(
            first is not None
            and first.type == "break_statement"
            and first.child_by_field_name("label") is None
        )

    def _destructured_builtin_path(self, pattern_node) -> tuple[str, object] | None:
        current = pattern_node
        property_node = current
        if current is not None and current.type == "pair_pattern":
            property_node = current.child_by_field_name("key")
        elif current is not None and current.type in {
            "assignment_pattern",
            "object_assignment_pattern",
        }:
            property_node = current.child_by_field_name("left")
        property_name = self._static_property_name(property_node)
        while current is not None and current.type != "variable_declarator":
            current = current.parent
        if current is None or property_name is None:
            return None
        value = self._resolve_value_node(current.child_by_field_name("value"))
        if value is None or value.type != "identifier":
            return None
        root_name = _get_text(self.source, value)
        if root_name not in {"Object", "Reflect"}:
            return None
        return f"{root_name}.{property_name}", pattern_node

    @staticmethod
    def _mutation_may_affect_path(target: str, path: str) -> bool:
        if not target:
            return True
        if target == path:
            return True
        if target.endswith(".*"):
            prefix = target[:-2]
            return path == prefix or path.startswith(f"{prefix}.")
        return path.startswith(f"{target}.")

    def _builtin_member_is_pristine(self, path: str, capture_node) -> bool:
        root_name = path.split(".", 1)[0]
        if not self._is_unshadowed_global_name(root_name):
            return False
        if self._lookup_explicit(path)[0] or self._lookup_explicit(f"{root_name}.*")[0]:
            return False
        capture_scope = self._enclosing_function_key(capture_node)
        for mutation_byte, target, is_module_level, scope_key in self.mutations:
            normalized_target = target
            if root_name == "Promise":
                if target in {"globalThis", "window", "global"}:
                    normalized_target = root_name
                else:
                    for global_prefix in ("globalThis.", "window.", "global."):
                        if target.startswith(global_prefix):
                            normalized_target = target[len(global_prefix) :]
                            break
            if not self._mutation_may_affect_path(normalized_target, path):
                continue
            if is_module_level:
                if capture_scope is not None or mutation_byte < capture_node.start_byte:
                    return False
            elif scope_key == capture_scope and mutation_byte < capture_node.start_byte:
                return False
        return True

    def _builtin_mutator_identity(
        self,
        function,
    ) -> tuple[str, str, list] | None:
        current = self._resolve_value_node(function)
        if current is not None and current.type == "call_expression":
            captured = self.bound_builtin_captures.get(
                (current.start_byte, current.end_byte)
            )
            if captured is not None:
                return captured
        wrapper = ""
        if current is not None and current.type in {
            "member_expression",
            "subscript_expression",
        }:
            property_name = self._member_property_name(current)
            if property_name in {"call", "apply"}:
                wrapper = property_name
                current = self._resolve_value_node(
                    current.child_by_field_name("object")
                )
        else:
            current = self._resolve_value_node(current)

        bound_arguments: list = []
        if current is not None and current.type == "call_expression":
            bind_function = _unwrap_ts_expression(
                current.child_by_field_name("function")
            )
            if bind_function is None or bind_function.type not in {
                "member_expression",
                "subscript_expression",
            }:
                return None
            if self._member_property_name(bind_function) != "bind":
                return None
            bind_arguments = current.child_by_field_name("arguments")
            packed = (
                list(bind_arguments.named_children)
                if bind_arguments is not None
                else []
            )
            bound_arguments = packed[1:]
            current = self._resolve_value_node(
                bind_function.child_by_field_name("object")
            )

        destructured = self._destructured_builtin_path(current)
        if destructured is not None:
            path, capture_node = destructured
        else:
            path = self._canonical_object_path(current) or self._mutation_target_path(
                current
            )
            capture_node = current
        supported = {
            "Object.assign",
            "Object.defineProperties",
            "Object.defineProperty",
            "Object.freeze",
            "Object.getPrototypeOf",
            "Object.isFrozen",
            "Object.setPrototypeOf",
            "Reflect.defineProperty",
            "Reflect.get",
            "Reflect.set",
            "Reflect.setPrototypeOf",
        }
        if path not in supported or capture_node is None:
            return None
        if not self._builtin_member_is_pristine(path, capture_node):
            return None
        return path, wrapper, bound_arguments

    def _capture_builtin_bind(
        self,
        call,
        function,
        argument_nodes: list,
        argument_sources: list[frozenset[str]],
    ) -> tuple[str, str, list[dict]] | None:
        bind_function = self._resolve_value_node(function)
        if bind_function is None or bind_function.type not in {
            "member_expression",
            "subscript_expression",
        }:
            return None
        if self._member_property_name(bind_function) != "bind":
            return None
        base = bind_function.child_by_field_name("object")
        identity = self._builtin_mutator_identity(base)
        if identity is None:
            return None
        path, wrapper, existing_bound = identity
        if wrapper and not existing_bound and argument_nodes:
            expected_this = self._canonical_object_path(argument_nodes[0])
            if expected_this != path:
                return None
        captures: list[dict] = []
        for index, node in enumerate(argument_nodes[1:], start=1):
            target = self._canonical_object_path(node)
            source_value = self._resolve_value_node(node)
            properties = self._object_assign_source_properties(
                node,
                source_value=source_value,
                source_path=target,
            )
            if target is None and properties:
                target = properties[0][4]
            captures.append(
                {
                    "node": node,
                    "sources": (
                        argument_sources[index]
                        if index < len(argument_sources)
                        else frozenset()
                    ),
                    "target": target,
                    "source_value": source_value,
                    "properties": list(properties) if properties is not None else None,
                }
            )
        captured = (path, wrapper, [*existing_bound, *captures])
        self.bound_builtin_captures[(call.start_byte, call.end_byte)] = captured
        return captured

    def _mutator_arguments(
        self,
        wrapper: str,
        bound_arguments: list,
        argument_nodes: list,
        argument_sources: list[frozenset[str]],
    ) -> tuple[list, list[frozenset[str]], list[dict | None]]:
        if wrapper == "call":
            nodes = argument_nodes[1:]
            sources = argument_sources[1:]
        elif wrapper == "apply":
            packed = (
                _unwrap_ts_expression(argument_nodes[1])
                if len(argument_nodes) > 1
                else None
            )
            if packed is None or packed.type != "array":
                return [], [], []
            nodes = list(packed.named_children)
            sources = [self._visit_expression(node) for node in nodes]
        else:
            nodes = argument_nodes
            sources = argument_sources
        captures: list[dict | None] = [None] * len(nodes)
        if bound_arguments:
            nodes = [*(capture["node"] for capture in bound_arguments), *nodes]
            sources = [
                *(capture["sources"] for capture in bound_arguments),
                *sources,
            ]
            captures = [*bound_arguments, *captures]
        return nodes, sources, captures

    def _builtin_call_target(self, call):
        call = _unwrap_ts_expression(call)
        if call is None or call.type != "call_expression":
            return None
        identity = self._builtin_mutator_identity(call.child_by_field_name("function"))
        if identity is None:
            return None
        path, wrapper, bound_arguments = identity
        if path in {
            "Object.isFrozen",
            "Reflect.defineProperty",
            "Reflect.set",
            "Reflect.setPrototypeOf",
        }:
            return None
        arguments = call.child_by_field_name("arguments")
        nodes = list(arguments.named_children) if arguments is not None else []
        if wrapper == "call":
            nodes = nodes[1:]
        elif wrapper == "apply":
            packed = _unwrap_ts_expression(nodes[1]) if len(nodes) > 1 else None
            if packed is None or packed.type != "array":
                return None
            nodes = list(packed.named_children)
        nodes = [
            *(
                capture["node"] if isinstance(capture, dict) else capture
                for capture in bound_arguments
            ),
            *nodes,
        ]
        return nodes[0] if nodes else None

    def _builtin_result_target_is_stable(
        self,
        call,
        target,
        use_byte: int,
    ) -> bool:
        target = _unwrap_ts_expression(target)
        if target is None or target.type != "identifier":
            return False
        target_name = self._canonical_object_name(_get_text(self.source, target))
        call_scope = self._enclosing_function_key(call)
        return not any(
            mutation_target == target_name
            and scope_key == call_scope
            and call.start_byte < mutation_byte < use_byte
            for mutation_byte, mutation_target, is_module_level, scope_key in self.mutations
            if not is_module_level
        )

    def _single_callable_return_value(self, function):
        values = self._callable_return_expressions(function)
        return values[0] if len(values) == 1 else None

    def _descriptor_value(self, descriptor) -> dict:
        properties = self._object_assign_source_properties(descriptor)
        if properties is None:
            return {
                "known": False,
                "invalid": False,
                "fields": {},
                "fallback_sources": frozenset(),
            }
        fields: dict[str, tuple[frozenset[str], object | None]] = {}
        object_is_known = True
        fallback_sources = frozenset()
        for property_name, sources, value, property_getter, source_path in properties:
            fallback_sources |= sources
            if property_name is None:
                object_is_known = False
                continue
            if property_getter is not None:
                sources, getter_can_complete = self._invoke_function(
                    property_getter,
                    [],
                    [],
                    invocation_node=descriptor,
                    this_target=source_path,
                )
                if not getter_can_complete:
                    self.path_terminated = True
                returned = self._single_callable_return_value(property_getter)
                if returned is not None:
                    value = returned
            fields[property_name] = (sources, value)
            fallback_sources |= sources

        getter = None
        setter = None
        getter_present = "get" in fields
        setter_present = "set" in fields
        data_present = "value" in fields or "writable" in fields
        invalid = False
        for field, present in (("get", getter_present), ("set", setter_present)):
            if not present:
                continue
            candidate = fields[field][1]
            resolved_candidate = self._resolve_value_node(candidate)
            if self._is_static_undefined_expression(resolved_candidate):
                continue
            callable_value = self._resolve_callable(candidate)
            if callable_value is None:
                if resolved_candidate is not None and resolved_candidate.type in {
                    "string",
                    "number",
                    "true",
                    "false",
                    "null",
                    "object",
                    "array",
                }:
                    invalid = True
                else:
                    object_is_known = False
            elif field == "get":
                getter = callable_value
            else:
                setter = callable_value
        if data_present and (getter_present or setter_present):
            invalid = True

        attributes = {}
        for field in ("writable", "enumerable", "configurable"):
            if field not in fields:
                continue
            attributes[field] = self._static_condition_value(fields[field][1])

        return {
            "known": object_is_known,
            "invalid": invalid,
            "fields": fields,
            "fallback_sources": fallback_sources,
            "value_present": "value" in fields,
            "value": fields.get("value", (frozenset(), None))[1],
            "value_sources": fields.get("value", (frozenset(), None))[0],
            "getter_present": getter_present,
            "getter": getter,
            "setter_present": setter_present,
            "setter": setter,
            "attributes": attributes,
        }

    def _property_operation_failure(self, *, throws: bool) -> bool:
        if throws:
            self._record_possible_exception()
            self.path_terminated = True
        return False

    def _set_property_path(
        self,
        object_path: str,
        property_name: str | None,
        sources: frozenset[str],
        value_node,
        invocation_node,
        *,
        failure_throws: bool,
    ) -> bool:
        if property_name is None:
            self._assign_member_name(object_path, None, sources, value_node)
            return True
        exists = self._property_exists_state(object_path, property_name)
        kind = self._property_kind_state(object_path, property_name)
        if exists is False:
            kind = None
        if exists is not True and self._is_definitely_frozen_path(object_path):
            return self._property_operation_failure(throws=failure_throws)
        if kind == "accessor":
            setter_state, setter = self._property_accessor_state(
                object_path,
                property_name,
                "setter",
            )
            if setter_state is False:
                return self._property_operation_failure(throws=failure_throws)
            if setter_state is True and setter is not None:
                _, can_complete = self._invoke_function(
                    setter,
                    [sources],
                    [value_node],
                    invocation_node=invocation_node,
                    this_target=object_path,
                )
                if not can_complete:
                    self.path_terminated = True
                return can_complete
            # An unresolved setter may accept or reject the write. Preserve the
            # old and new sources rather than proving either outcome safe.
            segment = self._heap_property_segment(property_name)
            _, current = self._lookup_explicit(f"{object_path}.{segment}")
            self._assign_member_name(
                object_path,
                property_name,
                current[0] | sources,
                None,
            )
            return True
        if kind == "data":
            writable = self._property_attribute_state(
                object_path,
                property_name,
                "writable",
            )
            if writable is False:
                return self._property_operation_failure(throws=failure_throws)
            if writable is None:
                segment = self._heap_property_segment(property_name)
                present, current = self._lookup_explicit(f"{object_path}.{segment}")
                if present:
                    sources |= current[0]
        if exists is not True or kind is None:
            self._record_data_property(
                object_path,
                property_name,
                sources,
                value_node,
                invocation_node,
            )
        else:
            self._assign_member_name(object_path, property_name, sources, value_node)
        return True

    def _delete_property_path(
        self,
        object_path: str,
        property_name: str | None,
        marker_node,
        *,
        failure_throws: bool,
    ) -> bool:
        if property_name is None:
            self._assign_member_name(
                object_path, None, self._all_visible_sources(), marker_node
            )
            return True
        if self._property_exists_state(object_path, property_name) is False:
            return True
        configurable = self._property_attribute_state(
            object_path,
            property_name,
            "configurable",
        )
        if configurable is False:
            return self._property_operation_failure(throws=failure_throws)
        if configurable is None:
            if failure_throws:
                self._record_possible_exception()
                exists_states = frozenset({_PROPERTY_ABSENT})
            else:
                exists_states = frozenset({_PROPERTY_PRESENT, _PROPERTY_ABSENT})
            self._set_property_metadata(
                object_path,
                property_name,
                "exists",
                exists_states,
                marker_node,
            )
            return True
        self._set_property_metadata(
            object_path,
            property_name,
            "exists",
            frozenset({_PROPERTY_ABSENT}),
            marker_node,
        )
        return True

    def _apply_property_descriptor(
        self,
        object_path: str,
        property_name: str | None,
        summary: dict,
        marker_node,
        *,
        failure_throws: bool,
    ) -> bool:
        if summary["invalid"]:
            # ToPropertyDescriptor throws for both Object and Reflect APIs.
            self.path_terminated = True
            return False
        if property_name is None or not summary["known"]:
            fallback = summary["fallback_sources"] | self._all_visible_sources()
            self._assign_member_name(object_path, property_name, fallback, marker_node)
            return True

        fields = summary["fields"]
        exists_state = self._property_exists_state(object_path, property_name)
        exists = exists_state is not False
        current_kind = self._property_kind_state(object_path, property_name)
        current_configurable = self._property_attribute_state(
            object_path,
            property_name,
            "configurable",
        )
        requests_data = summary["value_present"] or "writable" in fields
        requests_accessor = summary["getter_present"] or summary["setter_present"]
        requested_kind = (
            "data"
            if requests_data
            else "accessor"
            if requests_accessor
            else current_kind
            if exists
            else "data"
        )

        if self._is_definitely_frozen_path(object_path):
            if exists_state is False:
                return self._property_operation_failure(throws=failure_throws)
            if exists_state is None and failure_throws:
                self._record_possible_exception()
        if current_configurable is False and fields:
            if summary["attributes"].get("configurable") is True:
                return self._property_operation_failure(throws=failure_throws)
            requested_enumerable = summary["attributes"].get("enumerable")
            current_enumerable = self._property_attribute_state(
                object_path,
                property_name,
                "enumerable",
            )
            if (
                requested_enumerable is not None
                and current_enumerable is not None
                and requested_enumerable != current_enumerable
            ):
                return self._property_operation_failure(throws=failure_throws)
            if current_kind is not None and requested_kind != current_kind:
                return self._property_operation_failure(throws=failure_throws)
            if current_kind == "accessor" and requested_kind == "accessor":
                for field in ("getter", "setter"):
                    if not summary[f"{field}_present"]:
                        continue
                    current_state, current_value = self._property_accessor_state(
                        object_path,
                        property_name,
                        field,
                    )
                    requested_value = summary[field]
                    requested_state = requested_value is not None
                    if current_state != requested_state or (
                        requested_state
                        and not self._same_value_node(
                            current_value,
                            requested_value,
                        )
                    ):
                        return self._property_operation_failure(throws=failure_throws)

        def attribute(field: str, default: bool) -> bool | None:
            if field in fields:
                return summary["attributes"].get(field)
            if exists:
                return self._property_attribute_state(
                    object_path,
                    property_name,
                    field,
                )
            return default

        enumerable = attribute("enumerable", False)
        configurable = attribute("configurable", False)
        if requested_kind == "accessor":
            same_kind = exists and current_kind == "accessor"
            current_getter_state, current_getter = self._property_accessor_state(
                object_path,
                property_name,
                "getter",
            )
            current_setter_state, current_setter = self._property_accessor_state(
                object_path,
                property_name,
                "setter",
            )
            getter_state = (
                summary["getter"] is not None
                if summary["getter_present"]
                else current_getter_state
                if same_kind
                else False
            )
            setter_state = (
                summary["setter"] is not None
                if summary["setter_present"]
                else current_setter_state
                if same_kind
                else False
            )
            self._record_accessor_property(
                object_path,
                property_name,
                marker_node,
                getter_state=getter_state,
                getter=(
                    summary["getter"]
                    if summary["getter_present"]
                    else current_getter
                    if same_kind
                    else None
                ),
                setter_state=setter_state,
                setter=(
                    summary["setter"]
                    if summary["setter_present"]
                    else current_setter
                    if same_kind
                    else None
                ),
                enumerable=enumerable,
                configurable=configurable,
            )
            return True

        same_data_kind = exists and current_kind == "data"
        if summary["value_present"]:
            value_sources = summary["value_sources"]
            value = summary["value"]
        elif same_data_kind:
            segment = self._heap_property_segment(property_name)
            present, current = self._lookup_explicit(f"{object_path}.{segment}")
            value_sources, value = current if present else (frozenset(), marker_node)
        else:
            value_sources, value = frozenset(), marker_node
        writable = attribute("writable", False)
        if current_configurable is False and same_data_kind:
            current_writable = self._property_attribute_state(
                object_path,
                property_name,
                "writable",
            )
            if current_writable is False and writable is True:
                return self._property_operation_failure(throws=failure_throws)
            if current_writable is False and summary["value_present"]:
                segment = self._heap_property_segment(property_name)
                present, current = self._lookup_explicit(f"{object_path}.{segment}")
                if (
                    not present
                    or current[0] != value_sources
                    or not self._same_value_node(
                        current[1],
                        value,
                    )
                ):
                    return self._property_operation_failure(throws=failure_throws)
        self._record_data_property(
            object_path,
            property_name,
            value_sources,
            value,
            marker_node,
            writable=writable,
            enumerable=enumerable,
            configurable=configurable,
        )
        return True

    @staticmethod
    def _is_static_undefined_expression(node) -> bool:
        node = _unwrap_ts_expression(node)
        if node is None:
            return False
        if node.type == "undefined":
            return True
        return bool(
            node.type == "unary_expression"
            and any(
                not child.is_named and child.type == "void" for child in node.children
            )
        )

    def _apply_builtin_mutator(
        self,
        function,
        argument_nodes: list,
        argument_sources: list[frozenset[str]],
    ) -> tuple[str, object | None, frozenset[str]] | None:
        identity = self._builtin_mutator_identity(function)
        if identity is None:
            return None
        path, wrapper, bound_arguments = identity
        argument_nodes, argument_sources, argument_captures = self._mutator_arguments(
            wrapper,
            bound_arguments,
            argument_nodes,
            argument_sources,
        )
        if not argument_nodes:
            return path, None, frozenset()
        target = argument_nodes[0]
        target_capture = argument_captures[0] if argument_captures else None
        target_sources = argument_sources[0] if argument_sources else frozenset()
        effect = (path, target, target_sources)

        if path == "Object.assign":
            target_name = (
                (target_capture.get("target") if target_capture is not None else None)
                or self._canonical_object_path(target)
                or self._ensure_object_identity_path(target)
            )
            if target_name is None:
                return effect
            for index, source_object in enumerate(argument_nodes[1:], start=1):
                capture = (
                    argument_captures[index] if index < len(argument_captures) else None
                )
                properties = (
                    self._object_assign_source_properties(
                        source_object,
                        source_value=capture.get("source_value"),
                        source_path=capture.get("target"),
                    )
                    if capture is not None
                    else self._object_assign_source_properties(source_object)
                )
                if properties is None:
                    fallback = (
                        argument_sources[index]
                        if index < len(argument_sources)
                        else frozenset()
                    )
                    self._assign_member_name(
                        target_name,
                        None,
                        fallback,
                        _unwrap_ts_expression(source_object),
                    )
                    continue
                for property_name, sources, value, getter, source_path in properties:
                    if getter is not None:
                        sources, getter_can_complete = self._invoke_function(
                            getter,
                            [],
                            [],
                            invocation_node=source_object,
                            this_target=source_path,
                        )
                        if not getter_can_complete:
                            self.path_terminated = True
                            return effect
                    self._set_property_path(
                        target_name,
                        property_name,
                        sources,
                        None if getter is not None else value,
                        source_object,
                        failure_throws=True,
                    )
                    if self.path_terminated:
                        return effect
            return effect

        if path == "Reflect.set" and len(argument_nodes) >= 3:
            target_name = self._canonical_object_path(
                target
            ) or self._ensure_object_identity_path(target)
            known_key, property_name = self._static_computed_property_value(
                argument_nodes[1]
            )
            if target_name is not None and not (known_key and property_name is None):
                self._set_property_path(
                    target_name,
                    property_name if known_key else None,
                    argument_sources[2] if len(argument_sources) > 2 else frozenset(),
                    argument_nodes[2],
                    function,
                    failure_throws=False,
                )
            return effect

        if (
            path in {"Object.defineProperty", "Reflect.defineProperty"}
            and len(argument_nodes) >= 3
        ):
            target_name = self._canonical_object_path(
                target
            ) or self._ensure_object_identity_path(target)
            known_key, property_name = self._static_computed_property_value(
                argument_nodes[1]
            )
            summary = self._descriptor_value(argument_nodes[2])
            if not summary["known"] and len(argument_sources) > 2:
                summary["fallback_sources"] |= argument_sources[2]
            if target_name is not None and not (known_key and property_name is None):
                self._apply_property_descriptor(
                    target_name,
                    property_name if known_key else None,
                    summary,
                    argument_nodes[2],
                    failure_throws=path == "Object.defineProperty",
                )
            return effect

        if path == "Object.defineProperties" and len(argument_nodes) >= 2:
            target_name = self._canonical_object_path(
                target
            ) or self._ensure_object_identity_path(target)
            if target_name is None:
                return effect
            descriptors = self._object_assign_source_properties(argument_nodes[1])
            if descriptors is None:
                fallback = (
                    argument_sources[1] if len(argument_sources) > 1 else frozenset()
                )
                self._assign_member_name(
                    target_name,
                    None,
                    fallback | self._all_visible_sources(),
                    argument_nodes[1],
                )
                return effect
            descriptor_entries = []
            for property_name, sources, descriptor, getter, source_path in descriptors:
                if getter is not None:
                    sources, getter_can_complete = self._invoke_function(
                        getter,
                        [],
                        [],
                        invocation_node=argument_nodes[1],
                        this_target=source_path,
                    )
                    if not getter_can_complete:
                        self.path_terminated = True
                        return effect
                    returned = self._single_callable_return_value(getter)
                    descriptor = returned if returned is not None else descriptor
                summary = self._descriptor_value(descriptor)
                summary["fallback_sources"] |= sources
                if summary["invalid"]:
                    # Object.defineProperties converts every descriptor before
                    # defining any property, so one invalid descriptor leaves
                    # the target unchanged.
                    self.path_terminated = True
                    return effect
                descriptor_entries.append((property_name, descriptor, summary))
            for property_name, descriptor, summary in descriptor_entries:
                self._apply_property_descriptor(
                    target_name,
                    property_name,
                    summary,
                    descriptor,
                    failure_throws=True,
                )
                if self.path_terminated:
                    return effect
            return effect

        if path in {"Object.setPrototypeOf", "Reflect.setPrototypeOf"}:
            prototype = argument_nodes[1] if len(argument_nodes) > 1 else None
            sources = (
                argument_sources[1]
                if len(argument_sources) > 1
                else self._all_visible_sources()
            )
            target_name = self._canonical_object_path(target)
            if target_name is not None:
                self._assign_member_name(target_name, None, sources, prototype)
            return effect

        return effect

    def _object_assign_failure_is_precise(
        self,
        identity: tuple[str, str, list] | None,
        argument_nodes: list,
    ) -> bool:
        if (
            identity is None
            or identity[0] != "Object.assign"
            or identity[1]
            or identity[2]
            or not argument_nodes
        ):
            return False
        target = self._resolve_value_node(argument_nodes[0])
        if target is None or target.type not in {"object", "array"}:
            return False
        for source in argument_nodes[1:]:
            value = self._resolve_value_node(source)
            if value is not None and value.type in {"null", "undefined"}:
                continue
            if self._object_assign_source_properties(source) is None:
                return False
        return True

    def _non_escaping_namespace_call(self, function) -> bool:
        current = self._resolve_value_node(function)
        if current is not None and current.type == "identifier":
            name = _get_text(self.source, current)
            if name in {"Boolean", "Number", "String"}:
                return self._is_unshadowed_global_name(name)
        path = self._canonical_object_path(current)
        if path == "JSON.stringify":
            return self._builtin_member_is_pristine(path, current)
        identity = self._builtin_mutator_identity(function)
        return bool(
            identity is not None and identity[0] in {"Object.freeze", "Object.isFrozen"}
        )

    def _invalidate_escaped_sql_namespaces(self, call, argument_nodes: list) -> None:
        trusted_namespaces = self.prisma_namespaces | self.parameterizing_sql_namespaces
        escaped: set[str] = set()
        stack = [(argument, frozenset()) for argument in reversed(argument_nodes)]
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            raw_node, seen_aliases = stack.pop()
            node = _unwrap_ts_expression(raw_node)
            if node is None:
                continue
            projected_namespace = self._canonical_object_path(node)
            if projected_namespace in trusted_namespaces:
                escaped.add(projected_namespace)
                continue
            if node.type == "identifier":
                name = _get_text(self.source, node)
                namespace = self._canonical_object_path(node)
                if namespace in trusted_namespaces:
                    escaped.add(namespace)
                    continue
                if name in seen_aliases:
                    continue
                value = self._lookup(name)[1]
                if value is not None:
                    stack.append((value, seen_aliases | {name}))
                continue
            if node.type in {"member_expression", "subscript_expression"}:
                selected_value = None
                selected_path = self._canonical_object_path(node)
                if selected_path is not None:
                    present, binding = self._lookup_explicit(selected_path)
                    if present:
                        selected_value = binding[1]
                receiver = _unwrap_ts_expression(node.child_by_field_name("object"))
                receiver_value = self._resolve_value_node(receiver)
                property_name = self._member_property_name(node)
                if selected_value is None and property_name is not None:
                    if receiver_value is not None and receiver_value.type == "object":
                        selected_value, _ = self._object_argument_property(
                            receiver_value,
                            property_name,
                        )
                    elif receiver_value is not None and receiver_value.type == "array":
                        try:
                            index = int(property_name, 10)
                        except ValueError:
                            index = -1
                        elements = list(receiver_value.named_children)
                        if 0 <= index < len(elements):
                            selected_value = elements[index]
                if selected_value is not None:
                    stack.append((selected_value, seen_aliases))
                elif selected_path is None:
                    # A dynamic projection may still return any trusted
                    # namespace stored in the selected container.
                    escaped.update(trusted_namespaces)
                continue
            if node.type == "unary_expression":
                continue
            if (
                node.type == "binary_expression"
                and any(
                    not child.is_named and child.type == "+" for child in node.children
                )
                and self._expression_is_definitely_string(node)
            ):
                continue
            if node.type == "template_string":
                # Template interpolation exposes only the coerced string.
                continue
            if node.type == "call_expression" and self._non_escaping_namespace_call(
                node.child_by_field_name("function")
            ):
                continue
            value_children: list = []
            if node.type == "ternary_expression":
                value_children = [
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ]
            elif node.type == "object":
                for child in node.named_children:
                    if child.type == "pair":
                        value_children.append(child.child_by_field_name("value"))
                    elif child.type in {
                        "shorthand_property_identifier",
                        "spread_element",
                    }:
                        value_children.append(child)
                    elif child.type == "method_definition":
                        value_children.append(child.child_by_field_name("body"))
            elif node.type in {"array", "arguments"}:
                value_children = list(node.named_children)
            elif node.type == "sequence_expression":
                value_children = list(node.named_children[-1:])
            elif node.type == "binary_expression" and any(
                not child.is_named and child.type in {"&&", "||", "??"}
                for child in node.children
            ):
                value_children = [
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ]
            elif node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                value_children = [node.child_by_field_name("right")]
            else:
                value_children = list(node.named_children)
            for child in reversed(value_children):
                if child is None:
                    continue
                if child.type.endswith("_type") or child.type in {
                    "type_annotation",
                    "predefined_type",
                    "type_identifier",
                }:
                    continue
                stack.append((child, seen_aliases))
        if stack:
            self.analysis_complete = False
            escaped.update(trusted_namespaces)
            if "D281 namespace-escape budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 namespace-escape budget exhausted")

        for namespace in escaped:
            self._assign_member_name(
                namespace,
                None,
                frozenset(),
                call,
            )

    def _visit_call(self, call) -> frozenset[str]:
        candidate = _server_action_sql_candidate(call, self.source)
        if candidate is not None:
            self._check_sql_sink(call, candidate)

        function = _unwrap_ts_expression(call.child_by_field_name("function"))
        receiver_node = None
        receiver_sources = frozenset()
        function_sources = frozenset()
        method = ""
        if function is not None and function.type in {
            "member_expression",
            "subscript_expression",
        }:
            receiver_node = function.child_by_field_name("object")
            receiver_sources = self._visit_expression(receiver_node)
            property_node = function.child_by_field_name(
                "property" if function.type == "member_expression" else "index"
            )
            if function.type == "subscript_expression":
                function_sources |= self._visit_expression(property_node)
            method = self._static_property_name(property_node) or ""
        else:
            # JavaScript evaluates the callee before its arguments. This also
            # preserves heap writes in expressions such as getFn(x = value)().
            function_sources = self._visit_expression(function)
        if self.path_terminated:
            return function_sources | receiver_sources

        local_function = self._resolve_callable(function)
        builtin_identity = self._builtin_mutator_identity(function)
        generator_resume = (
            self._generator_invocation_for(receiver_node)
            if method == "next" and receiver_node is not None
            else None
        )
        promise_static_kind = self._pristine_promise_static_kind(
            function,
            receiver_node,
            method,
        )
        resolved_promise_root = self._resolve_value_node(receiver_node)
        untrusted_promise_static = bool(
            method in {"resolve", "reject"}
            and resolved_promise_root is not None
            and resolved_promise_root.type == "identifier"
            and _get_text(self.source, resolved_promise_root) == "Promise"
            and promise_static_kind is None
        )
        native_promise_parent = (
            self._promise_result_key(receiver_node)
            if method in {"then", "catch", "finally"}
            else None
        )
        native_promise_reaction = bool(
            native_promise_parent is not None
            and native_promise_parent in self.promise_summaries
            and self._promise_reaction_is_pristine(
                function,
                receiver_node,
                method,
            )
        )
        untrusted_promise_reaction = bool(
            method in {"then", "catch", "finally"}
            and not native_promise_reaction
            and (
                (
                    native_promise_parent is not None
                    and native_promise_parent in self.promise_summaries
                )
                or receiver_sources
            )
        )
        if (
            function is not None
            and function.type in {"member_expression", "subscript_expression"}
            and local_function is None
            and builtin_identity is None
            and generator_resume is None
            and promise_static_kind is None
            and not native_promise_reaction
        ):
            # Accessing an unresolved method can invoke a getter or Proxy trap
            # before argument evaluation begins.
            self._record_possible_exception()

        arguments = call.child_by_field_name("arguments")
        argument_nodes = (
            [arguments]
            if arguments is not None and arguments.type == "template_string"
            else (list(arguments.named_children) if arguments is not None else [])
        )
        argument_nodes = self._expand_static_call_argument_spreads(argument_nodes)
        argument_sources = []
        for argument in argument_nodes:
            sources = (
                frozenset()
                if argument.type in _TS_FUNCTION_NODE_TYPES
                else self._visit_expression(argument)
            )
            argument_sources.append(sources)
            if self.path_terminated:
                return (
                    function_sources
                    | receiver_sources
                    | frozenset().union(*argument_sources)
                )

        native_reaction_key = (
            self._register_promise_reaction(
                call,
                native_promise_parent,
                method,
                argument_nodes,
            )
            if native_promise_reaction and native_promise_parent is not None
            else None
        )
        exact_promise_call = bool(
            promise_static_kind is not None or native_reaction_key is not None
        )
        precise_builtin_failure = self._object_assign_failure_is_precise(
            builtin_identity,
            argument_nodes,
        )

        bind_capture = self._capture_builtin_bind(
            call,
            function,
            argument_nodes,
            argument_sources,
        )

        if builtin_identity is not None and not precise_builtin_failure:
            # Built-in mutators may throw before or after a partial heap write.
            self._record_possible_exception()
        builtin_effect = self._apply_builtin_mutator(
            function,
            argument_nodes,
            argument_sources,
        )
        if (
            builtin_effect is not None
            and builtin_effect[0] == "Object.getPrototypeOf"
            and argument_nodes
            and self._promise_result_key(argument_nodes[0]) in self.promise_summaries
        ):
            # Every intrinsic Promise instance inherits its reaction methods
            # from Promise.prototype. Preserve that identity so mutating an
            # alias returned by getPrototypeOf revokes the native-method proof.
            self.call_result_targets[(call.start_byte, call.end_byte)] = (
                "Promise.prototype"
            )
        if (
            builtin_effect is not None
            and builtin_effect[0] == "Reflect.get"
            and len(argument_nodes) >= 2
        ):
            known_key, property_name = self._static_computed_property_value(
                argument_nodes[1]
            )
            property_value = None
            if known_key and property_name is not None:
                target_path = self._canonical_object_path(argument_nodes[0])
                if target_path is not None:
                    present, binding = self._lookup_explicit(
                        f"{target_path}.{self._heap_property_segment(property_name)}"
                    )
                    if present:
                        property_value = binding[1]
                if property_value is None:
                    property_value, _ = self._object_argument_property(
                        self._resolve_value_node(argument_nodes[0]),
                        property_name,
                    )
            alias_key = self._promise_result_key(property_value)
            if alias_key is not None:
                self.promise_alias_keys[(call.start_byte, call.end_byte)] = alias_key
        if builtin_effect is not None and builtin_effect[1] is not None:
            returned_target = _unwrap_ts_expression(builtin_effect[1])
            if returned_target is not None and returned_target.type in {
                "object",
                "array",
            }:
                returned_path = self._canonical_object_path(returned_target)
                if returned_path is not None:
                    self.call_result_targets[(call.start_byte, call.end_byte)] = (
                        returned_path
                    )
        if builtin_effect is not None and builtin_effect[0] == "Object.freeze":
            frozen_target = self._canonical_object_path(builtin_effect[1])
            if frozen_target is not None:
                self._mark_object_frozen(frozen_target, call)
            else:
                self.frozen_call_results.add((call.start_byte, call.end_byte))
        if self.path_terminated:
            return (
                function_sources
                | receiver_sources
                | (
                    frozenset().union(*argument_sources)
                    if argument_sources
                    else frozenset()
                )
            )
        if builtin_effect is not None and not precise_builtin_failure:
            self._record_possible_exception()
        elif (
            local_function is None
            and generator_resume is None
            and bind_capture is None
            and not exact_promise_call
        ):
            # An unresolved call can throw after callee and argument evaluation.
            self._record_possible_exception()

        if (
            local_function is None
            and builtin_effect is None
            and generator_resume is None
            and bind_capture is None
            and not exact_promise_call
            and not self._non_escaping_namespace_call(function)
        ):
            self._invalidate_escaped_sql_namespaces(call, argument_nodes)
        can_complete_normally = True
        nested_finding_start = len(self.findings)
        if promise_static_kind is not None:
            argument_promise_key = (
                self._promise_result_key(argument_nodes[0])
                if promise_static_kind == "resolve" and argument_nodes
                else None
            )
            if (
                argument_promise_key is not None
                and argument_promise_key in self.promise_summaries
            ):
                self._register_forwarded_promise(call, argument_promise_key)
            else:
                settled_sources = (
                    argument_sources[0] if argument_sources else frozenset()
                )
                self._register_settled_promise(
                    call,
                    "fulfilled" if promise_static_kind == "resolve" else "rejected",
                    settled_sources,
                )
            result_sources = frozenset()
        elif native_reaction_key is not None:
            result_sources = frozenset()
        elif generator_resume is not None:
            generator_key, generator_info = generator_resume
            result_sources, can_complete_normally, _ = self._resume_generator(
                generator_key,
                generator_info,
                call,
            )
        elif local_function is not None:
            invoke_nodes = argument_nodes
            invoke_sources = argument_sources
            if method == "call":
                invoke_nodes = argument_nodes[1:]
                invoke_sources = argument_sources[1:]
            elif method == "apply":
                array_argument = (
                    _unwrap_ts_expression(argument_nodes[1])
                    if len(argument_nodes) > 1
                    else None
                )
                if array_argument is not None and array_argument.type == "array":
                    invoke_nodes = list(array_argument.named_children)
                    invoke_sources = [
                        self._visit_expression(argument) for argument in invoke_nodes
                    ]
                else:
                    invoke_nodes = []
                    fallback = (
                        argument_sources[1]
                        if len(argument_sources) > 1
                        else frozenset()
                    )
                    invoke_sources = [
                        fallback
                        for _ in self._function_parameter_patterns(local_function)
                    ]
            if self._is_generator_callable(local_function):
                self.generator_invocations[(call.start_byte, call.end_byte)] = {
                    "function": local_function,
                    "sources": list(invoke_sources),
                    "nodes": list(invoke_nodes),
                    "targets": self._argument_object_targets(invoke_nodes),
                    "resume_after": None,
                    "done": False,
                }
                result_sources = frozenset()
                can_complete_normally = True
            elif self._is_async_callable(local_function):
                invocation_outcome: dict = {}
                _, can_complete_normally = self._invoke_function(
                    local_function,
                    invoke_sources,
                    invoke_nodes,
                    invocation_node=call,
                    argument_targets=self._argument_object_targets(invoke_nodes),
                    async_boundary=True,
                    stop_at_await=True,
                    invocation_outcome=invocation_outcome,
                )
                self._register_async_promise(
                    call,
                    local_function,
                    invoke_sources,
                    invoke_nodes,
                    self._argument_object_targets(invoke_nodes),
                    invocation_outcome.get("return_sources", frozenset()),
                    invocation_outcome,
                )
                result_sources = frozenset()
                exact_promise_call = True
            else:
                result_sources, can_complete_normally = self._invoke_function(
                    local_function,
                    invoke_sources,
                    invoke_nodes,
                    invocation_node=call,
                    argument_targets=self._argument_object_targets(invoke_nodes),
                )
            if candidate is not None and any(
                finding.get("rule_id") == "SKY-D281"
                for finding in self.findings[nested_finding_start:]
            ):
                # The local wrapper led to a concrete inner SQL sink. Retain
                # that source-to-sink finding and suppress the generic warning
                # on the wrapper call itself.
                self.safe_sink_spans.add((call.start_byte, call.end_byte))
        else:
            if bind_capture is not None:
                result_sources = frozenset()
            elif builtin_effect is not None:
                builtin_path, builtin_target, builtin_target_sources = builtin_effect
                if builtin_path in {
                    "Object.isFrozen",
                    "Reflect.defineProperty",
                    "Reflect.set",
                    "Reflect.setPrototypeOf",
                }:
                    result_sources = frozenset()
                elif builtin_target is not None:
                    result_sources = builtin_target_sources
                else:
                    result_sources = frozenset().union(*argument_sources)
            else:
                result_sources = (
                    function_sources
                    | receiver_sources
                    | (
                        frozenset().union(*argument_sources)
                        if argument_sources
                        else frozenset()
                    )
                    | (
                        self._all_visible_sources()
                        if untrusted_promise_static or untrusted_promise_reaction
                        else frozenset()
                    )
                )

        if exact_promise_call:
            return frozenset()

        promise_method = method in {"then", "catch", "finally"}
        receiver_promise_key = (
            self._promise_result_key(receiver_node) if promise_method else None
        )
        promise_receiver_sources = (
            self.promise_result_sources.get(receiver_promise_key, receiver_sources)
            if receiver_promise_key is not None
            else receiver_sources
        )
        receiver_promise_frames = (
            self.promise_reaction_frames.get(receiver_promise_key)
            if receiver_promise_key is not None
            else None
        )
        receiver_promise_effects = (
            self.promise_reaction_effects.get(receiver_promise_key)
            if receiver_promise_key is not None
            else None
        )
        promise_is_deferred = promise_method and not self._call_is_awaited(call)
        if promise_method and not promise_is_deferred and receiver_promise_effects:
            # Awaiting the outer link of a chain observes all earlier
            # reactions before its own callback and continuation.
            self._apply_frame_effects(self.frames, receiver_promise_effects)

        callback_results: dict[int, frozenset[str]] = {}
        deferred_reaction_versions: list[list[dict]] = []
        deferred_reaction_base = self._clone_frames()
        if receiver_promise_effects is not None:
            self._apply_frame_effects(
                deferred_reaction_base,
                receiver_promise_effects,
            )
        for callback_index, argument in enumerate(argument_nodes):
            callback = self._resolve_callable(argument)
            if callback is None:
                continue
            parameter_count = len(self._function_parameter_patterns(callback))
            callback_args = self._callback_sources(
                method,
                promise_receiver_sources if promise_method else receiver_sources,
                parameter_count,
                callback_index,
                argument_sources,
            )
            if callback_args is None:
                continue
            callback_values = [None] * len(callback_args)
            if method == "reduce" and callback_index == 0 and len(argument_nodes) > 1:
                callback_values[0] = argument_nodes[1]
            if promise_is_deferred:
                # Promise reactions run in a later microtask. Analyze the
                # callback for findings, but do not expose its heap writes or
                # abrupt completion to code that runs in the current turn.
                caller_frames = self.frames
                caller_path_terminated = self.path_terminated
                self.frames = [dict(frame) for frame in deferred_reaction_base]
                callback_result, _ = self._invoke_function(
                    callback,
                    callback_args,
                    callback_values,
                    invocation_node=call,
                    async_boundary=True,
                )
                callback_results[callback_index] = callback_result
                deferred_reaction_versions.append(self._clone_frames())
                self.frames = caller_frames
                self.path_terminated = caller_path_terminated
                continue
            callback_result, callback_can_complete = self._invoke_function(
                callback,
                callback_args,
                callback_values,
                invocation_node=call,
            )
            callback_results[callback_index] = callback_result
            if not promise_method:
                result_sources |= callback_result
            if not callback_can_complete and self._callback_is_definitely_invoked(
                method, receiver_node
            ):
                can_complete_normally = False

        if promise_method:
            if method == "then":
                result_sources = callback_results.get(0, promise_receiver_sources)
                result_sources |= callback_results.get(1, frozenset())
            elif method == "catch":
                result_sources = promise_receiver_sources | callback_results.get(
                    0, frozenset()
                )
            else:
                # Promise.prototype.finally preserves the original settled
                # value; the callback's return value is ignored.
                result_sources = promise_receiver_sources

            if untrusted_promise_reaction:
                self.analysis_complete = False
                if "D281 Promise reaction identity unresolved" not in self.diagnostics:
                    self.diagnostics.append("D281 Promise reaction identity unresolved")
                result_sources |= self._all_visible_sources()

            call_key = (call.start_byte, call.end_byte)
            self.promise_result_sources[call_key] = result_sources
            if promise_is_deferred:
                if deferred_reaction_versions:
                    reaction_frames = self._merge_frame_versions(
                        deferred_reaction_base,
                        deferred_reaction_versions,
                    )
                    self.promise_reaction_frames[call_key] = reaction_frames
                    self.promise_reaction_effects[call_key] = self._frame_effects(
                        self._clone_frames(),
                        reaction_frames,
                    )
                elif receiver_promise_effects is not None:
                    self.promise_reaction_effects[call_key] = [
                        dict(frame) for frame in receiver_promise_effects
                    ]
                    if receiver_promise_frames is not None:
                        self.promise_reaction_frames[call_key] = [
                            dict(frame) for frame in receiver_promise_frames
                        ]
            else:
                self.promise_reaction_frames[call_key] = self._clone_frames()
                self.promise_reaction_effects[call_key] = self._frame_effects(
                    deferred_reaction_base,
                    self.frames,
                )
        if not can_complete_normally:
            self.path_terminated = True
        return result_sources

    def _receiver_tokens(self, receiver) -> tuple[str, ...]:
        if receiver is None:
            return ()
        text = _get_text(self.source, receiver)
        return tuple(
            token.lower() for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", text)
        )

    def _import_identity_for_token(self, token: str):
        identity = self.import_identities.get(token)
        if identity is not None:
            return identity
        matches = [
            candidate
            for name, candidate in self.import_identities.items()
            if name.lower() == token.lower()
        ]
        return matches[0] if len(matches) == 1 else None

    def _receiver_has_sql_provenance(self, receiver) -> bool:
        def imported_sql_identity(node) -> bool:
            for token in self._receiver_tokens(node):
                identity = self._import_identity_for_token(token)
                if identity is not None and any(
                    hint in identity[0].lower()
                    for hint in self._SQL_DRIVER_MODULE_HINTS
                ):
                    return True
            return False

        def visit(node, seen: frozenset[str], depth: int) -> bool:
            node = _unwrap_ts_expression(node)
            if node is None:
                return False
            if depth >= 32:
                self.analysis_complete = False
                if "D281 receiver alias depth exhausted" not in self.diagnostics:
                    self.diagnostics.append("D281 receiver alias depth exhausted")
                return False
            if imported_sql_identity(node):
                return True
            if node.type == "identifier":
                name = _get_text(self.source, node)
                if name in seen:
                    return False
                value = self._lookup(name)[1]
                if value is not None and visit(value, seen | {name}, depth + 1):
                    return True
                lowered = name.lower()
                if lowered in self._NON_SQL_RECEIVER_HINTS:
                    return False
                return lowered in self._SQL_RECEIVER_HINTS
            if node.type in {"call_expression", "new_expression"}:
                target = node.child_by_field_name(
                    "function"
                ) or node.child_by_field_name("constructor")
                return imported_sql_identity(target) or visit(target, seen, depth + 1)
            if node.type in {"member_expression", "subscript_expression"}:
                return visit(node.child_by_field_name("object"), seen, depth + 1)
            tokens = self._receiver_tokens(node)
            if any(token in self._NON_SQL_RECEIVER_HINTS for token in tokens):
                return False
            return any(token in self._SQL_RECEIVER_HINTS for token in tokens)

        return visit(receiver, frozenset(), 0)

    def _contains_tainted_raw_sql_escape(self, root) -> bool:
        stack = [root] if root is not None else []
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            node = stack.pop()
            if node.type == "call_expression":
                function = _unwrap_ts_expression(node.child_by_field_name("function"))
                resolved_function = self._resolve_value_node(function)
                if resolved_function is not None and resolved_function.type in {
                    "member_expression",
                    "subscript_expression",
                }:
                    property_node = resolved_function.child_by_field_name(
                        "property"
                        if resolved_function.type == "member_expression"
                        else "index"
                    )
                    method = self._static_property_name(property_node) or ""
                    if method in {
                        "raw",
                        "unsafe",
                        "$queryRawUnsafe",
                        "$executeRawUnsafe",
                    }:
                        arguments = node.child_by_field_name("arguments")
                        if arguments is not None and self._visit_expression(arguments):
                            return True
            stack.extend(reversed(node.named_children))
        if stack:
            self.analysis_complete = False
            if "D281 raw-escape budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 raw-escape budget exhausted")
        return False

    def _call_parameter_bindings(self, call, function) -> dict[str, object]:
        arguments = call.child_by_field_name("arguments")
        argument_nodes = (
            list(arguments.named_children)
            if arguments is not None and arguments.type == "arguments"
            else []
        )
        bindings: dict[str, object] = {}
        for pattern, argument in zip(
            self._function_parameter_patterns(function),
            argument_nodes,
        ):
            names = self._pattern_names(pattern)
            if len(names) == 1:
                bindings[names[0]] = argument
        return bindings

    def _sources_with_parameter_bindings(
        self,
        expression,
        bindings: dict[str, object],
        *,
        depth: int = 0,
    ) -> frozenset[str]:
        node = _unwrap_ts_expression(expression)
        if node is None:
            return frozenset()
        if depth >= 32:
            self.analysis_complete = False
            if "D281 query-config depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 query-config depth exhausted")
            return self._all_visible_sources()
        if node.type in {"identifier", "shorthand_property_identifier"}:
            bound = bindings.get(_get_text(self.source, node))
            if bound is not None:
                return self._visit_expression(bound)
            return self._visit_expression(node)
        if node.type in {
            "property_identifier",
            "private_property_identifier",
            "string",
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
        }:
            return frozenset()
        sources = frozenset()
        for child in node.named_children:
            if child.type.endswith("_type") or child.type in {
                "type_annotation",
                "predefined_type",
                "type_identifier",
            }:
                continue
            sources |= self._sources_with_parameter_bindings(
                child,
                bindings,
                depth=depth + 1,
            )
        return sources

    def _query_config_status(
        self,
        expression,
        bindings: dict[str, object] | None = None,
        *,
        depth: int = 0,
    ) -> str | None:
        """Classify `{text, values}` as safe or attacker-controlled SQL text."""
        if depth >= 16:
            self.analysis_complete = False
            if "D281 query-config summary depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 query-config summary depth exhausted")
            return None
        bindings = bindings or {}
        node = _unwrap_ts_expression(expression)
        if node is None:
            return None
        if node.type == "identifier":
            name = _get_text(self.source, node)
            value = bindings.get(name)
            if value is None:
                value = self._lookup(name)[1]
            if value is None or value is node:
                return None
            return self._query_config_status(
                value,
                bindings,
                depth=depth + 1,
            )
        if node.type == "call_expression":
            function = self._resolve_callable(node.child_by_field_name("function"))
            if function is None:
                return None
            call_bindings = self._call_parameter_bindings(node, function)
            statuses = [
                self._query_config_status(
                    returned,
                    call_bindings,
                    depth=depth + 1,
                )
                for returned in self._callable_return_expressions(function)
            ]
            if statuses and all(status == "parameterized" for status in statuses):
                return "parameterized"
            if "tainted_text" in statuses:
                return "tainted_text"
            return None
        if node.type != "object":
            return None
        text_value = None
        values_value = None
        for child in node.named_children:
            if child.type == "spread_element":
                return None
            if child.type == "shorthand_property_identifier":
                key = self._static_property_name(child)
                if key == "text":
                    text_value = child
                elif key == "values":
                    values_value = child
                continue
            if child.type != "pair":
                continue
            key = self._static_property_name(child.child_by_field_name("key"))
            if key == "text":
                text_value = child.child_by_field_name("value")
            elif key == "values":
                values_value = child.child_by_field_name("value")
        if text_value is None or values_value is None:
            return None
        text_sources = self._sources_with_parameter_bindings(text_value, bindings)
        return "tainted_text" if text_sources else "parameterized"

    def _stable_parameterizing_sql_import(
        self,
        name: str,
        tag_call,
        *,
        namespace_member: bool,
    ) -> bool:
        """Require the tag at this sink to still be its trusted import."""
        identity = self.import_identities.get(name)
        if identity is None:
            return False
        module, exported_name = identity
        normalized_module = module.replace("\\", "/").lower()
        if namespace_member:
            trusted_identity = bool(
                (
                    normalized_module == "@prisma/client"
                    and exported_name in {"Prisma", "*"}
                )
                or (
                    normalized_module in {"drizzle-orm", "slonik", "@databases/sql"}
                    and exported_name == "*"
                )
            )
        else:
            trusted_identity = bool(
                (
                    normalized_module in {"drizzle-orm", "slonik", "@databases/sql"}
                    and exported_name == "sql"
                )
                or (
                    normalized_module == "@databases/sql" and exported_name == "default"
                )
            )
        if not trusted_identity:
            return False

        tag_scope = self._enclosing_function_key(tag_call)

        def binding_invalidates_tag(
            binding: tuple[frozenset[str], object | None],
        ) -> bool:
            sources, value = binding
            value = _unwrap_ts_expression(value)
            if value is None:
                return True
            value_scope = self._enclosing_function_key(value)
            return bool(
                sources
                or value_scope != tag_scope
                or value.start_byte < tag_call.start_byte
            )

        # Frame zero contains the pristine import sentinel. A nearer binding,
        # or a changed sentinel, means this path shadowed/reassigned the import.
        for frame_index in range(len(self.frames) - 1, -1, -1):
            frame = self.frames[frame_index]
            if name not in frame:
                continue
            sources, value = frame[name]
            pristine_import = bool(
                frame_index == 0
                and name in self.import_identities
                and not sources
                and value is None
            )
            if not pristine_import:
                if binding_invalidates_tag(frame[name]):
                    return False
            break
        if namespace_member:
            for member_name in (f"{name}.sql", f"{name}.*"):
                for frame in reversed(self.frames):
                    if member_name not in frame:
                        continue
                    if binding_invalidates_tag(frame[member_name]):
                        return False
                    break

        aliases = {name}
        changed = True
        while changed and len(aliases) <= 32:
            changed = False
            for alias_name, value in self.module_values.items():
                value = _unwrap_ts_expression(value)
                if value is None or value.type != "identifier":
                    continue
                if (
                    _get_text(self.source, value) in aliases
                    and alias_name not in aliases
                ):
                    aliases.add(alias_name)
                    changed = True
        if len(aliases) > 32:
            self.analysis_complete = False
            if "D281 SQL-tag alias budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 SQL-tag alias budget exhausted")
            return False

        for mutation_byte, target, is_module_level, scope_key in self.mutations:
            relevant = target == name
            if namespace_member:
                relevant = relevant or any(
                    target == alias
                    or target == f"{alias}.sql"
                    or target.startswith(f"{alias}.sql.")
                    or target == f"{alias}.*"
                    for alias in aliases
                )
            if not relevant:
                continue
            if is_module_level:
                # Module initialization finishes before any action runs. For a
                # tag constructed at module scope, preserve source order.
                if tag_scope is not None or mutation_byte < tag_call.start_byte:
                    return False
            elif scope_key == tag_scope and mutation_byte < tag_call.start_byte:
                return False
        return True

    def _is_parameterized_sql_expression(self, expression) -> bool:
        current = _unwrap_ts_expression(expression)
        seen: set[str] = set()
        for _ in range(64):
            if current is None:
                return False
            if self._query_config_status(current) == "parameterized":
                return True
            if current.type == "identifier":
                name = _get_text(self.source, current)
                if name in seen:
                    return False
                seen.add(name)
                current = _unwrap_ts_expression(self._lookup(name)[1])
                continue
            if current.type != "call_expression":
                return False
            arguments = current.child_by_field_name("arguments")
            if arguments is None or arguments.type != "template_string":
                return False
            function = _unwrap_ts_expression(current.child_by_field_name("function"))
            if function is None:
                return False
            proven = False
            if function.type == "identifier":
                name = _get_text(self.source, function)
                proven = bool(
                    name in self.parameterizing_sql_tags
                    and self._stable_parameterizing_sql_import(
                        name,
                        current,
                        namespace_member=False,
                    )
                )
            elif function.type in {"member_expression", "subscript_expression"}:
                receiver = _unwrap_ts_expression(function.child_by_field_name("object"))
                property_node = function.child_by_field_name(
                    "property" if function.type == "member_expression" else "index"
                )
                method = self._static_property_name(property_node) or ""
                receiver_name = (
                    _get_text(self.source, receiver)
                    if receiver is not None and receiver.type == "identifier"
                    else ""
                )
                proven = bool(
                    method == "sql"
                    and receiver_name
                    and receiver_name
                    in self.prisma_namespaces | self.parameterizing_sql_namespaces
                    and self._stable_parameterizing_sql_import(
                        receiver_name,
                        current,
                        namespace_member=True,
                    )
                )
            return proven and not self._contains_tainted_raw_sql_escape(arguments)
        self.analysis_complete = False
        if "D281 SQL-value alias depth exhausted" not in self.diagnostics:
            self.diagnostics.append("D281 SQL-value alias depth exhausted")
        return False

    def _is_whole_sql_text_source(
        self,
        expression,
        bindings: dict[str, object] | None = None,
        *,
        depth: int = 0,
    ) -> bool:
        if depth >= 32:
            self.analysis_complete = False
            if "D281 SQL-forwarding depth exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 SQL-forwarding depth exhausted")
            return False
        bindings = bindings or {}
        node = _unwrap_ts_expression(expression)
        seen: set[str] = set()
        for _ in range(64):
            if node is None:
                return False
            if node.type == "await_expression":
                awaited = next(iter(node.named_children), None)
                promise_key = self._promise_result_key(awaited)
                if promise_key is not None:
                    if promise_key in self.promise_summaries:
                        return any(
                            outcome["status"] == "fulfilled"
                            and bool(outcome["sources"])
                            for outcome in self.promise_summaries[promise_key].get(
                                "outcomes", []
                            )
                        )
                    return bool(self.promise_result_sources.get(promise_key))
                return self._is_whole_sql_text_source(
                    awaited,
                    bindings,
                    depth=depth + 1,
                )
            if node.type == "identifier":
                name = _get_text(self.source, node)
                if name in seen:
                    return False
                seen.add(name)
                promise_key = self._promise_result_key(node)
                if promise_key is not None:
                    if promise_key in self.promise_summaries:
                        return False
                    return bool(self.promise_result_sources.get(promise_key))
                bound_argument = bindings.get(name)
                if bound_argument is not None:
                    return self._is_whole_sql_text_source(
                        bound_argument,
                        depth=depth + 1,
                    )
                sources, value = self._lookup(name)
                if sources and value is None:
                    return True
                node = _unwrap_ts_expression(value)
                continue
            if node.type in {"member_expression", "subscript_expression"}:
                receiver = _unwrap_ts_expression(node.child_by_field_name("object"))
                if receiver is not None and receiver.type == "identifier":
                    bound_argument = bindings.get(_get_text(self.source, receiver))
                    if bound_argument is not None:
                        return self._is_whole_sql_text_source(
                            bound_argument,
                            depth=depth + 1,
                        )
                return bool(self._visit_expression(node))
            if node.type == "template_string":
                static_text = "".join(
                    _get_text(self.source, child)
                    for child in node.named_children
                    if child.type == "string_fragment"
                )
                return not static_text.strip()
            if node.type in {"binary_expression", "ternary_expression"}:
                static_fragments = []
                stack = list(node.named_children)
                while stack:
                    child = _unwrap_ts_expression(stack.pop())
                    if child is None:
                        continue
                    if child.type == "string":
                        text = _get_text(self.source, child)
                        static_fragments.append(text[1:-1] if len(text) >= 2 else text)
                    elif child.type == "string_fragment":
                        static_fragments.append(_get_text(self.source, child))
                    elif child.type not in {
                        "identifier",
                        "member_expression",
                        "subscript_expression",
                    }:
                        stack.extend(child.named_children)
                return not "".join(static_fragments).strip()
            if node.type != "call_expression":
                return False
            function = _unwrap_ts_expression(node.child_by_field_name("function"))
            if function is None:
                return False
            local_function = self._resolve_callable(function)
            if local_function is not None:
                call_bindings = self._call_parameter_bindings(node, local_function)
                for name, value in list(call_bindings.items()):
                    value = _unwrap_ts_expression(value)
                    if value is not None and value.type == "identifier":
                        outer_value = bindings.get(_get_text(self.source, value))
                        if outer_value is not None:
                            call_bindings[name] = outer_value
                return any(
                    self._is_whole_sql_text_source(
                        returned,
                        call_bindings,
                        depth=depth + 1,
                    )
                    for returned in self._callable_return_expressions(local_function)
                )
            if function.type == "identifier":
                return _get_text(self.source, function) in {
                    "String",
                    "decodeURI",
                    "decodeURIComponent",
                    "stringify",
                }
            if function.type in {"member_expression", "subscript_expression"}:
                property_node = function.child_by_field_name(
                    "property" if function.type == "member_expression" else "index"
                )
                method = self._static_property_name(property_node) or ""
                return method in {
                    "concat",
                    "get",
                    "join",
                    "normalize",
                    "replace",
                    "replaceAll",
                    "slice",
                    "substring",
                    "toString",
                    "toLowerCase",
                    "toUpperCase",
                    "trim",
                }
            return False
        return False

    def _member_callable_is_mutated(self, receiver, method: str, call) -> bool:
        receiver = _unwrap_ts_expression(receiver)
        if receiver is None or receiver.type != "identifier":
            return True
        aliases = {_get_text(self.source, receiver)}
        changed = True
        while changed and len(aliases) <= 32:
            changed = False
            visible_values = dict(self.module_values)
            for frame in self.frames:
                visible_values.update(
                    {
                        name: value
                        for name, (_, value) in frame.items()
                        if value is not None
                    }
                )
            for name, value in visible_values.items():
                value = _unwrap_ts_expression(value)
                if value is None or value.type != "identifier":
                    continue
                if _get_text(self.source, value) in aliases and name not in aliases:
                    aliases.add(name)
                    changed = True
        if len(aliases) > 32:
            self.analysis_complete = False
            if "D281 member-alias budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 member-alias budget exhausted")
            return True
        for _mutation_byte, target, is_module_level, _scope_key in self.mutations:
            # Function-local writes are interpreted only when their call path
            # executes. Treating every helper body as reachable makes hoisted
            # declaration position change the result and creates both FPs/FNs.
            if not is_module_level:
                continue
            for name in aliases:
                if target in {name, f"{name}.{method}"}:
                    return True
                if target.startswith(f"{name}.{method}."):
                    return True
        return False

    def _callable_is_console_only(self, function) -> bool:
        allowed_calls = re.compile(
            r"^(?:console\.(?:debug|error|info|log|trace|warn)|"
            r"JSON\.stringify|String)$"
        )
        body = function.child_by_field_name("body")
        stack = [body] if body is not None else []
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            node = stack.pop()
            if node is not body and node.type in _TS_FUNCTION_NODE_TYPES:
                continue
            if node.type in {"call_expression", "new_expression"}:
                target = node.child_by_field_name(
                    "function"
                ) or node.child_by_field_name("constructor")
                target_text = _get_text(self.source, target).replace(" ", "")
                if not allowed_calls.fullmatch(target_text):
                    return False
            stack.extend(reversed(node.named_children))
        if stack:
            self.analysis_complete = False
            if "D281 local-callable proof budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 local-callable proof budget exhausted")
            return False
        return True

    def _is_unshadowed_global_name(self, name: str) -> bool:
        present, _ = self._lookup_explicit(name)
        return bool(
            not present
            and name not in self.functions
            and name not in self.import_identities
            and name not in self.module_values
        )

    def _is_proven_trusted_sql_value(
        self,
        expression,
        seen: frozenset[str] = frozenset(),
        *,
        depth: int = 0,
    ) -> bool:
        """Require positive provenance before suppressing the generic SQL rule."""
        node = _unwrap_ts_expression(expression)
        if node is None or depth >= 32:
            return False
        if node.type in {
            "string",
            "string_fragment",
            "number",
            "true",
            "false",
            "null",
            "undefined",
        }:
            return True
        if node.type == "identifier":
            name = _get_text(self.source, node)
            if name in seen:
                return False
            sources, value = self._lookup(name)
            return bool(
                not sources
                and value is not None
                and self._is_proven_trusted_sql_value(
                    value,
                    seen | {name},
                    depth=depth + 1,
                )
            )
        if node.type == "new_expression":
            constructor = _unwrap_ts_expression(node.child_by_field_name("constructor"))
            arguments = node.child_by_field_name("arguments")
            return bool(
                constructor is not None
                and constructor.type == "identifier"
                and _get_text(self.source, constructor) == "Date"
                and self._is_unshadowed_global_name("Date")
                and all(
                    self._is_proven_trusted_sql_value(
                        argument,
                        seen,
                        depth=depth + 1,
                    )
                    for argument in (arguments.named_children if arguments else [])
                )
            )
        if node.type == "call_expression":
            function = _unwrap_ts_expression(node.child_by_field_name("function"))
            arguments = node.child_by_field_name("arguments")
            argument_nodes = list(arguments.named_children) if arguments else []
            if not all(
                self._is_proven_trusted_sql_value(
                    argument,
                    seen,
                    depth=depth + 1,
                )
                for argument in argument_nodes
            ):
                return False
            if function is not None and function.type == "identifier":
                name = _get_text(self.source, function)
                return name in {
                    "Boolean",
                    "Number",
                    "String",
                } and self._is_unshadowed_global_name(name)
            if function is None or function.type != "member_expression":
                return False
            receiver = _unwrap_ts_expression(function.child_by_field_name("object"))
            method = self._static_property_name(
                function.child_by_field_name("property")
            )
            if method not in {
                "getDate",
                "getDay",
                "getFullYear",
                "getHours",
                "getMilliseconds",
                "getMinutes",
                "getMonth",
                "getSeconds",
                "getTime",
                "getTimezoneOffset",
                "toISOString",
                "toJSON",
                "toString",
                "valueOf",
            }:
                return False
            if receiver is not None and receiver.type == "identifier":
                receiver_value = self._lookup(_get_text(self.source, receiver))[1]
                if receiver_value is not None:
                    receiver = _unwrap_ts_expression(receiver_value)
            return bool(
                receiver is not None
                and receiver.type == "new_expression"
                and self._is_proven_trusted_sql_value(
                    receiver,
                    seen,
                    depth=depth + 1,
                )
            )
        if node.type == "template_string":
            substitutions = [
                child
                for child in node.named_children
                if child.type == "template_substitution"
            ]
            return all(
                all(
                    self._is_proven_trusted_sql_value(
                        child,
                        seen,
                        depth=depth + 1,
                    )
                    for child in substitution.named_children
                )
                for substitution in substitutions
            )
        if node.type in {
            "binary_expression",
            "parenthesized_expression",
            "unary_expression",
        }:
            return all(
                self._is_proven_trusted_sql_value(
                    child,
                    seen,
                    depth=depth + 1,
                )
                for child in node.named_children
            )
        return False

    def _check_sql_sink(self, call, candidate) -> None:
        method, sql_expression, tagged, receiver = candidate
        sink_key = (call.start_byte, call.end_byte)
        if sink_key in self.seen_sinks:
            return
        receiver_path = self._canonical_object_path(receiver)
        has_runtime_member = False
        runtime_member = (frozenset(), None)
        has_runtime_wildcard = False
        if receiver_path is not None:
            has_runtime_member, runtime_member = self._lookup_explicit(
                f"{receiver_path}.{method}"
            )
            has_runtime_wildcard, _ = self._lookup_explicit(f"{receiver_path}.*")

        local_callable = (
            self._resolve_callable(runtime_member[1])
            if has_runtime_member and not has_runtime_wildcard
            else self._object_member_callable(receiver, method)
        )
        runtime_member_changed = bool(
            has_runtime_member
            and (has_runtime_wildcard or local_callable is None or runtime_member[0])
        )
        local_callable_mutated = bool(
            runtime_member_changed
            or (
                local_callable is not None
                and self._member_callable_is_mutated(receiver, method, call)
            )
        )
        if local_callable is not None and not local_callable_mutated:
            if self._callable_is_console_only(local_callable):
                self.safe_sink_spans.add(sink_key)
            return
        if not local_callable_mutated and not self._receiver_has_sql_provenance(
            receiver
        ):
            return
        if self._is_parameterized_sql_expression(call):
            self.safe_sink_spans.add(sink_key)
            return
        if self._is_parameterized_sql_expression(sql_expression):
            self.safe_sink_spans.add(sink_key)
            return
        if tagged and self._is_proven_parameterizing_tag(call, method, receiver):
            self.safe_sink_spans.add(sink_key)
            return
        query_config_status = self._query_config_status(sql_expression)
        sources = self._visit_expression(sql_expression)
        if not sources:
            if self._is_proven_trusted_sql_value(sql_expression):
                self.safe_sink_spans.add(sink_key)
            return
        unsafe_method = method in _UNSAFE_SQL_TAGS or method in {"raw", "unsafe"}
        if (
            not unsafe_method
            and query_config_status != "tainted_text"
            and not self._has_sql_keyword(sql_expression)
            and not self._is_whole_sql_text_source(sql_expression)
        ):
            return
        self.seen_sinks.add(sink_key)
        line = sql_expression.start_point[0] + 1
        source_names = sorted(sources)[:4]
        source_label = ", ".join(f"`{name}`" for name in source_names)
        self.findings.append(
            {
                "rule_id": "SKY-D281",
                "severity": "CRITICAL",
                "message": (
                    f"Untrusted Server Action input {source_label} reaches SQL "
                    f"text via `.{method}()`. Use a parameterized query."
                ),
                "file": self.file_path,
                "line": line,
                "col": sql_expression.start_point[1],
                "_d281_sink_span": (call.start_byte, call.end_byte),
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "server_action_sql_taint",
                        "source": "Server Action parameter(s): "
                        + ", ".join(source_names),
                        "sink": f".{method} SQL text argument",
                        "path": [
                            "untrusted action input reaches SQL expression at "
                            f"line {line}"
                        ],
                        "guards_seen": [],
                        "guards_missing": ["parameterized SQL binding"],
                        "confidence_reason": (
                            "A lexical taint path from a Server Action parameter "
                            "reaches SQL text rather than a bound-value argument."
                        ),
                        "test_hint": (
                            "Submit SQL metacharacters through the named action "
                            "input and verify the driver treats them as data."
                        ),
                        "fix_shape": (
                            "replace SQL text construction with placeholders and "
                            "bound parameters"
                        ),
                        "analysis_complete": False,
                        "analysis_diagnostics": [],
                    }
                },
            }
        )

    def _has_sql_keyword(self, expression) -> bool:
        fragments = self._sql_fragments(expression)
        compact_text = "".join(fragments)
        spaced_text = " ".join(fragments)
        return any(
            re.search(
                rf"\b{re.escape(keyword)}\b",
                compact_text,
                re.IGNORECASE,
            )
            or re.search(
                rf"\b{re.escape(keyword)}\b",
                spaced_text,
                re.IGNORECASE,
            )
            for keyword in _SQL_KEYWORDS
        )

    def _sql_fragments(self, root) -> list[str]:
        fragments: list[str] = []
        stack: list[tuple[object, frozenset[str]]] = (
            [(root, frozenset())] if root is not None else []
        )
        visited = 0
        while stack and visited < self._MAX_DEPTH_FALLBACK_NODES:
            visited += 1
            node, seen = stack.pop()
            node = _unwrap_ts_expression(node)
            if node is None:
                continue
            if node.type == "string":
                text = _get_text(self.source, node)
                fragments.append(text[1:-1] if len(text) >= 2 else text)
                continue
            if node.type == "string_fragment":
                fragments.append(_get_text(self.source, node))
                continue
            if node.type == "identifier":
                name = _get_text(self.source, node)
                if name in seen:
                    continue
                value = self._lookup(name)[1]
                if value is not None:
                    stack.append((value, seen | {name}))
                continue

            ordered_children: list = []
            if node.type == "call_expression":
                function = _unwrap_ts_expression(node.child_by_field_name("function"))
                local_function = self._resolve_callable(function)
                function_key = (
                    f"@function:{local_function.start_byte}:{local_function.end_byte}"
                    if local_function is not None
                    else ""
                )
                if local_function is not None and function_key not in seen:
                    return_values = self._callable_return_expressions(local_function)
                    stack.extend(
                        (value, seen | {function_key})
                        for value in reversed(return_values)
                    )
                    continue
                if function is not None and function.type == "member_expression":
                    receiver = function.child_by_field_name("object")
                    if receiver is not None:
                        ordered_children.append(receiver)
                arguments = node.child_by_field_name("arguments")
                if arguments is not None:
                    if arguments.type == "template_string":
                        ordered_children.append(arguments)
                    else:
                        ordered_children.extend(arguments.named_children)
            elif node.type in {"member_expression", "subscript_expression"}:
                receiver = node.child_by_field_name("object")
                if receiver is not None:
                    ordered_children.append(receiver)
                if node.type == "subscript_expression":
                    index = node.child_by_field_name("index")
                    if index is not None:
                        ordered_children.append(index)
            else:
                ordered_children.extend(
                    child
                    for child in node.named_children
                    if not child.type.endswith("_type")
                    and child.type
                    not in {
                        "type_annotation",
                        "predefined_type",
                        "type_identifier",
                    }
                )
            stack.extend((child, seen) for child in reversed(ordered_children))

        if stack:
            self.analysis_complete = False
            if "D281 SQL-fragment budget exhausted" not in self.diagnostics:
                self.diagnostics.append("D281 SQL-fragment budget exhausted")
        return fragments

    def _is_proven_parameterizing_tag(self, call, method: str, receiver) -> bool:
        if method not in self._SAFE_PRISMA_TAGS:
            return False
        arguments = call.child_by_field_name("arguments")
        if self._contains_tainted_raw_sql_escape(arguments):
            return False
        receiver = _unwrap_ts_expression(receiver)
        if receiver is None or receiver.type != "identifier":
            return False
        receiver_name = _get_text(self.source, receiver)
        constructor_name = ""
        proven_receiver = receiver_name in self.prisma_instances
        if not proven_receiver:
            bound_value = self._lookup(receiver_name)[1]
            value = _unwrap_ts_expression(bound_value)
            if value is not None and value.type == "new_expression":
                constructor = _unwrap_ts_expression(
                    value.child_by_field_name("constructor")
                )
                if constructor is not None and constructor.type == "identifier":
                    constructor_name = _get_text(self.source, constructor)
                    seen_constructors: set[str] = set()
                    for _ in range(32):
                        if constructor_name in self.prisma_constructors:
                            proven_receiver = True
                            break
                        if constructor_name in seen_constructors:
                            break
                        seen_constructors.add(constructor_name)
                        alias_value = _unwrap_ts_expression(
                            self._lookup(constructor_name)[1]
                        )
                        if alias_value is None or alias_value.type != "identifier":
                            break
                        constructor_name = _get_text(self.source, alias_value)
        if not proven_receiver:
            return False

        aliases = {receiver_name}
        changed = True
        while changed and len(aliases) <= 32:
            changed = False
            visible_values = dict(self.module_values)
            for frame in self.frames:
                visible_values.update(
                    {
                        name: value
                        for name, (_, value) in frame.items()
                        if value is not None
                    }
                )
            for name, alias_value in visible_values.items():
                alias_value = _unwrap_ts_expression(alias_value)
                if alias_value is None or alias_value.type != "identifier":
                    continue
                if (
                    _get_text(self.source, alias_value) in aliases
                    and name not in aliases
                ):
                    aliases.add(name)
                    changed = True
        protected = aliases | ({constructor_name} if constructor_name else set())
        for mutation_byte, target, is_module_level, _scope_key in self.mutations:
            if not is_module_level and mutation_byte >= call.start_byte:
                continue
            if any(
                target == name
                or target.startswith(name + ".")
                or target.startswith(name + "[")
                for name in protected
            ):
                return False
        return True


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
                if not (
                    _is_null_literal_expression(left)
                    or _is_null_literal_expression(right)
                ):
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
