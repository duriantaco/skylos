from __future__ import annotations

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


def _get_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def scan_danger(
    root_node, file_path: str, lang: "Language | None" = None
) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = TS_LANG
    if not lang:
        return []

    source_bytes: bytes = root_node.text

    def check(pattern: str, cap_name: str, rule: str, sev: str, msg: str) -> None:
        try:
            query = Query(lang, pattern)
            cursor = QueryCursor(query)
            captures = cursor.captures(root_node)
            nodes = captures.get(cap_name, [])

            for node in nodes:
                line = node.start_point[0] + 1
                findings.append(
                    {
                        "rule_id": rule,
                        "severity": sev,
                        "message": msg,
                        "file": str(file_path),
                        "line": line,
                        "col": 0,
                    }
                )
        except Exception:
            pass

    check(
        '(call_expression function: (identifier) @eval (#eq? @eval "eval"))',
        "eval",
        "SKY-D501",
        "CRITICAL",
        "Use of eval() detected",
    )

    check(
        '(assignment_expression left: (member_expression property: (property_identifier) @xss (#eq? @xss "innerHTML")))',
        "xss",
        "SKY-D502",
        "HIGH",
        "Unsafe innerHTML assignment",
    )

    check(
        '(call_expression function: (member_expression property: (property_identifier) @dw (#eq? @dw "write") object: (identifier) @obj (#eq? @obj "document")))',
        "dw",
        "SKY-D503",
        "HIGH",
        "document.write() can lead to XSS vulnerabilities",
    )

    check(
        '(new_expression constructor: (identifier) @fn (#eq? @fn "Function"))',
        "fn",
        "SKY-D504",
        "CRITICAL",
        "new Function() is equivalent to eval()",
    )

    for fn_name in ("setTimeout", "setInterval"):
        check(
            f'(call_expression function: (identifier) @timer (#eq? @timer "{fn_name}") arguments: (arguments (string) @str))',
            "str",
            "SKY-D505",
            "HIGH",
            f"{fn_name}() with string argument is equivalent to eval()",
        )

    _check_exec(root_node, source_bytes, file_path, findings, lang)

    check(
        '(assignment_expression left: (member_expression property: (property_identifier) @oh (#eq? @oh "outerHTML")))',
        "oh",
        "SKY-D507",
        "HIGH",
        "Unsafe outerHTML assignment",
    )

    # SKY-D509: dangerouslySetInnerHTML
    check(
        '(jsx_attribute (property_identifier) @attr (#eq? @attr "dangerouslySetInnerHTML"))',
        "attr",
        "SKY-D509",
        "HIGH",
        "dangerouslySetInnerHTML bypasses React's XSS protections",
    )

    # SKY-D510: Prototype pollution via __proto__
    check(
        '(member_expression property: (property_identifier) @proto (#eq? @proto "__proto__"))',
        "proto",
        "SKY-D510",
        "HIGH",
        "Prototype pollution via __proto__ access",
    )

    _check_hardcoded_secrets(root_node, source_bytes, file_path, findings)
    _check_fetch_ssrf(root_node, source_bytes, file_path, findings, lang)
    _check_weak_crypto(root_node, source_bytes, file_path, findings, lang)
    _check_open_redirect(root_node, source_bytes, file_path, findings, lang)
    _check_sql_template_injection(root_node, source_bytes, file_path, findings, lang)

    return findings


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


def _check_hardcoded_secrets(
    root_node, source: bytes, file_path: str, findings: list[dict]
) -> None:
    def _walk(node):
        if node.type in ("string", "template_string"):
            text = _get_text(source, node)
            if text and text[0] in ("'", '"', "`"):
                text = text[1:]
            if text and text[-1] in ("'", '"', "`"):
                text = text[:-1]
            if len(text) >= 16:
                for prefix in _SECRET_PREFIXES:
                    if text.startswith(prefix) or text.lower().startswith(
                        prefix.lower()
                    ):
                        findings.append(
                            {
                                "rule_id": "SKY-D508",
                                "severity": "CRITICAL",
                                "message": "Potential hardcoded secret or API key. Use environment variables instead.",
                                "file": str(file_path),
                                "line": node.start_point[0] + 1,
                                "col": 0,
                            }
                        )
                        return
        for child in node.children:
            _walk(child)

    _walk(root_node)


def _check_fetch_ssrf(
    root_node, source: bytes, file_path: str, findings: list[dict], lang=None
) -> None:
    """SKY-D511: Detect fetch/axios with variable URL (potential SSRF)."""
    if lang is None:
        lang = TS_LANG
    if not lang:
        return

    pattern = '(call_expression function: (identifier) @fn (#eq? @fn "fetch") arguments: (arguments) @args)'
    try:
        query = Query(lang, pattern)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        for node in captures.get("args", []):
            first_arg = None
            for child in node.children:
                if child.type not in ("(", ")", ","):
                    first_arg = child
                    break
            if first_arg and first_arg.type == "identifier":
                findings.append(
                    {
                        "rule_id": "SKY-D511",
                        "severity": "MEDIUM",
                        "message": "fetch() with variable URL — potential SSRF. Validate URL against allowlist.",
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
    except Exception:
        pass

    pattern2 = '(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj "axios")) arguments: (arguments) @args)'
    try:
        query = Query(lang, pattern2)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        for node in captures.get("args", []):
            first_arg = None
            for child in node.children:
                if child.type not in ("(", ")", ","):
                    first_arg = child
                    break
            if first_arg and first_arg.type == "identifier":
                findings.append(
                    {
                        "rule_id": "SKY-D511",
                        "severity": "MEDIUM",
                        "message": "axios call with variable URL — potential SSRF. Validate URL against allowlist.",
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
    except Exception:
        pass


def _check_weak_crypto(
    root_node, source: bytes, file_path: str, findings: list[dict], lang=None
) -> None:
    """SKY-D513: Detect crypto.createHash('md5') or crypto.createHash('sha1')."""
    if lang is None:
        lang = TS_LANG
    if not lang:
        return
    pattern = '(call_expression function: (member_expression property: (property_identifier) @prop (#eq? @prop "createHash")) arguments: (arguments) @args)'
    try:
        query = Query(lang, pattern)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        for node in captures.get("args", []):
            for child in node.children:
                if child.type == "string":
                    text = _get_text(source, child).strip("'\"")
                    if text in ("md5", "sha1"):
                        findings.append(
                            {
                                "rule_id": "SKY-D513",
                                "severity": "MEDIUM",
                                "message": f"Weak hash algorithm {text.upper()}. Use SHA-256 or better.",
                                "file": str(file_path),
                                "line": node.start_point[0] + 1,
                                "col": 0,
                            }
                        )
                    break
    except Exception:
        pass


def _check_open_redirect(
    root_node, source: bytes, file_path: str, findings: list[dict], lang=None
) -> None:
    """SKY-D515: Detect res.redirect(variable) — Express open redirect."""
    if lang is None:
        lang = TS_LANG
    if not lang:
        return
    pattern = '(call_expression function: (member_expression property: (property_identifier) @prop (#eq? @prop "redirect")) arguments: (arguments) @args)'
    try:
        query = Query(lang, pattern)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        for node in captures.get("args", []):
            first_arg = None
            for child in node.children:
                if child.type not in ("(", ")", ","):
                    first_arg = child
                    break
            if first_arg and first_arg.type not in (
                "string",
                "template_string",
                "number",
            ):
                findings.append(
                    {
                        "rule_id": "SKY-D515",
                        "severity": "HIGH",
                        "message": "Open redirect — res.redirect() with variable argument. Validate redirect target.",
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
    except Exception:
        pass


def _check_sql_template_injection(
    root_node, source: bytes, file_path: str, findings: list[dict], lang=None
) -> None:
    """SKY-D516: Detect SQL keywords in template literals passed to query/exec/execute."""
    if lang is None:
        lang = TS_LANG
    if not lang:
        return
    _SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP")
    for method_name in ("query", "exec", "execute"):
        pattern = f'(call_expression function: (member_expression property: (property_identifier) @prop (#eq? @prop "{method_name}")) arguments: (arguments (template_string) @tpl))'
        try:
            query = Query(lang, pattern)
            cursor = QueryCursor(query)
            captures = cursor.captures(root_node)
            for node in captures.get("tpl", []):
                text = _get_text(source, node).upper()
                if any(kw in text for kw in _SQL_KEYWORDS):
                    findings.append(
                        {
                            "rule_id": "SKY-D516",
                            "severity": "CRITICAL",
                            "message": "SQL query built with template literal — risk of SQL injection. Use parameterized queries.",
                            "file": str(file_path),
                            "line": node.start_point[0] + 1,
                            "col": 0,
                        }
                    )
        except Exception:
            pass


def _check_exec(
    root_node, source: bytes, file_path: str, findings: list[dict], lang=None
) -> None:
    if lang is None:
        lang = TS_LANG
    pattern = '(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#eq? @prop "exec")))'
    try:
        query = Query(lang, pattern)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        prop_nodes = captures.get("prop", [])
    except Exception:
        return

    for prop_node in prop_nodes:
        call_node = prop_node.parent
        if call_node is None:
            continue
        obj_node = call_node.child_by_field_name("object")
        if obj_node is None:
            continue

        obj_name = _get_text(source, obj_node).lower()

        if obj_name in _SAFE_EXEC_OBJECTS:
            continue

        line = prop_node.start_point[0] + 1
        findings.append(
            {
                "rule_id": "SKY-D506",
                "severity": "HIGH",
                "message": "child_process.exec() can lead to command injection. Use execFile() instead.",
                "file": str(file_path),
                "line": line,
                "col": 0,
            }
        )
