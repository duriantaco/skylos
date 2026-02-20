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


def scan_danger(root_node, file_path: str) -> list[dict]:
    findings: list[dict] = []
    if not TS_LANG:
        return []

    source_bytes: bytes = root_node.text

    def check(pattern: str, cap_name: str, rule: str, sev: str, msg: str) -> None:
        try:
            query = Query(TS_LANG, pattern)
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

    _check_exec(root_node, source_bytes, file_path, findings)

    check(
        '(assignment_expression left: (member_expression property: (property_identifier) @oh (#eq? @oh "outerHTML")))',
        "oh",
        "SKY-D507",
        "HIGH",
        "Unsafe outerHTML assignment",
    )

    return findings


def _check_exec(root_node, source: bytes, file_path: str, findings: list[dict]) -> None:
    pattern = '(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#eq? @prop "exec")))'
    try:
        query = Query(TS_LANG, pattern)
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
