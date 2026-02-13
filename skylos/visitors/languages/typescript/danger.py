from tree_sitter import Language, QueryCursor
import tree_sitter_typescript as tsts

try:
    TS_LANG = Language(tsts.language_typescript())
except:
    TS_LANG = None


def scan_danger(root_node, file_path):
    findings = []
    if not TS_LANG:
        return []

    def check(pattern, cap_name, rule, sev, msg):
        try:
            query = TS_LANG.query(pattern)
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

    # document.write
    check(
        '(call_expression function: (member_expression property: (property_identifier) @dw (#eq? @dw "write") object: (identifier) @obj (#eq? @obj "document")))',
        "dw",
        "SKY-D503",
        "HIGH",
        "document.write() can lead to XSS vulnerabilities",
    )

    # new Function()
    check(
        '(new_expression constructor: (identifier) @fn (#eq? @fn "Function"))',
        "fn",
        "SKY-D504",
        "CRITICAL",
        "new Function() is equivalent to eval()",
    )

    # setTimeout/setInterval with string argument
    for fn_name in ("setTimeout", "setInterval"):
        check(
            f'(call_expression function: (identifier) @timer (#eq? @timer "{fn_name}") arguments: (arguments (string) @str))',
            "str",
            "SKY-D505",
            "HIGH",
            f"{fn_name}() with string argument is equivalent to eval()",
        )

    # child_process.exec (Node.js command injection)
    check(
        '(call_expression function: (member_expression property: (property_identifier) @exec (#eq? @exec "exec")))',
        "exec",
        "SKY-D506",
        "HIGH",
        "child_process.exec() can lead to command injection. Use execFile() instead.",
    )

    # outerHTML assignment (similar to innerHTML)
    check(
        '(assignment_expression left: (member_expression property: (property_identifier) @oh (#eq? @oh "outerHTML")))',
        "oh",
        "SKY-D507",
        "HIGH",
        "Unsafe outerHTML assignment",
    )

    return findings
