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

    return findings
