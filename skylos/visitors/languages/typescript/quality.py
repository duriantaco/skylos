from tree_sitter import Language, QueryCursor, Query
import tree_sitter_typescript as tsts

try:
    TS_LANG = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None

COMPLEXITY_NODES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "switch_case",
    "catch_clause",
    "ternary_expression",
}


def scan_quality(root_node, source, file_path, threshold=10):
    findings = []
    if not TS_LANG:
        return []

    func_nodes = []
    query_str = """
    (function_declaration) @func
    (arrow_function) @func
    (method_definition) @func
    """

    try:
        query = Query(TS_LANG, query_str)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        func_nodes = captures.get("func", [])
    except Exception:
        return []

    for func_node in func_nodes:
        complexity = _calc_complexity(func_node)

        if complexity > threshold:
            line = func_node.start_point[0] + 1
            name = "anonymous"
            try:
                name_node = func_node.child_by_field_name("name")
                if name_node:
                    name = source[name_node.start_byte : name_node.end_byte].decode(
                        "utf-8", errors="replace"
                    )
            except Exception:
                pass

            findings.append(
                {
                    "rule_id": "SKY-Q501",
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' is too complex ({complexity})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

    return findings


def _calc_complexity(node):
    count = 1
    cursor = node.walk()
    visited_children = False

    while True:
        if visited_children:
            if cursor.node.id == node.id:
                break
            if cursor.goto_next_sibling():
                visited_children = False
            elif cursor.goto_parent():
                visited_children = True
            else:
                break
        else:
            if cursor.node.type in COMPLEXITY_NODES:
                count += 1
            if cursor.goto_first_child():
                visited_children = False
            else:
                visited_children = True
    return count
