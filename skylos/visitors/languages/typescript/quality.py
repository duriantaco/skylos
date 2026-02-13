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


NESTING_NODES = {
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
}


def _get_func_name(func_node, source):
    name = "anonymous"
    try:
        name_node = func_node.child_by_field_name("name")
        if name_node:
            name = source[name_node.start_byte : name_node.end_byte].decode(
                "utf-8", errors="replace"
            )
    except Exception:
        pass
    return name


def _get_func_nodes(root_node):
    query_str = """
    (function_declaration) @func
    (arrow_function) @func
    (method_definition) @func
    """
    try:
        query = Query(TS_LANG, query_str)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        return captures.get("func", [])
    except Exception:
        return []


def _max_nesting(node, depth=0):
    max_depth = depth
    cursor = node.walk()
    visited = False
    while True:
        if visited:
            if cursor.node.id == node.id:
                break
            if cursor.goto_next_sibling():
                visited = False
            elif cursor.goto_parent():
                visited = True
            else:
                break
        else:
            current = cursor.node
            if current.id != node.id and current.type in NESTING_NODES:
                child_max = _max_nesting(current, depth + 1)
                if child_max > max_depth:
                    max_depth = child_max
                visited = True
                continue
            if cursor.goto_first_child():
                visited = False
            else:
                visited = True
    return max_depth


def _param_count(func_node):
    params = func_node.child_by_field_name("parameters")
    if not params:
        return 0
    count = 0
    for child in params.children:
        if child.type not in ("(", ")", ","):
            count += 1
    return count


def scan_quality(
    root_node,
    source,
    file_path,
    threshold=10,
    max_nesting=4,
    max_length=50,
    max_params=5,
):
    findings = []
    if not TS_LANG:
        return []

    func_nodes = _get_func_nodes(root_node)

    for func_node in func_nodes:
        line = func_node.start_point[0] + 1
        name = _get_func_name(func_node, source)

        # Cyclomatic complexity
        complexity = _calc_complexity(func_node)
        if complexity > threshold:
            findings.append(
                {
                    "rule_id": "SKY-Q601",
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has cyclomatic complexity {complexity} (limit: {threshold})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        # Nesting depth
        nesting = _max_nesting(func_node)
        if nesting > max_nesting:
            findings.append(
                {
                    "rule_id": "SKY-Q602",
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has nesting depth {nesting} (limit: {max_nesting})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        # Function length
        func_length = func_node.end_point[0] - func_node.start_point[0] + 1
        if func_length > max_length:
            findings.append(
                {
                    "rule_id": "SKY-Q603",
                    "severity": "LOW",
                    "message": f"Function '{name}' is {func_length} lines long (limit: {max_length})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        # Argument count
        params = _param_count(func_node)
        if params > max_params:
            findings.append(
                {
                    "rule_id": "SKY-Q604",
                    "severity": "LOW",
                    "message": f"Function '{name}' has {params} parameters (limit: {max_params})",
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
