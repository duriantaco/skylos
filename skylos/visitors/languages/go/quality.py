from __future__ import annotations

from tree_sitter import Language, QueryCursor, Query

try:
    import tree_sitter_go as tsgo

    GO_LANG: Language | None = Language(tsgo.language())
except Exception:
    GO_LANG = None

COMPLEXITY_NODES: set[str] = {
    "if_statement",
    "for_statement",
    "expression_switch_statement",
    "type_switch_statement",
    "select_statement",
    "expression_case",
    "type_case",
    "default_case",
    "communication_case",
}

BOOL_OP_NODES: set[str] = {"binary_expression"}
BOOL_OPS: set[str] = {"&&", "||"}

NESTING_NODES: set[str] = {
    "if_statement",
    "for_statement",
    "expression_switch_statement",
    "type_switch_statement",
    "select_statement",
}

_FUNC_BOUNDARY_NODES: set[str] = {
    "function_declaration",
    "method_declaration",
    "func_literal",
}

_FUNC_PATTERN = """
(function_declaration) @func
(method_declaration) @func
"""

_QUERY_CACHE: dict[tuple[int, str], Query] = {}


def _get_query(lang: Language, key: str, pattern: str) -> Query | None:
    cache_key = (id(lang), key)
    if cache_key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[cache_key] = Query(lang, pattern)
        except Exception:
            _QUERY_CACHE[cache_key] = None
    return _QUERY_CACHE[cache_key]


def _get_func_name(func_node, source: bytes) -> str:
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


def _get_func_nodes(root_node, lang: Language) -> list:
    query = _get_query(lang, "go_quality_funcs", _FUNC_PATTERN)
    if query is None:
        return []
    try:
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        return captures.get("func", [])
    except Exception:
        return []


def _calc_complexity(node) -> int:
    count = 1
    stack = [node]
    while stack:
        current = stack.pop()
        for child in current.children:
            # Don't recurse into nested function literals
            if child.type == "func_literal":
                continue
            if child.type in COMPLEXITY_NODES:
                count += 1
            if child.type == "binary_expression":
                op_node = child.child_by_field_name("operator")
                if op_node and op_node.type in BOOL_OPS:
                    count += 1
            stack.append(child)
    return count


def _max_nesting(node, depth: int = 0) -> int:
    max_depth = depth
    for child in node.children:
        if child.type in _FUNC_BOUNDARY_NODES:
            continue
        if child.type in NESTING_NODES:
            child_max = _max_nesting(child, depth + 1)
            if child_max > max_depth:
                max_depth = child_max
        else:
            child_max = _max_nesting(child, depth)
            if child_max > max_depth:
                max_depth = child_max
    return max_depth


def _param_count(func_node) -> int:
    params = func_node.child_by_field_name("parameters")
    if not params:
        return 0
    count = 0
    for child in params.children:
        if child.type == "parameter_declaration":
            # Each name in a parameter_declaration is a separate param
            names = 0
            for sub in child.children:
                if sub.type == "identifier":
                    names += 1
            count += max(names, 1)
    return count


def scan_go_quality(
    root_node,
    source: bytes,
    file_path: str,
    threshold: int = 10,
    max_nesting: int = 4,
    max_length: int = 50,
    max_params: int = 5,
    lang: Language | None = None,
) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = GO_LANG
    if not lang:
        return []

    func_nodes = _get_func_nodes(root_node, lang)

    for func_node in func_nodes:
        line: int = func_node.start_point[0] + 1
        name = _get_func_name(func_node, source)

        complexity = _calc_complexity(func_node)
        if complexity > threshold:
            findings.append(
                {
                    "rule_id": "SKY-Q301",
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has cyclomatic complexity {complexity} (limit: {threshold})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        nesting = _max_nesting(func_node)
        if nesting > max_nesting:
            findings.append(
                {
                    "rule_id": "SKY-Q302",
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has nesting depth {nesting} (limit: {max_nesting})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        func_length: int = func_node.end_point[0] - func_node.start_point[0] + 1
        if func_length > max_length:
            findings.append(
                {
                    "rule_id": "SKY-C304",
                    "severity": "LOW",
                    "message": f"Function '{name}' is {func_length} lines long (limit: {max_length})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

        params = _param_count(func_node)
        if params > max_params:
            findings.append(
                {
                    "rule_id": "SKY-C303",
                    "severity": "LOW",
                    "message": f"Function '{name}' has {params} parameters (limit: {max_params})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

    return findings
