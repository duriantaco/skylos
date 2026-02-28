from __future__ import annotations

from tree_sitter import Language, QueryCursor, Query
import tree_sitter_typescript as tsts

try:
    TS_LANG: Language | None = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None

COMPLEXITY_NODES: set[str] = {
    "if_statement",
    "for_statement",
    "while_statement",
    "switch_case",
    "catch_clause",
    "ternary_expression",
}


NESTING_NODES: set[str] = {
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
}

_LOOP_NODES: set[str] = {
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
}

_FUNC_BOUNDARY_NODES: set[str] = {
    "function_declaration",
    "arrow_function",
    "method_definition",
    "function",
}

_TERMINATOR_TYPES: set[str] = {
    "return_statement",
    "throw_statement",
    "break_statement",
    "continue_statement",
}

# Module-level query cache
_QUERY_CACHE: dict[tuple[int, str], Query] = {}

_FUNC_PATTERN = """
(function_declaration) @func
(arrow_function) @func
(method_definition) @func
"""

_AWAIT_PATTERN = "(await_expression) @await_expr"


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


def _get_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _get_func_nodes(root_node, lang: Language) -> list:
    query = _get_query(lang, "quality_funcs", _FUNC_PATTERN)
    if query is None:
        return []
    try:
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
        return captures.get("func", [])
    except Exception:
        return []


def _max_nesting(node, depth: int = 0) -> int:
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


def _param_count(func_node) -> int:
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
        lang = TS_LANG
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

    # --- Duplicate condition in if-else chain (SKY-Q305) ---
    _check_duplicate_conditions(root_node, source, file_path, findings)

    # --- Await in loop (SKY-Q402) ---
    _check_await_in_loop(root_node, source, file_path, findings, lang)

    # --- Unreachable code (SKY-UC002) ---
    _check_unreachable_code(root_node, source, file_path, findings)

    return findings


def _calc_complexity(node) -> int:
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


def _check_duplicate_conditions(
    root_node, source: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-Q305: Detect identical condition expressions in if-else-if chains."""
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "if_statement":
            conditions: list[tuple[str, int]] = []
            current = node
            while current and current.type == "if_statement":
                cond = current.child_by_field_name("condition")
                if cond:
                    cond_text = _get_text(source, cond)
                    conditions.append((cond_text, cond.start_point[0] + 1))
                # Find else clause → else if
                alt = current.child_by_field_name("alternative")
                if alt and alt.type == "else_clause":
                    # else_clause has children: 'else' keyword + the consequent
                    inner = None
                    for child in alt.children:
                        if child.type == "if_statement":
                            inner = child
                            break
                    current = inner
                else:
                    current = None

            if len(conditions) >= 2:
                seen: dict[str, int] = {}
                for cond_text, cond_line in conditions:
                    if cond_text in seen:
                        findings.append(
                            {
                                "rule_id": "SKY-Q305",
                                "severity": "MEDIUM",
                                "message": f"Duplicate condition '{cond_text}' in if-else chain (first seen at line {seen[cond_text]})",
                                "file": str(file_path),
                                "line": cond_line,
                                "col": 0,
                            }
                        )
                    else:
                        seen[cond_text] = cond_line

        for child in node.children:
            stack.append(child)


def _check_await_in_loop(
    root_node, source: bytes, file_path: str, findings: list[dict], lang: Language
) -> None:
    """SKY-Q402: Detect await expressions inside for/while loops."""
    query = _get_query(lang, "quality_await", _AWAIT_PATTERN)
    if query is None:
        return
    try:
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
    except Exception:
        return

    for node in captures.get("await_expr", []):
        # Walk up parents. If we hit a loop before a function boundary, flag it.
        current = node.parent
        while current:
            if current.type in _FUNC_BOUNDARY_NODES:
                break
            if current.type in _LOOP_NODES:
                findings.append(
                    {
                        "rule_id": "SKY-Q402",
                        "severity": "MEDIUM",
                        "message": "await inside loop — consider using Promise.all() for parallel execution.",
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
                break
            current = current.parent


def _check_unreachable_code(
    root_node, source: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-UC002: Flag statements after return/throw/break/continue in a block."""
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "statement_block":
            found_terminator = False
            for child in node.children:
                if child.type in ("{", "}"):
                    continue
                if found_terminator and child.type not in ("comment", "ERROR"):
                    findings.append(
                        {
                            "rule_id": "SKY-UC002",
                            "severity": "MEDIUM",
                            "message": "Unreachable code after return/throw/break/continue.",
                            "file": str(file_path),
                            "line": child.start_point[0] + 1,
                            "col": 0,
                        }
                    )
                    break  # Only flag once per block
                if child.type in _TERMINATOR_TYPES:
                    found_terminator = True
        for child in node.children:
            stack.append(child)
