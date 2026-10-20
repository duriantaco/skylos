from __future__ import annotations

import re
import tree_sitter_typescript as tsts
from tree_sitter import Language, Query, QueryCursor

from skylos.constants import get_non_library_dir_kind

from .quality_signals import scan_quality_signals
from .type_safety import _is_generated_file, scan_type_safety

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
    "function_expression",
    "generator_function",
    "generator_function_declaration",
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

_QUERY_CACHE: dict[tuple[int, str], Query] = {}

_FUNC_PATTERN = """
(function_declaration) @func
(function_expression) @func
(generator_function) @func
(generator_function_declaration) @func
(arrow_function) @func
(method_definition) @func
"""

_AWAIT_PATTERN = "(await_expression) @await_expr"
_CONDITION_PREVIEW_LIMIT = 120
_TEST_CALLBACK_CALLS = frozenset(
    {"test", "it", "describe", "suite", "specify", "context"}
)
_TEST_CALLBACK_MODIFIERS = frozenset(
    {
        "only",
        "skip",
        "todo",
        "concurrent",
        "serial",
        "sequential",
        "failing",
        "each",
        "describe",
    }
)
_TEST_FUNCTION_NODES = frozenset(
    {
        "arrow_function",
        "function",
        "function_expression",
        "function_declaration",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)


def _get_query(lang: Language, key: str, pattern: str) -> Query | None:
    cache_key = (id(lang), key)
    if cache_key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[cache_key] = Query(lang, pattern)
        except Exception:
            _QUERY_CACHE[cache_key] = None
    return _QUERY_CACHE[cache_key]


_BINDING_NAME_FIELDS = {
    "variable_declarator": "name",
    "pair": "key",
    "public_field_definition": "name",
    "field_definition": "property",
    "assignment_expression": "left",
}


def _get_func_name(func_node, source: bytes) -> str:
    """The declared name, or the variable/property/field the function is bound to."""
    try:
        name_node = func_node.child_by_field_name("name")
        if name_node is None:
            parent = func_node.parent
            field = (
                _BINDING_NAME_FIELDS.get(parent.type) if parent is not None else None
            )
            if field is not None:
                value = parent.child_by_field_name(
                    "right" if parent.type == "assignment_expression" else "value"
                )
                if value is None or value.id == func_node.id:
                    name_node = parent.child_by_field_name(field)
        if name_node is not None:
            name = source[name_node.start_byte : name_node.end_byte].decode(
                "utf-8", errors="replace"
            )
            return name.strip("\"'`") or "anonymous"
    except Exception:
        pass
    return "anonymous"


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
    stack = [(node, depth)]

    while stack:
        current, current_depth = stack.pop()
        for child in current.children:
            if child.type in _FUNC_BOUNDARY_NODES:
                continue
            # `else if` continues the same chain: it is not a deeper block.
            else_if = child.type == "if_statement" and current.type == "else_clause"
            child_depth = (
                current_depth + 1
                if child.type in NESTING_NODES and not else_if
                else current_depth
            )
            if child_depth > max_depth:
                max_depth = child_depth
            stack.append((child, child_depth))

    return max_depth


_LOGICAL_OPERATORS = frozenset({"&&", "||", "??"})
_COGNITIVE_NESTING_NODES = frozenset(
    {
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "catch_clause",
        "ternary_expression",
    }
)


def _logical_operator(node):
    if node is None or node.type != "binary_expression":
        return None
    operator = node.child_by_field_name("operator")
    return (
        operator.type
        if operator is not None and operator.type in _LOGICAL_OPERATORS
        else None
    )


def _logical_sequence(node, out: list) -> None:
    # Flat operator chains are left-deep ASTs; source length must not consume
    # Python's call stack. Keep the same left-to-right operator sequence.
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            out.append(current)
            continue
        operator = _logical_operator(current)
        if operator is not None:
            pending.extend(
                (
                    current.child_by_field_name("right"),
                    operator,
                    current.child_by_field_name("left"),
                )
            )


def _cognitive_complexity(func_node) -> int:
    """Sonar cognitive complexity: structures cost 1 plus their nesting;
    `else if`/`else` cost 1; each run of one logical operator costs 1;
    nested functions add a nesting level, as in the Python rule."""
    total = 0
    pending = [(child, 0) for child in reversed(func_node.children)]
    while pending:
        node, nesting = pending.pop()
        kind = node.type
        children = list(node.children)
        if kind in _FUNC_BOUNDARY_NODES:
            pending.extend((child, nesting + 1) for child in reversed(children))
            continue
        if kind == "if_statement":
            is_else_if = node.parent is not None and node.parent.type == "else_clause"
            total += 1 if is_else_if else 1 + nesting
            alternative = node.child_by_field_name("alternative")
            for child in reversed(children):
                if alternative is not None and child.id == alternative.id:
                    inner = [c for c in child.named_children]
                    if inner and inner[0].type == "if_statement":
                        pending.append((inner[0], nesting))
                    else:
                        total += 1
                        pending.extend(
                            (c, nesting + 1) for c in reversed(child.children)
                        )
                elif child.type == "parenthesized_expression":
                    pending.append((child, nesting))
                else:
                    pending.append((child, nesting + 1))
            continue
        if kind in _COGNITIVE_NESTING_NODES:
            total += 1 + nesting
            pending.extend((child, nesting + 1) for child in reversed(children))
            continue
        if (
            _logical_operator(node) is not None
            and _logical_operator(node.parent) is None
        ):
            operators: list = []
            _logical_sequence(node, operators)
            total += 1 + sum(1 for a, b in zip(operators, operators[1:]) if a != b)
        if (
            kind in {"break_statement", "continue_statement"}
            and node.child_by_field_name("label") is not None
        ):
            total += 1
        pending.extend((child, nesting) for child in reversed(children))
    return total


def _code_line_count(func_node, source: bytes) -> int:
    """Lines with code: blank lines and comment-only lines are not counted."""
    # The parser distinguishes comments from comment-like text in strings,
    # templates and regular expressions. Preserve newlines when masking only
    # its comment spans, including code after a closing block comment.
    start, end = func_node.start_byte, func_node.end_byte
    comments = []
    pending = [func_node]
    while pending:
        node = pending.pop()
        if node.type == "comment":
            comments.append((node.start_byte, node.end_byte))
        else:
            pending.extend(node.named_children)
    pieces = []
    position = start
    for left, right in sorted(comments):
        pieces.append(source[position:left])
        pieces.append(re.sub(rb"[^\r\n]", b" ", source[left:right]))
        position = right
    pieces.append(source[position:end])
    return sum(bool(line.strip()) for line in b"".join(pieces).splitlines())


_TEST_FILE_NAME = re.compile(r"\.(?:spec|test|e2e|cy)\.[cm]?[jt]sx?$", re.IGNORECASE)
_TEST_FILE_DIRS = frozenset(
    {"__tests__", "__mocks__", "test", "tests", "e2e", "cypress"}
)


def _is_js_test_file(file_path) -> bool:
    from .conventions import is_expo_router_file
    from .nextjs import is_nextjs_project_entry_file, is_nextjs_project_pages_file

    # A URL segment called tests does not make a shipped framework route a
    # test suite. This classification is only for the narrow callback-length
    # exception; raw metrics remain available for every test-file function.
    if (
        is_nextjs_project_entry_file(str(file_path))
        or is_nextjs_project_pages_file(str(file_path))
        or is_expo_router_file(file_path)
    ):
        return False
    path = str(file_path).replace("\\", "/")
    parts = [part.lower() for part in path.split("/")]
    return (
        get_non_library_dir_kind(file_path) == "test"
        or bool(_TEST_FILE_NAME.search(parts[-1]))
        or bool(_TEST_FILE_DIRS.intersection(parts[:-1]))
    )


def _param_count(func_node) -> int:
    params = func_node.child_by_field_name("parameters")
    if not params:
        return 0
    count = 0
    for child in params.children:
        if child.type not in ("(", ")", ","):
            count += 1
    return count


def _is_test_callback_call(callee, source: bytes) -> bool:
    """Recognize a test DSL call, including common modifiers and `.each` calls."""
    if callee.type == "call_expression":
        callee = callee.child_by_field_name("function")
        if callee is None or callee.type != "member_expression":
            return False
        property_node = callee.child_by_field_name("property")
        if property_node is None or _get_text(source, property_node) != "each":
            return False

    modifiers: list[str] = []
    while callee is not None and callee.type == "member_expression":
        property_node = callee.child_by_field_name("property")
        if property_node is None:
            return False
        modifier = _get_text(source, property_node)
        if modifier not in _TEST_CALLBACK_MODIFIERS:
            return False
        modifiers.append(modifier)
        callee = callee.child_by_field_name("object")

    if callee is None or callee.type != "identifier":
        return False
    root = _get_text(source, callee)
    if "describe" in modifiers and (
        root != "test"
        or modifiers.count("describe") != 1
        or modifiers[-1] != "describe"
    ):
        return False
    return root in _TEST_CALLBACK_CALLS


def _is_nested_subtest_call(callee, func_node, source: bytes) -> bool:
    """Match `t.test(...)` only when `t` is the enclosing test's context."""
    if callee.type != "member_expression":
        return False
    obj = callee.child_by_field_name("object")
    prop = callee.child_by_field_name("property")
    if (
        obj is None
        or obj.type != "identifier"
        or prop is None
        or _get_text(source, prop) != "test"
    ):
        return False

    enclosing = func_node.parent
    while enclosing is not None and enclosing.type not in _TEST_FUNCTION_NODES:
        enclosing = enclosing.parent
    if enclosing is None or enclosing.type != "arrow_function":
        return False

    param = enclosing.child_by_field_name("parameter")
    if param is None:
        params = enclosing.child_by_field_name("parameters")
        if params is None or not params.named_children:
            return False
        param = params.named_children[0]
        if param.type != "identifier":
            param = param.child_by_field_name("pattern")
    return (
        param is not None
        and param.type == "identifier"
        and _get_text(source, param) == _get_text(source, obj)
        and _is_test_callback(enclosing, source)
    )


def _is_test_callback(func_node, source: bytes) -> bool:
    """Limit the length exemption to a test or suite's direct callback."""
    arguments = func_node.parent
    if arguments is None or arguments.type != "arguments":
        return False
    call = arguments.parent
    if call is None or call.type != "call_expression":
        return False
    args = arguments.named_children
    callback_index = next(
        (index for index, argument in enumerate(args) if argument.id == func_node.id),
        -1,
    )
    if callback_index < 0:
        return False
    if len(args) == 1:
        if callback_index != 0:
            return False
    elif (
        args[0].type not in {"string", "template_string"}
        or callback_index not in (1, 2)
        or len(args) - callback_index not in (1, 2)
        or (
            len(args) - callback_index == 2
            and args[-1].type in {"arrow_function", "function_expression"}
        )
    ):
        return False
    callee = call.child_by_field_name("function")
    return callee is not None and (
        _is_test_callback_call(callee, source)
        or _is_nested_subtest_call(callee, func_node, source)
    )


def scan_quality(
    root_node,
    source: bytes,
    file_path: str,
    threshold: int = 10,
    max_nesting: int = 4,
    max_length: int = 50,
    max_params: int = 5,
    lang: Language | None = None,
    measurement: dict | None = None,
    cognitive_threshold: int = 15,
) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = TS_LANG
    if not lang:
        return []

    func_nodes = _get_func_nodes(root_node, lang)
    is_test_file = _is_js_test_file(file_path)
    if measurement is not None:
        measurement.update(
            {
                "language": "TypeScript"
                if str(file_path).endswith((".ts", ".tsx", ".mts", ".cts"))
                else "JavaScript",
                "function_lines": [node.start_point[0] + 1 for node in func_nodes],
                "rule_units": {
                    "SKY-Q301": len(func_nodes),
                    "SKY-Q302": len(func_nodes),
                    "SKY-C303": len(func_nodes),
                    "SKY-C304": sum(
                        not (is_test_file and _is_test_callback(node, source))
                        for node in func_nodes
                    ),
                },
            }
        )

    # Keep test helpers and unrelated callbacks measurable. Only the existing
    # proven test/suite callback length exception applies below.
    generated_file = _is_generated_file(file_path, source)
    # The type-safety hint also accepts folder/header conventions. Those do
    # not prove that a real function should lose its metric observations.
    # Repository-level generated exclusions are handled by scan discovery.
    for func_node in func_nodes:
        line: int = func_node.start_point[0] + 1
        name = _get_func_name(func_node, source)

        complexity = _calc_complexity(func_node)
        if complexity > threshold:
            findings.append(
                {
                    "rule_id": "SKY-Q301",
                    "value": complexity,
                    "threshold": threshold,
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has cyclomatic complexity {complexity} (limit: {threshold})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                    "name": name,
                    "simple_name": name,
                }
            )

        nesting = _max_nesting(func_node)
        if nesting > max_nesting:
            findings.append(
                {
                    "rule_id": "SKY-Q302",
                    "value": nesting,
                    "threshold": max_nesting,
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has nesting depth {nesting} (limit: {max_nesting})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                    "name": name,
                    "simple_name": name,
                }
            )

        cognitive = _cognitive_complexity(func_node)
        if cognitive > cognitive_threshold:
            findings.append(
                {
                    "rule_id": "SKY-Q306",
                    "value": cognitive,
                    "threshold": cognitive_threshold,
                    "severity": "MEDIUM",
                    "message": f"Function '{name}' has cognitive complexity {cognitive} (limit: {cognitive_threshold})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                    "name": name,
                    "simple_name": name,
                }
            )

        func_length: int = _code_line_count(func_node, source)
        if func_length > max_length and not (
            is_test_file and _is_test_callback(func_node, source)
        ):
            findings.append(
                {
                    "rule_id": "SKY-C304",
                    "value": func_length,
                    "threshold": max_length,
                    "severity": "LOW",
                    "message": f"Function '{name}' has {func_length} code lines (limit: {max_length}); blank and comment lines are not counted",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                    "name": name,
                    "simple_name": name,
                }
            )

        params = _param_count(func_node)
        if params > max_params:
            findings.append(
                {
                    "rule_id": "SKY-C303",
                    "value": params,
                    "threshold": max_params,
                    "severity": "LOW",
                    "message": f"Function '{name}' has {params} parameters (limit: {max_params})",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                    "name": name,
                    "simple_name": name,
                }
            )

    # --- Duplicate condition in if-else chain (SKY-Q305) ---
    _check_duplicate_conditions(root_node, source, file_path, findings)

    # --- Await in loop (SKY-Q402) ---
    _check_await_in_loop(root_node, source, file_path, findings, lang)

    # --- Unreachable code (SKY-UC002) ---
    _check_unreachable_code(root_node, source, file_path, findings)

    # --- Type-evidence bypasses (SKY-T103 through SKY-T106) ---
    findings.extend(
        scan_type_safety(
            root_node,
            source,
            file_path,
            lang,
            generated_file=generated_file,
        )
    )

    # --- Concrete generated-code quality mistakes ---
    findings.extend(
        scan_quality_signals(
            root_node,
            source,
            file_path,
            lang,
            generated_file=generated_file,
        )
    )

    return findings


def _calc_complexity(node) -> int:
    count = 1
    stack = [node]
    while stack:
        current = stack.pop()
        if current.id != node.id and current.type in _FUNC_BOUNDARY_NODES:
            continue
        if current.type in COMPLEXITY_NODES:
            count += 1
        stack.extend(current.children)
    return count


def _check_duplicate_conditions(
    root_node, source: bytes, file_path: str, findings: list[dict]
) -> None:
    """SKY-Q305: Detect identical condition expressions in if-else-if chains."""
    stack = [root_node]
    processed_chain_nodes: set[int] = set()
    while stack:
        node = stack.pop()
        if node.type == "if_statement" and node.id not in processed_chain_nodes:
            func_name = _enclosing_function_name(node, source)
            conditions: list[tuple[str, int]] = []
            current = node
            while current and current.type == "if_statement":
                processed_chain_nodes.add(current.id)
                cond = current.child_by_field_name("condition")
                if cond:
                    cond_text = _get_text(source, cond)
                    conditions.append((cond_text, cond.start_point[0] + 1))
                alt = current.child_by_field_name("alternative")
                if alt and alt.type == "else_clause":
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
                        preview = _condition_preview(cond_text)
                        finding = {
                            "rule_id": "SKY-Q305",
                            "severity": "MEDIUM",
                            "message": f"Duplicate condition '{preview}' in if-else chain (first seen at line {seen[cond_text]})",
                            "file": str(file_path),
                            "line": cond_line,
                            "col": 0,
                        }
                        if func_name:
                            finding["name"] = func_name
                            finding["simple_name"] = func_name
                        findings.append(finding)
                    else:
                        seen[cond_text] = cond_line

        for child in node.children:
            stack.append(child)


def _condition_preview(cond_text: str) -> str:
    if len(cond_text) <= _CONDITION_PREVIEW_LIMIT:
        return cond_text

    return cond_text[: _CONDITION_PREVIEW_LIMIT - 3] + "..."


def _enclosing_function_name(node, source: bytes) -> str | None:
    current = node.parent
    while current:
        if current.type in _FUNC_BOUNDARY_NODES:
            return _get_func_name(current, source)
        current = current.parent
    return None


def _check_await_in_loop(
    root_node, source: bytes, file_path: str, findings: list[dict], lang: Language
) -> None:
    """SKY-Q402: Review sequential awaits in loops that may be parallelizable."""
    query = _get_query(lang, "quality_await", _AWAIT_PATTERN)
    if query is None:
        return
    try:
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
    except Exception:
        return

    for node in captures.get("await_expr", []):
        func_name = _enclosing_function_name(node, source)
        current = node.parent
        while current:
            if current.type in _FUNC_BOUNDARY_NODES:
                break
            if current.type in _LOOP_NODES:
                if _is_clearly_serial_loop(current, node, source):
                    break
                finding = {
                    "rule_id": "SKY-Q402",
                    "severity": "LOW",
                    "message": (
                        "Sequential await in loop; consider bounded parallelism only "
                        "when iterations are independent and ordering and rate "
                        "limits allow."
                    ),
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
                if func_name:
                    finding["name"] = func_name
                    finding["simple_name"] = func_name
                findings.append(finding)
                break
            current = current.parent


def _is_clearly_serial_loop(loop, await_node, source: bytes) -> bool:
    """Exclude loop controls and common intentional serial or batched work."""
    body = loop.child_by_field_name("body")
    if body is None or not (body.start_byte <= await_node.start_byte < body.end_byte):
        return True
    if loop.type in {"while_statement", "do_statement"}:
        return True
    if loop.type == "for_in_statement" and any(
        child.type == "await" for child in loop.children
    ):
        return True
    if loop.type == "for_statement":
        condition = loop.child_by_field_name("condition")
        if condition is None or condition.type == "empty_statement":
            return True
    if _has_loop_exit(body, loop) or _is_batched_or_delayed_await(await_node, source):
        return True
    return False


def _has_loop_exit(body, loop) -> bool:
    """Find exits from this loop without attributing nested callables or loops."""
    stack = [body]
    while stack:
        current = stack.pop()
        if current.type in _FUNC_BOUNDARY_NODES:
            continue
        if current.type == "return_statement":
            return True
        if current.type in {"break_statement", "continue_statement"}:
            ancestor = current.parent
            while ancestor is not None and ancestor.id != loop.id:
                if ancestor.type in _LOOP_NODES or (
                    current.type == "break_statement"
                    and ancestor.type == "switch_statement"
                ):
                    break
                ancestor = ancestor.parent
            if ancestor is not None and ancestor.id == loop.id:
                return True
        stack.extend(current.children)
    return False


def _is_batched_or_delayed_await(await_node, source: bytes) -> bool:
    expression = next(iter(await_node.named_children), None)
    while expression is not None and expression.type == "parenthesized_expression":
        expression = next(iter(expression.named_children), None)
    if expression is None or expression.type != "call_expression":
        return False
    callee = expression.child_by_field_name("function")
    if callee is None:
        return False
    if callee.type == "identifier":
        return _get_text(source, callee).lower() in {
            "sleep",
            "delay",
            "backoff",
            "pause",
        }
    if callee.type == "member_expression":
        obj = callee.child_by_field_name("object")
        prop = callee.child_by_field_name("property")
        if obj is None or prop is None:
            return False
        if _get_text(source, obj) == "Promise" and _get_text(source, prop) in {
            "all",
            "allSettled",
        }:
            return True
        return _get_text(source, prop).lower() in {"sleep", "delay", "backoff", "pause"}
    return False


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
                    break
                if child.type in _TERMINATOR_TYPES:
                    found_terminator = True
        for child in node.children:
            stack.append(child)
