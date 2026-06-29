from __future__ import annotations

import ast
import math
import re
import string
from tree_sitter import Language, Query, QueryCursor
import tree_sitter_java as tsj

from skylos.constants import (
    ENTROPY_THRESHOLD,
    MIN_LONG_SECRET_LENGTH,
    MIN_SECRET_LENGTH,
    get_non_library_dir_kind,
)
from skylos.visitors.languages.statement_scan import iter_semicolon_assignments
from skylos.visitors.languages.java.flow import scan_java_security_flows

try:
    JAVA_LANG: Language | None = Language(tsj.language())
except Exception:
    JAVA_LANG = None

_QUERY_CACHE: dict[tuple[int, str], Query] = {}

_SIMPLE_PATTERN = """
(method_invocation
  object: (identifier) @rt_obj
  name: (identifier) @rt_method
  (#eq? @rt_obj "Runtime")
  (#eq? @rt_method "exec"))

(method_invocation
  name: (identifier) @exec_method
  (#eq? @exec_method "exec")
  arguments: (argument_list) @exec_args)

(method_invocation
  object: (identifier) @proc_obj
  name: (identifier) @proc_start
  (#eq? @proc_start "start"))
"""

_SQL_PATTERN = """
(method_invocation
  name: (identifier) @sql_method
  (#match? @sql_method "^(executeQuery|executeUpdate|execute|prepareStatement)$")
  arguments: (argument_list) @sql_args)
"""

_CRYPTO_PATTERN = """
(method_invocation
  name: (identifier) @get_instance
  (#eq? @get_instance "getInstance")
  arguments: (argument_list (string_literal) @algo_str))
"""

_DESERIAL_PATTERN = """
(object_creation_expression
  type: (type_identifier) @ois_type
  (#eq? @ois_type "ObjectInputStream"))
"""

_STRING_PATTERN = """
(string_literal) @string_node
"""

_ARCHIVE_ENTRY_HINTS = (
    "ZipInputStream",
    "ZipEntry",
    "JarInputStream",
    "JarEntry",
    "TarArchiveInputStream",
    "TarArchiveEntry",
)

_ARCHIVE_NAME_HINTS = (".getName()", ".getRealName()")
_ARCHIVE_SINK_HINTS = (
    "new FileOutputStream(",
    "Files.copy(",
    "Files.write(",
    "Files.writeString(",
    "Files.newOutputStream(",
)

_ARCHIVE_SINK_ARGS = {
    "new FileOutputStream(": (0,),
    "Files.copy(": (1,),
    "Files.write(": (0,),
    "Files.writeString(": (0,),
    "Files.newOutputStream(": (0,),
}
_ARCHIVE_GUARD_HINTS = (
    ".normalize(",
    "normalize()",
    "toRealPath(",
    "getCanonicalPath(",
    "getCanonicalFile(",
)

_REQUEST_SOURCE_PATTERNS = (
    re.compile(
        r"(?ms)^\s*(?:[\w<>\[\],.?]+\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*(?:request|req)\.(?:getParameter|getPathInfo|getHeader)\s*\(",
    ),
    re.compile(
        r"@(?:RequestParam|PathVariable)(?:\([^)]*\))?\s+(?:final\s+)?(?:[\w<>\[\],.?]+\s+)*(?P<var>[A-Za-z_]\w*)",
        re.MULTILINE,
    ),
)

_REQUEST_PATH_SINK_PATTERNS = (
    "new FileInputStream(",
    "new FileReader(",
    "new FileOutputStream(",
    "Files.readAllBytes(",
    "Files.readString(",
    "Files.newInputStream(",
    "Files.newOutputStream(",
    "Files.copy(",
    "Files.write(",
    "Files.writeString(",
)

_REQUEST_SINK_ARGS = {
    "new FileInputStream(": (0,),
    "new FileReader(": (0,),
    "new FileOutputStream(": (0,),
    "Files.readAllBytes(": (0,),
    "Files.readString(": (0,),
    "Files.newInputStream(": (0,),
    "Files.newOutputStream(": (0,),
    "Files.copy(": (0, 1),
    "Files.write(": (0,),
    "Files.writeString(": (0,),
}

_REQUEST_GUARD_HINTS = (
    ".normalize(",
    "normalize()",
    "toRealPath(",
    "getCanonicalPath(",
    "getCanonicalFile(",
)

_REQUEST_INLINE_SOURCE_PATTERN = re.compile(
    r"\b(?:request|req)\.(?:getParameter|getPathInfo|getHeader)\s*\("
)

_CONTROL_FLOW_HINTS = ("throw ", "return", "continue", "break")
_STARTSWITH_CALL_PATTERN = re.compile(
    r"(?P<receiver>[A-Za-z_][\w.()]+)\.startsWith\s*\((?P<arg>[^)]*)\)"
)

_JAVA_ASSIGNMENT_PATTERN = re.compile(
    r"(?:(?:final)\s+)?(?:[\w.<>\[\],?]+\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);"
)
_JAVA_CONST_INT_PATTERN = re.compile(
    r"\b(?:final\s+)?(?:int|long)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<value>-?\d+)\s*;"
)
_JAVA_ENHANCED_FOR_PATTERN = re.compile(
    r"\bfor\s*\([^:;]+?\b(?P<var>[A-Za-z_]\w*)\s*:\s*(?P<src>[A-Za-z_]\w*)\s*\)"
)
_JAVA_REQUEST_SOURCE_RE = re.compile(
    r"\b(?:request|req)\.(?:getParameter|getPathInfo|getHeader|getHeaders|getHeaderNames|getParameterMap|getParameterValues|getParameterNames|getCookies|getQueryString)\s*\("
)
_JAVA_COOKIE_CREATION_RE = re.compile(
    r"\b(?:javax\.servlet\.http\.)?Cookie\s+(?P<var>[A-Za-z_]\w*)\s*=\s*new\s+(?:javax\.servlet\.http\.)?Cookie\s*\("
)
_JAVA_LIST_ADD_RE = re.compile(r"\b(?P<var>[A-Za-z_]\w*)\.add\s*\((?P<expr>.*)\)\s*;")
_JAVA_LIST_GET_RE = re.compile(r"\b(?P<var>[A-Za-z_]\w*)\.get\s*\((?P<index>\d+)\)")
_JAVA_LIST_REMOVE_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\.remove\s*\((?P<index>\d+)\)"
)
_JAVA_MAP_PUT_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\.put\s*\(\s*\"(?P<key>[^\"]+)\"\s*,\s*(?P<expr>.*)\)\s*;"
)
_JAVA_MAP_GET_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\.get\s*\(\s*\"(?P<key>[^\"]+)\"\s*\)"
)
_JAVA_METHOD_CALL_RE = re.compile(
    r"\b(?P<receiver>[A-Za-z_]\w*)\.(?P<method>[A-Za-z_]\w*)\s*\((?P<args>.*)\)\s*;"
)
_JAVA_METHOD_INVOCATION_RE = re.compile(
    r"(?:\b(?P<receiver>[A-Za-z_]\w*)|new\s+(?P<new_class>[\w.]+)\s*\([^)]*\))\.(?P<method>[A-Za-z_]\w*)\s*\((?P<args>[^;]*)\)"
)
_JAVA_PROCESS_BUILDER_RE = re.compile(
    r"\b(?:ProcessBuilder|java\.lang\.ProcessBuilder)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*new\s+(?:ProcessBuilder|java\.lang\.ProcessBuilder)\s*\((?P<args>.*)\)\s*;"
)
_JAVA_NEW_OBJECT_RE = re.compile(
    r"\b(?:[\w.<>\[\],?]+\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*new\s+(?P<class>[\w.]+)\s*\((?P<args>[^;]*)\)\s*;"
)
_JAVA_PATH_SINK_HINTS = (
    "new FileInputStream(",
    "new java.io.FileInputStream(",
    "new FileOutputStream(",
    "new java.io.FileOutputStream(",
    "new FileReader(",
    "new java.io.FileReader(",
    "new File(",
    "new java.io.File(",
    "Files.readAllBytes(",
    "java.nio.file.Files.readAllBytes(",
    "Files.readString(",
    "java.nio.file.Files.readString(",
    "Files.newInputStream(",
    "java.nio.file.Files.newInputStream(",
    "Files.newOutputStream(",
    "java.nio.file.Files.newOutputStream(",
    "Files.write(",
    "java.nio.file.Files.write(",
    "Files.writeString(",
    "java.nio.file.Files.writeString(",
    "Paths.get(",
    "java.nio.file.Paths.get(",
)
_JAVA_SQL_SINK_ARGS = {
    ".prepareCall(": (0,),
    ".prepareStatement(": (0,),
    ".executeQuery(": (0,),
    ".executeUpdate(": (0,),
    ".execute(": (0,),
}
_JAVA_LDAP_SINK_ARGS = {
    ".search(": (1,),
}
_JAVA_XSS_WRITER_METHODS = (".print(", ".println(", ".printf(", ".format(", ".write(")
_JAVA_XSS_SANITIZER_HINTS = (
    "encodeForHTML(",
    "encodeForHtml(",
    "Encode.forHtml(",
    "escapeHtml(",
    "htmlEscape(",
)

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

_SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP")

def _base64_alphabet(extra: str) -> str:
    return string.ascii_uppercase + string.ascii_lowercase + string.digits + extra


_BASE64_CHARS = set(_base64_alphabet("+/=-_"))
_KNOWN_NON_SECRET_ALPHABETS = {
    _base64_alphabet("+/="),
    _base64_alphabet("+/"),
    _base64_alphabet("-_="),
    _base64_alphabet("-_"),
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_known_non_secret_alphabet(value: str) -> bool:
    return value in _KNOWN_NON_SECRET_ALPHABETS


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


def _run_batch(root_node, lang: Language, key: str, pattern: str) -> dict[str, list]:
    query = _get_query(lang, key, pattern)
    if query is None:
        return {}
    try:
        cursor = QueryCursor(query)
        return cursor.captures(root_node)
    except Exception:
        return {}


def _iter_nodes(root_node):
    stack = [root_node]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _names_in_line(line: str, names: set[str]) -> set[str]:
    return {name for name in names if re.search(rf"\b{re.escape(name)}\b", line)}


def _line_mentions_names(line: str, names: set[str]) -> bool:
    return bool(_names_in_line(line, names))


def _guard_block_contains_sink(lines: list[str], guard_idx: int, sink_idx: int) -> bool:
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


def _guard_without_braces_contains_sink(
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


def _collect_canonical_string_vars(lines: list[str]) -> tuple[set[str], set[str]]:
    canonical_vars: set[str] = set()
    slash_terminated_vars: set[str] = set()

    for line in lines:
        assignments = iter_semicolon_assignments(line)
        if not assignments:
            continue
        _, var, expr = assignments[0]
        if "getCanonicalPath(" not in expr:
            continue
        canonical_vars.add(var)
        if _expr_is_slash_terminated_base(expr):
            slash_terminated_vars.add(var)

    return canonical_vars, slash_terminated_vars


def _collect_canonical_string_vars_for_names(
    lines: list[str], names: set[str]
) -> set[str]:
    canonical_vars: set[str] = set()

    for line in lines:
        assignments = iter_semicolon_assignments(line)
        if not assignments:
            continue
        _, var, expr = assignments[0]
        if "getCanonicalPath(" not in expr:
            continue
        if _line_mentions_names(expr, names | canonical_vars):
            canonical_vars.add(var)

    return canonical_vars


def _expr_is_slash_terminated_base(expr: str) -> bool:
    return any(
        token in expr
        for token in (
            "File.separator",
            "java.io.File.separator",
            '"/"',
            '"\\\\"',
            "separatorChar",
        )
    )


def _line_has_safe_startswith_guard(
    line: str, canonical_vars: set[str], slash_terminated_vars: set[str]
) -> bool:
    for match in _STARTSWITH_CALL_PATTERN.finditer(line):
        receiver = match.group("receiver").strip()
        arg = match.group("arg").strip()
        receiver_is_canonical_string = (
            receiver in canonical_vars or "getCanonicalPath()" in receiver
        )
        arg_is_canonical_string = arg in canonical_vars or "getCanonicalPath()" in arg

        if receiver_is_canonical_string and arg_is_canonical_string:
            if arg in slash_terminated_vars or _expr_is_slash_terminated_base(arg):
                return True
            continue

        return True

    return False


def _has_named_path_guard(
    lines: list[str], names: set[str], hints: tuple[str, ...], sink_idx: int
) -> bool:
    has_normalize = False
    canonical_vars, slash_terminated_vars = _collect_canonical_string_vars(lines)
    sink_canonical_vars = _collect_canonical_string_vars_for_names(lines, names)

    for idx, line in enumerate(lines):
        mentioned = _names_in_line(line, names)
        startswith_line = "startsWith(" in line or "starts_with(" in line
        if not mentioned and not (
            has_normalize
            and startswith_line
            and _line_mentions_names(line, sink_canonical_vars)
        ):
            continue
        if any(hint in line for hint in hints):
            has_normalize = True
        if (
            has_normalize
            and "if" in line
            and startswith_line
            and ("!" in line or "== false" in line or "false ==" in line)
        ):
            if not _line_has_safe_startswith_guard(
                line, canonical_vars, slash_terminated_vars
            ):
                continue
            trailing = "\n".join(lines[idx : min(len(lines), idx + 4)])
            if any(token in trailing for token in _CONTROL_FLOW_HINTS):
                return True
        if (
            idx <= sink_idx
            and has_normalize
            and "if" in line
            and startswith_line
            and "!" not in line
            and "== false" not in line
            and "false ==" not in line
            and _line_has_safe_startswith_guard(
                line, canonical_vars, slash_terminated_vars
            )
            and (
                _guard_block_contains_sink(lines, idx, sink_idx)
                or _guard_without_braces_contains_sink(lines, idx, sink_idx)
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


def _iter_assignment_events(text: str) -> list[tuple[int, str, str]]:
    return iter_semicolon_assignments(text)


def _iter_sink_calls(
    text: str, sink_args: dict[str, tuple[int, ...]]
) -> list[tuple[int, list[str]]]:
    calls: list[tuple[int, list[str]]] = []
    for token, positions in sink_args.items():
        search_from = 0
        while True:
            idx = text.find(token, search_from)
            if idx < 0:
                break
            args = _extract_call_args(text[idx:], token)
            selected_args = [args[pos] for pos in positions if pos < len(args)]
            calls.append((text[:idx].count("\n"), selected_args))
            search_from = idx + 1
    calls.sort(key=lambda item: item[0])
    return calls


def _first_tainted_names(expr: str, tainted_vars: set[str]) -> set[str]:
    return _names_in_line(expr, tainted_vars)


def _expr_uses_taint(expr: str, tainted_vars: set[str]) -> bool:
    return bool(_first_tainted_names(expr, tainted_vars))


def _expr_has_java_request_source(expr: str) -> bool:
    return bool(_JAVA_REQUEST_SOURCE_RE.search(expr))


def _expr_has_xss_sanitizer(expr: str) -> bool:
    return any(hint in expr for hint in _JAVA_XSS_SANITIZER_HINTS)


def _java_class_base(class_name: str | None) -> str | None:
    if not class_name:
        return None
    return class_name.rsplit(".", 1)[-1]


def _java_arg_count(args: str) -> int:
    args = args.strip()
    if not args:
        return 0
    depth = 0
    count = 1
    in_string: str | None = None
    escaped = False
    for ch in args:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {"'", '"'}:
            in_string = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(depth - 1, 0)
        elif ch == "," and depth == 0:
            count += 1
    return count


def _class_name_for_method(node, source_bytes: bytes) -> str | None:
    current = node.parent
    while current is not None:
        if current.type in {
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
        }:
            name_node = current.child_by_field_name("name")
            if name_node is not None:
                return _get_text(source_bytes, name_node)
            return None
        current = current.parent
    return None


def _java_assignment_matches(line: str) -> list[tuple[str, str]]:
    assignments: list[tuple[str, str]] = []
    for match in _JAVA_ASSIGNMENT_PATTERN.finditer(line):
        var = match.group("var")
        expr = match.group("expr").strip()
        if var in {"if", "for", "while", "switch", "return"}:
            continue
        assignments.append((var, expr))
    return assignments


def _java_statement_text(lines: list[str], start_idx: int, max_lines: int = 8) -> str:
    parts: list[str] = []
    for line in lines[start_idx : min(len(lines), start_idx + max_lines)]:
        parts.append(line.strip())
        if ";" in line:
            break
    return " ".join(parts)


def _split_java_ternary(expr: str) -> tuple[str, str, str] | None:
    question_idx = expr.find("?")
    if question_idx < 0:
        return None

    depth = 0
    for idx in range(question_idx + 1, len(expr)):
        ch = expr[idx]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            return (
                expr[:question_idx].strip(),
                expr[question_idx + 1 : idx].strip(),
                expr[idx + 1 :].strip(),
            )
    return None


def _eval_java_constant_condition(expr: str, constants: dict[str, int]) -> bool | None:
    candidate = expr
    for name, value in constants.items():
        candidate = re.sub(rf"\b{re.escape(name)}\b", str(value), candidate)
    candidate = candidate.replace("&&", " and ").replace("||", " or ")
    candidate = re.sub(r"!\s*(?!=)", " not ", candidate)
    try:
        parsed = ast.parse(candidate, mode="eval")
        value = _eval_java_constant_ast(parsed.body)
        return bool(value) if isinstance(value, (bool, int, float)) else None
    except Exception:
        return None


def _eval_java_constant_ast(node: ast.AST) -> bool | int | float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bool, int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp):
        operand = _eval_java_constant_ast(node.operand)
        if isinstance(node.op, ast.Not):
            return not bool(operand)
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return +operand
    if isinstance(node, ast.BoolOp):
        values = [bool(_eval_java_constant_ast(value)) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
    if isinstance(node, ast.BinOp):
        left = _eval_java_constant_ast(node.left)
        right = _eval_java_constant_ast(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.BitAnd):
            return int(left) & int(right)
        if isinstance(node.op, ast.BitOr):
            return int(left) | int(right)
    if isinstance(node, ast.Compare):
        left = _eval_java_constant_ast(node.left)
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = _eval_java_constant_ast(comparator)
            if isinstance(op, ast.Lt):
                ok = left < right
            elif isinstance(op, ast.LtE):
                ok = left <= right
            elif isinstance(op, ast.Gt):
                ok = left > right
            elif isinstance(op, ast.GtE):
                ok = left >= right
            elif isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            else:
                raise ValueError("unsupported comparison")
            if not ok:
                return False
            left = right
        return True
    raise ValueError("unsupported constant expression")


def _select_static_java_ternary_branch(
    expr: str, constants: dict[str, int]
) -> str | None:
    ternary = _split_java_ternary(expr)
    if not ternary:
        return None
    condition, true_expr, false_expr = ternary
    value = _eval_java_constant_condition(condition, constants)
    if value is None:
        return None
    return true_expr if value else false_expr


def _expr_is_java_tainted(
    expr: str,
    tainted_vars: set[str],
) -> bool:
    if _expr_has_java_request_source(expr):
        return True
    if _expr_uses_taint(expr, tainted_vars):
        return True
    return False


def _expr_is_java_tainted_with_context(
    expr: str,
    tainted_vars: set[str],
    request_wrappers: set[str],
    object_types: dict[str, str],
    helper_summaries: dict[tuple[str | None, str, int], tuple[bool, bool]],
) -> bool:
    if _expr_is_java_tainted(expr, tainted_vars):
        return True

    for match in _JAVA_METHOD_INVOCATION_RE.finditer(expr):
        args = match.group("args")
        args_tainted = _expr_is_java_tainted_with_context(
            args, tainted_vars, request_wrappers, object_types, helper_summaries
        )
        summary_taint = _java_method_call_summary_taint(
            match, args_tainted, request_wrappers, object_types, helper_summaries
        )
        if summary_taint is not None:
            if summary_taint:
                return True
            continue

        if args_tainted:
            return True

    return False


def _java_method_call_summary_taint(
    match,
    args_tainted: bool,
    request_wrappers: set[str],
    object_types: dict[str, str],
    helper_summaries: dict[tuple[str | None, str, int], tuple[bool, bool]],
) -> bool | None:
    method = match.group("method")
    receiver = match.group("receiver")
    new_class = _java_class_base(match.group("new_class"))
    receiver_class = object_types.get(receiver or "") if receiver else new_class
    summary = helper_summaries.get(
        (receiver_class, method, _java_arg_count(match.group("args")))
    )

    if summary is not None:
        returns_request_source, returns_arg_taint = summary
        return returns_request_source or (returns_arg_taint and args_tainted)

    return None


def _extract_java_method_signature(method_text: str) -> tuple[str | None, list[str]]:
    header = method_text.split("{", 1)[0]
    name_match = re.search(r"\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)", header)
    if not name_match:
        return None, []
    params: list[str] = []
    for raw_param in name_match.group("params").split(","):
        cleaned = raw_param.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", cleaned)
        cleaned = cleaned.replace("final ", "")
        param_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[\])?$", cleaned)
        if param_match:
            params.append(param_match.group(1))
    return name_match.group("name"), params


def _java_expr_taint_with_collections(
    expr: str,
    tainted_vars: set[str],
    map_entries: dict[tuple[str, str], tuple[bool, bool]],
    list_entries: dict[str, list[tuple[bool, bool]]],
) -> bool:
    map_get_match = _JAVA_MAP_GET_RE.search(expr)
    if map_get_match:
        entry = map_entries.get(
            (map_get_match.group("var"), map_get_match.group("key"))
        )
        if entry is not None:
            return entry[0]
    list_get_match = _JAVA_LIST_GET_RE.search(expr)
    if list_get_match:
        entries = list_entries.get(list_get_match.group("var"), [])
        index = int(list_get_match.group("index"))
        if 0 <= index < len(entries):
            return entries[index][0]
    return _expr_is_java_tainted(expr, tainted_vars)


def _java_method_returns_tainted_param(method_text: str, params: list[str]) -> bool:
    tainted_vars = set(params)
    constants: dict[str, int] = {}
    map_entries: dict[tuple[str, str], tuple[bool, bool]] = {}
    list_entries: dict[str, list[tuple[bool, bool]]] = {}
    skip_else_assignments: set[str] = set()
    conditional_tainted_assignments: set[str] = set()

    for raw_line in method_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        const_match = _JAVA_CONST_INT_PATTERN.search(stripped)
        if const_match:
            constants[const_match.group("var")] = int(const_match.group("value"))

        inline_if_match = re.search(
            r"\bif\s*\((?P<condition>.*)\)\s*(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
            stripped,
        )
        if inline_if_match:
            value = _eval_java_constant_condition(
                inline_if_match.group("condition"), constants
            )
            var = inline_if_match.group("var")
            expr = inline_if_match.group("expr").strip()
            if value is None:
                if _java_expr_taint_with_collections(
                    expr, tainted_vars, map_entries, list_entries
                ):
                    tainted_vars.add(var)
                    conditional_tainted_assignments.add(var)
                continue
            if value is True:
                if _java_expr_taint_with_collections(
                    expr, tainted_vars, map_entries, list_entries
                ):
                    tainted_vars.add(var)
                else:
                    tainted_vars.discard(var)
                skip_else_assignments.add(var)
                continue

        inline_else_match = re.search(
            r"\belse\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
            stripped,
        )
        if (
            inline_else_match
            and inline_else_match.group("var") in skip_else_assignments
        ):
            skip_else_assignments.discard(inline_else_match.group("var"))
            continue
        if (
            inline_else_match
            and inline_else_match.group("var") in conditional_tainted_assignments
        ):
            conditional_tainted_assignments.discard(inline_else_match.group("var"))
            continue

        list_add_match = _JAVA_LIST_ADD_RE.search(stripped)
        if list_add_match:
            list_var = list_add_match.group("var")
            list_expr = list_add_match.group("expr")
            list_tainted = _java_expr_taint_with_collections(
                list_expr, tainted_vars, map_entries, list_entries
            )
            list_entries.setdefault(list_var, []).append((list_tainted, False))

        list_remove_match = _JAVA_LIST_REMOVE_RE.search(stripped)
        if list_remove_match:
            list_var = list_remove_match.group("var")
            index = int(list_remove_match.group("index"))
            entries = list_entries.get(list_var)
            if entries and 0 <= index < len(entries):
                entries.pop(index)

        map_put_match = _JAVA_MAP_PUT_RE.search(stripped)
        if map_put_match:
            map_entries[(map_put_match.group("var"), map_put_match.group("key"))] = (
                _java_expr_taint_with_collections(
                    map_put_match.group("expr"),
                    tainted_vars,
                    map_entries,
                    list_entries,
                ),
                False,
            )

        return_match = re.search(r"\breturn\s+(?P<expr>[^;]+);", stripped)
        if return_match and _java_expr_taint_with_collections(
            return_match.group("expr"), tainted_vars, map_entries, list_entries
        ):
            return True

        for var, expr in _java_assignment_matches(stripped):
            selected_branch = _select_static_java_ternary_branch(expr, constants)
            if selected_branch is not None:
                expr = selected_branch
            if _java_expr_taint_with_collections(
                expr, tainted_vars, map_entries, list_entries
            ):
                tainted_vars.add(var)
            else:
                tainted_vars.discard(var)

    return False


def _collect_java_helper_summaries(
    root_node, source_bytes: bytes
) -> dict[tuple[str | None, str, int], tuple[bool, bool]]:
    summaries: dict[tuple[str | None, str, int], tuple[bool, bool]] = {}
    for node in _iter_nodes(root_node):
        if node.type != "method_declaration":
            continue
        method_text = _get_text(source_bytes, node)
        name, params = _extract_java_method_signature(method_text)
        if not name:
            continue
        class_name = _class_name_for_method(node, source_bytes)
        returns_request_source = _java_method_returns_tainted_param(method_text, [])
        returns_arg_taint = (
            _java_method_returns_tainted_param(method_text, params) if params else False
        )
        summaries[(class_name, name, len(params))] = (
            returns_request_source,
            returns_arg_taint,
        )
    return summaries


def _line_has_unsanitized_xss_taint(
    line: str, tainted_vars: set[str], xss_sanitized_vars: set[str]
) -> bool:
    if _expr_has_xss_sanitizer(line):
        return False
    tainted_names = _names_in_line(line, tainted_vars)
    return any(name not in xss_sanitized_vars for name in tainted_names)


def _add_java_flow_finding(
    findings: list[dict],
    seen: set[tuple[str, int, str]],
    *,
    rule_id: str,
    severity: str,
    message: str,
    file_path: str,
    line: int,
    category: str | None = None,
    cwe: str | None = None,
) -> None:
    key = (rule_id, line, category or "")
    if key in seen:
        return
    seen.add(key)
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": line,
        "col": 0,
    }
    if category:
        finding["category"] = category
    if cwe:
        finding["cwe"] = cwe
    findings.append(finding)


def _extend_unique_findings(findings: list[dict], new_findings: list[dict]) -> None:
    seen = {
        (
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("line"),
            finding.get("category", ""),
        )
        for finding in findings
    }
    for finding in new_findings:
        key = (
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("line"),
            finding.get("category", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)


def _sink_tainted_names(
    args: list[str],
    names: set[str],
    direct_pattern: re.Pattern[str] | None = None,
) -> set[str]:
    for arg in args:
        if direct_pattern and direct_pattern.search(arg):
            return {"__direct__"}
        matched = _names_in_line(arg, names)
        if matched:
            return matched
    return set()


def _scan_archive_extraction(
    root_node, file_path: str, source_bytes: bytes
) -> list[dict]:
    findings: list[dict] = []
    seen_lines: set[int] = set()

    for node in _iter_nodes(root_node):
        if node.type not in {"method_declaration", "constructor_declaration"}:
            continue

        method_text = _get_text(source_bytes, node)
        if not any(hint in method_text for hint in _ARCHIVE_ENTRY_HINTS):
            continue
        if not any(hint in method_text for hint in _ARCHIVE_SINK_HINTS):
            continue

        lines = method_text.splitlines()
        tainted_vars: set[str] = set()
        latest_assignment: dict[str, int] = {}
        events: list[tuple[int, int, object]] = []
        events.extend(
            (line_offset, 0, (alias, expr))
            for line_offset, alias, expr in _iter_assignment_events(method_text)
        )
        events.extend(
            (line_offset, 1, args)
            for line_offset, args in _iter_sink_calls(method_text, _ARCHIVE_SINK_ARGS)
        )
        events.sort(key=lambda item: (item[0], item[1]))

        for line_offset, kind, payload in events:
            if kind == 0:
                alias, expr = payload
                if any(hint in expr for hint in _ARCHIVE_NAME_HINTS) or any(
                    re.search(rf"\b{re.escape(name)}\b", expr) for name in tainted_vars
                ):
                    tainted_vars.add(alias)
                else:
                    tainted_vars.discard(alias)
                latest_assignment[alias] = line_offset
                continue

            args = payload
            used_names = _sink_tainted_names(args, tainted_vars)
            direct_entry_name = bool(
                _sink_tainted_names(
                    args,
                    set(),
                    re.compile(r"\.(?:getName|getRealName)\s*\("),
                )
            )
            if not used_names and not direct_entry_name:
                continue

            guard_start = 0
            if used_names:
                guard_start = max(latest_assignment.get(name, 0) for name in used_names)
            if used_names and _has_named_path_guard(
                lines[guard_start : line_offset + 1],
                used_names,
                _ARCHIVE_GUARD_HINTS,
                line_offset - guard_start,
            ):
                continue

            line_no = node.start_point[0] + line_offset + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            findings.append(
                {
                    "rule_id": "SKY-D215",
                    "severity": "HIGH",
                    "message": "Archive entry name is written to disk without canonical path validation. Normalize the target path and enforce it stays under the extraction directory.",
                    "file": str(file_path),
                    "line": line_no,
                    "col": 0,
                }
            )
            break

    return findings


def _scan_request_path_traversal(
    root_node, file_path: str, source_bytes: bytes
) -> list[dict]:
    findings: list[dict] = []
    seen_lines: set[int] = set()

    for node in _iter_nodes(root_node):
        if node.type not in {"method_declaration", "constructor_declaration"}:
            continue

        method_text = _get_text(source_bytes, node)
        tainted_vars: set[str] = {
            match.group("var")
            for match in _REQUEST_SOURCE_PATTERNS[1].finditer(method_text)
        }
        latest_assignment: dict[str, int] = {name: 0 for name in tainted_vars}

        if not tainted_vars and not _REQUEST_INLINE_SOURCE_PATTERN.search(method_text):
            continue

        lines = method_text.splitlines()
        events = []
        events.extend(
            (line_offset, 0, (alias, expr))
            for line_offset, alias, expr in _iter_assignment_events(method_text)
        )
        events.extend(
            (line_offset, 1, args)
            for line_offset, args in _iter_sink_calls(method_text, _REQUEST_SINK_ARGS)
        )
        events.sort(key=lambda item: (item[0], item[1]))

        for line_offset, kind, payload in events:
            if kind == 0:
                alias, expr = payload
                if _REQUEST_INLINE_SOURCE_PATTERN.search(expr) or any(
                    re.search(rf"\b{re.escape(name)}\b", expr) for name in tainted_vars
                ):
                    tainted_vars.add(alias)
                else:
                    tainted_vars.discard(alias)
                latest_assignment[alias] = line_offset
                continue

            used_names = _sink_tainted_names(
                payload,
                tainted_vars,
                _REQUEST_INLINE_SOURCE_PATTERN,
            )
            if not used_names:
                continue

            guard_start = max(
                (
                    latest_assignment.get(name, 0)
                    for name in used_names
                    if name != "__direct__"
                ),
                default=0,
            )
            if used_names and _has_named_path_guard(
                lines[guard_start : line_offset + 1],
                used_names,
                _REQUEST_GUARD_HINTS,
                line_offset - guard_start,
            ):
                continue

            line_no = node.start_point[0] + line_offset + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            findings.append(
                {
                    "rule_id": "SKY-D215",
                    "severity": "HIGH",
                    "message": "Request-controlled path reaches a filesystem sink without canonical path validation. Normalize the path and enforce it stays under the intended root.",
                    "file": str(file_path),
                    "line": line_no,
                    "col": 0,
                }
            )
            break

    return findings


def _scan_servlet_security_flows(
    root_node,
    file_path: str,
    source_bytes: bytes,
    helper_summaries: dict[tuple[str | None, str, int], tuple[bool, bool]],
) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for node in _iter_nodes(root_node):
        if node.type not in {"method_declaration", "constructor_declaration"}:
            continue

        method_text = _get_text(source_bytes, node)
        if not any(
            hint in method_text
            for hint in (
                "request.",
                "req.",
                "Cookie",
                "ProcessBuilder",
                "new File(",
                "new java.io.File(",
                "java.util.Random",
                "Math.random",
                "getWriter()",
                "getSession()",
                "prepareStatement",
                "prepareCall",
                ".search(",
                ".evaluate(",
                ".compile(",
            )
        ):
            continue

        lines = method_text.splitlines()
        tainted_vars: set[str] = set()
        xss_sanitized_vars: set[str] = set()
        constants: dict[str, int] = {}
        tainted_collections: set[str] = set()
        tainted_process_builders: set[str] = set()
        cookie_vars: set[str] = set()
        insecure_cookie_vars: set[str] = set()
        request_wrappers: set[str] = set()
        object_types: dict[str, str] = {}
        skip_else_assignments: set[str] = set()
        conditional_tainted_assignments: set[str] = set()
        map_entries: dict[tuple[str, str], tuple[bool, bool]] = {}
        list_entries: dict[str, list[tuple[bool, bool]]] = {}
        pending_assignment: tuple[str, list[str]] | None = None

        def expr_tainted(expr: str) -> bool:
            return _expr_is_java_tainted_with_context(
                expr, tainted_vars, request_wrappers, object_types, helper_summaries
            )

        for line_offset, line in enumerate(lines):
            line_no = node.start_point[0] + line_offset + 1
            stripped = line.strip()
            statement_text = _java_statement_text(lines, line_offset)
            if not stripped or stripped.startswith("//"):
                continue

            const_match = _JAVA_CONST_INT_PATTERN.search(stripped)
            if const_match:
                constants[const_match.group("var")] = int(const_match.group("value"))

            object_match = _JAVA_NEW_OBJECT_RE.search(stripped)
            if object_match:
                object_args = object_match.group("args")
                object_var = object_match.group("var")
                object_class = _java_class_base(object_match.group("class"))
                if object_class:
                    object_types[object_var] = object_class
                if re.search(r"\b(?:request|req)\b", object_args) or expr_tainted(
                    object_args
                ):
                    request_wrappers.add(object_var)
                else:
                    request_wrappers.discard(object_var)

            for_match = _JAVA_ENHANCED_FOR_PATTERN.search(stripped)
            if for_match and for_match.group("src") in tainted_vars:
                tainted_vars.add(for_match.group("var"))

            inline_if_match = re.search(
                r"\bif\s*\((?P<condition>.*)\)\s*(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
                stripped,
            )
            if inline_if_match:
                value = _eval_java_constant_condition(
                    inline_if_match.group("condition"), constants
                )
                var = inline_if_match.group("var")
                expr = inline_if_match.group("expr").strip()
                if value is None:
                    if expr_tainted(expr):
                        tainted_vars.add(var)
                        if _expr_has_xss_sanitizer(expr):
                            xss_sanitized_vars.add(var)
                        else:
                            xss_sanitized_vars.discard(var)
                        conditional_tainted_assignments.add(var)
                    continue
                if value is True:
                    if expr_tainted(expr):
                        tainted_vars.add(var)
                        if _expr_has_xss_sanitizer(expr):
                            xss_sanitized_vars.add(var)
                        else:
                            xss_sanitized_vars.discard(var)
                    else:
                        tainted_vars.discard(var)
                        xss_sanitized_vars.discard(var)
                    skip_else_assignments.add(var)
                    continue

            inline_else_match = re.search(
                r"\belse\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
                stripped,
            )
            if (
                inline_else_match
                and inline_else_match.group("var") in skip_else_assignments
            ):
                skip_else_assignments.discard(inline_else_match.group("var"))
                continue
            if (
                inline_else_match
                and inline_else_match.group("var") in conditional_tainted_assignments
            ):
                conditional_tainted_assignments.discard(inline_else_match.group("var"))
                continue

            cookie_match = _JAVA_COOKIE_CREATION_RE.search(stripped)
            if cookie_match:
                cookie_vars.add(cookie_match.group("var"))

            method_match = _JAVA_METHOD_CALL_RE.search(stripped)
            if method_match:
                receiver = method_match.group("receiver")
                method = method_match.group("method")
                args = method_match.group("args")
                if method == "setSecure" and receiver in cookie_vars:
                    if "false" in args.lower():
                        insecure_cookie_vars.add(receiver)
                    elif "true" in args.lower():
                        insecure_cookie_vars.discard(receiver)
                elif method == "addCookie" and _expr_uses_taint(
                    args, insecure_cookie_vars
                ):
                    _add_java_flow_finding(
                        findings,
                        seen,
                        rule_id="SKY-D252",
                        severity="HIGH",
                        message="Cookie is added with Secure disabled. Set Secure before sending sensitive cookies.",
                        file_path=file_path,
                        line=line_no,
                        category="cookie_security",
                        cwe="CWE-614",
                    )
                elif method == "command" and (
                    expr_tainted(args) or _expr_uses_taint(args, tainted_collections)
                ):
                    tainted_process_builders.add(receiver)
                elif method == "start" and receiver in tainted_process_builders:
                    _add_java_flow_finding(
                        findings,
                        seen,
                        rule_id="SKY-D212",
                        severity="CRITICAL",
                        message="ProcessBuilder starts a shell command built from servlet-controlled data. Use fixed argv elements and validate inputs.",
                        file_path=file_path,
                        line=line_no,
                        cwe="CWE-78",
                    )

            builder_match = _JAVA_PROCESS_BUILDER_RE.search(stripped)
            if builder_match:
                builder_var = builder_match.group("var")
                builder_args = builder_match.group("args")
                if expr_tainted(builder_args) or _expr_uses_taint(
                    builder_args, tainted_collections
                ):
                    tainted_process_builders.add(builder_var)

            list_add_match = _JAVA_LIST_ADD_RE.search(stripped)
            if list_add_match:
                list_var = list_add_match.group("var")
                list_expr = list_add_match.group("expr")
                list_tainted = expr_tainted(list_expr)
                list_xss_safe = _expr_has_xss_sanitizer(list_expr) or (
                    _first_tainted_names(list_expr, tainted_vars)
                    and _first_tainted_names(list_expr, tainted_vars)
                    <= xss_sanitized_vars
                )
                list_entries.setdefault(list_var, []).append(
                    (list_tainted, list_xss_safe)
                )
                if list_tainted:
                    tainted_collections.add(list_var)

            list_remove_match = _JAVA_LIST_REMOVE_RE.search(stripped)
            if list_remove_match:
                list_var = list_remove_match.group("var")
                index = int(list_remove_match.group("index"))
                entries = list_entries.get(list_var)
                if entries and 0 <= index < len(entries):
                    entries.pop(index)
                    if not any(item[0] for item in entries):
                        tainted_collections.discard(list_var)

            map_put_match = _JAVA_MAP_PUT_RE.search(stripped)
            if map_put_match:
                map_expr = map_put_match.group("expr")
                map_tainted = expr_tainted(map_expr)
                map_xss_safe = _expr_has_xss_sanitizer(map_expr) or (
                    _first_tainted_names(map_expr, tainted_vars)
                    and _first_tainted_names(map_expr, tainted_vars)
                    <= xss_sanitized_vars
                )
                map_entries[
                    (map_put_match.group("var"), map_put_match.group("key"))
                ] = (
                    map_tainted,
                    map_xss_safe,
                )

            selected_assignments: list[tuple[str, str]]
            if pending_assignment is not None:
                pending_var, pending_parts = pending_assignment
                pending_parts.append(stripped)
                if ";" not in stripped:
                    continue
                selected_assignments = [
                    (pending_var, " ".join(pending_parts).rstrip(";").strip())
                ]
                pending_assignment = None
            else:
                pending_match = re.search(
                    r"(?:(?:final)\s+)?(?:[\w.<>\[\],?]+\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*$",
                    stripped,
                )
                if pending_match:
                    pending_assignment = (pending_match.group("var"), [])
                    continue
                selected_assignments = _java_assignment_matches(stripped)

            for var, expr in selected_assignments:
                selected_branch = _select_static_java_ternary_branch(expr, constants)
                if selected_branch is not None:
                    expr = selected_branch

                map_get_match = _JAVA_MAP_GET_RE.search(expr)
                list_get_match = _JAVA_LIST_GET_RE.search(expr)
                collection_xss_safe = False
                if map_get_match:
                    entry = map_entries.get(
                        (map_get_match.group("var"), map_get_match.group("key"))
                    )
                    if entry is None:
                        is_tainted = expr_tainted(expr)
                    else:
                        is_tainted, collection_xss_safe = entry
                elif list_get_match:
                    entries = list_entries.get(list_get_match.group("var"), [])
                    index = int(list_get_match.group("index"))
                    if 0 <= index < len(entries):
                        is_tainted, collection_xss_safe = entries[index]
                    else:
                        is_tainted = expr_tainted(expr)
                else:
                    invocation = _JAVA_METHOD_INVOCATION_RE.search(expr)
                    summary_taint = None
                    if invocation is not None:
                        args_tainted = expr_tainted(invocation.group("args"))
                        summary_taint = _java_method_call_summary_taint(
                            invocation,
                            args_tainted,
                            request_wrappers,
                            object_types,
                            helper_summaries,
                        )
                    is_tainted = (
                        summary_taint
                        if summary_taint is not None
                        else expr_tainted(expr)
                    )
                if is_tainted:
                    tainted_names = _first_tainted_names(expr, tainted_vars)
                    tainted_vars.add(var)
                    if (
                        collection_xss_safe
                        or _expr_has_xss_sanitizer(expr)
                        or (tainted_names and tainted_names <= xss_sanitized_vars)
                    ):
                        xss_sanitized_vars.add(var)
                    else:
                        xss_sanitized_vars.discard(var)
                else:
                    tainted_vars.discard(var)
                    xss_sanitized_vars.discard(var)
                    tainted_collections.discard(var)
                    tainted_process_builders.discard(var)

                if is_tainted and (
                    ".prepareCall(" in expr
                    or ".prepareStatement(" in expr
                    or ".executeQuery(" in expr
                    or ".executeUpdate(" in expr
                    or ".execute(" in expr
                    or ".queryForObject(" in expr
                    or ".queryForRowSet(" in expr
                    or ".query(" in expr
                ):
                    _add_java_flow_finding(
                        findings,
                        seen,
                        rule_id="SKY-D211",
                        severity="CRITICAL",
                        message="SQL query uses servlet-controlled data. Use parameterized queries with fixed SQL.",
                        file_path=file_path,
                        line=line_no,
                        cwe="CWE-89",
                    )

            if (
                (
                    "Math.random()" in stripped
                    or "new java.util.Random().next" in stripped
                    or "new Random().next" in stripped
                )
                and "SecureRandom" not in stripped
                and any(
                    token in method_text
                    for token in ("rememberMe", "getSession()", "new Cookie(")
                )
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D250",
                    severity="HIGH",
                    message="Weak random value is used in security-sensitive token or session material. Use SecureRandom.",
                    file_path=file_path,
                    line=line_no,
                    category="weak_random",
                    cwe="CWE-330",
                )

            if (
                any(hint in stripped for hint in _JAVA_PATH_SINK_HINTS)
                and expr_tainted(stripped)
                and not (
                    ("new File(" in stripped or "new java.io.File(" in stripped)
                    and not any(
                        sink in stripped
                        for sink in (
                            "FileInputStream(",
                            "FileOutputStream(",
                            "FileReader(",
                            "Files.",
                            "java.nio.file.Files.",
                        )
                    )
                    and any(hint in method_text for hint in _REQUEST_GUARD_HINTS)
                    and "startsWith(" in method_text
                )
                and not _has_named_path_guard(
                    lines[: line_offset + 1],
                    _first_tainted_names(stripped, tainted_vars),
                    _REQUEST_GUARD_HINTS,
                    line_offset,
                )
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D215",
                    severity="HIGH",
                    message="Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                    file_path=file_path,
                    line=line_no,
                    cwe="CWE-22",
                )

            if ".exec(" in statement_text and (
                expr_tainted(statement_text)
                or _expr_uses_taint(statement_text, tainted_collections)
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D212",
                    severity="CRITICAL",
                    message="Process execution uses servlet-controlled data. Use fixed argv elements and validate inputs.",
                    file_path=file_path,
                    line=line_no,
                    cwe="CWE-78",
                )

            if (
                ".prepareCall(" in stripped
                or ".prepareStatement(" in stripped
                or ".executeQuery(" in stripped
                or ".executeUpdate(" in stripped
                or ".execute(" in stripped
                or ".queryForObject(" in stripped
                or ".queryForRowSet(" in stripped
                or ".query(" in stripped
            ):
                if expr_tainted(statement_text):
                    _add_java_flow_finding(
                        findings,
                        seen,
                        rule_id="SKY-D211",
                        severity="CRITICAL",
                        message="SQL query uses servlet-controlled data. Use parameterized queries with fixed SQL.",
                        file_path=file_path,
                        line=line_no,
                        cwe="CWE-89",
                    )

            if ".search(" in stripped and expr_tainted(stripped):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D240",
                    severity="CRITICAL",
                    message="LDAP search filter uses servlet-controlled data. Escape LDAP filter values or use safe APIs.",
                    file_path=file_path,
                    line=line_no,
                    category="ldap_injection",
                    cwe="CWE-90",
                )

            if (".evaluate(" in stripped or ".compile(" in stripped) and expr_tainted(
                stripped
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D241",
                    severity="CRITICAL",
                    message="XPath expression uses servlet-controlled data. Use fixed expressions or strict allowlists.",
                    file_path=file_path,
                    line=line_no,
                    category="xpath_injection",
                    cwe="CWE-643",
                )

            if (
                "getWriter()" in stripped
                and any(method in stripped for method in _JAVA_XSS_WRITER_METHODS)
                and _line_has_unsanitized_xss_taint(
                    stripped, tainted_vars, xss_sanitized_vars
                )
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D226",
                    severity="HIGH",
                    message="Servlet response writes untrusted data without HTML encoding.",
                    file_path=file_path,
                    line=line_no,
                    cwe="CWE-79",
                )

            if (
                "getSession()" in stripped
                and (".setAttribute(" in stripped or ".putValue(" in stripped)
                and expr_tainted(stripped)
            ):
                _add_java_flow_finding(
                    findings,
                    seen,
                    rule_id="SKY-D253",
                    severity="HIGH",
                    message="Servlet-controlled data crosses into HTTP session state.",
                    file_path=file_path,
                    line=line_no,
                    category="trust_boundary",
                    cwe="CWE-501",
                )

    return findings


def scan_danger(root_node, file_path: str, lang: Language | None = None) -> list[dict]:
    findings: list[dict] = []
    if lang is None:
        lang = JAVA_LANG
    if not lang:
        return []

    source_bytes: bytes = root_node.text
    simple_captures = _run_batch(root_node, lang, "danger_simple", _SIMPLE_PATTERN)

    for node in simple_captures.get("rt_method", []):
        findings.append(
            {
                "rule_id": "SKY-D203",
                "severity": "HIGH",
                "message": "Runtime.exec() — risk of command injection. Use ProcessBuilder with argument list instead.",
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
            }
        )

    sql_captures = _run_batch(root_node, lang, "danger_sql", _SQL_PATTERN)
    for args_node in sql_captures.get("sql_args", []):
        for child in args_node.children:
            if child.type in ("(", ")", ","):
                continue
            if child.type == "binary_expression":
                text = _get_text(source_bytes, child).upper()
                if any(kw in text for kw in _SQL_KEYWORDS):
                    findings.append(
                        {
                            "rule_id": "SKY-D211",
                            "severity": "CRITICAL",
                            "message": "SQL query built with string concatenation — risk of SQL injection. Use PreparedStatement with parameterized queries.",
                            "file": str(file_path),
                            "line": child.start_point[0] + 1,
                            "col": 0,
                        }
                    )
            break

    crypto_captures = _run_batch(root_node, lang, "danger_crypto", _CRYPTO_PATTERN)
    for node in crypto_captures.get("algo_str", []):
        text = _get_text(source_bytes, node).strip('"')
        if text in ("MD5", "md5"):
            findings.append(
                {
                    "rule_id": "SKY-D207",
                    "severity": "MEDIUM",
                    "message": "Weak hash algorithm MD5. Use SHA-256 or better.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )
        elif text in ("SHA1", "SHA-1", "sha1"):
            findings.append(
                {
                    "rule_id": "SKY-D208",
                    "severity": "MEDIUM",
                    "message": "Weak hash algorithm SHA-1. Use SHA-256 or better.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )
        elif text == "DES":
            findings.append(
                {
                    "rule_id": "SKY-D207",
                    "severity": "HIGH",
                    "message": "Weak cipher DES. Use AES-256 instead.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    deserial_captures = _run_batch(
        root_node, lang, "danger_deserial", _DESERIAL_PATTERN
    )
    for node in deserial_captures.get("ois_type", []):
        findings.append(
            {
                "rule_id": "SKY-D204",
                "severity": "CRITICAL",
                "message": "ObjectInputStream — unsafe deserialization. Attacker-controlled data can lead to remote code execution.",
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
            }
        )

    findings.extend(_scan_archive_extraction(root_node, file_path, source_bytes))
    try:
        _extend_unique_findings(
            findings,
            scan_java_security_flows(root_node, file_path, source_bytes),
        )
    except Exception:
        # Compatibility fallback only: keep the previous text scanners available
        # for parser/analyzer failures, but do not use them as normal coverage.
        helper_summaries = _collect_java_helper_summaries(root_node, source_bytes)
        _extend_unique_findings(
            findings, _scan_request_path_traversal(root_node, file_path, source_bytes)
        )
        _extend_unique_findings(
            findings,
            _scan_servlet_security_flows(
                root_node, file_path, source_bytes, helper_summaries
            ),
        )

    is_test_file = get_non_library_dir_kind(file_path) == "test"
    string_captures = _run_batch(root_node, lang, "danger_strings", _STRING_PATTERN)
    for node in string_captures.get("string_node", []):
        text = _get_text(source_bytes, node).strip('"')
        if len(text) < MIN_SECRET_LENGTH:
            continue
        found_prefix = False
        for prefix in _SECRET_PREFIXES:
            if text.startswith(prefix) or text.lower().startswith(prefix.lower()):
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
            and not is_test_file
            and not _is_known_non_secret_alphabet(text)
            and len(text) >= MIN_LONG_SECRET_LENGTH
            and all(c in _BASE64_CHARS for c in text)
            and _shannon_entropy(text) > ENTROPY_THRESHOLD
        ):
            findings.append(
                {
                    "rule_id": "SKY-S101",
                    "severity": "HIGH",
                    "message": "High-entropy string detected — possible hardcoded secret.",
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )

    return findings
