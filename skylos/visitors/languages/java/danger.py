from __future__ import annotations

import math
import re
from tree_sitter import Language, Query, QueryCursor
import tree_sitter_java as tsj

from skylos.constants import (
    ENTROPY_THRESHOLD,
    MIN_LONG_SECRET_LENGTH,
    MIN_SECRET_LENGTH,
    get_non_library_dir_kind,
)

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

_LOCAL_ALIAS_PATTERN = re.compile(
    r"(?ms)^\s*(?:(?:final)\s+)*(?:[\w<>\[\],.?]+\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>.*?);",
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

_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


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
    return {
        name for name in names if re.search(rf"\b{re.escape(name)}\b", line)
    }


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
        match = _LOCAL_ALIAS_PATTERN.match(line)
        if not match:
            continue
        var = match.group("var")
        expr = match.group("expr")
        if "getCanonicalPath(" not in expr:
            continue
        canonical_vars.add(var)
        if _expr_is_slash_terminated_base(expr):
            slash_terminated_vars.add(var)

    return canonical_vars, slash_terminated_vars


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
    known_guard_vars = canonical_vars | slash_terminated_vars

    for idx, line in enumerate(lines):
        mentioned = _names_in_line(line, names)
        startswith_line = "startsWith(" in line or "starts_with(" in line
        if not mentioned and not (
            has_normalize
            and startswith_line
            and _line_mentions_names(line, known_guard_vars)
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
    return [
        (text[: match.start()].count("\n"), match.group("var"), match.group("expr"))
        for match in _LOCAL_ALIAS_PATTERN.finditer(text)
    ]


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


def _scan_archive_extraction(root_node, file_path: str, source_bytes: bytes) -> list[dict]:
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


def _scan_request_path_traversal(root_node, file_path: str, source_bytes: bytes) -> list[dict]:
    findings: list[dict] = []
    seen_lines: set[int] = set()

    for node in _iter_nodes(root_node):
        if node.type not in {"method_declaration", "constructor_declaration"}:
            continue

        method_text = _get_text(source_bytes, node)
        tainted_vars: set[str] = {
            match.group("var") for match in _REQUEST_SOURCE_PATTERNS[1].finditer(method_text)
        }
        latest_assignment: dict[str, int] = {
            name: 0 for name in tainted_vars
        }

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
                (latest_assignment.get(name, 0) for name in used_names if name != "__direct__"),
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
    findings.extend(_scan_request_path_traversal(root_node, file_path, source_bytes))

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
