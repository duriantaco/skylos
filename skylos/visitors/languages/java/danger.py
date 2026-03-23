from __future__ import annotations

import math
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


def scan_danger(
    root_node, file_path: str, lang: Language | None = None
) -> list[dict]:
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

    deserial_captures = _run_batch(root_node, lang, "danger_deserial", _DESERIAL_PATTERN)
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
