from __future__ import annotations

import ast
import base64
import binascii
import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from hashlib import blake2s
from html import unescape
from html.parser import HTMLParser
from math import log2

try:
    import yaml
except ModuleNotFoundError:  # Keep non-YAML scans available in partial installs.
    yaml = None

__all__ = [
    "is_client_exposure_context",
    "is_public_client_env_name",
    "iter_sensitive_client_env_references",
    "scan_ctx",
]

CLIENT_PATHS = (
    "/static/",
    "/public/",
    "/frontend/",
    "/client/",
    "/dist/",
    "/build/",
    "/assets/",
    "/.next/",
    "/out/",
)

_EXPLICIT_PUBLIC_CLIENT_PATHS = (
    "/public/",
    "/static/",
    "/assets/",
    "/.next/static/",
    "/build/client/",
    "/dist/client/",
    "/out/",
)
_EXPLICIT_SERVER_OUTPUT_PATHS = (
    "/.next/server/",
    "/build/server/",
    "/dist/server/",
    "/.output/server/",
)

PUBLIC_CLIENT_ENV_PREFIXES = (
    "NEXT_PUBLIC_",
    "REACT_APP_",
    "VITE_",
    "NUXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "PUBLIC_",
)
_SENSITIVE_CLIENT_ENV_TERMS = frozenset(
    {
        "AUTH",
        "CREDENTIAL",
        "CREDENTIALS",
        "KEY",
        "PASSWORD",
        "PASSWD",
        "PRIVATE",
        "SECRET",
        "TOKEN",
    }
)
_SENSITIVE_CLIENT_ENV_NAMES = frozenset(
    {
        "DATABASE_URL",
        "DB_URL",
        "MONGODB_URI",
        "MONGO_URI",
        "REDIS_URL",
    }
)
_SENSITIVE_PUBLIC_ENV_TERMS = frozenset(
    {
        "CREDENTIAL",
        "CREDENTIALS",
        "PASSWORD",
        "PASSWD",
        "PRIVATE",
        "SECRET",
        "TOKEN",
    }
)
_CLIENT_ENV_OBJECT_SOURCE_PATTERN = (
    r"(?:process\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])|"
    r"import\s*\.\s*meta\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\]))"
)
CLIENT_ENV_RE = re.compile(
    rf"{_CLIENT_ENV_OBJECT_SOURCE_PATTERN}\s*"
    r"(?:\.\s*(?P<dot>[A-Za-z_$][A-Za-z0-9_$]*)|"
    r"\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])"
)
_CLIENT_ENV_OBJECT_SOURCE_RE = re.compile(rf"^{_CLIENT_ENV_OBJECT_SOURCE_PATTERN}$")
_CLIENT_ENV_ALIAS_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9_$\.\]])"
    rf"(?:(?:const|let|var)\s+)?"
    rf"(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*)"
    rf"(?:\s*:[^=;\r\n]{{0,256}})?\s*=\s*(?:\(\s*)?"
    rf"(?P<target>{_CLIENT_ENV_OBJECT_SOURCE_PATTERN}|"
    rf"[A-Za-z_$][A-Za-z0-9_$]*)"
    rf"(?:\s*!|\s+(?:as|satisfies)\s+[^;,\r\n)]{{1,256}})?\s*"
    rf"(?:\)\s*)?"
    rf"(?=[;,\r\n)]|$)"
)
_CLIENT_ENV_ALIAS_MEMBER_RE = re.compile(
    r"(?<![A-Za-z0-9_$\.\]])(?P<object>[A-Za-z_$][A-Za-z0-9_$]*)\s*"
    r"(?:\.\s*(?P<dot>[A-Za-z_$][A-Za-z0-9_$]*)|"
    r"\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])"
)
_CLIENT_ENV_ALIAS_DESTRUCTURE_RE = re.compile(
    r"\b(?:const|let|var)\s*\{(?P<body>[^{}\r\n]{1,1024})\}\s*=\s*"
    rf"(?P<target>{_CLIENT_ENV_OBJECT_SOURCE_PATTERN}|"
    r"[A-Za-z_$][A-Za-z0-9_$]*)"
)
_CLIENT_ENV_DESTRUCTURED_NAME_RE = re.compile(
    r"['\"](?P<quoted>[^'\"]+)['\"]|(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
)

JS_TS_SUFFIXES = (
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
)
_NEXT_ROUTE_BASENAMES = frozenset(f"route{suffix}" for suffix in JS_TS_SUFFIXES)

SECRET_CONFIG_SUFFIXES = (
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".lock",
    ".ini",
    ".cfg",
    ".conf",
)

ALLOWED_FILE_SUFFIXES = (
    ".py",
    ".pyi",
    ".pyw",
    ".env",
    *SECRET_CONFIG_SUFFIXES,
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
    ".html",
    ".htm",
    ".css",
    ".map",
    ".go",
    ".php",
    ".rs",
    ".dart",
    ".kt",
    ".kts",
)

PROVIDER_PATTERNS = [
    ("github", re.compile(r"(ghp|gho|ghu|ghs|ghr|gpat)_[A-Za-z0-9]{36,}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("slack", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,48}")),
    ("stripe", re.compile(r"sk_(live|test)_[A-Za-z0-9]{16,}")),
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}\b"),
    ),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    ),
]

# These providers normally require word boundaries to avoid matching inside
# identifiers. A structurally approved checksum has no identifier semantics,
# so inspect its decoded payload without those boundaries before suppressing it.
CHECKSUM_PROVIDER_PATTERNS = [
    (
        "aws_access_key_id",
        re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}"),
    ),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("twilio", re.compile(r"SK[0-9a-fA-F]{32}")),
]
PROVIDER_PATTERN_BY_NAME = dict(PROVIDER_PATTERNS)

_SEGMENTED_SECRET_KEY_RE = (
    r"(?i:(?:[A-Za-z0-9]+[_-])*(?:(?:api|private)[_-]key|token|secret|"
    r"password|passwd|pwd|bearer|credentials?)"
    r"(?![A-Za-z0-9_-]*[_-](?:hash|digest|checksum|fingerprint)"
    r"(?:[_-]|(?![A-Za-z0-9_-])))"
    r"(?:[_-][A-Za-z0-9]+)*)"
)
_COMPACT_SECRET_KEY_RE = (
    r"(?i:[A-Za-z0-9]*(?:(?:api|private)key|token|secret|password|passwd|pwd|"
    r"bearer|credentials?))"
)
_SECRET_KEY_NAME_RE = rf"(?:{_SEGMENTED_SECRET_KEY_RE}|{_COMPACT_SECRET_KEY_RE})"

GENERIC_KEYED_VALUE = re.compile(
    rf"""(?x)
    (?<![A-Za-z0-9_-])
    (?P<key_quote>['"]?){_SECRET_KEY_NAME_RE}(?P=key_quote)
    (?![A-Za-z0-9_-])
    \s*[:=]\s*(?P<q>['"])(?P<val>[^'"]{{16,}})(?P=q)
"""
)

BARE_GENERIC_VALUE = re.compile(
    r"(?P<bare>(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-]))"
)

# Public compatibility pattern used by MCP diff validation. Keep this linear:
# charset requirements for bare tokens are checked in Python by scan_ctx.
GENERIC_VALUE = re.compile(
    rf"""(?x)
    (?:
      (?<![A-Za-z0-9_-])
      (?P<key_quote>['"]?){_SECRET_KEY_NAME_RE}(?P=key_quote)
      (?![A-Za-z0-9_-])
      \s*[:=]\s*(?P<q>['"])(?P<val>[^'"]{{16,}})(?P=q)
    )
    |
    (?P<bare>(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{{32,}}(?![A-Za-z0-9_-]))
"""
)

SAFE_TEST_HINTS = {
    "example",
    "sample",
    "fake",
    "placeholder",
    "dummy",
    "test_",
    "_test",
    "test_test_",
    "changeme",
    "password",
    "secret",
    "not_a_real",
    "do_not_use",
}

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NPM_PACKAGE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,213}$")
_NUGET_PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_BUN_REGISTRY_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?"
    r"(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)

INTEGRITY_FIELD_VALUE_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9_-])
    (?P<field_quote>['"]?)(?:integrity|narhash|contenthash)(?P=field_quote)
    (?![A-Za-z0-9_-])
    (?:
        \s*(?::=|[:=])\s*(?P<q>['"])(?P<quoted>[^'"]{16,})(?P=q)
        |
        \s*(?::=|[:=])\s*`(?P<template>(?:\\[^\r\n]|[^`\\\r\n])*)`
        |
        \s+(?P<bare_q>['"])(?P<bare>[^'"]{16,})(?P=bare_q)
    )
"""
)
HASH_FIELD_VALUE_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9_-])
    (?P<field_quote>['"]?)(?:hash|checksum)(?P=field_quote)
    (?![A-Za-z0-9_-])
    (?:
        \s*(?::=|[:=])\s*(?P<q>['"])(?P<quoted>[^'"]{16,})(?P=q)
        |
        \s*(?::=|[:=])\s*`(?P<template>(?:\\[^\r\n]|[^`\\\r\n])*)`
    )
"""
)
_DOTENV_ASSIGNMENT_RE = re.compile(
    r"(?i)^[ \t]*(?:export[ \t]+)?"
    r"(?:'(?P<quoted_field>[A-Za-z_][A-Za-z0-9_.-]*)'|"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*="
    r"[ \t]*(?P<value>[^\r\n]*)$"
)
_INI_CHECKSUM_VALUE_RE = re.compile(
    r"(?i)^[ \t]*(?P<field>integrity|narhash|contenthash|hash|checksum)"
    r"[ \t]*[:=][ \t]*(?P<value>[^'\"\r\n][^\r\n]*?)"
    r"(?:[ \t]+[;#][^\r\n]*)?$"
)
_INI_OPTION_RE = re.compile(r"^[ \t]*(?P<key>[^:=\s][^:=]*?)[ \t]*(?P<delimiter>[:=])")
_CHECKSUM_FIELD_NAMES = frozenset(
    {"integrity", "narhash", "contenthash", "hash", "checksum"}
)
YAML_DECORATED_VALUE_RE = re.compile(
    r"(?<!\S)(?:(?:&[A-Za-z0-9_-]+|!!?[A-Za-z0-9_:/.-]+)\s+)+"
    r"(?P<value>[^#\s,}\]]{16,})"
)
SRI_VALUE_RE = re.compile(
    r"(?i)^(?P<algorithm>sha(?:1|224|256|384|512))-(?P<digest>[A-Za-z0-9+/_-]+={0,2})$"
)
SRI_CANDIDATE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+/_-])"
    r"(?P<token>sha(?:1|224|256|384|512)-[A-Za-z0-9+/_-]+={0,2})"
    r"(?![A-Za-z0-9+/_-])"
)
NPM_SRI_VALUE_RE = re.compile(
    r"^(?P<algorithm>sha(?:256|384|512))-(?P<digest>[A-Za-z0-9+/]+={0,2})$"
)
YARN_SRI_VALUE_RE = re.compile(
    r"^(?P<algorithm>sha(?:1|256|384|512))-(?P<digest>[A-Za-z0-9+/]+={0,2})$"
)
RAW_BASE64_VALUE_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
LOWERCASE_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
DENO_V3_JSR_INTEGRITY_RE = re.compile(r"^5 [0-9a-f]{64}$")
SRI_DIGEST_LENGTHS = {
    "sha1": 20,
    "sha224": 28,
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}

NPM_LOCKFILE_NAMES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})
JSON_LOCKFILE_NAMES = frozenset(
    {
        *NPM_LOCKFILE_NAMES,
        "bun.lock",
        "deno.lock",
        "flake.lock",
        "packages.lock.json",
    }
)
PNPM_LOCKFILE_VERSIONS = frozenset({"5.2", "5.3", "5.4", "6.0", "6.1", "9.0"})
NUGET_LOCKFILE_NAME_RE = re.compile(
    r"^packages\.[A-Za-z0-9][A-Za-z0-9_.-]*\.lock\.json$"
)
YARN_V1_GENERATED_HEADER = (
    "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY."
)
YARN_V1_HEADER = "# yarn lockfile v1"
YARN_SCALAR_RE = re.compile(
    r"^  (?P<field>version|resolved|uid|registry) "
    r'(?P<q>[\'"])(?P<value>[^\'"]+)(?P=q)$'
)
YARN_INTEGRITY_RE = re.compile(
    r"^  integrity[ ]+(?P<q>['\"]?)"
    r"(?P<value>[^\s'\"]+)(?P=q)[ ]*$"
)
YARN_DEPENDENCY_HEADER_RE = re.compile(
    r"^  (?P<field>dependencies|optionalDependencies):$"
)
YARN_DEPENDENCY_RE = re.compile(
    r'^    (?P<name_q>[\'"]?)(?P<name>[^\s\'"]+)(?P=name_q) '
    r'(?P<range_q>[\'"])(?P<range>[^\'"]+)(?P=range_q)$'
)

IGNORE_DIRECTIVE = "skylos: ignore[SKY-S101]"
DEFAULT_MIN_ENTROPY = 3.9
_ORDERED_ASCII_RUN_MIN_LENGTH = 8
_ORDERED_CHARACTER_SET_PUNCTUATION = frozenset("-._~+/=")

IS_TEST_PATH = re.compile(r"(^|/)(tests?(/|$)|test_[^/]+\.py$)")


def _entropy(s):
    if len(s) == 0:
        return 0.0

    char_counts = {}
    for character in s:
        if character in char_counts:
            char_counts[character] += 1
        else:
            char_counts[character] = 1

    total_chars = len(s)
    entropy = 0.0

    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * log2(probability)

    return entropy


def _ordered_ascii_domain(character: str) -> str | None:
    if "0" <= character <= "9":
        return "digit"
    if "A" <= character <= "Z":
        return "upper"
    if "a" <= character <= "z":
        return "lower"
    return None


def _without_long_ordered_ascii_runs(value: str) -> tuple[str, int]:
    """Remove maximal ascending digit/A-Z/a-z runs without reordering input."""
    kept = []
    removed = 0
    start = 0
    while start < len(value):
        domain = _ordered_ascii_domain(value[start])
        end = start + 1
        while (
            domain is not None
            and end < len(value)
            and _ordered_ascii_domain(value[end]) == domain
            and ord(value[end]) == ord(value[end - 1]) + 1
        ):
            end += 1

        if end - start >= _ORDERED_ASCII_RUN_MIN_LENGTH:
            removed += end - start
        else:
            kept.append(value[start:end])
        start = end

    return "".join(kept), removed


def _looks_like_ordered_character_set(value: str, *, min_entropy: float) -> bool:
    """Require every alphanumeric character to be part of an ordered run."""
    residual, removed = _without_long_ordered_ascii_runs(value)
    if removed < _ORDERED_ASCII_RUN_MIN_LENGTH or any(
        character not in _ORDERED_CHARACTER_SET_PUNCTUATION
        for character in residual
    ):
        return False
    return _entropy(residual) < min_entropy


def _bare_candidate_is_complete_ordered_character_set(
    line_content: str,
    *,
    start: int,
    end: int,
    min_entropy: float,
) -> bool:
    """Return whether a bare candidate spans one complete quoted character set."""
    left = start - 1
    while (
        left >= 0
        and line_content[left] in _ORDERED_CHARACTER_SET_PUNCTUATION
    ):
        left -= 1
    if left < 0 or line_content[left] not in {"'", '"'}:
        return False

    quote = line_content[left]
    right = end
    while (
        right < len(line_content)
        and line_content[right] in _ORDERED_CHARACTER_SET_PUNCTUATION
    ):
        right += 1
    if right >= len(line_content) or line_content[right] != quote:
        return False

    return _looks_like_ordered_character_set(
        line_content[left + 1 : right],
        min_entropy=min_entropy,
    )


def _mask(tok):
    token_length = len(tok)

    if token_length <= 8:
        return "*" * token_length

    else:
        first_part = tok[:4]
        last_part = tok[-4:]
        return first_part + "…" + last_part


def _looks_like_identifier(s):
    return bool(_IDENTIFIER.fullmatch(s))


def _has_bare_token_charset_mix(s):
    has_upper = False
    has_lower = False
    has_digit = False
    for char in s:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        if has_upper and has_lower and has_digit:
            return True
    return False


def _keyed_generic_candidates(line_content: str):
    candidates = []
    keyed_spans = []
    for keyed_match in GENERIC_KEYED_VALUE.finditer(line_content):
        keyed_token = keyed_match.group("val")
        keyed_start = keyed_match.start("val")
        keyed_end = keyed_match.end("val")
        keyed_spans.append((keyed_start, keyed_end))
        candidates.append((keyed_start, 0, keyed_token, False, keyed_end))
    return candidates, keyed_spans


def _is_covered_by_span(token: str, start: int, *span_groups) -> bool:
    return any(
        _is_known_integrity_candidate(token, start, spans) for spans in span_groups
    )


def _structural_generic_candidates(structural_contexts, keyed_spans, approved_spans):
    candidates = []
    for context_start, context_end, decoded_value, _ in structural_contexts:
        value = decoded_value.strip()
        if not value or _is_covered_by_span(
            value, context_start, keyed_spans, approved_spans
        ):
            continue
        candidates.append((context_start, 1, value, False, context_end))
    return candidates


def _decorated_generic_candidates(
    line_content: str, keyed_spans, context_spans, approved_spans
):
    candidates = []
    value_spans = []
    for match in YAML_DECORATED_VALUE_RE.finditer(line_content):
        raw_value = match.group("value")
        value = raw_value.strip("'\"")
        start = match.start("value") + len(raw_value) - len(raw_value.lstrip("'\""))
        end = start + len(value)
        value_spans.append((start, end))
        if _is_covered_by_span(
            value, start, keyed_spans, context_spans, approved_spans
        ):
            continue
        candidates.append((start, 1, value, False, end))
    return candidates, value_spans


def _integrity_value_group(match):
    if match.group("quoted") is not None:
        return "quoted"
    if match.group("template") is not None:
        return "template"
    return "bare"


def _trimmed_match_value(match, group):
    raw_value = match.group(group)
    value = raw_value.strip()
    start = match.start(group) + len(raw_value) - len(raw_value.lstrip())
    return value, start, start + len(value)


def _first_unescaped_js_interpolation(value: str) -> int | None:
    search_start = 0
    while True:
        marker = value.find("${", search_start)
        if marker < 0:
            return None
        backslashes = 0
        index = marker - 1
        while index >= 0 and value[index] == "\\":
            backslashes += 1
            index -= 1
        if backslashes % 2 == 0:
            return marker
        search_start = marker + 2


def _looks_like_secret_template_prefix(value: str) -> bool:
    if len(value) < 16:
        return False
    if any(char in "$+/=" for char in value):
        return True

    character_classes = []
    for char in value:
        if char.islower():
            character_classes.append("lower")
        elif char.isupper():
            character_classes.append("upper")
        elif char.isdigit():
            character_classes.append("digit")
    transitions = sum(
        left != right
        for left, right in zip(character_classes, character_classes[1:])
    )
    return transitions >= 10


def _checksum_match_values(
    match, group: str, rel_name: str
) -> tuple[tuple[str, int, int], ...]:
    value, start, end = _trimmed_match_value(match, group)
    if group == "template":
        normalized = rel_name.lower()
        if normalized.endswith(".go"):
            return ((value, start, end),) if len(value) >= 16 else ()
        if not normalized.endswith((*JS_TS_SUFFIXES, ".html", ".htm")):
            return ()
        interpolation = _first_unescaped_js_interpolation(value)
        if interpolation is not None:
            prefix = value[:interpolation].rstrip()
            if not _looks_like_secret_template_prefix(prefix):
                return ()
            return ((prefix, start, start + len(prefix)),)
        return ((value, start, end),) if len(value) >= 16 else ()
    return ((value, start, end),)


def _integrity_field_candidates(
    line_content: str,
    keyed_spans,
    context_spans,
    approved_spans,
    *,
    rel_name: str,
):
    candidates = []
    value_spans = []
    for match in INTEGRITY_FIELD_VALUE_RE.finditer(line_content):
        group = _integrity_value_group(match)
        for value, start, end in _checksum_match_values(match, group, rel_name):
            value_spans.append((start, end))
            if _is_covered_by_span(
                value, start, keyed_spans, context_spans, approved_spans
            ):
                continue
            candidates.append((start, 1, value, False, end))
    return candidates, value_spans


def _hash_field_candidates(
    line_content: str,
    keyed_spans,
    context_spans,
    approved_spans,
    *,
    rel_name: str,
):
    candidates = []
    value_spans = []
    for match in HASH_FIELD_VALUE_RE.finditer(line_content):
        if match.group("quoted") is not None:
            group = "quoted"
        else:
            group = "template"
        for value, start, end in _checksum_match_values(match, group, rel_name):
            value_spans.append((start, end))
            if _is_conventional_lowercase_hash(value) or _is_covered_by_span(
                value, start, keyed_spans, context_spans, approved_spans
            ):
                continue
            candidates.append((start, 1, value, False, end))
    return candidates, value_spans


def _sri_generic_candidates(
    line_content: str, keyed_spans, integrity_spans, approved_spans
):
    candidates = []
    sri_spans = []
    for match in SRI_CANDIDATE_RE.finditer(line_content):
        token = match.group("token")
        start = match.start("token")
        end = match.end("token")
        if _is_covered_by_span(
            token, start, keyed_spans, integrity_spans, approved_spans
        ):
            continue
        sri_spans.append((start, end))
        candidates.append((start, 2, token, True, end))
    return candidates, sri_spans


def _bare_generic_candidates(
    line_content: str, keyed_spans, sri_spans, integrity_spans, approved_spans
):
    candidates = []
    for match in BARE_GENERIC_VALUE.finditer(line_content):
        token = match.group("bare")
        start = match.start("bare")
        if not _has_bare_token_charset_mix(token) or _is_covered_by_span(
            token, start, keyed_spans, sri_spans, integrity_spans, approved_spans
        ):
            continue
        candidates.append((start, 3, token, True, match.end("bare")))
    return candidates


def _find_generic_values(
    line_content: str,
    *,
    approved_structural_spans: tuple[tuple[int, int], ...],
    structural_contexts: tuple[tuple[int, int, str, str], ...],
    rel_name: str,
):
    if rel_name == "yarn.lock":
        yarn_match = YARN_INTEGRITY_RE.fullmatch(line_content)
        if yarn_match is not None:
            value = yarn_match.group("value")
            structural_contexts = (
                *structural_contexts,
                (
                    yarn_match.start("value"),
                    yarn_match.end("value"),
                    value,
                    value,
                ),
            )
    approved_spans = _merge_spans(approved_structural_spans)
    context_spans = _merge_spans(
        (start, end) for start, end, _, _ in structural_contexts
    )
    candidates, keyed_spans = _keyed_generic_candidates(line_content)
    candidates.extend(
        _structural_generic_candidates(structural_contexts, keyed_spans, approved_spans)
    )

    integrity_spans = list(context_spans)
    decorated, decorated_spans = _decorated_generic_candidates(
        line_content, keyed_spans, context_spans, approved_spans
    )
    integrity, field_spans = _integrity_field_candidates(
        line_content,
        keyed_spans,
        context_spans,
        approved_spans,
        rel_name=rel_name,
    )
    hashes, hash_spans = _hash_field_candidates(
        line_content,
        keyed_spans,
        context_spans,
        approved_spans,
        rel_name=rel_name,
    )
    candidates.extend((*decorated, *integrity, *hashes))
    integrity_spans.extend((*decorated_spans, *field_spans, *hash_spans))
    integrity_spans = _merge_spans(integrity_spans)
    sri, sri_spans = _sri_generic_candidates(
        line_content, keyed_spans, integrity_spans, approved_spans
    )
    candidates.extend(sri)
    candidates.extend(
        _bare_generic_candidates(
            line_content,
            keyed_spans,
            sri_spans,
            integrity_spans,
            approved_spans,
        )
    )

    for start, _, token, is_bare, source_end in sorted(candidates):
        yield token, is_bare, start, source_end


def _merge_spans(spans) -> list[tuple[int, int]]:
    spans = sorted(spans)
    if not spans:
        return []

    merged = [spans[0]]
    for start, end in spans[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


def _is_known_integrity_candidate(
    token: str, start: int, known_integrity_spans: list[tuple[int, int]]
) -> bool:
    end = start + len(token)
    span_index = bisect_right(known_integrity_spans, (start, float("inf"))) - 1
    if span_index < 0:
        return False
    span_start, span_end = known_integrity_spans[span_index]
    return span_start <= start and end <= span_end


def _is_valid_sri_token(value: str) -> bool:
    match = SRI_VALUE_RE.fullmatch(value)
    if match is None:
        return False

    algorithm = match.group("algorithm").lower()
    expected_digest_length = SRI_DIGEST_LENGTHS[algorithm]
    expected_encoded_length = 4 * ((expected_digest_length + 2) // 3)
    expected_padding = (-expected_digest_length) % 3
    encoded_digest = match.group("digest")
    unpadded_digest = encoded_digest.rstrip("=")
    supplied_padding = len(encoded_digest) - len(unpadded_digest)
    if len(
        unpadded_digest
    ) != expected_encoded_length - expected_padding or supplied_padding not in {
        0,
        expected_padding,
    }:
        return False

    normalized_digest = unpadded_digest.translate(str.maketrans("-_", "+/"))
    normalized_digest += "=" * expected_padding
    try:
        digest = base64.b64decode(normalized_digest, validate=True)
    except (binascii.Error, ValueError):
        return False

    return len(digest) == expected_digest_length


def _is_valid_standard_sri_token(value: str, pattern) -> bool:
    match = pattern.fullmatch(value)
    if match is None:
        return False

    algorithm = match.group("algorithm")
    expected_digest_length = SRI_DIGEST_LENGTHS[algorithm]
    expected_encoded_length = 4 * ((expected_digest_length + 2) // 3)
    expected_padding = (-expected_digest_length) % 3
    encoded_digest = match.group("digest")
    unpadded_digest = encoded_digest.rstrip("=")
    supplied_padding = len(encoded_digest) - len(unpadded_digest)
    if len(
        unpadded_digest
    ) != expected_encoded_length - expected_padding or supplied_padding not in {
        0,
        expected_padding,
    }:
        return False

    normalized_digest = unpadded_digest + ("=" * expected_padding)
    try:
        digest = base64.b64decode(normalized_digest, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(digest) == expected_digest_length


def _is_valid_npm_sri_token(value: str) -> bool:
    return _is_valid_standard_sri_token(value, NPM_SRI_VALUE_RE)


def _is_valid_yarn_sri_token(value: str) -> bool:
    return _is_valid_standard_sri_token(value, YARN_SRI_VALUE_RE)


def _is_valid_sri_list(value: str, token_validator) -> bool:
    if value.strip() != value or any(character in value for character in "\t\r\n"):
        return False
    tokens = value.split(" ")
    return (
        1 <= len(tokens) <= 8
        and all(tokens)
        and all(token_validator(token) for token in tokens)
    )


def _is_valid_raw_sha512(value: str) -> bool:
    if RAW_BASE64_VALUE_RE.fullmatch(value) is None:
        return False
    unpadded_value = value.rstrip("=")
    if len(unpadded_value) != 86 or len(value) - len(unpadded_value) != 2:
        return False
    try:
        digest = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(digest) == 64


def _is_conventional_lowercase_hash(value: str) -> bool:
    prefixed = re.fullmatch(r"(sha(?:1|224|256|384|512))[:=-]([0-9a-f]+)", value)
    if prefixed is not None:
        return len(prefixed.group(2)) == 2 * SRI_DIGEST_LENGTHS[prefixed.group(1)]
    return (
        len(value)
        in {2 * digest_length for digest_length in SRI_DIGEST_LENGTHS.values()}
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


_JSON_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_MAX_JSON_DEPTH = 256
_MAX_JSON_NODES = 500_000
_MAX_JSON_CAPTURED_STRINGS = 100_000
_MAX_PNPM_YAML_NODES = 500_000
_MAX_GENERIC_YAML_EVENTS = 500_000
_MAX_GENERIC_YAML_NODES = 500_000
_MAX_YARN_ENTRIES = 100_000
_MAX_YARN_HEADER_LENGTH = 65_536
_MAX_YARN_SELECTORS = 4_096
_MAX_YARN_ENTRY_DEPENDENCIES = 100_000


class _SecretContextLimit(ValueError):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.line = max(1, line)


class _JsonSpanParser:
    def __init__(self, source: str, *, capture_path, root_keys, jsonc: bool = False):
        self.source = source
        self.capture_path = capture_path
        self.root_keys = root_keys
        self.jsonc = jsonc
        self.index = 0
        self.node_count = 0
        self.string_spans = []

    def parse(self):
        value = self._parse_value((), 0)
        self._skip_ignored()
        if self.index != len(self.source):
            raise ValueError("trailing JSON content")
        return value, self.string_spans

    def _parse_value(self, path, depth):
        self._enter_value(depth)
        self._skip_ignored()
        if self.index >= len(self.source):
            raise ValueError("missing JSON value")

        char = self.source[self.index]
        if char == "{":
            return self._parse_object(path, depth)
        if char == "[":
            return self._parse_array(path, depth)
        if char == '"':
            return self._parse_captured_string(path)
        return self._parse_scalar_value()

    def _enter_value(self, depth):
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        self.node_count += 1
        if self.node_count > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded")

    def _parse_captured_string(self, path):
        value, start, end = self._parse_string()
        capture_kind = self.capture_path(path)
        if capture_kind is None:
            return value
        if len(self.string_spans) >= _MAX_JSON_CAPTURED_STRINGS:
            raise ValueError("JSON capture limit exceeded")
        self.string_spans.append((capture_kind, value, start, end))
        return value

    def _parse_scalar_value(self):
        if self.source.startswith("true", self.index):
            self.index += 4
            return True
        if self.source.startswith("false", self.index):
            self.index += 5
            return False
        if self.source.startswith("null", self.index):
            self.index += 4
            return None

        match = _JSON_NUMBER_RE.match(self.source, self.index)
        if match is None:
            raise ValueError("invalid JSON value")
        token = match.group(0)
        self.index = match.end()
        if any(marker in token for marker in ".eE"):
            return float(token)
        return int(token)

    def _parse_object(self, path, depth):
        self.index += 1
        root_result = {} if not path else None
        seen_keys = set()
        self._skip_ignored()
        if self._consume("}"):
            return root_result

        while True:
            key = self._parse_object_key(seen_keys)
            value = self._parse_value((*path, key), depth + 1)
            if root_result is not None and key in self.root_keys:
                root_result[key] = value
            if self._finish_object_member():
                return root_result

    def _parse_object_key(self, seen_keys):
        self._skip_ignored()
        if self.index >= len(self.source) or self.source[self.index] != '"':
            raise ValueError("JSON object key must be a string")
        key, _, _ = self._parse_string()
        if key in seen_keys:
            raise ValueError("duplicate JSON key")
        seen_keys.add(key)
        self._skip_ignored()
        if not self._consume(":"):
            raise ValueError("missing JSON object colon")
        return key

    def _finish_object_member(self):
        self._skip_ignored()
        if self._consume("}"):
            return True
        if not self._consume(","):
            raise ValueError("missing JSON object separator")
        self._skip_ignored()
        if self.index >= len(self.source) or self.source[self.index] != "}":
            return False
        if not self.jsonc:
            raise ValueError("trailing JSON object comma")
        self.index += 1
        return True

    def _parse_array(self, path, depth):
        self.index += 1
        item_index = 0
        self._skip_ignored()
        if self._consume("]"):
            return [] if not path else None

        while True:
            item_path = (*path, item_index)
            self._parse_value(item_path, depth + 1)
            item_index += 1
            self._skip_ignored()
            if self._consume("]"):
                return [] if not path else None
            if not self._consume(","):
                raise ValueError("missing JSON array separator")
            self._skip_ignored()
            if self.index < len(self.source) and self.source[self.index] == "]":
                if not self.jsonc:
                    raise ValueError("trailing JSON array comma")
                self.index += 1
                return [] if not path else None

    def _parse_string(self):
        content_start = self.index + 1
        try:
            value, end = json.decoder.scanstring(self.source, content_start, True)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid JSON string") from exc
        self.index = end
        return value, content_start, end - 1

    def _skip_ignored(self):
        while True:
            while (
                self.index < len(self.source) and self.source[self.index] in " \t\r\n"
            ):
                self.index += 1
            if not self.jsonc or self.index + 1 >= len(self.source):
                return
            marker = self.source[self.index : self.index + 2]
            if marker == "//":
                line_end_candidates = [
                    position
                    for position in (
                        self.source.find("\r", self.index + 2),
                        self.source.find("\n", self.index + 2),
                    )
                    if position >= 0
                ]
                if not line_end_candidates:
                    self.index = len(self.source)
                else:
                    line_end = min(line_end_candidates)
                    self.index = line_end + (
                        2 if self.source.startswith("\r\n", line_end) else 1
                    )
                continue
            if marker == "/*":
                comment_end = self.source.find("*/", self.index + 2)
                if comment_end < 0:
                    raise ValueError("unterminated JSONC comment")
                self.index = comment_end + 2
                continue
            return

    def _consume(self, token: str) -> bool:
        if self.source.startswith(token, self.index):
            self.index += len(token)
            return True
        return False


def _is_safe_npm_package_name(package_name) -> bool:
    if not isinstance(package_name, str) or "\\" in package_name:
        return False
    parts = package_name.split("/")
    if package_name.startswith("@"):
        return (
            len(package_name) <= 214
            and len(parts) == 2
            and _NPM_PACKAGE_SEGMENT_RE.fullmatch(parts[0][1:]) is not None
            and _NPM_PACKAGE_SEGMENT_RE.fullmatch(parts[1]) is not None
        )
    return len(parts) == 1 and _NPM_PACKAGE_SEGMENT_RE.fullmatch(parts[0]) is not None


def _split_npm_descriptor(selector: str):
    if selector.startswith("@"):
        scope_end = selector.find("/")
        delimiter = selector.find("@", scope_end + 1) if scope_end > 1 else -1
    else:
        delimiter = selector.find("@")
    if delimiter <= 0:
        return None
    package_name = selector[:delimiter]
    requested = selector[delimiter + 1 :]
    if not requested or not _is_safe_npm_package_name(package_name):
        return None
    return package_name, requested


def _has_safe_pnpm_id_text(package_id) -> bool:
    return (
        isinstance(package_id, str)
        and len(package_id) <= 1024
        and "\\" not in package_id
        and ".." not in package_id
        and all(
            character.isprintable() and not character.isspace()
            for character in package_id
        )
    )


def _is_safe_pnpm_descriptor_id(package_id: str, *, leading_slash: bool) -> bool:
    if leading_slash:
        if not package_id.startswith("/"):
            return False
        package_id = package_id[1:]
    descriptor = _split_npm_descriptor(package_id)
    return descriptor is not None and descriptor[1][0].isalnum()


def _is_safe_pnpm_v5_id(package_id: str) -> bool:
    if not package_id.startswith("/"):
        return False
    parts = package_id[1:].split("/")
    if parts[0].startswith("@"):
        if len(parts) != 3:
            return False
        package_name = f"{parts[0]}/{parts[1]}"
        version = parts[2]
    else:
        if len(parts) != 2:
            return False
        package_name, version = parts
    return (
        _is_safe_npm_package_name(package_name)
        and bool(version)
        and version[0].isalnum()
    )


def _is_safe_pnpm_package_id(package_id, lockfile_version: str) -> bool:
    if not _has_safe_pnpm_id_text(package_id):
        return False
    if lockfile_version == "9.0":
        return _is_safe_pnpm_descriptor_id(package_id, leading_slash=False)
    if lockfile_version in {"6.0", "6.1"}:
        return _is_safe_pnpm_descriptor_id(package_id, leading_slash=True)
    return _is_safe_pnpm_v5_id(package_id)


def _is_safe_nuget_package_id(package_id) -> bool:
    return (
        isinstance(package_id, str)
        and _NUGET_PACKAGE_ID_RE.fullmatch(package_id) is not None
    )


def _is_safe_npm_package_path(package_path) -> bool:
    if not isinstance(package_path, str) or "\\" in package_path:
        return False

    parts = package_path.split("/")
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules" or index + 1 >= len(parts):
            return False
        index += 1
        if parts[index].startswith("@"):
            if index + 1 >= len(parts):
                return False
            package_name = f"{parts[index]}/{parts[index + 1]}"
            index += 2
        else:
            package_name = parts[index]
            index += 1
        if not _is_safe_npm_package_name(package_name):
            return False
    return True


def _is_npm_integrity_path(path, lockfile_version: int) -> bool:
    if lockfile_version in {2, 3} and len(path) == 3 and path[0] == "packages":
        return _is_safe_npm_package_path(path[1]) and path[2] == "integrity"

    if lockfile_version not in {1, 2}:
        return False
    if len(path) < 3 or len(path) % 2 == 0 or path[-1] != "integrity":
        return False
    for index, segment in enumerate(path[:-1]):
        if index % 2 == 0:
            if segment != "dependencies":
                return False
        elif not _is_safe_npm_package_name(segment):
            return False
    return True


def _is_safe_bun_package_key(package_key) -> bool:
    if not isinstance(package_key, str) or "\\" in package_key:
        return False
    parts = package_key.split("/")
    index = 0
    while index < len(parts):
        if parts[index].startswith("@"):
            if index + 1 >= len(parts):
                return False
            package_name = f"{parts[index]}/{parts[index + 1]}"
            index += 2
        else:
            package_name = parts[index]
            index += 1
        if not _is_safe_npm_package_name(package_name):
            return False
    return bool(parts)


def _is_bun_package_tuple_path(path, item_index: int) -> bool:
    return (
        len(path) == 3
        and path[0] == "packages"
        and _is_safe_bun_package_key(path[1])
        and path[2] == item_index
    )


def _is_bun_registry_descriptor(value: str) -> bool:
    descriptor = _split_npm_descriptor(value)
    return (
        descriptor is not None
        and _BUN_REGISTRY_VERSION_RE.fullmatch(descriptor[1]) is not None
    )


def _is_deno_package_integrity_path(path, *, ecosystem: str) -> bool:
    if len(path) != 3 or path[0] != ecosystem or path[2] != "integrity":
        return False
    descriptor = _split_npm_descriptor(path[1])
    if descriptor is None:
        return False
    requested = descriptor[1]
    return (
        requested[0].isalnum()
        and "\\" not in requested
        and ".." not in requested
        and all(
            character.isprintable() and not character.isspace()
            for character in requested
        )
    )


def _deno_integrity_kind(path):
    if len(path) == 3:
        candidate_path = path
        version_family = "v4"
    elif len(path) == 4 and path[:2] == ("npm", "packages"):
        candidate_path = ("npm", *path[2:])
        version_family = "v2"
    elif len(path) == 4 and path[:2] in {
        ("packages", "npm"),
        ("packages", "jsr"),
    }:
        candidate_path = (path[1], *path[2:])
        version_family = "v3"
    else:
        return None

    ecosystem = candidate_path[0]
    if ecosystem not in {"npm", "jsr"} or not _is_deno_package_integrity_path(
        candidate_path, ecosystem=ecosystem
    ):
        return None
    if version_family == "v2" and ecosystem != "npm":
        return None
    return f"deno_{version_family}_{ecosystem}"


def _is_flake_narhash_path(path) -> bool:
    return (
        len(path) == 4
        and path[0] == "nodes"
        and isinstance(path[1], str)
        and path[1] not in {"", ".", ".."}
        and "\\" not in path[1]
        and path[2:] == ("locked", "narHash")
    )


def _is_nuget_contenthash_path(path) -> bool:
    return (
        len(path) == 4
        and path[0] == "dependencies"
        and isinstance(path[1], str)
        and bool(path[1])
        and _is_safe_nuget_package_id(path[2])
        and path[3] == "contentHash"
    )


def _is_nuget_lockfile_name(rel_name: str) -> bool:
    return rel_name == "packages.lock.json" or (
        NUGET_LOCKFILE_NAME_RE.fullmatch(rel_name) is not None
    )


def _line_spans(source: str, absolute_spans) -> dict[int, tuple[tuple[int, int], ...]]:
    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer(r"\r\n?|\n", source))
    spans_by_line = {}
    for start, end in absolute_spans:
        line_index = bisect_right(line_starts, start) - 1
        end_line_index = bisect_right(line_starts, max(start, end - 1)) - 1
        if line_index != end_line_index:
            continue
        line_start = line_starts[line_index]
        spans_by_line.setdefault(line_index + 1, []).append(
            (start - line_start, end - line_start)
        )
    return {line: tuple(sorted(spans)) for line, spans in spans_by_line.items()}


def _line_contexts(source: str, absolute_contexts):
    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer(r"\r\n?|\n", source))
    contexts_by_line = {}
    for start, end, value in absolute_contexts:
        raw_value = (
            value
            if end - start == len(value) and source.startswith(value, start, end)
            else source[start:end]
        )
        line_index = bisect_right(line_starts, start) - 1
        end_line_index = bisect_right(line_starts, max(start, end - 1)) - 1
        line_start = line_starts[line_index]
        if line_index != end_line_index:
            # Multiline scalars are never approved. Keep their line-local span
            # to the scalar indicator so an inline comment cannot be mistaken
            # for part of the decoded value and hidden from raw scanning.
            end = start + 1
        contexts_by_line.setdefault(line_index + 1, []).append(
            (start - line_start, end - line_start, value, raw_value)
        )
    return {
        line: tuple(sorted(contexts)) for line, contexts in contexts_by_line.items()
    }


def _parse_yarn_entry_header(line: str):
    if (
        not line
        or len(line) > _MAX_YARN_HEADER_LENGTH
        or line[0].isspace()
        or not line.endswith(":")
        or line.count(", ") >= _MAX_YARN_SELECTORS
    ):
        return None
    selectors = line[:-1].split(", ")
    if not selectors:
        return None
    normalized_selectors = []
    for selector in selectors:
        if len(selector) >= 2 and selector[0] in {'"', "'"}:
            if selector[-1] != selector[0]:
                return None
            selector = selector[1:-1]
        elif '"' in selector or "'" in selector:
            return None
        if _split_npm_descriptor(selector) is None:
            return None
        normalized_selectors.append(selector)
    return tuple(normalized_selectors)


def _new_yarn_entry():
    return {
        "scalar_fields": set(),
        "integrities": [],
        "dependency_fields": set(),
        "dependency_keys": {},
        "dependency_section": None,
    }


def _finish_yarn_entry(entry, approved_candidates) -> bool:
    if entry is None:
        return True
    if "version" not in entry["scalar_fields"]:
        return False
    if len(entry["integrities"]) == 1:
        line_number, start, end, value = entry["integrities"][0]
        if _is_valid_yarn_sri_token(value):
            approved_candidates.append((line_number, start, end))
    return True


def _start_yarn_entry(line: str, seen_selectors):
    selectors = _parse_yarn_entry_header(line)
    if selectors is None:
        return None
    fingerprints = {
        blake2s(selector.encode("utf-8", "surrogatepass"), digest_size=16).digest()
        for selector in selectors
    }
    if len(fingerprints) != len(selectors) or any(
        fingerprint in seen_selectors for fingerprint in fingerprints
    ):
        return None
    seen_selectors.update(fingerprints)
    return _new_yarn_entry()


def _record_yarn_scalar(entry, line: str):
    match = YARN_SCALAR_RE.fullmatch(line)
    if match is None:
        return None
    field = match.group("field")
    if field in entry["scalar_fields"]:
        return False
    entry["scalar_fields"].add(field)
    entry["dependency_section"] = None
    return True


def _record_yarn_integrity(entry, line: str, line_number: int):
    match = YARN_INTEGRITY_RE.fullmatch(line)
    if match is None:
        return None
    if entry["integrities"]:
        return False
    entry["integrities"].append(
        (
            line_number,
            match.start("value"),
            match.end("value"),
            match.group("value"),
        )
    )
    entry["dependency_section"] = None
    return True


def _record_yarn_dependency_header(entry, line: str):
    match = YARN_DEPENDENCY_HEADER_RE.fullmatch(line)
    if match is None:
        return None
    field = match.group("field")
    if field in entry["dependency_fields"]:
        return False
    entry["dependency_fields"].add(field)
    entry["dependency_keys"].setdefault(field, set())
    entry["dependency_section"] = field
    return True


def _record_yarn_dependency(entry, line: str) -> bool:
    match = YARN_DEPENDENCY_RE.fullmatch(line)
    section = entry["dependency_section"]
    if match is None or section is None:
        return False
    package_name = match.group("name")
    dependency_keys = entry["dependency_keys"][section]
    fingerprint = blake2s(
        package_name.encode("utf-8", "surrogatepass"), digest_size=16
    ).digest()
    if (
        not _is_safe_npm_package_name(package_name)
        or len(dependency_keys) >= _MAX_YARN_ENTRY_DEPENDENCIES
        or fingerprint in dependency_keys
    ):
        return False
    dependency_keys.add(fingerprint)
    return True


def _consume_yarn_entry_line(entry, line: str, line_number: int) -> bool:
    result = _record_yarn_scalar(entry, line)
    if result is not None:
        return result
    result = _record_yarn_integrity(entry, line, line_number)
    if result is not None:
        return result
    result = _record_yarn_dependency_header(entry, line)
    if result is not None:
        return result
    return _record_yarn_dependency(entry, line)


def _group_yarn_approved_spans(approved_candidates):
    approved_by_line = {}
    for line_number, start, end in approved_candidates:
        approved_by_line.setdefault(line_number, []).append((start, end))
    return {line: tuple(sorted(spans)) for line, spans in approved_by_line.items()}


def _yarn_integrity_spans(file_lines: list[str]):
    expected_header = [YARN_V1_GENERATED_HEADER, YARN_V1_HEADER]
    if (
        len(file_lines) < 2
        or [line.rstrip("\r\n") for line in file_lines[:2]] != expected_header
    ):
        return {}, {}

    current_entry = None
    seen_selectors = set()
    entry_count = 0
    approved_candidates = []
    for line_number, raw_line in enumerate(file_lines[2:], start=3):
        line = raw_line.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            if current_entry is None or not _consume_yarn_entry_line(
                current_entry, line, line_number
            ):
                return {}, {}
            continue
        if not _finish_yarn_entry(current_entry, approved_candidates):
            return {}, {}
        entry_count += 1
        if entry_count > _MAX_YARN_ENTRIES:
            return {}, {}
        current_entry = _start_yarn_entry(line, seen_selectors)
        if current_entry is None:
            return {}, {}

    if not _finish_yarn_entry(current_entry, approved_candidates):
        return {}, {}
    return _group_yarn_approved_spans(approved_candidates), {}


def _capture_npm_integrity_path(path):
    if not path or path[-1] != "integrity":
        return None
    return path[0] if _is_npm_integrity_path(path, 2) else "context"


def _capture_bun_integrity_path(path):
    if _is_bun_package_tuple_path(path, 0):
        return ("bun_descriptor", path[1])
    if _is_bun_package_tuple_path(path, 3):
        return ("bun_integrity", path[1])
    if len(path) == 3 and path[0] == "packages" and path[2] == 3:
        return "context"
    if path and path[-1] == "integrity":
        return "context"
    return None


def _capture_deno_integrity_path(path):
    if not path or path[-1] != "integrity":
        return None
    return _deno_integrity_kind(path) or "context"


def _capture_flake_integrity_path(path):
    if not path or path[-1] != "narHash":
        return None
    return "flake" if _is_flake_narhash_path(path) else "context"


def _capture_nuget_integrity_path(path):
    if not path or path[-1] != "contentHash":
        return None
    return "nuget" if _is_nuget_contenthash_path(path) else "context"


def _json_capture_path_for(rel_name: str):
    if rel_name in NPM_LOCKFILE_NAMES:
        return _capture_npm_integrity_path
    if rel_name == "bun.lock":
        return _capture_bun_integrity_path
    if rel_name == "deno.lock":
        return _capture_deno_integrity_path
    if rel_name == "flake.lock":
        return _capture_flake_integrity_path
    return _capture_nuget_integrity_path


def _json_context_values(rel_name: str, string_spans):
    return [
        (start, end, value)
        for kind, value, start, end in string_spans
        if not (
            rel_name == "bun.lock"
            and isinstance(kind, tuple)
            and kind[0] == "bun_descriptor"
        )
    ]


def _npm_integrity_validator(kind, lockfile_version):
    packages_context = kind == "packages" and lockfile_version in {2, 3}
    dependencies_context = kind == "dependencies" and lockfile_version in {1, 2}
    if not packages_context and not dependencies_context:
        return None
    if dependencies_context or lockfile_version == 2:
        return _is_valid_yarn_sri_token
    return _is_valid_npm_sri_token


def _approved_npm_json_spans(document, string_spans):
    lockfile_version = document.get("lockfileVersion")
    if type(lockfile_version) is not int or lockfile_version not in {1, 2, 3}:
        return []
    approved_spans = []
    for kind, value, start, end in string_spans:
        validator = _npm_integrity_validator(kind, lockfile_version)
        if validator is not None and _is_valid_sri_list(value, validator):
            approved_spans.append((start, end))
    return approved_spans


def _approved_bun_json_spans(document, string_spans):
    lockfile_version = document.get("lockfileVersion")
    if type(lockfile_version) is not int or lockfile_version not in {0, 1}:
        return []
    descriptors = {
        kind[1]: value
        for kind, value, _, _ in string_spans
        if isinstance(kind, tuple) and kind[0] == "bun_descriptor"
    }
    return [
        (start, end)
        for kind, value, start, end in string_spans
        if isinstance(kind, tuple)
        and kind[0] == "bun_integrity"
        and _is_bun_registry_descriptor(descriptors.get(kind[1], ""))
        and _is_valid_sri_token(value)
    ]


def _is_approved_deno_integrity(kind, value, expected_prefix, lockfile_version):
    if not isinstance(kind, str) or not kind.startswith(expected_prefix):
        return False
    if kind.endswith("_npm"):
        return _is_valid_sri_list(value, _is_valid_npm_sri_token)
    if not kind.endswith("_jsr"):
        return False
    if lockfile_version == "3":
        return DENO_V3_JSR_INTEGRITY_RE.fullmatch(value) is not None
    return LOWERCASE_SHA256_HEX_RE.fullmatch(value) is not None


def _approved_deno_json_spans(document, string_spans):
    lockfile_version = document.get("version")
    expected_prefix = {
        "2": "deno_v2_",
        "3": "deno_v3_",
        "4": "deno_v4_",
        "5": "deno_v4_",
    }.get(lockfile_version)
    if expected_prefix is None:
        return []
    return [
        (start, end)
        for kind, value, start, end in string_spans
        if _is_approved_deno_integrity(kind, value, expected_prefix, lockfile_version)
    ]


def _approved_flake_json_spans(document, string_spans):
    if type(document.get("version")) is not int or document.get("version") != 7:
        return []
    return [
        (start, end)
        for kind, value, start, end in string_spans
        if kind == "flake"
        and value.startswith("sha256-")
        and _is_valid_npm_sri_token(value)
    ]


def _approved_nuget_json_spans(document, string_spans):
    if type(document.get("version")) is not int or document.get("version") != 1:
        return []
    return [
        (start, end)
        for kind, value, start, end in string_spans
        if kind == "nuget" and _is_valid_raw_sha512(value)
    ]


def _approved_json_spans(rel_name: str, document, string_spans):
    if rel_name in NPM_LOCKFILE_NAMES:
        return _approved_npm_json_spans(document, string_spans)
    if rel_name == "bun.lock":
        return _approved_bun_json_spans(document, string_spans)
    if rel_name == "deno.lock":
        return _approved_deno_json_spans(document, string_spans)
    if rel_name == "flake.lock":
        return _approved_flake_json_spans(document, string_spans)
    return _approved_nuget_json_spans(document, string_spans)


def _json_integrity_spans(rel_name: str, file_lines: list[str]):
    if rel_name not in JSON_LOCKFILE_NAMES and not _is_nuget_lockfile_name(rel_name):
        return {}, {}

    source = "".join(file_lines)
    root_key = (
        "lockfileVersion"
        if rel_name in {*NPM_LOCKFILE_NAMES, "bun.lock"}
        else "version"
    )
    parser = _JsonSpanParser(
        source,
        capture_path=_json_capture_path_for(rel_name),
        root_keys={root_key},
        jsonc=rel_name == "bun.lock",
    )
    try:
        document, string_spans = parser.parse()
    except MemoryError:
        return {}, {}
    except (OverflowError, RecursionError, ValueError):
        partial_context = _json_context_values(rel_name, parser.string_spans)
        return {}, _line_contexts(source, partial_context)

    all_contexts = _json_context_values(rel_name, string_spans)
    context_by_line = _line_contexts(source, all_contexts)
    if not isinstance(document, dict):
        return {}, context_by_line
    approved_spans = _approved_json_spans(rel_name, document, string_spans)
    return _line_spans(source, approved_spans), context_by_line


def _yaml_scalar_content_span(source: str, event):
    start = event.start_mark.index
    end = event.end_mark.index
    if event.style in {'"', "'"}:
        quote_offset = source.find(event.style, start, end)
        if quote_offset < 0:
            return None
        start = quote_offset + 1
        end -= 1
    elif source.startswith(event.value, end - len(event.value), end):
        # Event start marks include an optional tag/anchor prefix. Anchor
        # aliases should report the scalar itself, not the `&name` marker.
        start = end - len(event.value)
    if start > end:
        return None
    return start, end


class _YamlSpanParser:
    def __init__(self, source: str, *, capture_path, loader):
        self.source = source
        self.capture_path = capture_path
        self.events = iter(yaml.parse(source, Loader=loader))
        self.event_count = 0
        self.node_count = 0
        self.string_spans = []

    def parse(self):
        self._expect(yaml.events.StreamStartEvent)
        self._expect(yaml.events.DocumentStartEvent)
        document = self._parse_node((), 0)
        self._expect(yaml.events.DocumentEndEvent)
        self._expect(yaml.events.StreamEndEvent)
        try:
            next(self.events)
        except StopIteration:
            return document, self.string_spans
        raise ValueError("trailing YAML events")

    def _next_event(self):
        self.event_count += 1
        if self.event_count > _MAX_PNPM_YAML_NODES:
            raise ValueError("YAML event limit exceeded")
        try:
            return next(self.events)
        except StopIteration as exc:
            raise ValueError("incomplete YAML event stream") from exc

    def _expect(self, event_type):
        event = self._next_event()
        if not isinstance(event, event_type):
            raise ValueError("unexpected YAML event")
        return event

    def _parse_node(self, path, depth, event=None):
        self._enter_node(depth)
        event = self._next_event() if event is None else event
        if isinstance(event, yaml.events.ScalarEvent):
            return self._parse_scalar_event(path, event)
        if isinstance(event, yaml.events.AliasEvent):
            raise ValueError("YAML aliases are not accepted")
        if isinstance(event, yaml.events.MappingStartEvent):
            return self._parse_mapping_event(path, depth, event)
        if isinstance(event, yaml.events.SequenceStartEvent):
            return self._parse_sequence_event(path, depth, event)
        raise ValueError("unsupported YAML node")

    def _enter_node(self, depth):
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("YAML nesting limit exceeded")
        self.node_count += 1
        if self.node_count > _MAX_PNPM_YAML_NODES:
            raise ValueError("YAML node limit exceeded")

    def _parse_scalar_event(self, path, event):
        capture_kind = self.capture_path(path)
        span = _yaml_scalar_content_span(self.source, event)
        if capture_kind is not None and span is not None:
            if len(self.string_spans) >= _MAX_JSON_CAPTURED_STRINGS:
                raise ValueError("YAML capture limit exceeded")
            self.string_spans.append((capture_kind, event.value, *span))
        if event.anchor is not None or event.tag is not None:
            raise ValueError("anchored or tagged YAML scalar")
        return event.value

    def _parse_mapping_key(self, event, seen_keys):
        if (
            not isinstance(event, yaml.events.ScalarEvent)
            or event.anchor is not None
            or event.tag is not None
            or event.value == "<<"
        ):
            raise ValueError("unsupported YAML mapping key")
        key = event.value
        if key in seen_keys:
            raise ValueError("duplicate YAML mapping key")
        seen_keys.add(key)
        return key

    def _parse_mapping_event(self, path, depth, event):
        if event.anchor is not None or event.tag is not None:
            raise ValueError("anchored or tagged YAML mapping")
        root_result = {} if not path else None
        seen_keys = set()
        while True:
            key_event = self._next_event()
            if isinstance(key_event, yaml.events.MappingEndEvent):
                return root_result
            key = self._parse_mapping_key(key_event, seen_keys)
            value = self._parse_node((*path, key), depth + 1)
            if root_result is not None:
                root_result[key] = value

    def _parse_sequence_event(self, path, depth, event):
        if event.anchor is not None or event.tag is not None:
            raise ValueError("anchored or tagged YAML sequence")
        item_index = 0
        while True:
            child_event = self._next_event()
            if isinstance(child_event, yaml.events.SequenceEndEvent):
                return [] if not path else None
            self._parse_node((*path, item_index), depth + 1, child_event)
            item_index += 1


def _pnpm_capture_kind(path):
    if not path or path[-1] != "integrity":
        return None
    if len(path) != 4 or path[0] != "packages" or path[2] != "resolution":
        return "context"
    package_id = path[1]
    for kind, version in (("pnpm9", "9.0"), ("pnpm6", "6.0"), ("pnpm5", "5.4")):
        if _is_safe_pnpm_package_id(package_id, version):
            return kind
    return "context"


def _pnpm_context_values(scalar_spans):
    return [(start, end, value) for _, value, start, end in scalar_spans]


def _pnpm_expected_kind(lockfile_version):
    if lockfile_version == "9.0":
        return "pnpm9"
    if lockfile_version in {"6.0", "6.1"}:
        return "pnpm6"
    if lockfile_version in PNPM_LOCKFILE_VERSIONS:
        return "pnpm5"
    return None


def _finish_pnpm_spans(source: str, document, scalar_spans):
    contexts = _pnpm_context_values(scalar_spans)
    context_by_line = _line_contexts(source, contexts)
    if not isinstance(document, dict):
        return {}, context_by_line
    expected_kind = _pnpm_expected_kind(document.get("lockfileVersion"))
    if expected_kind is None:
        return {}, context_by_line
    approved_spans = [
        (start, end)
        for kind, value, start, end in scalar_spans
        if kind == expected_kind and _is_valid_sri_list(value, _is_valid_yarn_sri_token)
    ]
    return _line_spans(source, approved_spans), context_by_line


def _pnpm_integrity_spans(file_lines: list[str]):
    if yaml is None:
        return {}, {}
    source = "".join(file_lines)
    loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
    parser = _YamlSpanParser(
        source,
        capture_path=_pnpm_capture_kind,
        loader=loader,
    )
    try:
        document, scalar_spans = parser.parse()
    except MemoryError:
        return {}, {}
    except (RecursionError, ValueError, yaml.YAMLError):
        partial_context = _pnpm_context_values(parser.string_spans)
        return {}, _line_contexts(source, partial_context)
    return _finish_pnpm_spans(source, document, scalar_spans)


def _yaml_checksum_kind(key):
    if not isinstance(key, str):
        return None
    normalized = key.lower()
    if normalized in {"hash", "checksum"}:
        return "hash"
    if normalized in _CHECKSUM_FIELD_NAMES:
        return "integrity"
    return None


class _YamlChecksumCollector:
    def __init__(self, source: str, scalar_spans):
        self.source = source
        self.scalar_spans = scalar_spans
        self.stack = []
        self.scalar_anchors = {}
        self.event_count = 0
        self.node_count = 0

    def collect(self, loader):
        for event in yaml.parse(self.source, Loader=loader):
            self._handle_event(event)

    @staticmethod
    def _event_line(event) -> int:
        return getattr(getattr(event, "start_mark", None), "line", 0) + 1

    def _count_event(self, event) -> int:
        self.event_count += 1
        event_line = self._event_line(event)
        if self.event_count > _MAX_GENERIC_YAML_EVENTS:
            raise _SecretContextLimit("YAML event limit exceeded", event_line)
        return event_line

    def _count_node(self, event_line: int):
        self.node_count += 1
        if self.node_count > _MAX_GENERIC_YAML_NODES:
            raise _SecretContextLimit("YAML node limit exceeded", event_line)

    def _start_document(self):
        if self.stack:
            raise ValueError("nested YAML document")
        self.scalar_anchors.clear()

    def _end_document(self):
        if self.stack:
            raise ValueError("incomplete YAML document")

    def _consume_parent_collection(self):
        if not self.stack or not self.stack[-1][0]:
            return
        parent = self.stack[-1]
        parent[1] = not parent[1]
        parent[2] = None

    def _start_collection(self, event, event_line: int):
        self._count_node(event_line)
        self._consume_parent_collection()
        is_mapping = isinstance(event, yaml.events.MappingStartEvent)
        self.stack.append([is_mapping, True, None])

    def _end_collection(self, event):
        expected_mapping = isinstance(event, yaml.events.MappingEndEvent)
        if not self.stack or self.stack[-1][0] != expected_mapping:
            raise ValueError("unexpected YAML collection end")
        self.stack.pop()

    def _consume_mapping_scalar(self, value):
        if not self.stack or not self.stack[-1][0]:
            return None
        parent = self.stack[-1]
        if parent[1]:
            parent[1] = False
            parent[2] = value
            return None
        kind = _yaml_checksum_kind(parent[2])
        parent[1] = True
        parent[2] = None
        return kind

    def _capture(self, kind, value, span, event_line: int):
        if kind is None or span is None:
            return
        if len(self.scalar_spans) >= _MAX_JSON_CAPTURED_STRINGS:
            raise _SecretContextLimit("YAML capture limit exceeded", event_line)
        self.scalar_spans.append((kind, value, *span))

    def _handle_scalar(self, event, event_line: int):
        self._count_node(event_line)
        span = _yaml_scalar_content_span(self.source, event)
        if event.anchor is not None and span is not None:
            self.scalar_anchors[event.anchor] = (event.value, *span)
        kind = self._consume_mapping_scalar(event.value)
        self._capture(kind, event.value, span, event_line)

    def _handle_alias(self, event, event_line: int):
        self._count_node(event_line)
        anchored = self.scalar_anchors.get(event.anchor)
        value = anchored[0] if anchored is not None else None
        kind = self._consume_mapping_scalar(value)
        self._capture(kind, value, anchored[1:] if anchored else None, event_line)

    def _handle_event(self, event):
        event_line = self._count_event(event)
        if isinstance(event, yaml.events.DocumentStartEvent):
            self._start_document()
        elif isinstance(event, yaml.events.DocumentEndEvent):
            self._end_document()
        elif isinstance(
            event, (yaml.events.StreamStartEvent, yaml.events.StreamEndEvent)
        ):
            return
        elif isinstance(
            event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)
        ):
            self._start_collection(event, event_line)
        elif isinstance(
            event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)
        ):
            self._end_collection(event)
        elif isinstance(event, yaml.events.ScalarEvent):
            self._handle_scalar(event, event_line)
        elif isinstance(event, yaml.events.AliasEvent):
            self._handle_alias(event, event_line)
        else:
            raise ValueError("unsupported YAML event")


def _collect_yaml_checksum_spans(source: str, loader, scalar_spans):
    _YamlChecksumCollector(source, scalar_spans).collect(loader)


def _yaml_checksum_context_spans(file_lines: list[str]):
    if yaml is None:
        return {}, {}, None

    source = "".join(file_lines)
    loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
    scalar_spans = []
    incomplete_line = None
    try:
        _collect_yaml_checksum_spans(source, loader, scalar_spans)
    except MemoryError:
        return {}, {}, 1
    except _SecretContextLimit as exc:
        incomplete_line = exc.line
    except RecursionError:
        incomplete_line = 1
    except yaml.YAMLError as exc:
        incomplete_line = getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
    except ValueError:
        incomplete_line = 1

    all_contexts = []
    single_line_contexts = []
    for kind, value, start, end in scalar_spans:
        raw_value = source[start:end]
        context = (start, end, value)
        all_contexts.append(context)
        if "\n" in raw_value or "\r" in raw_value:
            # Mapping a decoded multiline scalar back to one physical line is
            # ambiguous for generic entropy. Keep it for decoded provider
            # signatures, whose location can safely point to the scalar start.
            continue
        if kind == "hash" and _is_conventional_lowercase_hash(value.strip()):
            continue
        single_line_contexts.append(context)
    return (
        _line_contexts(source, single_line_contexts),
        _line_contexts(source, all_contexts),
        incomplete_line,
    )


def _line_value_context(line: str, raw_value: str, value_start: int):
    value = raw_value.strip()
    if not value or value[0] in {'"', "'"}:
        return None
    start = value_start + len(raw_value) - len(raw_value.lstrip())
    end = start + len(value)
    return start, end, value, line[start:end]


def _trimmed_line_context(match, line: str):
    return _line_value_context(line, match.group("value"), match.start("value"))


def _closing_quote_index(value: str, quote: str, start: int) -> int | None:
    for index in range(start, len(value)):
        if value[index] != quote:
            continue
        backslashes = 0
        preceding = index - 1
        while preceding >= 0 and value[preceding] == "\\":
            backslashes += 1
            preceding -= 1
        if backslashes % 2 == 0:
            return index
    return None


def _is_dotenv_name(rel_name: str) -> bool:
    normalized = rel_name.lower()
    return (
        normalized == ".env"
        or normalized.startswith(".env.")
        or normalized.endswith(".env")
    )


def _dotenv_line_details(line: str):
    assignment = _DOTENV_ASSIGNMENT_RE.fullmatch(line)
    if assignment is None:
        return None, None, None

    field = (assignment.group("quoted_field") or assignment.group("field")).lower()
    raw_value = assignment.group("value")
    leading = len(raw_value) - len(raw_value.lstrip())
    stripped_value = raw_value[leading:]
    if stripped_value.startswith(("'", '"')):
        quote = stripped_value[0]
        if _closing_quote_index(stripped_value, quote, 1) is not None:
            return None, None, None
        context = None
        if field in _CHECKSUM_FIELD_NAMES:
            quoted_content = stripped_value[1:]
            context = _line_value_context(
                line,
                quoted_content,
                assignment.start("value") + leading + 1,
            )
        return quote, field, context

    comment = re.search(r"[ \t]+#", raw_value)
    if comment is not None:
        raw_value = raw_value[: comment.start()]
    if field not in _CHECKSUM_FIELD_NAMES:
        return None, None, None
    return (
        None,
        field,
        _line_value_context(line, raw_value, assignment.start("value")),
    )


class _ChecksumContextAccumulator:
    def __init__(self):
        self.generic_by_line = {}
        self.incomplete_line = None

    def add(self, line_number, field, context):
        if context is None:
            return
        if field in {"hash", "checksum"} and _is_conventional_lowercase_hash(
            context[2]
        ):
            return
        if len(self.generic_by_line) >= _MAX_JSON_CAPTURED_STRINGS:
            if self.incomplete_line is None:
                self.incomplete_line = line_number
            return
        self.generic_by_line[line_number] = (context,)

    def result(self):
        return self.generic_by_line, {}, self.incomplete_line


class _DotenvChecksumContexts(_ChecksumContextAccumulator):
    def __init__(self):
        super().__init__()
        self.quote = None
        self.pending = []
        self.pending_overflow_line = None

    def consume(self, line_number: int, line: str):
        if self.quote is None:
            self._consume_assignment(line_number, line)
        else:
            self._consume_quoted_line(line_number, line)

    def _consume_assignment(self, line_number: int, line: str):
        opened_quote, field, context = _dotenv_line_details(line)
        if opened_quote is None:
            self.add(line_number, field, context)
            return
        self.quote = opened_quote
        if context is not None:
            self.pending.append((line_number, field, context))

    def _consume_quoted_line(self, line_number: int, line: str):
        if _closing_quote_index(line, self.quote, 0) is not None:
            self.quote = None
            self.pending.clear()
            self.pending_overflow_line = None
            return
        _, field, context = _dotenv_line_details(line)
        if context is None:
            return
        if len(self.pending) < _MAX_JSON_CAPTURED_STRINGS:
            self.pending.append((line_number, field, context))
        elif self.pending_overflow_line is None:
            self.pending_overflow_line = line_number

    def finish(self):
        if self.quote is None:
            return self.result()
        for line_number, field, context in self.pending:
            self.add(line_number, field, context)
        if self.pending_overflow_line is not None and self.incomplete_line is None:
            self.incomplete_line = self.pending_overflow_line
        return self.result()


def _dotenv_checksum_contexts(file_lines: list[str]):
    contexts = _DotenvChecksumContexts()
    for index, raw_line in enumerate(file_lines):
        contexts.consume(index + 1, raw_line.rstrip("\r\n"))
    return contexts.finish()


def _ini_checksum_contexts(file_lines: list[str]):
    contexts = _ChecksumContextAccumulator()
    option_indent = None
    for index, raw_line in enumerate(file_lines):
        line = raw_line.rstrip("\r\n")
        stripped = line.lstrip(" \t")
        if not stripped or stripped.startswith(("#", ";")):
            continue
        indent = len(line) - len(stripped)
        if option_indent is not None and indent > option_indent:
            continue
        if stripped.startswith("["):
            option_indent = None
            continue
        option = _INI_OPTION_RE.match(line)
        if option is None:
            continue
        option_indent = indent
        match = _INI_CHECKSUM_VALUE_RE.fullmatch(line)
        if match is None:
            continue
        context = _trimmed_line_context(match, line)
        contexts.add(index + 1, match.group("field").lower(), context)
    return contexts.result()


def _line_config_checksum_contexts(rel_name: str, file_lines: list[str]):
    normalized = rel_name.lower()
    if _is_dotenv_name(normalized):
        return _dotenv_checksum_contexts(file_lines)
    if normalized.endswith((".ini", ".cfg", ".conf")):
        return _ini_checksum_contexts(file_lines)
    return {}, {}, None


def _merge_context_maps(*context_maps):
    merged = {}
    for contexts_by_line in context_maps:
        for line_number, contexts in contexts_by_line.items():
            merged.setdefault(line_number, []).extend(contexts)
    return {
        line_number: tuple(sorted(set(contexts)))
        for line_number, contexts in merged.items()
    }


def _data_checksum_context_spans(rel_name: str, file_lines: list[str]):
    normalized = rel_name.lower()
    if normalized.endswith((".yaml", ".yml")) and normalized != "pnpm-lock.yaml":
        return _yaml_checksum_context_spans(file_lines)
    return _line_config_checksum_contexts(normalized, file_lines)


def _skip_html_whitespace(raw_tag: str, index: int) -> int:
    while index < len(raw_tag) and raw_tag[index].isspace():
        index += 1
    return index


def _html_token_end(raw_tag: str, index: int, forbidden: str) -> int:
    while (
        index < len(raw_tag)
        and not raw_tag[index].isspace()
        and raw_tag[index] not in forbidden
    ):
        index += 1
    return index


def _html_attribute_value_span(raw_tag: str, index: int):
    length = len(raw_tag)
    index = _skip_html_whitespace(raw_tag, index)
    if index >= length or raw_tag[index] != "=":
        return None

    index = _skip_html_whitespace(raw_tag, index + 1)
    if index >= length:
        return None
    if raw_tag[index] not in {'"', "'"}:
        value_end = _html_token_end(raw_tag, index, "<=>")
        return index, value_end, value_end

    value_start = index + 1
    value_end = raw_tag.find(raw_tag[index], value_start)
    if value_end < 0:
        return value_start, length, length
    return value_start, value_end, value_end + 1


def _iter_html_attributes(raw_tag: str):
    length = len(raw_tag)
    index = _html_token_end(raw_tag, 1, "/>")

    while index < length:
        index = _skip_html_whitespace(raw_tag, index)
        if index >= length or raw_tag[index] in "/>":
            return

        name_start = index
        index = _html_token_end(raw_tag, index, "/=>")
        if index == name_start:
            index += 1
            continue
        name = raw_tag[name_start:index]

        value_span = _html_attribute_value_span(raw_tag, index)
        if value_span is None:
            index = _skip_html_whitespace(raw_tag, index)
            continue
        value_start, value_end, index = value_span
        yield name, value_start, value_end


class _HtmlIntegrityParser(HTMLParser):
    def __init__(self, source: str):
        super().__init__(convert_charrefs=False)
        self.source = source
        self.line_starts = [0]
        # HTMLParser.getpos() advances lines on LF only; bare CR remains part
        # of the current column even though scan_ctx later treats it as EOL.
        self.line_starts.extend(match.end() for match in re.finditer("\n", source))
        self.tag_count = 0
        self.contexts = []

    def handle_starttag(self, tag, attrs):
        del tag, attrs
        self.tag_count += 1
        line_number, line_offset = self.getpos()
        if self.tag_count > _MAX_JSON_NODES:
            raise _SecretContextLimit("HTML tag limit exceeded", line_number)
        raw_tag = self.get_starttag_text()
        if not raw_tag:
            return
        tag_start = self.line_starts[line_number - 1] + line_offset
        for name, relative_start, relative_end in _iter_html_attributes(raw_tag):
            if name.lower() != "integrity":
                continue
            start = tag_start + relative_start
            end = tag_start + relative_end
            raw_value = self.source[start:end]
            if "\n" in raw_value or "\r" in raw_value:
                continue
            if len(self.contexts) >= _MAX_JSON_CAPTURED_STRINGS:
                raise _SecretContextLimit(
                    "HTML integrity capture limit exceeded", line_number
                )
            self.contexts.append((start, end, unescape(raw_value)))


def _html_integrity_spans(file_lines: list[str]):
    source = "".join(file_lines)
    parser = _HtmlIntegrityParser(source)
    incomplete_line = None
    try:
        parser.feed(source)
        parser.close()
    except MemoryError:
        return {}, {}, 1
    except _SecretContextLimit as exc:
        incomplete_line = exc.line
    except (RecursionError, ValueError):
        incomplete_line = 1

    approved = [
        (start, end)
        for start, end, value in parser.contexts
        if _is_valid_sri_list(value, _is_valid_sri_token)
    ]
    return (
        _line_spans(source, approved),
        _line_contexts(source, parser.contexts),
        incomplete_line,
    )


def _lockfile_integrity_spans(rel_name: str, file_lines: list[str]):
    if rel_name.lower().endswith((".html", ".htm")):
        return _html_integrity_spans(file_lines)
    if rel_name == "yarn.lock":
        approved, contexts = _yarn_integrity_spans(file_lines)
        return approved, contexts, None
    if rel_name == "pnpm-lock.yaml":
        approved, contexts = _pnpm_integrity_spans(file_lines)
        return approved, contexts, None
    approved, contexts = _json_integrity_spans(rel_name, file_lines)
    return approved, contexts, None


def _docstring_lines(tree):
    if tree is None:
        return set()

    docstring_line_numbers = set()

    def find_docstring_lines(node):
        if not hasattr(node, "body") or not node.body:
            return

        first_statement = node.body[0]

        is_expression = isinstance(first_statement, ast.Expr)
        if not is_expression:
            return

        value = getattr(first_statement, "value", None)
        if not isinstance(value, ast.Constant):
            return

        if not isinstance(value.value, str):
            return

        start_line = getattr(first_statement, "lineno", None)
        end_line = getattr(first_statement, "end_lineno", start_line)

        if start_line is not None:
            if end_line is None:
                end_line = start_line

            for line_num in range(start_line, end_line + 1):
                docstring_line_numbers.add(line_num)

    if isinstance(tree, ast.Module):
        find_docstring_lines(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            find_docstring_lines(node)

    return docstring_line_numbers


_MAX_CLIENT_ENV_PARSE_BYTES = 8_000_000
_MAX_CLIENT_ENV_NODES = 300_000
_MAX_CLIENT_ENV_BINDINGS = 20_000
_MAX_CLIENT_ENV_REFERENCES = 512
_MAX_CLIENT_ENV_ALIAS_DEPTH = 8
_CLIENT_SCOPE_NODE_TYPES = frozenset(
    {
        "arrow_function",
        "catch_clause",
        "class_static_block",
        "for_in_statement",
        "for_statement",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
        "program",
        "statement_block",
        "switch_body",
    }
)
_CLIENT_FUNCTION_NODE_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_CLIENT_EXPRESSION_WRAPPERS = frozenset(
    {
        "as_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_SHADOWED_CLIENT_BINDING = object()


@dataclass(frozen=True)
class _ClientEnvReference:
    source: str
    start_offset: int
    end_offset: int

    def start(self) -> int:
        return self.start_offset

    def end(self) -> int:
        return self.end_offset

    def group(self, group=0) -> str:
        if group != 0:
            raise IndexError("client env references expose only group 0")
        return self.source[self.start_offset : self.end_offset]


@dataclass(frozen=True)
class _RawClientEnvReference:
    start_byte: int
    end_byte: int
    env_name: str


@dataclass(frozen=True)
class _ClientEnvScan:
    references: tuple[_RawClientEnvReference, ...]
    complete: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ClientBinding:
    name: str
    declaration_start: int
    declaration_end: int
    value_node: object | None
    is_const: bool


def _public_client_env_prefix(name: str) -> str | None:
    return next(
        (prefix for prefix in PUBLIC_CLIENT_ENV_PREFIXES if name.startswith(prefix)),
        None,
    )


def is_public_client_env_name(name: str) -> bool:
    return _public_client_env_prefix(name) is not None


def _normalized_env_name(name: str) -> str:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", camel_split).strip("_").upper()


def _is_sensitive_client_env_name(name: str) -> bool:
    if not name:
        return False

    public_prefix = _public_client_env_prefix(name)
    semantic_name = name[len(public_prefix) :] if public_prefix else name
    normalized = _normalized_env_name(semantic_name)
    terms = frozenset(part for part in normalized.split("_") if part)
    if public_prefix:
        return bool(
            normalized in _SENSITIVE_CLIENT_ENV_NAMES
            or _SENSITIVE_PUBLIC_ENV_TERMS.intersection(terms)
        )
    return bool(
        normalized in _SENSITIVE_CLIENT_ENV_NAMES
        or _SENSITIVE_CLIENT_ENV_TERMS.intersection(terms)
    )


def _parse_client_typescript(source_bytes: bytes):
    if len(source_bytes) > _MAX_CLIENT_ENV_PARSE_BYTES:
        return None
    try:
        from skylos.visitors.languages.typescript.core import TypeScriptCore

        return TypeScriptCore("skylos-client-exposure.tsx", source_bytes).root_node
    except Exception:  # skylos: ignore[SKY-L007]
        # Callers convert parser failure into SKY-ANALYSIS-INCOMPLETE.
        return None


def _bounded_client_nodes(root_node) -> tuple[list, bool]:
    nodes = []
    stack = [root_node]
    while stack and len(nodes) < _MAX_CLIENT_ENV_NODES:
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.named_children))
    return nodes, not stack


def _client_scope_key(node) -> tuple[str, int, int]:
    return node.type, node.start_byte, node.end_byte


def _nearest_client_scope(node):
    current = node
    while current is not None:
        if current.type in _CLIENT_SCOPE_NODE_TYPES:
            return current
        current = current.parent
    return None


def _nearest_client_function_scope(node):
    current = node
    while current is not None:
        if current.type in _CLIENT_FUNCTION_NODE_TYPES or current.type == "program":
            return current
        current = current.parent
    return None


def _node_text(source_bytes: bytes, node) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def _binding_pattern_names(pattern, source_bytes: bytes) -> list[str]:
    if pattern is None:
        return []
    if pattern.type in {
        "identifier",
        "shorthand_property_identifier_pattern",
    }:
        return [_node_text(source_bytes, pattern)]
    if pattern.type in {"required_parameter", "optional_parameter"}:
        return _binding_pattern_names(
            pattern.child_by_field_name("pattern"), source_bytes
        )
    if pattern.type == "pair_pattern":
        return _binding_pattern_names(
            pattern.child_by_field_name("value"), source_bytes
        )
    if pattern.type == "assignment_pattern":
        return _binding_pattern_names(pattern.child_by_field_name("left"), source_bytes)
    if pattern.type == "rest_pattern":
        return _binding_pattern_names(
            next(iter(pattern.named_children), None), source_bytes
        )

    names = []
    for child in pattern.named_children:
        names.extend(_binding_pattern_names(child, source_bytes))
    return names


def _declaration_is_const(declaration) -> bool:
    return bool(
        declaration is not None
        and declaration.type == "lexical_declaration"
        and declaration.children
        and declaration.children[0].type == "const"
    )


def _declaration_is_var(declaration) -> bool:
    return bool(
        declaration is not None
        and declaration.type == "variable_declaration"
        and declaration.children
        and declaration.children[0].type == "var"
    )


def _client_binding(
    name: str,
    node,
    *,
    value_node=None,
    is_const: bool = False,
    declaration_end: int | None = None,
) -> _ClientBinding:
    return _ClientBinding(
        name,
        node.start_byte,
        node.end_byte if declaration_end is None else declaration_end,
        value_node,
        is_const,
    )


def _collect_variable_client_bindings(node, source_bytes: bytes):
    scope = (
        _nearest_client_function_scope(node.parent)
        if _declaration_is_var(node.parent)
        else _nearest_client_scope(node.parent)
    )
    name_node = node.child_by_field_name("name")
    value_node = node.child_by_field_name("value")
    simple_name = name_node is not None and name_node.type == "identifier"
    for name in _binding_pattern_names(name_node, source_bytes):
        yield (
            scope,
            _client_binding(
                name,
                node,
                value_node=value_node if simple_name else None,
                is_const=_declaration_is_const(node.parent),
            ),
        )


def _collect_function_client_bindings(node, source_bytes: bytes):
    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        parameters = node.child_by_field_name("parameter")
    for name in _binding_pattern_names(parameters, source_bytes):
        yield node, _client_binding(name, node, declaration_end=node.start_byte)

    if node.type not in {"function_declaration", "generator_function_declaration"}:
        return
    parent_scope = _nearest_client_scope(node.parent)
    for name in _binding_pattern_names(node.child_by_field_name("name"), source_bytes):
        yield parent_scope, _client_binding(name, node)


def _collect_import_client_bindings(node, source_bytes: bytes):
    scope = _nearest_client_scope(node.parent)
    stack = list(node.named_children)
    while stack:
        child = stack.pop()
        if child.type == "import_specifier":
            local = child.child_by_field_name("alias") or child.child_by_field_name(
                "name"
            )
            for name in _binding_pattern_names(local, source_bytes):
                yield scope, _client_binding(name, child)
            continue
        if child.type == "identifier" and child.parent.type == "import_clause":
            yield scope, _client_binding(_node_text(source_bytes, child), child)
            continue
        stack.extend(child.named_children)


def _client_bindings_for_node(node, source_bytes: bytes):
    if node.type == "variable_declarator":
        yield from _collect_variable_client_bindings(node, source_bytes)
    elif node.type in _CLIENT_FUNCTION_NODE_TYPES:
        yield from _collect_function_client_bindings(node, source_bytes)
    elif node.type == "catch_clause":
        for name in _binding_pattern_names(
            node.child_by_field_name("parameter"), source_bytes
        ):
            yield node, _client_binding(name, node, declaration_end=node.start_byte)
    elif node.type == "for_in_statement":
        for name in _binding_pattern_names(
            node.child_by_field_name("left"), source_bytes
        ):
            yield node, _client_binding(name, node, declaration_end=node.start_byte)
    elif node.type == "import_statement":
        yield from _collect_import_client_bindings(node, source_bytes)


def _collect_client_bindings(nodes, source_bytes: bytes):
    bindings: dict[tuple[str, int, int], dict[str, list[_ClientBinding]]] = {}
    binding_count = 0
    for node in nodes:
        for scope, binding in _client_bindings_for_node(node, source_bytes):
            if scope is None:
                continue
            if binding_count >= _MAX_CLIENT_ENV_BINDINGS:
                return bindings, False
            by_name = bindings.setdefault(_client_scope_key(scope), {})
            by_name.setdefault(binding.name, []).append(binding)
            binding_count += 1
    return bindings, binding_count < _MAX_CLIENT_ENV_BINDINGS


def _visible_client_binding(bindings, name: str, use_node):
    current = use_node
    while current is not None:
        if current.type in _CLIENT_SCOPE_NODE_TYPES:
            records = bindings.get(_client_scope_key(current), {}).get(name, ())
            if records:
                return records[0] if len(records) == 1 else _SHADOWED_CLIENT_BINDING
        current = current.parent
    return None


def _unwrap_client_expression(node):
    current = node
    while current is not None and current.type in _CLIENT_EXPRESSION_WRAPPERS:
        candidate = current.child_by_field_name("expression")
        if candidate is None:
            candidate = current.child_by_field_name("value")
        if candidate is None:
            candidate = next(
                (
                    child
                    for child in current.named_children
                    if not child.type.endswith("type")
                    and child.type not in {"type_annotation", "type_arguments"}
                ),
                None,
            )
        current = candidate
    return current


def _is_unshadowed_process_env(node, bindings, source_bytes: bytes) -> bool:
    node = _unwrap_client_expression(node)
    if node is None or node.type not in {"member_expression", "subscript_expression"}:
        return False
    object_node = _unwrap_client_expression(node.child_by_field_name("object"))
    property_node = node.child_by_field_name(
        "property" if node.type == "member_expression" else "index"
    )
    if object_node is None or property_node is None:
        return False
    if _static_env_property_name(property_node, source_bytes) != "env":
        return False
    if (
        object_node.type == "identifier"
        and _node_text(source_bytes, object_node) == "process"
    ):
        return _visible_client_binding(bindings, "process", object_node) is None
    return bool(
        object_node.type == "meta_property"
        and _node_text(source_bytes, object_node) == "import.meta"
    )


def _binding_is_env_alias(
    binding,
    bindings,
    source_bytes: bytes,
    *,
    use_offset: int,
    depth: int,
    seen: frozenset[tuple[str, int]],
) -> bool:
    if (
        not isinstance(binding, _ClientBinding)
        or not binding.is_const
        or binding.value_node is None
        or binding.declaration_end > use_offset
        or depth >= _MAX_CLIENT_ENV_ALIAS_DEPTH
    ):
        return False
    binding_key = (binding.name, binding.declaration_start)
    if binding_key in seen:
        return False

    value_node = _unwrap_client_expression(binding.value_node)
    if _is_unshadowed_process_env(value_node, bindings, source_bytes):
        return True
    if value_node is None or value_node.type != "identifier":
        return False
    target = _visible_client_binding(
        bindings, _node_text(source_bytes, value_node), value_node
    )
    return _binding_is_env_alias(
        target,
        bindings,
        source_bytes,
        use_offset=value_node.start_byte,
        depth=depth + 1,
        seen=seen | {binding_key},
    )


def _expression_is_env_object(node, bindings, source_bytes: bytes) -> bool:
    node = _unwrap_client_expression(node)
    if _is_unshadowed_process_env(node, bindings, source_bytes):
        return True
    if node is None or node.type != "identifier":
        return False
    binding = _visible_client_binding(bindings, _node_text(source_bytes, node), node)
    return _binding_is_env_alias(
        binding,
        bindings,
        source_bytes,
        use_offset=node.start_byte,
        depth=0,
        seen=frozenset(),
    )


def _decode_js_string_literal(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded escape decoder state machine
    text: str,
) -> str | None:
    if len(text) < 2 or text[0] not in {'"', "'"} or text[-1] != text[0]:
        return None
    result = []
    index = 1
    end = len(text) - 1
    simple_escapes = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "0": "\0",
    }
    while index < end and len(result) <= 256:
        character = text[index]
        if character != "\\":
            result.append(character)
            index += 1
            continue
        index += 1
        if index >= end:
            return None
        escape = text[index]
        if escape in simple_escapes:
            result.append(simple_escapes[escape])
            index += 1
            continue
        if escape in {"\\", "'", '"'}:
            result.append(escape)
            index += 1
            continue
        if escape == "x" and index + 2 < end:
            digits = text[index + 1 : index + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                result.append(chr(int(digits, 16)))
                index += 3
                continue
        if escape == "u":
            if index + 1 < end and text[index + 1] == "{":
                close = text.find("}", index + 2, min(end, index + 10))
                digits = text[index + 2 : close] if close >= 0 else ""
                if digits and re.fullmatch(r"[0-9A-Fa-f]{1,6}", digits):
                    codepoint = int(digits, 16)
                    if codepoint <= 0x10FFFF:
                        result.append(chr(codepoint))
                        index = close + 1
                        continue
            elif index + 4 < end:
                digits = text[index + 1 : index + 5]
                if re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                    result.append(chr(int(digits, 16)))
                    index += 5
                    continue
        return None
    return "".join(result) if index == end and len(result) <= 256 else None


def _static_env_property_name(node, source_bytes: bytes) -> str | None:
    if node is None:
        return None
    if node.type in {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source_bytes, node)
    if node.type == "string":
        return _decode_js_string_literal(_node_text(source_bytes, node))
    if node.type == "computed_property_name":
        return _static_env_property_name(
            next(iter(node.named_children), None), source_bytes
        )
    return None


def _destructured_env_properties(pattern, source_bytes: bytes):
    if pattern is None or pattern.type != "object_pattern":
        return
    for child in pattern.named_children:
        key_node = None
        if child.type == "shorthand_property_identifier_pattern":
            key_node = child
        elif child.type == "pair_pattern":
            key_node = child.child_by_field_name("key")
        elif child.type in {"assignment_pattern", "object_assignment_pattern"}:
            key_node = child.child_by_field_name("left")
        if key_node is None:
            continue
        env_name = _static_env_property_name(key_node, source_bytes)
        if env_name:
            yield key_node, env_name


def _prepare_client_env_scan(source_bytes: bytes):
    if len(source_bytes) > _MAX_CLIENT_ENV_PARSE_BYTES:
        return None, None, False, ["client env parse byte budget exceeded"]
    root_node = _parse_client_typescript(source_bytes)
    if root_node is None:
        return None, None, False, ["client env parser unavailable"]
    diagnostics = []
    complete = not bool(getattr(root_node, "has_error", False))
    if not complete:
        diagnostics.append("TypeScript parser recovered from invalid syntax")
    nodes, nodes_complete = _bounded_client_nodes(root_node)
    if not nodes_complete:
        complete = False
        diagnostics.append("client env node budget exceeded")
    bindings, bindings_complete = _collect_client_bindings(nodes, source_bytes)
    if not bindings_complete:
        complete = False
        diagnostics.append("client env binding budget exceeded")
    return nodes, bindings, complete, diagnostics


def _client_env_reference_candidates(node, bindings, source_bytes: bytes):
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        if not _expression_is_env_object(object_node, bindings, source_bytes):
            return
        property_node = node.child_by_field_name(
            "property" if node.type == "member_expression" else "index"
        )
        env_name = _static_env_property_name(property_node, source_bytes)
        if env_name and _is_sensitive_client_env_name(env_name):
            yield _RawClientEnvReference(node.start_byte, node.end_byte, env_name)
        return

    if node.type != "variable_declarator":
        return
    value_node = node.child_by_field_name("value")
    if not _expression_is_env_object(value_node, bindings, source_bytes):
        return
    pattern = node.child_by_field_name("name")
    for key_node, env_name in _destructured_env_properties(pattern, source_bytes):
        if _is_sensitive_client_env_name(env_name):
            yield _RawClientEnvReference(
                key_node.start_byte,
                key_node.end_byte,
                env_name,
            )


def _raw_client_env_references(source_bytes: bytes) -> _ClientEnvScan:
    nodes, bindings, complete, diagnostics = _prepare_client_env_scan(source_bytes)
    if nodes is None or bindings is None:
        return _ClientEnvScan((), False, tuple(diagnostics))

    references = []
    seen = set()
    for node in nodes:
        if len(references) >= _MAX_CLIENT_ENV_REFERENCES:
            complete = False
            diagnostics.append("client env reference budget exceeded")
            break
        for reference in _client_env_reference_candidates(node, bindings, source_bytes):
            key = (reference.start_byte, reference.end_byte, reference.env_name)
            if key not in seen:
                seen.add(key)
                references.append(reference)
            if len(references) >= _MAX_CLIENT_ENV_REFERENCES:
                break

    references.sort(key=lambda reference: (reference.start_byte, reference.end_byte))
    return _ClientEnvScan(tuple(references), complete, tuple(diagnostics))


def _reference_char_offsets(source_text: str, byte_offsets: set[int]) -> dict[int, int]:
    if source_text.isascii():
        return {offset: offset for offset in byte_offsets}
    offsets = {}
    byte_offset = 0
    if 0 in byte_offsets:
        offsets[0] = 0
    for char_offset, character in enumerate(source_text, start=1):
        byte_offset += len(character.encode("utf-8"))
        if byte_offset in byte_offsets:
            offsets[byte_offset] = char_offset
    return offsets


def _client_env_references_with_status(source_text: str):
    source_bytes = source_text.encode("utf-8")
    scan = _raw_client_env_references(source_bytes)
    byte_offsets = {
        offset
        for reference in scan.references
        for offset in (reference.start_byte, reference.end_byte)
    }
    char_offsets = _reference_char_offsets(source_text, byte_offsets)
    references = []
    for reference in scan.references:
        start = char_offsets.get(reference.start_byte)
        end = char_offsets.get(reference.end_byte)
        if start is None or end is None:
            continue
        references.append(
            (_ClientEnvReference(source_text, start, end), reference.env_name)
        )
    return references, scan.complete, scan.diagnostics


def iter_sensitive_client_env_references(source_text: str):
    """Yield bounded, structural secret-like env references in JS/TS source."""
    references, _, _ = _client_env_references_with_status(source_text)
    yield from references


def _source_env_aliases(source_text: str) -> set[str]:
    """Recover a bounded alias superset for fail-closed incomplete scans."""
    assignments = list(_CLIENT_ENV_ALIAS_ASSIGNMENT_RE.finditer(source_text))[:512]
    aliases: set[str] = set()
    for _ in range(32):
        changed = False
        for match in assignments:
            alias = match.group("alias")
            target = match.group("target").strip()
            if alias in aliases:
                continue
            if _CLIENT_ENV_OBJECT_SOURCE_RE.fullmatch(target) or target in aliases:
                aliases.add(alias)
                changed = True
        if not changed:
            break
    return aliases


def _unresolved_sensitive_client_env_alias_candidate(source_text: str):
    aliases = _source_env_aliases(source_text)
    if aliases:
        for match in _CLIENT_ENV_ALIAS_MEMBER_RE.finditer(source_text):
            env_name = match.group("dot") or match.group("bracket") or ""
            if match.group("object") in aliases and _is_sensitive_client_env_name(
                env_name
            ):
                return match

    for match in _CLIENT_ENV_ALIAS_DESTRUCTURE_RE.finditer(source_text):
        target = match.group("target").strip()
        if not (_CLIENT_ENV_OBJECT_SOURCE_RE.fullmatch(target) or target in aliases):
            continue
        for name_match in _CLIENT_ENV_DESTRUCTURED_NAME_RE.finditer(
            match.group("body")
        ):
            env_name = name_match.group("quoted") or name_match.group("name") or ""
            if _is_sensitive_client_env_name(env_name):
                return match
    return None


def _unresolved_sensitive_client_env_candidate(source_text: str, references):
    proven_spans = {(match.start(), match.end()) for match, _ in references}
    for match in CLIENT_ENV_RE.finditer(source_text):
        env_name = match.group("dot") or match.group("bracket") or ""
        if (
            _is_sensitive_client_env_name(env_name)
            and (match.start(), match.end()) not in proven_spans
        ):
            return match
    alias_match = _unresolved_sensitive_client_env_alias_candidate(source_text)
    if alias_match is None:
        return None
    if (alias_match.start(), alias_match.end()) in proven_spans:
        return None
    return alias_match


def _use_client_directive_status(file_lines) -> tuple[bool, bool, tuple[str, ...]]:
    source_text = "".join(file_lines)
    source_bytes = source_text.encode("utf-8")
    truncated = len(source_bytes) > _MAX_CLIENT_ENV_PARSE_BYTES
    if truncated:
        source_bytes = source_bytes[:_MAX_CLIENT_ENV_PARSE_BYTES]
    root_node = _parse_client_typescript(source_bytes)
    if root_node is None:
        return False, False, ("use client directive parser unavailable",)
    for statement in root_node.named_children:
        if statement.type == "comment":
            continue
        if statement.type == "ERROR" or bool(getattr(statement, "is_missing", False)):
            return False, False, ("use client directive parse was incomplete",)
        if statement.type != "expression_statement":
            # Directive prologues cannot resume after a real statement, so a
            # later truncated suffix cannot change this ownership decision.
            return False, True, ()
        expression = next(iter(statement.named_children), None)
        if expression is None or expression.type != "string":
            return False, True, ()
        directive = _decode_js_string_literal(_node_text(source_bytes, expression))
        if directive == "use client":
            return True, True, ()
    if truncated:
        return False, False, ("use client directive parse byte budget exceeded",)
    if bool(getattr(root_node, "has_error", False)):
        return False, False, ("use client directive parse was incomplete",)
    return False, True, ()


def _has_use_client_directive(file_lines) -> bool:
    return _use_client_directive_status(file_lines)[0]


def _is_explicit_server_client_context(normalized: str, basename: str) -> bool:
    return bool(
        "/pages/api/" in normalized
        or any(segment in normalized for segment in _EXPLICIT_SERVER_OUTPUT_PATHS)
        or ("/app/" in normalized and basename in _NEXT_ROUTE_BASENAMES)
        or ".server." in basename
    )


def _is_named_client_context(normalized: str, basename: str) -> bool:
    return bool(
        ".client." in basename
        or ".browser." in basename
        or basename.startswith(("client.", "browser."))
        or any(segment in normalized for segment in CLIENT_PATHS)
    )


def _client_exposure_context_with_status(
    rel_path: str, file_lines
) -> tuple[bool, bool, tuple[str, ...]]:
    """Return client ownership plus whether a negative decision is complete."""
    normalized = "/" + rel_path.replace("\\", "/").lower().lstrip("/")
    basename = normalized.rsplit("/", 1)[-1]

    if any(segment in normalized for segment in _EXPLICIT_PUBLIC_CLIENT_PATHS):
        return True, True, ()

    if _is_explicit_server_client_context(normalized, basename):
        return False, True, ()

    if _is_named_client_context(normalized, basename):
        return True, True, ()

    if basename.endswith(JS_TS_SUFFIXES):
        return _use_client_directive_status(file_lines)
    return False, True, ()


def is_client_exposure_context(rel_path: str, file_lines) -> bool:
    """Return whether source or output is intentionally client-accessible."""
    return _client_exposure_context_with_status(rel_path, file_lines)[0]


def _append_client_analysis_incomplete(
    findings,
    *,
    rel_path: str,
    line: int,
    diagnostics,
    ownership_unknown: bool = False,
) -> None:
    if any(
        finding.get("rule_id") == "SKY-ANALYSIS-INCOMPLETE"
        and finding.get("file") == rel_path
        for finding in findings
    ):
        return
    subject = "ownership" if ownership_unknown else "environment exposure"
    findings.append(
        {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": "processing_error",
            "message": (
                f"Client-side {subject} analysis was bounded before a "
                "sensitive candidate could be resolved."
            ),
            "file": rel_path,
            "line": max(1, line),
            "col": 0,
            "metadata": {
                "analysis_complete": False,
                "analysis_diagnostics": list(tuple(diagnostics)[:4]),
            },
        }
    )


def _append_secret_context_incomplete(findings, *, rel_path: str, line: int) -> None:
    findings.append(
        {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": "processing_error",
            "message": (
                "Secret-field context analysis reached its safety limit; "
                "later contextual findings may be incomplete."
            ),
            "file": rel_path,
            "line": max(1, line),
            "col": 0,
            "metadata": {
                "analysis_complete": False,
                "analysis_diagnostics": ["secret_context_limit"],
            },
        }
    )


def scan_ctx(
    ctx,
    *,
    min_entropy=DEFAULT_MIN_ENTROPY,
    scan_comments=True,
    scan_docstrings=True,
    allowlist_patterns=None,
    ignore_path_substrings=None,
    ignore_tests=True,
):
    rel_path = ctx.get("relpath", "")
    rel_name = rel_path.replace("\\", "/").rsplit("/", 1)[-1]
    if not rel_path.endswith(ALLOWED_FILE_SUFFIXES) and not rel_name.startswith(
        ".env."
    ):
        return []

    if ignore_tests and IS_TEST_PATH.search(rel_path.replace("\\", "/")):
        return []

    if ignore_path_substrings:
        for substring in ignore_path_substrings:
            if substring and substring in rel_path:
                return []

    file_lines = ctx.get("lines") or []
    (
        is_client_context,
        client_context_complete,
        client_context_diagnostics,
    ) = _client_exposure_context_with_status(rel_path, file_lines)
    syntax_tree = ctx.get("tree")
    (
        approved_structural_spans,
        structural_context_spans,
        lock_context_incomplete_line,
    ) = _lockfile_integrity_spans(rel_name, file_lines)
    (
        data_context_spans,
        data_decoded_context_spans,
        data_context_incomplete_line,
    ) = _data_checksum_context_spans(rel_name, file_lines)
    incomplete_lines = [
        line
        for line in (lock_context_incomplete_line, data_context_incomplete_line)
        if line is not None
    ]
    context_incomplete_line = min(incomplete_lines) if incomplete_lines else None
    decoded_context_spans = _merge_context_maps(
        structural_context_spans,
        data_decoded_context_spans,
    )
    structural_context_spans = _merge_context_maps(
        structural_context_spans,
        data_context_spans,
    )

    allowlist_regexes = []
    if allowlist_patterns:
        for pattern in allowlist_patterns:
            compiled_regex = re.compile(pattern)
            allowlist_regexes.append(compiled_regex)

    if scan_docstrings:
        docstring_lines = set()
    else:
        docstring_lines = _docstring_lines(syntax_tree)

    findings = []
    if context_incomplete_line is not None:
        _append_secret_context_incomplete(
            findings,
            rel_path=rel_path,
            line=min(context_incomplete_line, max(1, len(file_lines))),
        )

    for line_number, raw_line in enumerate(file_lines, start=1):
        line_content = raw_line.rstrip("\n")

        if IGNORE_DIRECTIVE in line_content:
            continue

        stripped_line = line_content.lstrip()
        if not scan_comments and stripped_line.startswith("#"):
            continue

        if not scan_docstrings and line_number in docstring_lines:
            continue

        should_skip_line = False
        for regex_pattern in allowlist_regexes:
            if regex_pattern.search(line_content):
                should_skip_line = True
                break

        if should_skip_line:
            continue

        for provider_name, pattern_regex in PROVIDER_PATTERNS:
            pattern_matches = pattern_regex.finditer(line_content)

            for regex_match in pattern_matches:
                potential_secret = regex_match.group(0)

                token_lowercase = potential_secret.lower()
                has_safe_hint = False

                for safe_hint in SAFE_TEST_HINTS:
                    if safe_hint in token_lowercase:
                        has_safe_hint = True
                        break

                if has_safe_hint:
                    continue

                col_pos = regex_match.start()

                finding = {
                    "rule_id": "SKY-S101",
                    "severity": "CRITICAL",
                    "provider": provider_name,
                    "message": f"Potential {provider_name} secret detected",
                    "file": rel_path,
                    "line": line_number,
                    "col": max(0, col_pos),
                    "end_col": max(1, col_pos + len(potential_secret)),
                    "preview": _mask(potential_secret),
                }
                findings.append(finding)

        decoded_provider_matches = set()
        decoded_contexts = decoded_context_spans.get(line_number, ())
        line_approved_spans = approved_structural_spans.get(line_number, ())
        for (
            context_start,
            context_end,
            decoded_value,
            raw_context,
        ) in decoded_contexts:
            if raw_context != decoded_value:
                for provider_name, pattern_regex in PROVIDER_PATTERNS:
                    raw_provider_tokens = {
                        raw_match.group(0)
                        for raw_match in pattern_regex.finditer(raw_context)
                    }
                    for regex_match in pattern_regex.finditer(decoded_value):
                        potential_secret = regex_match.group(0)
                        if potential_secret in raw_provider_tokens:
                            continue
                        if any(
                            safe_hint in potential_secret.lower()
                            for safe_hint in SAFE_TEST_HINTS
                        ):
                            continue
                        match_key = (
                            provider_name,
                            potential_secret,
                            context_start,
                            context_end,
                        )
                        if match_key in decoded_provider_matches:
                            continue
                        decoded_provider_matches.add(match_key)
                        findings.append(
                            {
                                "rule_id": "SKY-S101",
                                "severity": "CRITICAL",
                                "provider": provider_name,
                                "message": f"Potential {provider_name} secret detected",
                                "file": rel_path,
                                "line": line_number,
                                "col": max(0, context_start),
                                "end_col": max(context_start + 1, context_end),
                                "preview": _mask(potential_secret),
                            }
                        )

            if not _is_known_integrity_candidate(
                raw_context, context_start, line_approved_spans
            ):
                continue
            for provider_name, pattern_regex in CHECKSUM_PROVIDER_PATTERNS:
                standard_tokens = {
                    standard_match.group(0)
                    for standard_match in PROVIDER_PATTERN_BY_NAME[
                        provider_name
                    ].finditer(decoded_value)
                }
                for regex_match in pattern_regex.finditer(decoded_value):
                    potential_secret = regex_match.group(0)
                    if potential_secret in standard_tokens or any(
                        safe_hint in potential_secret.lower()
                        for safe_hint in SAFE_TEST_HINTS
                    ):
                        continue
                    findings.append(
                        {
                            "rule_id": "SKY-S101",
                            "severity": "CRITICAL",
                            "provider": provider_name,
                            "message": f"Potential {provider_name} secret detected",
                            "file": rel_path,
                            "line": line_number,
                            "col": max(0, context_start),
                            "end_col": max(context_start + 1, context_end),
                            "preview": _mask(potential_secret),
                        }
                    )

        aws_key_indicators = ["AWS_SECRET_ACCESS_KEY", "aws_secret_access_key"]
        line_has_aws_key = False

        for indicator in aws_key_indicators:
            if indicator in line_content or indicator in line_content.lower():
                line_has_aws_key = True
                break

        if line_has_aws_key:
            aws_secret_pattern = r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            aws_match = re.search(aws_secret_pattern, line_content)

            if aws_match:
                aws_token = aws_match.group(1)
                tok_entropy = _entropy(aws_token)
                if tok_entropy >= min_entropy:
                    col_pos = aws_match.start(1)

                    aws_finding = {
                        "rule_id": "SKY-S101",
                        "severity": "CRITICAL",
                        "provider": "aws_secret_access_key",
                        "message": "Potential AWS secret access key detected",
                        "file": rel_path,
                        "line": line_number,
                        "col": max(0, col_pos),
                        "end_col": max(1, col_pos + len(aws_token)),
                        "preview": _mask(aws_token),
                        "entropy": round(tok_entropy, 2),
                    }
                    findings.append(aws_finding)

        in_tests = bool(IS_TEST_PATH.search(rel_path.replace("\\", "/")))

        if in_tests:
            generic_values = ()
        else:
            generic_values = _find_generic_values(
                line_content,
                approved_structural_spans=approved_structural_spans.get(
                    line_number, ()
                ),
                structural_contexts=structural_context_spans.get(line_number, ()),
                rel_name=rel_name,
            )
            if rel_name.lower().endswith((".html", ".htm", ".css", ".map")):
                # Client artifacts commonly contain SRI hashes, content hashes,
                # generated asset IDs, and minifier/source-map symbols. Keep
                # keyed/provider secrets, but do not interpret bare artifact
                # tokens as credentials merely because they have high entropy.
                generic_values = (
                    candidate for candidate in generic_values if not candidate[1]
                )

        for generic_value in generic_values:
            extracted_token, is_bare, col_pos, source_end = generic_value
            clean_token = extracted_token.strip()

            if not clean_token:
                continue
            if is_bare and _looks_like_identifier(clean_token):
                continue

            token_lowercase = clean_token.lower()
            has_safe_hint = False

            for safe_hint in SAFE_TEST_HINTS:
                if safe_hint in token_lowercase:
                    has_safe_hint = True
                    break

            if has_safe_hint:
                continue
            tok_entropy = _entropy(clean_token)

            if not (tok_entropy >= min_entropy and len(clean_token) >= 20):
                continue
            if is_bare and _bare_candidate_is_complete_ordered_character_set(
                line_content,
                start=col_pos,
                end=source_end,
                min_entropy=min_entropy,
            ):
                continue

            generic_finding = {
                "rule_id": "SKY-S101",
                "severity": "CRITICAL",
                "provider": "generic",
                "message": f"High-entropy value detected (entropy={tok_entropy:.2f})",
                "file": rel_path,
                "line": line_number,
                "col": max(0, col_pos),
                "end_col": max(1, source_end),
                "preview": _mask(clean_token),
                "entropy": round(tok_entropy, 2),
            }
            findings.append(generic_finding)

    # A neutral source file can still be a client boundary when its directive
    # prologue exceeded the parse budget. Preserve a blocking result whenever
    # that unresolved ownership decision intersects secret-like content.
    if not client_context_complete and rel_path.lower().endswith(JS_TS_SUFFIXES):
        source_text = "".join(file_lines)
        unresolved = _unresolved_sensitive_client_env_candidate(source_text, ())
        secret_finding = next(
            (finding for finding in findings if finding.get("rule_id") == "SKY-S101"),
            None,
        )
        if unresolved is not None or secret_finding is not None:
            if unresolved is not None:
                line = source_text.count("\n", 0, unresolved.start()) + 1
            else:
                line = int(secret_finding.get("line") or 1)
            _append_client_analysis_incomplete(
                findings,
                rel_path=rel_path,
                line=line,
                diagnostics=client_context_diagnostics,
                ownership_unknown=True,
            )

    # S102: Client-side secret exposure
    if is_client_context:
        for f in findings:
            if f["rule_id"] == "SKY-S101":
                f["rule_id"] = "SKY-S102"
                f["message"] = (
                    f"Client-side secret exposure: "
                    f"Secret exposed in client-accessible path: {rel_path}"
                )

    if is_client_context and rel_path.lower().endswith(JS_TS_SUFFIXES):
        source_text = "".join(file_lines)
        line_starts = [0]
        line_starts.extend(
            index + 1
            for index, character in enumerate(source_text)
            if character == "\n"
        )
        references, references_complete, diagnostics = (
            _client_env_references_with_status(source_text)
        )
        for match, env_name in references:
            line_number = bisect_right(line_starts, match.start())
            line_start = line_starts[line_number - 1]
            col_pos = match.start() - line_start
            reference = match.group(0)
            is_public_env = is_public_client_env_name(env_name)
            if is_public_env:
                message = (
                    "Client-side secret exposure: "
                    f"Sensitive-looking public env var '{reference}' is "
                    "intentionally bundled into client code"
                )
            else:
                message = (
                    "Client-side secret exposure: "
                    f"Server-only env var '{reference}' may be bundled into "
                    "client code"
                )
            findings.append(
                {
                    "rule_id": "SKY-S102",
                    "severity": "HIGH",
                    "message": message,
                    "file": rel_path,
                    "line": line_number,
                    "col": col_pos,
                    "end_col": col_pos + len(reference),
                    "env_name": env_name,
                    "public_env": is_public_env,
                }
            )
        if not references_complete:
            unresolved = _unresolved_sensitive_client_env_candidate(
                source_text,
                references,
            )
            if unresolved is not None:
                line_number = bisect_right(line_starts, unresolved.start())
                _append_client_analysis_incomplete(
                    findings,
                    rel_path=rel_path,
                    line=line_number,
                    diagnostics=diagnostics,
                )

    return findings
