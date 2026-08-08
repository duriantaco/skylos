from __future__ import annotations

import ast
import base64
import binascii
import json
import re
from bisect import bisect_right
from hashlib import blake2s
from math import log2

try:
    import yaml
except ModuleNotFoundError:  # Keep non-YAML scans available in partial installs.
    yaml = None

__all__ = ["scan_ctx"]

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

CLIENT_ENV_RE = re.compile(
    r"process\.env\."
    r"(?!NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_PUBLIC_|EXPO_PUBLIC_)"
    r"[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|AUTH)[A-Z_]*"
)

JS_TS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

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
        \s*[:=]\s*(?P<q>['"])(?P<quoted>[^'"]{16,})(?P=q)
        |
        \s*[:=]\s*(?P<assigned_bare>[^'"\s,}\]]{16,})
        |
        \s+(?P<bare_q>['"]?)(?P<bare>[^'"\s,}\]]{16,})(?P=bare_q)
    )
"""
)
HASH_FIELD_VALUE_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9_-])
    (?P<field_quote>['"]?)(?:hash|checksum)(?P=field_quote)
    (?![A-Za-z0-9_-])
    (?:
        \s*[:=]\s*(?P<q>['"])(?P<quoted>[^'"]{16,})(?P=q)
        |
        \s*[:=]\s*(?P<assigned_bare>[^'"\s,}\]]{16,})
    )
"""
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
    if match.group("assigned_bare") is not None:
        return "assigned_bare"
    return "bare"


def _trimmed_match_value(match, group):
    raw_value = match.group(group)
    value = raw_value.strip()
    start = match.start(group) + len(raw_value) - len(raw_value.lstrip())
    return value, start, start + len(value)


def _integrity_field_candidates(
    line_content: str, keyed_spans, context_spans, approved_spans
):
    candidates = []
    value_spans = []
    for match in INTEGRITY_FIELD_VALUE_RE.finditer(line_content):
        value, start, end = _trimmed_match_value(match, _integrity_value_group(match))
        value_spans.append((start, end))
        if _is_covered_by_span(
            value, start, keyed_spans, context_spans, approved_spans
        ):
            continue
        candidates.append((start, 1, value, False, end))
    return candidates, value_spans


def _hash_field_candidates(
    line_content: str, keyed_spans, context_spans, approved_spans
):
    candidates = []
    value_spans = []
    for match in HASH_FIELD_VALUE_RE.finditer(line_content):
        group = "quoted" if match.group("quoted") is not None else "assigned_bare"
        value, start, end = _trimmed_match_value(match, group)
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
):
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
        line_content, keyed_spans, context_spans, approved_spans
    )
    hashes, hash_spans = _hash_field_candidates(
        line_content, keyed_spans, context_spans, approved_spans
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
_MAX_YARN_ENTRIES = 100_000
_MAX_YARN_HEADER_LENGTH = 65_536
_MAX_YARN_SELECTORS = 4_096
_MAX_YARN_ENTRY_DEPENDENCIES = 100_000


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
        start += 1
        end -= 1
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


def _lockfile_integrity_spans(rel_name: str, file_lines: list[str]):
    if rel_name == "yarn.lock":
        return _yarn_integrity_spans(file_lines)
    if rel_name == "pnpm-lock.yaml":
        return _pnpm_integrity_spans(file_lines)
    return _json_integrity_spans(rel_name, file_lines)


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
    syntax_tree = ctx.get("tree")
    approved_structural_spans, structural_context_spans = _lockfile_integrity_spans(
        rel_name, file_lines
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
        structural_contexts = structural_context_spans.get(line_number, ())
        line_approved_spans = approved_structural_spans.get(line_number, ())
        for (
            context_start,
            context_end,
            decoded_value,
            raw_context,
        ) in structural_contexts:
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

            if tok_entropy >= min_entropy and len(clean_token) >= 20:
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

    # S102: Client-side secret exposure
    norm_path = "/" + rel_path.replace("\\", "/")
    is_client_path = any(seg in norm_path for seg in CLIENT_PATHS)

    if is_client_path:
        for f in findings:
            if f["rule_id"] == "SKY-S101":
                f["rule_id"] = "SKY-S102"
                f["message"] = (
                    f"Client-side secret exposure: "
                    f"Secret exposed in client-accessible path: {rel_path}"
                )

    if rel_path.endswith(JS_TS_SUFFIXES):
        for line_number, raw_line in enumerate(file_lines, start=1):
            line_content = raw_line.rstrip("\n")
            for m in CLIENT_ENV_RE.finditer(line_content):
                col_pos = m.start()
                findings.append(
                    {
                        "rule_id": "SKY-S102",
                        "severity": "CRITICAL",
                        "message": (
                            f"Client-side secret exposure: "
                            f"Non-public env var '{m.group(0)}' may be bundled into client code"
                        ),
                        "file": rel_path,
                        "line": line_number,
                        "col": col_pos,
                    }
                )

    return findings
