from __future__ import annotations

import base64
import re
import unicodedata


ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
}

_zw_escaped = []
for c in ZERO_WIDTH_CHARS:
    _zw_escaped.append(re.escape(c))
_ZERO_WIDTH_RE = re.compile("[" + "".join(_zw_escaped) + "]")
_ZERO_WIDTH_TRANSLATION = {ord(c): None for c in ZERO_WIDTH_CHARS}

MAX_ZERO_WIDTH_HITS = 64
MAX_BASE64_TOKENS = 64
MAX_BASE64_TOKEN_CHARS = 8192
MAX_BASE64_RESULTS = 16

# common cyrillic/greek characters that look like latin ASCII
_CONFUSABLES: dict[str, str] = {
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0421": "C",  # Cyrillic С
    "\u0415": "E",  # Cyrillic Е
    "\u041d": "H",  # Cyrillic Н
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0455": "s",  # Cyrillic ѕ
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u0391": "A",  # Greek Α
    "\u0392": "B",  # Greek Β
    "\u0395": "E",  # Greek Ε
    "\u0397": "H",  # Greek Η
    "\u0399": "I",  # Greek Ι
    "\u039a": "K",  # Greek Κ
    "\u039c": "M",  # Greek Μ
    "\u039d": "N",  # Greek Ν
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u03a4": "T",  # Greek Τ
    "\u03a7": "X",  # Greek Χ
    "\u03bf": "o",  # Greek ο
}

_conf_escaped = []
for c in _CONFUSABLES:
    _conf_escaped.append(re.escape(c))
_CONFUSABLE_RE = re.compile("[" + "".join(_conf_escaped) + "]")

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text


def strip_zero_width(
    text: str, *, max_hits: int | None = MAX_ZERO_WIDTH_HITS
) -> tuple[str, list[tuple[str, int]]]:
    found: list[tuple[str, int]] = []
    line_no = 1
    cursor = 0
    for match in _ZERO_WIDTH_RE.finditer(text):
        if max_hits is not None and len(found) >= max_hits:
            break
        start = match.start()
        line_no += text.count("\n", cursor, start)
        cursor = match.end()
        char_hex = f"U+{ord(match.group()):04X}"
        found.append((char_hex, line_no))

    cleaned = text.translate(_ZERO_WIDTH_TRANSLATION)
    return cleaned, found


def decode_base64_blobs(
    text: str,
    *,
    max_tokens: int | None = MAX_BASE64_TOKENS,
    max_token_chars: int | None = MAX_BASE64_TOKEN_CHARS,
    max_results: int | None = MAX_BASE64_RESULTS,
) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    tokens_seen = 0
    line_no = 1
    cursor = 0
    for match in _BASE64_TOKEN_RE.finditer(text):
        if max_tokens is not None and tokens_seen >= max_tokens:
            break
        tokens_seen += 1

        start = match.start()
        end = match.end()
        line_no += text.count("\n", cursor, start)
        cursor = end

        if max_token_chars is not None and end - start > max_token_chars:
            continue

        token = match.group()

        try:
            decoded_bytes = base64.b64decode(token, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="strict")
        except Exception:
            continue

        if (
            len(decoded) >= 8
            and " " in decoded
            and sum(1 for c in decoded if c.isprintable()) / len(decoded) > 0.8
        ):
            results.append((decoded, line_no))
            if max_results is not None and len(results) >= max_results:
                break

    return results


def detect_homoglyphs(text: str) -> list[tuple[str, str, int]]:
    if not _CONFUSABLE_RE.search(text):
        return []

    results: list[tuple[str, str, int]] = []

    for line_no, line in enumerate(text.splitlines(), 1):
        for word_match in re.finditer(r"\S+", line):
            word = word_match.group()
            has_ascii = bool(re.search(r"[a-zA-Z]", word))
            has_confusable = bool(_CONFUSABLE_RE.search(word))
            if not (has_ascii and has_confusable):
                continue
            for char_match in _CONFUSABLE_RE.finditer(word):
                char = char_match.group()
                results.append((char, _CONFUSABLES[char], line_no))

    return results
