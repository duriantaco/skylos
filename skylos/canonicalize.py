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


def strip_zero_width(text: str) -> tuple[str, list[tuple[str, int]]]:
    found: list[tuple[str, int]] = []
    for match in _ZERO_WIDTH_RE.finditer(text):
        pos = match.start()
        line_no = text[:pos].count("\n") + 1
        char_hex = f"U+{ord(match.group()):04X}"
        found.append((char_hex, line_no))

    cleaned = _ZERO_WIDTH_RE.sub("", text)
    return cleaned, found


def decode_base64_blobs(text: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for match in _BASE64_TOKEN_RE.finditer(text):
        token = match.group()
        line_no = text[: match.start()].count("\n") + 1

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

    return results


def detect_homoglyphs(text: str) -> list[tuple[str, str, int]]:
    if not _CONFUSABLE_RE.search(text):
        return []

    results: list[tuple[str, str, int]] = []
    has_ascii_alpha = bool(re.search(r"[a-zA-Z]", text))

    if not has_ascii_alpha:
        return []

    for match in _CONFUSABLE_RE.finditer(text):
        char = match.group()
        line_no = text[: match.start()].count("\n") + 1
        results.append((char, _CONFUSABLES[char], line_no))

    return results
