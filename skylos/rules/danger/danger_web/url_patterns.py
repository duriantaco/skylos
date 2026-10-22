"""Whether a regular expression only lets through URLs whose scheme cannot
run script.

``url_pattern_is_safe`` parses the pattern with the standard library's own
regex parser and spells out every literal text a match can begin with,
following literals, small character sets, optional parts, alternatives and
groups. Zero-width assertions are skipped, which only adds matches. The
spelling stops at anything it cannot list (``.``, ``\\S``, large or negated
sets, back references) and keeps the text before it. The pattern is safe
when no URL beginning with any of those texts can use a script-running
scheme (``html_context.safe_url_prefix``). An empty text, as in
``(https://)?.*``, is never safe."""

from __future__ import annotations

import re
import string
from functools import lru_cache

from skylos.rules.danger.danger_web.html_context import safe_url_prefix

try:
    from re import _constants as _codes
    from re import _parser as _syntax
except ImportError:
    import sre_constants as _codes
    import sre_parse as _syntax

FLAG_NAMES = frozenset(
    {"I", "IGNORECASE", "M", "MULTILINE", "S", "DOTALL", "X", "VERBOSE", "A", "ASCII", "U", "UNICODE"}
)
ANCHORED_METHODS = frozenset({"match", "fullmatch"})
_MAX_TEXTS = 64
_MAX_TEXT = 24
_MAX_SET = 32
_ZERO_WIDTH = frozenset({_codes.AT, _codes.ASSERT, _codes.ASSERT_NOT})
def _repeat_codes():
    codes = {_codes.MAX_REPEAT, _codes.MIN_REPEAT}
    possessive = getattr(_codes, "POSSESSIVE_REPEAT", None)
    if possessive is not None:
        codes.add(possessive)
    return frozenset(codes)


_REPEATS = _repeat_codes()
_ATOMIC = getattr(_codes, "ATOMIC_GROUP", None)
_START_ANCHORS = frozenset({_codes.AT_BEGINNING, _codes.AT_BEGINNING_STRING})


class _Scan:
    """Case rules in force while spelling part of a pattern."""

    def __init__(self, folded: bool, ascii_only: bool):
        self.folded = folded
        self.ascii_only = ascii_only

    def scoped(self, added: int, removed: int) -> "_Scan":
        folded = self.folded
        if added & re.IGNORECASE:
            folded = True
        if removed & re.IGNORECASE:
            folded = False
        ascii_only = self.ascii_only
        if added & re.ASCII:
            ascii_only = True
        elif added & re.UNICODE:
            ascii_only = False
        return _Scan(folded, ascii_only)

    def chars(self, code: int) -> frozenset:
        return _variants(code, self.folded, self.ascii_only)


@lru_cache(maxsize=2048)
def _variants(code: int, folded: bool, ascii_only: bool) -> frozenset:
    """Characters a literal matches, ASCII letters in lower case (a URL
    scheme is compared without case)."""
    char = chr(code)
    found = {char}
    if folded:
        flags = re.IGNORECASE
        if ascii_only:
            flags |= re.ASCII
        pattern = re.escape(char)
        for letter in string.ascii_letters:
            if re.fullmatch(pattern, letter, flags):
                found.add(letter)
    return frozenset(_lower_ascii(item) for item in found)


def _lower_ascii(char: str) -> str:
    if char.isascii():
        return char.lower()
    return char


def _set_members(items, scan: _Scan):
    members = set()
    for code, value in items:
        if code == _codes.LITERAL:
            members |= scan.chars(value)
        elif code == _codes.RANGE and value[1] - value[0] < _MAX_SET:
            for point in range(value[0], value[1] + 1):
                members |= scan.chars(point)
        else:
            return None
        if len(members) > _MAX_SET:
            return None
    return members


def _closed(texts):
    return {(text, False) for text, _ in texts}


def _bounded(texts):
    if len(texts) > _MAX_TEXTS:
        return None
    return texts


def _append(texts, chars):
    grown = set()
    for text, open_end in texts:
        if not open_end:
            grown.add((text, False))
            continue
        for char in chars:
            longer = text + char
            grown.add((longer, len(longer) < _MAX_TEXT))
    return _bounded(grown)


def _spell(texts, items, scan: _Scan):
    """Texts a match can begin with after ``items``, from each open text."""
    for code, value in items:
        texts = _step(texts, code, value, scan)
        if texts is None:
            return None
        if not any(open_end for _, open_end in texts):
            return texts
    return texts


def _alternatives(texts, branches, scan: _Scan):
    merged = set()
    for branch in branches:
        spelled = _spell(texts, branch, scan)
        if spelled is None:
            return None
        merged |= spelled
    return _bounded(merged)


def _repeat(texts, value, scan: _Scan):
    low, high, inner = value
    once = _spell(texts, inner, scan)
    if once is None:
        return None
    result = set()
    if low == 0:
        result |= texts
    if high == 1:
        result |= once
    else:
        result |= _closed(once)
    return _bounded(result)


def _step(texts, code, value, scan: _Scan):
    if code in _ZERO_WIDTH:
        return texts
    if code == _codes.LITERAL:
        return _append(texts, scan.chars(value))
    if code == _codes.IN:
        members = _set_members(value, scan)
        if members is None:
            return _closed(texts)
        return _append(texts, members)
    if code == _codes.SUBPATTERN:
        _group, added, removed, inner = value
        return _spell(texts, inner, scan.scoped(added, removed))
    if _ATOMIC is not None and code == _ATOMIC:
        return _spell(texts, value, scan)
    if code == _codes.BRANCH:
        return _alternatives(texts, value[1], scan)
    if code in _REPEATS:
        return _repeat(texts, value, scan)
    return _closed(texts)


def _anchored_at_start(items, flags: int) -> bool:
    if not items or items[0][0] != _codes.AT:
        return False
    anchor = items[0][1]
    if anchor == _codes.AT_BEGINNING_STRING:
        return True
    return anchor in _START_ANCHORS and not flags & re.MULTILINE


def url_pattern_is_safe(pattern, flags: int, method: str) -> bool:
    """No string that ``pattern`` lets through can, as a URL, use a scheme
    that runs script. ``method`` is how the pattern is applied: ``match`` and
    ``fullmatch`` start at the beginning of the string; ``search`` counts
    only when the pattern itself begins with ``\\A``, or ``^`` without
    MULTILINE."""
    if not isinstance(pattern, str):
        return False
    try:
        parsed = _syntax.parse(pattern, flags)
    except (re.error, RecursionError, OverflowError, ValueError, TypeError):
        return False
    flags = parsed.state.flags
    items = list(parsed)
    if method not in ANCHORED_METHODS and not _anchored_at_start(items, flags):
        return False
    scan = _Scan(bool(flags & re.IGNORECASE), bool(flags & re.ASCII))
    try:
        texts = _spell({("", True)}, items, scan)
    except RecursionError:
        return False
    if not texts:
        return False
    return all(safe_url_prefix(text) for text, _ in texts)
