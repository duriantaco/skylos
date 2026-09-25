from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator


_PLAIN_TOKEN_RE = re.compile(
    r"""
    //[^\n]*
    |/\*.*?\*/
    |(?:\$@|@\$|@|\$)?"(?:""|\\.|[^"\\])*"
    |'(?:\\.|[^'\\])*'
    """,
    re.DOTALL | re.VERBOSE,
)
_RAW_START_RE = re.compile(r'(?<!\$)(?P<dollars>\$*)(?P<quotes>"{3,})')
_MAX_RAW_NESTING = 32


@dataclass(frozen=True)
class _RawTokenMatch:
    source: str
    begin: int
    finish: int

    def group(self) -> str:
        return self.source[self.begin : self.finish]

    def start(self) -> int:
        return self.begin

    def end(self) -> int:
        return self.finish


_TokenMatch = re.Match[str] | _RawTokenMatch


class _CSharpTokenPattern:
    """Find comments and strings, including variable-width raw literals.

    ``danger`` uses ``finditer`` to recover ordinary interpolation holes. Raw
    literals must be yielded as *one* token so their text cannot be recovered
    accidentally as code when they contain nested string literals.
    """

    def finditer(self, source: str) -> Iterator[_TokenMatch]:
        position = 0
        while position < len(source):
            plain = _PLAIN_TOKEN_RE.search(source, position)
            raw = _RAW_START_RE.search(source, position)
            if raw is not None and (plain is None or raw.start() <= plain.start()):
                end = _raw_literal_end(source, raw)
                yield _RawTokenMatch(source, raw.start(), end)
                position = end
            elif plain is not None:
                yield plain
                position = plain.end()
            else:
                break


_TOKEN_RE = _CSharpTokenPattern()


def _raw_literal_end(source: str, opener: re.Match[str], nesting: int = 0) -> int:
    """Find the matching delimiter, skipping C# expressions inside raw holes."""
    if nesting >= _MAX_RAW_NESTING:
        return len(source)

    delimiter = opener.group("quotes")
    dollars = len(opener.group("dollars"))
    if not dollars:
        end = source.find(delimiter, opener.end())
        if end >= 0:
            return end + len(delimiter)
    else:
        index = opener.end()
        while index < len(source):
            if source.startswith(delimiter, index):
                return index + len(delimiter)
            if source[index] == "{" and source.startswith("{" * dollars, index):
                index = _interpolation_end(
                    source, index + dollars, dollars, nesting + 1
                )
            else:
                index += 1

    # Invalid or incomplete source: hide the suffix rather than invent code.
    return len(source)


def _interpolation_end(source: str, start: int, brace_count: int, nesting: int) -> int:
    depth = 0
    index = start
    while index < len(source):
        raw = _RAW_START_RE.match(source, index)
        if raw is not None:
            index = _raw_literal_end(source, raw, nesting)
            continue
        plain = _PLAIN_TOKEN_RE.match(source, index)
        if plain is not None:
            index = plain.end()
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            if depth == 0 and source.startswith("}" * brace_count, index):
                return index + brace_count
            if depth:
                depth -= 1
        index += 1
    return len(source)


def matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def mask_comments_and_strings(source: str) -> str:
    """Mask comments and literals without changing offsets or line numbers.

    Raw strings, including interpolated raw strings, are masked as a whole.
    Their interpolation holes are located only to find the closing delimiter;
    expressions inside the holes remain masked.
    """
    chars = list(source)
    for token in _TOKEN_RE.finditer(source):
        chars[token.start() : token.end()] = _mask_token(token)
    return "".join(chars)


def _mask_token(match: _TokenMatch) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group())
