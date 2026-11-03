from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field

_IDENT_START_RE = re.compile(r"[^\W\d]", re.UNICODE)
_IDENT_RE = re.compile(r"[^\W\d]\w*", re.UNICODE)
_KDOC_LINK_RE = re.compile(r"\[(?P<name>[^\W\d][\w.]*)\](?!\s*\()")
_KDOC_TAG_RE = re.compile(
    r"@(?:see|throws|exception|sample)\s+(?P<name>[^\W\d][\w.]*)", re.UNICODE
)


@dataclass(frozen=True)
class KotlinString:
    start: int
    end: int
    raw: bool
    texts: tuple[str, ...]
    exprs: tuple[tuple[int, int], ...]

    @property
    def is_constant(self) -> bool:
        return not self.exprs

    @property
    def prefix(self) -> str:
        if not self.texts:
            return ""
        return self.texts[0]

    @property
    def literal_text(self) -> str:
        return "".join(self.texts)


@dataclass
class KotlinSource:
    text: str
    code: str
    strings: list[KotlinString] = field(default_factory=list)
    kdoc_names: list[str] = field(default_factory=list)
    _line_starts: list[int] = field(default_factory=list)
    _string_starts: list[int] = field(default_factory=list)
    _string_ends: dict[int, KotlinString] = field(default_factory=dict)
    _pairs: dict[int, int] | None = None

    def close_of(self, open_index: int) -> int:
        if self._pairs is None:
            pairs: dict[int, int] = {}
            stacks: dict[str, list[int]] = {"(": [], "[": [], "{": []}
            openers = {")": "(", "]": "[", "}": "{"}
            for index, char in enumerate(self.code):
                if char in stacks:
                    stacks[char].append(index)
                elif char in openers and stacks[openers[char]]:
                    pairs[stacks[openers[char]].pop()] = index
            self._pairs = pairs
        return self._pairs.get(open_index, -1)

    def line_for(self, offset: int) -> int:
        if not self._line_starts:
            starts = [0]
            for index, char in enumerate(self.text):
                if char == "\n":
                    starts.append(index + 1)
            self._line_starts = starts
        return bisect_right(self._line_starts, max(offset, 0))

    def string_at(self, offset: int) -> KotlinString | None:
        if not self._string_starts:
            self._string_starts = [item.start for item in self.strings]
        index = bisect_right(self._string_starts, offset) - 1
        if index >= 0 and self.strings[index].start == offset:
            return self.strings[index]
        return None

    def string_ending_at(self, end: int) -> KotlinString | None:
        if not self._string_ends:
            self._string_ends = {item.end: item for item in self.strings}
        return self._string_ends.get(end)

    def strings_in(self, start: int, end: int) -> list[KotlinString]:
        if not self._string_starts:
            self._string_starts = [item.start for item in self.strings]
        index = bisect_right(self._string_starts, start - 1)
        found = []
        while index < len(self.strings) and self.strings[index].start < end:
            if self.strings[index].end <= end:
                found.append(self.strings[index])
            index += 1
        return found


class _Lexer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.out = list(text)
        self.strings: list[KotlinString] = []
        self.kdoc_names: list[str] = []

    def blank(self, start: int, end: int) -> None:
        out = self.out
        for index in range(start, min(end, len(out))):
            if out[index] not in "\n\r":
                out[index] = " "

    def code(self, pos: int, closer: str | None = None) -> int:
        text = self.text
        length = len(text)
        depth = 0
        while pos < length:
            char = text[pos]
            if char == "/" and text.startswith("//", pos):
                end = text.find("\n", pos)
                if end < 0:
                    end = length
                self.blank(pos, end)
                pos = end
                continue
            if char == "/" and text.startswith("/*", pos):
                pos = self.block_comment(pos)
                continue
            if char == '"':
                pos = self.string(pos)
                continue
            if char == "'":
                pos = self.char_literal(pos)
                continue
            if closer is not None:
                if char == "{":
                    depth += 1
                elif char == "}":
                    if depth == 0:
                        return pos
                    depth -= 1
            pos += 1
        return pos

    def block_comment(self, pos: int) -> int:
        text = self.text
        start = pos
        depth = 0
        while pos < len(text):
            if text.startswith("/*", pos):
                depth += 1
                pos += 2
                continue
            if text.startswith("*/", pos):
                depth -= 1
                pos += 2
                if depth == 0:
                    break
                continue
            pos += 1
        if text.startswith("/**", start):
            self.read_kdoc(text[start:pos])
        self.blank(start, pos)
        return pos

    def read_kdoc(self, body: str) -> None:
        for match in _KDOC_LINK_RE.finditer(body):
            self.kdoc_names.append(match.group("name"))
        for match in _KDOC_TAG_RE.finditer(body):
            self.kdoc_names.append(match.group("name"))

    def char_literal(self, pos: int) -> int:
        text = self.text
        end = pos + 1
        while end < len(text) and end - pos < 12:
            if text[end] == "\\":
                end += 2
                continue
            if text[end] == "'":
                self.blank(pos + 1, end)
                return end + 1
            if text[end] == "\n":
                break
            end += 1
        return pos + 1

    def string(self, pos: int) -> int:
        text = self.text
        raw = text.startswith('"""', pos)
        quote_len = 1
        if raw:
            quote_len = 3
        start = pos
        pos += quote_len
        texts: list[str] = []
        exprs: list[tuple[int, int]] = []
        chunk: list[str] = []
        while pos < len(text):
            char = text[pos]
            if raw and text.startswith('"""', pos):
                while text.startswith('""""', pos):
                    chunk.append('"')
                    self.out[pos] = " "
                    pos += 1
                pos += 3
                break
            if not raw and char == '"':
                pos += 1
                break
            if not raw and char == "\n":
                break
            if not raw and char == "\\":
                chunk.append(text[pos : pos + 2])
                self.blank(pos, pos + 2)
                pos += 2
                continue
            if char == "$" and text.startswith("${", pos):
                texts.append("".join(chunk))
                chunk = []
                self.blank(pos, pos + 2)
                expr_start = pos + 2
                expr_end = self.code(expr_start, closer="}")
                exprs.append((expr_start, expr_end))
                if expr_end < len(text):
                    self.blank(expr_end, expr_end + 1)
                pos = expr_end + 1
                continue
            if (
                char == "$"
                and pos + 1 < len(text)
                and _IDENT_START_RE.match(text[pos + 1])
            ):
                match = _IDENT_RE.match(text, pos + 1)
                texts.append("".join(chunk))
                chunk = []
                self.blank(pos, pos + 1)
                exprs.append((match.start(), match.end()))
                pos = match.end()
                continue
            chunk.append(char)
            self.blank(pos, pos + 1)
            pos += 1
        texts.append("".join(chunk))
        self.strings.append(
            KotlinString(start, min(pos, len(text)), raw, tuple(texts), tuple(exprs))
        )
        return pos


def lex(source: str) -> KotlinSource:
    lexer = _Lexer(source)
    lexer.code(0)
    lexer.strings.sort(key=lambda item: item.start)
    return KotlinSource(
        text=source,
        code="".join(lexer.out),
        strings=lexer.strings,
        kdoc_names=lexer.kdoc_names,
    )


def matching_brace(text: str, open_brace: int) -> int:
    return matching_close(text, open_brace, "{", "}")


def matching_close(text: str, open_index: int, opener: str, closer: str) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
    return -1


def mask_comments_and_strings(source: str) -> str:
    return lex(source).code
