"""Skylos inline ignore directives, read only from real source comments.

One grammar serves every language: ``skylos: ignore`` (blanket),
``skylos: ignore[SKY-D211, SKY-U001]`` (only the named rules) and
``skylos: ignore-start`` ... ``skylos: ignore-end``. A directive must open
the comment's text, applies to the comment's own line, and a block applies
to every line from its start to its end. A block comment that spans lines
carries no directive.

TypeScript and JavaScript find their comments in the tree-sitter tree. The
other languages use the comment lexer below, which knows each language's
strings, so text inside a string literal is never read as a directive. A
file the lexer cannot follow to its end (an unterminated string or comment,
or an unusual line terminator) yields no directives, so its findings stay
reported.
"""

from __future__ import annotations

import bisect
import re
from pathlib import PurePath

SKYLOS_DIRECTIVE_RE = re.compile(
    r"^skylos\s*:\s*(?:"
    r"(?P<block>ignore-(?:start|end))(?=\s|$)|"
    r"ignore\s*\[(?P<rules>[^\]]*)\](?=\s|$)|"
    r"(?P<blanket>ignore)(?!\s*\[)(?=\s|$)"
    r")",
    re.IGNORECASE | re.ASCII,
)
SKYLOS_RULE_ID_RE = re.compile(
    r"\bSKY-[A-Z][A-Z0-9-]*\b",
    re.IGNORECASE | re.ASCII,
)
SKYLOS_IGNORE_END_RE = re.compile(
    r"\bskylos\s*:\s*ignore-end\b",
    re.IGNORECASE | re.ASCII,
)
_SKYLOS_TEXT_RE = re.compile(r"skylos", re.IGNORECASE)
_UNSUPPORTED_LINE_ENDING_RE = re.compile("\r(?!\n)|[\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")

_FAMILY_BY_SUFFIX = {
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".dart": "dart",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "c",
    ".cc": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".hh": "c",
    ".hxx": "c",
    ".php": "php",
    ".module": "php",
    ".install": "php",
    ".inc": "php",
    ".theme": "php",
    ".profile": "php",
    ".engine": "php",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".bats": "shell",
}

_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)
_CHAR_LITERAL_RE = re.compile(
    r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}"
    r"|x[0-9a-fA-F]{1,2}|[0-7]{1,3}|[^\n])|[^\\'\n])'"
)
_C_CHAR_LITERAL_RE = re.compile(r"'(?:\\[^\n]|[^\\'\n]){1,4}'")
_C_RAW_STRING_RE = re.compile(r'(?:u8|u|U|L)?R"([^()\\\s"]{0,16})\(')
_RUST_RAW_STRING_RE = re.compile(r'(?:b|c)?r(#*)"')
_CSHARP_STRING_RE = re.compile(r'(\$*)(@?)(\$*)(")')
_PHP_OPEN_TAG_RE = re.compile(r"<\?(?:php(?=\s)|=)?", re.IGNORECASE)
_PHP_HEREDOC_RE = re.compile(
    r"<<<[ \t]*(?P<quote>['\"]?)(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)\r?\n"
)
_SHELL_HEREDOC_RE = re.compile(
    r"<<(?P<dash>-?)[ \t]*(?P<quote>['\"]?)(?P<label>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
)
_SHELL_WORD_BREAKS = frozenset(" \t\n;&|()<>")


class _Unreadable(Exception):
    """The lexer could not follow the file, so it reports no directives."""


def comment_family(path) -> str | None:
    return _FAMILY_BY_SUFFIX.get(PurePath(str(path)).suffix.lower())


def comment_body(comment_text: str) -> str | None:
    if comment_text.startswith("//"):
        return comment_text[2:]
    if comment_text.startswith("#"):
        return comment_text[1:]
    if not comment_text.startswith("/*") or "\n" in comment_text:
        return None
    body = comment_text[2:].rstrip()
    if body.endswith("*/"):
        return body[:-2]
    return None


def parse_directive(body: str) -> tuple[str, set[str], int] | None:
    stripped = body.lstrip()
    directive = SKYLOS_DIRECTIVE_RE.match(stripped)
    if directive is None:
        return None

    block = directive.group("block")
    if block:
        return block.lower().removeprefix("ignore-"), set(), directive.end()

    rules = directive.group("rules")
    if rules is not None:
        rule_ids = [rule_id.strip() for rule_id in rules.split(",")]
        if not rule_ids or any(
            not SKYLOS_RULE_ID_RE.fullmatch(rule_id) for rule_id in rule_ids
        ):
            return None
        return (
            "rules",
            {rule_id.upper() for rule_id in rule_ids},
            directive.end(),
        )

    return "blanket", set(), directive.end()


def directive_ignores(
    comments, line_count: int
) -> tuple[set[int], dict[int, set[str]]]:
    """Ignored lines and rule ignores by line from ``(line, comment_text)``."""
    events_by_line: dict[int, list[tuple[str, set[str]]]] = {}
    for line, comment_text in comments:
        if line > line_count:
            continue
        body = comment_body(comment_text)
        if body is None:
            continue
        parsed = parse_directive(body)
        if parsed is None:
            continue
        kind, rules, directive_end = parsed
        events_by_line.setdefault(line, []).append((kind, rules))
        if kind == "start" and SKYLOS_IGNORE_END_RE.search(
            body.lstrip(), directive_end
        ):
            events_by_line[line].append(("end", set()))

    ignore_lines: set[int] = set()
    ignore_rules_by_line: dict[int, set[str]] = {}
    in_ignore_block = False
    for line in range(1, line_count + 1):
        if in_ignore_block:
            ignore_lines.add(line)
        for kind, rules in events_by_line.get(line, ()):
            if kind == "rules":
                ignore_rules_by_line.setdefault(line, set()).update(rules)
            else:
                ignore_lines.add(line)
            if kind == "start":
                in_ignore_block = True
            elif kind == "end":
                in_ignore_block = False

    return ignore_lines, ignore_rules_by_line


def source_comments(text: str, family: str) -> list[tuple[int, str]] | None:
    """Every comment as ``(line, text)``, or ``None`` when the lexer is lost."""
    if _UNSUPPORTED_LINE_ENDING_RE.search(text):
        return None
    try:
        return _CommentLexer(text, family).comments()
    except _Unreadable:
        return None


def inline_ignores(path, text: str) -> tuple[set[int], dict[int, set[str]]]:
    """Directives honoured in a non-TypeScript source file."""
    family = comment_family(path)
    if family is None or not _SKYLOS_TEXT_RE.search(text):
        return set(), {}
    comments = source_comments(text, family)
    if not comments:
        return set(), {}
    return directive_ignores(comments, text.count("\n") + 1)


class _CommentLexer:
    def __init__(self, text: str, family: str) -> None:
        self.text = text
        self.family = family
        self.pos = 0
        self.found: list[tuple[int, str]] = []
        self.line_starts = [0]
        self.line_starts.extend(
            index + 1 for index, char in enumerate(text) if char == "\n"
        )
        self.pending_heredocs: list[tuple[str, bool]] = []

    def comments(self) -> list[tuple[int, str]]:
        if self.family == "php":
            self._php_document()
        else:
            self._code(None)
        return self.found

    def _line_of(self, pos: int) -> int:
        return bisect.bisect_right(self.line_starts, pos)

    def _record(self, start: int, end: int) -> None:
        self.found.append((self._line_of(start), self.text[start:end]))

    def _prev_char(self) -> str:
        if self.pos == 0:
            return ""
        return self.text[self.pos - 1]

    def _code(self, closer: str | None) -> None:
        text = self.text
        opener = {"}": "{", ")": "("}.get(closer or "")
        depth = 0
        while self.pos < len(text):
            char = text[self.pos]
            if (
                closer is None
                and self.family == "php"
                and text.startswith("?>", self.pos)
            ):
                self.pos += 2
                return
            if opener and char == opener:
                depth += 1
            elif closer and char == closer:
                if depth == 0:
                    self.pos += 1
                    return
                depth -= 1
            if char == "\n" and self.pending_heredocs:
                self.pos += 1
                self._shell_heredoc_bodies()
                continue
            if self._comment() or self._string():
                continue
            if char == "\\" and self.family == "shell":
                self.pos += 2
                continue
            self.pos += 1
        if closer is not None:
            raise _Unreadable

    def _comment(self) -> bool:
        text = self.text
        pos = self.pos
        family = self.family
        if family == "shell":
            if text[pos] != "#" or (pos and text[pos - 1] not in _SHELL_WORD_BREAKS):
                return False
            self._line_comment()
            return True
        if text.startswith("//", pos):
            self._line_comment()
            return True
        if family == "php" and text[pos] == "#" and not text.startswith("#[", pos):
            self._line_comment()
            return True
        if text.startswith("/*", pos):
            self._block_comment()
            return True
        return False

    def _line_comment(self) -> None:
        text = self.text
        start = self.pos
        end = text.find("\n", start)
        if end < 0:
            end = len(text)
        if self.family == "php":
            close = text.find("?>", start, end)
            if close >= 0:
                end = close
        self._record(start, end)
        self.pos = end

    def _block_comment(self) -> None:
        text = self.text
        start = self.pos
        nested = self.family in {"kotlin", "dart", "rust"}
        depth = 0
        index = start
        while index < len(text):
            if text.startswith("/*", index):
                depth += 1
                index += 2
                if not nested and depth > 1:
                    depth = 1
                continue
            if text.startswith("*/", index):
                depth -= 1
                index += 2
                if depth == 0:
                    self._record(start, index)
                    self.pos = index
                    return
                continue
            index += 1
        raise _Unreadable

    def _string(self) -> bool:
        handler = getattr(self, f"_{self.family}_string")
        return handler()

    def _scan_quoted(
        self,
        quote: str,
        *,
        escapes: bool = True,
        multiline: bool = False,
        doubled_quote_escape: bool = False,
        interpolation: str | None = None,
    ) -> None:
        text = self.text
        self.pos += len(quote)
        while self.pos < len(text):
            if text.startswith(quote, self.pos):
                if doubled_quote_escape and text.startswith(quote * 2, self.pos):
                    self.pos += 2 * len(quote)
                    continue
                self.pos += len(quote)
                return
            char = text[self.pos]
            if escapes and char == "\\":
                self.pos += 2
                continue
            if char == "\n" and not multiline:
                raise _Unreadable
            if interpolation and self._interpolation(interpolation):
                continue
            self.pos += 1
        raise _Unreadable

    def _interpolation(self, kind: str) -> bool:
        text = self.text
        pos = self.pos
        if kind == "dollar_brace" and text.startswith("${", pos):
            self.pos += 2
            self._code("}")
            return True
        if kind == "brace":
            if text.startswith("{{", pos):
                self.pos += 2
                return True
            if text[pos] == "{":
                self.pos += 1
                self._code("}")
                return True
        if kind == "php" and (text.startswith("{$", pos) or text.startswith("${", pos)):
            self.pos += 2
            self._code("}")
            return True
        if kind == "shell" and text.startswith("$(", pos):
            self.pos += 2
            self._code(")")
            return True
        return False

    def _char_literal(self, pattern=_CHAR_LITERAL_RE) -> bool:
        match = pattern.match(self.text, self.pos)
        if match is None:
            self.pos += 1
            return True
        self.pos = match.end()
        return True

    def _go_string(self) -> bool:
        char = self.text[self.pos]
        if char == "`":
            end = self.text.find("`", self.pos + 1)
            if end < 0:
                raise _Unreadable
            self.pos = end + 1
            return True
        if char == '"':
            self._scan_quoted('"')
            return True
        if char == "'":
            return self._char_literal()
        return False

    def _java_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if text.startswith('"""', self.pos):
            self._scan_quoted('"""', multiline=True)
            return True
        if char == '"':
            self._scan_quoted('"')
            return True
        if char == "'":
            return self._char_literal()
        return False

    def _kotlin_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if text.startswith('"""', self.pos):
            self._scan_quoted(
                '"""', escapes=False, multiline=True, interpolation="dollar_brace"
            )
            while self.pos < len(text) and text[self.pos] == '"':
                self.pos += 1
            return True
        if char == '"':
            self._scan_quoted('"', interpolation="dollar_brace")
            return True
        if char == "'":
            return self._char_literal()
        return False

    def _csharp_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if char == "'":
            return self._char_literal()
        if char not in '"$@':
            return False
        match = _CSHARP_STRING_RE.match(text, self.pos)
        if match is None:
            return False
        if char != '"' and self._prev_char() in _IDENT_CHARS:
            return False
        dollars = len(match.group(1)) + len(match.group(3))
        verbatim = bool(match.group(2))
        quote_start = match.start(4)
        quotes = 0
        while text.startswith('"', quote_start + quotes):
            quotes += 1
        if not verbatim and quotes >= 3:
            delimiter = '"' * quotes
            end = text.find(delimiter, quote_start + quotes)
            if end < 0:
                raise _Unreadable
            end += quotes
            while end < len(text) and text[end] == '"':
                end += 1
            self.pos = end
            return True
        self.pos = quote_start
        interpolation = None
        if dollars:
            interpolation = "brace"
        if verbatim:
            self._scan_quoted(
                '"',
                escapes=False,
                multiline=True,
                doubled_quote_escape=True,
                interpolation=interpolation,
            )
        else:
            self._scan_quoted('"', interpolation=interpolation)
        return True

    def _dart_string(self) -> bool:
        text = self.text
        pos = self.pos
        raw = False
        if (
            text[pos] == "r"
            and text[pos + 1 : pos + 2] in {"'", '"'}
            and self._prev_char() not in _IDENT_CHARS
        ):
            raw = True
            pos += 1
        if text[pos] not in {"'", '"'}:
            return False
        self.pos = pos
        quote = text[pos]
        triple = text.startswith(quote * 3, pos)
        if triple:
            quote *= 3
        interpolation = None
        if not raw:
            interpolation = "dollar_brace"
        self._scan_quoted(
            quote,
            escapes=not raw,
            multiline=triple,
            interpolation=interpolation,
        )
        return True

    def _rust_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if char in "bcr" and self._prev_char() not in _IDENT_CHARS:
            raw = _RUST_RAW_STRING_RE.match(text, self.pos)
            if raw is not None:
                closing = '"' + raw.group(1)
                end = text.find(closing, raw.end())
                if end < 0:
                    raise _Unreadable
                self.pos = end + len(closing)
                return True
            if char in "bc" and text.startswith('"', self.pos + 1):
                self.pos += 1
                self._scan_quoted('"', multiline=True)
                return True
            if char == "b" and text.startswith("'", self.pos + 1):
                self.pos += 1
                return self._char_literal()
            return False
        if char == '"':
            self._scan_quoted('"', multiline=True)
            return True
        if char == "'":
            return self._char_literal()
        return False

    def _c_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if char in "uULR" and self._prev_char() not in _IDENT_CHARS:
            raw = _C_RAW_STRING_RE.match(text, self.pos)
            if raw is not None:
                closing = ")" + raw.group(1) + '"'
                end = text.find(closing, raw.end())
                if end < 0:
                    raise _Unreadable
                self.pos = end + len(closing)
                return True
            return False
        if char == '"':
            self._c_quoted()
            return True
        if char == "'":
            if self._prev_char().isdigit():
                self.pos += 1
                return True
            return self._char_literal(_C_CHAR_LITERAL_RE)
        return False

    def _c_quoted(self) -> None:
        text = self.text
        self.pos += 1
        while self.pos < len(text):
            char = text[self.pos]
            if char == '"':
                self.pos += 1
                return
            if char == "\\":
                self.pos += 2
                continue
            if char == "\n":
                raise _Unreadable
            self.pos += 1
        raise _Unreadable

    def _php_document(self) -> None:
        text = self.text
        while self.pos < len(text):
            opened = _PHP_OPEN_TAG_RE.search(text, self.pos)
            if opened is None:
                return
            self.pos = opened.end()
            self._code(None)

    def _php_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if char == "<" and text.startswith("<<<", self.pos):
            heredoc = _PHP_HEREDOC_RE.match(text, self.pos)
            if heredoc is None:
                return False
            closing = re.compile(
                r"^[ \t]*" + re.escape(heredoc.group("label")) + r"\b", re.MULTILINE
            )
            end = closing.search(text, heredoc.end())
            if end is None:
                raise _Unreadable
            self.pos = end.end()
            return True
        if char == "'":
            self._scan_quoted("'", multiline=True)
            return True
        if char in {'"', "`"}:
            self._scan_quoted(char, multiline=True, interpolation="php")
            return True
        return False

    def _shell_string(self) -> bool:
        text = self.text
        char = text[self.pos]
        if char == "'":
            if self._prev_char() == "$":
                self._scan_quoted("'", multiline=True)
                return True
            end = text.find("'", self.pos + 1)
            if end < 0:
                raise _Unreadable
            self.pos = end + 1
            return True
        if char == '"':
            self._scan_quoted('"', multiline=True, interpolation="shell")
            return True
        if char == "`":
            self._scan_quoted("`", multiline=True)
            return True
        if char == "<" and text.startswith("<<", self.pos):
            if text.startswith("<<<", self.pos):
                self.pos += 3
                return True
            heredoc = _SHELL_HEREDOC_RE.match(text, self.pos)
            if heredoc is None:
                return False
            self.pending_heredocs.append(
                (heredoc.group("label"), bool(heredoc.group("dash")))
            )
            self.pos = heredoc.end()
            return True
        return False

    def _shell_heredoc_bodies(self) -> None:
        text = self.text
        while self.pending_heredocs:
            label, strip_tabs = self.pending_heredocs.pop(0)
            while True:
                if self.pos >= len(text):
                    raise _Unreadable
                end = text.find("\n", self.pos)
                if end < 0:
                    end = len(text)
                line = text[self.pos : end]
                self.pos = min(end + 1, len(text))
                if strip_tabs:
                    line = line.lstrip("\t")
                if line == label:
                    break
