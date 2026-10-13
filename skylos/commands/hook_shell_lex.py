"""Splitting a shell command into pipelines of simple commands.

Used by :mod:`skylos.commands.hook_shell_reads`. Handles what agents usually
write: quotes, ``;``/``&&``/``||``/``&``/newlines, pipes, redirects (with
file-descriptor numbers), comments, here-documents, and command
substitutions, which become placeholders so the caller can parse each one
on its own.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

PUNCTUATION = ";&|()<>\n"
SUBSTITUTION_RE = re.compile(r"__skylos_sub_(\d+)__")
# Stands in for a "$" the shell does not expand (single-quoted or "\$").
LITERAL_DOLLAR = "\ue000"
# Words that mark entering and leaving a "( ... )" subshell.
SUBSHELL_OPEN = "\ue001("
SUBSHELL_CLOSE = "\ue001)"
# Quoted strings and words longer than this are replaced (shlex is
# quadratic on long tokens), and only this much command text is analysed.
MAX_QUOTED = 4096
MAX_COMMAND_CHARS = 16384

_WORD_START = " \t\n;&|()"
# Characters prepare() looks at; runs of anything else are copied as is.
_PLAIN_RUN = re.compile(r"[^'\"\\#0-9$<>`]+")
_DIGITS = re.compile(r"\d+")
_LONG_WORD = re.compile(r"[^\s;&|()<>'\"]{%d,}" % (MAX_QUOTED + 1))
_SUBSTITUTION = "__skylos_sub_{}__"
_FD = "__skylos_fd_{}__"
_FD_RE = re.compile(r"__skylos_fd_(\d+)__")
# Not preceded or followed by another "<", so here-strings (<<<) are skipped.
_HEREDOC_RE = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*\\?(['\"]?)([^\s'\"<>|;&()]+)\2")
_TERMINALS = frozenset({"/dev/stdout", "/dev/stderr", "/dev/tty"})


@dataclass
class Command:
    words: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)  # targets of "<"
    herestrings: list[str] = field(default_factory=list)  # words after "<<<"
    hidden: bool = False  # stdout goes to a file or /dev/null


def prepare(text: str) -> tuple[str, list[str]]:
    """Quote-aware pass before lexing: drop comments and here-document
    bodies, mark file-descriptor numbers on redirects ("2>"), and replace
    ``$(...)``, backticks, ``<(...)`` and ``>(...)`` with placeholders.
    Returns the new text and each placeholder's command."""
    text = _strip_heredoc_bodies(text)
    text = _LONG_WORD.sub("long", text)[:MAX_COMMAND_CHARS]
    out: list[str] = []
    bodies: list[str] = []
    quote = ""
    unclosed = False  # after one unclosed "$(", bash rejects the command
    index = 0
    while index < len(text):
        run = _PLAIN_RUN.match(text, index)
        if run:
            out.append(run.group(0))
            index = run.end()
            continue
        char = text[index]
        if char in "'\"\\":
            quote, index = _copy_quoted(text, index, quote, out)
            continue
        at_word_start = index == 0 or text[index - 1] in _WORD_START
        if not quote and at_word_start and char == "#":
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline
            continue
        if not quote and at_word_start and char.isdigit():
            digits = _DIGITS.match(text, index).group(0)
            if text.startswith(("<", ">"), index + len(digits)):
                out.append(_FD.format(digits))
                index += len(digits)
                continue
        body = None if unclosed else _substitution_at(text, index)
        if body is None:
            unclosed = unclosed or (char in "$<>`" and _opens_substitution(text, index))
            out.append(char)
            index += 1
            continue
        start, end = body
        bodies.append(text[start:end])
        out.append(_SUBSTITUTION.format(len(bodies) - 1))
        index = end + 1
    return "".join(out), bodies


def truncates(text: str) -> bool:
    """Whether :func:`prepare` would cut ``text`` short: the command, without
    here-document bodies, is longer than MAX_COMMAND_CHARS. Callers must not
    treat what follows the cut as checked."""
    if len(text) <= MAX_COMMAND_CHARS:
        return False
    return len(_LONG_WORD.sub("long", _strip_heredoc_bodies(text))) > MAX_COMMAND_CHARS


def tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""  # prepare() already removed comments
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: the shell would reject it too
        return re.findall(r"[^\s;&|()<>]+|[;&|()<>\n]+", text)


def pipelines(words: list[str]) -> list[list[Command]]:
    """Split tokens into pipelines of simple commands, applying redirects."""
    lines: list[list[Command]] = [[Command()]]
    index = 0
    while index < len(words):
        token = words[index]
        current = lines[-1][-1]
        if not _is_operator(token):
            current.words.append(token)
            index += 1
            continue
        core = token.replace("\n", "")
        if "<" in core or ">" in core:
            target = words[index + 1] if index + 1 < len(words) else ""
            _redirect(current, core, target)
            index += 2
            continue
        if core in {"|", "|&"}:
            lines[-1].append(Command())
        else:
            for char in core:
                if char in "()":
                    marker = SUBSHELL_OPEN if char == "(" else SUBSHELL_CLOSE
                    lines.append([Command(words=[marker])])
            lines.append([Command()])
        index += 1
    return [[cmd for cmd in line if cmd.words or cmd.inputs] for line in lines]


def _copy_quoted(text: str, index: int, quote: str, out: list[str]) -> tuple[str, int]:
    """Copy a quote character, a whole single-quoted string, or a backslash
    escape; return the new quote state and index. A "$" the shell will not
    expand becomes LITERAL_DOLLAR, and a very long string a placeholder."""
    char = text[index]
    if char == "\\":
        escaped = text[index + 1 : index + 2]
        if escaped in {"\n", ""}:
            # Line continuation (and a trailing backslash): the shell removes
            # it, so "pip install \<newline> x" is one command.
            return quote, index + 2
        out.append("\\" + (LITERAL_DOLLAR if escaped == "$" else escaped))
        return quote, index + 2
    if char == "'" and not quote:
        end = text.find("'", index + 1)
        if end < 0:
            out.append(char)
            return quote, index + 1
        body = text[index + 1 : end]
        if len(body) > MAX_QUOTED:
            body = "long"
        out.append("'" + body.replace("$", LITERAL_DOLLAR) + "'")
        return quote, end + 1
    if char == '"' and not quote:
        end = _double_quote_end(text, index + 1)
        body = text[index + 1 : end] if end is not None else ""
        if (
            end is not None
            and len(body) > MAX_QUOTED
            and not any(mark in body for mark in ("$", "`"))
        ):
            out.append('"long"')
            return quote, end + 1
    out.append(char)
    if char == '"':
        return ("" if quote == '"' else '"'), index + 1
    return quote, index + 1


def _double_quote_end(text: str, index: int) -> int | None:
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index
        index += 1
    return None


def _opens_substitution(text: str, index: int) -> bool:
    if text[index] == "`":
        return True
    return text.startswith("(", index + 1) and not text.startswith("((", index + 1)


def _substitution_at(text: str, index: int) -> tuple[int, int] | None:
    """(start, end) of the command inside a substitution opening at
    ``index``, or None."""
    char = text[index]
    if char == "`":
        end = _closing(text, index + 1, "`")
        return None if end is None else (index + 1, end)
    if (
        char in "$<>"
        and text.startswith("(", index + 1)
        and not text.startswith("((", index + 1)  # arithmetic
    ):
        end = _closing(text, index + 2, ")")
        return None if end is None else (index + 2, end)
    return None


def _strip_heredoc_bodies(text: str) -> str:
    """Drop here-document bodies: they are data, and their quotes and
    parentheses would otherwise confuse the lexer."""
    lines = text.split("\n")
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        index += 1
        for match in _HEREDOC_RE.finditer(line):
            index = _after_heredoc(
                lines, index, match.group(3), strip_tabs=match.group(1) == "-"
            )
    return "\n".join(kept)


def _after_heredoc(
    lines: list[str], index: int, delimiter: str, *, strip_tabs: bool
) -> int:
    while index < len(lines):
        body = lines[index].lstrip("\t") if strip_tabs else lines[index]
        index += 1
        if body == delimiter:
            break
    return index


def _closing(text: str, start: int, closer: str) -> int | None:
    """Index of the ``closer`` that ends a substitution opened before
    ``start``, skipping quoted text and nested parentheses."""
    depth = 1
    quote = ""
    index = start
    while index < len(text):
        char = text[index]
        if quote == "'" or char in "'\"\\":
            # Inside backticks a single quote opens a string as well.
            quote, index = _skip_quoted(text, index, quote)
            continue
        if closer == "`" and char == "`":
            return index
        if closer == ")" and char in "()":
            depth += 1 if char == "(" else -1
            if depth == 0:
                return index
        index += 1
    return None


def _skip_quoted(text: str, index: int, quote: str) -> tuple[str, int]:
    char = text[index]
    if quote == "'":
        return ("" if char == "'" else quote), index + 1
    if char == "\\":
        return quote, index + 2
    if char == '"':
        return ("" if quote == '"' else '"'), index + 1
    return ("'" if not quote else quote), index + 1


def _is_operator(token: str) -> bool:
    return bool(token) and all(char in PUNCTUATION for char in token)


def _redirect(command: Command, operator: str, target: str) -> None:
    fd = None
    if command.words:
        marker = _FD_RE.fullmatch(command.words[-1])
        if marker:
            fd = marker.group(1)
            command.words.pop()
    if operator in {"<", "<>"}:
        if fd in {None, "0"}:
            command.inputs.append(target)
        return
    if operator == "<<<":
        command.herestrings.append(target)
        return
    if operator.startswith("<"):
        return  # here-document or descriptor duplication
    if operator in {"&>", "&>>"}:
        command.hidden = True
        return
    if fd not in {None, "1"}:
        return  # stderr and other descriptors
    if operator == ">&" and target in {"1", "2", "&1", "&2"}:
        return  # still on the terminal
    if target not in _TERMINALS:
        command.hidden = True
