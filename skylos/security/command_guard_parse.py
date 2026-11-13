from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skylos.security.command_guard_types import CommandRisk


COMMAND_PREFIXES = {"command", "nohup", "sudo", "time"}
# Commands after which a relative path may not be relative to where the
# script started: they change directory (bash or PowerShell), run code the
# scanner cannot see or define code that runs later (aliases, functions,
# traps, case arms), or relink paths.
CWD_HAZARD_WORDS = {
    ".",
    "alias",
    "case",
    "cd",
    "chdir",
    "eval",
    "exec",
    "ln",
    "pop-location",
    "popd",
    "push-location",
    "pushd",
    "set-location",
    "sl",
    "source",
    "trap",
}
CWD_HAZARD_RE = re.compile(
    r"(?<![\w./-])(?:alias|case|cd|chdir|eval|exec|function|ln|pop-location|popd"
    r"|push-location|pushd|set-location|sl|source|trap)(?![\w./-])|--chdir\b",
    re.IGNORECASE,
)
FUNCTION_DEFINITION_RE = re.compile(r"[\w.:-][ \t]*\([ \t]*\)")
SOURCE_DOT_RE = re.compile(
    r"(?:^|[;&|(){}!`]|\b(?:do|elif|else|if|then|until|while)\b)\s*"
    r"(?:(?:builtin|command)\s+)*\.(?=\s)",
    re.MULTILINE,
)
# Words that can stand before the command word of a simple command.
COMMAND_WORD_PREFIXES = {
    "!",
    "(",
    "{",
    "builtin",
    "command",
    "do",
    "elif",
    "else",
    "if",
    "nohup",
    "sudo",
    "then",
    "time",
    "until",
    "while",
}
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_]\w*\+?=")
# HOME assigned, exported, read into or defaulted; "$HOME" and "${HOME}" only
# read it.
HOME_ASSIGNMENT_RE = re.compile(r"(?<![$\w{])HOME\b|\$\{HOME:?=|(?i:\$env:home)\b")
OPTIONS_WITH_VALUES = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--method",
    "--output",
    "--post-data",
    "--post-file",
    "--request",
    "--upload-file",
    "-F",
    "-T",
    "-X",
    "-d",
    "-o",
}


SHELL_WORD_BREAKS = " \t\r\n;&|()<>"


@dataclass(frozen=True)
class ShellScript:
    statements: tuple[tuple[int, str], ...]
    comments: tuple[tuple[int, str], ...]
    heredocs: tuple[tuple[int, int, str], ...]


def parse_shell_script(text: str) -> ShellScript:
    return _ShellScriptParser(text).parse()


def split_shell_statements(command: str) -> list[str]:
    return _split_shell_on(command, {";", "&&", "||"})


def split_pipeline(statement: str) -> list[str]:
    return _split_shell_on(statement, {"|"})


def shell_tokens(statement: str) -> list[str]:
    try:
        return shlex.split(statement, comments=False, posix=True)
    except ValueError:
        return statement.split()


def dequote_shell(text: str) -> str:
    """``text`` with backslash escapes resolved and quote characters removed,
    so ``c\\d``, ``c''d`` and ``HO"ME"`` read as ``cd`` and ``HOME``. Cruder
    than the shell (it also unquotes single-quoted text); used only to find
    words, so it errs towards finding them."""
    joined = text.replace("\\\n", "")  # a backslash-newline continues the line
    unescaped = re.sub(r"\\(.)", r"\1", joined, flags=re.DOTALL)
    return unescaped.replace("'", "").replace('"', "")


def may_change_directory(script: str) -> bool:
    """Whether a relative path in ``script`` might not be relative to where the
    script started. Errs towards yes: a hazard word or function definition
    anywhere in the text or its dequoted form (even in a comment or string),
    a ``.`` that sources a file, a command word built from a variable,
    substitution, glob or brace expansion, or ``env -C``/``--chdir``.
    """
    for text in (script, dequote_shell(script)):
        if (
            CWD_HAZARD_RE.search(text)
            or SOURCE_DOT_RE.search(text)
            or FUNCTION_DEFINITION_RE.search(text)
        ):
            return True
    return any(
        _hides_directory_change(shell_tokens(line))
        for statement in split_shell_statements(script)
        for part in split_pipeline(statement)
        for line in part.splitlines()
    )


def redefines_home(script: str) -> bool:
    return any(
        HOME_ASSIGNMENT_RE.search(text) for text in (script, dequote_shell(script))
    )


def _hides_directory_change(tokens: list[str]) -> bool:
    idx = 0
    while idx < len(tokens) and (
        tokens[idx] in COMMAND_WORD_PREFIXES or ASSIGNMENT_RE.match(tokens[idx])
    ):
        idx += 1
    if idx == len(tokens):
        return False
    raw = dequote_shell(tokens[idx])
    word = raw.lstrip("({!").lower()
    if word in CWD_HAZARD_WORDS or word.startswith("$") or "$(" in word or "`" in word:
        return True
    # A glob or brace expansion can turn the word into "cd": "c?", "{c,}d".
    if word not in {"[", "[["} and ("{" in raw or any(char in word for char in "*?[")):
        return True
    return word == "env" and any(
        arg.startswith("-") and not arg.startswith("--") and "C" in arg
        for arg in tokens[idx + 1 :]
    )


def split_redirects(command: str) -> tuple[list[str], list[str]]:
    """Words of one simple command, and the files its output is redirected to.

    Quote-aware, unlike ``shlex``: a quoted ``">"`` is an argument. An input
    redirect (``< file``) keeps ``file`` as a word because the command reads
    it, as does a here-string (``<<< "$(cat file)"`` runs its substitution);
    ``<> file`` is both read and written, ``>& file`` writes ``file``;
    heredoc delimiters and ``>&2`` descriptor copies are dropped. Subshell
    parentheses are not part of a word: ``(cat x > f)`` writes ``f``.
    """
    words: list[str] = []
    targets: list[str] = []
    word: list[str] = []
    in_word = quoted = False
    pending: str | None = None
    depth = idx = 0  # depth: open "(" of a "$(" inside the current word

    def finish() -> None:
        nonlocal word, in_word, quoted, pending, depth
        if in_word:
            text = "".join(word)
            if pending == "duplicate" and (text.isdigit() or text == "-"):
                pending = "skip"
            if pending in {"write", "duplicate", "read_write"}:
                targets.append(text)
            if pending in {None, "read_write"}:
                words.append(text)
            pending = None
        word, in_word, quoted, depth = [], False, False, 0

    while idx < len(command):
        char = command[idx]
        if char == "\\" and idx + 1 < len(command):
            word.append(command[idx + 1])
            in_word = quoted = True
            idx += 2
            continue
        if char in {"'", '"'}:
            end = idx + 1
            while end < len(command) and command[end] != char:
                if char == '"' and command[end] == "\\" and end + 1 < len(command):
                    end += 1
                word.append(command[end])
                end += 1
            in_word = quoted = True
            idx = end + 1
            continue
        if char.isspace():
            finish()
            idx += 1
            continue
        if char in "<>" or (char == "&" and command.startswith(">", idx + 1)):
            if in_word and not quoted and "".join(word).isdigit():
                word, in_word = [], False  # ``2>``: a descriptor number
            else:
                finish()
            if char == "<":
                end = idx
                while end < len(command) and command[end] == "<":
                    end += 1
                if end - idx == 1 and command.startswith(">", end):
                    pending = "read_write"
                    end += 1
                else:
                    pending = "skip" if end - idx == 2 else None
                idx = end
                continue
            end = idx + (2 if char == "&" else 1)
            if command.startswith(">", end):
                end += 1
            if command.startswith("|", end):
                end += 1
            if command.startswith("&", end):
                end += 1
                pending = "duplicate"  # ``>&2`` copies a descriptor
            else:
                pending = "write"
            idx = end
            continue
        if char in "()" and not (in_word or depth):
            idx += 1  # a subshell opens or closes between words
            continue
        if char == ")" and not depth:
            finish()  # ``... f)``: the subshell closes after a word
            idx += 1
            continue
        depth += {"(": 1, ")": -1}.get(char, 0)
        word.append(char)
        in_word = True
        idx += 1
    finish()
    return words, targets


def split_option(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        flag, value = token.split("=", 1)
        return flag, value
    return token, None


def tokens_start_with(tokens: list[str], prefix: tuple[str, ...]) -> bool:
    return tuple(token.lower() for token in tokens[: len(prefix)]) == prefix


def command_name(tokens: list[str]) -> str:
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        name = token.rsplit("/", 1)[-1].lower()
        if "=" in token and not token.startswith(("$", "./", "/")):
            idx += 1
            continue
        if name in COMMAND_PREFIXES:
            idx += 1
            continue
        return name
    return ""


def dedupe_risks(risks: list[CommandRisk]) -> list[CommandRisk]:
    seen: set[str] = set()
    deduped: list[CommandRisk] = []
    for risk in risks:
        if risk.rule_id in seen:
            continue
        seen.add(risk.rule_id)
        deduped.append(risk)
    return deduped


def _split_shell_on(text: str, separators: set[str]) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    idx = 0
    while idx < len(text):
        char = text[idx]
        if quote == "'":
            if char == "'":
                quote = None
            idx += 1
            continue
        if escaped:
            escaped = False
            idx += 1
            continue
        if char == "\\":
            escaped = True
            idx += 1
            continue
        if quote:
            if char == quote:
                quote = None
            idx += 1
            continue
        if char in {"'", '"'}:
            quote = char
            idx += 1
            continue

        matched = _matched_separator(text, idx, separators)
        if matched == "&" and (
            (idx > 0 and text[idx - 1] in "<>")
            or (idx + 1 < len(text) and text[idx + 1] == ">")
        ):
            matched = None
        if matched:
            part = text[start:idx].strip()
            if part:
                parts.append(part)
            idx += len(matched)
            start = idx
            continue
        idx += 1

    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _matched_separator(text: str, idx: int, separators: set[str]) -> str | None:
    for sep in sorted(separators, key=len, reverse=True):
        if text.startswith(sep, idx):
            if sep == "|" and text.startswith("||", idx):
                continue
            return sep
    return None


class _ShellScriptParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.statements: list[tuple[int, str]] = []
        self.comments: list[tuple[int, str]] = []
        self.heredocs: list[tuple[int, int, str]] = []
        self.pending: list[tuple[str, bool, int]] = []
        self.chars: list[str] = []
        self.start: int | None = None

    def parse(self) -> ShellScript:
        text = self.text
        quote: str | None = None
        idx = 0
        while idx < len(text):
            char = text[idx]
            if quote == "'":
                if char == "'":
                    quote = None
                self._keep(char, idx)
                idx += 1
            elif char == "\\" and text.startswith("\n", idx + 1):
                idx += 2
            elif char == "\\" and idx + 1 < len(text):
                self._keep(text[idx : idx + 2], idx)
                idx += 2
            elif quote == '"':
                if char == '"':
                    quote = None
                self._keep(char, idx)
                idx += 1
            elif char in {"'", '"'}:
                quote = char
                self._keep(char, idx)
                idx += 1
            else:
                idx = self._unquoted(char, idx)
        self._flush()
        return ShellScript(
            tuple(self.statements), tuple(self.comments), tuple(self.heredocs)
        )

    def _unquoted(self, char: str, idx: int) -> int:
        text = self.text
        if char == "#" and self._at_word_start():
            end = text.find("\n", idx)
            if end < 0:
                end = len(text)
            self.comments.append((idx, text[idx:end]))
            return end
        arithmetic = self._arithmetic_end(idx)
        if arithmetic is not None:
            self._keep(text[idx:arithmetic], idx)
            return arithmetic
        if text.startswith("<<<", idx):
            self._keep("<<<", idx)
            return idx + 3
        if text.startswith("<<", idx):
            return self._heredoc_operator(idx)
        if char == "\n":
            if "".join(self.chars).rstrip().endswith("|"):
                self._keep(" ", idx)
            else:
                self._flush()
            return self._heredoc_bodies(idx + 1)
        if text.startswith("&&", idx) or text.startswith("||", idx):
            self._flush()
            return idx + 2
        if char == ";":
            self._flush()
            return idx + 1
        self._keep(char, idx)
        return idx + 1

    def _at_word_start(self) -> bool:
        last = "".join(self.chars[-1:])[-1:]
        return last == "" or last in SHELL_WORD_BREAKS

    def _arithmetic_end(self, idx: int) -> int | None:
        text = self.text
        if text.startswith("$((", idx):
            opening = idx + 1
        elif text.startswith("((", idx) and self._at_word_start():
            opening = idx
        else:
            return None
        depth = 0
        for end in range(opening, len(text)):
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
                if depth == 0:
                    return end + 1
        return None

    def _heredoc_operator(self, idx: int) -> int:
        text = self.text
        end = idx + 2
        strip_tabs = text.startswith("-", end)
        if strip_tabs:
            end += 1
        while end < len(text) and text[end] in " \t":
            end += 1
        word_end, delimiter = _heredoc_delimiter(text, end)
        if delimiter:
            self.pending.append((delimiter, strip_tabs, len(self.statements)))
        self._keep(text[idx:word_end], idx)
        return word_end

    def _heredoc_bodies(self, pos: int) -> int:
        pending = self.pending
        self.pending = []
        for delimiter, strip_tabs, owner in pending:
            found = _heredoc_end(self.text, pos, delimiter, strip_tabs)
            if found is None:
                return pos
            body_end, after = found
            self.heredocs.append((owner, pos, self.text[pos:body_end]))
            pos = after
        return pos

    def _keep(self, chunk: str, idx: int) -> None:
        self.chars.append(chunk)
        if self.start is None and chunk.strip():
            self.start = idx + len(chunk) - len(chunk.lstrip())

    def _flush(self) -> None:
        statement = "".join(self.chars).strip()
        if statement and self.start is not None:
            self.statements.append((self.start, statement))
        self.chars = []
        self.start = None


def _heredoc_delimiter(text: str, start: int) -> tuple[int, str]:
    chars: list[str] = []
    quote: str | None = None
    idx = start
    while idx < len(text) and text[idx] != "\n":
        char = text[idx]
        if quote:
            if char == quote:
                quote = None
            else:
                chars.append(char)
        elif char in {"'", '"'}:
            quote = char
        elif char == "\\" and idx + 1 < len(text):
            chars.append(text[idx + 1])
            idx += 1
        elif char in SHELL_WORD_BREAKS:
            break
        else:
            chars.append(char)
        idx += 1
    return idx, "".join(chars)


def _heredoc_end(
    text: str, pos: int, delimiter: str, strip_tabs: bool
) -> tuple[int, int] | None:
    line_start = pos
    while line_start < len(text):
        line_end = text.find("\n", line_start)
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end].rstrip("\r")
        if strip_tabs:
            line = line.lstrip("\t")
        if line == delimiter:
            return line_start, min(line_end + 1, len(text))
        line_start = line_end + 1
    return None
