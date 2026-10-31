"""Bounded shell structure: top-level root gates and function spans.

The parser understands the compound commands scripts normally use and gives
up (returns None) on anything else, so a caller can only lose precision.
"""

from __future__ import annotations

import re
import shlex
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass

MAX_SOURCE_CHARACTERS = 2_000_000
MAX_TOKENS = 200_000
MAX_DEPTH = 200

_LIST_SEPARATORS = frozenset({";", "\n", "&"})
_CASE_ENDS = frozenset({";;", ";&", ";;&"})
_LIST_CLOSERS = frozenset({")"}) | _CASE_ENDS
_WORD_END = " \t\r\n;&|)"
_OVERRIDDEN_BUILTINS = frozenset(
    {".", "[", "builtin", "command", "enable", "eval", "exit", "id", "source", "test"}
)
_ALIASING_COMMANDS = frozenset({"alias", "enable"})
_PRE_GATE_REJECTS = frozenset({".", "alias", "enable", "eval", "source"})
_PREFIX_COMMANDS = frozenset({"builtin", "command"})
_EUID_SHELLS = frozenset({"bash", "zsh"})
_COMMAND_IDENTITY_RE = re.compile(
    r'"?\$\(\s*(?:/usr/bin/|/bin/)?id\s+-u\s*\)"?'
    r'|"?`\s*(?:/usr/bin/|/bin/)?id\s+-u\s*`"?'
)
_VARIABLE_IDENTITY_RE = re.compile(r'"?\$(?:\{(?:EUID|UID)\}|EUID\b|UID\b)"?')
_SHEBANG_RE = re.compile(r"#!\s*(?P<command>\S+)(?P<arguments>[^\n]*)")
_EVAL_SET_RE = re.compile(r"(?:^|[\s;&|(){}])set(?:\s+(?:--|[^\s;&|+-])|\s*$)")
_ZERO_RE = re.compile(r"""(["']?)0\1""")
_ARITHMETIC_RE = re.compile(r"\s*\$?\{?(?:EUID|UID)\}?\s*(?P<op>==|!=)\s*0\s*")
_NAME_RE = re.compile(r"[A-Za-z_][\w:.-]*")


class _Unsupported(Exception):
    pass


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    line: int


@dataclass
class _Simple:
    words: list[str]
    line: int


@dataclass
class _Group:
    kind: str
    body: list
    line: int


@dataclass
class _If:
    clauses: list
    orelse: list | None
    line: int


@dataclass
class _Compound:
    parts: list
    line: int


@dataclass
class _Function:
    name: str
    body: object
    line: int
    end: int


@dataclass
class _Pipeline:
    commands: list
    negated: bool


@dataclass
class _AndOr:
    pipelines: list
    operators: list
    line: int
    background: bool = False


@dataclass(frozen=True)
class ShellStructure:
    functions: tuple[tuple[int, int], ...] = ()
    root_gate_line: int | None = None
    positionals_rebound: bool = False

    def _function_at(self, line: int) -> tuple[int, int] | None:
        index = bisect_right(self.functions, (line, float("inf"))) - 1
        if index >= 0 and self.functions[index][1] >= line:
            return self.functions[index]
        return None

    def in_function(self, line: int) -> bool:
        return self._function_at(line) is not None

    def root_gate_covers(self, line: int) -> bool:
        """The sink at ``line`` can only run after the root gate passed."""
        if self.root_gate_line is None:
            return False
        function = self._function_at(line)
        if function is not None:
            return function[0] > self.root_gate_line
        return line > self.root_gate_line


class _Lexer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.tokens: list[_Token] = []
        self.line = 1
        self.word_start: int | None = None
        self.word_line = 1
        self.heredocs: list[tuple[str, bool]] = []
        self.skip_to: int | None = None

    def run(self) -> list[_Token]:
        source = self.source
        index = 0
        while index < len(source):
            if len(self.tokens) > MAX_TOKENS:
                raise _Unsupported
            self.skip_to = None
            index = self._step(index)
            if self.skip_to is not None:
                self.line += source.count("\n", index, self.skip_to)
                index = self.skip_to
        self.skip_to = None
        self._finish(len(source))
        if self.skip_to is not None or self.heredocs:
            raise _Unsupported
        return self.tokens

    def _step(self, index: int) -> int:
        source = self.source
        char = source[index]
        if char == "\\":
            if source.startswith("\\\n", index):
                self.line += 1
                return index + 2
            self._start(index)
            return self._advance(index, index + 2)
        if char in " \t\r":
            self._finish(index)
            return index + 1
        if char == "\n":
            self._finish(index)
            self._emit("op", "\n")
            self.line += 1
            return self._skip_heredocs(index + 1)
        if char == "#" and self.word_start is None:
            end = source.find("\n", index)
            if end < 0:
                return len(source)
            return end
        if char in "'\"`$":
            self._start(index)
            return self._advance(index, self._quoted(index))
        if char == "<":
            return self._less(index)
        return self._operator(index)

    def _operator(self, index: int) -> int:
        source = self.source
        char = source[index]
        word = self._word_text(index)
        if char == "&":
            if source.startswith("&&", index):
                return self._op(index, "&&")
            if source.startswith("&>", index) or word.endswith((">", "<")):
                self._start(index)
                return index + 1
            return self._op(index, "&")
        if char == "|":
            if source.startswith("||", index):
                return self._op(index, "||")
            if word.endswith(">"):
                return index + 1
            if source.startswith("|&", index):
                return self._op(index, "|&")
            return self._op(index, "|")
        if char == ";":
            for operator in (";;&", ";;", ";&", ";"):
                if source.startswith(operator, index):
                    return self._op(index, operator)
        if char == "(":
            return self._open_paren(index, word)
        if char == ")":
            return self._op(index, ")")
        self._start(index)
        return index + 1

    def _open_paren(self, index: int, word: str) -> int:
        if self.word_start is None and self.source.startswith("((", index):
            self._start(index)
            end = self._balanced(index)
            self.line += self.source.count("\n", index, end)
            self._finish(end)
            return end
        if word and word[-1] in "=@?*+!":
            return self._advance(index, self._balanced(index))
        return self._op(index, "(")

    def _less(self, index: int) -> int:
        source = self.source
        if source.startswith("<<<", index):
            self._start(index)
            return index + 3
        if not source.startswith("<<", index):
            self._start(index)
            return index + 1
        self._finish(index)
        position = index + 2
        strip = source.startswith("-", position)
        if strip:
            position += 1
        while position < len(source) and source[position] in " \t":
            position += 1
        start = position
        while position < len(source) and source[position] not in " \t\r\n;&|<>()":
            if source[position] in "'\"":
                position = self._quoted(position)
            else:
                position += 1
        delimiter = source[start:position].replace("'", "").replace('"', "")
        delimiter = delimiter.replace("\\", "")
        if not delimiter:
            raise _Unsupported
        self.heredocs.append((delimiter, strip))
        return position

    def _skip_heredocs(self, index: int) -> int:
        source = self.source
        pending, self.heredocs = self.heredocs, []
        for delimiter, strip in pending:
            while True:
                if index >= len(source):
                    raise _Unsupported
                end = source.find("\n", index)
                if end < 0:
                    end = len(source)
                text = source[index:end].rstrip("\r")
                if strip:
                    text = text.lstrip("\t")
                index = end + 1
                self.line += 1
                if text == delimiter:
                    break
        return index

    def _quoted(self, index: int) -> int:
        source = self.source
        char = source[index]
        if char == "'":
            end = source.find("'", index + 1)
            if end < 0:
                raise _Unsupported
            return end + 1
        if char == '"':
            return self._double(index)
        if char == "`":
            return self._backtick(index)
        return self._dollar(index)

    def _double(self, index: int) -> int:
        source = self.source
        position = index + 1
        while position < len(source):
            char = source[position]
            if char == "\\":
                position += 2
            elif char == '"':
                return position + 1
            elif char == "$":
                position = self._dollar(position)
            elif char == "`":
                position = self._backtick(position)
            else:
                position += 1
        raise _Unsupported

    def _backtick(self, index: int) -> int:
        source = self.source
        position = index + 1
        while position < len(source):
            if _heredoc_at(source, position):
                raise _Unsupported
            if source[position] == "\\":
                position += 2
            elif source[position] == "`":
                return position + 1
            else:
                position += 1
        raise _Unsupported

    def _dollar(self, index: int) -> int:
        source = self.source
        if source.startswith("$'", index):
            position = index + 2
            while position < len(source):
                if source[position] == "\\":
                    position += 2
                elif source[position] == "'":
                    return position + 1
                else:
                    position += 1
            raise _Unsupported
        if source.startswith('$"', index):
            return self._double(index + 1)
        if source.startswith("$(", index):
            return self._balanced(index + 1)
        if source.startswith("${", index):
            return self._braced(index + 1)
        return index + 1

    def _balanced(self, index: int) -> int:
        command = not self.source.startswith("((", index)
        return self._nested(index, "(", ")", comments=True, command=command)

    def _braced(self, index: int) -> int:
        return self._nested(index, "{", "}", comments=False, command=False)

    def _nested(
        self, index: int, opening: str, closing: str, *, comments: bool, command: bool
    ) -> int:
        source = self.source
        depth = 0
        position = index
        while position < len(source):
            char = source[position]
            if char == "\\":
                position += 2
                continue
            if command and _heredoc_at(source, position):
                raise _Unsupported
            if comments and char == "#" and source[position - 1] in " \t\n(":
                end = source.find("\n", position)
                if end < 0:
                    raise _Unsupported
                position = end
                continue
            if char in "'\"`" or (
                char == "$"
                and source[position + 1 : position + 2] in ("(", "{", "'", '"')
            ):
                position = self._quoted(position)
                continue
            if char == opening:
                depth += 1
            elif char == closing:
                depth -= 1
                if depth == 0:
                    return position + 1
            position += 1
        raise _Unsupported

    def _condition(self, index: int) -> int:
        source = self.source
        position = index
        while position < len(source):
            char = source[position]
            if (
                source.startswith("]]", position)
                and source[position - 1] in " \t\n"
                and (position + 2 >= len(source) or source[position + 2] in _WORD_END)
            ):
                return position + 2
            if char == "\\":
                position += 2
            elif char in "'\"`$":
                position = self._quoted(position)
            else:
                position += 1
        raise _Unsupported

    def _advance(self, start: int, end: int) -> int:
        self.line += self.source.count("\n", start, end)
        return end

    def _start(self, index: int) -> None:
        if self.word_start is None:
            self.word_start = index
            self.word_line = self.line

    def _word_text(self, index: int) -> str:
        if self.word_start is None:
            return ""
        return self.source[self.word_start : index]

    def _finish(self, index: int) -> None:
        if self.word_start is None:
            return
        text = self.source[self.word_start : index]
        line = self.word_line
        self.word_start = None
        if text == "[[":
            end = self._condition(index)
            text = self.source[index - 2 : end]
            self.tokens.append(_Token("word", text, line))
            self.skip_to = end
            return
        self.tokens.append(_Token("word", text, line))

    def _op(self, index: int, operator: str) -> int:
        self._finish(index)
        self._emit("op", operator)
        return index + len(operator)

    def _emit(self, kind: str, text: str) -> None:
        self.tokens.append(_Token(kind, text, self.line))


def _tokens(source: str) -> list[_Token]:
    if len(source) > MAX_SOURCE_CHARACTERS:
        raise _Unsupported
    return _Lexer(source).run()


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.position = 0
        self.depth = 0
        self.last_line = 1

    def program(self) -> list:
        items = self.statements(frozenset())
        if self.peek() is not None:
            raise _Unsupported
        return items

    def peek(self, offset: int = 0) -> _Token | None:
        position = self.position + offset
        if position < len(self.tokens):
            return self.tokens[position]
        return None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise _Unsupported
        self.position += 1
        self.last_line = token.line + token.text.count("\n")
        return token

    def is_word(self, text: str, offset: int = 0) -> bool:
        token = self.peek(offset)
        return token is not None and token.kind == "word" and token.text == text

    def is_op(self, texts, offset: int = 0) -> bool:
        token = self.peek(offset)
        return token is not None and token.kind == "op" and token.text in texts

    def expect_word(self, text: str) -> None:
        token = self.take()
        if token.kind != "word" or token.text != text:
            raise _Unsupported

    def expect_op(self, text: str) -> None:
        token = self.take()
        if token.kind != "op" or token.text != text:
            raise _Unsupported

    def skip_newlines(self) -> None:
        while self.is_op({"\n"}):
            self.take()

    def statements(self, stops: frozenset) -> list:
        items = []
        while True:
            while self.is_op({";", "\n"}):
                self.take()
            token = self.peek()
            if token is None:
                return items
            if token.kind == "op" and token.text in _LIST_CLOSERS:
                return items
            if token.kind == "word" and token.text in stops:
                return items
            item = self.and_or()
            if self.is_op(_LIST_SEPARATORS):
                item.background = self.take().text == "&"
            items.append(item)

    def and_or(self) -> _AndOr:
        token = self.peek()
        if token is None:
            raise _Unsupported
        pipelines = [self.pipeline()]
        operators = []
        while self.is_op({"&&", "||"}):
            operators.append(self.take().text)
            self.skip_newlines()
            pipelines.append(self.pipeline())
        return _AndOr(pipelines, operators, token.line)

    def pipeline(self) -> _Pipeline:
        negated = False
        if self.is_word("!"):
            self.take()
            negated = True
        commands = [self.command()]
        while self.is_op({"|", "|&"}):
            self.take()
            self.skip_newlines()
            commands.append(self.command())
        return _Pipeline(commands, negated)

    def command(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise _Unsupported
        try:
            return self._command()
        finally:
            self.depth -= 1

    def _command(self):
        token = self.peek()
        if token is None:
            raise _Unsupported
        if token.kind == "op":
            if token.text != "(":
                raise _Unsupported
            self.take()
            body = self.statements(frozenset())
            self.expect_op(")")
            return self.trailing(_Group("subshell", body, token.line))
        builders = {
            "if": self.if_clause,
            "while": self.loop,
            "until": self.loop,
            "for": self.for_loop,
            "select": self.for_loop,
            "case": self.case,
            "{": self.brace,
            "function": self.function,
        }
        builder = builders.get(token.text)
        if builder is not None:
            return self.trailing(builder())
        if (
            _NAME_RE.fullmatch(token.text)
            and self.is_op({"("}, 1)
            and self.is_op({")"}, 2)
        ):
            return self.function()
        return self.simple()

    def trailing(self, node):
        while self.peek() is not None and self.peek().kind == "word":
            self.take()
        return node

    def simple(self) -> _Simple:
        line = self.peek().line
        words = []
        while self.peek() is not None and self.peek().kind == "word":
            words.append(self.take().text)
        if not words:
            raise _Unsupported
        return _Simple(words, line)

    def if_clause(self) -> _If:
        line = self.take().line
        clauses = []
        condition = self.statements(frozenset({"then"}))
        self.expect_word("then")
        body = self.statements(frozenset({"elif", "else", "fi"}))
        clauses.append((condition, body))
        while self.is_word("elif"):
            self.take()
            condition = self.statements(frozenset({"then"}))
            self.expect_word("then")
            body = self.statements(frozenset({"elif", "else", "fi"}))
            clauses.append((condition, body))
        orelse = None
        if self.is_word("else"):
            self.take()
            orelse = self.statements(frozenset({"fi"}))
        self.expect_word("fi")
        return _If(clauses, orelse, line)

    def loop(self) -> _Compound:
        line = self.take().line
        condition = self.statements(frozenset({"do"}))
        self.expect_word("do")
        body = self.statements(frozenset({"done"}))
        self.expect_word("done")
        return _Compound([condition, body], line)

    def for_loop(self) -> _Compound:
        line = self.take().line
        if self.take().kind != "word":
            raise _Unsupported
        if self.is_word("in"):
            self.take()
            while self.peek() is not None and self.peek().kind == "word":
                self.take()
        if self.is_op({";", "\n"}):
            self.take()
        self.skip_newlines()
        self.expect_word("do")
        body = self.statements(frozenset({"done"}))
        self.expect_word("done")
        return _Compound([body], line)

    def case(self) -> _Compound:
        line = self.take().line
        if self.take().kind != "word":
            raise _Unsupported
        self.skip_newlines()
        self.expect_word("in")
        bodies = []
        while True:
            self.skip_newlines()
            if self.is_word("esac"):
                self.take()
                return _Compound(bodies, line)
            if self.is_op({"("}):
                self.take()
            if self.take().kind != "word":
                raise _Unsupported
            while self.is_op({"|"}):
                self.take()
                if self.take().kind != "word":
                    raise _Unsupported
            self.expect_op(")")
            bodies.append(self.statements(frozenset({"esac"})))
            if self.is_op(_CASE_ENDS):
                self.take()

    def brace(self) -> _Group:
        line = self.take().line
        body = self.statements(frozenset({"}"}))
        self.expect_word("}")
        return _Group("brace", body, line)

    def function(self) -> _Function:
        token = self.take()
        line = token.line
        name = token.text
        if name == "function":
            name = self.take().text
        if self.is_op({"("}):
            self.take()
            self.expect_op(")")
        self.skip_newlines()
        body = self.command()
        return _Function(name, body, line, self.last_line)


def _children(node):
    if isinstance(node, _AndOr):
        for pipeline in node.pipelines:
            yield from pipeline.commands
    elif isinstance(node, _Group):
        yield from node.body
    elif isinstance(node, _If):
        for condition, body in node.clauses:
            yield from condition
            yield from body
        if node.orelse is not None:
            yield from node.orelse
    elif isinstance(node, _Compound):
        for part in node.parts:
            yield from part
    elif isinstance(node, _Function):
        yield node.body


def _walk(nodes):
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        stack.extend(_children(node))


def _outer_functions(items) -> list[_Function]:
    found = []
    stack = list(items)
    while stack:
        node = stack.pop()
        if isinstance(node, _Function):
            found.append(node)
            continue
        stack.extend(_children(node))
    return found


def _single_command(item: _AndOr):
    if item.operators or item.background or len(item.pipelines[0].commands) != 1:
        return None
    return item.pipelines[0].commands[0]


def _heredoc_at(source: str, position: int) -> bool:
    return source.startswith("<<", position) and not source.startswith("<<<", position)


def _contains_return(node) -> bool:
    return any(
        isinstance(child, _Simple) and child.words[0] == "return"
        for child in _walk([node])
    )


class _ExitOracle:
    """Top-level functions that always exit, judged once each in source order.

    A helper may only rely on helpers defined before it, so each answer is
    independent of where a later gate sits.
    """

    def __init__(self, program, names: Counter) -> None:
        self.functions = {}
        for item in program:
            command = _single_command(item)
            if isinstance(command, _Function) and names[command.name] == 1:
                self.functions[command.name] = command
        self.known: dict[str, bool] = {}

    def exits(self, name: str, before_line: int) -> bool:
        function = self.functions.get(name)
        if function is None or function.end >= before_line:
            return False
        if name not in self.known:
            self.known[name] = False
            body = function.body
            self.known[name] = (
                isinstance(body, _Group)
                and body.kind == "brace"
                and _statements_exit(body.body, self, function.line)
            )
        return self.known[name]


def _exits(command, oracle: _ExitOracle, before_line: int) -> bool:
    if isinstance(command, _Simple):
        return command.words[0] == "exit" or oracle.exits(command.words[0], before_line)
    if isinstance(command, _Group) and command.kind == "brace":
        return _statements_exit(command.body, oracle, before_line)
    return False


def _statements_exit(items, oracle: _ExitOracle, before_line: int) -> bool:
    for item in items:
        if _contains_return(item):
            return False
        command = _single_command(item)
        if (
            command is not None
            and not item.pipelines[0].negated
            and _exits(command, oracle, before_line)
        ):
            return True
    return False


def _flip(polarity: str | None) -> str | None:
    if polarity == "root":
        return "nonroot"
    if polarity == "nonroot":
        return "root"
    return None


def _is_identity(word: str, variables: bool) -> bool:
    if _COMMAND_IDENTITY_RE.fullmatch(word):
        return True
    return variables and _VARIABLE_IDENTITY_RE.fullmatch(word) is not None


def _comparison_polarity(operands: list[str], variables: bool) -> str | None:
    negate = bool(operands) and operands[0] == "!"
    if negate:
        operands = operands[1:]
    if len(operands) != 3:
        return None
    left, operator, right = operands
    identity = (_is_identity(left, variables) and _ZERO_RE.fullmatch(right)) or (
        _is_identity(right, variables) and _ZERO_RE.fullmatch(left)
    )
    if not identity:
        return None
    polarity = None
    if operator in ("-eq", "=", "=="):
        polarity = "root"
    elif operator in ("-ne", "!="):
        polarity = "nonroot"
    if negate:
        return _flip(polarity)
    return polarity


def _test_polarity(words: list[str], variables: bool) -> str | None:
    if len(words) == 1 and words[0].startswith("((") and words[0].endswith("))"):
        match = _ARITHMETIC_RE.fullmatch(words[0][2:-2])
        if match is None or not variables:
            return None
        if match.group("op") == "==":
            return "root"
        return "nonroot"
    if len(words) == 1 and words[0].startswith("[[") and words[0].endswith("]]"):
        try:
            operands = shlex.split(words[0][2:-2], posix=False)
        except ValueError:
            return None
        return _comparison_polarity(operands, variables)
    if len(words) >= 2 and words[0] == "[" and words[-1] == "]":
        return _comparison_polarity(words[1:-1], variables)
    if words and words[0] == "test":
        return _comparison_polarity(words[1:], variables)
    return None


def _condition_polarity(statements, variables: bool) -> str | None:
    if len(statements) != 1:
        return None
    command = _single_command(statements[0])
    if not isinstance(command, _Simple):
        return None
    polarity = _test_polarity(command.words, variables)
    if statements[0].pipelines[0].negated:
        return _flip(polarity)
    return polarity


def _gate_shape(item: _AndOr, variables: bool):
    """The command that must exit when the script is not root, or None."""
    if item.background:
        return None
    if len(item.pipelines) == 2:
        first, second = item.pipelines
        if len(first.commands) != 1 or len(second.commands) != 1 or second.negated:
            return None
        test = first.commands[0]
        if not isinstance(test, _Simple):
            return None
        polarity = _test_polarity(test.words, variables)
        if first.negated:
            polarity = _flip(polarity)
        wanted = {"||": "root", "&&": "nonroot"}[item.operators[0]]
        if polarity != wanted:
            return None
        return second.commands[0]
    command = _single_command(item)
    if not isinstance(command, _If) or item.pipelines[0].negated:
        return None
    condition, body = command.clauses[0]
    if _condition_polarity(condition, variables) != "nonroot":
        return None
    return _Group("brace", body, item.line)


def _effective_words(words: list[str]) -> list[str]:
    words = list(words)
    while words and words[0] in _PREFIX_COMMANDS:
        words = words[1:]
        while words and words[0].startswith("-") and words[0] != "--":
            words = words[1:]
    return words


def _rebinds_positionals(words: list[str]) -> bool:
    words = _effective_words(words)
    if not words:
        return False
    if words[0] == "eval":
        arguments = " ".join(words[1:])
        if "$" in arguments or "`" in arguments:
            return True
        try:
            unquoted = " ".join(shlex.split(arguments))
        except ValueError:
            return True
        return _EVAL_SET_RE.search(unquoted) is not None
    if words[0] != "set":
        return False
    skip = False
    for word in words[1:]:
        if skip:
            skip = False
            continue
        if word == "--":
            return True
        if word.startswith(("-", "+")):
            skip = "o" in word[1:]
            continue
        return True
    return False


def _variable_identity_allowed(source: str) -> bool:
    match = _SHEBANG_RE.match(source)
    if match is None:
        return False
    command = match.group("command").rsplit("/", 1)[-1]
    if command == "env":
        arguments = match.group("arguments").split()
        while arguments and (arguments[0].startswith("-") or "=" in arguments[0]):
            arguments = arguments[1:]
        if not arguments:
            return False
        command = arguments[0].rsplit("/", 1)[-1]
    return command in _EUID_SHELLS


def _root_gate_line(program, nodes, variables: bool) -> int | None:
    simple = [node for node in nodes if isinstance(node, _Simple)]
    names = Counter(node.name for node in nodes if isinstance(node, _Function))
    if set(names) & _OVERRIDDEN_BUILTINS:
        return None
    if any(node.words[0] in _ALIASING_COMMANDS for node in simple):
        return None
    reject_lines = [
        node.line
        for node in simple
        if (_effective_words(node.words) or [""])[0] in _PRE_GATE_REJECTS
    ]
    first_reject = min(reject_lines, default=None)
    oracle = _ExitOracle(program, names)
    for item in program:
        if first_reject is not None and first_reject <= item.line:
            return None
        action = _gate_shape(item, variables)
        if action is not None and _exits(action, oracle, item.line):
            return item.line
    return None


def shell_structure(source: str) -> ShellStructure | None:
    try:
        program = _Parser(_tokens(source)).program()
    except (_Unsupported, RecursionError, IndexError):
        return None
    nodes = list(_walk(program))
    spans = tuple(
        sorted((function.line, function.end) for function in _outer_functions(program))
    )
    return ShellStructure(
        functions=spans,
        root_gate_line=_root_gate_line(
            program, nodes, _variable_identity_allowed(source)
        ),
        positionals_rebound=any(
            isinstance(node, _Simple) and _rebinds_positionals(node.words)
            for node in nodes
        ),
    )
