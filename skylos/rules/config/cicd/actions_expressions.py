"""Reader for GitHub Actions ``${{ }}`` expressions.

Follows the grammar of GitHub's expression language as GitHub documents it
(https://docs.github.com/en/actions/reference/workflows-and-actions/expressions):
references with member, wildcard and subscript steps, the documented
functions with their argument counts, ``!``, ``&&``, ``||``, equality and
ordering."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Union

DEPTH_LIMIT = 50

_SCANNER = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<text>'(?:[^']|'')*')
  | (?P<open_text>')
  | (?P<operator>==|!=|<=|>=|&&|\|\||[<>!(),\[\]*.])
  | (?P<word>[A-Za-z_][A-Za-z0-9_-]*)
  | (?P<number>[+-]?(?:0x[0-9A-Fa-f]+|0o[0-7]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?))
  | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)
_ENDS_NUMBER = frozenset(" \t\r\n\f\v()[],!<>=&|")
_CONSTANTS = {"true": True, "false": False, "null": None}
_ARITY = {
    "contains": (2, 2),
    "startswith": (2, 2),
    "endswith": (2, 2),
    "format": (1, None),
    "join": (1, 2),
    "tojson": (1, 1),
    "fromjson": (1, 1),
    "hashfiles": (1, None),
    "case": (3, None),
    "success": (0, 0),
    "always": (0, 0),
    "cancelled": (0, 0),
    "failure": (0, 0),
}
_PASSES_VALUE = frozenset({"tojson", "fromjson", "format", "join"})
_ACCESSIBLE_BEFORE_DOT = frozenset({"word", ")", "]", "*"})


class ExpressionError(ValueError):
    pass


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    text: str


@dataclass
class Value:
    span: Span
    value: Union[str, float, bool, None]


@dataclass
class Wildcard:
    span: Span


@dataclass
class Field:
    span: Span
    name: str


@dataclass
class Subscript:
    span: Span
    key: "Node"


@dataclass
class Invoke:
    span: Span
    name: str
    arguments: list["Node"] = field(default_factory=list)


@dataclass
class Logical:
    span: Span
    operator: str
    left: "Node"
    right: "Node"


@dataclass
class Comparison:
    span: Span
    operator: str
    left: "Node"
    right: "Node"


@dataclass
class Negation:
    span: Span
    operand: "Node"


@dataclass
class Reference:
    span: Span
    base: "Node"
    steps: list[Union[Field, Wildcard, Subscript]] = field(default_factory=list)

    def names(self) -> list[str | None]:
        found: list[str | None] = []
        if isinstance(self.base, Field):
            found.append(self.base.name.lower())
        else:
            found.append(None)
        for step in self.steps:
            found.append(_step_name(step))
        return found

    def key(self) -> str | None:
        if not isinstance(self.base, Field):
            return None
        segments = [self.base.name]
        for step in self.steps:
            if isinstance(step, Field):
                segments.append(step.name)
            elif isinstance(step, Subscript) and _literal_text(step.key) is not None:
                segments.append(_literal_text(step.key))
            else:
                segments.append("*")
        return ".".join(segments).lower()

    def under(self, prefix: str) -> bool:
        return _covers(prefix, self, exact=False)

    def is_exactly(self, pattern: str) -> bool:
        return _covers(pattern, self, exact=True)

    def only_member(self) -> str | None:
        if not isinstance(self.base, Field) or len(self.steps) != 1:
            return None
        step = self.steps[0]
        if isinstance(step, Field):
            return step.name
        if isinstance(step, Subscript):
            return _literal_text(step.key)
        return None


Node = Union[Value, Wildcard, Field, Subscript, Invoke, Logical, Comparison, Negation, Reference]


def _literal_text(node: Node) -> str | None:
    if isinstance(node, Value) and isinstance(node.value, str):
        return node.value
    return None


def _step_name(step: Union[Field, Wildcard, Subscript]) -> str | None:
    if isinstance(step, Field):
        return step.name.lower()
    if isinstance(step, Subscript):
        text = _literal_text(step.key)
        if text is not None:
            return text.lower()
    return None


def _covers(pattern: str, reference: Reference, *, exact: bool) -> bool:
    wanted = pattern.lower().split(".")
    names = reference.names()
    if len(wanted) > len(names) or (exact and len(wanted) != len(names)):
        return False
    for expected, actual in zip(wanted, names):
        if expected != "*" and expected != actual:
            return False
    return True


def _to_number(text: str) -> float:
    unsigned = text.lstrip("+-")
    negative = text.startswith("-")
    if unsigned.startswith(("0x", "0o")):
        base = 8
        if unsigned[1] == "x":
            base = 16
        magnitude = int(unsigned[2:], base)
        if magnitude >= 2**32:
            raise ExpressionError(f"number out of range: {text}")
        if magnitude >= 2**31:
            magnitude -= 2**32
        if negative:
            return float(-magnitude)
        return float(magnitude)
    number = float(text)
    if number in (float("inf"), float("-inf")):
        raise ExpressionError(f"number out of range: {text}")
    return number


@dataclass(frozen=True)
class _Lexeme:
    kind: str
    start: int
    end: int
    value: Union[str, float, bool, None] = None


def _scan(source: str) -> list[_Lexeme]:
    lexemes: list[_Lexeme] = []
    position = 0
    while position < len(source):
        match = _SCANNER.match(source, position)
        kind = match.lastgroup
        start, end = match.span()
        position = end
        if kind == "space":
            continue
        previous = None
        if lexemes:
            previous = lexemes[-1].kind
        if kind == "operator" and match.group() == "." and previous not in _ACCESSIBLE_BEFORE_DOT:
            number = _SCANNER.match(source, start + 1)
            if number is None or number.lastgroup != "number" or source[start + 1] == ".":
                raise ExpressionError(f"unexpected '.' at {start}")
            kind = "number"
            end = number.end()
            position = end
        if kind == "number":
            if end < len(source) and source[end] not in _ENDS_NUMBER and source[end] != ".":
                raise ExpressionError(f"malformed number at {start}")
            lexemes.append(_Lexeme("number", start, end, _to_number(source[start:end])))
        elif kind == "text":
            lexemes.append(_Lexeme("text", start, end, source[start + 1 : end - 1].replace("''", "'")))
        elif kind == "word":
            lexemes.append(_word(source[start:end], start, end, previous))
        elif kind == "operator":
            lexemes.append(_Lexeme(match.group(), start, end))
        else:
            raise ExpressionError(f"unexpected {source[start:end]!r} at {start}")
    return lexemes


def _word(text: str, start: int, end: int, previous: str | None) -> _Lexeme:
    if previous != ".":
        if text in _CONSTANTS:
            return _Lexeme("constant", start, end, _CONSTANTS[text])
        if text == "Infinity":
            return _Lexeme("number", start, end, float("inf"))
        if text == "NaN":
            return _Lexeme("number", start, end, float("nan"))
    return _Lexeme("word", start, end, text)


class _Reader:
    def __init__(self, source: str) -> None:
        self.source = source
        self.lexemes = _scan(source)
        self.index = 0
        self.depth = 0

    def read(self) -> Node:
        if not self.lexemes:
            raise ExpressionError("empty expression")
        node = self._guarded(self._disjunction)
        if self.index != len(self.lexemes):
            raise ExpressionError("unexpected trailing input")
        return node

    def _guarded(self, rule):
        self.depth += 1
        if self.depth > DEPTH_LIMIT:
            raise ExpressionError("expression nested too deeply")
        try:
            return rule()
        finally:
            self.depth -= 1

    def _peek(self, *kinds: str) -> bool:
        return self.index < len(self.lexemes) and self.lexemes[self.index].kind in kinds

    def _advance(self) -> _Lexeme:
        if self.index >= len(self.lexemes):
            raise ExpressionError("unexpected end of expression")
        lexeme = self.lexemes[self.index]
        self.index += 1
        return lexeme

    def _require(self, kind: str) -> _Lexeme:
        if not self._peek(kind):
            raise ExpressionError(f"expected {kind!r}")
        return self._advance()

    def _span(self, start: int, end: int) -> Span:
        return Span(start, end, self.source[start:end].strip())

    def _chain(self, operand, operators, build) -> Node:
        left = operand()
        while self._peek(*operators):
            operator = self._advance().kind
            right = self._guarded(operand)
            left = build(self._span(left.span.start, right.span.end), operator, left, right)
        return left

    def _disjunction(self) -> Node:
        return self._chain(self._conjunction, ("||",), Logical)

    def _conjunction(self) -> Node:
        return self._chain(self._equality, ("&&",), Logical)

    def _equality(self) -> Node:
        return self._chain(self._relation, ("==", "!="), Comparison)

    def _relation(self) -> Node:
        return self._chain(self._negation, ("<", "<=", ">", ">="), Comparison)

    def _negation(self) -> Node:
        if not self._peek("!"):
            return self._access()
        bang = self._advance()
        operand = self._guarded(self._negation)
        return Negation(self._span(bang.start, operand.span.end), operand)

    def _access(self) -> Node:
        base, can_step = self._atom()
        if not can_step:
            return base
        steps: list[Union[Field, Wildcard, Subscript]] = []
        while self._peek(".", "["):
            if self._advance().kind == ".":
                steps.append(self._member())
            else:
                steps.append(self._subscript())
        if not steps and not isinstance(base, Field):
            return base
        end = base.span.end
        if steps:
            end = steps[-1].span.end
        return Reference(self._span(base.span.start, end), base, steps)

    def _member(self) -> Union[Field, Wildcard]:
        lexeme = self._advance()
        if lexeme.kind == "word":
            return Field(self._span(lexeme.start, lexeme.end), lexeme.value)
        if lexeme.kind == "*":
            return Wildcard(self._span(lexeme.start, lexeme.end))
        raise ExpressionError("expected a member name or '*' after '.'")

    def _subscript(self) -> Subscript:
        opening = self.lexemes[self.index - 1]
        if self._peek("*"):
            star = self._advance()
            key: Node = Wildcard(self._span(star.start, star.end))
        else:
            key = self._guarded(self._disjunction)
        closing = self._require("]")
        return Subscript(self._span(opening.start, closing.end), key)

    def _atom(self) -> tuple[Node, bool]:
        lexeme = self._advance()
        if lexeme.kind in ("number", "text", "constant"):
            return Value(self._span(lexeme.start, lexeme.end), lexeme.value), False
        if lexeme.kind == "(":
            inner = self._guarded(self._disjunction)
            closing = self._require(")")
            inner.span = self._span(lexeme.start, closing.end)
            return inner, True
        if lexeme.kind == "word" and self._peek("("):
            return self._invoke(lexeme), True
        if lexeme.kind == "word":
            return Field(self._span(lexeme.start, lexeme.end), lexeme.value), True
        raise ExpressionError(f"unexpected {lexeme.kind!r} at {lexeme.start}")

    def _invoke(self, name: _Lexeme) -> Invoke:
        self._require("(")
        arguments: list[Node] = []
        if not self._peek(")"):
            arguments.append(self._guarded(self._disjunction))
            while self._peek(","):
                self._advance()
                arguments.append(self._guarded(self._disjunction))
        closing = self._require(")")
        function = name.value.lower()
        if function not in _ARITY:
            raise ExpressionError(f"unknown function {name.value}")
        fewest, most = _ARITY[function]
        if len(arguments) < fewest or (most is not None and len(arguments) > most):
            raise ExpressionError(f"{name.value}() takes a different number of arguments")
        if function == "case" and len(arguments) % 2 == 0:
            raise ExpressionError("case() takes an odd number of arguments")
        return Invoke(self._span(name.start, closing.end), function, arguments)


def parse_expression(source: str) -> Node:
    return _Reader(source).read()


def parse_reference(source: str) -> Reference | None:
    try:
        node = parse_expression(source)
    except ExpressionError:
        return None
    if isinstance(node, Reference):
        return node
    return None


def flowing_references(node: Node) -> list[Reference]:
    found: list[Reference] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, Reference):
            found.append(current)
        elif isinstance(current, Logical) and current.operator == "||":
            pending.extend([current.right, current.left])
        elif isinstance(current, Logical):
            pending.append(current.right)
        elif isinstance(current, Invoke) and current.name in _PASSES_VALUE:
            pending.extend(reversed(current.arguments))
        elif isinstance(current, Invoke) and current.name == "case":
            pending.extend(reversed([*current.arguments[1::2], current.arguments[-1]]))
    return found


def invoke_inputs(reference: Reference) -> list[Reference]:
    if not isinstance(reference.base, Invoke):
        return []
    return [
        found
        for argument in reference.base.arguments
        for found in flowing_references(argument)
    ]


def template_spans(text: str) -> list[tuple[str, int, int]]:
    spans = []
    cursor = 0
    while True:
        opening = text.find("${{", cursor)
        if opening < 0:
            return spans
        quoted = False
        closing = -1
        for index in range(opening + 3, len(text)):
            char = text[index]
            if char == "'":
                quoted = not quoted
            elif char == "}" and not quoted and text[index - 1] == "}":
                closing = index
                break
        if closing < 0:
            return spans
        spans.append((text[opening + 3 : closing - 1], opening, closing + 1))
        cursor = closing + 1
