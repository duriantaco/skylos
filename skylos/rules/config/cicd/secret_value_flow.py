"""Bounded, static value-flow analysis for GitHub Actions secret expressions.

References used by a comparison do not expose their original string value.
Logical operators return operands, so their result needs separate analysis.
Nothing here evaluates workflow expressions or imports inspected code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


MAX_EXPRESSION_CHARS = 16_384
MAX_TOKENS = 2_048
MAX_DEPTH = 64
ALL_SECRETS = "*"
DYNAMIC_SECRET = "[dynamic]"

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUMBER = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)")
_PRECEDENCE = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, "<=": 4, ">": 4, ">=": 4}
_BOOLEAN_FUNCTION_ARITY = {
    "contains": 2,
    "startswith": 2,
    "endswith": 2,
    "success": 0,
    "always": 0,
    "cancelled": 0,
    "failure": 0,
}


class _UnsupportedExpression(ValueError):
    pass


@dataclass(frozen=True)
class _Value:
    secrets: frozenset[str] = frozenset()
    truth: bool | None = None
    string: str | None = None
    context: bool = False
    scalar: bool = False


def _tokens(expression):
    position = 0
    while position < len(expression):
        character = expression[position]
        if character.isspace():
            position += 1
            continue
        if character == "'":
            position += 1
            pieces = []
            closed = False
            while position < len(expression):
                character = expression[position]
                position += 1
                if character != "'":
                    pieces.append(character)
                    continue
                if position < len(expression) and expression[position] == "'":
                    pieces.append("'")
                    position += 1
                    continue
                closed = True
                break
            if closed:
                yield ("string", "".join(pieces))
            else:
                yield ("invalid", "unterminated string")
            continue
        match = _IDENTIFIER.match(expression, position)
        if match is not None:
            yield ("identifier", match.group())
            position = match.end()
            continue
        match = _NUMBER.match(expression, position)
        if match is not None:
            yield ("number", match.group())
            position = match.end()
            continue
        pair = expression[position : position + 2]
        if pair in _PRECEDENCE:
            yield ("operator", pair)
            position += 2
            continue
        if character in "!<>.[](),*":
            yield ("operator", character)
        else:
            yield ("invalid", character)
        position += 1


def _references(expression):
    """Conservative fallback, retaining references outside quoted literals."""
    names = set()
    previous = None
    tokens = iter(_tokens(expression))
    for token in tokens:
        if token == ("identifier", "secrets") or (
            token[0] == "identifier" and token[1].lower() == "secrets"
        ):
            if previous == ("operator", "."):
                previous = token
                continue
            following = next(tokens, None)
            if following == ("operator", "."):
                member = next(tokens, None)
                if member is not None and member[0] == "identifier":
                    names.add(member[1])
                else:
                    names.add(ALL_SECRETS)
                previous = member
                continue
            if following == ("operator", "["):
                member = next(tokens, None)
                closing = next(tokens, None)
                if (
                    member is not None
                    and member[0] == "string"
                    and closing == ("operator", "]")
                ):
                    names.add(member[1])
                else:
                    names.add(DYNAMIC_SECRET)
                previous = closing
                continue
            names.add(ALL_SECRETS)
            previous = following
            continue
        previous = token
    return names


class _Parser:
    def __init__(self, expression):
        self.tokens = []
        for token in _tokens(expression):
            if len(self.tokens) >= MAX_TOKENS:
                raise _UnsupportedExpression("token limit")
            self.tokens.append(token)
        self.position = 0

    def _peek(self, text=None):
        if self.position >= len(self.tokens):
            return False
        if text is None:
            return self.tokens[self.position]
        token = self.tokens[self.position]
        return token[0] == "operator" and token[1] == text

    def _take(self, text=None):
        token = self._peek()
        if token is False:
            raise _UnsupportedExpression("missing operand or delimiter")
        if text is not None and (token[0] != "operator" or token[1] != text):
            raise _UnsupportedExpression("missing operand or delimiter")
        self.position += 1
        return token

    def parse(self):
        value = self._expression(1, 0)
        if self.position != len(self.tokens):
            raise _UnsupportedExpression("unconsumed expression")
        return value.secrets

    def _expression(self, minimum, depth):
        if depth > MAX_DEPTH:
            raise _UnsupportedExpression("depth limit")
        left = self._primary(depth + 1)
        while self._peek() is not False:
            token = self._peek()
            if token[0] != "operator":
                break
            operator = token[1]
            precedence = _PRECEDENCE.get(operator, 0)
            if precedence < minimum:
                break
            self._take()
            right = self._expression(precedence + 1, depth + 1)
            if operator == "&&":
                if left.truth is False:
                    left = _Value(truth=False, scalar=True)
                elif left.truth is True:
                    left = right
                else:
                    # A falsy returned left operand is only '', 0, false or
                    # null, not the original nonempty secret contents.
                    truth = None
                    if right.truth is False:
                        truth = False
                    left = _Value(
                        right.secrets,
                        truth=truth,
                        context=right.context,
                        scalar=right.scalar,
                    )
            elif operator == "||":
                if left.truth is False:
                    left = right
                elif left.truth is not True:
                    left = _Value(
                        left.secrets | right.secrets,
                        scalar=left.scalar and right.scalar,
                    )
            else:
                left = _Value(scalar=True)
        return left

    def _primary(self, depth):
        if depth > MAX_DEPTH:
            raise _UnsupportedExpression("depth limit")
        if self._peek("!"):
            self._take()
            operand = self._primary(depth + 1)
            truth = None
            if operand.truth is not None:
                truth = not operand.truth
            return _Value(truth=truth, scalar=True)
        token = self._take()
        if token[1] == "(" and token[0] == "operator":
            value = self._expression(1, depth + 1)
            self._take(")")
        elif token[0] == "string":
            value = _Value(truth=bool(token[1]), string=token[1], scalar=True)
        elif token[0] == "number":
            try:
                if "x" in token[1].lower():
                    number = int(token[1], 16)
                else:
                    number = float(token[1])
            except ValueError as error:
                raise _UnsupportedExpression("invalid number") from error
            value = _Value(truth=bool(number), scalar=True)
        elif token[0] == "identifier":
            name = token[1].lower()
            if self._peek("("):
                value = self._function(name, depth + 1)
            elif name == "secrets":
                value = _Value(frozenset({ALL_SECRETS}), truth=True, context=True)
            elif name == "true":
                value = _Value(truth=True, scalar=True)
            elif name in {"false", "null"}:
                value = _Value(truth=False, scalar=True)
            else:
                value = _Value()
        else:
            raise _UnsupportedExpression("unsupported primary")
        while self._peek(".") or self._peek("["):
            if self._peek("."):
                self._take()
                member = self._take()
                if member[0] != "identifier" and member != ("operator", "*"):
                    raise _UnsupportedExpression("invalid property")
                if value.context:
                    names = frozenset({member[1]})
                    value = _Value(names, scalar=member[1] != "*")
                elif value.scalar:
                    # Runner Index.EvaluateCore returns null for ordinary
                    # primitive indexing and an empty array for a wildcard.
                    if member == ("operator", "*"):
                        value = _Value(truth=True)
                    else:
                        value = _Value(truth=False, scalar=True)
                else:
                    # A member access must not retain the base's literal
                    # string or truth value. Unknown collection contents may
                    # still carry secret values (for example fromJSON).
                    value = _Value(value.secrets)
            else:
                self._take()
                member = self._expression(1, depth + 1)
                self._take("]")
                if value.context:
                    name = DYNAMIC_SECRET
                    if member.string is not None:
                        name = member.string
                    value = _Value(frozenset({name}), scalar=True)
                elif value.scalar:
                    value = _Value(truth=False, scalar=True)
                else:
                    value = _Value(value.secrets)
        return value

    def _function(self, name, depth):
        self._take("(")
        arguments = []
        if not self._peek(")"):
            while True:
                arguments.append(self._expression(1, depth + 1))
                if not self._peek(","):
                    break
                self._take()
        self._take(")")
        if _BOOLEAN_FUNCTION_ARITY.get(name) == len(arguments):
            truth = None
            if name == "always":
                truth = True
            return _Value(truth=truth, scalar=True)
        names = set()
        for argument in arguments:
            names.update(argument.secrets)
        # Unsupported functions retain every secret argument. Known string
        # producers such as format, toJSON, fromJSON and join do so as well.
        scalar = False
        if name in {"format", "tojson", "join"}:
            scalar = True
        return _Value(frozenset(names), scalar=scalar)


def _expressions(template):
    position = 0
    while True:
        start = template.find("${{", position)
        if start < 0:
            return
        position = start + 3
        content_start = position
        quoted = False
        while position < len(template):
            if template[position] == "'":
                if quoted and template[position : position + 2] == "''":
                    position += 2
                    continue
                quoted = not quoted
            elif not quoted and template[position : position + 2] == "}}":
                yield template[content_start:position], True
                position += 2
                break
            position += 1
        else:
            # Malformed delimiters cannot establish a safe expression.
            yield template[content_start:], False
            return


def secret_value_names(template: str) -> list[str]:
    """Return secrets whose contents may reach a scalar's rendered value.

    '*' denotes the whole context; '[dynamic]' denotes an unresolved index.
    Unsupported syntax or parser limits retain quote-aware secret references.
    """
    names = set()
    for expression, complete in _expressions(template):
        if not complete or len(expression) > MAX_EXPRESSION_CHARS:
            names.update(_references(expression))
            continue
        try:
            names.update(_Parser(expression).parse())
        except (ValueError, RecursionError):
            names.update(_references(expression))
    return sorted(names)
