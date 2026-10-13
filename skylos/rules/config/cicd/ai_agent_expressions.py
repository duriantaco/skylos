"""Abstract evaluation of GitHub Actions ``if:`` expressions for actor gates.

The AI-agent workflow rules (SKY-D350 to SKY-D354) need one question answered
for each untrusted event: can this job or step run when the account that
triggered the event lacks write access to the repository? The evaluator below
answers it without running anything. Every atom is either known for the event
(``github.event_name``, fields that are null for that event), a *gate* (an
``author_association`` of the triggering account, an exact actor login, a
same-repository pull request check, a gated ``needs`` job), or unknown.

Results are pairs ``(may_be_true, may_be_false)``. Under ``untrusted=True`` a
gate atom is false; under ``untrusted=False`` it may be either. Anything the
parser does not understand is unknown, so it never counts as a gate.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# author_association values that require repository membership.
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
UNTRUSTED_ASSOCIATIONS = (
    "NONE",
    "CONTRIBUTOR",
    "FIRST_TIMER",
    "FIRST_TIME_CONTRIBUTOR",
    "MANNEQUIN",
)
# Upstream events whose runs only accounts with write access can start.
TRUSTED_UPSTREAM_EVENTS = frozenset(
    {"push", "schedule", "workflow_dispatch", "release", "merge_group", "create"}
)

# Payload objects that exist for each untrusted event. A known object that is
# missing for an event is null there (for example github.event.comment on an
# `issues` event).
KNOWN_ENTITIES = frozenset(
    {"issue", "comment", "pull_request", "review", "discussion", "workflow_run"}
)
EVENT_ENTITIES: dict[str, frozenset[str]] = {
    "issues": frozenset({"issue"}),
    "issue_comment": frozenset({"issue", "comment"}),
    "pull_request_target": frozenset({"pull_request"}),
    "pull_request_review": frozenset({"pull_request", "review"}),
    "pull_request_review_comment": frozenset({"pull_request", "comment"}),
    "discussion": frozenset({"discussion"}),
    "discussion_comment": frozenset({"discussion", "comment"}),
    "workflow_run": frozenset({"workflow_run"}),
}
# The payload object written by the account that triggered the event.
ACTOR_ENTITY: dict[str, str] = {
    "issues": "issue",
    "issue_comment": "comment",
    "pull_request_target": "pull_request",
    "pull_request_review": "review",
    "pull_request_review_comment": "comment",
    "discussion": "discussion",
    "discussion_comment": "comment",
    "workflow_run": "workflow_run",
}

_ACTOR_PATHS = frozenset(
    {
        ("github", "actor"),
        ("github", "actor_id"),
        ("github", "triggering_actor"),
        ("github", "event", "sender", "login"),
        ("github", "event", "sender", "id"),
    }
)
_STATUS_OVERRIDES = frozenset({"always", "failure", "cancelled"})
# Values a comparison is about; the other side is what they are compared to.
_SUBJECT_KINDS = frozenset(
    {"null", "actor", "headrepo", "fork", "wr_event", "needs", "private", "visibility"}
)
_MAX_TOKENS = 2_000
_MAX_DEPTH = 64

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<str>'(?:[^']|'')*')"
    r"|(?P<num>(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))"
    r"|(?P<op>==|!=|<=|>=|&&|\|\||[<>!().,\[\]*])"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*)"
    r")"
)
_WRAPPED_RE = re.compile(r"\$\{\{(?P<body>.*)\}\}", re.DOTALL)

MAY_BE_EITHER = (True, True)
TRUE = (True, False)
FALSE = (False, True)


class _ParseError(Exception):
    pass


def _tokenize(text: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None or match.end() == pos:
            raise _ParseError(text[pos:])
        pos = match.end()
        if match.group("str") is not None:
            tokens.append(("lit", match.group("str")[1:-1].replace("''", "'")))
        elif match.group("num") is not None:
            raw = match.group("num")
            tokens.append(("lit", float(int(raw, 16)) if raw.lower().startswith("0x") else float(raw)))
        elif match.group("op") is not None:
            tokens.append(("op", match.group("op")))
        else:
            tokens.append(("ident", match.group("ident")))
        if len(tokens) > _MAX_TOKENS:
            raise _ParseError("too many tokens")
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, Any]]):
        self.tokens = tokens
        self.pos = 0
        self.depth = 0

    def _peek(self) -> tuple[str, Any] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _is_op(self, *ops: str) -> bool:
        token = self._peek()
        return token is not None and token[0] == "op" and token[1] in ops

    def _take(self) -> tuple[str, Any]:
        token = self._peek()
        if token is None:
            raise _ParseError("unexpected end")
        self.pos += 1
        return token

    def _expect(self, op: str) -> None:
        token = self._take()
        if token != ("op", op):
            raise _ParseError(f"expected {op}")

    def parse(self) -> tuple:
        node = self._or()
        if self._peek() is not None:
            raise _ParseError("trailing tokens")
        return node

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _ParseError("expression too deep")

    def _or(self) -> tuple:
        self._enter()
        node = self._and()
        while self._is_op("||"):
            self._take()
            node = ("or", node, self._and())
        self.depth -= 1
        return node

    def _and(self) -> tuple:
        node = self._equality()
        while self._is_op("&&"):
            self._take()
            node = ("and", node, self._equality())
        return node

    def _equality(self) -> tuple:
        node = self._comparison()
        while self._is_op("==", "!="):
            op = self._take()[1]
            node = ("cmp", op, node, self._comparison())
        return node

    def _comparison(self) -> tuple:
        node = self._unary()
        while self._is_op("<", "<=", ">", ">="):
            op = self._take()[1]
            node = ("cmp", op, node, self._unary())
        return node

    def _unary(self) -> tuple:
        if self._is_op("!"):
            self._take()
            self._enter()
            node = ("not", self._unary())
            self.depth -= 1
            return node
        return self._postfix()

    def _postfix(self) -> tuple:
        node = self._primary()
        while True:
            if self._is_op("."):
                self._take()
                token = self._take()
                if token[0] == "ident":
                    part = token[1].lower()
                elif token == ("op", "*"):
                    part = "*"
                else:
                    raise _ParseError("bad property")
                node = ("path", node[1] + (part,)) if node[0] == "path" else ("dyn",)
            elif self._is_op("["):
                self._take()
                index = self._or()
                self._expect("]")
                if node[0] == "path" and index[0] == "lit" and isinstance(index[1], str):
                    node = ("path", node[1] + (index[1].lower(),))
                elif node[0] == "path" and index[0] == "lit":
                    node = ("path", node[1] + (str(index[1]),))
                else:
                    node = ("dyn",)
            else:
                return node

    def _primary(self) -> tuple:
        token = self._take()
        if token[0] == "lit":
            return ("lit", token[1])
        if token == ("op", "("):
            node = self._or()
            self._expect(")")
            return node
        if token[0] != "ident":
            raise _ParseError("unexpected token")
        name = token[1]
        lowered = name.lower()
        if lowered == "true":
            return ("lit", True)
        if lowered == "false":
            return ("lit", False)
        if lowered == "null":
            return ("lit", None)
        if self._is_op("("):
            self._take()
            args: list[tuple] = []
            if not self._is_op(")"):
                args.append(self._or())
                while self._is_op(","):
                    self._take()
                    args.append(self._or())
            self._expect(")")
            return ("call", lowered, tuple(args))
        return ("path", (lowered,))


def condition_source(value: Any) -> str | None:
    """The expression text of an ``if:`` value, or None when it is absent.

    A value with text around or between ``${{ }}`` blocks is a string, which
    GitHub treats as always true, so it is returned as a truthy literal.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return "true" if value else "false"
    if not isinstance(value, str):
        return "'opaque'"
    text = value.strip()
    if "${{" in text:
        match = _WRAPPED_RE.fullmatch(text)
        if match is None or "${{" in match.group("body") or "}}" in match.group("body"):
            return "'interpolated string'"
        return match.group("body")
    return text


def parse_condition(value: Any) -> tuple | None:
    """Parse an ``if:`` value; None when absent or unparseable."""
    source = condition_source(value)
    if source is None or not source.strip():
        return None
    try:
        return _Parser(_tokenize(source)).parse()
    except (_ParseError, ValueError, RecursionError):
        return ("unparsed",)


def has_status_override(node: tuple | None) -> bool:
    """Whether a job condition can run after a needed job was skipped."""
    if node is None:
        return False
    stack = [node]
    while stack:
        current = stack.pop()
        if current[0] == "call" and current[1] in _STATUS_OVERRIDES:
            return True
        for child in current[1:]:
            if isinstance(child, tuple) and child and isinstance(child[0], str):
                stack.append(child)
            elif isinstance(child, tuple):
                stack.extend(c for c in child if isinstance(c, tuple))
    return False


def _never(_job: str) -> bool:
    return False


@dataclass(frozen=True)
class EvalContext:
    event: str
    untrusted: bool
    # Whether job <id> cannot have run (skipped or blocked) for this event and
    # actor assumption.
    needs_blocked: Callable[[str], bool]
    # Whether job <id> chooses its outputs by event type (a dispatcher job).
    routes_by_event: Callable[[str], bool] = _never


def _gate(ctx: EvalContext) -> tuple[bool, bool]:
    return FALSE if ctx.untrusted else MAY_BE_EITHER


def _negated_gate(ctx: EvalContext) -> tuple[bool, bool]:
    return TRUE if ctx.untrusted else MAY_BE_EITHER


def _path_value(parts: tuple[str, ...], ctx: EvalContext) -> tuple:
    event = ctx.event
    if parts == ("github", "event_name"):
        return ("const", event)
    if parts in _ACTOR_PATHS:
        return ("actor", "login")
    if parts == ("github", "repository"):
        return ("repo",)
    if parts == ("github", "repository_owner"):
        return ("owner",)
    # Only a public repository has outsiders: a private or internal one is
    # visible to members alone, so these act as gates for untrusted accounts.
    if parts == ("github", "event", "repository", "private"):
        return ("private",)
    if parts == ("github", "event", "repository", "visibility"):
        return ("visibility",)
    if len(parts) >= 3 and parts[:2] == ("github", "event"):
        entity = parts[2]
        present = EVENT_ENTITIES.get(event, frozenset())
        if entity in KNOWN_ENTITIES and entity not in present:
            return ("null",)
        rest = parts[3:]
        if entity == ACTOR_ENTITY.get(event):
            if rest == ("author_association",):
                return ("actor", "assoc")
            if rest in {("user", "login"), ("user", "id")}:
                return ("actor", "login")
        if event == "pull_request_target" and entity == "pull_request":
            if rest == ("head", "repo", "full_name"):
                return ("headrepo",)
            if rest == ("head", "repo", "fork"):
                return ("fork",)
        if event == "workflow_run" and entity == "workflow_run":
            # GitHub fills workflow_run.pull_requests only for pull requests
            # whose head is in this repository, never for forks.
            if rest[:1] == ("pull_requests",):
                return ("null",) if ctx.untrusted else ("unknown",)
            if rest == ("head_repository", "full_name"):
                return ("headrepo",)
            if rest == ("head_repository", "fork"):
                return ("fork",)
            if rest == ("event",):
                return ("wr_event",)
        if event == "issues" and entity == "issue" and rest == ("pull_request",):
            return ("null",)
        return ("unknown",)
    if len(parts) >= 3 and parts[0] == "needs":
        return ("needs", parts[1], parts[2])
    return ("unknown",)


def _const_truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, float):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def _truthiness(value: tuple, ctx: EvalContext) -> tuple[bool, bool]:
    kind = value[0]
    if kind == "const":
        return TRUE if _const_truthy(value[1]) else FALSE
    if kind == "null":
        return FALSE
    if kind in {"actor", "headrepo", "repo", "owner"}:
        return TRUE
    if kind == "fork":
        # An account without write access can only open a pull request from a fork.
        return TRUE if ctx.untrusted else MAY_BE_EITHER
    if kind == "private":
        return FALSE if ctx.untrusted else MAY_BE_EITHER
    return MAY_BE_EITHER


def _value(node: tuple, ctx: EvalContext) -> tuple:
    kind = node[0]
    if kind == "lit":
        return ("const", node[1])
    if kind == "path":
        return _path_value(node[1], ctx)
    if kind == "call":
        name, args = node[1], node[2]
        if name == "fromjson" and len(args) == 1:
            inner = _value(args[0], ctx)
            if inner[0] == "const" and isinstance(inner[1], str):
                try:
                    return ("const", json.loads(inner[1]))
                except (ValueError, RecursionError):
                    return ("unknown",)
        if name in {"always", "success"}:
            return ("const", True)
        return ("unknown",)
    if kind in {"or", "and"}:
        left = _value(node[1], ctx)
        truth = _truthiness(left, ctx)
        if kind == "or":
            if truth == FALSE:
                return _value(node[2], ctx)
            if truth == TRUE:
                return left
        else:
            if truth == FALSE:
                return left
            if truth == TRUE:
                return _value(node[2], ctx)
        return ("unknown",)
    if kind in {"not", "cmp"}:
        result = evaluate(node, ctx)
        if result == TRUE:
            return ("const", True)
        if result == FALSE:
            return ("const", False)
    return ("unknown",)


def _coerce_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        try:
            return float(int(text, 16)) if text.lower().startswith("0x") else float(text)
        except ValueError:
            return math.nan
    return math.nan


def _const_equal(left: Any, right: Any) -> bool | None:
    if isinstance(left, (list, dict)) or isinstance(right, (list, dict)):
        return None
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right):
        return left == right
    a, b = _coerce_number(left), _coerce_number(right)
    if math.isnan(a) or math.isnan(b):
        return False
    return a == b


def _compare(op: str, left_node: tuple, right_node: tuple, ctx: EvalContext):
    left = _value(left_node, ctx)
    right = _value(right_node, ctx)
    if op not in {"==", "!="}:
        if left[0] == "const" and right[0] == "const":
            a, b = _coerce_number(left[1]), _coerce_number(right[1])
            if isinstance(left[1], str) and isinstance(right[1], str):
                a, b = left[1].casefold(), right[1].casefold()  # type: ignore[assignment]
            elif math.isnan(a) or math.isnan(b):
                return FALSE
            result = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
            return TRUE if result else FALSE
        return MAY_BE_EITHER

    equal = op == "=="
    if left[0] == "const" and right[0] == "const":
        result = _const_equal(left[1], right[1])
        if result is None:
            return MAY_BE_EITHER
        return TRUE if result == equal else FALSE
    if left[0] not in _SUBJECT_KINDS and right[0] in _SUBJECT_KINDS:
        left, right = right, left

    def gate_if(condition: bool) -> tuple[bool, bool]:
        if not condition:
            return MAY_BE_EITHER
        return _gate(ctx) if equal else _negated_gate(ctx)

    kind = left[0]
    other = right[1] if right[0] == "const" else None
    if kind == "null" and right[0] == "const":
        if other is None:
            return TRUE if equal else FALSE
        if isinstance(other, str) and other.strip() and math.isnan(_coerce_number(other)):
            return FALSE if equal else TRUE
        return MAY_BE_EITHER
    if kind == "actor" and left[1] == "assoc":
        return gate_if(
            right[0] == "const"
            and isinstance(other, str)
            and other.upper() in TRUSTED_ASSOCIATIONS
        )
    if kind == "actor" and left[1] == "login":
        literal = right[0] == "const" and (
            (isinstance(other, str) and other.strip() != "")
            or (isinstance(other, float) and not math.isnan(other))
        )
        return gate_if(literal or right[0] == "owner")
    if kind == "headrepo":
        return gate_if(right[0] == "repo")
    if kind == "fork" and right[0] == "const":
        if other is False or (isinstance(other, str) and other.lower() == "false"):
            return _gate(ctx) if equal else _negated_gate(ctx)
        if other is True or (isinstance(other, str) and other.lower() == "true"):
            return _negated_gate(ctx) if equal else _gate(ctx)
        return MAY_BE_EITHER
    if kind == "private" and right[0] == "const":
        if other is True or (isinstance(other, str) and other.lower() == "true"):
            return _gate(ctx) if equal else _negated_gate(ctx)
        if other is False or (isinstance(other, str) and other.lower() == "false"):
            return _negated_gate(ctx) if equal else _gate(ctx)
        return MAY_BE_EITHER
    if kind == "visibility" and right[0] == "const":
        if isinstance(other, str) and other.lower() in {"private", "internal"}:
            return _gate(ctx) if equal else _negated_gate(ctx)
        if isinstance(other, str) and other.lower() == "public":
            return _negated_gate(ctx) if equal else _gate(ctx)
        return MAY_BE_EITHER
    if kind == "wr_event":
        return gate_if(
            isinstance(other, str) and other.lower() in TRUSTED_UPSTREAM_EVENTS
        )
    if kind == "needs" and right[0] == "const":
        blocked = ctx.needs_blocked(left[1])
        if not blocked:
            if (
                left[2] == "outputs"
                and equal
                and isinstance(other, str)
                and other != ""
                and ctx.routes_by_event(left[1])
            ):
                # A dispatcher picks this value for some event types only; a
                # run for this event is not provable, so it is not assumed.
                return FALSE
            return MAY_BE_EITHER
        if left[2] == "result":
            # A skipped or blocked job never reports success.
            if isinstance(other, str) and other.lower() == "success":
                return FALSE if equal else TRUE
            return MAY_BE_EITHER
        if left[2] == "outputs" and isinstance(other, str) and other != "":
            # Outputs of a job that did not run are empty strings.
            return FALSE if equal else TRUE
    return MAY_BE_EITHER


def _contains(args: tuple, ctx: EvalContext) -> tuple[bool, bool]:
    if len(args) != 2:
        return MAY_BE_EITHER
    haystack = _value(args[0], ctx)
    needle = _value(args[1], ctx)
    if haystack[0] != "const":
        return MAY_BE_EITHER
    items = haystack[1]
    if isinstance(items, list):
        if needle[0] == "const":
            found = any(_const_equal(item, needle[1]) for item in items)
            return TRUE if found else FALSE
        if needle[0] == "null":
            return TRUE if any(item is None for item in items) else FALSE
        if needle == ("actor", "assoc"):
            trusted = bool(items) and all(
                isinstance(item, str) and item.upper() in TRUSTED_ASSOCIATIONS
                for item in items
            )
            return _gate(ctx) if trusted else MAY_BE_EITHER
        if needle == ("actor", "login"):
            return _gate(ctx) if items else FALSE
        if needle[0] == "wr_event":
            trusted = bool(items) and all(
                isinstance(item, str) and item.lower() in TRUSTED_UPSTREAM_EVENTS
                for item in items
            )
            return _gate(ctx) if trusted else MAY_BE_EITHER
        return MAY_BE_EITHER
    if isinstance(items, str):
        if needle[0] == "const" and isinstance(needle[1], str):
            return TRUE if needle[1].casefold() in items.casefold() else FALSE
        if needle == ("actor", "assoc"):
            upper = items.upper()
            if any(value in upper for value in UNTRUSTED_ASSOCIATIONS):
                return MAY_BE_EITHER
            return _gate(ctx) if upper.strip() else FALSE
    return MAY_BE_EITHER


def evaluate(node: tuple | None, ctx: EvalContext) -> tuple[bool, bool]:
    """(may_be_true, may_be_false) for a parsed condition under ``ctx``."""
    if node is None:
        return TRUE
    kind = node[0]
    if kind == "or":
        left = evaluate(node[1], ctx)
        right = evaluate(node[2], ctx)
        return (left[0] or right[0], left[1] and right[1])
    if kind == "and":
        left = evaluate(node[1], ctx)
        right = evaluate(node[2], ctx)
        return (left[0] and right[0], left[1] or right[1])
    if kind == "not":
        inner = evaluate(node[1], ctx)
        return (inner[1], inner[0])
    if kind == "cmp":
        return _compare(node[1], node[2], node[3], ctx)
    if kind == "call":
        name = node[1]
        if name == "contains":
            return _contains(node[2], ctx)
        if name in {"success", "always"}:
            return TRUE
        if name in {"startswith", "endswith"} and len(node[2]) == 2:
            left = _value(node[2][0], ctx)
            right = _value(node[2][1], ctx)
            if (
                left[0] == "const"
                and right[0] == "const"
                and isinstance(left[1], str)
                and isinstance(right[1], str)
            ):
                method = str.startswith if name == "startswith" else str.endswith
                return TRUE if method(left[1].casefold(), right[1].casefold()) else FALSE
            if left[0] == "null":
                return FALSE
            return MAY_BE_EITHER
        if name == "fromjson":
            return _truthiness(_value(node, ctx), ctx)
        return MAY_BE_EITHER
    if kind in {"lit", "path"}:
        return _truthiness(_value(node, ctx), ctx)
    return MAY_BE_EITHER
