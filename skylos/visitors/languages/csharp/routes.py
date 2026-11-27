"""Resolve the receivers of ASP.NET Core Minimal API route registrations."""

from __future__ import annotations

import re
from collections import defaultdict

from . import core
from .bindings import _USING, _shadows

MAP_CALL_RE = re.compile(
    r"\.\s*Map(?:Get|Post|Put|Delete|Patch|Methods|Fallback)\s*(?:<[^;{}()]*>)?\s*\("
)
_TYPES = {
    "Microsoft.AspNetCore.Builder.WebApplication": "endpoint",
    "Microsoft.AspNetCore.Builder.WebApplicationBuilder": "builder",
    "Microsoft.AspNetCore.Routing.IEndpointRouteBuilder": "endpoint",
    "Microsoft.AspNetCore.Routing.RouteGroupBuilder": "group",
}
_SIMPLE_TYPES = {name.rsplit(".", 1)[1]: name for name in _TYPES}
_APPLICATION = "Microsoft.AspNetCore.Builder.WebApplication"
_FACTORIES = {"CreateBuilder", "CreateSlimBuilder", "CreateEmptyBuilder"}
_ENDPOINT_KINDS = {"endpoint", "group", "versioned"}
_VERSIONING_METHOD = re.compile(
    r"(?<![.\w])(?P<name>NewVersionedApi|HasApiVersion)\s*(?:<[^;{}()]+>)?\s*\("
)
_EXTENSION_RECEIVER = re.compile(r"\s*(?:\[[^]\n]*\]\s*)*this\b")
_EXTENSION_BLOCK = re.compile(
    r"\bextension\s*(?:<[^;{}()]+>)?\s*\([^;{}()]+\)\s*(?:where\s+[^;{}]+)?\{"
)
_TOKEN = re.compile(r"[A-Za-z_]\w*|::|=>|==|!=|>=|<=|\S")


def _bracket_pairs(words: list[str]) -> dict[int, int]:
    pairs = {}
    openings = {"(": [], "{": []}
    for i, word in enumerate(words):
        if word in openings:
            openings[word].append(i)
        elif word in (")", "}"):
            stack = openings["(" if word == ")" else "{"]
            if stack:
                opening = stack.pop()
                pairs[i] = opening
                pairs[opening] = i
    return pairs


def declared_versioning_overrides(masked: str) -> set[str]:
    """Both classic extension methods and C# 14 extension blocks can override the package."""
    matches = list(_VERSIONING_METHOD.finditer(masked))
    if not matches:
        return set()
    overrides = {
        match["name"]
        for match in matches
        if _EXTENSION_RECEIVER.match(masked, match.end())
    }
    for block in _EXTENSION_BLOCK.finditer(masked):
        end = core.matching_brace(masked, block.end() - 1)
        overrides.update(
            match["name"] for match in matches if block.end() <= match.start() < end
        )
    return overrides


def declared_framework_homonyms(masked: str, *, include_file_local=False) -> set[str]:
    declarations = [
        decl
        for decl in core._TYPE_RE.finditer(masked)
        if decl["name"] in _SIMPLE_TYPES
        and (include_file_local or "file" not in decl["mods"].split())
    ]
    if not declarations:
        return set()
    namespaces = core._namespace_ranges(masked)
    types = core._type_ranges(masked, namespaces)
    return {core._qualified_type_name(decl, types, namespaces) for decl in declarations}


def _parents(name: str):
    while name:
        yield name + "."
        name = name.rpartition(".")[0]
    yield ""


class _ReceiverBindings:
    def __init__(
        self,
        masked: str,
        shadowed_types: frozenset[str],
        global_usings,
        versioning_package,
        versioning_overrides,
    ):
        self.versioning = (
            {"NewVersionedApi", "HasApiVersion"}
            - versioning_overrides
            - declared_versioning_overrides(masked)
            if versioning_package
            else set()
        )
        self.tokens = list(_TOKEN.finditer(masked))
        self.words = [token.group() for token in self.tokens]
        self.pairs = _bracket_pairs(self.words)
        self.end = len(masked)
        self.namespaces = core._namespace_ranges(masked)
        self.local_types = shadowed_types.union(
            declared_framework_homonyms(masked, include_file_local=True)
        )
        self.types = (
            core._type_ranges(masked, self.namespaces) if self.local_types else []
        )
        self.aliases = defaultdict(list)
        self.usings = []
        for alias, _, name in global_usings:
            if alias:
                self.aliases[alias].append((0, self.end, name))
            else:
                self.usings.append((0, self.end, name))
        for match in _USING.finditer(masked):
            pos = match.start("name")
            lo, hi, _ = max(
                (s for s in self.namespaces if s[0] <= pos < s[1]),
                default=(0, self.end, ""),
            )
            directive = (lo, hi, match["name"].removeprefix("global::"))
            if match["alias"]:
                self.aliases[match["alias"]].append(directive)
            else:
                self.usings.append(directive)
        self.bindings = defaultdict(list)
        # Untyped lambda parameters shadow outer variables, too.
        typed = []
        shadows = _shadows(masked, [], typed)
        types = {
            (name, lo, hi): _TYPES.get(self.framework_type(t, lo))
            for name, t, lo, hi in typed
        }
        for name, lo, hi in shadows:
            self.bindings[name].append((lo, hi, types.get((name, lo, hi))))

    def framework_type(self, name: str, offset: int) -> str | None:
        if name.startswith("global::"):
            name = name.removeprefix("global::")
            return name if name in _TYPES and name not in self.local_types else None

        head, dot, tail = name.partition(".")
        matching_aliases = [
            a for a in self.aliases.get(head, ()) if a[0] <= offset < a[1]
        ]
        if matching_aliases:
            # Conflicting aliases make the unqualified name uncertain.
            nearest = max(a[0] for a in matching_aliases)
            targets = {a[2] + dot + tail for a in matching_aliases if a[0] == nearest}
            if len(targets) != 1:
                return None
            name = targets.pop()
        if self.local_types:
            containing = core._containing_type_range(self.types, offset)
            scope = (
                containing[2]
                if containing
                else core._namespace_at(self.namespaces, offset)
            )
            imports = {imp for lo, hi, imp in self.usings if lo <= offset < hi}
            for prefix in _parents(scope):
                if prefix + name in self.local_types or any(
                    prefix + imp + "." + name in self.local_types for imp in imports
                ):
                    return None
        name = _SIMPLE_TYPES.get(name, name)
        return name if name in _TYPES and name not in self.local_types else None

    def binding(self, name: str, at: int):
        visible = (b for b in self.bindings.get(name, ()) if b[0] <= at < b[1])
        return max(visible, key=lambda b: (b[0], -b[1]), default=None)

    def qualified_name_start(self, i: int) -> int:
        while (
            i >= 2
            and self.words[i - 1] in (".", "::")
            and self.words[i - 2].isidentifier()
        ):
            i -= 2
        return i

    def expression_kind(self, end: int, *, standalone=False, expected_start=None):
        """Walk a receiver backwards, skipping balanced call arguments."""
        words = self.words
        i = end
        operations = []
        while i >= 0 and words[i] == ")":
            opening = self.pairs.get(i)
            if opening is None or opening < 3 or words[opening - 2] != ".":
                return None
            operations.append((words[opening - 1], opening + 1 == i))
            i = opening - 3
        if i < 0 or not words[i].isidentifier():
            return None
        start = self.qualified_name_start(i)
        if expected_start is not None and start != expected_start:
            return None
        if start and words[start - 1] in (".", "::", "new"):
            return None
        root = "".join(words[start : i + 1])
        known = self.binding(root, self.tokens[start].start())
        if known:
            kind = known[2]
        elif self.framework_type(root, self.tokens[start].start()) == _APPLICATION:
            kind = "factory"
        elif root == "app" and standalone and start == 0 and not operations:
            # Preserve the standalone top-level app.MapGet snippet.
            kind = "endpoint"
        else:
            return None
        for method, empty in reversed(operations):
            if kind == "factory" and method in _FACTORIES:
                kind = "builder"
            elif (kind, method) == ("factory", "Create") or (
                kind == "builder" and method == "Build" and empty
            ):
                kind = "endpoint"
            elif kind in _ENDPOINT_KINDS and method == "MapGroup":
                kind = "group"
            elif (
                kind == "endpoint"
                and method == "NewVersionedApi"
                and method in self.versioning
            ):
                kind = "versioned"
            elif (
                kind in {"group", "versioned"}
                and method == "HasApiVersion"
                and method in self.versioning
            ):
                continue  # This convention returns the original builder.
            else:
                return None
        return kind

    def initializer_kind(self, i: int):
        stop = i + 1
        while stop < len(self.words) and self.words[stop] not in (";", ",", "}", ")"):
            if self.words[stop] == "(":
                close = self.pairs.get(stop)
                if close is None:
                    return None
                stop = close
            elif self.words[stop] in ("{", "="):
                return None
            stop += 1
        return self.expression_kind(stop - 1, expected_start=i + 1)

    def assign(self, i: int, blocks: list[int]):
        words = self.words
        name = words[i - 1]
        before = words[i - 2] if i >= 2 else ""
        if not name.isidentifier() or before in (".", "::", "using"):
            return
        declaration = before.isidentifier() and before not in ("else", "return")
        closing = self.pairs.get(blocks[-1]) if blocks else None
        limit = self.tokens[closing].end() if closing is not None else self.end
        offset = self.tokens[i].start()
        if before in (")", "else"):
            # A write in a branch without braces need not execute.
            kind = None
        elif declaration and before != "var":
            start = self.qualified_name_start(i - 2)
            kind = _TYPES.get(
                self.framework_type("".join(words[start : i - 1]), offset)
            )
        else:
            kind = self.initializer_kind(i)
        current = self.binding(name, offset)
        if not declaration and current and current[1] > limit and current[2] != kind:
            # The outer value is uncertain after a conditional reassignment.
            self.bindings[name].append((offset, current[1], None))
        self.bindings[name].append((offset, limit, kind))


def endpoint_receiver_offsets(
    masked_source: str,
    *,
    shadowed_types: frozenset[str] = frozenset(),
    global_usings=(),
    versioning_package: bool = False,
    versioning_overrides: frozenset[str] = frozenset(),
) -> set[int]:
    """Return the dot offsets of registrations on known endpoint builders."""
    calls = {match.start() for match in MAP_CALL_RE.finditer(masked_source)}
    if not calls:
        return set()
    receivers = _ReceiverBindings(
        masked_source,
        shadowed_types,
        global_usings,
        versioning_package,
        versioning_overrides,
    )
    proven = set()
    blocks = []
    for i, token in enumerate(receivers.tokens):
        word = receivers.words[i]
        if word == "{":
            blocks.append(i)
        elif word == "}" and blocks:
            blocks.pop()
        elif word == "=" and i > 0:
            receivers.assign(i, blocks)
        elif (
            token.start() in calls
            and receivers.expression_kind(i - 1, standalone=not blocks)
            in _ENDPOINT_KINDS
        ):
            proven.add(token.start())
    return proven
