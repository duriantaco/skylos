"""Compile picomatch-style glob patterns (as JS tools write them) to regexes.

Supported: ``*``, ``?``, ``**`` path segments, ``[...]`` classes (``[!x]``
negated), nested ``{a,b}`` braces with empty alternatives, and the extglobs
``?(..)``, ``*(..)``, ``+(..)``, ``@(..)``. A pattern that uses anything else
(``!(..)``) raises :class:`UnsupportedGlob`; callers then ignore the pattern,
which only ever removes an entry candidate the table would have added.
Paths are matched relative to a base directory, with ``/`` separators.
"""

from __future__ import annotations

import re
from functools import lru_cache


class UnsupportedGlob(ValueError):
    pass


_SEGMENT_STARTS = frozenset({"/", "{", ",", "|", "("})


def _translate(pattern: str) -> str:
    length = len(pattern)

    def parse(index: int, terminators: str) -> tuple[str, int]:
        parts: list[str] = []
        while index < length:
            char = pattern[index]
            if char in terminators:
                break
            if pattern.startswith("**", index):
                at_start = index == 0 or pattern[index - 1] in _SEGMENT_STARTS
                following = pattern[index + 2] if index + 2 < length else ""
                if at_start and following == "/":
                    parts.append(r"(?:[^/]*/)*")
                    index += 3
                    continue
                if at_start and (following == "" or following in terminators):
                    parts.append(r".*")
                    index += 2
                    continue
                parts.append(r"[^/]*")
                index += 2
                continue
            if char in "?*+@!" and index + 1 < length and pattern[index + 1] == "(":
                if char == "!":
                    raise UnsupportedGlob(pattern)
                alternatives, index = group(index + 2, "|", ")")
                body = "(?:" + "|".join(alternatives) + ")"
                parts.append(body + {"?": "?", "*": "*", "+": "+", "@": ""}[char])
                continue
            if char == "*":
                parts.append(r"[^/]*")
                index += 1
                continue
            if char == "?":
                parts.append(r"[^/]")
                index += 1
                continue
            if char == "[":
                end = pattern.find("]", index + 2)
                if end == -1:
                    raise UnsupportedGlob(pattern)
                content = pattern[index + 1 : end]
                negated = content.startswith(("!", "^"))
                if negated:
                    content = content[1:]
                escaped = "".join("\\" + c if c in "\\^]" else c for c in content)
                parts.append("[" + ("^" if negated else "") + escaped + "]")
                index = end + 1
                continue
            if char == "{":
                alternatives, index = group(index + 1, ",", "}")
                parts.append("(?:" + "|".join(alternatives) + ")")
                continue
            if char == "\\" and index + 1 < length:
                parts.append(re.escape(pattern[index + 1]))
                index += 2
                continue
            if char in ")}|":
                raise UnsupportedGlob(pattern)
            parts.append(re.escape(char))
            index += 1
        return "".join(parts), index

    def group(index: int, separator: str, closer: str) -> tuple[list[str], int]:
        alternatives: list[str] = []
        while True:
            part, index = parse(index, separator + closer)
            alternatives.append(part)
            if index >= length:
                raise UnsupportedGlob(pattern)
            if pattern[index] == closer:
                return alternatives, index + 1
            index += 1

    regex, end = parse(0, "")
    if end != length:
        raise UnsupportedGlob(pattern)
    return regex


def normalise_pattern(pattern: str) -> str:
    pattern = pattern.strip()
    while pattern.startswith("./"):
        pattern = pattern[2:]
    if pattern.endswith("/"):
        pattern += "**"
    return pattern


@lru_cache(maxsize=8192)
def compile_glob(pattern: str) -> re.Pattern[str] | None:
    """Regex for one positive pattern, or None when it is unsupported."""
    try:
        return re.compile(_translate(normalise_pattern(pattern)))
    except (UnsupportedGlob, re.error, RecursionError):
        return None


class GlobSet:
    """Positive patterns minus ``!``-negated ones, as one matcher."""

    __slots__ = ("_exclude", "_include", "patterns")

    def __init__(self, patterns) -> None:
        include, exclude = [], []
        self.patterns = tuple(patterns)
        for pattern in self.patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                continue
            negated = pattern.startswith("!")
            compiled = compile_glob(pattern[1:] if negated else pattern)
            if compiled is None:
                continue
            (exclude if negated else include).append(compiled)
        self._include = tuple(include)
        self._exclude = tuple(exclude)

    def __bool__(self) -> bool:
        return bool(self._include)

    def matches(self, relative: str) -> bool:
        if not any(regex.fullmatch(relative) for regex in self._include):
            return False
        return not any(regex.fullmatch(relative) for regex in self._exclude)


def static_prefix(pattern: str) -> str:
    """The leading directory part of ``pattern`` that has no magic."""
    pattern = normalise_pattern(pattern)
    parts = []
    for part in pattern.split("/"):
        if any(char in part for char in "*?[{(!"):
            break
        parts.append(part)
    else:
        parts = parts[:-1]
    return "/".join(parts)


def expand_braces(pattern: str, limit: int = 256) -> list[str]:
    """``a.{js,ts}`` -> ``[a.js, a.ts]`` (for literal config file names)."""
    results = [pattern]
    expanded: list[str] = []
    while results:
        current = results.pop()
        start = current.find("{")
        if start == -1:
            expanded.append(current)
            if len(expanded) > limit:
                break
            continue
        depth, end = 0, -1
        for index in range(start, len(current)):
            if current[index] == "{":
                depth += 1
            elif current[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end == -1:
            expanded.append(current)
            continue
        body = current[start + 1 : end]
        options, depth, last = [], 0, 0
        for index, char in enumerate(body):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == "," and depth == 0:
                options.append(body[last:index])
                last = index + 1
        options.append(body[last:])
        for option in options:
            results.append(current[:start] + option + current[end + 1 :])
    return expanded
