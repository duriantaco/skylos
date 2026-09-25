from __future__ import annotations

import re
from bisect import bisect_right

from ._lex import mask_comments_and_strings


_TERMINATOR_RE = re.compile(r"\b(return|throw|break|continue)\b")
_BRANCH_LABEL_RE = re.compile(r"(?:case\b|default\s*:|@?[A-Za-z_]\w*\s*:)")


def _brace_pairs(source: str) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, char in enumerate(source):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            pairs[stack.pop()] = index
    return pairs


def _statement_end(source: str, start: int, block_end: int) -> int:
    """Find the terminator's semicolon, ignoring nested expressions."""
    parens = brackets = braces = 0
    for index in range(start, block_end):
        char = source[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == ";" and parens == brackets == braces == 0:
            return index
    return -1


def scan_quality(file_path: str, source: str) -> list[dict]:
    """Find statements after unconditional, direct C# block terminators.

    This intentionally avoids inferring that an ``if`` or other compound
    statement always terminates. A conservative lexical check is preferable
    to reporting conditional exits as unreachable code.
    """
    masked = mask_comments_and_strings(source)
    masked = re.sub(r"(?m)^[ \t]*#.*$", lambda match: " " * len(match.group()), masked)
    blocks = _brace_pairs(masked)
    conditional_directives = [
        match.start()
        for match in re.finditer(r"(?m)^[ \t]*#(?:if|elif|else|endif)\b", source)
    ]
    findings: list[dict] = []
    stack: list[int] = []
    reported_blocks: set[int] = set()
    line_starts = [0] + [match.end() for match in re.finditer("\n", source)]
    previous_significant = -1
    candidates = iter(_TERMINATOR_RE.finditer(masked))
    candidate = next(candidates, None)

    for index, char in enumerate(masked):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            stack.pop()

        if candidate is None or index != candidate.start():
            if not char.isspace():
                previous_significant = index
            continue

        keyword = candidate.group(1)
        candidate = next(candidates, None)
        if not stack or stack[-1] in reported_blocks:
            continue
        block_end = blocks.get(stack[-1])
        if block_end is None:
            continue
        directive_index = bisect_right(conditional_directives, stack[-1])
        if (
            directive_index < len(conditional_directives)
            and conditional_directives[directive_index] < block_end
        ):
            continue

        if previous_significant < 0 or masked[previous_significant] not in "{;}":
            continue

        semicolon = _statement_end(masked, index + len(keyword), block_end)
        if semicolon < 0:
            continue
        next_index = semicolon + 1
        while next_index < block_end and masked[next_index].isspace():
            next_index += 1
        if next_index >= block_end:
            continue
        # A switch case or goto label is another entry point, not dead code.
        if _BRANCH_LABEL_RE.match(masked, next_index):
            continue

        line = bisect_right(line_starts, next_index)
        findings.append(
            {
                "rule_id": "SKY-UC002",
                "severity": "MEDIUM",
                "message": f"Unreachable code after {keyword}.",
                "file": file_path,
                "line": line,
                "col": next_index - line_starts[line - 1],
            }
        )
        reported_blocks.add(stack[-1])

    return findings
