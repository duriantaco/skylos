from __future__ import annotations

import re

_TOKEN_RE = re.compile(
    r"""
    //[^\n]*
    |/\*.*?\*/
    |(?:\$@|@\$|@|\$)?"(?:""|\\.|[^"\\])*"
    |'(?:\\.|[^'\\])*'
    """,
    re.DOTALL | re.VERBOSE,
)


def matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def mask_comments_and_strings(source: str) -> str:
    return _TOKEN_RE.sub(_mask_token, source)


def _mask_token(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))
