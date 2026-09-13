from __future__ import annotations

import re


_ECMASCRIPT_LINE_END_RE = re.compile(r"\r\n|[\n\r\u2028\u2029]")


def split_ecmascript_lines(source: str, *, keepends: bool = False) -> list[str]:
    """Split text at ECMAScript line terminators."""
    lines: list[str] = []
    start = 0
    for match in _ECMASCRIPT_LINE_END_RE.finditer(source):
        end = match.end() if keepends else match.start()
        lines.append(source[start:end])
        start = match.end()
    if start < len(source):
        lines.append(source[start:])
    return lines
