"""Whether an MDX document can load a project module.

MDX loads modules only through ESM statements (`import`/`export` at the start
of a line) or dynamic `import()`/`require()` in an expression. Front matter,
fenced code blocks and inline code spans are prose. A document with none of
these consumes no module export,
so it need not hold back export checks. Unreadable or oversized documents are
treated as consumers.
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_MDX_BYTES = 512 * 1024
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_ESM_RE = re.compile(r"^\s*(?:import|export)(?![\w$])")
_LOAD_RE = re.compile(r"(?<![\w$.])(?:import|require)\(")
_CODE_SPAN_RE = re.compile(r"(`+)[^`].*?\1|(`+)\2")
# Code spans are replaced by a word, so prose such as "import (`x`)" cannot
# be rejoined into a call.
_CODE_SPAN = " code "
_FRONTMATTER_RE = re.compile(
    r"\A(?:\ufeff)?---[^\S\r\n]*\r?\n[\s\S]*?^---[^\S\r\n]*$", re.MULTILINE
)


def mdx_has_module_statements(path) -> bool:
    try:
        path = Path(path)
        if path.stat().st_size > MAX_MDX_BYTES:
            return True
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return True
    text = _FRONTMATTER_RE.sub("", text, count=1)
    fence = None
    for line in text.splitlines():
        marker = _FENCE_RE.match(line)
        if fence is not None:
            if (
                marker
                and marker.group(1)[0] == fence[0]
                and len(marker.group(1)) >= len(fence)
                and not line[marker.end() :].strip()
            ):
                fence = None
            continue
        if marker:
            fence = marker.group(1)
            continue
        if _ESM_RE.match(line) or _LOAD_RE.search(_CODE_SPAN_RE.sub(_CODE_SPAN, line)):
            return True
    return False


_DYNAMIC_SPECIFIER_RE = re.compile(
    r"""(?<![\w$.])(?:import|require)\(\s*(['"])([^'"\r\n]+)\1"""
)


def mdx_module_parts(text: str) -> tuple[list[tuple[int, str]], set[str]]:
    """Return an MDX document's ESM blocks and its expression load specifiers.

    An ESM block starts with a line beginning ``import``/``export`` and ends
    at the next blank line (MDX's own rule); each block is returned with its
    zero-based first line so parsed line numbers match the document. The
    specifiers are the string literals of ``import()``/``require()`` calls in
    the remaining lines. Front matter, fenced code and code spans are prose.
    """
    lines = text.splitlines()
    skip = 0
    frontmatter = _FRONTMATTER_RE.match(text)
    if frontmatter:
        skip = text[: frontmatter.end()].count("\n") + 1
    blocks: list[tuple[int, str]] = []
    specifiers: set[str] = set()
    fence = None
    block_start = None
    block: list[str] = []
    for index, line in enumerate(lines):
        if index < skip:
            continue
        if block_start is not None:
            if line.strip():
                block.append(line)
                continue
            blocks.append((block_start, "\n".join(block)))
            block_start, block = None, []
            continue
        marker = _FENCE_RE.match(line)
        if fence is not None:
            if (
                marker
                and marker.group(1)[0] == fence[0]
                and len(marker.group(1)) >= len(fence)
                and not line[marker.end() :].strip()
            ):
                fence = None
            continue
        if marker:
            fence = marker.group(1)
            continue
        if _ESM_RE.match(line):
            block_start, block = index, [line]
            continue
        prose = _CODE_SPAN_RE.sub(_CODE_SPAN, line)
        specifiers.update(
            match.group(2) for match in _DYNAMIC_SPECIFIER_RE.finditer(prose)
        )
    if block_start is not None:
        blocks.append((block_start, "\n".join(block)))
    return blocks, specifiers
