from __future__ import annotations


def visible_initial_source(source: str, max_chars: int) -> str:
    bounded_chars = max(0, max_chars)
    excerpt = source[:bounded_chars]
    if len(source) <= len(excerpt) or excerpt.endswith(("\n", "\r")):
        return excerpt
    lines = excerpt.splitlines(keepends=True)
    if not lines:
        return ""
    return "".join(lines[:-1])
