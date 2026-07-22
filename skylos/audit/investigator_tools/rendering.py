"""Byte-bounded rendering for source observations."""

from __future__ import annotations

from skylos.audit.redaction import redact_text


SearchHit = tuple[str, str, int, str]


def _bounded_search_hits(
    hits: list[SearchHit],
    max_bytes: int,
) -> tuple[list[SearchHit], bool]:
    visible: list[SearchHit] = []
    used = 0
    for hit in hits:
        encoded_size = len(hit[0].encode("utf-8")) + (1 if visible else 0)
        if used + encoded_size > max_bytes:
            return visible, True
        visible.append(hit)
        used += encoded_size
    return visible, False


def _bounded_numbered_lines(
    lines: list[str],
    *,
    start: int,
    max_bytes: int,
) -> tuple[list[str], str, bool]:
    visible: list[str] = []
    rendered: list[str] = []
    used = 0
    for offset, line in enumerate(lines):
        item = f"{start + offset}: {redact_text(line)}"
        encoded_size = len(item.encode("utf-8")) + (1 if rendered else 0)
        if used + encoded_size > max_bytes:
            return visible, "\n".join(rendered), True
        visible.append(line)
        rendered.append(item)
        used += encoded_size
    return visible, "\n".join(rendered), False


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    suffix = "\n[TRUNCATED]"
    budget = max(0, max_bytes - len(suffix.encode("utf-8")))
    prefix = encoded[:budget].decode("utf-8", errors="ignore")
    return prefix + suffix
