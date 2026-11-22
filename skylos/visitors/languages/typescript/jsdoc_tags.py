"""Release tags in the comments directly before a TS/JS declaration.

`@public`, `@alpha` and `@beta` mark a declaration as published API (the
TSDoc release tags); `@alias` marks a deliberate second name. `@internal`
gives no protection. Only comments separated from the declaration by
whitespace count, and a `//` comment must start its line, so a trailing
comment of the previous statement does not tag the next one.
"""

from __future__ import annotations

import re

PUBLIC_API_TAGS = frozenset({"@public", "@alpha", "@beta", "@alias"})
_TAG_RE = re.compile(r"(?:(?<=^)|(?<=[\s*{]))@([A-Za-z][A-Za-z0-9_]*)")
_STATEMENT_LISTS = frozenset({"program", "statement_block", "class_body"})


def leading_comment_tags(source: bytes, node) -> frozenset[str]:
    """Return the `@tags` of the comments immediately before ``node``."""
    tags: set[str] = set()
    current = node
    previous = node.prev_sibling
    while previous is not None and previous.type == "comment":
        if source[previous.end_byte : current.start_byte].strip():
            break
        if source[previous.start_byte : previous.start_byte + 2] == b"//":
            line_start = source.rfind(b"\n", 0, previous.start_byte) + 1
            if source[line_start : previous.start_byte].strip():
                break
        text = source[previous.start_byte : previous.end_byte].decode(
            "utf-8", "replace"
        )
        tags.update("@" + match.group(1) for match in _TAG_RE.finditer(text))
        current = previous
        previous = previous.prev_sibling
    return frozenset(tags)


def has_public_api_tag(tags) -> bool:
    return bool(PUBLIC_API_TAGS.intersection(tags))


def declaration_has_public_api_tag(source: bytes, node) -> bool:
    """Whether the statement declaring ``node`` (or its export) is tagged.

    Walks from a name node to the statement that holds it, checking the
    export statement and the statement in its list on the way.
    """
    current = node
    while current is not None:
        parent = current.parent
        is_statement = current.type == "export_statement" or (
            parent is not None and parent.type in _STATEMENT_LISTS
        )
        if is_statement and has_public_api_tag(leading_comment_tags(source, current)):
            return True
        if parent is None or parent.type in _STATEMENT_LISTS:
            return False
        current = parent
    return False
