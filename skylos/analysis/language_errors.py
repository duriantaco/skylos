from __future__ import annotations

from skylos.analysis.errors import analysis_error_payload


class LanguageParseError(ValueError):
    """A language parser cannot completely understand a discovered source file."""

    def __init__(self, message: str, *, line: int = 1, column: int = 1):
        super().__init__(message)
        self.lineno = line
        self.offset = column


def tree_sitter_analysis_error(file, root, language: str) -> dict | None:
    if root is None:
        error = analysis_error_payload(
            file,
            LanguageParseError(
                f"{language} parser is unavailable; analysis is incomplete"
            ),
            kind="language_parser_unavailable",
        )
    elif root.has_error:
        pending = [root]
        error_node = root
        while pending:
            node = pending.pop()
            if node.type == "ERROR" or node.is_missing:
                error_node = node
                break
            pending.extend(
                reversed([child for child in node.children if child.has_error])
            )
        point = error_node.start_point
        error = analysis_error_payload(
            file,
            LanguageParseError(
                f"{language} parser cannot completely understand this file; "
                "findings may be incomplete",
                line=point[0] + 1,
                column=point[1] + 1,
            ),
            kind="syntax_error",
        )
    else:
        return None
    error["language"] = language
    return error


def with_analysis_error(result: tuple, error: dict | None) -> tuple:
    """Attach worker error metadata without changing collected findings."""
    if error is None:
        return result
    if len(result) > 25:
        fields = list(result)
        if fields[25] is None:
            fields[25] = error
        return tuple(fields)
    base = (*result, *([None] * max(0, 13 - len(result))))
    metadata = (
        set(),  # ignored lines
        [],  # suppressed findings
        {},  # inferred types
        {},  # instance attribute types
        set(),  # used attribute names
        set(),  # used attribute context
        [],  # source lines
        {},  # parameter method refs
        {},  # call argument types
        [],  # clone fragments
        None,  # architecture metrics
        set(),  # top-level refs
        error,
        {},  # ignored rules by line
        False,  # explicit exports
    )
    return (*base, *metadata[len(base) - 13 :])
