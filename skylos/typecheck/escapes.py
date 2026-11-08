"""New compiler escape hatches, only for opt-in comparable baseline checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from skylos.done import suppressions
from skylos.done.answer_sites import _is_generated, _is_test_code


@dataclass(frozen=True)
class _LocatedDirective(suppressions.Directive):
    column: int = 1


def _is_test(path: str) -> bool:
    return _is_test_code(path, set())


def _pyrefly_directives(text: str) -> list[_LocatedDirective]:
    source = suppressions._python_source(text)
    pattern = re.compile(
        r"#\s*pyrefly\s*:\s*(ignore-errors|ignore)\b(?:\[(?P<rules>[^\]]*)\])?"
    )
    found = []
    first_code = None
    for line, comments in source.comments.items():
        for comment in comments:
            match = pattern.match(comment)
            if match is None:
                continue
            whole_file = match.group(1) == "ignore-errors"
            if whole_file:
                if first_code is None:
                    tree = ast.parse(text)
                    statements = list(tree.body)
                    if (
                        statements
                        and isinstance(statements[0], ast.Expr)
                        and isinstance(statements[0].value, ast.Constant)
                        and isinstance(statements[0].value.value, str)
                    ):
                        statements = statements[1:]
                    first_code = statements[0].lineno if statements else float("inf")
                if line >= first_code:
                    continue  # Pyrefly ignores misplaced file-level comments.
            found.append(
                _LocatedDirective(
                    line,
                    "pyrefly: " + match.group(1),
                    "pyrefly",
                    suppressions._split_rules(match.group("rules")),
                    "file" if whole_file else "line",
                    "",
                    match.group(0),
                    max(1, source.lines[line - 1].find("#") + 1),
                )
            )
    return found


def _any_directives(path: str, text: str) -> list[_LocatedDirective]:
    from skylos.done.js_inventory import _parse
    from skylos.visitors.languages.typescript.type_safety import (
        _assertion_parts,
        _normalized_type_node,
    )

    tree = _parse(path, text)
    if tree is None or tree.has_error:
        raise ValueError("TypeScript escape analysis could not parse " + path)
    source = text.encode("utf-8", errors="surrogatepass")
    stack = [tree]
    found = []
    while stack:
        node = stack.pop()
        parts = _assertion_parts(node, source)
        if parts is not None and _normalized_type_node(parts[1], source) == "any":
            found.append(
                _LocatedDirective(
                    node.start_point[0] + 1,
                    "assertion to any",
                    "TypeScript",
                    (),
                    "line",
                    "",
                    "as any",
                    node.start_point[1] + 1,
                )
            )
        stack.extend(reversed(node.named_children))
    return found


def _additional_suppressions(comparison, checker: str, root: Path):
    heads, bases, base_texts, _ = suppressions._read_changed(comparison)
    extensions = (
        (".ts", ".tsx", ".mts", ".cts") if checker == "tsc" else (".py", ".pyi")
    )
    extract = (
        _any_directives
        if checker == "tsc"
        else lambda path, text: _pyrefly_directives(text)
    )

    def relevant(path, text):
        if (
            _is_test(path)
            or _is_generated(path, text)
            or suppressions.is_vendored(path)
        ):
            return False
        try:
            (Path(comparison.root) / path).resolve().relative_to(root)
        except ValueError:
            return False
        return True

    head_directives = {
        path: (text, extract(path, text), added)
        for path, (text, _, added) in heads.items()
        if path.endswith(extensions) and relevant(path, text)
    }
    base_directives = {
        path: extract(path, text)
        for path, text in base_texts.items()
        if path.endswith(extensions) and relevant(path, text)
    }
    return suppressions._added(
        comparison,
        head_directives,
        base_directives,
        base_texts,
        _is_test,
        _is_generated,
    )


def new_type_escapes(comparison, *, root: Path, checker: str) -> list[dict]:
    """Return only net-new production escapes for the selected compiler.

    The caller must establish a complete, isolated baseline comparison first.
    Existing A118/T104 defaults and their advice/negative controls are untouched.
    """
    if checker not in {"mypy", "pyright", "pyrefly", "tsc"}:
        raise ValueError("Unsupported checker for escape analysis")
    root = Path(root).resolve()
    suffixes = (
        (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
        if checker == "tsc"
        else (".py", ".pyi")
    )
    for changed in comparison.changed:
        for path, read in (
            (changed.base_path, comparison.base_text),
            (changed.head_path, comparison.head_text),
        ):
            if (
                not path
                or not path.endswith(suffixes)
                or _is_test(path)
                or suppressions.is_vendored(path)
            ):
                continue
            try:
                (Path(comparison.root) / path).resolve().relative_to(root)
            except ValueError:
                continue
            if read(path) is None and not _is_generated(path, None):
                raise ValueError(
                    "Type escape analysis could not read production source: " + path
                )
    found = suppressions.added_suppressions(comparison, _is_test, _is_generated)
    names = {
        "mypy": {"type: ignore", "mypy: ignore-errors", "mypy: disable-error-code"},
        "pyright": {"type: ignore", "pyright: ignore", "pyright: basic"},
        "pyrefly": {"type: ignore"},
        "tsc": {"@ts-ignore", "@ts-expect-error", "@ts-nocheck"},
    }[checker]
    relevant = [item for item in found if item.directive.name in names]
    if checker in {"tsc", "pyrefly"}:
        relevant.extend(_additional_suppressions(comparison, checker, root))
    diagnostics = []
    for item in relevant:
        if item.in_test or item.generated:
            continue
        try:
            file = (
                (Path(comparison.root) / item.path)
                .resolve()
                .relative_to(root)
                .as_posix()
            )
        except ValueError:
            continue
        escape = item.directive.name == "assertion to any"
        diagnostics.append(
            {
                "file": file,
                "line": item.directive.line,
                "column": getattr(item.directive, "column", 1),
                "code": "type-escape" if escape else "type-suppression",
                "message": "New TypeScript assertion to any bypasses type checking"
                if escape
                else "New compiler suppression added: " + item.directive.name,
                "severity": "error",
                "origin": "introduced",
                "source": "suppression_guard",
            }
        )
    return sorted(
        diagnostics,
        key=lambda item: (item["file"], item["line"], item["column"], item["code"]),
    )
