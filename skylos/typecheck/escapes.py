"""New compiler escape hatches, only for opt-in comparable baseline checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from skylos.done import suppressions
from skylos.done.answer_sites import _is_generated, _is_test_code


_BRIDGE_TYPES = frozenset({"unknown", "never", "object", "{}"})
_TYPING_MODULES = frozenset({"typing", "typing_extensions"})
_ESCAPE_MESSAGES = {
    "assertion to any": "New TypeScript assertion to any bypasses type checking",
    "double assertion": "New double assertion bypasses type checking",
    "typing.cast": "New typing.cast asserts a type without checking it",
    "explicit any": "New explicit any removes type checking here; use unknown or a precise type",
}
_ADVISORY_MESSAGES = {
    "bare Any": "New bare Any annotation removes type checking here",
}


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
        _ASSERTION_TYPES,
        _assertion_parts,
        _normalized_type_node,
        _unwrap_value,
    )

    tree = _parse(path, text)
    if tree is None or tree.has_error:
        raise ValueError("TypeScript escape analysis could not parse " + path)
    source = text.encode("utf-8", errors="surrogatepass")
    declaration = path.endswith((".d.ts", ".d.mts", ".d.cts"))
    stack = [tree]
    found = []
    while stack:
        node = stack.pop()
        if (
            node.type == "predefined_type"
            and not declaration
            and source[node.start_byte : node.end_byte] == b"any"
            and not _is_assertion_target(node)
        ):
            found.append(
                _LocatedDirective(
                    node.start_point[0] + 1,
                    "explicit any",
                    "TypeScript",
                    (),
                    "line",
                    "",
                    "any",
                    node.start_point[1] + 1,
                )
            )
        parts = _assertion_parts(node, source)
        if parts is not None:
            name = None
            shown = ""
            if _normalized_type_node(parts[1], source) == "any":
                name, shown = "assertion to any", "as any"
            else:
                inner, _ = _unwrap_value(parts[0])
                if inner is not None and inner.type in _ASSERTION_TYPES:
                    inner_parts = _assertion_parts(inner, source)
                    if inner_parts is not None:
                        bridge = _normalized_type_node(inner_parts[1], source)
                        if bridge in _BRIDGE_TYPES:
                            name, shown = "double assertion", "as " + bridge + " as"
            if name is not None:
                found.append(
                    _LocatedDirective(
                        node.start_point[0] + 1,
                        name,
                        "TypeScript",
                        (),
                        "line",
                        "",
                        shown,
                        node.start_point[1] + 1,
                    )
                )
        stack.extend(reversed(node.named_children))
    return found


def _is_assertion_target(node) -> bool:
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_type":
        parent = parent.parent
    if parent is None:
        return False
    if parent.type == "as_expression":
        return True
    grandparent = parent.parent
    return (
        parent.type == "type_arguments"
        and grandparent is not None
        and grandparent.type == "type_assertion"
    )


def _python_assertions(text: str) -> list[_LocatedDirective]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    cast_names = set()
    any_names = set()
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module in _TYPING_MODULES:
                for alias in node.names:
                    if alias.name == "cast":
                        cast_names.add(alias.asname or alias.name)
                    elif alias.name == "Any":
                        any_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _TYPING_MODULES:
                    modules.add(alias.asname or alias.name)
    found = []

    def is_bare_any(annotation) -> bool:
        if isinstance(annotation, ast.Name):
            return annotation.id in any_names
        return (
            isinstance(annotation, ast.Attribute)
            and annotation.attr == "Any"
            and isinstance(annotation.value, ast.Name)
            and annotation.value.id in modules
        )

    for node in ast.walk(tree):
        annotations = []
        if isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
        elif isinstance(node, ast.arg):
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            annotations.append(node.returns)
        for annotation in annotations:
            if is_bare_any(annotation):
                found.append(
                    _LocatedDirective(
                        annotation.lineno,
                        "bare Any",
                        "the type checker",
                        (),
                        "line",
                        "",
                        "Any",
                        annotation.col_offset + 1,
                    )
                )
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_cast = isinstance(func, ast.Name) and func.id in cast_names
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "cast"
            and isinstance(func.value, ast.Name)
            and func.value.id in modules
        ):
            is_cast = True
        if is_cast:
            found.append(
                _LocatedDirective(
                    node.lineno,
                    "typing.cast",
                    "the type checker",
                    (),
                    "line",
                    "",
                    "cast(...)",
                    node.col_offset + 1,
                )
            )
    return found


def _signatures(tree: ast.AST) -> dict[str, tuple[int, int, dict[str, bool], bool]]:
    found = {}

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                args = child.args
                params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                for extra in (args.vararg, args.kwarg):
                    if extra is not None:
                        params.append(extra)
                annotated = {p.arg: p.annotation is not None for p in params}
                found[name] = (
                    child.lineno,
                    child.body[0].lineno,
                    annotated,
                    child.returns is not None,
                )
                visit(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _removed_annotations(comparison, root: Path) -> list[dict]:
    heads, _, base_texts, _ = suppressions._read_changed(comparison)
    base_of = {c.head_path: c.base_path for c in comparison.changed if c.head_path}
    found = []
    for path, (text, _, added) in sorted(heads.items()):
        base = base_texts.get(base_of.get(path) or "")
        if (
            not base
            or not path.endswith((".py", ".pyi"))
            or _is_test(path)
            or _is_generated(path, text)
        ):
            continue
        try:
            file = (Path(comparison.root) / path).resolve().relative_to(root).as_posix()
            before = _signatures(ast.parse(base))
            after = _signatures(ast.parse(text))
        except (ValueError, SyntaxError, RecursionError):
            continue
        for name, (line, body, params, returns) in sorted(after.items()):
            old = before.get(name)
            if old is None or not added.intersection(range(line, max(line + 1, body))):
                continue
            lost = [p for p, had in old[2].items() if had and params.get(p) is False]
            if old[3] and not returns:
                lost.append("return")
            if lost:
                found.append(
                    {
                        "path": path,
                        "file": file,
                        "line": line,
                        "column": 1,
                        "code": "type-escape",
                        "message": f"Type annotation removed from {name}: "
                        + ", ".join(lost),
                    }
                )
    return found


def _accepted_escapes(comparison) -> dict[tuple[str, str], str]:
    """Reviewed exceptions from the base commit: a session cannot add its own."""
    from skylos.done.base import DoneError
    from skylos.done.config import base_config_text, parse_done_config

    sha = getattr(comparison, "config_sha", None)
    if sha is None:
        return {}
    try:
        config = parse_done_config(base_config_text(comparison, sha=sha))
    except DoneError as exc:
        raise ValueError("Could not read the base commit's settings") from exc
    return {(file, line): reason for file, line, reason in config.type_escape_allow}


def _line_text(comparison, path: str, line: int) -> str:
    lines = (comparison.head_text(path) or "").splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def _additional_suppressions(comparison, checker: str, root: Path):
    heads, bases, base_texts, _ = suppressions._read_changed(comparison)

    def extract(path, text):
        if checker == "tsc":
            return _any_directives(path, text)
        found = _python_assertions(text)
        if checker == "pyrefly":
            found = [*_pyrefly_directives(text), *found]
        return found

    extensions = (".py", ".pyi")
    if checker == "tsc":
        extensions = (".ts", ".tsx", ".mts", ".cts")

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


def _escape_diagnostic(
    file, line, column, code, message, reason, severity="error"
) -> dict:
    if reason:
        severity = "info"
        message = f"{message} (accepted by the base commit: {reason})"
    return {
        "file": file,
        "line": line,
        "column": column,
        "code": code,
        "message": message,
        "severity": severity,
        "origin": "introduced",
        "source": "suppression_guard",
    }


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
    relevant.extend(_additional_suppressions(comparison, checker, root))
    accepted = _accepted_escapes(comparison)
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
        code = "type-suppression"
        severity = "error"
        message = "New compiler suppression added: " + item.directive.name
        if item.directive.name in _ESCAPE_MESSAGES:
            code = "type-escape"
            message = _ESCAPE_MESSAGES[item.directive.name]
        elif item.directive.name in _ADVISORY_MESSAGES:
            code = "type-widening"
            severity = "warning"
            message = _ADVISORY_MESSAGES[item.directive.name]
        diagnostics.append(
            _escape_diagnostic(
                file,
                item.directive.line,
                getattr(item.directive, "column", 1),
                code,
                message,
                accepted.get(
                    (item.path, _line_text(comparison, item.path, item.directive.line))
                ),
                severity,
            )
        )
    if checker != "tsc":
        for removal in _removed_annotations(comparison, root):
            diagnostics.append(
                _escape_diagnostic(
                    removal["file"],
                    removal["line"],
                    removal["column"],
                    removal["code"],
                    removal["message"],
                    accepted.get(
                        (
                            removal["path"],
                            _line_text(comparison, removal["path"], removal["line"]),
                        )
                    ),
                )
            )
    return sorted(
        diagnostics,
        key=lambda item: (item["file"], item["line"], item["column"], item["code"]),
    )
