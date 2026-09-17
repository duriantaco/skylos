"""Narrow, static evidence for literal paths supplied directly by pytest.

This does not import pytest, evaluate decorators, inspect conftest files, or
claim that arbitrary test parameters are trusted. Unsupported syntax supplies
no evidence; the caller keeps its ordinary parameter taint.
"""

from __future__ import annotations

import ast
from pathlib import PurePosixPath, PureWindowsPath


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_MAX_ROWS = 256
_MAX_NAMES = 32
_MAX_PATH_LENGTH = 4096
_ARGUMENTS = ("argnames", "argvalues", "indirect", "ids", "scope")
_PYTEST_CALLS = {
    "pytest.param",
    "pytest.fixture",
    "pytest.yield_fixture",
    "pytest.raises",
    "pytest.warns",
    "pytest.deprecated_call",
    "pytest.approx",
    "pytest.fail",
    "pytest.skip",
    "pytest.xfail",
    "pytest.importorskip",
    "pytest.register_assert_rewrite",
}
_UNSUPPORTED_FLOW = (
    ast.If,
    ast.IfExp,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.AugAssign,
    ast.NamedExpr,
    ast.Lambda,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
    ast.Global,
    ast.Nonlocal,
    ast.Import,
    ast.ImportFrom,
)


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _import_name(node: ast.Import | ast.ImportFrom, item: ast.alias) -> str:
    return item.asname or (
        item.name.split(".", 1)[0] if isinstance(node, ast.Import) else item.name
    )


def _is_mark(name: str) -> bool:
    parts = name.split(".")
    return (
        len(parts) == 3
        and parts[:2] == ["pytest", "mark"]
        and not parts[2].startswith("_")
    )


def _pytest_imports(tree: ast.Module) -> dict[str, str]:
    imports: dict[str, tuple[str, ast.AST]] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "pytest":
                    imports[alias.asname or alias.name] = ("pytest", alias)
        elif (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "pytest"
        ):
            for alias in statement.names:
                if alias.name in {"mark", "param"}:
                    imports[alias.asname or alias.name] = (
                        f"pytest.{alias.name}",
                        alias,
                    )

    if not imports:
        return {}
    qualified_imports = {name: value for name, (value, _) in imports.items()}
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    invalid: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = _import_name(node, alias)
                if name == "*":
                    return {}
                if name in imports and imports[name][1] is not alias:
                    invalid.add(name)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.ExceptHandler)):
            invalid.add(node.name or "")
        elif isinstance(node, ast.arg):
            invalid.add(node.arg)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            invalid.add(node.name or "")
        elif isinstance(node, ast.MatchMapping):
            invalid.add(node.rest or "")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            invalid.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            invalid.add(_name(node).split(".", 1)[0])
        elif isinstance(node, ast.Name) and node.id in imports:
            # Do not trust an API that escapes through an alias or call argument.
            expression: ast.AST = node
            parent = parents.get(expression)
            while isinstance(parent, ast.Attribute) and parent.value is expression:
                expression, parent = parent, parents.get(parent)
            qualified = _resolved(expression, qualified_imports)
            known_call = (
                isinstance(parent, ast.Call)
                and parent.func is expression
                and (qualified in _PYTEST_CALLS or _is_mark(qualified))
            )
            bare_decorator = (
                isinstance(parent, (*_FUNCTIONS, ast.ClassDef))
                and expression in parent.decorator_list
                and (
                    qualified in {"pytest.fixture", "pytest.yield_fixture"}
                    or _is_mark(qualified)
                )
            )
            if not (known_call or bare_decorator):
                return {}
    # All import spellings can refer to the same mutable pytest objects.
    if invalid.intersection(imports):
        return {}
    return qualified_imports


def _resolved(node: ast.AST, imports: dict[str, str]) -> str:
    name = _name(node)
    root, _, suffix = name.partition(".")
    if root not in imports:
        return ""
    return f"{imports[root]}.{suffix}" if suffix else imports[root]


def _relative_path(node: ast.AST) -> bool:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    value = node.value
    if not value or len(value) > _MAX_PATH_LENGTH or "\x00" in value:
        return False
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    return not (
        posix.is_absolute()
        or windows.drive
        or windows.root
        or ".." in posix.parts
        or ".." in windows.parts
        or value in {".", "./", ".\\"}
    )


def _names(node: ast.AST) -> tuple[list[str], bool] | None:
    scalar_rows = False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        names = [part.strip() for part in node.value.split(",")]
        scalar_rows = len(names) == 1
    elif isinstance(node, (ast.List, ast.Tuple)):
        if not all(
            isinstance(item, ast.Constant) and isinstance(item.value, str)
            for item in node.elts
        ):
            return None
        names = [item.value for item in node.elts]
    else:
        return None
    if (
        not names
        or len(names) > _MAX_NAMES
        or len(names) != len(set(names))
        or any(not name.isidentifier() for name in names)
    ):
        return None
    return names, scalar_rows


def _literal_metadata(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool, type(None)))
    return isinstance(node, (ast.List, ast.Tuple)) and all(
        isinstance(item, ast.Constant)
        and isinstance(item.value, (str, int, float, bool, type(None)))
        for item in node.elts
    )


def _parameters(
    decorator: ast.Call, imports: dict[str, str]
) -> tuple[set[str], set[str]] | None:
    if len(decorator.args) > len(_ARGUMENTS):
        return None
    arguments = dict(zip(_ARGUMENTS, decorator.args))
    for keyword in decorator.keywords:
        if keyword.arg not in _ARGUMENTS or keyword.arg in arguments:
            return None
        arguments[keyword.arg] = keyword.value
    if "argnames" not in arguments or "argvalues" not in arguments:
        return None
    parsed = _names(arguments["argnames"])
    rows = arguments["argvalues"]
    if parsed is None or not isinstance(rows, (ast.List, ast.Tuple)):
        return None
    names, scalar_rows = parsed
    if not rows.elts or len(rows.elts) > _MAX_ROWS:
        return None
    for metadata in ("ids", "scope"):
        if metadata in arguments and not _literal_metadata(arguments[metadata]):
            return None

    indirect = arguments.get("indirect")
    if indirect is None or (
        isinstance(indirect, ast.Constant) and indirect.value is False
    ):
        blocked: set[str] = set()
    elif isinstance(indirect, ast.Constant) and indirect.value is True:
        blocked = set(names)
    elif isinstance(indirect, (ast.List, ast.Tuple)) and all(
        isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value in names
        for item in indirect.elts
    ):
        blocked = {item.value for item in indirect.elts}
    else:
        return None

    trusted = set(names) - blocked
    for row in rows.elts:
        if isinstance(row, ast.Call) and _resolved(row.func, imports) == "pytest.param":
            if (
                any(
                    keyword.arg != "id"
                    or not isinstance(keyword.value, ast.Constant)
                    or not isinstance(keyword.value.value, (str, type(None)))
                    for keyword in row.keywords
                )
                or len(row.keywords) > 1
            ):
                return None
            values = row.args
        elif scalar_rows:
            values = [row]
        elif isinstance(row, (ast.List, ast.Tuple)):
            values = row.elts
        else:
            return None
        if len(values) != len(names) or any(
            isinstance(value, ast.Starred) for value in values
        ):
            return None
        trusted.intersection_update(
            name for name, value in zip(names, values) if _relative_path(value)
        )
    return set(names), trusted


def _straight_line_body(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for statement in fn.body:
        for node in ast.walk(statement):
            # The shared taint visitor does not merge these aliases/bindings.
            # Keep the old conservative parameter taint rather than guessing.
            if isinstance(node, (*_UNSUPPORTED_FLOW, *_FUNCTIONS, ast.ClassDef)):
                return False
            if type(node).__name__ == "TryStar":
                return False
            if isinstance(node, (ast.With, ast.AsyncWith)) and any(
                item.optional_vars is not None for item in node.items
            ):
                return False
            if isinstance(node, ast.Assign) and any(
                not isinstance(target, ast.Name) for target in node.targets
            ):
                return False
            if isinstance(node, ast.AnnAssign) and not isinstance(
                node.target, ast.Name
            ):
                return False
    return True


def literal_path_parameters(tree: ast.Module) -> dict[ast.AST, frozenset[str]]:
    """Return proof only for direct, non-rebound literal pytest parameters."""
    imports = _pytest_imports(tree)
    if not imports:
        return {}
    loaded_names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    result: dict[ast.AST, frozenset[str]] = {}
    for fn in tree.body:
        if (
            not isinstance(fn, _FUNCTIONS)
            or not fn.name.startswith("test_")
            or fn.name in loaded_names
            or not fn.decorator_list
            or not _straight_line_body(fn)
        ):
            continue
        trusted: set[str] = set()
        seen: set[str] = set()
        for decorator in fn.decorator_list:
            if (
                not isinstance(decorator, ast.Call)
                or _resolved(decorator.func, imports) != "pytest.mark.parametrize"
            ):
                break
            parsed = _parameters(decorator, imports)
            if parsed is None or seen.intersection(parsed[0]):
                break
            names, safe_names = parsed
            seen.update(names)
            trusted.update(safe_names)
        else:
            rebound = {
                node.id
                for statement in fn.body
                for node in ast.walk(statement)
                if isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
            }
            result[fn] = frozenset(trusted - rebound)
    return result
