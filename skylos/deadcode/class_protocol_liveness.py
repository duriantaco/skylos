"""Class members a documented third-party base class reads by name.

* ``twisted.web.resource.Resource.render`` dispatches a request to
  ``render_<METHOD>`` and the site traversal calls ``getChild``.
* ``distutils``/``setuptools`` ``Command`` option parsing reads
  ``user_options``, ``boolean_options``, ``negative_opt`` and ``description``
  from the command class and calls its three lifecycle methods.
* pydantic reads the inner ``Config`` class of a model or settings class.

Only classes that derive from the named base, directly or through project
classes, qualify; the same member on any other class stays ordinary code.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Sequence

from skylos.deadcode.python_ast import ParsedPythonFile

_MAX_BASE_DEPTH = 16
_HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
_RESOURCE_BASES = frozenset(
    {
        "twisted.web.resource.Resource",
        "twisted.web.resource.IResource",
    }
)
_RESOURCE_METHODS = frozenset(
    {"render", "getChild", *(f"render_{method}" for method in _HTTP_METHODS)}
)
_COMMAND_BASES = frozenset(
    {
        "setuptools.Command",
        "distutils.cmd.Command",
        "distutils.core.Command",
        "setuptools._distutils.cmd.Command",
    }
)
_COMMAND_METHODS = frozenset({"initialize_options", "finalize_options", "run"})
_COMMAND_ATTRIBUTES = frozenset(
    {"user_options", "boolean_options", "negative_opt", "description"}
)
_PYDANTIC_BASES = frozenset(
    {
        "pydantic.BaseModel",
        "pydantic.BaseSettings",
        "pydantic.main.BaseModel",
        "pydantic.env_settings.BaseSettings",
        "pydantic.generics.GenericModel",
        "pydantic.v1.BaseModel",
        "pydantic.v1.BaseSettings",
        "pydantic_settings.BaseSettings",
        "pydantic_settings.main.BaseSettings",
        "sqlmodel.SQLModel",
    }
)


def _resolved(path: Any, cache: dict[str, str]) -> str:
    text = str(path)
    key = cache.get(text)
    if key is None:
        try:
            key = str(Path(text).resolve())
        except OSError:
            key = text
        cache[text] = key
    return key


def _inherited_bases(name: str, classes: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    pending = [(name, 0)]
    seen = set()
    while pending:
        current, depth = pending.pop()
        if current in seen or depth > _MAX_BASE_DEPTH:
            continue
        seen.add(current)
        class_def = classes.get(current)
        if class_def is None:
            continue
        for base in getattr(class_def, "base_classes", None) or ():
            if not isinstance(base, str):
                continue
            found.add(base)
            pending.append((base, depth + 1))
    return found


def _import_origins(tree: ast.Module) -> dict[str, set[str]]:
    origins: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    origins.setdefault(alias.asname or alias.name, set()).add(
                        f"{node.module}.{alias.name}"
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    origins.setdefault(alias.asname, set()).add(alias.name)
                else:
                    head = alias.name.split(".", 1)[0]
                    origins.setdefault(head, set()).add(head)
    return origins


def _source_bases(node: ast.ClassDef, origins: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    for base in node.bases:
        expression = base
        if isinstance(expression, ast.Subscript):
            expression = expression.value
        attrs = []
        while isinstance(expression, ast.Attribute):
            attrs.append(expression.attr)
            expression = expression.value
        if not isinstance(expression, ast.Name):
            continue
        attrs.reverse()
        for origin in origins.get(expression.id, ()):
            found.add(".".join([origin, *attrs]))
    return found


def find_class_protocol_members(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
) -> list[Any]:
    classes: dict[str, Any] = {}
    by_line: dict[tuple[str, int], list[Any]] = {}
    resolved: dict[str, str] = {}
    for defn in definitions.values():
        kind = getattr(defn, "type", None)
        if kind not in {"class", "method", "function", "variable"}:
            continue
        if kind == "class":
            classes.setdefault(str(getattr(defn, "name", "")), defn)
        key = (_resolved(getattr(defn, "filename", ""), resolved), defn.line)
        by_line.setdefault(key, []).append(defn)

    bases_cache: dict[str, set[str]] = {}

    def bases_of(name: str) -> set[str]:
        cached = bases_cache.get(name)
        if cached is None:
            cached = _inherited_bases(name, classes)
            bases_cache[name] = cached
        return cached

    def members(file_key: str, line: int, kinds: set[str], name: str) -> list[Any]:
        return [
            defn
            for defn in by_line.get((file_key, line), ())
            if defn.type in kinds and getattr(defn, "simple_name", "") == name
        ]

    targets: list[Any] = []
    for parsed in parsed_files:
        file_key = _resolved(parsed.path, resolved)
        origins = None
        for node in ast.walk(parsed.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if origins is None:
                origins = _import_origins(parsed.tree)
            bases = _source_bases(node, origins)
            for class_def in members(file_key, node.lineno, {"class"}, node.name):
                for base in getattr(class_def, "base_classes", None) or ():
                    if isinstance(base, str):
                        bases.add(base)
            for base in list(bases):
                bases |= bases_of(base)
            method_names: frozenset[str] = frozenset()
            attribute_names: frozenset[str] = frozenset()
            if bases & _RESOURCE_BASES:
                method_names |= _RESOURCE_METHODS
            if bases & _COMMAND_BASES:
                method_names |= _COMMAND_METHODS
                attribute_names |= _COMMAND_ATTRIBUTES
            reads_config = bool(bases & _PYDANTIC_BASES)
            if not method_names and not attribute_names and not reads_config:
                continue
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if child.name in method_names:
                        targets.extend(
                            members(
                                file_key,
                                child.lineno,
                                {"method", "function"},
                                child.name,
                            )
                        )
                elif isinstance(child, ast.ClassDef):
                    if reads_config and child.name == "Config":
                        targets.extend(
                            members(file_key, child.lineno, {"class"}, child.name)
                        )
                elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                    if isinstance(child, ast.Assign):
                        assigned = child.targets
                    else:
                        assigned = [child.target]
                    for target in assigned:
                        if (
                            isinstance(target, ast.Name)
                            and target.id in attribute_names
                        ):
                            targets.extend(
                                members(file_key, child.lineno, {"variable"}, target.id)
                            )
    return targets
