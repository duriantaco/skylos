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
from skylos.deadcode._reachability_bindings import argument_nodes, bound_names

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


def _inherited_bases(name: str, classes: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    pending = [(name, 0)]
    seen = set()
    while pending:
        current, depth = pending.pop()
        if current in seen or depth > _MAX_BASE_DEPTH:
            continue
        seen.add(current)
        for base in classes.get(current, ()):
            found.add(base)
            pending.append((base, depth + 1))
    return found


def _scope_statements(scope):
    pending = list(reversed(scope.body))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(
            reversed(
                [
                    child
                    for child in ast.iter_child_nodes(node)
                    if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case))
                ]
            )
        )


def _import_origins(nodes, counts) -> dict[str, set[str]]:
    origins: dict[str, set[str]] = {}
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*" and counts[alias.asname or alias.name] == 1:
                    origins.setdefault(alias.asname or alias.name, set()).add(
                        f"{node.module}.{alias.name}"
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if counts[alias.asname or alias.name.split(".")[0]] != 1:
                    continue
                if alias.asname:
                    origins.setdefault(alias.asname, set()).add(alias.name)
                else:
                    head = alias.name.split(".", 1)[0]
                    origins.setdefault(head, set()).add(head)
    return origins


def _scoped_class_bases(tree, class_names):
    """Resolve a base in its lexical scope, invalidating any rebound name."""

    def walk(scope, inherited):
        nodes = list(_scope_statements(scope))
        counts = bound_names(scope.body).counts
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            counts.update(arg.arg for arg in argument_nodes(scope.args))
        wildcard = bool(counts["*"])
        origins = (
            {}
            if wildcard
            else {
                name: values for name, values in inherited.items() if not counts[name]
            }
        )
        if not wildcard:
            origins.update(_import_origins(nodes, counts))
        for node in nodes:
            if (
                not wildcard
                and isinstance(node, ast.ClassDef)
                and counts[node.name] == 1
            ):
                names = class_names.get((node.lineno, node.name), set())
                if len(names) == 1:
                    origins[node.name] = names
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                yield node, _source_bases(node, origins)
                yield from walk(node, origins)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Methods do not close over their class namespace.
                enclosing = inherited if isinstance(scope, ast.ClassDef) else origins
                yield from walk(node, enclosing)

    yield from walk(tree, {})


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
    classes: dict[str, set[str]] = {}
    by_line: dict[tuple[str, int], list[Any]] = {}
    resolved: dict[str, str] = {}
    for defn in definitions.values():
        kind = getattr(defn, "type", None)
        if kind not in {"class", "method", "function", "variable"}:
            continue
        key = (_resolved(getattr(defn, "filename", ""), resolved), defn.line)
        by_line.setdefault(key, []).append(defn)

    source_bases = []
    for parsed in parsed_files:
        file_key = _resolved(parsed.path, resolved)
        class_names = {}
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.ClassDef):
                names = {
                    defn.name
                    for defn in by_line.get((file_key, node.lineno), ())
                    if defn.type == "class" and defn.simple_name == node.name
                }
                class_names[node.lineno, node.name] = names
        for node, bases in _scoped_class_bases(parsed.tree, class_names):
            source_bases.append((file_key, node, bases))
            for name in class_names.get((node.lineno, node.name), ()):
                classes[name] = bases

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
    for file_key, node, direct_bases in source_bases:
        bases = set(direct_bases)
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
                    if isinstance(target, ast.Name) and target.id in attribute_names:
                        targets.extend(
                            members(file_key, child.lineno, {"variable"}, target.id)
                        )
    return targets
