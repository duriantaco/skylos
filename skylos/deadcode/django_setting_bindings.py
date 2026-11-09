"""Selected source bindings behind Django's named settings imports."""

from __future__ import annotations

import ast
from copy import copy

from skylos.deadcode.framework_liveness import _bound_names


def collect_setting_bindings(statements, module, package, resolve_from_module):
    """Final possible import/alias sources, without treating readers as settings."""

    def origins(value, bindings):
        if isinstance(value, ast.Name):
            return {
                (module, value.id) if source is None else source
                for source in bindings.get(value.id, {None})
            }
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            return {
                (source[0], value.attr)
                for source in bindings.get(value.value.id, ())
                if source is not None and source[1] is None
            } or {None}
        return {None}

    def join(*branches):
        names = set().union(*(branch.keys() for branch in branches))
        return {
            name: set().union(*(branch.get(name, {None}) for branch in branches))
            for name in names
        }

    def suite(body, bindings):
        for statement in body:
            if isinstance(statement, ast.If):
                if isinstance(statement.test, ast.Constant):
                    selected = (
                        statement.body if statement.test.value else statement.orelse
                    )
                    bindings = suite(selected, bindings)
                else:
                    bindings = join(
                        suite(statement.body, bindings.copy()),
                        suite(statement.orelse, bindings.copy()),
                    )
                continue
            if isinstance(statement, (ast.Try, ast.TryStar)):
                branches = [
                    suite(statement.orelse, suite(statement.body, bindings.copy()))
                ]
                branches.extend(
                    suite(handler.body, bindings.copy())
                    for handler in statement.handlers
                )
                bindings = suite(statement.finalbody, join(*branches))
                continue
            if isinstance(statement, ast.ImportFrom):
                source = resolve_from_module(statement, package)
                if source:
                    for alias in statement.names:
                        if alias.name != "*":
                            bindings[alias.asname or alias.name] = {
                                (source, alias.name)
                            }
                continue
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    source = alias.name if alias.asname else alias.name.split(".")[0]
                    bindings[alias.asname or source] = {(source, None)}
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if value is None:
                    continue
                selected = origins(value, bindings)
                for name in _bound_names(statement):
                    bindings[name] = selected.copy()
                continue
            if isinstance(statement, ast.Delete):
                for name in _bound_names(statement):
                    bindings[name] = set()
                continue
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bindings[statement.name] = {None}
                continue
            if isinstance(
                statement, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)
            ):
                possible = bindings.copy()
                for name in _bound_names(statement):
                    possible[name] = {None}
                bindings = join(bindings, suite(statement.body, possible))
                bindings = suite(getattr(statement, "orelse", ()), bindings)
                continue
            for name in _bound_names(statement):
                bindings[name] = {None}
            if isinstance(statement, (ast.Return, ast.Raise)):
                break
        return bindings

    return {
        name: sources
        for name, sources in suite(statements, {}).items()
        if name.isupper()
    }


def _setting_view(scanner, source_name, role):
    view = copy(scanner)
    view.values = {}
    if source_name in scanner.values:
        view.values[role] = scanner.values[source_name]
    view.module_settings = {role: scanner.module_settings.get(source_name, ())}
    view.setting_mutations = {role: scanner.setting_mutations.get(source_name, ())}
    view.value_contexts = {}
    if source_name in scanner.value_contexts:
        view.value_contexts[role] = scanner.value_contexts[source_name]
    view.setting_bindings = {}
    view.setting_source_names = {role: source_name}
    if source_name == role == "AUTHENTICATION_BACKENDS":
        return view
    view.authentication_backend_assignments = list(
        view.module_settings.get("AUTHENTICATION_BACKENDS", ())
    )
    view.authentication_backend_mutations = [
        (value, (value.lineno, value.col_offset))
        for value in view.setting_mutations.get("AUTHENTICATION_BACKENDS", ())
    ]
    view.authentication_backend_invalidations = []
    return view


def selected_setting_views(settings, scanners):
    """Project settings roles onto only the source values actually imported."""
    views = []
    emitted = set()

    def select(module, name, role, trail):
        key = module, name
        if key in trail or module not in scanners:
            return
        scanner = scanners[module]
        bindings = getattr(scanner, "setting_bindings", {})
        sources = bindings.get(name, {None})
        if None in sources and (module, name, role) not in emitted:
            emitted.add((module, name, role))
            views.append(_setting_view(scanner, name, role))
        for source in sources:
            if source is not None and source[1] is not None:
                select(*source, role, trail | {key})

    for module in sorted(settings):
        scanner = scanners.get(module)
        if scanner is None:
            continue
        names = (
            set(scanner.values)
            | set(scanner.module_settings)
            | set(getattr(scanner, "setting_bindings", {}))
        )
        for name in sorted(names):
            if name.isupper():
                select(module, name, name, set())
    return views
