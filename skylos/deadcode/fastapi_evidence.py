"""Reconcile FastAPI hints with source-proven registration evidence."""

from __future__ import annotations

import ast
from collections import Counter
from fnmatch import fnmatch
from pathlib import Path

from skylos.deadcode.python_ast import parse_python_files
from skylos.visitors.framework_aware import FRAMEWORK_DECORATORS


def definition_site(definition):
    return str(Path(definition.filename).resolve()), definition.line


def _other_decorators(definition, report):
    node = getattr(definition, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    sites = getattr(report, "decorator_sites", set())
    filename = str(Path(definition.filename).resolve())
    callback = report.project.callable(definition.name)
    for decorator in node.decorator_list:
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        site = filename, node.lineno, decorator.lineno, decorator.col_offset
        if isinstance(sites, dict) and sites:
            managed_nodes = sites.get(definition_site(definition), ())
            if any(
                item.lineno == decorator.lineno
                and item.col_offset == decorator.col_offset
                for item in managed_nodes
            ):
                continue
        elif sites:
            if site in sites:
                continue
        provider = (
            report.project.resolve(expression, callback.bindings, callback.module)
            if callback is not None
            else None
        )
        yield expression, provider


def _independent_framework_decorator(definition, report):
    for expression, provider in _other_decorators(definition, report):
        spellings = ["@" + ast.unparse(expression)]
        if isinstance(provider, str):
            spellings.append("@" + provider)
        if any(
            fnmatch(spelling, pattern)
            for spelling in spellings
            for pattern in FRAMEWORK_DECORATORS
        ):
            return True
    return False


def _opaque_decorator(definition, report):
    transparent = {
        "builtins.staticmethod",
        "builtins.classmethod",
        "contextlib.contextmanager",
        "contextlib.asynccontextmanager",
    }
    return any(
        provider not in transparent
        and not (
            isinstance(expression, ast.Name)
            and expression.id in {"staticmethod", "classmethod"}
            and provider is None
        )
        for expression, provider in _other_decorators(definition, report)
    )


def reconcile_fastapi_evidence(definitions, file_contexts, refs, files, root):
    """Keep declaration hints separate from actual execution and signatures."""
    relevant = any(
        "fastapi" in getattr(flags, "detected_frameworks", ())
        or getattr(flags, "dependency_injected_params", ())
        or getattr(flags, "dependency_alias_names", ())
        or getattr(flags, "framework_decorated_lines", ())
        for _defs, _tests, flags, _file, _module, _config in file_contexts
    )
    if not relevant:
        return None
    from skylos.deadcode.fastapi_dependency_proofs import collect_fastapi_dependencies
    from skylos.deadcode.fastapi_hook_proofs import collect_fastapi_hooks
    from skylos.deadcode.fastapi_liveness import (
        FastAPIAnalysisLimit,
        collect_fastapi_liveness,
    )

    python_files = [
        Path(file) for file in files if Path(file).suffix in {".py", ".pyi"}
    ]
    parsed = parse_python_files(python_files)
    report = collect_fastapi_liveness(definitions, parsed, Path(root).resolve())
    if not report.complete:
        return report
    try:
        collect_fastapi_hooks(report.project, report)
        collect_fastapi_dependencies(report.project, report)
    except FastAPIAnalysisLimit as error:
        return report.project.incomplete(str(error))

    candidates = set(report.candidates)
    roots = set(report.roots)
    uncertain = set(getattr(report, "uncertain", ()))
    independent = set()
    opaque = set()
    try:
        for definition in definitions.values():
            if definition.type not in {"function", "method", "class"}:
                continue
            site = definition_site(definition)
            if site not in candidates:
                continue
            if _independent_framework_decorator(definition, report):
                independent.add(site)
            elif site not in roots and _opaque_decorator(definition, report):
                opaque.add(site)
    except FastAPIAnalysisLimit as error:
        return report.project.incomplete(str(error))
    report.independent_framework_sites = independent
    uncertain.update(opaque)
    report.uncertain.update(opaque)
    discarded_refs = Counter()
    for definition in definitions.values():
        if definition.type not in {"function", "method", "class"}:
            continue
        site = definition_site(definition)
        if site not in candidates:
            continue
        if site in independent:
            continue
        definition._fastapi_inactive = site not in roots and site not in uncertain
        if site in uncertain and site not in roots:
            definition.references = max(1, definition.references)
            definition.heuristic_refs["unresolved_callback"] = 1.0
        if site not in roots and site not in uncertain:
            discarded_refs[definition.name, str(definition.filename)] += getattr(
                definition, "_framework_decorator_ref_count", 0
            )

    if discarded_refs:
        retained = []
        for reference in refs:
            key = reference[0], str(reference[1])
            if discarded_refs[key]:
                discarded_refs[key] -= 1
            else:
                retained.append(reference)
        refs[:] = retained

    injected = set(getattr(report, "injected_parameters", ()))
    callback_parameters = set(getattr(report, "callback_parameters", ()))
    for _defs, _test_flags, flags, file, _module, _config in file_contexts:
        filename = str(Path(file).resolve())
        if Path(file).suffix not in {".py", ".pyi"}:
            continue
        managed = {line for path, line in candidates - independent if path == filename}
        proven = {line for path, line in roots if path == filename}
        flags.framework_decorated_lines.difference_update(managed)
        flags.framework_decorated_lines.update(proven)
        flags.fastapi_candidate_lines = managed
        flags.fastapi_dependency_parameters = {
            (line, name) for path, line, name in injected if path == filename
        }
        flags.fastapi_callback_parameters = {
            (line, name) for path, line, name in callback_parameters if path == filename
        }
    return report


def suppress_synthetic_fastapi_execution(definition, report):
    """A callable passed to a dependency marker has not thereby been called."""
    if not report.complete:
        return False
    site = definition_site(definition)
    if site not in report.candidates or site in report.roots:
        return False
    if site in getattr(report, "independent_framework_sites", ()):
        return False
    return site not in getattr(report.project, "executed_callables", ())
