"""Project credential-use evidence from static Python import bindings."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from skylos.analysis.circular_deps import _absolute_from_module
from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.file_worker import _parse_python_source, _read_python_source
from skylos.config import load_config
from skylos.rules.quality.logic_security import (
    HardcodedCredentialRule,
    _credential_literal_sources,
    _resolved_builtin_getattr_calls,
)
from skylos.rules.vibe_dictionary import build_vibe_dictionary


def collect_project_credential_sources(
    files, modmap, *, project_root=None, config_file=None, analysis_errors=None
):
    """Return literal locations that can reach credential arguments.

    Parse each discovered Python source once, construct its lexical resolver
    once, and query imported exports through those resolvers. No project code
    is imported or executed. Unknown imports provide no credential evidence.
    """
    modules = defaultdict(list)
    literals = {}
    scans = []
    errors = analysis_errors if analysis_errors is not None else []
    resolutions = {}
    active = set()
    depth_error_reported = False

    def resolve_qualified(parts, constructor_sources=None):
        nonlocal depth_error_reported
        if len(active) >= 32:
            if not depth_error_reported:
                errors.append(
                    analysis_error_payload(
                        project_root or ".",
                        RuntimeError(
                            "Credential import resolution exceeded 32 modules"
                        ),
                        kind="credential_source_analysis",
                    )
                )
                depth_error_reported = True
            return set()
        for stop in range(len(parts), 0, -1):
            module = ".".join(parts[:stop])
            if module not in modules:
                continue
            suffix = tuple(parts[stop:])
            if not suffix:
                return set()
            query = (module, suffix, constructor_sources)
            if query in resolutions:
                return resolutions[query]
            if query in active:
                return set()
            active.add(query)
            try:
                result = set()
                for export in modules[module]:
                    result.update(
                        export(suffix, constructor_sources=constructor_sources)
                    )
            finally:
                active.remove(query)
            resolutions[query] = result
            return result
        return set()

    def import_resolver(module_name, file):
        def resolve_import(statement, local_name, suffix, constructor_sources=None):
            result = set()
            for alias in statement.names:
                bound = alias.asname or (
                    alias.name.split(".")[0]
                    if isinstance(statement, ast.Import)
                    else alias.name
                )
                if bound != local_name or alias.name == "*":
                    continue
                if isinstance(statement, ast.Import):
                    origin = alias.name if alias.asname else alias.name.split(".")[0]
                else:
                    origin = _absolute_from_module(statement, module_name, file)
                    if not origin:
                        continue
                    origin = f"{origin}.{alias.name}"
                result.update(
                    resolve_qualified(
                        (*origin.split("."), *suffix), constructor_sources
                    )
                )
            return result

        return resolve_import

    for file in files:
        file = Path(file)
        if file.suffix not in {".py", ".pyi", ".pyw"}:
            continue
        module_name = modmap.get(file, modmap.get(str(file), ""))
        if not module_name:
            continue
        try:
            cfg = load_config(file, config_file=config_file)
            rule = HardcodedCredentialRule(build_vibe_dictionary(cfg.get("vibe")))
            source = _read_python_source(file, project_root)
            tree = _parse_python_source(source, file)
            absolute = str(file.absolute())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    literals[id(node)] = (absolute, node.lineno, node.col_offset)

            def register(scan, export, module=module_name, filename=absolute):
                scans.append((filename, scan))
                modules[module].append(export)

            _credential_literal_sources(
                tree,
                rule._credential_keyword,
                _resolved_builtin_getattr_calls(tree),
                imported_sources=import_resolver(module_name, absolute),
                resolver_callback=register,
            )
        except Exception as error:
            errors.append(
                analysis_error_payload(file, error, kind="credential_source_analysis")
            )

    used = set()
    for file, scan in scans:
        try:
            used.update(scan())
        except Exception as error:
            errors.append(
                analysis_error_payload(file, error, kind="credential_source_analysis")
            )
    locations = defaultdict(set)
    for literal in used:
        if literal in literals:
            file, line, column = literals[literal]
            locations[file].add((line, column))
    return {file: sorted(values) for file, values in locations.items()}
