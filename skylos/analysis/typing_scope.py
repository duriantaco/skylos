"""Project evidence for typing advice in custom pytest support packages."""

from collections import deque
from pathlib import Path

from skylos.analysis.circular_deps import _import_targets
from skylos.rules.quality._typing import is_typing_test_path


def scope_typing_findings(
    findings, modmap, raw_imports, project_root, *, production_modules=()
):
    """Exclude test-only helpers reached inside a non-root conftest suite.

    A directory name such as t is not proof. Require a discovered conftest,
    an import path from that suite, and no production import into the helper
    or its dependency chain. Shared helpers, entrypoints and modules a
    non-test package ``__init__`` imports retain typing advice. This scope
    applies only to T101/T102; it never filters security findings.
    """
    root = Path(project_root)
    modules = {module: Path(file) for file, module in modmap.items()}
    boundaries = {
        file.parent
        for file in modules.values()
        if file.name == "conftest.py" and file.parent != root
    }
    if not boundaries:
        return findings
    candidates = {
        name
        for name, file in modules.items()
        if any(file.is_relative_to(boundary) for boundary in boundaries)
    }
    known = set(modules)
    graph = {name: set() for name in known}
    for file, imports in raw_imports.items():
        name = modmap.get(file, modmap.get(str(file)))
        if name not in graph:
            continue
        for imported, _line, kind, names in imports:
            graph[name].update(_import_targets(imported, kind, names, known))
    seeds = {name for name in candidates if is_typing_test_path(modules[name], root)}

    def reachable(initial):
        found = set(initial)
        queue = deque(initial)
        while queue:
            for target in graph[queue.popleft()] & candidates:
                if target not in found:
                    found.add(target)
                    queue.append(target)
        return found

    test_only = reachable(seeds)
    explicit_production = set(production_modules) | {
        name for name, file in modules.items() if file.name == "__main__.py"
    }
    # A package __init__ is the package's import-time surface: whatever it
    # imports runs for every importer, so it is library code even when a
    # conftest inside that package (pkg/conftest.py) also reaches it.
    explicit_production |= {
        name
        for name in candidates
        if modules[name].name in {"__init__.py", "__init__.pyi"}
        and not is_typing_test_path(modules[name], root)
    }
    shared = {
        target
        for source, targets in graph.items()
        if (source not in test_only or source in explicit_production)
        and not is_typing_test_path(modules[source], root)
        for target in targets & candidates
    }
    test_only.difference_update(reachable(shared | explicit_production & candidates))
    paths = {str(modules[name]) for name in test_only}
    return [
        finding
        for finding in findings
        if finding.get("rule_id") not in {"SKY-T101", "SKY-T102"}
        or str(finding.get("file")) not in paths
    ]
