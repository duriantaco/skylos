"""Find cycles between sibling Python packages using resolved import sites."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from skylos.analysis.circular_deps import ModuleDependency
from skylos.constants import is_test_path

PACKAGE_CYCLE_RULE_ID = "SKY-Q807"


def _production_modules(
    module_files: Mapping[str, str], project_root: Path | None
) -> dict[str, Path]:
    modules = {}
    for module, filename in module_files.items():
        path = Path(filename)
        relative = (
            path.relative_to(project_root)
            if project_root is not None and path.is_relative_to(project_root)
            else path
        )
        if (
            module
            and path.suffix == ".py"
            and not is_test_path(relative)
            and not path.name.startswith("test_")
            and path.name != "conftest.py"
        ):
            modules[module] = path
    return modules


def _sibling_packages(
    source: str, target: str, package_dirs: Mapping[str, Path]
) -> tuple[str, str] | None:
    source_parts, target_parts = source.split("."), target.split(".")
    for depth, (left, right) in enumerate(zip(source_parts, target_parts), 1):
        if left == right:
            continue
        source_package = ".".join(source_parts[:depth])
        target_package = ".".join(target_parts[:depth])
        source_dir = package_dirs.get(source_package)
        target_dir = package_dirs.get(target_package)
        if (
            source_dir is not None
            and target_dir is not None
            and source_dir != target_dir
            and source_dir.parent == target_dir.parent
        ):
            return source_package, target_package
        return None
    return None


def get_package_cycle_findings(
    module_files: Mapping[str, str],
    imports: Iterable[ModuleDependency],
    *,
    project_root: Path | None = None,
) -> list[dict]:
    """Report one finding for each mutually dependent group of sibling packages."""
    modules = _production_modules(module_files, project_root)
    package_dirs = {
        module: path.parent
        for module, path in modules.items()
        if path.name == "__init__.py"
    }
    sites = defaultdict(set)
    for dep in imports:
        source = modules.get(dep.from_module)
        target = modules.get(dep.to_module)
        if source is None or target is None or dep.import_line <= 0:
            continue
        siblings = _sibling_packages(dep.from_module, dep.to_module, package_dirs)
        if siblings is None:
            continue
        left, right = siblings
        if source.is_relative_to(package_dirs[left]) and target.is_relative_to(
            package_dirs[right]
        ):
            sites[siblings].add(
                (str(source), dep.import_line, dep.from_module, dep.to_module)
            )
    if not sites:
        return []

    import networkx as nx

    graph = nx.DiGraph(sites.keys())
    groups = sorted(
        sorted(component)
        for component in nx.strongly_connected_components(graph)
        if len(component) > 1
    )
    findings = []
    for members in groups:
        evidence = sorted(
            (*site, source, target)
            for source, target in graph.subgraph(members).edges()
            for site in sites[source, target]
        )
        findings.append(_package_cycle_finding(members, evidence))
    return findings


def _package_cycle_finding(
    members: list[str], evidence: list[tuple[str, int, str, str, str, str]]
) -> dict:
    file, line, *_ = evidence[0]
    return {
        "rule_id": PACKAGE_CYCLE_RULE_ID,
        "kind": "architecture",
        "type": "sibling_package_cycle",
        "name": ", ".join(members),
        "severity": "LOW",
        "message": f"Sibling packages depend on one another: {', '.join(members)}",
        "file": file,
        "line": line,
        "cycle_members": members,
        "dependency_edges": [
            {
                "from_module": source_module,
                "to_module": target_module,
                "from_package": source_package,
                "to_package": target_package,
                "file": path,
                "line": lineno,
            }
            for path, lineno, source_module, target_module, source_package, target_package in evidence
        ],
        "related_locations": [
            {
                "file": path,
                "start_line": lineno,
                "end_line": lineno,
                "message": f"{source_module} imports {target_module}",
            }
            for path, lineno, source_module, target_module, _, _ in evidence
        ],
    }
