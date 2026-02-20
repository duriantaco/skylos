"""
Rule IDs:
- SKY-Q801: High instability warning
- SKY-Q802: High distance from main sequence
- SKY-Q803: Zone of Pain / Zone of Uselessness warning
- SKY-Q804: Dependency Inversion Principle violation
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModuleMetrics:
    name: str
    file_path: str
    ca: int = 0
    ce: int = 0
    instability: float = 0.0
    abstractness: float = 0.0
    distance: float = 0.0
    zone: str = "healthy"
    total_classes: int = 0
    abstract_classes: int = 0
    total_functions: int = 0
    abstract_methods: int = 0
    type_vars: int = 0
    protocols: int = 0
    loc: int = 0

    @property
    def total_coupling(self) -> int:
        return self.ca + self.ce


@dataclass
class DIPViolation:
    stable_module: str
    unstable_module: str
    stable_instability: float
    unstable_instability: float
    severity: str = "MEDIUM"


@dataclass
class ArchitectureResult:
    modules: dict[str, ModuleMetrics] = field(default_factory=dict)
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)
    dip_violations: list[DIPViolation] = field(default_factory=list)
    system_metrics: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)


def _compute_abstractness(tree: ast.AST) -> dict[str, Any]:
    total_classes = 0
    abstract_classes = 0
    total_functions = 0
    abstract_methods = 0
    type_vars = 0
    protocols = 0
    has_type_checking = False

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            total_classes += 1
            is_abstract = False
            is_protocol = False

            for base in node.bases:
                if isinstance(base, ast.Name):
                    if base.id in ("ABC", "ABCMeta"):
                        is_abstract = True
                    elif base.id == "Protocol":
                        is_protocol = True
                elif isinstance(base, ast.Attribute):
                    if base.attr in ("ABC", "ABCMeta"):
                        is_abstract = True
                    elif base.attr == "Protocol":
                        is_protocol = True

            if is_abstract:
                abstract_classes += 1
            if is_protocol:
                protocols += 1
                abstract_classes += 1

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in item.decorator_list:
                        if isinstance(dec, ast.Name) and dec.id == "abstractmethod":
                            abstract_methods += 1
                        elif isinstance(dec, ast.Attribute) and dec.attr == "abstractmethod":
                            abstract_methods += 1

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            total_functions += 1

        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "TypeVar":
                    type_vars += 1
                elif isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "TypeVar":
                    type_vars += 1

        elif isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                has_type_checking = True
            elif isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING":
                has_type_checking = True

    total_elements = total_classes + total_functions
    abstract_elements = abstract_classes

    if total_elements > 0:
        base_abstractness = abstract_elements / total_elements
    else:
        base_abstractness = 0.0

    type_var_bonus = min(0.1, type_vars * 0.02)
    if has_type_checking:
        type_checking_bonus = 0.05
    else:
        type_checking_bonus = 0.0

    abstractness = min(1.0, base_abstractness + type_var_bonus + type_checking_bonus)

    return {
        "abstractness": abstractness,
        "total_classes": total_classes,
        "abstract_classes": abstract_classes,
        "total_functions": total_functions,
        "abstract_methods": abstract_methods,
        "type_vars": type_vars,
        "protocols": protocols,
    }


def _classify_zone(abstractness: float, instability: float) -> str:
    if abstractness > 0.7 and instability < 0.3:
        return "zone_of_pain"

    if abstractness < 0.3 and instability > 0.7:
        return "zone_of_uselessness"

    distance = abs(abstractness + instability - 1.0)
    if distance <= 0.2:
        return "main_sequence"

    return "healthy"


def analyze_architecture(
    dependency_graph: dict[str, set[str]],
    module_files: dict[str, str],
    module_trees: dict[str, ast.AST] | None = None,
) -> ArchitectureResult:
    
    result = ArchitectureResult()

    all_modules = set(module_files.keys())
    afferent: dict[str, set[str]] = defaultdict(set)
    efferent: dict[str, set[str]] = defaultdict(set)

    for module, deps in dependency_graph.items():
        for dep in deps:
            if dep in all_modules and dep != module:
                efferent[module].add(dep)
                afferent[dep].add(module)

    for module_name in all_modules:
        file_path = module_files.get(module_name, "")
        metrics = ModuleMetrics(name=module_name, file_path=file_path)
        metrics.ca = len(afferent.get(module_name, set()))
        metrics.ce = len(efferent.get(module_name, set()))

        total = metrics.ca + metrics.ce

        if total > 0:
            metrics.instability = metrics.ce / total
        else:
            metrics.instability = 0.0

        if module_trees and module_name in module_trees:
            tree = module_trees[module_name]
            if tree is not None:
                abs_data = _compute_abstractness(tree)
                metrics.abstractness = abs_data["abstractness"]
                metrics.total_classes = abs_data["total_classes"]
                metrics.abstract_classes = abs_data["abstract_classes"]
                metrics.total_functions = abs_data["total_functions"]
                metrics.abstract_methods = abs_data["abstract_methods"]
                metrics.type_vars = abs_data["type_vars"]
                metrics.protocols = abs_data["protocols"]

        metrics.distance = abs(metrics.abstractness + metrics.instability - 1.0)
        metrics.zone = _classify_zone(metrics.abstractness, metrics.instability)

        if file_path:
            try:
                text = Path(file_path).read_text(errors="replace")
                metrics.loc = sum(
                    1 for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
            except (OSError, UnicodeDecodeError):
                pass

        result.modules[module_name] = metrics

    # "stable" means instability < 0.3
    instability_threshold = 0.3
    # "unstable" means instability > 0.7
    unstable_threshold = 0.7 

    for module, deps in efferent.items():
        m_metrics = result.modules.get(module)
        if not m_metrics or m_metrics.instability >= instability_threshold:
            continue

        for dep in deps:
            dep_metrics = result.modules.get(dep)
            if not dep_metrics:
                continue
            if dep_metrics.instability > unstable_threshold:
                if m_metrics.instability < 0.1:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                violation = DIPViolation(
                    stable_module=module,
                    unstable_module=dep,
                    stable_instability=round(m_metrics.instability, 3),
                    unstable_instability=round(dep_metrics.instability, 3),
                    severity=severity,
                )
                result.dip_violations.append(violation)

    package_modules: dict[str, list[str]] = defaultdict(list)
    for module_name in all_modules:
        parts = module_name.split(".")
        if len(parts) > 1:
            package = ".".join(parts[:-1])
        else:
            package = module_name
        package_modules[package].append(module_name)

    for package, members in package_modules.items():
        member_metrics = [result.modules[m] for m in members if m in result.modules]
        if not member_metrics:
            continue

        pkg_ca = sum(m.ca for m in member_metrics)
        pkg_ce = sum(m.ce for m in member_metrics)
        pkg_total = pkg_ca + pkg_ce
        pkg_instability = pkg_ce / pkg_total if pkg_total > 0 else 0.0

        avg_abstractness = (
            sum(m.abstractness for m in member_metrics) / len(member_metrics)
            if member_metrics else 0.0
        )
        avg_distance = (
            sum(m.distance for m in member_metrics) / len(member_metrics)
            if member_metrics else 0.0
        )

        result.packages[package] = {
            "modules": sorted(members),
            "module_count": len(members),
            "afferent_coupling": pkg_ca,
            "efferent_coupling": pkg_ce,
            "instability": round(pkg_instability, 3),
            "avg_abstractness": round(avg_abstractness, 3),
            "avg_distance": round(avg_distance, 3),
            "total_loc": sum(m.loc for m in member_metrics),
        }

    all_metrics = list(result.modules.values())
    if all_metrics:
        total_deps = sum(len(deps) for deps in dependency_graph.values())
        intra_package_deps = 0
        for module, deps in dependency_graph.items():
            m_pkg = module.split(".")[0] if "." in module else module
            for dep in deps:
                d_pkg = dep.split(".")[0] if "." in dep else dep
                if m_pkg == d_pkg:
                    intra_package_deps += 1

        modularity = intra_package_deps / total_deps if total_deps > 0 else 1.0

        instabilities = [m.instability for m in all_metrics if m.total_coupling > 0]
        instability_variance = (
            sum((i - sum(instabilities) / len(instabilities)) ** 2 for i in instabilities)
            / len(instabilities)
            if instabilities else 0.0
        )

        distances = []
        for m in all_metrics:
            distances.append(m.distance)

        if distances:
            mean_distance = sum(distances) / len(distances)
        else:
            mean_distance = 0.0

        architecture_fitness = 1.0 - mean_distance

        result.system_metrics = {
            "total_modules": len(all_metrics),
            "total_packages": len(result.packages),
            "total_loc": sum(m.loc for m in all_metrics),
            "modularity_index": round(modularity, 3),
            "architecture_fitness": round(architecture_fitness, 3),
            "mean_distance": round(mean_distance, 3),
            "instability_variance": round(instability_variance, 4),
            "coupling_health": round(1.0 - min(1.0, instability_variance * 10), 3),
            "dip_violations": len(result.dip_violations),
            "zone_distribution": {
                "main_sequence": sum(1 for m in all_metrics if m.zone == "main_sequence"),
                "healthy": sum(1 for m in all_metrics if m.zone == "healthy"),
                "zone_of_pain": sum(1 for m in all_metrics if m.zone == "zone_of_pain"),
                "zone_of_uselessness": sum(1 for m in all_metrics if m.zone == "zone_of_uselessness"),
            },
        }
    else:
        result.system_metrics = {
            "total_modules": 0,
            "total_packages": 0,
            "total_loc": 0,
            "modularity_index": 1.0,
            "architecture_fitness": 1.0,
            "mean_distance": 0.0,
            "instability_variance": 0.0,
            "coupling_health": 1.0,
            "dip_violations": 0,
            "zone_distribution": {},
        }

    _generate_findings(result)

    return result


def _generate_findings(result: ArchitectureResult):
    for name, m in result.modules.items():
        # SKY-Q802: High distance from main sequence
        if m.distance > 0.5 and m.total_coupling > 0:

            if m.distance > 0.7:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            result.findings.append({
                "rule_id": "SKY-Q802",
                "kind": "architecture",
                "severity": severity,
                "type": "module",
                "name": name,
                "simple_name": name.split(".")[-1],
                "value": round(m.distance, 3),
                "threshold": 0.5,
                "instability": round(m.instability, 3),
                "abstractness": round(m.abstractness, 3),
                "message": (
                    f"Module '{name}' is far from the Main Sequence "
                    f"(D={m.distance:.2f}, I={m.instability:.2f}, A={m.abstractness:.2f}). "
                    f"Zone: {m.zone.replace('_', ' ')}."
                ),
                "file": m.file_path,
                "basename": Path(m.file_path).name if m.file_path else name,
                "line": 1,
            })

        # SKY-Q803: Zone warnings
        if m.zone in ("zone_of_pain", "zone_of_uselessness") and m.total_coupling > 0:
            if m.zone == "zone_of_pain":
                zone_msg = (
                    f"Module '{name}' is in the Zone of Pain "
                    f"(highly abstract A={m.abstractness:.2f}, highly stable I={m.instability:.2f}). "
                    f"Changes here ripple widely. Consider reducing abstractness or allowing more instability."
                )
            else:
                zone_msg = (
                    f"Module '{name}' is in the Zone of Uselessness "
                    f"(concrete A={m.abstractness:.2f}, unstable I={m.instability:.2f}). "
                    f"Nobody depends on it. Consider abstracting its interface or removing if unused."
                )

            result.findings.append({
                "rule_id": "SKY-Q803",
                "kind": "architecture",
                "severity": "MEDIUM",
                "type": "module",
                "name": name,
                "simple_name": name.split(".")[-1],
                "value": m.zone,
                "instability": round(m.instability, 3),
                "abstractness": round(m.abstractness, 3),
                "distance": round(m.distance, 3),
                "message": zone_msg,
                "file": m.file_path,
                "basename": Path(m.file_path).name if m.file_path else name,
                "line": 1,
            })

    # SKY-Q804: DIP violations
    for v in result.dip_violations:
        stable_file = result.modules.get(v.stable_module)
        result.findings.append({
            "rule_id": "SKY-Q804",
            "kind": "architecture",
            "severity": v.severity,
            "type": "module",
            "name": v.stable_module,
            "simple_name": v.stable_module.split(".")[-1],
            "value": f"{v.stable_module} -> {v.unstable_module}",
            "message": (
                f"Dependency Inversion violation: stable module '{v.stable_module}' "
                f"(I={v.stable_instability:.2f}) depends on unstable module "
                f"'{v.unstable_module}' (I={v.unstable_instability:.2f}). "
                f"Consider introducing an abstraction layer."
            ),
            "file": stable_file.file_path if stable_file else "",
            "basename": Path(stable_file.file_path).name if stable_file and stable_file.file_path else v.stable_module,
            "line": 1,
        })


def get_architecture_findings(
    dependency_graph: dict[str, set[str]],
    module_files: dict[str, str],
    module_trees: dict[str, ast.AST] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:

    result = analyze_architecture(
        dependency_graph=dependency_graph,
        module_files=module_files,
        module_trees=module_trees,
    )

    summary = {
        "system_metrics": result.system_metrics,
        "module_count": len(result.modules),
        "packages": {
            name: {
                "instability": pkg["instability"],
                "avg_abstractness": pkg["avg_abstractness"],
                "avg_distance": pkg["avg_distance"],
                "module_count": pkg["module_count"],
            }
            for name, pkg in result.packages.items()
        },
        "module_metrics": {
            name: {
                "ca": m.ca,
                "ce": m.ce,
                "instability": round(m.instability, 3),
                "abstractness": round(m.abstractness, 3),
                "distance": round(m.distance, 3),
                "zone": m.zone,
            }
            for name, m in result.modules.items()
        },
    }

    return result.findings, summary
