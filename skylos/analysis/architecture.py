"""
Rule IDs:
- SKY-Q801: High instability warning
- SKY-Q802: High distance from main sequence
- SKY-Q803: Zone of Pain / Zone of Uselessness warning
- SKY-Q804: Dependency Inversion Principle violation
- SKY-Q805: Architecture layer policy violation
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from skylos.analysis.architecture_findings import generate_architecture_findings
from skylos.analysis.architecture_layers import get_layer_policy_findings


@dataclass
class ModuleMetrics:
    name: str
    file_path: str
    ca: int = 0
    ce: int = 0
    instability: float = 0.0
    abstractness: float = 0.0
    distance: float = 0.0
    zone: str = "off_main_sequence"
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
                        elif (
                            isinstance(dec, ast.Attribute)
                            and dec.attr == "abstractmethod"
                        ):
                            abstract_methods += 1

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            total_functions += 1

        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                if (
                    isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "TypeVar"
                ):
                    type_vars += 1
                elif (
                    isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == "TypeVar"
                ):
                    type_vars += 1

        elif isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                has_type_checking = True
            elif (
                isinstance(node.test, ast.Attribute)
                and node.test.attr == "TYPE_CHECKING"
            ):
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
    distance = abs(abstractness + instability - 1.0)
    if distance <= 0.2:
        return "main_sequence"

    if abstractness < 0.3 and instability < 0.3:
        return "zone_of_pain"

    if abstractness > 0.7 and instability > 0.7:
        return "zone_of_uselessness"

    return "off_main_sequence"


def _has_main_guard(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue

        test = node.test
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and len(test.comparators) == 1
        ):
            left = test.left
            right = test.comparators[0]
            if isinstance(test.ops[0], ast.Eq):
                left_is_name = isinstance(left, ast.Name) and left.id == "__name__"
                right_is_main = (
                    isinstance(right, ast.Constant) and right.value == "__main__"
                )
                right_is_name = isinstance(right, ast.Name) and right.id == "__name__"
                left_is_main = (
                    isinstance(left, ast.Constant) and left.value == "__main__"
                )
                if (left_is_name and right_is_main) or (right_is_name and left_is_main):
                    return True

    return False


def analyze_architecture(
    dependency_graph: dict[str, set[str]],
    module_files: dict[str, str],
    module_trees: dict[str, ast.AST] | None = None,
    module_abstractness: dict[str, dict[str, Any]] | None = None,
    module_loc: dict[str, int] | None = None,
    iad_findings_advisory: bool = True,
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

        if module_abstractness and module_name in module_abstractness:
            abs_data = module_abstractness[module_name]
            metrics.abstractness = abs_data["abstractness"]
            metrics.total_classes = abs_data["total_classes"]
            metrics.abstract_classes = abs_data["abstract_classes"]
            metrics.total_functions = abs_data["total_functions"]
            metrics.abstract_methods = abs_data["abstract_methods"]
            metrics.type_vars = abs_data["type_vars"]
            metrics.protocols = abs_data["protocols"]
        elif module_trees and module_name in module_trees:
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
        if metrics.total_coupling == 0:
            metrics.zone = "disconnected"
        else:
            metrics.zone = _classify_zone(metrics.abstractness, metrics.instability)

        if module_loc and module_name in module_loc:
            metrics.loc = module_loc[module_name]
        elif file_path:
            try:
                text = Path(file_path).read_text(
                    errors="replace"
                )  # skylos: ignore[SKY-D215] analyzer reads discovered source files
                metrics.loc = sum(
                    1
                    for line in text.splitlines()
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
            if member_metrics
            else 0.0
        )
        avg_distance = (
            sum(m.distance for m in member_metrics) / len(member_metrics)
            if member_metrics
            else 0.0
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
            sum(
                (i - sum(instabilities) / len(instabilities)) ** 2
                for i in instabilities
            )
            / len(instabilities)
            if instabilities
            else 0.0
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
                "main_sequence": sum(
                    1 for m in all_metrics if m.zone == "main_sequence"
                ),
                "off_main_sequence": sum(
                    1 for m in all_metrics if m.zone == "off_main_sequence"
                ),
                "zone_of_pain": sum(1 for m in all_metrics if m.zone == "zone_of_pain"),
                "zone_of_uselessness": sum(
                    1 for m in all_metrics if m.zone == "zone_of_uselessness"
                ),
                "disconnected": sum(1 for m in all_metrics if m.zone == "disconnected"),
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

    generate_architecture_findings(
        result,
        iad_findings_advisory=iad_findings_advisory,
    )

    return result


def get_architecture_findings(
    dependency_graph: dict[str, set[str]],
    module_files: dict[str, str],
    module_trees: dict[str, ast.AST] | None = None,
    module_abstractness: dict[str, dict[str, Any]] | None = None,
    module_loc: dict[str, int] | None = None,
    entrypoint_modules: set[str] | None = None,
    package_boundary_modules: set[str] | None = None,
    private_helper_ce_limit: int = 2,
    private_helper_ca_limit: int = 3,
    layer_policy: dict[str, Any] | None = None,
    iad_findings_advisory: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    result = analyze_architecture(
        dependency_graph=dependency_graph,
        module_files=module_files,
        module_trees=module_trees,
        module_abstractness=module_abstractness,
        module_loc=module_loc,
        iad_findings_advisory=iad_findings_advisory,
    )

    contextual_entrypoints = set(entrypoint_modules or ())
    if module_trees:
        for module_name, tree in module_trees.items():
            if tree is not None and _has_main_guard(tree):
                contextual_entrypoints.add(module_name)

    findings = _filter_contextual_findings(
        result.findings,
        result.modules,
        dependency_graph=dependency_graph,
        entrypoint_modules=contextual_entrypoints,
        package_boundary_modules=set(package_boundary_modules or ()),
        private_helper_ce_limit=private_helper_ce_limit,
        private_helper_ca_limit=private_helper_ca_limit,
    )

    policy_findings, policy_summary = get_layer_policy_findings(
        dependency_graph=dependency_graph,
        module_files=module_files,
        policy=layer_policy,
    )
    if policy_findings:
        findings.extend(policy_findings)

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
    if policy_summary:
        summary["layer_policy"] = policy_summary

    return findings, summary


def _filter_contextual_findings(
    findings: list[dict[str, Any]],
    modules: dict[str, ModuleMetrics],
    *,
    dependency_graph: dict[str, set[str]],
    entrypoint_modules: set[str],
    package_boundary_modules: set[str],
    private_helper_ce_limit: int,
    private_helper_ca_limit: int,
) -> list[dict[str, Any]]:
    afferent: dict[str, set[str]] = defaultdict(set)
    for importer, deps in dependency_graph.items():
        for dep in deps:
            afferent[dep].add(importer)

    filtered = []
    for finding in findings:
        rule_id = finding.get("rule_id")
        module_name = finding.get("name")

        if (
            rule_id in {"SKY-Q802", "SKY-Q803"}
            and isinstance(module_name, str)
            and _is_reexported_package_boundary_module(
                module_name,
                package_boundary_modules,
                afferent,
            )
        ):
            continue

        if (
            rule_id == "SKY-Q803"
            and isinstance(module_name, str)
            and _is_test_module(module_name, finding.get("file", ""))
        ):
            continue

        if rule_id == "SKY-Q803" and module_name in entrypoint_modules:
            continue

        if rule_id in {"SKY-Q802", "SKY-Q803"} and isinstance(module_name, str):
            simple_name = module_name.rsplit(".", 1)[-1]
            metrics = modules.get(module_name)
            if (
                rule_id == "SKY-Q802"
                and simple_name.startswith("_")
                and metrics is not None
                and metrics.ce <= private_helper_ce_limit
            ):
                continue
            if (
                rule_id == "SKY-Q803"
                and simple_name.startswith("_")
                and metrics is not None
                and metrics.zone in {"zone_of_pain", "zone_of_uselessness"}
                and metrics.ca <= private_helper_ca_limit
            ):
                continue

        filtered.append(finding)

    return filtered


def _is_reexported_package_boundary_module(
    module_name: str,
    package_boundary_modules: set[str],
    afferent: dict[str, set[str]],
) -> bool:
    if module_name not in package_boundary_modules or "." not in module_name:
        return False

    parent_package = module_name.rsplit(".", 1)[0]
    return afferent.get(module_name, set()) == {parent_package}


def _is_test_module(module_name: str, file_path: Any) -> bool:
    path = Path(str(file_path)).as_posix() if file_path else ""
    basename = Path(path).name if path else ""
    parts = set(module_name.split("."))

    return (
        "tests" in parts
        or module_name.startswith("test_")
        or ".test_" in module_name
        or basename.startswith("test_")
        or basename.endswith("_test.py")
        or "/tests/" in path
    )
