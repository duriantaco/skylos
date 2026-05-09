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
import fnmatch
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
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
            left = test.left
            right = test.comparators[0]
            if isinstance(test.ops[0], ast.Eq):
                left_is_name = isinstance(left, ast.Name) and left.id == "__name__"
                right_is_main = isinstance(right, ast.Constant) and right.value == "__main__"
                right_is_name = isinstance(right, ast.Name) and right.id == "__name__"
                left_is_main = isinstance(left, ast.Constant) and left.value == "__main__"
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
                text = Path(file_path).read_text(errors="replace")
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
                "disconnected": sum(
                    1 for m in all_metrics if m.zone == "disconnected"
                ),
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

    _generate_findings(result, iad_findings_advisory=iad_findings_advisory)

    return result


def _iad_scope_fields(advisory: bool) -> dict[str, Any]:
    fields = {
        "advisory": advisory,
        "scope": "file",
        "metric_granularity": "file-level heuristic",
        "metric_origin": "Martin I/A/D release-unit metric",
    }
    if advisory:
        fields["advisory_reason"] = (
            "Martin's instability/abstractness/distance metric was defined for "
            "release units. Skylos reports it at Python file granularity as an "
            "architecture signal; it is not gate-blocking unless I/A/D enforcement "
            "is enabled."
        )
    else:
        fields["enforcement_reason"] = (
            "I/A/D enforcement is enabled, so this file-level architecture signal "
            "can block strict gates."
        )
    return fields


def _iad_gate_note(advisory: bool) -> str:
    if advisory:
        return (
            "Advisory: this file-level I/A/D signal does not block gates unless "
            "I/A/D enforcement is enabled."
        )
    return (
        "I/A/D enforcement is enabled, so this file-level architecture signal can "
        "block strict gates."
    )


def _generate_findings(
    result: ArchitectureResult,
    *,
    iad_findings_advisory: bool = True,
):
    for name, m in result.modules.items():
        # SKY-Q802: High distance from main sequence
        if m.distance > 0.5 and m.total_coupling > 0:
            if m.distance > 0.7:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            result.findings.append(
                {
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
                        f"Zone: {m.zone.replace('_', ' ')}. "
                        f"{_iad_gate_note(iad_findings_advisory)}"
                    ),
                    "file": m.file_path,
                    "basename": Path(m.file_path).name if m.file_path else name,
                    "line": 1,
                    **_iad_scope_fields(iad_findings_advisory),
                }
            )

        # SKY-Q803: Zone warnings
        if m.zone in ("zone_of_pain", "zone_of_uselessness") and m.total_coupling > 0:
            if m.zone == "zone_of_pain":
                zone_msg = (
                    f"Module '{name}' is in the Zone of Pain "
                    f"(concrete A={m.abstractness:.2f}, stable I={m.instability:.2f}). "
                    "Changes here can ripple widely at file granularity. "
                    f"{_iad_gate_note(iad_findings_advisory)}"
                )
            else:
                zone_msg = (
                    f"Module '{name}' is in the Zone of Uselessness "
                    f"(abstract A={m.abstractness:.2f}, unstable I={m.instability:.2f}). "
                    "Few stable consumers depend on it. "
                    f"{_iad_gate_note(iad_findings_advisory)}"
                )

            result.findings.append(
                {
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
                    **_iad_scope_fields(iad_findings_advisory),
                }
            )

    # SKY-Q804: DIP violations
    for v in result.dip_violations:
        stable_file = result.modules.get(v.stable_module)
        result.findings.append(
            {
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
                "basename": Path(stable_file.file_path).name
                if stable_file and stable_file.file_path
                else v.stable_module,
                "line": 1,
            }
        )


def _normalize_layer_policy(policy: Any) -> dict[str, Any] | None:
    if not isinstance(policy, dict):
        return None

    raw_layers = policy.get("layers") or []
    raw_rules = policy.get("rules") or []
    if not isinstance(raw_layers, list) or not isinstance(raw_rules, list):
        return None
    if not raw_layers or not raw_rules:
        return None

    layers: list[dict[str, Any]] = []
    for raw_layer in raw_layers:
        if not isinstance(raw_layer, dict):
            continue
        name = str(raw_layer.get("name") or "").strip()
        if not name:
            continue
        patterns = raw_layer.get("patterns")
        if patterns is None:
            patterns = raw_layer.get("packages")
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list):
            patterns = []
        clean_patterns = [str(p).strip() for p in patterns if str(p).strip()]
        if clean_patterns:
            layers.append({"name": name, "patterns": clean_patterns})

    rules: list[dict[str, Any]] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            continue
        from_layer = str(raw_rule.get("from") or "").strip()
        if not from_layer:
            continue

        allow = raw_rule.get("allow") or []
        deny = raw_rule.get("deny") or []
        if isinstance(allow, str):
            allow = [allow]
        if isinstance(deny, str):
            deny = [deny]
        if not isinstance(allow, list):
            allow = []
        if not isinstance(deny, list):
            deny = []

        clean_allow = [str(v).strip() for v in allow if str(v).strip()]
        clean_deny = [str(v).strip() for v in deny if str(v).strip()]
        if clean_allow or clean_deny:
            rules.append(
                {
                    "from": from_layer,
                    "allow": clean_allow,
                    "deny": clean_deny,
                    "severity": str(raw_rule.get("severity") or "HIGH").upper(),
                }
            )

    if not layers or not rules:
        return None

    return {
        "strict": bool(policy.get("strict", False)),
        "layers": layers,
        "rules": rules,
    }


def _layer_pattern_matches(module_name: str, file_path: str, pattern: str) -> bool:
    normalized = pattern.strip().replace("/", ".").strip(".")
    if not normalized:
        return False

    file_module = Path(file_path).with_suffix("").as_posix().replace("/", ".")
    candidates = {module_name, file_module}
    for candidate in candidates:
        if candidate == normalized or candidate.startswith(normalized + "."):
            return True
        if fnmatch.fnmatchcase(candidate, normalized):
            return True
        if fnmatch.fnmatchcase(candidate, normalized + ".*"):
            return True
        if normalized in candidate.split("."):
            return True

    return False


def _map_modules_to_layers(
    module_files: dict[str, str],
    layers: list[dict[str, Any]],
) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for module_name, file_path in module_files.items():
        matches: list[tuple[int, int, str]] = []
        for layer in layers:
            for pattern in layer["patterns"]:
                if _layer_pattern_matches(module_name, file_path, pattern):
                    specificity = pattern.count(".")
                    matches.append((specificity, len(pattern), layer["name"]))
        if matches:
            matches.sort(key=lambda item: (-item[0], -item[1], item[2]))
            mapped[module_name] = matches[0][2]
        else:
            mapped[module_name] = "unknown"
    return mapped


def get_layer_policy_findings(
    dependency_graph: dict[str, set[str]],
    module_files: dict[str, str],
    policy: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized = _normalize_layer_policy(policy)
    if not normalized:
        return [], {}

    layer_map = _map_modules_to_layers(module_files, normalized["layers"])
    rules_by_from = {rule["from"]: rule for rule in normalized["rules"]}
    findings: list[dict[str, Any]] = []

    checked_edges = 0
    for from_module, deps in sorted(dependency_graph.items()):
        from_layer = layer_map.get(from_module, "unknown")
        for to_module in sorted(deps):
            if to_module not in module_files:
                continue
            to_layer = layer_map.get(to_module, "unknown")
            if from_module == to_module:
                continue
            checked_edges += 1

            rule = rules_by_from.get(from_layer)
            violation_reason = ""
            severity = "HIGH"

            if normalized["strict"] and (
                from_layer == "unknown" or to_layer == "unknown"
            ):
                violation_reason = (
                    "Dependency involves module(s) outside configured architecture layers"
                )
                severity = "MEDIUM"
            elif rule is None:
                continue
            elif to_layer in set(rule["deny"]):
                violation_reason = (
                    f"Layer '{from_layer}' is explicitly denied from depending on "
                    f"'{to_layer}'"
                )
                severity = rule["severity"]
            elif rule["allow"] and to_layer not in set(rule["allow"]):
                allowed = ", ".join(rule["allow"])
                violation_reason = (
                    f"Layer '{from_layer}' may only depend on: {allowed}"
                )
                severity = rule["severity"]
            else:
                continue

            source_file = module_files.get(from_module, "")
            findings.append(
                {
                    "rule_id": "SKY-Q805",
                    "kind": "architecture",
                    "severity": severity
                    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                    else "HIGH",
                    "type": "module_dependency",
                    "name": from_module,
                    "simple_name": from_module.split(".")[-1],
                    "value": f"{from_layer}->{to_layer}",
                    "from_module": from_module,
                    "to_module": to_module,
                    "from_layer": from_layer,
                    "to_layer": to_layer,
                    "message": (
                        f"Architecture layer violation: '{from_module}' "
                        f"({from_layer}) depends on '{to_module}' ({to_layer}). "
                        f"{violation_reason}."
                    ),
                    "file": source_file,
                    "basename": Path(source_file).name if source_file else from_module,
                    "line": 1,
                }
            )

    mapped_counts: dict[str, int] = defaultdict(int)
    for layer in layer_map.values():
        mapped_counts[layer] += 1

    summary = {
        "enabled": True,
        "strict": normalized["strict"],
        "layer_count": len(normalized["layers"]),
        "rule_count": len(normalized["rules"]),
        "checked_edges": checked_edges,
        "violation_count": len(findings),
        "module_layers": dict(sorted(layer_map.items())),
        "layer_distribution": dict(sorted(mapped_counts.items())),
    }
    return findings, summary


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
