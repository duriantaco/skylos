import fnmatch
from collections import defaultdict
from pathlib import Path
from typing import Any


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
                violation_reason = "Dependency involves module(s) outside configured architecture layers"
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
                violation_reason = f"Layer '{from_layer}' may only depend on: {allowed}"
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
