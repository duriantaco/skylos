from pathlib import Path
from typing import Any


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
            "I/A/D enforcement is enabled. See remediations for safe options."
        )
    return (
        "I/A/D enforcement is enabled, so this file-level architecture signal can "
        "block strict gates. See remediations for safe options."
    )


def _iad_docs_url(rule_id: str) -> str:
    return f"https://docs.skylos.dev/rules/{rule_id}"


def _iad_remediations(module_name: str, zone: str) -> list[dict[str, str]]:
    simple_name = module_name.rsplit(".", 1)[-1]
    if simple_name.startswith("_"):
        helper_hint = (
            "This module is already marked private. If it belongs to one release-unit, "
            "keep the finding as an advisory signal unless the fan-in reflects a real "
            "maintenance problem. Do not add fake imports or one-off abstractions just "
            "to move the metric."
        )
        helper_title = "Keep private-helper intent explicit"
    else:
        private_name = f"_{simple_name}"
        helper_hint = (
            f"If '{module_name}' is an internal helper rather than public API, rename "
            f"the module to '{private_name}' and update imports. Do not add fake "
            "imports or one-off abstractions just to move the metric."
        )
        helper_title = "Mark internal helpers as private"

    remediations = [
        {
            "title": helper_title,
            "hint": helper_hint,
            "applies_when": "The module is an implementation detail inside one release-unit.",
        },
        {
            "title": "Introduce a real abstraction boundary",
            "hint": (
                "Add a Protocol or ABC only when consumers genuinely need an interface "
                "with multiple implementations or an extension boundary. Avoid header "
                "interfaces created only to satisfy the score."
            ),
            "applies_when": "The module is public API or has real interchangeable implementations.",
        },
        {
            "title": "Split responsibilities when fan-in is meaningful",
            "hint": (
                "If many consumers depend on unrelated behavior in this module, split "
                "cohesive responsibilities so changes do not ripple through all callers."
            ),
            "applies_when": "High fan-in reflects mixed responsibilities, not just shared helpers.",
        },
    ]

    if zone == "zone_of_uselessness":
        remediations.append(
            {
                "title": "Remove or move unused abstractions",
                "hint": (
                    "If abstractions have few stable consumers, move them near their "
                    "callers or remove abstractions that are not carrying a real boundary."
                ),
                "applies_when": "The module is abstract but not depended on by stable code.",
            }
        )

    return remediations


def generate_architecture_findings(
    result: Any,
    *,
    iad_findings_advisory: bool = True,
) -> None:
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
                    "docs_url": _iad_docs_url("SKY-Q802"),
                    "remediations": _iad_remediations(name, m.zone),
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
                    "docs_url": _iad_docs_url("SKY-Q803"),
                    "remediations": _iad_remediations(name, m.zone),
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
