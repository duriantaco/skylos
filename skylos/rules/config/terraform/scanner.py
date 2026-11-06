"""Static Terraform policy orchestration with explicit evaluation coverage."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from skylos.rules.config.terraform.aws import (
    SUPPORTED_RESOURCES,
    SUPPORTED_RULES,
    evaluate_project,
)
from skylos.rules.config.terraform.model import load_project


def scan_terraform(
    root,
    *,
    changed_files=None,
    ignore=None,
    analysis_errors=None,
    configuration_coverage=None,
    exclude_folders=None,
    scan_paths=None,
    required_rules=None,
):
    project = load_project(
        root,
        changed_files=changed_files,
        scan_paths=scan_paths,
        exclude_folders=exclude_folders,
    )
    checks, findings = evaluate_project(project, ignore=ignore)
    errors = list(project.analysis_errors)
    module_calls = project.coverage.get("module_calls", [])
    discovery_errors = project.coverage.get("discovery_errors", [])
    requested = [required_rules] if isinstance(required_rules, str) else required_rules
    required = set(requested or ()) & SUPPORTED_RULES
    for rule in sorted(required):
        unknown = [
            check
            for check in checks
            if check["rule_id"] == rule and check["status"] == "unknown"
        ]
        if rule in set(ignore or ()) or unknown or module_calls or discovery_errors:
            location = (
                unknown[0]
                if unknown
                else module_calls[0]
                if module_calls
                else discovery_errors[0]
                if discovery_errors
                else {}
            )
            errors.append(
                {
                    "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                    "severity": "HIGH",
                    "kind": "terraform_evaluation_incomplete",
                    "error_type": "TerraformPolicyUnresolved",
                    "file": location.get("file", str(Path(root))),
                    "line": location.get("line", 1),
                    "column": 1,
                    "message": f"Required Terraform policy {rule} could not be fully evaluated",
                    "required_rule": rule,
                }
            )
    if analysis_errors is not None:
        analysis_errors.extend(errors)
    counts = Counter(check["status"] for check in checks)
    unsupported = [
        {
            "resource": f"{resource.resource_type}.{resource.name}",
            "file": resource.file,
            "line": resource.line,
        }
        for resource in project.resources
        if resource.resource_type not in SUPPORTED_RESOURCES
    ]
    evaluation_status = (
        "partial"
        if errors
        or counts["unknown"]
        or unsupported
        or module_calls
        or discovery_errors
        else "complete"
    )
    if (
        not project.coverage.get("files_discovered")
        and not errors
        and not discovery_errors
    ):
        evaluation_status = "not_applicable"
    coverage = {
        **project.coverage,
        "checks": checks,
        "supported_rules": sorted(SUPPORTED_RULES),
        "evaluation_status": evaluation_status,
        "evaluation_counts": {
            status: counts[status]
            for status in ("unsafe", "safe", "unknown", "not_applicable")
        },
        "checks_evaluated": len(checks),
        "unsupported_resource_count": len(unsupported),
        "unsupported_resources": unsupported,
        "unresolved_module_count": len(module_calls),
        "policy_scope": "declaration_policy",
    }
    if configuration_coverage is not None:
        configuration_coverage["terraform"] = coverage
    return findings
