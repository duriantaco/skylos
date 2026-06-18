from __future__ import annotations

from pathlib import Path

from skylos.config import load_config
from skylos.reporting.architecture_result import attach_circular_and_architecture
from skylos.reporting.dead_code_result import (
    dead_code_evidence,
    definition_context,
    unused_definitions,
    whitelisted_definitions,
)
from skylos.reporting.rollups import attach_directory_rollups


def _primary_path(path):
    if not isinstance(path, (list, tuple)):
        return path

    for item in path:
        return item

    return "."


def _normal_set(values):
    return set(values or ())


def build_analysis_result(
    analyzer,
    files,
    thr,
    exclude_folders,
    enable_secrets,
    enable_danger,
    enable_quality,
    enable_sca,
    all_secrets,
    all_dangers,
    all_quality,
    all_sca,
    all_suppressed,
    empty_files,
    modmap,
    all_raw_imports,
    path,
    unused_ts_exports=None,
    workspace_inventory=None,
    architecture_abstractness=None,
    architecture_loc=None,
    architecture_main_guard_modules=None,
    pyproject_entrypoint_qnames=None,
    pyproject_entrypoint_modules=None,
    config_file=None,
):
    """Assemble the final result dict from analysis outputs."""
    architecture_main_guard_modules = _normal_set(architecture_main_guard_modules)
    pyproject_entrypoint_qnames = _normal_set(pyproject_entrypoint_qnames)
    pyproject_entrypoint_modules = _normal_set(pyproject_entrypoint_modules)

    ledger, evidence = dead_code_evidence(
        analyzer,
        path,
        pyproject_entrypoint_qnames,
    )
    unused = unused_definitions(analyzer, thr, evidence)
    context_map = definition_context(analyzer, thr, evidence)
    whitelisted = whitelisted_definitions(analyzer, all_suppressed)

    result = _base_result(
        analyzer,
        files,
        exclude_folders,
        context_map,
        whitelisted,
        all_suppressed,
        evidence,
        ledger,
    )
    _attach_analysis_reports(analyzer, result)
    _attach_workspace(analyzer, result, workspace_inventory, path)
    _attach_findings(
        result,
        enable_secrets,
        enable_danger,
        enable_sca,
        all_secrets,
        all_dangers,
        all_sca,
    )
    _attach_quality(result, enable_quality, all_quality)
    _attach_empty_files(result, empty_files)
    _enrich_danger(result, enable_danger)
    _bucket_unused_definitions(result, unused)
    _attach_unused_ts_exports(result, unused_ts_exports)

    project_cfg = load_config(_primary_path(path), config_file=config_file)
    attach_circular_and_architecture(
        result,
        project_cfg,
        files,
        modmap,
        all_raw_imports,
        enable_quality,
        all_quality,
        architecture_abstractness,
        architecture_loc,
        architecture_main_guard_modules,
        pyproject_entrypoint_qnames,
        pyproject_entrypoint_modules,
    )
    _attach_grade(
        result,
        files,
        enable_danger,
        enable_quality,
        enable_sca,
        enable_secrets,
    )
    attach_directory_rollups(result, getattr(analyzer, "_project_root", None))
    return result


def _base_result(
    analyzer,
    files,
    exclude_folders,
    context_map,
    whitelisted,
    all_suppressed,
    dead_code_evidence,
    dead_code_ledger,
):
    return {
        "definitions": context_map,
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "unused_files": [],
        "whitelisted": whitelisted,
        "suppressed": all_suppressed,
        "dead_code_evidence": dead_code_evidence,
        "analysis_summary": {
            "total_files": len(files),
            "excluded_folders": exclude_folders or [],
            "languages": analyzer._count_languages(files),
            "dead_code_evidence": dead_code_ledger.summary(),
        },
    }


def _attach_analysis_reports(analyzer, result):
    liveness_report = getattr(analyzer, "_dead_code_liveness_report", None)
    if liveness_report is not None:
        result["analysis_summary"]["dead_code_liveness"] = liveness_report.to_dict()

    grep_verify_report = getattr(analyzer, "_grep_verify_report", None)
    if grep_verify_report is not None:
        result["analysis_summary"]["grep_verify"] = dict(grep_verify_report)


def _attach_workspace(analyzer, result, workspace_inventory, path):
    if workspace_inventory is None:
        return
    if hasattr(analyzer, "_project_root"):
        project_root = analyzer._project_root
    else:
        project_root = Path(_primary_path(path)).resolve()
    summary = result["analysis_summary"]
    result["workspaces"] = workspace_inventory.to_dict(project_root)
    summary["monorepo_detected"] = workspace_inventory.is_monorepo
    summary["workspace_count"] = len(workspace_inventory.packages)
    summary["workspace_total_packages"] = workspace_inventory.total_packages
    summary["workspace_diagnostic_count"] = len(workspace_inventory.diagnostics)


def _attach_findings(
    result,
    enable_secrets,
    enable_danger,
    enable_sca,
    all_secrets,
    all_dangers,
    all_sca,
):
    summary = result["analysis_summary"]
    if enable_secrets and all_secrets:
        result["secrets"] = all_secrets
        summary["secrets_count"] = len(all_secrets)
    if enable_danger and all_dangers:
        result["danger"] = all_dangers
        summary["danger_count"] = len(all_dangers)
    if enable_sca:
        result["dependency_vulnerabilities"] = all_sca
        summary["sca_count"] = len(all_sca)


def _split_quality_findings(all_quality):
    custom_hits = []
    core_quality = []
    for finding in all_quality:
        rule_id = str(finding.get("rule_id", ""))
        if rule_id.startswith("CUSTOM-"):
            custom_hits.append(finding)
        else:
            core_quality.append(finding)
    return core_quality, custom_hits


def _attach_quality(result, enable_quality, all_quality):
    if not enable_quality or not all_quality:
        return
    core_quality, custom_hits = _split_quality_findings(all_quality)
    if core_quality:
        from skylos.rules.quality.standards import enrich_finding

        for finding in core_quality:
            enrich_finding(finding)
        result["quality"] = core_quality
        result["analysis_summary"]["quality_count"] = len(core_quality)
    if custom_hits:
        result["custom_rules"] = custom_hits
        result["analysis_summary"]["custom_rules_count"] = len(custom_hits)


def _attach_empty_files(result, empty_files):
    if not empty_files:
        return
    result["unused_files"] = empty_files
    result["analysis_summary"]["unused_files_count"] = len(empty_files)


def _enrich_danger(result, enable_danger):
    if not enable_danger or not result.get("danger"):
        return
    from skylos.rules.compliance import enrich_findings_with_compliance

    result["danger"] = enrich_findings_with_compliance(result["danger"])


def _bucket_unused_definitions(result, unused):
    buckets = {
        "function": "unused_functions",
        "method": "unused_functions",
        "import": "unused_imports",
        "class": "unused_classes",
        "type": "unused_classes",
        "variable": "unused_variables",
        "constant": "unused_variables",
        "parameter": "unused_parameters",
    }
    for item in unused:
        bucket = buckets.get(item["type"])
        if bucket:
            result[bucket].append(item)


def _attach_unused_ts_exports(result, unused_ts_exports):
    if not unused_ts_exports:
        return
    result.setdefault("unused_exports", []).extend(unused_ts_exports)
    result["analysis_summary"]["unused_exports_count"] = len(unused_ts_exports)
def _attach_grade(
    result,
    files,
    enable_danger,
    enable_quality,
    enable_sca,
    enable_secrets,
):
    try:
        from skylos.reporting.grader import count_lines_of_code, compute_grade

        total_loc = count_lines_of_code(files)
        categories = _grade_categories(
            enable_danger,
            enable_quality,
            enable_sca,
            enable_secrets,
        )
        result["analysis_summary"]["total_loc"] = total_loc
        result["analysis_summary"]["grade_categories"] = categories
        result["grade"] = compute_grade(
            result,
            total_loc,
            included_categories=categories,
        )
    except Exception:
        _debug_traceback()


def _grade_categories(enable_danger, enable_quality, enable_sca, enable_secrets):
    categories = []
    if enable_danger:
        categories.append("security")
    if enable_quality:
        categories.append("quality")
    categories.append("dead_code")
    if enable_sca:
        categories.append("dependencies")
    if enable_secrets:
        categories.append("secrets")
    return categories
