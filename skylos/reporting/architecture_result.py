from __future__ import annotations

import ast
import os
import traceback
from pathlib import Path

from skylos.analysis.circular_deps import CircularDependencyRule

_MAX_ARCHITECTURE_SOURCE_BYTES = 2_000_000


def attach_circular_and_architecture(
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
):
    if not project_cfg.get("check_circular", True):
        return
    circular_rule = _build_circular_rule(files, modmap, all_raw_imports)
    try:
        circular_findings = circular_rule.analyze()
    except Exception:
        _debug_traceback()
        return
    if circular_findings:
        result["circular_dependencies"] = circular_findings
    if enable_quality:
        _attach_architecture(
            result,
            project_cfg,
            files,
            modmap,
            all_raw_imports,
            all_quality,
            circular_rule,
            architecture_abstractness,
            architecture_loc,
            architecture_main_guard_modules,
            pyproject_entrypoint_qnames,
            pyproject_entrypoint_modules,
        )


def _build_circular_rule(files, modmap, all_raw_imports):
    circular_rule = CircularDependencyRule()
    for file in files:
        if not str(file).endswith(".py"):
            continue
        mod = modmap.get(file, "")
        raw_imp = all_raw_imports.get(file, [])
        circular_rule.add_file_imports(str(file), mod, raw_imp)
    return circular_rule


def _debug_traceback():
    if os.getenv("SKYLOS_DEBUG"):
        traceback.print_exc()


def _attach_architecture(
    result,
    project_cfg,
    files,
    modmap,
    all_raw_imports,
    all_quality,
    circular_rule,
    architecture_abstractness,
    architecture_loc,
    architecture_main_guard_modules,
    pyproject_entrypoint_qnames,
    pyproject_entrypoint_modules,
):
    try:
        findings, summary = _architecture_findings(
            project_cfg,
            files,
            modmap,
            all_raw_imports,
            circular_rule,
            architecture_abstractness,
            architecture_loc,
            architecture_main_guard_modules,
            pyproject_entrypoint_qnames,
            pyproject_entrypoint_modules,
        )
    except Exception:
        _debug_traceback()
        return
    _attach_architecture_findings(result, project_cfg, all_quality, findings)
    if summary:
        result["architecture_metrics"] = summary


def _architecture_findings(
    project_cfg,
    files,
    modmap,
    all_raw_imports,
    circular_rule,
    architecture_abstractness,
    architecture_loc,
    architecture_main_guard_modules,
    pyproject_entrypoint_qnames,
    pyproject_entrypoint_modules,
):
    from skylos.analysis.architecture import get_architecture_findings
    from skylos.analyzer import _architecture_iad_strict

    dep_graph = dict(circular_rule._analyzer.architecture_dependencies)
    mod_files = dict(circular_rule._analyzer.modules)
    entrypoint_modules = _architecture_entrypoint_modules(
        pyproject_entrypoint_qnames,
        pyproject_entrypoint_modules,
        architecture_main_guard_modules,
        all_raw_imports,
        modmap,
        mod_files,
    )
    package_modules = _package_boundary_modules(all_raw_imports, modmap, mod_files)
    mod_trees = _architecture_module_trees(files, modmap, architecture_abstractness)
    return get_architecture_findings(
        dependency_graph=dep_graph,
        module_files=mod_files,
        module_trees=mod_trees,
        module_abstractness=architecture_abstractness,
        module_loc=architecture_loc,
        entrypoint_modules=entrypoint_modules,
        package_boundary_modules=package_modules,
        layer_policy=project_cfg.get("architecture"),
        iad_findings_advisory=not _architecture_iad_strict(
            project_cfg.get("architecture")
        ),
    )


def _architecture_entrypoint_modules(
    pyproject_entrypoint_qnames,
    pyproject_entrypoint_modules,
    architecture_main_guard_modules,
    all_raw_imports,
    modmap,
    mod_files,
):
    from skylos.analyzer import _expand_reexported_entrypoint_modules

    entrypoint_modules = pyproject_entrypoint_modules | architecture_main_guard_modules
    return _expand_reexported_entrypoint_modules(
        pyproject_entrypoint_qnames,
        entrypoint_modules,
        all_raw_imports,
        modmap,
        mod_files,
    )


def _package_boundary_modules(all_raw_imports, modmap, mod_files):
    from skylos.analyzer import _find_package_boundary_modules

    return _find_package_boundary_modules(all_raw_imports, modmap, mod_files)


def _architecture_module_trees(files, modmap, architecture_abstractness):
    if architecture_abstractness:
        return {}
    source_root = _source_root(files)
    mod_trees = {}
    for file in files:
        if not str(file).endswith(".py"):
            continue
        mod = modmap.get(file, "")
        _add_module_tree(mod_trees, mod, file, source_root)
    return mod_trees


def _source_root(files):
    resolved = []
    for file in files:
        try:
            resolved.append(Path(file).resolve())
        except OSError:
            continue
    if not resolved:
        return Path(".").resolve()
    root = Path(os.path.commonpath(resolved))
    if root.is_file():
        return root.parent
    return root


def _safe_source_path(file, source_root):
    source_path = Path(file)
    if source_path.is_symlink():
        return None
    try:
        resolved_path = source_path.resolve()
        resolved_path.relative_to(source_root)
    except (OSError, ValueError):
        return None
    return resolved_path


def _add_module_tree(mod_trees, mod, file, source_root):
    source_path = _safe_source_path(file, source_root)
    if source_path is None:
        return
    try:
        stat = source_path.stat()
    except OSError:
        return
    if not source_path.is_file():
        return
    if stat.st_size > _MAX_ARCHITECTURE_SOURCE_BYTES:
        return
    try:
        src = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    try:
        mod_trees[mod] = ast.parse(src)
    except SyntaxError:
        return


def _attach_architecture_findings(result, project_cfg, all_quality, arch_findings):
    if not arch_findings:
        return
    ignored_rules = set(project_cfg.get("ignore", []))
    kept = []
    for finding in arch_findings:
        if finding.get("rule_id") not in ignored_rules:
            kept.append(finding)
    if not kept:
        return
    all_quality.extend(kept)
    from skylos.rules.quality.standards import enrich_finding

    for finding in kept:
        enrich_finding(finding)
    result.setdefault("quality", []).extend(kept)
    result["analysis_summary"]["quality_count"] = len(result.get("quality", []) or [])
