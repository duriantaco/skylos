from __future__ import annotations

import os
import traceback
from pathlib import Path

from skylos.analysis.architecture_support import (
    architecture_iad_strict,
    expand_reexported_entrypoint_modules,
    find_package_boundary_modules,
)
from skylos.analysis.ast_cache import MODE_IGNORE, load_python_module
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
    *,
    ts_importers_of=None,
    project_root=None,
    workspace_inventory=None,
):
    check_circular = project_cfg.get("check_circular", True)
    if not check_circular and not enable_quality:
        return
    circular_rule = _build_circular_rule(files, modmap, all_raw_imports)
    try:
        circular_findings = circular_rule.analyze()
    except Exception:
        _debug_traceback()
        return
    if check_circular and circular_findings:
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
            ts_importers_of,
            project_root,
            workspace_inventory,
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
    ts_importers_of,
    project_root,
    workspace_inventory,
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
            ts_importers_of,
            project_root,
            workspace_inventory,
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
    ts_importers_of,
    project_root,
    workspace_inventory,
):
    from skylos.analysis.architecture import get_architecture_findings

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
    module_abstractness = dict(architecture_abstractness or {})
    module_loc = dict(architecture_loc or {})
    module_packages = {}
    unmeasured_ts_modules = _add_typescript_architecture(
        files,
        project_root,
        ts_importers_of,
        dep_graph,
        mod_files,
        module_abstractness,
        module_loc,
        module_packages,
        workspace_inventory,
    )
    findings, summary = get_architecture_findings(
        dependency_graph=dep_graph,
        module_files=mod_files,
        module_trees=mod_trees,
        module_abstractness=module_abstractness,
        module_loc=module_loc,
        module_packages=module_packages,
        entrypoint_modules=entrypoint_modules,
        package_boundary_modules=package_modules,
        layer_policy=project_cfg.get("architecture"),
        iad_findings_advisory=not architecture_iad_strict(
            project_cfg.get("architecture")
        ),
    )
    if unmeasured_ts_modules:
        # Graph and layer checks remain valid without a parseable source, but
        # file-level I/A/D warnings would assume A=0 and invent a signal.
        findings = [
            finding
            for finding in findings
            if not (
                finding.get("rule_id") in {"SKY-Q802", "SKY-Q803"}
                and finding.get("name") in unmeasured_ts_modules
            )
        ]
        summary["abstractness_unavailable_modules"] = sorted(unmeasured_ts_modules)
    return findings, summary


def _add_typescript_architecture(
    files,
    project_root,
    ts_importers_of,
    dep_graph,
    module_files,
    module_abstractness,
    module_loc,
    module_packages,
    workspace_inventory,
):
    from skylos.analysis.typescript_architecture import build_ts_architecture_inputs

    root = Path(project_root) if project_root is not None else _source_root(files)
    ts_graph, ts_files, ts_abstractness, ts_loc = build_ts_architecture_inputs(
        files, root, ts_importers_of or {}
    )
    if not ts_files:
        return set()

    # Python and TypeScript may share a relative stem (for example app.py and
    # app.ts). Keep both nodes while retaining the directory prefix used by
    # architecture layer patterns.
    names = {}
    occupied = set(module_files) | set(ts_files)
    for name in sorted(ts_files):
        if name not in module_files:
            names[name] = name
            continue
        suffix = 1
        candidate = f"{name}.ts"
        while candidate in occupied:
            suffix += 1
            candidate = f"{name}.ts{suffix}"
        names[name] = candidate
        occupied.add(candidate)

    workspace_packages = sorted(
        (
            (package.root, package.name)
            for package in getattr(workspace_inventory, "packages", ())
        ),
        key=lambda package: len(package[0].parts),
        reverse=True,
    )
    root_package = getattr(workspace_inventory, "root_package", None)
    root_package_name = root_package.name if root_package is not None else "root"
    for name, file_path in ts_files.items():
        renamed = names[name]
        module_files[renamed] = file_path
        module_packages[renamed] = _typescript_release_unit(
            Path(file_path), workspace_packages, root_package_name
        )
        if name in ts_abstractness:
            module_abstractness[renamed] = ts_abstractness[name]
        if name in ts_loc:
            module_loc[renamed] = ts_loc[name]
    for name, dependencies in ts_graph.items():
        dep_graph[names[name]] = {names[dep] for dep in dependencies}
    return {names[name] for name in ts_files if name not in ts_abstractness}


def _typescript_release_unit(file_path, workspace_packages, root_package_name):
    for package_root, package_name in workspace_packages:
        try:
            file_path.relative_to(package_root)
        except ValueError:
            continue
        return package_name
    return root_package_name


def _architecture_entrypoint_modules(
    pyproject_entrypoint_qnames,
    pyproject_entrypoint_modules,
    architecture_main_guard_modules,
    all_raw_imports,
    modmap,
    mod_files,
):
    entrypoint_modules = pyproject_entrypoint_modules | architecture_main_guard_modules
    return expand_reexported_entrypoint_modules(
        pyproject_entrypoint_qnames,
        entrypoint_modules,
        all_raw_imports,
        modmap,
        mod_files,
    )


def _package_boundary_modules(all_raw_imports, modmap, mod_files):
    return find_package_boundary_modules(all_raw_imports, modmap, mod_files)


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
    # Inside an analyzer run the other Python passes have usually parsed
    # this file already, so this is typically a cache hit.
    _, tree = load_python_module(source_path, MODE_IGNORE)
    if tree is None:
        return
    mod_trees[mod] = tree


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
