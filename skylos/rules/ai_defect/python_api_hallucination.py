from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.ai_defect.phantom_refs import (
    _build_parent_map,
    _build_scope_infos,
    _collect_module_facts,
    _module_name,
    _resolve_local_module_member,
    _resolve_import_from_base,
    scan_repo_phantom_security_references,
)
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


PYTHON_API_CHECK_ID = "python_local_api_reference"
_MAX_PYTHON_SOURCE_BYTES = 2 * 1024 * 1024
PYTHON_API_SUFFIXES = (".py", ".pyi", ".pyw")


@dataclass
class _PythonCoverageState:
    references: int = 0
    verified: int = 0
    skipped: int = 0
    reasons: Counter[str] = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = Counter()

    def skip(self, reason: str) -> None:
        self.skipped += 1
        self.reasons[reason] += 1


def scan_python_local_api_hallucinations(
    project_root: str | Path,
    py_files: Iterable[str | Path],
    *,
    target_files: Iterable[str | Path] | None = None,
    vibe_dictionary: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _safe_root(project_root)
    if root is None:
        return [], failed_python_api_check("invalid_project_root")
    files = _safe_python_files(root, py_files)
    if not files:
        return [], _not_applicable_check()
    targets = _safe_python_files(root, target_files or files)
    if not targets:
        return [], failed_python_api_check("no_safe_target_files")

    dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    findings = scan_repo_phantom_security_references(
        root,
        files,
        target_files=targets,
        vibe_dictionary=dictionary,
    )
    _enrich_python_findings(findings)
    coverage = _inspect_python_coverage(root, files, targets, findings)
    return findings, coverage


def failed_python_api_check(reason: str) -> dict[str, Any]:
    return _coverage_check(
        applicable_files=0,
        references=0,
        verified=0,
        skipped=1,
        findings=0,
        reasons=Counter({reason: 1}),
    )


def skipped_python_api_check(reason: str) -> dict[str, Any]:
    check = _not_applicable_check()
    check["reasons"] = [{"code": reason, "count": 1}]
    return check


def _inspect_python_coverage(
    root: Path,
    files: list[Path],
    targets: list[Path],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    modules = _module_files(root, files)
    local_modules = set(modules)
    package_modules = {
        module_name
        for module_name, file_path in modules.items()
        if file_path.name in {"__init__.py", "__init__.pyi", "__init__.pyw"}
    }
    trees, members, aliases, dynamic, load_reasons = _load_module_facts(
        modules, local_modules
    )
    state = _PythonCoverageState(reasons=Counter())
    target_modules = {_module_name(root, path): path for path in targets}

    for module_name, target_path in target_modules.items():
        tree = trees.get(module_name)
        if tree is None:
            state.references += 1
            state.skip(load_reasons.get(module_name, "target_surface_unavailable"))
            continue
        _inspect_target_references(
            root,
            target_path,
            module_name,
            tree,
            local_modules,
            trees,
            members,
            aliases,
            dynamic,
            package_modules,
            state,
        )

    checked = state.verified + len(findings)
    state.references = max(state.references, checked + state.skipped)
    return _coverage_check(
        applicable_files=len(targets),
        references=state.references,
        verified=state.verified,
        skipped=state.skipped,
        findings=len(findings),
        reasons=state.reasons,
    )


def _inspect_target_references(
    root: Path,
    target_path: Path,
    current_module: str,
    tree: ast.AST,
    local_modules: set[str],
    trees: dict[str, ast.AST],
    members: dict[str, set[str]],
    aliases: dict[str, dict[str, str]],
    dynamic: set[str],
    package_modules: set[str],
    state: _PythonCoverageState,
) -> None:
    parent_map = _build_parent_map(tree)
    scope_infos = _build_scope_infos(tree, current_module, local_modules)

    def ensure_module_loaded(module_name: str) -> bool:
        return module_name in trees

    _inspect_import_references(
        root,
        current_module,
        tree,
        local_modules,
        trees,
        members,
        dynamic,
        package_modules,
        state,
    )

    for expression, owner in _reference_expressions(tree, parent_map):
        resolved = _resolve_local_module_member(
            expr=expression,
            node=owner,
            tree=tree,
            parent_map=parent_map,
            scope_infos=scope_infos,
            module_alias_exports=aliases,
            local_modules=local_modules,
            ensure_module_loaded=ensure_module_loaded,
        )
        if resolved is None:
            continue
        target_module, member_name, _ = resolved
        state.references += 1
        if target_module in dynamic:
            state.skip("dynamic_module_surface")
        elif target_module not in trees:
            state.skip("target_surface_unavailable")
        elif member_name in members.get(target_module, set()):
            state.verified += 1


def _reference_expressions(
    tree: ast.AST,
    parent_map: dict[ast.AST, ast.AST],
) -> Iterable[tuple[ast.AST, ast.AST]]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
            continue
        parent = parent_map.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue
        owner = parent if isinstance(parent, ast.Call) and parent.func is node else node
        yield node, owner


def _inspect_import_references(
    root: Path,
    current_module: str,
    tree: ast.AST,
    local_modules: set[str],
    trees: dict[str, ast.AST],
    members: dict[str, set[str]],
    dynamic: set[str],
    package_modules: set[str],
    state: _PythonCoverageState,
) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            _inspect_from_import(
                root,
                current_module,
                node,
                local_modules,
                trees,
                members,
                dynamic,
                package_modules,
                state,
            )
        elif isinstance(node, ast.Import):
            _inspect_module_import(root, node, local_modules, state)


def _inspect_from_import(
    root: Path,
    current_module: str,
    node: ast.ImportFrom,
    local_modules: set[str],
    trees: dict[str, ast.AST],
    members: dict[str, set[str]],
    dynamic: set[str],
    package_modules: set[str],
    state: _PythonCoverageState,
) -> None:
    base = _resolve_import_from_base(current_module, node)
    if base not in local_modules:
        if _local_module_exists(root, base):
            state.references += 1
            state.skip("local_import_outside_scan")
        elif node.level and _has_local_module_prefix(base, local_modules):
            state.references += 1
            state.skip("unresolved_relative_import")
        return
    for alias in node.names:
        state.references += 1
        if alias.name == "*":
            state.skip("wildcard_import")
            continue
        if base in dynamic:
            state.skip("dynamic_module_surface")
            continue
        if base not in trees:
            state.skip("target_surface_unavailable")
            continue
        full_module = f"{base}.{alias.name}"
        if full_module in local_modules or alias.name in members.get(base, set()):
            state.verified += 1
        elif base in package_modules:
            state.skip("package_import_ownership_uncertain")


def _inspect_module_import(
    root: Path,
    node: ast.Import,
    local_modules: set[str],
    state: _PythonCoverageState,
) -> None:
    for alias in node.names:
        if alias.name in local_modules:
            state.references += 1
            state.verified += 1
        elif _has_local_module_prefix(alias.name, local_modules):
            state.references += 1
            state.skip("local_import_ownership_uncertain")
        elif _local_module_exists(root, alias.name):
            state.references += 1
            state.skip("local_import_outside_scan")


def _has_local_module_prefix(module_name: str, local_modules: set[str]) -> bool:
    return any(
        module_name.startswith(f"{candidate}.")
        or candidate.startswith(f"{module_name}.")
        for candidate in local_modules
    )


def _local_module_exists(root: Path, module_name: str) -> bool:
    if not module_name:
        return False
    module_path = root.joinpath(*module_name.split("."))
    candidates = [module_path.with_suffix(suffix) for suffix in PYTHON_API_SUFFIXES]
    candidates.extend(
        module_path / f"__init__{suffix}" for suffix in PYTHON_API_SUFFIXES
    )
    for candidate in candidates:
        if candidate.is_symlink():
            continue
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file():
            return True
    return module_path.is_dir() and not module_path.is_symlink()


def _module_files(root: Path, files: list[Path]) -> dict[str, Path]:
    modules: dict[str, Path] = {}
    for file_path in files:
        module_name = _module_name(root, file_path)
        if module_name:
            modules[module_name] = file_path
    return modules


def _enrich_python_findings(findings: list[dict[str, Any]]) -> None:
    for finding in findings:
        metadata = finding.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            finding["metadata"] = metadata
        metadata.setdefault("language", "python")
        metadata.setdefault("reference_kind", str(finding.get("type") or "reference"))
        metadata.setdefault("member_name", str(finding.get("simple_name") or ""))
        metadata.setdefault("proof_state", "verified")


def _load_module_facts(
    modules: dict[str, Path],
    local_modules: set[str],
) -> tuple[
    dict[str, ast.AST],
    dict[str, set[str]],
    dict[str, dict[str, str]],
    set[str],
    dict[str, str],
]:
    trees: dict[str, ast.AST] = {}
    members: dict[str, set[str]] = {}
    aliases: dict[str, dict[str, str]] = {}
    dynamic: set[str] = set()
    reasons: dict[str, str] = {}
    for module_name, file_path in modules.items():
        tree, reason = _parse_python_file(file_path)
        if tree is None:
            reasons[module_name] = reason or "target_surface_unavailable"
            continue
        trees[module_name] = tree
        module_members, has_dynamic_getattr, exported_modules = _collect_module_facts(
            tree, module_name, local_modules
        )
        members[module_name] = module_members
        aliases[module_name] = {
            alias: target
            for alias, target in exported_modules.items()
            if target in local_modules
        }
        if has_dynamic_getattr:
            dynamic.add(module_name)
    return trees, members, aliases, dynamic, reasons


def _parse_python_file(path: Path) -> tuple[ast.AST | None, str | None]:
    source = read_text_no_symlink(
        path,
        max_bytes=_MAX_PYTHON_SOURCE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if source is None:
        return None, "source_unreadable"
    try:
        return ast.parse(source), None
    except SyntaxError:
        return None, "parse_error"


def _safe_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    return root if root.is_dir() else None


def _safe_python_files(
    root: Path,
    files: Iterable[str | Path],
) -> list[Path]:
    selected: set[Path] = set()
    for value in files:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file() and resolved.suffix in PYTHON_API_SUFFIXES:
            selected.add(resolved)
    return sorted(selected, key=str)


def _coverage_check(
    *,
    applicable_files: int,
    references: int,
    verified: int,
    skipped: int,
    findings: int,
    reasons: Counter[str],
) -> dict[str, Any]:
    outcome = "fail" if findings else ("incomplete" if skipped else "pass")
    return {
        "id": PYTHON_API_CHECK_ID,
        "status": "completed",
        "outcome": outcome,
        "scope": "local_workspace_api_surface",
        "languages": ["python"],
        "applicable_files": applicable_files,
        "raw_imports": 0,
        "references": references,
        "checked_references": verified + findings,
        "verified_references": verified,
        "skipped_references": skipped,
        "finding_count": findings,
        "reasons": [
            {"code": code, "count": count} for code, count in sorted(reasons.items())
        ],
    }


def _not_applicable_check() -> dict[str, Any]:
    return {
        "id": PYTHON_API_CHECK_ID,
        "status": "skipped",
        "outcome": "pass",
        "scope": "local_workspace_api_surface",
        "languages": [],
        "applicable_files": 0,
        "raw_imports": 0,
        "references": 0,
        "checked_references": 0,
        "verified_references": 0,
        "skipped_references": 0,
        "finding_count": 0,
        "reasons": [{"code": "no_supported_files", "count": 1}],
    }
