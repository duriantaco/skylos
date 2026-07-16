from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from difflib import get_close_matches
from pathlib import Path
from typing import Any, Iterable, Sequence

from skylos.core.go_api_surface import (
    GoModule,
    GoPackageSurface,
    GoParsedFile,
    discover_go_modules_with_reasons,
    inspect_go_package_surface,
    iter_nodes,
    node_text,
    parse_go_file,
    resolve_go_import,
    safe_go_files,
)


GO_API_CHECK_ID = "go_workspace_api_surface"


@dataclass(frozen=True)
class _GoImportBinding:
    alias: str
    import_path: str
    surface: GoPackageSurface


@dataclass
class _GoScanState:
    surface_cache: dict[tuple[str, str], GoPackageSurface] = field(default_factory=dict)
    allowed_surface_files: frozenset[Path] | None = None
    exclude_folders: tuple[str, ...] = ()
    reasons: Counter[str] = field(default_factory=Counter)
    findings: list[dict[str, Any]] = field(default_factory=list)
    references: int = 0
    verified: int = 0
    skipped: int = 0

    def skip(self, reason: str) -> None:
        self.reasons[reason] += 1
        self.skipped += 1


def scan_go_local_api_hallucinations(
    project_root: str | Path,
    files: Iterable[str | Path],
    *,
    restrict_to_files: bool = False,
    exclude_folders: Sequence[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _safe_root(project_root)
    if root is None:
        return [], failed_go_api_check("invalid_project_root")
    go_files = safe_go_files(root, files)
    if not go_files:
        return [], _not_applicable_check()

    modules, discovery_reasons = discover_go_modules_with_reasons(
        root,
        go_files,
        exclude_folders=exclude_folders,
    )
    state = _GoScanState(
        allowed_surface_files=frozenset(go_files) if restrict_to_files else None,
        exclude_folders=tuple(exclude_folders or ()),
    )
    combined_reasons = set(discovery_reasons)
    if not restrict_to_files and exclude_folders:
        combined_reasons.add("excluded_workspace_paths")
    for reason in sorted(combined_reasons):
        state.references += 1
        state.skip(reason)
    for importer in go_files:
        _scan_go_importer(importer, modules, state)

    findings = _deduplicate_findings(state.findings)
    return findings, _coverage_check(
        applicable_files=len(go_files),
        references=state.references,
        verified=state.verified,
        skipped=state.skipped,
        findings=len(findings),
        reasons=state.reasons,
    )


def failed_go_api_check(reason: str) -> dict[str, Any]:
    return _coverage_check(
        applicable_files=0,
        references=0,
        verified=0,
        skipped=1,
        findings=0,
        reasons=Counter({reason: 1}),
    )


def skipped_go_api_check(reason: str) -> dict[str, Any]:
    check = _not_applicable_check()
    check["reasons"] = [{"code": reason, "count": 1}]
    return check


def _scan_go_importer(
    importer: Path,
    modules: list[GoModule],
    state: _GoScanState,
) -> None:
    parsed, parse_reason = parse_go_file(importer)
    if parsed is None:
        state.references += 1
        state.skip(parse_reason or "parse_error")
        return
    module = _module_for_file(importer, modules)
    if module is None:
        state.references += 1
        state.skip("go_module_manifest_missing")
        return
    bindings = _local_import_bindings(parsed, modules, state)
    if not bindings:
        return
    for node in iter_nodes(parsed.root_node):
        if node.type == "selector_expression":
            _inspect_selector(parsed, node, bindings, state)


def _local_import_bindings(
    parsed: GoParsedFile,
    modules: list[GoModule],
    state: _GoScanState,
) -> dict[str, _GoImportBinding]:
    bindings: dict[str, _GoImportBinding] = {}
    for spec in _import_specs(parsed):
        import_path = _import_path(parsed, spec)
        if not import_path:
            state.references += 1
            state.skip("dynamic_import_path")
            continue
        module, directory, matched_local = resolve_go_import(import_path, modules)
        if not matched_local:
            continue
        if module is None or directory is None:
            state.references += 1
            state.skip("unresolved_local_package")
            continue
        surface = _go_surface(module, import_path, directory, state)
        alias = _import_alias(parsed, spec, surface)
        if alias == "_":
            continue
        if alias == ".":
            state.references += 1
            state.skip("dot_import")
            continue
        if not alias:
            state.references += 1
            state.skip("import_alias_unresolved")
            continue
        binding = _GoImportBinding(alias, import_path, surface)
        if alias in bindings:
            state.references += 1
            state.skip("ambiguous_import_alias")
            bindings.pop(alias, None)
            continue
        bindings[alias] = binding
    return bindings


def _go_surface(
    module: GoModule,
    import_path: str,
    directory: Path,
    state: _GoScanState,
) -> GoPackageSurface:
    key = (import_path, str(directory.resolve(strict=False)))
    if key not in state.surface_cache:
        state.surface_cache[key] = inspect_go_package_surface(
            module,
            import_path,
            directory,
            allowed_files=state.allowed_surface_files,
            exclude_folders=state.exclude_folders,
        )
    return state.surface_cache[key]


def _inspect_selector(
    parsed: GoParsedFile,
    node: Any,
    bindings: dict[str, _GoImportBinding],
    state: _GoScanState,
) -> None:
    operand = node.child_by_field_name("operand")
    field_node = node.child_by_field_name("field")
    if operand is None or operand.type != "identifier" or field_node is None:
        return
    alias = node_text(parsed, operand)
    binding = bindings.get(alias)
    if binding is None:
        return
    state.references += 1
    if _alias_is_shadowed(parsed, node, alias):
        state.skip("import_alias_shadowed")
        return
    if not binding.surface.complete:
        reason = binding.surface.incomplete_reasons[0]
        state.skip(f"surface_{reason}")
        return
    symbol = node_text(parsed, field_node)
    if symbol in binding.surface.members:
        state.verified += 1
        return
    state.findings.append(_missing_go_symbol_finding(parsed, field_node, binding))


def _import_specs(parsed: GoParsedFile) -> list[Any]:
    specs = []
    for node in iter_nodes(parsed.root_node):
        if node.type == "import_spec":
            specs.append(node)
    return specs


def _import_path(parsed: GoParsedFile, spec: Any) -> str | None:
    path_node = spec.child_by_field_name("path")
    if path_node is None:
        return None
    raw = node_text(parsed, path_node).strip()
    if len(raw) < 2 or raw[0] not in {'"', "`"} or raw[-1] != raw[0]:
        return None
    return raw[1:-1]


def _import_alias(
    parsed: GoParsedFile,
    spec: Any,
    surface: GoPackageSurface,
) -> str | None:
    name_node = spec.child_by_field_name("name")
    if name_node is not None:
        return node_text(parsed, name_node)
    if surface.package_name:
        return surface.package_name
    tail = surface.import_path.rstrip("/").rsplit("/", 1)[-1]
    return tail or None


def _module_for_file(path: Path, modules: Iterable[GoModule]) -> GoModule | None:
    candidates = []
    for module in modules:
        try:
            path.relative_to(module.root)
        except ValueError:
            continue
        candidates.append(module)
    if not candidates:
        return None
    return max(candidates, key=lambda module: len(module.root.parts))


def _alias_is_shadowed(parsed: GoParsedFile, selector: Any, alias: str) -> bool:
    function = _enclosing_function(selector)
    if function is None:
        return False
    for node in iter_nodes(function):
        if node.start_byte >= selector.start_byte:
            continue
        if node.type not in {"identifier", "package_identifier"}:
            continue
        if node_text(parsed, node) != alias:
            continue
        if _declaration_identifier(node):
            return True
    return False


def _enclosing_function(node: Any) -> Any | None:
    current = node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "method_declaration",
            "func_literal",
        }:
            return current
        current = current.parent
    return None


def _declaration_identifier(node: Any) -> bool:
    current = node
    for _ in range(4):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in {
            "parameter_declaration",
            "variadic_parameter_declaration",
            "var_spec",
        }:
            return _inside_named_field(parent, node, "name")
        if parent.type in {"short_var_declaration", "range_clause"}:
            return _inside_named_field(parent, node, "left")
        if parent.type in {
            "function_declaration",
            "method_declaration",
            "func_literal",
        }:
            return False
        current = parent
    return False


def _inside_named_field(parent: Any, node: Any, field_name: str) -> bool:
    field_nodes = parent.children_by_field_name(field_name)
    return any(_node_contains(field_node, node) for field_node in field_nodes)


def _node_contains(container: Any, node: Any) -> bool:
    return (
        container.start_byte <= node.start_byte and node.end_byte <= container.end_byte
    )


def _missing_go_symbol_finding(
    parsed: GoParsedFile,
    field_node: Any,
    binding: _GoImportBinding,
) -> dict[str, Any]:
    symbol = node_text(parsed, field_node)
    suggestions = get_close_matches(
        symbol,
        sorted(binding.surface.members),
        n=3,
        cutoff=0.6,
    )
    suggestion_text = (
        f" Available close matches: {', '.join(suggestions)}." if suggestions else ""
    )
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "package_selector",
        "name": symbol,
        "simple_name": symbol,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"'{symbol}' is referenced from local Go package "
            f"'{binding.import_path}', but that symbol is not exported by its "
            f"static API surface.{suggestion_text}"
        ),
        "suggested_fix": (
            "Use an exported package symbol, add the missing declaration, or update the stale reference."
        ),
        "file": str(parsed.path),
        "basename": parsed.path.name,
        "line": int(field_node.start_point[0]) + 1,
        "col": int(field_node.start_point[1]),
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
        "confidence": 96,
        "metadata": {
            "language": "go",
            "reference_kind": "package_selector",
            "module_source": binding.import_path,
            "member_name": symbol,
            "api_surface_source": "go_api_surface",
            "surface_origin": str(binding.surface.directory),
            "proof_state": "verified",
        },
    }


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
        "id": GO_API_CHECK_ID,
        "status": "completed",
        "outcome": outcome,
        "scope": "local_workspace_api_surface",
        "languages": ["go"],
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
        "id": GO_API_CHECK_ID,
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


def _safe_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    return root if root.is_dir() else None


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        key = (
            finding.get("file"),
            finding.get("line"),
            finding.get("col"),
            finding.get("simple_name"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
