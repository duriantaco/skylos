from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from difflib import get_close_matches
from pathlib import Path
from typing import Any

from skylos.core.js_api_surface import (
    inspect_js_file_api_surface,
    inspect_js_package_api_surface,
)
from skylos.rules.ai_defect.js_api_references import (
    JsApiReference,
    extract_js_api_references,
)
from skylos.visitors.languages.typescript.analysis import resolve_ts_module


JS_API_CHECK_ID = "typescript_local_api_surface"
JS_SOURCE_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
)


@dataclass
class _ScanState:
    surface_cache: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    package_surface_cache: dict[
        tuple[str, str], tuple[dict[str, Any] | None, str | None, bool]
    ] = field(default_factory=dict)
    reasons: Counter[str] = field(default_factory=Counter)
    findings: list[dict[str, Any]] = field(default_factory=list)
    references: int = 0
    verified: int = 0
    skipped: int = 0

    def skip(self, reason: str) -> None:
        self.reasons[reason] += 1
        self.skipped += 1


def scan_js_local_api_hallucinations(
    project_root: str | Path,
    files: list[str | Path] | tuple[str | Path, ...],
    raw_imports_by_file: dict[Any, list[dict[str, Any]]],
    *,
    monorepo_resolver: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _safe_root(project_root)
    if root is None:
        return [], failed_js_api_check("invalid_project_root")
    js_files = _safe_js_files(root, files)
    if not js_files:
        return [], _not_applicable_check()

    state = _ScanState()
    for importer in js_files:
        _scan_importer(root, importer, state, monorepo_resolver)

    findings = _deduplicate_findings(state.findings)
    coverage = _coverage_check(
        applicable_files=len(js_files),
        raw_imports=_raw_import_count(raw_imports_by_file, js_files),
        references=state.references,
        verified=state.verified,
        skipped=state.skipped,
        findings=len(findings),
        reasons=state.reasons,
        languages=_languages(js_files),
    )
    return findings, coverage


def _scan_importer(
    root: Path,
    importer: Path,
    state: _ScanState,
    monorepo_resolver: Any | None,
) -> None:
    extracted, extraction_reasons = extract_js_api_references(importer)
    if extraction_reasons:
        state.reasons.update(extraction_reasons)
        extraction_skips = sum(extraction_reasons.values())
        state.references += extraction_skips
        state.skipped += extraction_skips
    for reference in extracted:
        state.references += 1
        _evaluate_reference(root, importer, reference, state, monorepo_resolver)


def _evaluate_reference(
    root: Path,
    importer: Path,
    reference: JsApiReference,
    state: _ScanState,
    monorepo_resolver: Any | None,
) -> None:
    reference_reason = _reference_skip_reason(reference)
    if reference_reason is not None:
        state.skip(reference_reason)
        return
    surface, resolution_reason = _surface_for_reference(
        root,
        importer,
        reference,
        state.surface_cache,
        state.package_surface_cache,
        monorepo_resolver,
    )
    if surface is None:
        state.skip(resolution_reason or "unresolved_module")
        return
    members = surface.get("members")
    if not isinstance(members, dict):
        state.skip("invalid_api_surface")
        return
    incomplete_reason = _surface_incomplete_reason(surface)
    if incomplete_reason is not None:
        state.skip(incomplete_reason)
        return
    if reference.symbol in members:
        state.verified += 1
        return
    state.findings.append(
        _missing_symbol_finding(importer, reference, surface, members)
    )


def _reference_skip_reason(reference: JsApiReference) -> str | None:
    if reference.skip_reason is not None:
        return reference.skip_reason
    if reference.source is None or reference.symbol is None:
        return "incomplete_reference_metadata"
    return None


def failed_js_api_check(reason: str) -> dict[str, Any]:
    return _coverage_check(
        applicable_files=0,
        raw_imports=0,
        references=0,
        verified=0,
        skipped=1,
        findings=0,
        reasons=Counter({reason: 1}),
        languages=[],
    )


def skipped_js_api_check(reason: str) -> dict[str, Any]:
    check = _not_applicable_check()
    check["reasons"] = [{"code": reason, "count": 1}]
    return check


def _surface_for_reference(
    root: Path,
    importer: Path,
    reference: JsApiReference,
    surface_cache: dict[str, dict[str, Any] | None],
    package_surface_cache: dict[
        tuple[str, str], tuple[dict[str, Any] | None, str | None, bool]
    ],
    monorepo_resolver: Any | None,
) -> tuple[dict[str, Any] | None, str | None]:
    source = str(reference.source)
    if not source.startswith("."):
        resolution_mode = _reference_resolution_mode(reference)
        package_key = (source, resolution_mode)
        if package_key not in package_surface_cache:
            package_surface_cache[package_key] = inspect_js_package_api_surface(
                root,
                source,
                resolution_mode=resolution_mode,
            )
        package_surface, package_reason, matched_package = package_surface_cache[
            package_key
        ]
        if matched_package:
            return package_surface, package_reason

    resolved = resolve_ts_module(source, str(importer), monorepo_resolver)
    if resolved is None:
        reason = (
            "unresolved_local_module"
            if source.startswith(".")
            else "external_or_unresolved_module"
        )
        return None, reason

    cache_key = str(Path(resolved).resolve(strict=False))
    if cache_key not in surface_cache:
        surface_cache[cache_key] = inspect_js_file_api_surface(
            root,
            resolved,
            name=source,
        )
    surface = surface_cache[cache_key]
    if surface is None:
        return None, "unsafe_or_unsupported_module"
    return surface, None


def _reference_resolution_mode(reference: JsApiReference) -> str:
    if reference.type_only:
        return "types"
    if reference.kind.startswith("commonjs_"):
        return "require"
    return "import"


def _surface_incomplete_reason(surface: dict[str, Any]) -> str | None:
    metadata = surface.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("complete", True):
        return None
    reasons = metadata.get("incomplete_reasons")
    if not isinstance(reasons, list) or not reasons:
        return "incomplete_api_surface"
    return f"surface_{str(reasons[0])}"


def _missing_symbol_finding(
    importer: Path,
    reference: JsApiReference,
    surface: dict[str, Any],
    members: dict[str, Any],
) -> dict[str, Any]:
    symbol = str(reference.symbol)
    source = str(reference.source)
    suggestions = get_close_matches(symbol, sorted(members), n=3, cutoff=0.6)
    suggestion_text = ""
    if suggestions:
        suggestion_text = f" Available close matches: {', '.join(suggestions)}."
    language = (
        "typescript"
        if importer.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}
        else "javascript"
    )
    surface_origin = str(surface.get("origin") or source)
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": reference.kind,
        "name": symbol,
        "simple_name": symbol,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"'{symbol}' is referenced from local module '{source}', but that "
            f"symbol is not exported by its static API surface.{suggestion_text}"
        ),
        "suggested_fix": (
            "Import an exported symbol, add the missing export, or update the stale reference."
        ),
        "file": str(importer),
        "basename": importer.name,
        "line": reference.line,
        "col": reference.col,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
        "confidence": 96,
        "metadata": {
            "language": language,
            "reference_kind": reference.kind,
            "module_source": source,
            "member_name": symbol,
            "type_only": reference.type_only,
            "api_surface_source": "js_api_surface",
            "surface_origin": surface_origin,
            "proof_state": "verified",
        },
    }


def _coverage_check(
    *,
    applicable_files: int,
    raw_imports: int,
    references: int,
    verified: int,
    skipped: int,
    findings: int,
    reasons: Counter[str],
    languages: list[str],
) -> dict[str, Any]:
    if findings:
        outcome = "fail"
    elif skipped:
        outcome = "incomplete"
    else:
        outcome = "pass"
    return {
        "id": JS_API_CHECK_ID,
        "status": "completed",
        "outcome": outcome,
        "scope": "local_workspace_static_exports",
        "languages": languages,
        "applicable_files": applicable_files,
        "raw_imports": raw_imports,
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
        "id": JS_API_CHECK_ID,
        "status": "skipped",
        "outcome": "pass",
        "scope": "local_workspace_static_exports",
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


def _safe_js_files(root: Path, files: Any) -> list[Path]:
    selected: list[Path] = []
    seen: set[Path] = set()
    for value in files or ():
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
        if not resolved.is_file() or not str(resolved).lower().endswith(
            JS_SOURCE_SUFFIXES
        ):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        selected.append(resolved)
    return sorted(selected, key=str)


def _raw_import_count(
    raw_imports_by_file: dict[Any, list[dict[str, Any]]],
    js_files: list[Path],
) -> int:
    allowed = {str(path.resolve(strict=False)) for path in js_files}
    count = 0
    for file_path, imports in (raw_imports_by_file or {}).items():
        if str(Path(file_path).resolve(strict=False)) not in allowed:
            continue
        if isinstance(imports, list):
            count += len(imports)
    return count


def _languages(files: list[Path]) -> list[str]:
    languages = set()
    for path in files:
        if path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}:
            languages.add("typescript")
        else:
            languages.add("javascript")
    return sorted(languages)


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        metadata = finding.get("metadata")
        reference_kind = (
            metadata.get("reference_kind") if isinstance(metadata, dict) else None
        )
        key = (
            finding.get("file"),
            finding.get("line"),
            finding.get("col"),
            finding.get("simple_name"),
            reference_kind,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
