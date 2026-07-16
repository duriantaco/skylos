from __future__ import annotations

from collections import Counter
from difflib import get_close_matches
from typing import Any

from skylos.core.java_api_surface import JavaParsedFile, JavaTypeSurface


JAVA_API_CHECK_ID = "java_workspace_api_surface"


def failed_java_api_check(reason: str) -> dict[str, Any]:
    return coverage_check(
        applicable_files=0,
        references=0,
        verified=0,
        skipped=1,
        findings=0,
        reasons=Counter({reason: 1}),
    )


def skipped_java_api_check(reason: str) -> dict[str, Any]:
    check = not_applicable_check()
    check["reasons"] = [{"code": reason, "count": 1}]
    return check


def missing_java_member_finding(
    parsed: JavaParsedFile,
    member_node: Any,
    surface: JavaTypeSurface,
    member_name: str,
    *,
    expected_kind: str = "member",
) -> dict[str, Any]:
    suggestions = get_close_matches(
        member_name,
        sorted(surface.members),
        n=3,
        cutoff=0.6,
    )
    suggestion_text = (
        f" Available close matches: {', '.join(suggestions)}." if suggestions else ""
    )
    return _java_finding(
        parsed,
        member_node,
        member_name,
        "static_member",
        (
            f"'{member_name}' is referenced from local Java type "
            f"'{surface.qualified_name}', but that static {expected_kind} is not present "
            f"in its source API surface.{suggestion_text}"
        ),
        module_source=surface.qualified_name,
        surface_origin=str(surface.file),
        extra_metadata={"expected_member_kind": expected_kind},
    )


def invalid_java_member_kind_finding(
    parsed: JavaParsedFile,
    member_node: Any,
    surface: JavaTypeSurface,
    member_name: str,
    *,
    expected_kind: str,
    actual_kinds: list[str],
) -> dict[str, Any]:
    actual = ", ".join(sorted(set(actual_kinds)))
    return _java_finding(
        parsed,
        member_node,
        member_name,
        "static_member",
        (
            f"'{member_name}' is used as a static {expected_kind} on local Java "
            f"type '{surface.qualified_name}', but the source surface declares it "
            f"as {actual}."
        ),
        module_source=surface.qualified_name,
        surface_origin=str(surface.file),
        extra_metadata={
            "expected_member_kind": expected_kind,
            "actual_member_kinds": actual,
        },
    )


def inaccessible_java_member_finding(
    parsed: JavaParsedFile,
    member_node: Any,
    surface: JavaTypeSurface,
    member_name: str,
    *,
    visibility: str,
) -> dict[str, Any]:
    return _java_finding(
        parsed,
        member_node,
        member_name,
        "static_member",
        (
            f"'{member_name}' exists on local Java type '{surface.qualified_name}', "
            f"but its {visibility} visibility does not allow this reference."
        ),
        module_source=surface.qualified_name,
        surface_origin=str(surface.file),
        extra_metadata={"member_visibility": visibility},
    )


def coverage_check(
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
        "id": JAVA_API_CHECK_ID,
        "status": "completed",
        "outcome": outcome,
        "scope": "local_workspace_api_surface",
        "languages": ["java"],
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


def not_applicable_check() -> dict[str, Any]:
    return {
        "id": JAVA_API_CHECK_ID,
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


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        key = (
            finding.get("file"),
            finding.get("line"),
            finding.get("col"),
            finding.get("simple_name"),
            finding.get("type"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _java_finding(
    parsed: JavaParsedFile,
    node: Any,
    symbol: str,
    reference_kind: str,
    message: str,
    *,
    module_source: str,
    surface_origin: str,
    extra_metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    metadata = {
        "language": "java",
        "reference_kind": reference_kind,
        "module_source": module_source,
        "member_name": symbol,
        "api_surface_source": "java_api_surface",
        "surface_origin": surface_origin,
        "proof_state": "verified",
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": reference_kind,
        "name": symbol,
        "simple_name": symbol,
        "value": "phantom",
        "threshold": 0,
        "message": message,
        "suggested_fix": (
            "Use an existing local type or static member, add the missing declaration, "
            "or update the stale reference."
        ),
        "file": str(parsed.path),
        "basename": parsed.path.name,
        "line": int(node.start_point[0]) + 1,
        "col": int(node.start_point[1]),
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
        "confidence": 96,
        "metadata": metadata,
    }
