from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .repo_activation import FileActivation, build_repo_activation_index
from .schemas import AnalysisResult
from .security_verifier import (
    SecurityVerifier,
    annotate_security_finding,
    is_security_finding,
)

COMPLETED_STATUS = "completed"
REPO_MAP_STAGE = "repo_map"
ENTRY_POINTS_STAGE = "entry_points"
AUDIT_STAGE = "audit"
VERIFY_STAGE = "verify"
FINALIZE_STAGE = "finalize"
MAX_PREFERRED_AUDIT_TARGETS = 12
REVIEW_RESULT_KEY = "result"
CANDIDATE_COUNT_KEY = "candidate_count"
SUPPORTED_KEY = "supported"
REFUTED_KEY = "refuted"
UNDECIDED_KEY = "undecided"
REFUTED_FINDINGS_KEY = "refuted_findings"


@dataclass(frozen=True)
class SecurityTaskStage:
    name: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityRepoNode:
    path: str
    review_score: int
    prefer_full_file_review: bool
    entrypoint_reasons: tuple[str, ...] = ()
    registration_hints: tuple[str, ...] = ()
    security_hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityEntrypoint:
    path: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SecurityTrustBoundary:
    path: str
    reason: str


@dataclass
class SecurityTaskflowRun:
    project_root: str
    scanned_files: list[str]
    repo_context_map: dict[str, str] = field(default_factory=dict)
    repo_map: list[SecurityRepoNode] = field(default_factory=list)
    preferred_audit_targets: list[str] = field(default_factory=list)
    entry_points: list[SecurityEntrypoint] = field(default_factory=list)
    trust_boundaries: list[SecurityTrustBoundary] = field(default_factory=list)
    stages: list[SecurityTaskStage] = field(default_factory=list)
    candidate_count: int = 0
    supported_count: int = 0
    refuted_count: int = 0
    hypothesis_count: int = 0
    final_finding_count: int = 0
    result: AnalysisResult | None = None

    def add_stage(self, name: str, **details: Any) -> None:
        self.stages.append(
            SecurityTaskStage(name=name, status=COMPLETED_STATUS, details=details)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "scanned_files": list(self.scanned_files),
            "preferred_audit_targets": list(self.preferred_audit_targets),
            "repo_context_map": dict(self.repo_context_map),
            "repo_map": [
                {
                    "path": node.path,
                    "review_score": node.review_score,
                    "prefer_full_file_review": node.prefer_full_file_review,
                    "entrypoint_reasons": list(node.entrypoint_reasons),
                    "registration_hints": list(node.registration_hints),
                    "security_hints": list(node.security_hints),
                }
                for node in self.repo_map
            ],
            "entry_points": [
                {"path": item.path, "reasons": list(item.reasons)}
                for item in self.entry_points
            ],
            "trust_boundaries": [
                {"path": item.path, "reason": item.reason}
                for item in self.trust_boundaries
            ],
            "stages": [
                {
                    "name": stage.name,
                    "status": stage.status,
                    "details": dict(stage.details),
                }
                for stage in self.stages
            ],
            "candidate_count": self.candidate_count,
            "supported_count": self.supported_count,
            "refuted_count": self.refuted_count,
            "hypothesis_count": self.hypothesis_count,
            "final_finding_count": self.final_finding_count,
        }


def _project_root(path: str | Path) -> Path:
    resolved = Path(path).resolve()
    return resolved.parent if resolved.is_file() else resolved


def _repo_node(meta: FileActivation) -> SecurityRepoNode:
    return SecurityRepoNode(
        path=meta.path,
        review_score=meta.review_score,
        prefer_full_file_review=meta.prefer_full_file_review,
        entrypoint_reasons=tuple(meta.entrypoint_reasons),
        registration_hints=tuple(meta.registration_hints),
        security_hints=tuple(meta.security_hints),
    )


def _build_repo_map(
    project_root: Path, files: list[Path]
) -> tuple[
    dict[str, str],
    list[SecurityRepoNode],
    list[str],
    list[SecurityEntrypoint],
    list[SecurityTrustBoundary],
]:
    review_index = build_repo_activation_index(
        files,
        project_root=project_root,
        static_findings={},
    )
    repo_context_map: dict[str, str] = {}
    for path, meta in review_index.by_path.items():
        context_block = meta.context_block()
        if context_block:
            repo_context_map[str(Path(path).resolve())] = context_block
    preferred_targets = [
        str(Path(path).resolve())
        for path in review_index.rank_files(max_files=MAX_PREFERRED_AUDIT_TARGETS)
    ]
    repo_map = sorted(
        (_repo_node(meta) for meta in review_index.by_path.values()),
        key=lambda node: (-node.review_score, node.path),
    )

    entry_points: list[SecurityEntrypoint] = []
    trust_boundaries: list[SecurityTrustBoundary] = []
    for meta in review_index.by_path.values():
        reasons = tuple(meta.entrypoint_reasons + meta.registration_hints)
        if reasons:
            entry_points.append(SecurityEntrypoint(path=meta.path, reasons=reasons))
        for reason in meta.security_hints:
            trust_boundaries.append(SecurityTrustBoundary(path=meta.path, reason=reason))

    entry_points.sort(key=lambda item: item.path)
    trust_boundaries.sort(key=lambda item: (item.path, item.reason))
    return (
        repo_context_map,
        repo_map,
        preferred_targets,
        entry_points,
        trust_boundaries,
    )


def _security_review_defaults(
    result: AnalysisResult, findings: list[Any]
) -> dict[str, Any]:
    return {
        REVIEW_RESULT_KEY: result,
        CANDIDATE_COUNT_KEY: len(findings),
        SUPPORTED_KEY: 0,
        REFUTED_KEY: 0,
        UNDECIDED_KEY: len(findings),
        REFUTED_FINDINGS_KEY: [],
    }


def _annotated_security_findings(result: AnalysisResult) -> list[Any]:
    findings = []
    for finding in list(result.findings):
        if is_security_finding(finding):
            annotate_security_finding(finding)
            findings.append(finding)
    return findings


def _apply_refuted_findings(
    result: AnalysisResult, refuted_findings: list[Any]
) -> None:
    refuted_ids = {id(finding) for finding in refuted_findings}
    if refuted_ids:
        result.findings = [
            finding for finding in result.findings if id(finding) not in refuted_ids
        ]


def _review_result_payload(
    result: AnalysisResult,
    findings: list[Any],
    verifier_result: dict[str, Any],
) -> dict[str, Any]:
    refuted_findings = list(verifier_result.get(REFUTED_FINDINGS_KEY) or [])
    _apply_refuted_findings(result, refuted_findings)
    return {
        REVIEW_RESULT_KEY: result,
        CANDIDATE_COUNT_KEY: len(findings),
        SUPPORTED_KEY: int(verifier_result.get(SUPPORTED_KEY, 0)),
        REFUTED_KEY: int(verifier_result.get(REFUTED_KEY, 0)),
        UNDECIDED_KEY: int(verifier_result.get(UNDECIDED_KEY, 0)),
        REFUTED_FINDINGS_KEY: refuted_findings,
    }


def review_security_analysis_result(
    *,
    result: AnalysisResult,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    findings = _annotated_security_findings(result)
    review = _security_review_defaults(result, findings)
    if not findings:
        return review

    try:
        verifier = SecurityVerifier(
            model=model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
        )
        verifier_result = verifier.review_findings(findings)
    except Exception:
        return review

    return _review_result_payload(result, findings, verifier_result)


def _build_taskflow_run(
    project_root: Path,
    files: list[Path],
) -> SecurityTaskflowRun:
    normalized_files = [str(Path(file_path).resolve()) for file_path in files]
    (
        repo_context_map,
        repo_map,
        preferred_targets,
        entry_points,
        trust_boundaries,
    ) = _build_repo_map(project_root, files)
    run = SecurityTaskflowRun(
        project_root=str(project_root),
        scanned_files=normalized_files,
        repo_context_map=repo_context_map,
        repo_map=repo_map,
        preferred_audit_targets=preferred_targets,
        entry_points=entry_points,
        trust_boundaries=trust_boundaries,
    )
    run.add_stage(
        REPO_MAP_STAGE,
        files_mapped=len(repo_map),
        repo_context_files=len(repo_context_map),
        preferred_audit_targets=len(preferred_targets),
    )
    run.add_stage(
        ENTRY_POINTS_STAGE,
        entry_points=len(entry_points),
        trust_boundaries=len(trust_boundaries),
    )
    return run


def _apply_review_to_run(run: SecurityTaskflowRun, review: dict[str, Any]) -> None:
    run.candidate_count = int(review[CANDIDATE_COUNT_KEY])
    run.supported_count = int(review[SUPPORTED_KEY])
    run.refuted_count = int(review[REFUTED_KEY])
    run.hypothesis_count = int(review[UNDECIDED_KEY])
    run.result = review[REVIEW_RESULT_KEY]
    run.final_finding_count = len(run.result.findings)
    run.add_stage(
        AUDIT_STAGE,
        files_analyzed=len(run.scanned_files),
        candidate_findings=run.candidate_count,
    )
    run.add_stage(
        VERIFY_STAGE,
        supported=run.supported_count,
        refuted=run.refuted_count,
        hypothesis=run.hypothesis_count,
    )
    run.add_stage(FINALIZE_STAGE, findings=run.final_finding_count)


def run_security_taskflow(
    *,
    path: str | Path,
    files: list[Path],
    analyzer,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> SecurityTaskflowRun:
    project_root = _project_root(path)
    run = _build_taskflow_run(project_root, files)
    analyzer.config.repo_context_map = dict(run.repo_context_map)
    result = analyzer.analyze_files(files, issue_types=["security_audit"])
    review = review_security_analysis_result(
        result=result,
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
    )
    _apply_review_to_run(run, review)
    run.result.summary = analyzer._generate_summary(run.result)
    return run
