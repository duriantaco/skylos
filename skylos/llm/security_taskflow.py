from __future__ import annotations

import ast
import hashlib
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
REVIEWED_CANDIDATES_KEY = "reviewed_candidates"
DEFAULT_CANDIDATE_STATE = "pending_review"
HYPOTHESIS_EVIDENCE = "hypothesis"
MAX_SECURITY_FACTS = 6
FLASK_FRAMEWORK = "flask"
FASTAPI_FRAMEWORK = "fastapi"
DJANGO_FRAMEWORK = "django"


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
    framework: str | None = None
    entrypoint_reasons: tuple[str, ...] = ()
    registration_hints: tuple[str, ...] = ()
    security_hints: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityEntrypoint:
    path: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SecurityTrustBoundary:
    path: str
    reason: str


@dataclass(frozen=True)
class SecurityFileFacts:
    framework: str | None = None
    sources: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()

    def to_context_lines(self) -> list[str]:
        lines = []
        if self.framework:
            lines.append(f"- framework: {self.framework}")
        if self.sources:
            lines.append("- user-controlled sources: " + ", ".join(self.sources[:MAX_SECURITY_FACTS]))
        if self.sinks:
            lines.append("- dangerous sinks: " + ", ".join(self.sinks[:MAX_SECURITY_FACTS]))
        if self.guards:
            lines.append("- guards/sanitizers: " + ", ".join(self.guards[:MAX_SECURITY_FACTS]))
        return lines


@dataclass(frozen=True)
class SecurityCandidateEvent:
    stage: str
    state: str
    evidence: str
    review_verdict: str | None = None
    review_reason: str | None = None


@dataclass
class SecurityFindingCandidate:
    candidate_id: str
    fingerprint: str
    file: str
    line: int
    rule_id: str
    message: str
    symbol: str | None = None
    state: str = DEFAULT_CANDIDATE_STATE
    evidence: str = HYPOTHESIS_EVIDENCE
    review_verdict: str | None = None
    review_reason: str | None = None
    history: list[SecurityCandidateEvent] = field(default_factory=list)


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
    candidate_ledger: list[SecurityFindingCandidate] = field(default_factory=list)
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
                    "framework": node.framework,
                    "entrypoint_reasons": list(node.entrypoint_reasons),
                    "registration_hints": list(node.registration_hints),
                    "security_hints": list(node.security_hints),
                    "sources": list(node.sources),
                    "sinks": list(node.sinks),
                    "guards": list(node.guards),
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
            "candidate_ledger": [
                {
                    "candidate_id": candidate.candidate_id,
                    "fingerprint": candidate.fingerprint,
                    "file": candidate.file,
                    "line": candidate.line,
                    "rule_id": candidate.rule_id,
                    "message": candidate.message,
                    "symbol": candidate.symbol,
                    "state": candidate.state,
                    "evidence": candidate.evidence,
                    "review_verdict": candidate.review_verdict,
                    "review_reason": candidate.review_reason,
                    "history": [
                        {
                            "stage": event.stage,
                            "state": event.state,
                            "evidence": event.evidence,
                            "review_verdict": event.review_verdict,
                            "review_reason": event.review_reason,
                        }
                        for event in candidate.history
                    ],
                }
                for candidate in self.candidate_ledger
            ],
        }


def _project_root(path: str | Path) -> Path:
    resolved = Path(path).resolve()
    return resolved.parent if resolved.is_file() else resolved


def _repo_node(meta: FileActivation) -> SecurityRepoNode:
    facts = _extract_security_file_facts(Path(meta.path))
    return SecurityRepoNode(
        path=meta.path,
        review_score=meta.review_score,
        prefer_full_file_review=meta.prefer_full_file_review,
        framework=facts.framework,
        entrypoint_reasons=tuple(meta.entrypoint_reasons),
        registration_hints=tuple(meta.registration_hints),
        security_hints=tuple(meta.security_hints),
        sources=facts.sources,
        sinks=facts.sinks,
        guards=facts.guards,
    )


def _framework_from_import(name: str) -> str | None:
    lowered = name.lower()
    if lowered.startswith("flask"):
        return FLASK_FRAMEWORK
    if lowered.startswith("fastapi"):
        return FASTAPI_FRAMEWORK
    if lowered.startswith("django"):
        return DJANGO_FRAMEWORK
    return None


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _call_name(node: ast.AST) -> str:
    return _dotted_name(node.func) if isinstance(node, ast.Call) else ""


def _is_shell_enabled_call(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _names_from_tree(tree: ast.AST) -> tuple[str | None, set[str], set[str], set[str]]:
    framework: str | None = None
    sources: set[str] = set()
    sinks: set[str] = set()
    guards: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                framework = framework or _framework_from_import(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            framework = framework or _framework_from_import(module)

        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node)
        if not call_name:
            continue

        if call_name in {
            "request.args.get",
            "request.form.get",
            "request.headers.get",
            "request.query_params.get",
            "request.GET.get",
            "request.POST.get",
            "request.files.get",
            "request.get_json",
        }:
            sources.add(call_name)
        if call_name in {"request.json.get"}:
            sources.add(call_name)

        if call_name in {"redirect", "flask.redirect"}:
            sinks.add("redirect")
        elif call_name in {"render_template_string", "flask.render_template_string"}:
            sinks.add("render_template_string")
        elif call_name in {
            "requests.get",
            "requests.post",
            "httpx.get",
            "httpx.post",
            "urllib.request.urlopen",
        }:
            sinks.add(call_name)
        elif call_name in {"subprocess.run", "subprocess.check_output", "subprocess.Popen"}:
            sinks.add(f"{call_name}(shell=True)" if _is_shell_enabled_call(node) else call_name)
        elif call_name.endswith(".execute") or call_name.endswith(".executemany"):
            sinks.add(call_name)
        elif call_name in {"open", "Path.read_text", "Path.write_text", "Path.open"}:
            sinks.add(call_name)
        elif call_name in {"jwt.decode", "jose.jwt.decode"}:
            sinks.add(call_name)

        if call_name in {"html.escape", "markupsafe.escape"}:
            guards.add(call_name)
        elif call_name in {"urlparse", "urllib.parse.urlparse"}:
            guards.add("urlparse")
        elif call_name in {"os.path.basename", "secure_filename", "Path.resolve"}:
            guards.add(call_name)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                decorator_name = _dotted_name(decorator)
                if decorator_name.endswith("login_required") or decorator_name.endswith(
                    "requires_auth"
                ):
                    guards.add(decorator_name.split(".")[-1])

    return framework, sources, sinks, guards


def _extract_security_file_facts(file_path: Path) -> SecurityFileFacts:
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError:
        return SecurityFileFacts()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return SecurityFileFacts()

    framework, sources, sinks, guards = _names_from_tree(tree)
    return SecurityFileFacts(
        framework=framework,
        sources=tuple(sorted(sources)),
        sinks=tuple(sorted(sinks)),
        guards=tuple(sorted(guards)),
    )


def _repo_context_for_node(meta: SecurityRepoNode) -> str:
    facts = SecurityFileFacts(
        framework=meta.framework,
        sources=meta.sources,
        sinks=meta.sinks,
        guards=meta.guards,
    )
    return "\n".join(facts.to_context_lines())


def _finding_file(finding: Any) -> str:
    if isinstance(finding, dict):
        location = finding.get("location") or {}
        return str(finding.get("file") or location.get("file") or "")
    return str(finding.location.file)


def _finding_line(finding: Any) -> int:
    if isinstance(finding, dict):
        location = finding.get("location") or {}
        return int(finding.get("line") or location.get("line") or 1)
    return int(finding.location.line)


def _finding_rule_id(finding: Any) -> str:
    return str(finding.get("rule_id") if isinstance(finding, dict) else finding.rule_id)


def _finding_message(finding: Any) -> str:
    return str(finding.get("message") if isinstance(finding, dict) else finding.message)


def _finding_symbol(finding: Any) -> str | None:
    value = finding.get("symbol") if isinstance(finding, dict) else finding.symbol
    return str(value) if value else None


def _finding_metadata(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return dict(finding.get("metadata") or {})
    return dict(getattr(finding, "metadata", None) or {})


def _candidate_fingerprint(finding: Any) -> str:
    raw = "|".join(
        [
            _finding_file(finding),
            str(_finding_line(finding)),
            _finding_rule_id(finding),
            _finding_symbol(finding) or "",
            _finding_message(finding),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _candidate_id(finding: Any) -> str:
    return f"sec-{_candidate_fingerprint(finding)}"


def _candidate_event(stage: str, finding: Any) -> SecurityCandidateEvent:
    metadata = _finding_metadata(finding)
    return SecurityCandidateEvent(
        stage=stage,
        state=metadata.get("security_evidence") or DEFAULT_CANDIDATE_STATE,
        evidence=metadata.get("security_evidence") or HYPOTHESIS_EVIDENCE,
        review_verdict=metadata.get("review_verdict"),
        review_reason=metadata.get("review_reason"),
    )


def _build_candidate_ledger(findings: list[Any]) -> list[SecurityFindingCandidate]:
    ledger: list[SecurityFindingCandidate] = []
    for finding in findings:
        if not is_security_finding(finding):
            continue
        candidate = SecurityFindingCandidate(
            candidate_id=_candidate_id(finding),
            fingerprint=_candidate_fingerprint(finding),
            file=_finding_file(finding),
            line=_finding_line(finding),
            rule_id=_finding_rule_id(finding),
            message=_finding_message(finding),
            symbol=_finding_symbol(finding),
        )
        candidate.history.append(
            SecurityCandidateEvent(
                stage=AUDIT_STAGE,
                state=DEFAULT_CANDIDATE_STATE,
                evidence=HYPOTHESIS_EVIDENCE,
            )
        )
        ledger.append(candidate)
    return ledger


def _update_candidate_ledger(ledger: list[SecurityFindingCandidate], findings: list[Any]) -> None:
    by_fingerprint = {candidate.fingerprint: candidate for candidate in ledger}
    for finding in findings:
        candidate = by_fingerprint.get(_candidate_fingerprint(finding))
        if candidate is None:
            continue
        event = _candidate_event(VERIFY_STAGE, finding)
        candidate.state = event.state
        candidate.evidence = event.evidence
        candidate.review_verdict = event.review_verdict
        candidate.review_reason = event.review_reason
        candidate.history.append(event)


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
    repo_map = sorted(
        (_repo_node(meta) for meta in review_index.by_path.values()),
        key=lambda node: (-node.review_score, node.path),
    )
    repo_node_by_path = {node.path: node for node in repo_map}
    repo_context_map: dict[str, str] = {}
    for path, meta in review_index.by_path.items():
        context_parts = []
        base_context = meta.context_block()
        if base_context:
            context_parts.append(base_context)
        node = repo_node_by_path.get(str(Path(path).resolve()))
        if node is not None:
            facts_context = _repo_context_for_node(node)
            if facts_context:
                context_parts.append(facts_context)
        if context_parts:
            repo_context_map[str(Path(path).resolve())] = "\n".join(context_parts)
    preferred_targets = [
        str(Path(path).resolve())
        for path in review_index.rank_files(max_files=MAX_PREFERRED_AUDIT_TARGETS)
    ]

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
        REVIEWED_CANDIDATES_KEY: findings,
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
        REVIEWED_CANDIDATES_KEY: findings,
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
    _update_candidate_ledger(run.candidate_ledger, review[REVIEWED_CANDIDATES_KEY])
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
    run.candidate_ledger = _build_candidate_ledger(result.findings)
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
