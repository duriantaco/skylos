from __future__ import annotations

import concurrent.futures
import json as _json
import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from skylos.core.grep_verify_common import (
    GrepRequest,
    _GrepDeadlineExceeded,
    _GrepEvidence,
    _GrepExecutionIncomplete,
    _run_grep,
    detect_language,
    execute_grep_batch,
    filter_grep_results,
    grep_execution_deadline,
    is_definition_line,
    is_substring_match,
    module_candidates,
    parameter_owner_name,
    record_grep_requests,
    replay_grep_results,
    repo_relative_path,
    source_globs_for_language,
)
from skylos.core.grep_verify_language_strategies import (
    _deterministic_suppress_multilang,
    _run_go_strategies,
    _run_java_strategies,
    _run_rust_strategies,
    _run_ts_strategies,
)
from skylos.core.grep_verify_parallel import parallel_multi_strategy_search_impl
from skylos.core.grep_verify_python_strategy import (
    multi_strategy_search as _multi_strategy_search_impl,
)
from skylos.core.grep_verify_strategies import (
    _DEFAULT_GREP_WORKERS,
    _MAX_RESULTS_PER_STRATEGY,
    _STRONG_ALIVE_STRATEGIES,
)

logger = logging.getLogger(__name__)

__all__ = [
    "_STRONG_ALIVE_STRATEGIES",
    "GrepStrategy",
    "GrepVerdict",
    "GrepVerificationResult",
    "_cached_group_results",
    "_deterministic_suppress_multilang",
    "_run_go_strategies",
    "_run_grep",
    "_run_java_strategies",
    "_run_rust_strategies",
    "_run_ts_strategies",
    "detect_language",
    "filter_grep_results",
    "grep_verify_findings",
    "is_definition_line",
    "is_substring_match",
    "module_candidates",
    "multi_strategy_search",
    "parallel_multi_strategy_search",
    "parameter_owner_name",
    "repo_relative_path",
    "source_globs_for_language",
]


@dataclass
class GrepVerdict:
    alive: bool
    suppression_code: str | None = None
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)


class GrepVerificationResult(dict[str, GrepVerdict]):
    """Verdicts plus whether every candidate was safely verified.

    This remains a ``dict`` so existing callers can keep using membership,
    indexing, and equality without an API migration.
    """

    def __init__(
        self,
        verdicts: dict[str, GrepVerdict] | None = None,
        *,
        candidate_count: int,
        verified_count: int,
        time_budget: float,
        incomplete_reason: str | None = None,
    ) -> None:
        super().__init__(verdicts or {})
        self.candidate_count = candidate_count
        self.verified_count = verified_count
        self.time_budget = time_budget
        self.incomplete_reason = incomplete_reason
        self.complete = incomplete_reason is None
        self.budget_exhausted = incomplete_reason == "budget_exhausted"


@dataclass
class GrepStrategy:
    name: str
    build_pattern: Callable[..., str | list[str]]
    include_globs: list[str] = field(default_factory=list)
    is_strong: bool = False
    languages: list[str] = field(default_factory=lambda: ["python"])
    use_regex: bool = True
    fixed_string: bool = False
    filter_definitions: bool = True
    result_key: str = ""

    @property
    def key(self) -> str:
        return self.result_key or self.name


@dataclass(frozen=True, slots=True)
class _PendingBatchFinding:
    finding: dict
    group_name: str
    requests: tuple[GrepRequest, ...]


_GREP_VERIFY_CACHE_VERSION = "v8"
_GREP_FINDING_BATCH_SIZE = 32
_GREP_CACHE_MAX_STRATEGIES = 64
_GREP_CACHE_MAX_LINES_PER_STRATEGY = 256
_GREP_CACHE_MAX_EVIDENCE_CHARS = 1_000_000

_DETERMINISTIC_RULES: list[tuple[str, str, str]] = [
    ("method_calls", "real_method_call", "Direct method-call usage found via grep"),
    ("imports", "imported_elsewhere", "Symbol is imported elsewhere in the project"),
    ("string_dispatch", "dynamic_dispatch", "Dynamic dispatch references this symbol"),
    ("qualified_references", "qualified_reference", "Qualified reference found"),
    ("test_references", "test_reference", "Tests reference this symbol"),
    ("config_references", "config_reference", "Referenced in config files"),
    ("cast_protocol", "protocol_required", "Cast to protocol type requires this"),
]


def _cached_group_results(
    cache: Any,
    group_name: str,
    finding: dict,
    search_fn: Callable[[], dict[str, list[str]]],
) -> dict[str, list[str]]:
    cached = _load_cached_group_results(cache, group_name, finding)
    if cached is not None:
        return cached
    results = search_fn()
    _store_cached_group_results(cache, group_name, finding, results)
    return results


def _cache_key(cache: Any, group_name: str, finding: dict) -> str | None:
    if cache is None or not group_name:
        return None

    repository_fingerprint = getattr(cache, "repository_fingerprint", None)
    if not isinstance(repository_fingerprint, str) or not repository_fingerprint:
        return None

    from skylos.core.grep_cache import file_content_hash as _fch

    simple_name = finding.get("simple_name", finding.get("name", ""))
    finding_file = finding.get("file", "")
    content_hash = _fch(finding_file) if finding_file else ""
    return (
        f"{_GREP_VERIFY_CACHE_VERSION}:group:{group_name}:"
        f"{simple_name}:{finding.get('full_name', '')}:"
        f"{finding.get('type', '')}:{content_hash}:"
        f"repo:{repository_fingerprint}"
    )


def _load_cached_group_results(
    cache: Any, group_name: str, finding: dict
) -> dict[str, list[str]] | None:
    cache_key = _cache_key(cache, group_name, finding)
    if cache_key is None:
        return None
    cached = cache.get(cache_key)
    if cached is None:
        return None
    try:
        decoded = _json.loads(cached[0]) if cached else {}
    except (_json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.debug("Ignoring invalid grep verification cache entry: %s", exc)
        return None

    return _normalize_cached_group_results(decoded)


def _normalize_cached_group_results(
    decoded: object,
) -> dict[str, list[str]] | None:
    if not isinstance(decoded, dict) or len(decoded) > _GREP_CACHE_MAX_STRATEGIES:
        logger.debug("Ignoring invalid grep verification cache result shape")
        return None

    normalized: dict[str, list[str]] = {}
    evidence_chars = 0
    for strategy, lines in decoded.items():
        if (
            not isinstance(strategy, str)
            or not isinstance(lines, list)
            or len(lines) > _GREP_CACHE_MAX_LINES_PER_STRATEGY
            or not all(isinstance(line, str) for line in lines)
        ):
            logger.debug("Ignoring invalid grep verification cache strategy")
            return None
        evidence_chars += sum(len(line) for line in lines)
        if evidence_chars > _GREP_CACHE_MAX_EVIDENCE_CHARS:
            logger.debug("Ignoring oversized grep verification cache evidence")
            return None
        normalized[strategy] = lines
    return normalized


def _store_cached_group_results(
    cache: Any,
    group_name: str,
    finding: dict,
    results: dict[str, list[str]],
) -> None:
    normalized = _normalize_cached_group_results(results)
    if normalized is None:
        return
    if any(
        isinstance(line, _GrepEvidence) and ":" in line.path
        for lines in normalized.values()
        for line in lines
    ):
        logger.debug("Skipping cache entry with an ambiguous legacy evidence path")
        return
    cache_key = _cache_key(cache, group_name, finding)
    if cache_key is None:
        return
    try:
        cache.put(cache_key, [_json.dumps(normalized)])
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        logger.debug("Failed to write grep verification cache entry: %s", exc)


def _finding_simple_name(finding: dict) -> str:
    return finding.get("simple_name", finding.get("name", ""))


def _finding_full_name(finding: dict) -> str:
    return finding.get("full_name", finding.get("name", ""))


def _finding_language(finding: dict) -> str:
    return detect_language(finding.get("file", ""))


def multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
) -> dict[str, list[str]]:
    return _multi_strategy_search_impl(
        finding,
        project_root,
        max_per_strategy=max_per_strategy,
        early_exit_threshold=early_exit_threshold,
    )


def parallel_multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> dict[str, list[str]]:
    return parallel_multi_strategy_search_impl(
        finding,
        project_root,
        cached_group_results=_cached_group_results,
        multi_strategy_search_fn=multi_strategy_search,
        logger=logger,
        max_per_strategy=max_per_strategy,
        early_exit_threshold=early_exit_threshold,
        max_workers=max_workers,
        cache=cache,
    )


def _apply_deterministic_rules(
    search_results: dict[str, list[str]],
    finding: dict,
) -> GrepVerdict | None:
    refs = search_results.get("references", [])
    if refs:
        simple_name = finding.get("simple_name", "")
        filtered = (
            [r for r in refs if not is_substring_match(r, simple_name)]
            if simple_name
            else refs
        )
        if filtered:
            return GrepVerdict(
                alive=True,
                suppression_code="grep_reference",
                rationale="Grep found usage references in the project",
                evidence=filtered[:3],
            )

    if search_results.get("exported_in_all") and search_results.get("imports"):
        return GrepVerdict(
            alive=True,
            suppression_code="exported_in_all",
            rationale="Exported in __all__ and imported elsewhere",
            evidence=(
                search_results["exported_in_all"][:2] + search_results["imports"][:1]
            ),
        )

    for strategy_key, code, rationale in _DETERMINISTIC_RULES:
        if search_results.get(strategy_key):
            return GrepVerdict(
                alive=True,
                suppression_code=code,
                rationale=rationale,
                evidence=search_results[strategy_key][:3],
            )

    return None


def _serial_group_name(finding: dict) -> str:
    language = _finding_language(finding)
    return "python_core" if language == "python" else f"serial_{language}"


def _plan_batched_finding(
    finding: dict,
    project_root: str,
    cache: Any,
) -> tuple[GrepVerdict | None, _PendingBatchFinding | None]:
    deterministic_verdict = _deterministic_suppression_verdict(finding)
    if deterministic_verdict:
        return deterministic_verdict, None

    group_name = _serial_group_name(finding)
    cached = _load_cached_group_results(cache, group_name, finding)
    if cached is not None:
        return _apply_deterministic_rules(cached, finding), None

    with record_grep_requests() as recorded:
        planned_results = multi_strategy_search(finding, project_root)
    unique_requests = tuple(dict.fromkeys(recorded))
    if unique_requests:
        return None, _PendingBatchFinding(finding, group_name, unique_requests)

    _store_cached_group_results(cache, group_name, finding, planned_results)
    return _apply_deterministic_rules(planned_results, finding), None


def _execute_pending_findings(
    pending: list[_PendingBatchFinding],
    project_root: str,
    cache: Any,
    deadline: float,
) -> tuple[dict[str, GrepVerdict], int, str | None]:
    requests = [request for item in pending for request in item.requests]
    try:
        batch_results = execute_grep_batch(requests, deadline=deadline)
    except _GrepExecutionIncomplete as exc:
        reason = (
            "budget_exhausted"
            if isinstance(exc, _GrepDeadlineExceeded)
            or time.monotonic() >= deadline
            else "verification_incomplete"
        )
        return {}, 0, reason
    incomplete_requests = getattr(batch_results, "incomplete_requests", set())
    verdicts: dict[str, GrepVerdict] = {}
    verified_count = 0
    for index, item in enumerate(pending):
        if time.monotonic() >= deadline:
            return verdicts, verified_count, "budget_exhausted"
        if any(request not in batch_results for request in item.requests):
            reason = (
                "budget_exhausted"
                if time.monotonic() >= deadline
                else "verification_incomplete"
            )
            return verdicts, verified_count, reason
        try:
            with replay_grep_results(batch_results, deadline=deadline):
                search_results = multi_strategy_search(item.finding, project_root)
        except _GrepExecutionIncomplete as exc:
            logger.debug("grep replay was incomplete: %s", exc)
            reason = (
                "budget_exhausted"
                if isinstance(exc, _GrepDeadlineExceeded)
                or time.monotonic() >= deadline
                else "verification_incomplete"
            )
            return verdicts, verified_count, reason
        request_incomplete = any(
            request in incomplete_requests for request in item.requests
        )
        if not request_incomplete:
            _store_cached_group_results(
                cache, item.group_name, item.finding, search_results
            )
        verdict = _apply_deterministic_rules(search_results, item.finding)
        if request_incomplete and not (verdict and verdict.alive):
            return verdicts, verified_count, "verification_incomplete"
        if verdict:
            verdicts[_finding_full_name(item.finding)] = verdict
        verified_count += 1
        if time.monotonic() >= deadline and index + 1 < len(pending):
            return verdicts, verified_count, "budget_exhausted"
    return verdicts, verified_count, None


def _grep_verify_findings_batched(
    findings: list[dict],
    project_root: str,
    time_budget: float,
    cache: Any,
    start_time: float,
) -> GrepVerificationResult:
    eligible_findings = [finding for finding in findings if _finding_full_name(finding)]
    verdicts: dict[str, GrepVerdict] = {}
    pending: list[_PendingBatchFinding] = []
    deadline = start_time + time_budget
    verified_count = 0
    incomplete_reason: str | None = None

    for finding in eligible_findings:
        if time.monotonic() >= deadline:
            incomplete_reason = "budget_exhausted"
            break
        full_name = _finding_full_name(finding)

        verdict, planned = _plan_batched_finding(finding, project_root, cache)
        if verdict:
            verdicts[full_name] = verdict
        if planned:
            pending.append(planned)
        else:
            verified_count += 1
        if len(pending) < _GREP_FINDING_BATCH_SIZE:
            continue
        if time.monotonic() >= deadline:
            incomplete_reason = "budget_exhausted"
            break
        batch_verdicts, batch_verified, incomplete_reason = (
            _execute_pending_findings(pending, project_root, cache, deadline)
        )
        verdicts.update(batch_verdicts)
        verified_count += batch_verified
        pending.clear()
        if incomplete_reason:
            break

    if pending and incomplete_reason is None:
        if time.monotonic() >= deadline:
            incomplete_reason = "budget_exhausted"
        else:
            batch_verdicts, batch_verified, incomplete_reason = (
                _execute_pending_findings(pending, project_root, cache, deadline)
            )
            verdicts.update(batch_verdicts)
            verified_count += batch_verified

    candidate_count = len(eligible_findings)
    if incomplete_reason is None and verified_count != candidate_count:
        incomplete_reason = "verification_incomplete"

    return GrepVerificationResult(
        verdicts if incomplete_reason is None else {},
        candidate_count=candidate_count,
        verified_count=verified_count,
        time_budget=time_budget,
        incomplete_reason=incomplete_reason,
    )


def _process_finding(
    finding: dict,
    search_fn: Callable[[dict], dict[str, list[str]]],
    deadline: float | None = None,
) -> tuple[str, GrepVerdict | None]:
    full_name = _finding_full_name(finding)
    if not full_name:
        return "", None

    deterministic_verdict = _deterministic_suppression_verdict(finding)
    if deterministic_verdict:
        return full_name, deterministic_verdict

    with grep_execution_deadline(deadline):
        search_results = search_fn(finding)
    return full_name, _apply_deterministic_rules(search_results, finding)


_FindingFuture = concurrent.futures.Future[tuple[str, GrepVerdict | None]]


def _submit_next_finding(
    executor: concurrent.futures.ThreadPoolExecutor,
    pending: set[_FindingFuture],
    findings: Iterator[dict],
    search_fn: Callable[[dict], dict[str, list[str]]],
    deadline: float,
) -> bool:
    if time.monotonic() >= deadline:
        return False
    for finding in findings:
        if not _finding_full_name(finding):
            continue
        pending.add(
            executor.submit(_process_finding, finding, search_fn, deadline)
        )
        return True
    return False


def _collect_finished_findings(
    done: set[_FindingFuture],
    verdicts: dict[str, GrepVerdict],
    deadline: float | None = None,
) -> tuple[int, str | None]:
    completed: list[tuple[str, GrepVerdict | None]] = []
    incomplete_reasons: set[str] = set()
    for future in done:
        try:
            completed.append(future.result())
        except Exception as exc:
            logger.debug("grep verification failed: %s", exc)
            incomplete_reasons.add(
                "budget_exhausted"
                if isinstance(exc, _GrepDeadlineExceeded)
                or (
                    isinstance(exc, _GrepExecutionIncomplete)
                    and deadline is not None
                    and time.monotonic() >= deadline
                )
                else "verification_incomplete"
            )
    for full_name, verdict in sorted(completed, key=lambda item: item[0]):
        if full_name and verdict:
            verdicts[full_name] = verdict
    if "verification_incomplete" in incomplete_reasons:
        reason = "verification_incomplete"
    elif "budget_exhausted" in incomplete_reasons:
        reason = "budget_exhausted"
    else:
        reason = None
    return len(completed), reason


def _grep_verify_findings_parallel(
    findings: list[dict],
    search_fn: Callable[[dict], dict[str, list[str]]],
    time_budget: float,
    max_workers: int,
    start_time: float,
) -> GrepVerificationResult:
    eligible_findings = [finding for finding in findings if _finding_full_name(finding)]
    verdicts: dict[str, GrepVerdict] = {}
    worker_count = max(1, int(max_workers or _DEFAULT_GREP_WORKERS))
    deadline = start_time + time_budget
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)
    pending: set[_FindingFuture] = set()
    findings_iter = iter(eligible_findings)
    verified_count = 0
    incomplete_reason: str | None = None

    try:
        for _ in range(worker_count):
            if not _submit_next_finding(
                executor, pending, findings_iter, search_fn, deadline
            ):
                break

        while pending and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            done, pending = concurrent.futures.wait(
                pending,
                timeout=remaining,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                break
            newly_verified, incomplete_reason = _collect_finished_findings(
                done, verdicts, deadline
            )
            verified_count += newly_verified
            if incomplete_reason:
                break
            for _ in done:
                _submit_next_finding(
                    executor, pending, findings_iter, search_fn, deadline
                )
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)

    candidate_count = len(eligible_findings)
    if incomplete_reason is None and verified_count != candidate_count:
        incomplete_reason = (
            "budget_exhausted"
            if time.monotonic() >= deadline
            else "verification_incomplete"
        )
    return GrepVerificationResult(
        verdicts if incomplete_reason is None else {},
        candidate_count=candidate_count,
        verified_count=verified_count,
        time_budget=time_budget,
        incomplete_reason=incomplete_reason,
    )


def grep_verify_findings(
    findings: list[dict],
    project_root: str,
    time_budget: float = 30.0,
    *,
    parallel: bool = False,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> GrepVerificationResult:
    cache_binder = getattr(type(cache), "bind_repository", None)
    if callable(cache_binder):
        cache_binder(cache, project_root)
    start_time = time.monotonic()
    if not parallel:
        return _grep_verify_findings_batched(
            findings, project_root, time_budget, cache, start_time
        )

    search_fn = _build_grep_search_fn(
        project_root,
        parallel=False,
        max_workers=max_workers,
        cache=cache,
    )
    return _grep_verify_findings_parallel(
        findings, search_fn, time_budget, max_workers, start_time
    )


def _build_grep_search_fn(
    project_root: str,
    *,
    parallel: bool,
    max_workers: int,
    cache: Any,
) -> Callable[[dict], dict[str, list[str]]]:
    if parallel:

        def search_fn(finding: dict) -> dict[str, list[str]]:
            return parallel_multi_strategy_search(
                finding, project_root, max_workers=max_workers, cache=cache
            )

        return search_fn

    def search_fn(finding: dict) -> dict[str, list[str]]:
        if cache is None:
            return multi_strategy_search(finding, project_root)
        return _cached_serial_search_results(finding, project_root, cache)

    return search_fn


def _cached_serial_search_results(
    finding: dict, project_root: str, cache: Any
) -> dict[str, list[str]]:
    lang = _finding_language(finding)
    group_name = "python_core" if lang == "python" else f"serial_{lang}"
    return _cached_group_results(
        cache,
        group_name,
        finding,
        lambda: multi_strategy_search(finding, project_root),
    )


def _deterministic_suppression_verdict(finding: dict) -> GrepVerdict | None:
    if not _deterministic_suppress_multilang(finding):
        return None
    return GrepVerdict(
        alive=True,
        suppression_code="lang_deterministic",
        rationale=(
            "Language-specific deterministic suppression "
            f"({_finding_language(finding)})"
        ),
        evidence=[finding.get("file", "")],
    )
