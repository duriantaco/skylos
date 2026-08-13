from __future__ import annotations

import concurrent.futures
import json as _json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from skylos.core.grep_verify_common import (
    GrepRequest,
    _run_grep,
    detect_language,
    execute_grep_batch,
    filter_grep_results,
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


_GREP_VERIFY_CACHE_VERSION = "v6"

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
        return _json.loads(cached[0]) if cached else {}
    except (_json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.debug("Ignoring invalid grep verification cache entry: %s", exc)
        return None


def _store_cached_group_results(
    cache: Any,
    group_name: str,
    finding: dict,
    results: dict[str, list[str]],
) -> None:
    cache_key = _cache_key(cache, group_name, finding)
    if cache_key is None:
        return
    try:
        cache.put(cache_key, [_json.dumps(results)])
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


def _grep_verify_findings_batched(
    findings: list[dict],
    project_root: str,
    time_budget: float,
    cache: Any,
    start_time: float,
) -> dict[str, GrepVerdict]:
    verdicts: dict[str, GrepVerdict] = {}
    pending: list[_PendingBatchFinding] = []
    requests: list[GrepRequest] = []

    for finding in findings:
        if time.monotonic() - start_time > time_budget:
            break
        full_name = _finding_full_name(finding)
        if not full_name:
            continue

        deterministic_verdict = _deterministic_suppression_verdict(finding)
        if deterministic_verdict:
            verdicts[full_name] = deterministic_verdict
            continue

        group_name = _serial_group_name(finding)
        cached = _load_cached_group_results(cache, group_name, finding)
        if cached is not None:
            verdict = _apply_deterministic_rules(cached, finding)
            if verdict:
                verdicts[full_name] = verdict
            continue

        with record_grep_requests() as recorded:
            planned_results = multi_strategy_search(finding, project_root)
        unique_requests = tuple(dict.fromkeys(recorded))
        if not unique_requests:
            _store_cached_group_results(cache, group_name, finding, planned_results)
            verdict = _apply_deterministic_rules(planned_results, finding)
            if verdict:
                verdicts[full_name] = verdict
            continue

        pending.append(
            _PendingBatchFinding(
                finding=finding,
                group_name=group_name,
                requests=unique_requests,
            )
        )
        requests.extend(unique_requests)

    if not requests:
        return verdicts

    batch_results, completed = execute_grep_batch(
        requests, deadline=start_time + time_budget
    )
    for item in pending:
        if not set(item.requests).issubset(completed):
            continue
        with replay_grep_results(batch_results):
            search_results = multi_strategy_search(item.finding, project_root)
        _store_cached_group_results(
            cache, item.group_name, item.finding, search_results
        )
        verdict = _apply_deterministic_rules(search_results, item.finding)
        if verdict:
            verdicts[_finding_full_name(item.finding)] = verdict

    return verdicts


def grep_verify_findings(
    findings: list[dict],
    project_root: str,
    time_budget: float = 30.0,
    *,
    parallel: bool = False,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> dict[str, GrepVerdict]:
    verdicts: dict[str, GrepVerdict] = {}
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

    def process_finding(finding: dict) -> tuple[str, GrepVerdict | None]:
        full_name = _finding_full_name(finding)
        if not full_name:
            return "", None

        deterministic_verdict = _deterministic_suppression_verdict(finding)
        if deterministic_verdict:
            return full_name, deterministic_verdict

        search_results = search_fn(finding)
        return full_name, _apply_deterministic_rules(search_results, finding)

    verified_names = set(verdicts)
    remaining_findings = [
        finding
        for finding in findings
        if _finding_full_name(finding)
        and _finding_full_name(finding) not in verified_names
    ]

    if parallel:
        max_workers = max(1, int(max_workers or _DEFAULT_GREP_WORKERS))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        pending: set[concurrent.futures.Future] = set()
        findings_iter = iter(remaining_findings)

        def submit_next() -> bool:
            if time.monotonic() - start_time > time_budget:
                return False
            for finding in findings_iter:
                if not _finding_full_name(finding):
                    continue
                pending.add(executor.submit(process_finding, finding))
                return True
            return False

        try:
            for _ in range(max_workers):
                if not submit_next():
                    break

            while pending and time.monotonic() - start_time <= time_budget:
                remaining = max(0.0, time_budget - (time.monotonic() - start_time))
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=remaining,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    break
                for future in done:
                    try:
                        full_name, verdict = future.result()
                    except Exception as e:
                        logger.debug("grep verification failed: %s", e)
                        continue
                    if full_name and verdict:
                        verdicts[full_name] = verdict
                    submit_next()
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

        return verdicts

    for finding in remaining_findings:
        if time.monotonic() - start_time > time_budget:
            break

        full_name, verdict = process_finding(finding)
        if verdict:
            verdicts[full_name] = verdict

    return verdicts


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
