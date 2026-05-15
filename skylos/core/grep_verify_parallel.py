from __future__ import annotations

import concurrent.futures
import logging
import threading
from typing import Any, Callable

from skylos.core.grep_verify_common import _deduplicate_grep_results, detect_language
from skylos.core.grep_verify_strategies import (
    _DEFAULT_GREP_WORKERS,
    _MAX_RESULTS_PER_STRATEGY,
    _STRONG_ALIVE_STRATEGIES,
    build_parallel_strategy_tasks,
)


def parallel_multi_strategy_search_impl(
    finding: dict,
    project_root: str,
    *,
    cached_group_results: Callable[..., dict[str, list[str]]],
    multi_strategy_search_fn: Callable[..., dict[str, list[str]]],
    logger: logging.Logger,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    if not simple_name or len(simple_name) <= 1:
        return {}

    lang = detect_language(finding.get("file", ""))
    results: dict[str, list[str]] = {}
    results_lock = threading.Lock()
    early_exit_event = threading.Event()

    def _check_early_exit() -> bool:
        with results_lock:
            for strategy in _STRONG_ALIVE_STRATEGIES:
                if len(results.get(strategy, [])) >= early_exit_threshold:
                    return True
        return False

    def _run_strategy_group(
        run_fn: Callable[..., dict[str, list[str]]],
        group_name: str = "",
        *args: Any,
    ) -> None:
        if early_exit_event.is_set():
            return
        partial_results = cached_group_results(
            cache,
            group_name,
            finding,
            lambda: run_fn(*args),
        )
        with results_lock:
            results.update(partial_results)
        if _check_early_exit():
            early_exit_event.set()

    tasks = build_parallel_strategy_tasks(
        finding,
        project_root,
        simple_name=simple_name,
        lang=lang,
        max_per_strategy=max_per_strategy,
        early_exit_threshold=early_exit_threshold,
        multi_strategy_search_fn=multi_strategy_search_fn,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for run_fn, group_name in tasks:
            if early_exit_event.is_set():
                break
            futures.append(executor.submit(_run_strategy_group, run_fn, group_name))

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result(timeout=30)
            except Exception as e:
                logger.debug("Strategy group failed: %s", e)
            if early_exit_event.is_set():
                for f in futures:
                    f.cancel()
                break

    return _deduplicate_grep_results(results)
