from __future__ import annotations

import re
from typing import Callable

from skylos.core.grep_verify_common import (
    _ALL_SOURCE_GLOBS,
    _run_grep,
    filter_grep_results,
    is_substring_match,
)
from skylos.core.grep_verify_language_strategies import (
    _run_go_strategies,
    _run_java_strategies,
    _run_rust_strategies,
    _run_ts_strategies,
)


_STRONG_ALIVE_STRATEGIES = {
    "references",
    "method_calls",
    "imports",
    "qualified_references",
    "string_dispatch",
    "ts_imports",
    "ts_jsx_usage",
    "go_calls",
    "java_imports",
    "rust_use",
}

_MAX_RESULTS_PER_STRATEGY = 5
_DEFAULT_GREP_WORKERS = 4


def _run_general_reference_strategies(
    finding: dict,
    project_root: str,
    *,
    simple_name: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    boundary = rf"\b{re.escape(simple_name)}\b"
    refs = _run_grep(
        boundary,
        project_root,
        use_regex=True,
        include_globs=_ALL_SOURCE_GLOBS,
        max_results=max_per_strategy * 2,
    )
    if refs:
        refs = [ref for ref in refs if not is_substring_match(ref, simple_name)]
        defs, usages = filter_grep_results(refs, finding)
        if usages:
            results["references"] = usages[:max_per_strategy]
        elif defs:
            results["references_definition_only"] = [
                "(only the definition itself found, no usages)"
            ]
    return results


def build_parallel_strategy_tasks(
    finding: dict,
    project_root: str,
    *,
    simple_name: str,
    lang: str,
    max_per_strategy: int,
    early_exit_threshold: int,
    multi_strategy_search_fn: Callable[..., dict[str, list[str]]],
) -> list[tuple[Callable[[], dict[str, list[str]]], str]]:
    tasks: list[tuple[Callable[[], dict[str, list[str]]], str]] = []

    if lang == "python":
        tasks.append(
            (
                lambda: multi_strategy_search_fn(
                    finding,
                    project_root,
                    max_per_strategy=max_per_strategy,
                    early_exit_threshold=early_exit_threshold,
                ),
                "python_core",
            )
        )
    else:
        tasks.append(
            (
                lambda: _run_general_reference_strategies(
                    finding,
                    project_root,
                    simple_name=simple_name,
                    max_per_strategy=max_per_strategy,
                ),
                "general_refs",
            )
        )

    if lang == "typescript":
        tasks.append(
            (
                lambda: _run_ts_strategies(finding, project_root, max_per_strategy),
                "typescript",
            )
        )
    elif lang == "go":
        tasks.append(
            (
                lambda: _run_go_strategies(finding, project_root, max_per_strategy),
                "go",
            )
        )
    elif lang == "java":
        tasks.append(
            (
                lambda: _run_java_strategies(finding, project_root, max_per_strategy),
                "java",
            )
        )
    elif lang == "rust":
        tasks.append(
            (
                lambda: _run_rust_strategies(finding, project_root, max_per_strategy),
                "rust",
            )
        )

    return tasks
