from __future__ import annotations

import re

from skylos.core.grep_search_state import grep_evidence_strategy, limit_grep_evidence

from skylos.core.grep_verify_common import (
    _deduplicate_grep_results,
    _filter_other_owner_same_method_calls,
    _grep_line_content,
    _grep_line_number,
    _grep_line_path,
    _is_python_source_reference,
    _run_grep,
    filter_grep_results,
    is_substring_match,
    module_candidates,
    parameter_owner_name,
    repo_relative_path,
)
from skylos.core.grep_verify_strategies import (
    _MAX_RESULTS_PER_STRATEGY,
    _STRONG_ALIVE_STRATEGIES,
)


def _strategy_search(strategy, *args, **kwargs):
    with grep_evidence_strategy(strategy):
        return _run_grep(*args, **kwargs)


def _parameter_contract_search(
    finding: dict,
    project_root: str,
    *,
    simple_name: str,
    owner_simple_name: str,
    file_path: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    """Collect owner-aware evidence for a lexical parameter binding."""
    results: dict[str, list[str]] = {}
    if not owner_simple_name:
        return results

    callback_pattern = rf"callback\s*=\s*(?:[\w\.]+\.)*{re.escape(owner_simple_name)}\b"
    callback_refs = _strategy_search(
        "callback_registrations",
        callback_pattern,
        project_root,
        use_regex=True,
        include_globs=["*.py"],
        max_results=max_per_strategy,
    )
    if callback_refs:
        results["callback_registrations"] = limit_grep_evidence(
            callback_refs, max_per_strategy, strategy="callback_registrations"
        )

    signature_pattern = (
        rf"def\s+{re.escape(owner_simple_name)}\s*\([^)]*\b{re.escape(simple_name)}\b"
    )
    signature_refs = _strategy_search(
        "signature_overrides",
        signature_pattern,
        project_root,
        use_regex=True,
        include_globs=["*.py"],
        max_results=max_per_strategy * 2,
    )
    if signature_refs:
        override_refs = []
        line_value = finding.get("line", 0)
        line_num = int(line_value) if isinstance(line_value, (int, float)) else 0
        for ref in signature_refs:
            match_file = _grep_line_path(ref)
            match_line = _grep_line_number(ref)
            if not match_file or match_line is None:
                continue
            if match_file == file_path and abs(match_line - line_num) <= 3:
                continue
            override_refs.append(ref)
        if override_refs:
            results["signature_overrides"] = limit_grep_evidence(
                override_refs, max_per_strategy, strategy="signature_overrides"
            )

    return _deduplicate_grep_results(results)


def multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
    stop_after_strong_evidence: bool = True,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    full_name = finding.get("full_name", "")
    kind = finding.get("type", "")
    file_path = finding.get("file", "")

    if file_path:
        rel_file = repo_relative_path(file_path, project_root)
    else:
        rel_file = ""

    if file_path:
        module_names = module_candidates(file_path, project_root)
    else:
        module_names = []

    if kind == "parameter":
        owner_full_name = parameter_owner_name(finding)
    else:
        owner_full_name = ""

    if owner_full_name:
        owner_simple_name = owner_full_name.rsplit(".", 1)[-1]
    else:
        owner_simple_name = ""

    results: dict[str, list[str]] = {}

    if not simple_name or len(simple_name) <= 1:
        return results

    if kind == "parameter":
        return _parameter_contract_search(
            finding,
            project_root,
            simple_name=simple_name,
            owner_simple_name=owner_simple_name,
            file_path=file_path,
            max_per_strategy=max_per_strategy,
        )

    def _should_early_exit() -> bool:
        if not stop_after_strong_evidence:
            return False
        for strategy in _STRONG_ALIVE_STRATEGIES:
            hits = results.get(strategy, [])
            if len(hits) >= early_exit_threshold:
                return True
        return False

    boundary_pattern = rf"\b{simple_name}\b"
    if kind != "import":
        refs = _strategy_search(
            "references",
            boundary_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py", "*.pyi"],
            max_results=max_per_strategy * 2,
        )
        if refs:
            refs = [
                r
                for r in refs
                if not is_substring_match(r, simple_name)
                and _is_python_source_reference(r, simple_name)
            ]
            refs = _filter_other_owner_same_method_calls(refs, finding)
            _defs, usages = filter_grep_results(refs, finding)
            if usages:
                results["references"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="references"
                )
            elif _defs:
                results["references_definition_only"] = [
                    "(only the definition itself found, no usages)"
                ]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if full_name and full_name != simple_name:
        qualified_refs = _strategy_search(
            "qualified_references",
            rf"\b{re.escape(full_name)}\b",
            project_root,
            use_regex=True,
            include_globs=["*.py", "*.pyi"],
            max_results=max_per_strategy,
        )
        if qualified_refs:
            qualified_refs = [
                ref
                for ref in qualified_refs
                if _is_python_source_reference(ref, simple_name)
            ]
            _defs, usages = filter_grep_results(qualified_refs, finding)
            if usages:
                results["qualified_references"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="qualified_references"
                )

    if kind in ("method", "function"):
        call_pattern = rf"\.{re.escape(simple_name)}[[:space:]]*\("
        call_refs = _strategy_search(
            "method_calls",
            call_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if call_refs:
            call_refs = _filter_other_owner_same_method_calls(call_refs, finding)
            _defs, usages = filter_grep_results(call_refs, finding)
            if usages:
                results["method_calls"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="method_calls"
                )

    if kind != "import":
        import_pattern = rf"import.*\b{simple_name}\b"
        import_refs = _strategy_search(
            "imports",
            import_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if import_refs:
            _defs, usages = filter_grep_results(import_refs, finding)
            if usages:
                results["imports"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="imports"
                )

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    quote_chars = "\"'"
    dispatch_patterns = [
        rf"(getattr|setattr|hasattr|delattr)[[:space:]]*\([^,]+,[[:space:]]*[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]",
        rf"\[[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]\]",
        rf"\.[[:alnum:]_]+[[:space:]]*\([[:space:]]*[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]",
        rf"[{quote_chars}]{re.escape(simple_name)}[{quote_chars}][[:space:]]*:[[:space:]]*[[:alnum:]_]+[[:space:]]*\(",
    ]
    for dp in dispatch_patterns:
        dp_refs = _strategy_search(
            "string_dispatch",
            dp,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if dp_refs:
            dp_refs = [
                r
                for r in dp_refs
                if not any(pat in r for pat in ["TypeVar(", "TypeAlias", "Literal["])
            ]
            _defs, usages = filter_grep_results(dp_refs, finding)
            if usages:
                combined = _deduplicate_grep_results(
                    {"string_dispatch": results.get("string_dispatch", []) + usages}
                )["string_dispatch"]
                results["string_dispatch"] = limit_grep_evidence(
                    combined, max_per_strategy, strategy="string_dispatch"
                )
                if stop_after_strong_evidence:
                    break

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    all_refs = _strategy_search(
        "exported_in_all",
        rf"__all__.*\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["*.py"],
        max_results=max_per_strategy,
    )
    if all_refs:
        results["exported_in_all"] = limit_grep_evidence(
            all_refs, max_per_strategy, strategy="exported_in_all"
        )

    if kind in ("import", "variable", "class"):
        cast_pattern = rf'cast\(\s*["\x27]{simple_name}["\x27]'
        cast_refs = _strategy_search(
            "cast_usage",
            cast_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if cast_refs:
            _defs, usages = filter_grep_results(cast_refs, finding)
            if usages:
                results["cast_usage"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="cast_usage"
                )

        bound_pattern = rf'bound\s*=\s*["\x27]{simple_name}["\x27]'
        bound_refs = _strategy_search(
            "typevar_bound",
            bound_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if bound_refs:
            _defs, usages = filter_grep_results(bound_refs, finding)
            if usages:
                results["typevar_bound"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="typevar_bound"
                )

    elif kind == "method":
        method_parts = full_name.split(".")
        if len(method_parts) >= 2:
            parent_class = method_parts[-2]
            if len(parent_class) > 2:
                cast_pattern = rf"cast\([^,]+,\s*[^)]*\b{parent_class}\b"
                cast_refs = _strategy_search(
                    "cast_protocol",
                    cast_pattern,
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if cast_refs:
                    _defs, usages = filter_grep_results(cast_refs, finding)
                    if usages:
                        results["cast_protocol"] = limit_grep_evidence(
                            usages, max_per_strategy, strategy="cast_protocol"
                        )

    test_refs = _strategy_search(
        "test_references",
        rf"\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["test_*.py", "*_test.py", "conftest.py"],
        max_results=max_per_strategy,
    )
    if test_refs:
        test_refs = [r for r in test_refs if not is_substring_match(r, simple_name)]
        _defs, test_usages = filter_grep_results(test_refs, finding)
        if test_usages:
            results["test_references"] = limit_grep_evidence(
                test_usages, max_per_strategy, strategy="test_references"
            )

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if rel_file and rel_file.endswith(".py"):
        file_refs = _strategy_search(
            "file_path_references",
            rel_file,
            project_root,
            fixed_string=True,
            max_results=max_per_strategy,
        )
        if file_refs:
            _defs, usages = filter_grep_results(file_refs, finding)
            if usages:
                results["file_path_references"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="file_path_references"
                )

        config_refs = _strategy_search(
            "config_references",
            rel_file,
            project_root,
            fixed_string=True,
            include_globs=["*.toml", "*.cfg", "*.ini", "*.yaml", "*.yml"],
            max_results=max_per_strategy,
        )
        if config_refs:
            _defs, usages = filter_grep_results(config_refs, finding)
            if usages:
                results["config_references"] = limit_grep_evidence(
                    usages, max_per_strategy, strategy="config_references"
                )

    for module_name in module_names:
        module_refs = _strategy_search(
            "module_references",
            module_name,
            project_root,
            fixed_string=True,
            max_results=max_per_strategy,
        )
        if module_refs:
            _defs, usages = filter_grep_results(module_refs, finding)
            if usages:
                combined = _deduplicate_grep_results(
                    {"module_references": results.get("module_references", []) + usages}
                )["module_references"]
                results["module_references"] = limit_grep_evidence(
                    combined, max_per_strategy, strategy="module_references"
                )
                if stop_after_strong_evidence:
                    break

    doc_refs = _strategy_search(
        "documentation",
        rf"\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["*.rst", "*.md"],
        max_results=max_per_strategy * 2,
    )
    if doc_refs:
        doc_refs = [r for r in doc_refs if not is_substring_match(r, simple_name)]
        if doc_refs:
            compatibility_refs = [
                r
                for r in doc_refs
                if any(
                    keyword in r.lower()
                    for keyword in (
                        "reintroduced",
                        "restored",
                        "backward compatibility",
                        "backwards compatibility",
                        "compatibility",
                        "synonym",
                        "alias",
                        "shim",
                        "shortcut",
                    )
                )
            ]
            if compatibility_refs:
                results["compatibility_references"] = limit_grep_evidence(
                    compatibility_refs,
                    max_per_strategy,
                    strategy="compatibility_references",
                )
            sphinx_refs = [
                r
                for r in doc_refs
                if any(
                    pat in r
                    for pat in [
                        ":func:",
                        ":meth:",
                        ":class:",
                        ":attr:",
                        "autofunction",
                        "autoclass",
                        "automethod",
                        "automodule",
                        ".. function::",
                        ".. method::",
                    ]
                )
            ]
            if sphinx_refs:
                results["sphinx_directive"] = limit_grep_evidence(
                    sphinx_refs, max_per_strategy, strategy="sphinx_directive"
                )
            else:
                results["doc_references"] = limit_grep_evidence(
                    doc_refs, max_per_strategy, strategy="doc_references"
                )

            if not simple_name.startswith("_"):
                changelog_patterns = [
                    "changelog",
                    "changes",
                    "history",
                    "news",
                    "release",
                ]
                api_refs = []
                for ref in doc_refs:
                    ref_path = _grep_line_path(ref).replace("\\", "/").lower()
                    in_docs_dir = (
                        ref_path.startswith("docs/")
                        or ref_path.startswith("doc/")
                        or "/docs/" in ref_path
                        or "/doc/" in ref_path
                    )
                    if not in_docs_dir:
                        continue
                    if any(pattern in ref_path for pattern in changelog_patterns):
                        continue
                    api_refs.append(ref)
                if api_refs:
                    results["public_api_docs"] = limit_grep_evidence(
                        api_refs, max_per_strategy, strategy="public_api_docs"
                    )

    if kind == "method":
        parts = full_name.split(".")
        if len(parts) >= 2:
            class_name = parts[-2]
            if len(class_name) > 2:
                class_refs = _strategy_search(
                    "class_usage",
                    rf"\b{class_name}\b",
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if class_refs:
                    usage_lines = []
                    for cr in class_refs:
                        line_text = _grep_line_content(cr)
                        if re.search(
                            rf"^\s*class\s+{re.escape(class_name)}", line_text
                        ):
                            continue
                        usage_lines.append(cr)
                    if usage_lines:
                        results["class_usage"] = limit_grep_evidence(
                            usage_lines, max_per_strategy, strategy="class_usage"
                        )

    return _deduplicate_grep_results(results)
