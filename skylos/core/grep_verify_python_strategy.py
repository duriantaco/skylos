from __future__ import annotations

import re

from skylos.core.grep_verify_common import (
    _deduplicate_grep_results,
    _filter_other_owner_same_method_calls,
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


def multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
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

    def _should_early_exit() -> bool:
        for strategy in _STRONG_ALIVE_STRATEGIES:
            hits = results.get(strategy, [])
            if len(hits) >= early_exit_threshold:
                return True
        return False

    boundary_pattern = rf"\b{simple_name}\b"
    if kind != "import":
        refs = _run_grep(
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
                results["references"] = usages[:max_per_strategy]
            elif _defs:
                results["references_definition_only"] = [
                    "(only the definition itself found, no usages)"
                ]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if full_name and full_name != simple_name:
        qualified_refs = _run_grep(
            rf"\b{re.escape(full_name)}\b",
            project_root,
            use_regex=True,
            max_results=max_per_strategy,
        )
        if qualified_refs:
            _defs, usages = filter_grep_results(qualified_refs, finding)
            if usages:
                results["qualified_references"] = usages[:max_per_strategy]

    if kind in ("method", "function"):
        call_pattern = rf"\.{re.escape(simple_name)}[[:space:]]*\("
        call_refs = _run_grep(
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
                results["method_calls"] = usages[:max_per_strategy]

    if kind != "import":
        import_pattern = rf"import.*\b{simple_name}\b"
        import_refs = _run_grep(
            import_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if import_refs:
            _defs, usages = filter_grep_results(import_refs, finding)
            if usages:
                results["imports"] = usages[:max_per_strategy]

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
        dp_refs = _run_grep(
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
                results["string_dispatch"] = usages[:max_per_strategy]
                break

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    all_refs = _run_grep(
        rf"__all__.*\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["*.py"],
        max_results=max_per_strategy,
    )
    if all_refs:
        results["exported_in_all"] = all_refs[:max_per_strategy]

    if kind in ("import", "variable", "class"):
        cast_pattern = rf'cast\(\s*["\x27]{simple_name}["\x27]'
        cast_refs = _run_grep(
            cast_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if cast_refs:
            _defs, usages = filter_grep_results(cast_refs, finding)
            if usages:
                results["cast_usage"] = usages[:max_per_strategy]

        bound_pattern = rf'bound\s*=\s*["\x27]{simple_name}["\x27]'
        bound_refs = _run_grep(
            bound_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if bound_refs:
            _defs, usages = filter_grep_results(bound_refs, finding)
            if usages:
                results["typevar_bound"] = usages[:max_per_strategy]

    elif kind == "method":
        method_parts = full_name.split(".")
        if len(method_parts) >= 2:
            parent_class = method_parts[-2]
            if len(parent_class) > 2:
                cast_pattern = rf"cast\([^,]+,\s*[^)]*\b{parent_class}\b"
                cast_refs = _run_grep(
                    cast_pattern,
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if cast_refs:
                    _defs, usages = filter_grep_results(cast_refs, finding)
                    if usages:
                        results["cast_protocol"] = usages[:max_per_strategy]

    test_refs = _run_grep(
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
            results["test_references"] = test_usages[:max_per_strategy]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if rel_file and rel_file.endswith(".py"):
        file_refs = _run_grep(
            rel_file, project_root, fixed_string=True, max_results=max_per_strategy
        )
        if file_refs:
            _defs, usages = filter_grep_results(file_refs, finding)
            if usages:
                results["file_path_references"] = usages[:max_per_strategy]

        config_refs = _run_grep(
            rel_file,
            project_root,
            fixed_string=True,
            include_globs=["*.toml", "*.cfg", "*.ini", "*.yaml", "*.yml"],
            max_results=max_per_strategy,
        )
        if config_refs:
            _defs, usages = filter_grep_results(config_refs, finding)
            if usages:
                results["config_references"] = usages[:max_per_strategy]

    for module_name in module_names:
        module_refs = _run_grep(
            module_name, project_root, fixed_string=True, max_results=max_per_strategy
        )
        if module_refs:
            _defs, usages = filter_grep_results(module_refs, finding)
            if usages:
                results["module_references"] = usages[:max_per_strategy]
                break

    if kind == "parameter" and owner_simple_name:
        callback_pattern = (
            rf"callback\s*=\s*(?:[\w\.]+\.)*{re.escape(owner_simple_name)}\b"
        )
        callback_refs = _run_grep(
            callback_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if callback_refs:
            results["callback_registrations"] = callback_refs[:max_per_strategy]

        def _parse_int(value):
            return int(value) if isinstance(value, (int, float)) else 0

        signature_pattern = rf"def\s+{re.escape(owner_simple_name)}\s*\([^)]*\b{re.escape(simple_name)}\b"
        signature_refs = _run_grep(
            signature_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy * 2,
        )
        if signature_refs:
            override_refs = []
            line_num = _parse_int(finding.get("line", 0))
            for ref in signature_refs:
                parts = ref.split(":", 2)
                if len(parts) < 2 or not parts[1].isdigit():
                    continue
                match_file = parts[0]
                match_line = int(parts[1])
                if match_file == file_path and abs(match_line - line_num) <= 3:
                    continue
                override_refs.append(ref)
            if override_refs:
                results["signature_overrides"] = override_refs[:max_per_strategy]

    doc_refs = _run_grep(
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
                results["compatibility_references"] = compatibility_refs[
                    :max_per_strategy
                ]
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
                results["sphinx_directive"] = sphinx_refs[:max_per_strategy]
            else:
                results["doc_references"] = doc_refs[:max_per_strategy]

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
                    ref_path = ref.split(":", 1)[0].replace("\\", "/").lower()
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
                    results["public_api_docs"] = api_refs[:max_per_strategy]

    if kind == "method":
        parts = full_name.split(".")
        if len(parts) >= 2:
            class_name = parts[-2]
            if len(class_name) > 2:
                class_refs = _run_grep(
                    rf"\b{class_name}\b",
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if class_refs:
                    usage_lines = []
                    for cr in class_refs:
                        if ":" in cr:
                            line_text = cr.split(":", 2)[-1]
                        else:
                            line_text = cr
                        if re.search(
                            rf"^\s*class\s+{re.escape(class_name)}", line_text
                        ):
                            continue
                        usage_lines.append(cr)
                    if usage_lines:
                        results["class_usage"] = usage_lines[:max_per_strategy]

    return _deduplicate_grep_results(results)
