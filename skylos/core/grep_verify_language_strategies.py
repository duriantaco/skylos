from __future__ import annotations

import re

from skylos.core.grep_verify_common import (
    _LANG_GLOBS,
    _run_grep,
    detect_language,
    filter_grep_results,
)


def _deterministic_suppress_ts(finding: dict) -> bool:
    file_path = finding.get("file", "")
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")

    if any(marker in file_path for marker in (".test.", ".spec.", "__tests__/")):
        if kind in ("function", "class") and simple_name.startswith("test"):
            return True

    if file_path.endswith("index.ts") or file_path.endswith("index.js"):
        if kind == "import":
            return True

    return False


def _deterministic_suppress_go(finding: dict) -> bool:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    file_path = finding.get("file", "")

    if simple_name.startswith("Test") and file_path.endswith("_test.go"):
        return True

    return False


def _deterministic_suppress_java(finding: dict) -> bool:
    decorators = finding.get("decorators", [])
    if isinstance(decorators, list):
        for dec in decorators:
            if str(dec).strip() in (
                "@Test",
                "@Override",
                "@Bean",
                "@Autowired",
                "@Component",
            ):
                return True
    return False


def _deterministic_suppress_php(finding: dict) -> bool:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    file_path = str(finding.get("file", "")).lower()

    if simple_name in {"__construct", "__destruct", "__invoke", "__toString"}:
        return True

    if "/tests/" in file_path or file_path.endswith("test.php"):
        if simple_name.startswith("test") or simple_name in {"setUp", "tearDown"}:
            return True

    return False


def _deterministic_suppress_rust(finding: dict) -> bool:
    decorators = finding.get("decorators", [])

    if isinstance(decorators, list):
        for dec in decorators:
            dec_str = str(dec).strip()
            if dec_str in ("#[test]", "#[cfg(test)]", "#[derive"):
                return True

    if finding.get("type") == "method":
        full_name = finding.get("full_name", "")
        if "::impl::" in full_name or "::Impl::" in full_name:
            return True

    return False


def _deterministic_suppress_multilang(finding: dict) -> bool:
    lang = detect_language(finding.get("file", ""))
    if lang == "typescript":
        return _deterministic_suppress_ts(finding)
    elif lang == "go":
        return _deterministic_suppress_go(finding)
    elif lang == "java":
        return _deterministic_suppress_java(finding)
    elif lang == "php":
        return _deterministic_suppress_php(finding)
    elif lang == "rust":
        return _deterministic_suppress_rust(finding)
    return False


def _run_ts_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    ts_globs = _LANG_GLOBS["typescript"]

    if not simple_name or len(simple_name) <= 1:
        return results

    import_pattern = rf"import\s+.*\b{re.escape(simple_name)}\b"
    import_refs = _run_grep(
        import_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if import_refs:
        _defs, usages = filter_grep_results(import_refs, finding)
        if usages:
            results["ts_imports"] = usages[:max_per_strategy]

    require_pattern = rf'require\s*\(["\x27].*{re.escape(simple_name)}["\x27]\)'
    require_refs = _run_grep(
        require_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if require_refs:
        _defs, usages = filter_grep_results(require_refs, finding)
        if usages:
            results["ts_require"] = usages[:max_per_strategy]

    if kind in ("class", "function", "variable") and simple_name[0].isupper():
        jsx_pattern = rf"<{re.escape(simple_name)}[\s/>]"
        jsx_refs = _run_grep(
            jsx_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.tsx", "*.jsx"],
            max_results=max_per_strategy,
        )
        if jsx_refs:
            _defs, usages = filter_grep_results(jsx_refs, finding)
            if usages:
                results["ts_jsx_usage"] = usages[:max_per_strategy]

    # Barrel exports: export { X }
    export_pattern = rf"export\s*\{{[^}}]*\b{re.escape(simple_name)}\b"
    export_refs = _run_grep(
        export_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if export_refs:
        _defs, usages = filter_grep_results(export_refs, finding)
        if usages:
            results["ts_barrel_export"] = usages[:max_per_strategy]

    # Decorator usage: @Decorator
    if kind in ("class", "function"):
        dec_pattern = rf"@{re.escape(simple_name)}"
        dec_refs = _run_grep(
            dec_pattern,
            project_root,
            use_regex=True,
            include_globs=ts_globs,
            max_results=max_per_strategy,
        )
        if dec_refs:
            _defs, usages = filter_grep_results(dec_refs, finding)
            if usages:
                results["ts_decorator"] = usages[:max_per_strategy]

    if kind in ("class", "interface"):
        impl_pattern = rf"implements\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=ts_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["ts_implements"] = usages[:max_per_strategy]

    return results


def _run_go_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    go_globs = _LANG_GLOBS["go"]

    if not simple_name or len(simple_name) <= 1:
        return results

    call_pattern = rf"\b\w+\.{re.escape(simple_name)}\s*\("
    call_refs = _run_grep(
        call_pattern,
        project_root,
        use_regex=True,
        include_globs=go_globs,
        max_results=max_per_strategy,
    )
    if call_refs:
        _defs, usages = filter_grep_results(call_refs, finding)
        if usages:
            results["go_calls"] = usages[:max_per_strategy]

    if kind == "method":
        iface_pattern = rf"\b{re.escape(simple_name)}\s*\("
        iface_refs = _run_grep(
            iface_pattern,
            project_root,
            use_regex=True,
            include_globs=go_globs,
            max_results=max_per_strategy,
        )
        if iface_refs:
            _defs, usages = filter_grep_results(iface_refs, finding)
            if usages:
                results["go_interface_method"] = usages[:max_per_strategy]

    # Struct field references
    if kind in ("variable", "field"):
        field_pattern = rf"\.{re.escape(simple_name)}\b"
        field_refs = _run_grep(
            field_pattern,
            project_root,
            use_regex=True,
            include_globs=go_globs,
            max_results=max_per_strategy,
        )
        if field_refs:
            _defs, usages = filter_grep_results(field_refs, finding)
            if usages:
                results["go_field_refs"] = usages[:max_per_strategy]

    return results


def _run_java_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    java_globs = _LANG_GLOBS["java"]

    if not simple_name or len(simple_name) <= 1:
        return results

    import_pattern = rf"import\s+.*\b{re.escape(simple_name)}\b"
    import_refs = _run_grep(
        import_pattern,
        project_root,
        use_regex=True,
        include_globs=java_globs,
        max_results=max_per_strategy,
    )
    if import_refs:
        _defs, usages = filter_grep_results(import_refs, finding)
        if usages:
            results["java_imports"] = usages[:max_per_strategy]

    if kind == "method":
        override_pattern = rf"@Override.*\b{re.escape(simple_name)}\b"
        override_refs = _run_grep(
            override_pattern,
            project_root,
            use_regex=True,
            include_globs=java_globs,
            max_results=max_per_strategy,
        )
        if override_refs:
            results["java_override"] = override_refs[:max_per_strategy]

    # implements/extends
    if kind == "class":
        impl_pattern = rf"(?:implements|extends)\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=java_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["java_implements"] = usages[:max_per_strategy]

    spring_pattern = rf"@\w+.*\b{re.escape(simple_name)}\b"
    spring_refs = _run_grep(
        spring_pattern,
        project_root,
        use_regex=True,
        include_globs=java_globs,
        max_results=max_per_strategy,
    )
    if spring_refs:
        _defs, usages = filter_grep_results(spring_refs, finding)
        if usages:
            results["java_annotations"] = usages[:max_per_strategy]

    return results


def _run_rust_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    rust_globs = _LANG_GLOBS["rust"]

    if not simple_name or len(simple_name) <= 1:
        return results

    use_pattern = rf"use\s+.*\b{re.escape(simple_name)}\b"
    use_refs = _run_grep(
        use_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if use_refs:
        _defs, usages = filter_grep_results(use_refs, finding)
        if usages:
            results["rust_use"] = usages[:max_per_strategy]

    if kind in ("class", "trait"):
        impl_pattern = rf"impl\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=rust_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["rust_impl"] = usages[:max_per_strategy]

    derive_pattern = rf"#\[derive\([^)]*\b{re.escape(simple_name)}\b"
    derive_refs = _run_grep(
        derive_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if derive_refs:
        results["rust_derive"] = derive_refs[:max_per_strategy]

    pub_pattern = rf"\b{re.escape(simple_name)}\s*\("
    pub_refs = _run_grep(
        pub_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if pub_refs:
        _defs, usages = filter_grep_results(pub_refs, finding)
        if usages:
            results["rust_calls"] = usages[:max_per_strategy]

    return results
