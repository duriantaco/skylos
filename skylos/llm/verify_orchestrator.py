from __future__ import annotations

import ast
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .dead_code_verifier import (
    DeadCodeVerifierAgent,
    Verdict,
    VerificationResult,
    apply_verdict,
    _parse_confidence,
    _parse_int,
)
from .verification import entry_points as _entry_points
from .verification.llm import (
    BATCH_SURVIVOR_SYSTEM as BATCH_SURVIVOR_SYSTEM,
    BATCH_VERIFY_SYSTEM,
    GRAPH_VERIFY_SYSTEM,
    HAIKU_PREFILTER_MAX_BATCH,
    HAIKU_PREFILTER_SYSTEM,
    MAX_BATCH_CONTEXT_CHARS,
    SUPPRESSION_AUDIT_SYSTEM,
    SURVIVOR_SYSTEM as SURVIVOR_SYSTEM,
    SURVIVOR_USER as SURVIVOR_USER,
    _call_llm_with_retry,
    _parse_batch_response,
    _parse_batch_survivor_response as _parse_batch_survivor_response,
    _strip_markdown_fences as _strip_markdown_fences,
)
from .verification.survivors import (
    _batch_challenge_survivors,
    _find_heuristic_match_sites as _find_heuristic_match_sites,
    _find_local_on_emit_survivors,
    _find_survivors,
    challenge_survivor,
)
from .verification.types import (
    VALID_VERIFICATION_MODES,
    VERIFICATION_MODE_JUDGE_ALL,
    VERIFICATION_MODE_PRODUCTION,
    EdgeResolution as EdgeResolution,
    SuppressionDecision,
    SurvivorVerdict as SurvivorVerdict,
    VerifyStats,
)
from .verification.phases import (
    VerificationOps,
    VerificationRuntime,
    run_candidate_selection_phase,
    run_entry_discovery_phase,
    run_haiku_prefilter_phase,
    run_suppression_audit_phase,
    run_verify_findings_phase,
)
from .verification.completion_phases import (
    run_finalize_phase,
    run_propagate_alive_phase,
    run_survivor_challenge_phase,
)

from skylos.core.grep_verify import (
    _run_grep,
    multi_strategy_search as _multi_strategy_search,
    parallel_multi_strategy_search as _parallel_multi_strategy_search,
    repo_relative_path as _repo_relative_path,
    module_candidates as _module_candidates,
    parameter_owner_name as _parameter_owner_name,
    detect_language as _detect_language,
)


logger = logging.getLogger(__name__)


EntryPoint = _entry_points.EntryPoint
RepoFacts = _entry_points.RepoFacts
ENTRY_POINT_SYSTEM = _entry_points.ENTRY_POINT_SYSTEM
ENTRY_POINT_USER = _entry_points.ENTRY_POINT_USER


def _gather_config_files(project_root: Path) -> dict[str, str]:
    return _entry_points._gather_config_files(project_root)


def _build_repo_facts(project_root: Path) -> RepoFacts:
    return _entry_points._build_repo_facts(
        project_root,
        gather_config_files=_gather_config_files,
    )


def _matches_pytest_pattern(name: str, patterns: list[str]) -> bool:
    return _entry_points._matches_pytest_pattern(name, patterns)


def _class_node_for_finding(source: str, finding: dict) -> Any | None:
    import ast

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    simple_name = str(finding.get("simple_name", finding.get("name", "")))
    line_num = _parse_int(finding.get("line", 0))
    best = None
    best_distance = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name != simple_name:
            continue
        distance = abs(getattr(node, "lineno", 0) - line_num)
        if best is None or distance < (best_distance or 10_000):
            best = node
            best_distance = distance
    return best


def _base_name(expr: Any) -> str:
    if hasattr(expr, "id"):
        return str(expr.id)
    if hasattr(expr, "attr"):
        return str(expr.attr)
    return ""


def _is_collectible_test_class(
    finding: dict, source: str, repo_facts: RepoFacts
) -> bool:
    import ast

    if str(finding.get("type", "")).lower() != "class":
        return False
    file_path = str(finding.get("file", ""))
    if not _is_test_context(file_path):
        return False

    class_node = _class_node_for_finding(source, finding)
    if class_node is None:
        return False

    class_name = class_node.name
    base_names = {_base_name(base) for base in class_node.bases}
    matches_pytest = _matches_pytest_pattern(
        class_name, repo_facts.pytest_class_patterns
    )
    matches_unittest = any(name.endswith("TestCase") for name in base_names if name)
    if not matches_pytest and not matches_unittest:
        return False

    for stmt in class_node.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "__test__":
                    if (
                        isinstance(stmt.value, ast.Constant)
                        and stmt.value.value is False
                    ):
                        return False

    method_names = {
        stmt.name
        for stmt in class_node.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if "__init__" in method_names or "__new__" in method_names:
        return False

    for method_name in method_names:
        if _matches_pytest_pattern(method_name, repo_facts.pytest_function_patterns):
            return True
    return False


def _definition_executes_for_side_effect(finding: dict, source: str) -> bool:
    import re

    if str(finding.get("type", "")).lower() != "class" or not source:
        return False

    line_num = _parse_int(finding.get("line", 0))
    if line_num <= 0:
        return False

    lines = source.splitlines()
    start = max(0, line_num - 7)
    end = min(len(lines), line_num + 1)
    nearby = "\n".join(lines[start:end])
    return bool(
        re.search(r"with\s+.*(?:pytest\.)?raises\s*\(", nearby)
        or re.search(r"with\s+.*assertRaises\s*\(", nearby)
    )


def _function_node_for_finding(source: str, finding: dict) -> Any | None:
    import ast

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    simple_name = str(finding.get("simple_name", finding.get("name", "")))
    if str(finding.get("type", "")).lower() == "parameter":
        owner_name = _parameter_owner_name(finding)
        if owner_name:
            simple_name = owner_name.rsplit(".", 1)[-1]

    line_num = _parse_int(finding.get("line", 0))
    best = None
    best_distance = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != simple_name:
            continue

        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if line_num and start <= line_num <= end:
            return node

        distance = abs(start - line_num)
        if best is None or distance < (best_distance or 10_000):
            best = node
            best_distance = distance
    return best


def _function_body_is_stub(node: Any) -> bool:
    import ast

    body = list(getattr(node, "body", []))
    if body and isinstance(body[0], ast.Expr):
        value = getattr(body[0], "value", None)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            body = body[1:]

    if len(body) != 1:
        return False

    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(
        getattr(stmt, "value", None), ast.Constant
    ):
        return getattr(stmt.value, "value", None) is Ellipsis
    if isinstance(stmt, ast.Raise):
        exc = getattr(stmt, "exc", None)
        if isinstance(exc, ast.Call):
            exc = exc.func
        return _base_name(exc) == "NotImplementedError"
    return False


def _parameter_contract_evidence(
    finding: dict,
    source: str,
    search_results: dict[str, list[str]],
) -> list[str]:
    if str(finding.get("type", "")).lower() != "parameter":
        return []

    evidence: list[str] = []
    owner_full_name = _parameter_owner_name(finding)
    is_method_parameter = owner_full_name.count(".") >= 2
    callback_hits = search_results.get("callback_registrations") or []
    if callback_hits:
        evidence.append("Runtime callback registration exists for the owning function")
        evidence.extend(callback_hits[:2])

    override_hits = search_results.get("signature_overrides") or []
    if source:
        function_node = _function_node_for_finding(source, finding)
    else:
        function_node = None
    if (
        is_method_parameter
        and override_hits
        and function_node is not None
        and _function_body_is_stub(function_node)
    ):
        evidence.append(
            "Owning method is an interface-style stub with matching override signatures"
        )
        evidence.extend(override_hits[:2])

    return evidence


def _entry_point_cache_path(project_root: Path) -> Path:
    return _entry_points._entry_point_cache_path(project_root)


def _config_files_hash(configs: dict[str, str]) -> str:
    return _entry_points._config_files_hash(configs)


def discover_entry_points(
    agent: DeadCodeVerifierAgent,
    project_root: Path,
    known_entry_points: list[str],
) -> list[EntryPoint]:
    return _entry_points.discover_entry_points(
        agent,
        project_root,
        known_entry_points,
        llm_call=_call_llm_with_retry,
        gather_config_files=_gather_config_files,
        entry_point_cache_path=_entry_point_cache_path,
        config_files_hash=_config_files_hash,
        log=logger,
    )


def _find_git_root(path: Path) -> Path | None:
    current = path.resolve()
    for _ in range(10):
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _read_context_around_match(grep_line: str, context_lines: int = 8) -> str | None:
    try:
        parts = grep_line.split(":")
        if len(parts) < 2:
            return None
        file_path = parts[0]
        line_str = parts[1].strip()
        if not line_str.isdigit():
            return None
        line_num = int(line_str)

        with open(file_path, "r", errors="replace") as f:
            all_lines = f.readlines()

        start = max(0, line_num - context_lines - 1)
        end = min(len(all_lines), line_num + context_lines)

        context_parts = []
        for i in range(start, end):
            if i == line_num - 1:
                marker = " >>> "
            else:
                marker = "     "
            context_parts.append(f"{i + 1:4d}{marker}{all_lines[i].rstrip()}")

        return "\n".join(context_parts)
    except (OSError, ValueError, IndexError):
        return None


def _enrich_search_results(
    search_results: dict[str, list[str]],
    max_contexts: int = 8,
) -> dict[str, str]:
    enriched = {}
    total_contexts = 0
    seen_file_lines: set[str] = set()  # cross-strategy dedup

    enrich_strategies = [
        "references",
        "imports",
        "conditional_import",
        "method_calls",
        "cast_usage",
        "cast_protocol",
        "typevar_bound",
        "string_dispatch",
        "exported_in_all",
        "sphinx_directive",
        "test_references",
        "qualified_references",
        "file_path_references",
        "module_references",
        "config_references",
        "compatibility_references",
        "callback_registrations",
        "signature_overrides",
        "public_api_docs",
    ]

    for strategy in enrich_strategies:
        lines = search_results.get(strategy, [])
        if not lines:
            continue

        contexts = []
        for line in lines[:2]:
            if total_contexts >= max_contexts:
                break
            parts = line.split(":", 2)
            if len(parts) >= 2 and parts[1].strip().isdigit():
                key = f"{parts[0]}:{parts[1]}"
            else:
                key = line
            if key in seen_file_lines:
                continue
            seen_file_lines.add(key)
            ctx = _read_context_around_match(line)
            if ctx:
                contexts.append(ctx)
                total_contexts += 1

        if contexts:
            enriched[strategy] = "\n---\n".join(contexts)

        if total_contexts >= max_contexts:
            break

    return enriched


_pip_install_cache: dict[str, str | None] = {}
_pip_temp_dirs: list = []


def _pip_install_to_temp(pip_name: str) -> str | None:
    """Disabled: installing packages named by analyzed repositories is unsafe."""
    logger.debug("_pip_install_to_temp disabled for security (requested: %s)", pip_name)
    return None


def _find_parent_class_info_ts(
    finding: dict,
    source_cache: dict[str, str],
    project_root: str = "",
) -> str | None:

    import re

    simple_name = finding.get("simple_name", finding.get("name", ""))
    full_name = finding.get("full_name", "")
    file_path = finding.get("file", "")

    parts = full_name.split(".")
    if len(parts) < 2:
        return None

    class_name = parts[-2]
    source = source_cache.get(file_path, "")
    if not source:
        return None

    ts_class_pat = re.compile(
        rf"class\s+{re.escape(class_name)}\s+extends\s+(\S+?)(?:\s+implements\s+(\S+?))?\s*\{{",
    )
    match = ts_class_pat.search(source)
    if not match:
        ts_impl_pat = re.compile(
            rf"class\s+{re.escape(class_name)}\s+implements\s+(\S+?)\s*\{{",
        )
        match = ts_impl_pat.search(source)
        if not match:
            return None
        bases = [match.group(1).strip().rstrip("{")]
    else:
        bases = [match.group(1).strip().rstrip("{")]
        if match.group(2):
            bases.append(match.group(2).strip().rstrip("{"))

    info = f"Class `{class_name}` extends/implements: {', '.join(bases)}."

    if not project_root:
        return info

    found_in_parent = False
    ts_globs = ["*.ts", "*.tsx", "*.js", "*.jsx"]

    for base in bases:
        base_name = base.split("<")[0].strip()
        if not base_name:
            continue

        parent_class_refs = _run_grep(
            rf"class\s+{re.escape(base_name)}",
            project_root,
            use_regex=True,
            include_globs=ts_globs,
            max_results=3,
        )
        if parent_class_refs:
            for ref in parent_class_refs:
                parent_file = ref.split(":")[0]
                method_in_parent = _run_grep(
                    rf"(?:public|protected|private)?\s*(?:async\s+)?{re.escape(simple_name)}\s*[\(<]",
                    parent_file,
                    use_regex=True,
                    max_results=2,
                )
                if method_in_parent:
                    info += (
                        f"\n  CONFIRMED: Parent `{base_name}` defines `{simple_name}`:"
                    )
                    for mr in method_in_parent[:2]:
                        info += f"\n    {mr}"
                    found_in_parent = True
                    break
        if found_in_parent:
            break

        if not found_in_parent:
            nm_dir = Path(project_root) / "node_modules"
            if nm_dir.is_dir():
                dts_refs = _run_grep(
                    rf"(?:export\s+)?(?:declare\s+)?(?:abstract\s+)?class\s+{re.escape(base_name)}",
                    str(nm_dir),
                    use_regex=True,
                    include_globs=["*.d.ts"],
                    max_results=3,
                )
                if dts_refs:
                    for ref in dts_refs:
                        dts_file = ref.split(":")[0]
                        method_in_dts = _run_grep(
                            rf"{re.escape(simple_name)}\s*[\(<]",
                            dts_file,
                            use_regex=True,
                            max_results=2,
                        )
                        if method_in_dts:
                            info += f"\n  CONFIRMED (node_modules .d.ts): Parent `{base_name}` defines `{simple_name}`:"
                            for mr in method_in_dts[:2]:
                                info += f"\n    {mr}"
                            found_in_parent = True
                            break
        if found_in_parent:
            break

    if found_in_parent:
        info += f"\n  Method `{simple_name}` is a confirmed override — overrides are NOT dead code."
    else:
        info += f"\n  Method `{simple_name}` has parent classes but could not confirm it overrides a parent method."
        info += (
            "\n  Check if the parent framework/library defines this method externally."
        )

    return info


def _python_base_names(class_node: ast.ClassDef) -> list[tuple[str, str]]:
    bases: list[tuple[str, str]] = []
    for base in class_node.bases:
        display = ast.unparse(base) if hasattr(ast, "unparse") else _base_name(base)
        base_name = _base_name(base)
        if display and base_name:
            bases.append((display, base_name))
    return bases


def _python_class_bases(source: str, class_name: str) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return _python_base_names(node)
    return []


def _python_imported_class_modules(source: str) -> dict[str, tuple[str, int, str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    imported: dict[str, tuple[str, int, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            imported[local_name] = (module, node.level, alias.name)
    return imported


def _local_module_path_candidates(
    module_path: str,
    import_level: int,
    current_file: str,
    project_root: str,
) -> list[Path]:
    if not project_root:
        return []

    root = Path(project_root).resolve()
    current = Path(current_file)
    if not current.is_absolute():
        current = root / current

    if import_level:
        base_dir = current.parent
        for _ in range(max(import_level - 1, 0)):
            base_dir = base_dir.parent
    else:
        base_dir = root

    module_parts = [part for part in module_path.split(".") if part]
    module_base = base_dir.joinpath(*module_parts)
    candidates = [module_base.with_suffix(".py"), module_base / "__init__.py"]

    safe_candidates: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        safe_candidates.append(resolved)
    return safe_candidates


def _read_cached_or_local_source(
    path: Path,
    source_cache: dict[str, str],
) -> str:
    path_str = str(path)
    if path_str in source_cache:
        return source_cache[path_str]
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _static_parent_method_refs_in_local_module(
    base_name: str,
    simple_name: str,
    module_path: str,
    import_level: int,
    current_file: str,
    project_root: str,
    source_cache: dict[str, str],
) -> list[str]:
    refs: list[str] = []
    for candidate in _local_module_path_candidates(
        module_path,
        import_level,
        current_file,
        project_root,
    ):
        source = _read_cached_or_local_source(candidate, source_cache)
        if not source:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name != base_name:
                continue
            for stmt in node.body:
                if (
                    isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and stmt.name == simple_name
                ):
                    refs.append(f"{candidate}:{stmt.lineno}: def {simple_name}(...)")
            if refs:
                return refs
    return refs


def _find_parent_class_info(
    finding: dict,
    source_cache: dict[str, str],
    project_root: str = "",
) -> str | None:
    import re

    kind = finding.get("type", "")
    if kind not in ("method", "function"):
        return None

    simple_name = finding.get("simple_name", finding.get("name", ""))
    full_name = finding.get("full_name", "")
    file_path = finding.get("file", "")

    lang = _detect_language(file_path)
    if lang == "typescript":
        return _find_parent_class_info_ts(finding, source_cache, project_root)

    parts = full_name.split(".")
    if len(parts) < 2:
        return None

    class_name = parts[-2]

    source = source_cache.get(file_path, "")
    if not source:
        return None

    base_pairs = _python_class_bases(source, class_name)
    if not base_pairs:
        return None

    bases = [display for display, _base_name_value in base_pairs]
    info = f"Class `{class_name}` inherits from: {', '.join(bases)}."

    if project_root:
        found_in_parent = False
        for _base_display, base_name in base_pairs:
            if base_name in ("object", "ABC", "Protocol"):
                continue
            parent_method_refs = _run_grep(
                rf"class\s+{re.escape(base_name)}",
                project_root,
                use_regex=True,
                include_globs=["*.py"],
                max_results=3,
            )
            if parent_method_refs:
                for ref in parent_method_refs:
                    parent_file = ref.split(":")[0]
                    method_in_parent = _run_grep(
                        rf"def\s+{re.escape(simple_name)}\s*\(",
                        parent_file,
                        use_regex=True,
                        max_results=2,
                    )
                    if method_in_parent:
                        info += f"\n  CONFIRMED: Parent `{base_name}` defines `{simple_name}`:"
                        for mr in method_in_parent[:2]:
                            info += f"\n    {mr}"
                        found_in_parent = True
                        break
            if found_in_parent:
                break

        if not found_in_parent:
            imported_modules = _python_imported_class_modules(source)
            for _base_display, base_name in base_pairs:
                if base_name in ("object", "ABC", "Protocol"):
                    continue
                imported = imported_modules.get(base_name)
                if not imported:
                    continue
                module_path, import_level, imported_class_name = imported
                method_refs = _static_parent_method_refs_in_local_module(
                    imported_class_name,
                    simple_name,
                    module_path,
                    import_level,
                    file_path,
                    project_root,
                    source_cache,
                )
                if method_refs:
                    info += f"\n  CONFIRMED (static local module): Parent `{module_path}.{imported_class_name}` defines `{simple_name}`:"
                    for mr in method_refs[:2]:
                        info += f"\n    {mr}"
                    found_in_parent = True
                    break

            if not found_in_parent:
                import sys

                for site_dir in sys.path:
                    if "site-packages" not in site_dir:
                        continue
                    for _base_display, base_name in base_pairs:
                        if base_name in ("object", "ABC", "Protocol"):
                            continue
                        parent_method_refs = _run_grep(
                            rf"def\s+{re.escape(simple_name)}\s*\(",
                            site_dir,
                            use_regex=True,
                            include_globs=["*.py"],
                            max_results=3,
                        )
                        if parent_method_refs:
                            for pmr in parent_method_refs:
                                parent_file = pmr.split(":")[0]
                                class_in_file = _run_grep(
                                    rf"class\s+{re.escape(base_name)}",
                                    parent_file,
                                    use_regex=True,
                                    max_results=1,
                                )
                                if class_in_file:
                                    info += f"\n  CONFIRMED (external library): Parent `{base_name}` defines `{simple_name}`:"
                                    for mr in parent_method_refs[:2]:
                                        info += f"\n    {mr}"
                                    found_in_parent = True
                                    break
                        if found_in_parent:
                            break
                    if found_in_parent:
                        break

        if found_in_parent:
            info += f"\n  Method `{simple_name}` is a confirmed override — overrides are NOT dead code."
        else:
            if source:
                source_lines = source.splitlines()
                method_start = max(0, finding.get("line", 1) - 1)
                check_range = source_lines[
                    method_start : min(method_start + 5, len(source_lines))
                ]
                hint_text = " ".join(check_range).lower()
                if any(
                    hint in hint_text
                    for hint in [
                        "part of the abc",
                        "abc override",
                        "abstract",
                        "pragma: no cover",
                        "required by",
                        "interface",
                        "protocol",
                    ]
                ):
                    info += "\n  HINT: Code comments/pragmas suggest this is an ABC/interface override."
                    info += f"\n  Method `{simple_name}` is likely a required override — treat as NOT dead code."
                else:
                    info += f"\n  Method `{simple_name}` has parent classes but could not confirm it overrides a parent method."
                    info += "\n  Check if the parent framework/library defines this method externally."
            else:
                info += f"\n  Method `{simple_name}` has parent classes but could not confirm it overrides a parent method."
                info += "\n  Check if the parent framework/library defines this method externally."

    return info


def _find_string_dispatch(
    simple_name: str,
    project_root: str,
    max_results: int = 10,
) -> list[str]:
    import subprocess

    patterns = [
        f'"{simple_name}"',
        f"'{simple_name}'",
    ]

    results = []
    for pattern in patterns:
        try:
            cmd = [
                "grep",
                "-rn",
                "--include=*.py",
                pattern,
                project_root,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                if "__pycache__" not in line and line not in results:
                    results.append(line)
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("String dispatch grep failed: %s", exc)

    return results[:max_results]


def _extract_joined_string_family(
    node: ast.AST | None,
) -> tuple[str, str, str] | None:
    if not isinstance(node, ast.JoinedStr):
        return None

    prefix_parts: list[str] = []
    suffix_parts: list[str] = []
    dynamic_name = None

    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            if dynamic_name is None:
                prefix_parts.append(part.value)
            else:
                suffix_parts.append(part.value)
        elif (
            isinstance(part, ast.FormattedValue)
            and dynamic_name is None
            and isinstance(part.value, ast.Name)
        ):
            dynamic_name = part.value.id
        else:
            return None

    if not dynamic_name:
        return None
    return "".join(prefix_parts), dynamic_name, "".join(suffix_parts)


def _match_dynamic_dispatch_name(
    simple_name: str,
    prefix: str,
    suffix: str,
) -> str | None:
    if not simple_name.startswith(prefix):
        return None
    if suffix and not simple_name.endswith(suffix):
        return None

    end = len(simple_name) - len(suffix) if suffix else len(simple_name)
    dynamic_fragment = simple_name[len(prefix) : end]
    return dynamic_fragment or None


def _literal_string_values(node: ast.AST | None) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values: list[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                values.append(elt.value)
            else:
                return []
        return values
    return []


def _is_module_namespace_target(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in {"globals", "locals", "vars"}

    if not isinstance(node, ast.Subscript):
        return False
    if not (
        isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "sys"
        and node.value.attr == "modules"
    ):
        return False

    slice_node = node.slice
    if isinstance(slice_node, ast.Name):
        return slice_node.id == "__name__"
    if isinstance(slice_node, ast.Constant):
        return slice_node.value == "__name__"
    return False


def _module_local_dynamic_dispatch_evidence(
    finding: dict,
    source: str,
    defs_map: dict[str, Any] | None = None,
) -> list[str]:
    simple_name = str(finding.get("simple_name", finding.get("name", ""))).strip()
    file_path = str(finding.get("file", ""))
    if not simple_name or not source:
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def _enclosing(node: ast.AST, types: tuple[type[ast.AST], ...]) -> ast.AST | None:
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, types):
                return current
        return None

    def _map_used_later(name: str, line_no: int) -> bool:
        for child in ast.walk(tree):
            if (
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load)
                and child.id == name
                and getattr(child, "lineno", 0) > line_no
            ):
                return True
        return False

    def _dispatcher_alive(name: str) -> bool:
        if not defs_map:
            return False
        for info in defs_map.values():
            if not isinstance(info, dict):
                continue
            if info.get("file") != file_path:
                continue
            if str(info.get("name", "")).split(".")[-1] != name:
                continue
            return not bool(info.get("dead", True))
        return False

    for assign in ast.walk(tree):
        if not (
            isinstance(assign, ast.Assign)
            and len(assign.targets) == 1
            and isinstance(assign.targets[0], ast.Name)
        ):
            continue
        map_name = assign.targets[0].id
        comp = assign.value
        if not isinstance(comp, ast.DictComp):
            continue

        for child in ast.walk(comp):
            if not (
                isinstance(child, ast.Subscript)
                and _is_module_namespace_target(child.value)
            ):
                continue
            family = _extract_joined_string_family(child.slice)
            if not family:
                continue
            prefix, dynamic_name, suffix = family
            dynamic_fragment = _match_dynamic_dispatch_name(simple_name, prefix, suffix)
            if not dynamic_fragment:
                continue

            for generator in comp.generators:
                if not (
                    isinstance(generator.target, ast.Name)
                    and generator.target.id == dynamic_name
                ):
                    continue
                literal_values = _literal_string_values(generator.iter)
                if dynamic_fragment in literal_values and _map_used_later(
                    map_name, getattr(assign, "lineno", 0)
                ):
                    line_no = getattr(child, "lineno", getattr(assign, "lineno", 0))
                    return [
                        f"{file_path}:{line_no}: `{map_name}` registers `{simple_name}` via dynamic globals()/locals() family dispatch"
                    ]

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.walk(func):
            if not (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "getattr"
                and len(child.args) >= 2
                and _is_module_namespace_target(child.args[0])
            ):
                continue
            family = _extract_joined_string_family(child.args[1])
            if not family:
                continue
            prefix, _dynamic_name, suffix = family
            dynamic_fragment = _match_dynamic_dispatch_name(simple_name, prefix, suffix)
            if not dynamic_fragment:
                continue
            if not _dispatcher_alive(func.name):
                continue
            line_no = getattr(child, "lineno", getattr(func, "lineno", 0))
            return [
                f'{file_path}:{line_no}: `{func.name}` resolves `{simple_name}` via getattr(..., f"{prefix}{{...}}{suffix}")'
            ]

    return []


def _finding_complexity_tier(finding: dict, search_results: dict | None) -> int:
    """Return 1 (trivial), 2 (moderate), or 3 (complex) based on finding signals."""
    if finding.get("heuristic_refs"):
        return 3
    if finding.get("decorators"):
        return 3
    if finding.get("framework_signals"):
        return 3
    if finding.get("dynamic_signals"):
        return 3
    if finding.get("is_exported"):
        return 3
    if finding.get("type") == "method":
        return 3
    hit_count = 0
    if search_results:
        hit_count = sum(len(v) for v in search_results.values() if isinstance(v, list))
    if hit_count > 3:
        return 3
    if finding.get("called_by"):
        return 2
    if hit_count >= 1:
        return 2
    return 1


_TIER_HALF_WINDOWS = {1: 10, 2: 20, 3: 30}
_TIER_MAX_CALLERS = {1: 0, 2: 3, 3: 5}
_TIER_MAX_ENRICHMENT = {1: 2, 2: 5, 3: 8}


def _build_graph_context(
    finding: dict,
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
    project_root: str = "",
    repo_facts: RepoFacts | None = None,
    *,
    grep_cache: Any = None,
) -> str:
    name = finding.get("name", "unknown")
    full_name = finding.get("full_name", name)
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    kind = finding.get("type", "function")
    refs = finding.get("references", 0)
    confidence = finding.get("confidence", 0)

    calls = finding.get("calls", [])
    called_by = finding.get("called_by", [])
    decorators = finding.get("decorators", [])
    heuristic_refs = finding.get("heuristic_refs", {})
    dynamic_signals = finding.get("dynamic_signals", [])
    framework_signals = finding.get("framework_signals", [])
    why_unused = finding.get("why_unused", [])
    why_confidence_reduced = finding.get("why_confidence_reduced", [])
    decorators_lower = _normalize_names(decorators)
    source = source_cache.get(file_path, "")
    repo_facts = repo_facts or RepoFacts()
    if project_root and file_path:
        rel_file = _repo_relative_path(file_path, project_root)
    else:
        rel_file = ""
    if project_root and file_path:
        module_names = _module_candidates(file_path, project_root)
    else:
        module_names = []
    if source:
        collectible_test_class = _is_collectible_test_class(finding, source, repo_facts)
    else:
        collectible_test_class = False
    definition_side_effect = _definition_executes_for_side_effect(finding, source)
    if not project_root:
        search_results = {}
    else:
        search_results = _get_cached_search_results(
            finding, project_root, cache=grep_cache
        )
    tier = _finding_complexity_tier(finding, search_results)
    guarded_import = _conditional_import_reason(finding, source)
    owner_full_name = _parameter_owner_name(finding)
    parameter_contract_evidence = _parameter_contract_evidence(
        finding, source, search_results
    )
    compatibility_evidence = search_results.get("compatibility_references", [])
    discovered_entry_point = finding.get("_judge_discovered_entry_point")
    prefilter_reason = finding.get("_judge_prefilter_reason")
    prefilter_rationale = finding.get("_judge_prefilter_rationale")
    prefilter_evidence = finding.get("_judge_prefilter_evidence", [])

    parts = []

    compact_search_keys = {"references_definition_only"}
    compact_context_ok = (
        tier <= 2
        and kind in {"function", "import", "variable"}
        and not called_by
        and not decorators
        and not heuristic_refs
        and not dynamic_signals
        and not framework_signals
        and not finding.get("is_exported")
        and not collectible_test_class
        and not definition_side_effect
        and not compatibility_evidence
        and not owner_full_name
        and not parameter_contract_evidence
        and not discovered_entry_point
        and not prefilter_reason
        and not guarded_import
        and (not search_results or set(search_results).issubset(compact_search_keys))
    )

    if compact_context_ok:
        parts.append(f"## Flagged Symbol: `{full_name}`")
        parts.append(f"- Type: {kind}")
        parts.append(f"- File: `{rel_file or file_path}:{line}`")
        parts.append(f"- Direct references: {refs}")
        parts.append(f"- Static confidence: {confidence}")
        if why_unused:
            parts.append(f"- Why flagged: {', '.join(why_unused)}")
        parts.append("")

        if source:
            source_lines = source.splitlines()
            start = max(0, line - 5)
            end = min(len(source_lines), line + 12)
            parts.append("## Flagged Function Source")
            for i in range(start, end):
                marker = " >>> " if i == line - 1 else "     "
                parts.append(f"{i + 1:4d}{marker}{source_lines[i]}")
            parts.append("")

        parts.append("## Call Graph")
        parts.append("  NOBODY calls this function. Zero callers in entire project.")
        parts.append("")

        if "references_definition_only" in search_results:
            parts.append("## Search Results")
            parts.append(
                "  Only the definition itself was found. No other usages were found across the project."
            )
            parts.append("")

        parts.append(
            "Decision hint: this is a low-ambiguity dead-code candidate with no dynamic, framework, export, or caller evidence."
        )
        return "\n".join(parts)

    parts.append(f"## Flagged Symbol: `{full_name}`")
    parts.append(f"- Type: {kind}")
    parts.append(f"- File: `{rel_file or file_path}:{line}`")
    parts.append(f"- Direct references: {refs}")
    parts.append(f"- Static confidence: {confidence}")
    if decorators:
        parts.append(f"- Decorators: {', '.join(decorators)}")
    if dynamic_signals:
        parts.append(f"- Dynamic signals: {', '.join(dynamic_signals)}")
    if framework_signals:
        parts.append(f"- Framework signals: {', '.join(framework_signals)}")
    if why_unused:
        parts.append(f"- Why flagged: {', '.join(why_unused)}")
    if why_confidence_reduced:
        parts.append(
            f"- Confidence reduced because: {', '.join(why_confidence_reduced)}"
        )
    if heuristic_refs:
        parts.append(
            f"- Heuristic refs (unverified attribute matches): {heuristic_refs}"
        )
    parts.append("")

    parts.append("## Structured Evidence")
    parts.append(f"- Test context: {'yes' if _is_test_context(file_path) else 'no'}")
    if finding.get("is_exported"):
        parts.append(
            "- **Export status**: This symbol is exported as part of the package's public API"
        )
    if decorators_lower:
        parts.append(f"- Decorator aliases: {decorators_lower}")
    if framework_signals:
        parts.append(f"- Framework signals: {framework_signals}")
    if dynamic_signals:
        parts.append(f"- Dynamic signals: {dynamic_signals}")
    if heuristic_refs:
        parts.append(f"- Heuristic ref buckets: {list(heuristic_refs.keys())}")
    if module_names:
        parts.append(f"- Module candidates: {module_names}")
    if owner_full_name:
        parts.append(f"- Parameter owner: {owner_full_name}")
    if discovered_entry_point:
        parts.append(f"- Discovered entry point: yes ({discovered_entry_point})")
    else:
        parts.append("- Discovered entry point: no")
    parts.append(
        f"- MkDocs hook registration: {'yes' if rel_file and rel_file in repo_facts.mkdocs_hook_files else 'no'}"
    )
    if _is_test_context(file_path):
        parts.append(f"- Pytest class patterns: {repo_facts.pytest_class_patterns}")
        parts.append(
            f"- Pytest function patterns: {repo_facts.pytest_function_patterns}"
        )
    parts.append(
        f"- Collectible pytest test class: {'yes' if collectible_test_class else 'no'}"
    )
    parts.append(
        f"- Definition side effect: {'yes' if definition_side_effect else 'no'}"
    )
    parts.append(
        f"- Compatibility retention notes: {'yes' if compatibility_evidence else 'no'}"
    )
    if parameter_contract_evidence:
        parts.append(
            f"- Parameter contract evidence: {parameter_contract_evidence[:3]}"
        )
    if prefilter_reason:
        parts.append(
            f"- Prefilter fact: {prefilter_reason} ({prefilter_rationale or 'no rationale'})"
        )
        if prefilter_evidence:
            parts.append(f"- Prefilter evidence: {prefilter_evidence[:3]}")
    if guarded_import:
        parts.append(f"- Guarded import: yes ({guarded_import})")
    else:
        parts.append("- Guarded import: no")
    if search_results:
        summary = {
            key: len(value)
            for key, value in search_results.items()
            if isinstance(value, list) and value
        }
        parts.append(f"- Search hit counts: {summary}")
    else:
        parts.append("- Search hit counts: {}")
    parts.append("")

    if source:
        source_lines = source.splitlines()
        half_window = _TIER_HALF_WINDOWS[tier]
        start = max(0, line - half_window - 1)
        end = min(len(source_lines), line + half_window)
        parts.append("## Flagged Function Source")
        for i in range(start, end):
            if i == line - 1:
                marker = " >>> "
            else:
                marker = "     "
            parts.append(f"{i + 1:4d}{marker}{source_lines[i]}")
        parts.append("")

    # Caller truncation — limit callers with source (tier-based)
    max_callers_with_source = _TIER_MAX_CALLERS[tier]
    caller_source_window = 10
    parts.append("## Call Graph: Callers (called_by)")
    if called_by:
        for idx, caller_name in enumerate(called_by[:10]):
            parts.append(f"\n### Caller: `{caller_name}`")
            caller_def = defs_map.get(caller_name)
            if caller_def:
                if isinstance(caller_def, dict):
                    caller_info = caller_def
                else:
                    caller_info = {}
                caller_file = caller_info.get("file", "")
                caller_line = caller_info.get("line", 0)
                caller_type = caller_info.get("type", "?")
                parts.append(
                    f"- Type: {caller_type}, File: `{caller_file}:{caller_line}`"
                )

                if idx < max_callers_with_source:
                    caller_source = source_cache.get(caller_file, "")
                    if caller_source:
                        clines = caller_source.splitlines()
                        cs = max(0, caller_line - 3)
                        ce = min(len(clines), caller_line + caller_source_window)
                        for ci in range(cs, ce):
                            parts.append(f"  {ci + 1:4d} | {clines[ci]}")
            else:
                parts.append("  (not found in defs_map)")
    else:
        parts.append("  NOBODY calls this function. Zero callers in entire project.")
    parts.append("")

    if calls:
        parts.append("## Call Graph: Callees (calls)")
        for callee in calls[:10]:
            parts.append(f"  - `{callee}`")
        parts.append("")

    parent_info = _find_parent_class_info(
        finding, source_cache, project_root=project_root
    )
    if parent_info:
        parts.append("## Inheritance Context")
        parts.append(parent_info)
        parts.append(
            "NOTE: If this method overrides a parent/ABC method, it is NOT dead code."
        )
        parts.append("")

    simple_name = finding.get("simple_name", finding.get("name", ""))
    if project_root and called_by:
        for caller in called_by[:5]:
            caller_simple = caller.split(".")[-1]
            if caller_simple and len(caller_simple) > 2:
                caller_dispatch = _find_string_dispatch(
                    caller_simple, project_root, max_results=3
                )
                if caller_dispatch:
                    parts.append(
                        f"## NOTE: Caller `{caller_simple}` is ALIVE via string dispatch:"
                    )
                    for sd in caller_dispatch:
                        parts.append(f"  {sd}")
                    parts.append(
                        "Since a caller is alive via string dispatch, THIS function is also NOT dead code."
                    )
                    parts.append("")

    if project_root and simple_name and len(simple_name) > 1:
        if search_results:
            parts.append("## Search Results Across Project")
            parts.append("")

            strategy_labels = {
                "references": "References (definition filtered out)",
                "references_definition_only": "Definition only — no other references",
                "method_calls": f".{simple_name}() calls",
                "imports": "Imports",
                "conditional_import": "CONDITIONAL IMPORT (try/except guarded)",
                "string_dispatch": "Dynamic dispatch (getattr, dict lookup, etc.)",
                "exported_in_all": "__all__ exports",
                "cast_usage": "cast() type ref",
                "typevar_bound": "TypeVar bound ref",
                "cast_protocol": "Protocol cast (methods are contract)",
                "class_usage": "Parent class usage",
                "test_references": "Test refs",
                "qualified_references": "Qualified refs",
                "file_path_references": "File path refs",
                "module_references": "Module path refs",
                "config_references": "Config refs",
                "callback_registrations": "Callback registrations",
                "signature_overrides": "Override signatures",
                "compatibility_references": "Compatibility notes",
                "sphinx_directive": "Sphinx directive",
                "doc_references": "Doc mentions",
                "public_api_docs": "Public API docs",
            }

            results_per_strategy = 10
            for strategy, lines in search_results.items():
                label = strategy_labels.get(strategy, strategy)
                parts.append(f"### {label}:")
                for line in lines[:results_per_strategy]:
                    parts.append(f"  {line}")
                parts.append("")

            max_enrichment = _TIER_MAX_ENRICHMENT[tier]
            enriched = _enrich_search_results(
                search_results, max_contexts=max_enrichment
            )
            if enriched:
                parts.append("## Source Context Around Matches")
                parts.append("")
                for strategy, context_text in enriched.items():
                    label = strategy_labels.get(strategy, strategy)
                    parts.append(f"### {label}:")
                    parts.append(context_text)
                    parts.append("")

            if (
                "references_definition_only" in search_results
                and len(search_results) == 1
            ):
                parts.append(
                    "NOTE: Only the definition itself was found. No usages anywhere in the project."
                )
        else:
            parts.append("## Multi-Strategy Search Results")
            parts.append(
                f"  ZERO references to `{simple_name}` found anywhere in project."
            )
            parts.append(
                "  Searched: source code, tests, docs, configs, imports, string dispatch,"
            )
            parts.append("  __all__ exports, cast() usage, TypeVar bounds.")
            parts.append("")

    return "\n".join(parts)


def verify_with_graph_context(
    agent: DeadCodeVerifierAgent,
    finding: dict,
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
    project_root: str = "",
    repo_facts: RepoFacts | None = None,
) -> VerificationResult:
    raw_conf = _parse_confidence(finding.get("confidence", 60))
    refs = _parse_int(finding.get("references", 0))

    if refs > 0:
        return VerificationResult(
            finding=finding,
            verdict=Verdict.UNCERTAIN,
            rationale=f"Has {refs} references; skipped",
            original_confidence=raw_conf,
            adjusted_confidence=raw_conf,
        )

    context = _build_graph_context(
        finding,
        defs_map,
        source_cache,
        project_root=project_root,
        repo_facts=repo_facts,
    )
    user_prompt = f"{context}\n\nVerify: is `{finding.get('full_name', finding.get('name'))}` truly dead code?\n\nJSON response:"

    try:
        response = _call_llm_with_retry(agent, GRAPH_VERIFY_SYSTEM, user_prompt)
        if not response:
            raise ValueError("LLM call failed")
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        verdict_str = data.get("verdict", "UNCERTAIN")
        try:
            verdict = Verdict(verdict_str)
        except (ValueError, KeyError):
            verdict = Verdict.UNCERTAIN
        rationale = data.get("rationale", "")

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Graph verification failed for {finding.get('name')}: {e}")
        verdict = Verdict.UNCERTAIN
        rationale = f"LLM call failed: {e}"

    adjusted = apply_verdict(finding, verdict)

    return VerificationResult(
        finding=finding,
        verdict=verdict,
        rationale=rationale,
        original_confidence=raw_conf,
        adjusted_confidence=adjusted,
    )


def _should_audit_suppression(finding: dict) -> bool:
    if finding.get("_llm_verdict") != Verdict.FALSE_POSITIVE.value:
        return False
    if finding.get("_suppression_audited"):
        return False
    if finding.get("_suppression_hard"):
        return False
    if finding.get("_deterministically_suppressed"):
        return finding.get("_suppression_reason") in _SOFT_SUPPRESSION_CODES

    rationale = str(finding.get("_llm_rationale", "")).lower()
    if "discovered as entry point in project config" in rationale:
        return False

    return True


def _record_prefilter_fact(
    finding: dict,
    *,
    code: str,
    rationale: str,
    evidence: list[str] | None = None,
) -> None:
    finding["_judge_prefilter_reason"] = code
    finding["_judge_prefilter_rationale"] = rationale
    if evidence:
        finding["_judge_prefilter_evidence"] = list(evidence)


def audit_suppressed_finding(
    agent: DeadCodeVerifierAgent,
    finding: dict,
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
    project_root: str = "",
    repo_facts: RepoFacts | None = None,
) -> VerificationResult:
    raw_conf = _parse_confidence(finding.get("confidence", 60))
    context = _build_graph_context(
        finding,
        defs_map,
        source_cache,
        project_root=project_root,
        repo_facts=repo_facts,
    )

    if finding.get("_deterministically_suppressed"):
        origin = "deterministic suppressor"
    else:
        origin = "primary verifier"
    reason = finding.get("_suppression_reason", "")
    evidence = finding.get("_suppression_evidence", [])
    if evidence:
        evidence_lines = "\n".join(f"- {item}" for item in evidence[:5])
    else:
        evidence_lines = "- (none)"

    user_prompt = (
        f"{context}\n\n"
        "## Prior FALSE_POSITIVE Decision\n"
        f"- Origin: {origin}\n"
        f"- Prior rationale: {finding.get('_llm_rationale', '(none)')}\n"
        f"- Suppression reason code: {reason or '(none)'}\n"
        f"- Suppression evidence:\n{evidence_lines}\n\n"
        f"Audit `{finding.get('full_name', finding.get('name'))}`.\n"
        "Should this symbol actually remain reported as dead code?\n\n"
        "JSON response:"
    )

    try:
        response = _call_llm_with_retry(agent, SUPPRESSION_AUDIT_SYSTEM, user_prompt)
        if not response:
            raise ValueError("LLM call failed")
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        verdict_str = data.get("verdict", "UNCERTAIN")
        try:
            verdict = Verdict(verdict_str)
        except (ValueError, KeyError):
            verdict = Verdict.UNCERTAIN
        rationale = data.get("rationale", "")

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Suppression audit failed for {finding.get('name')}: {e}")
        verdict = Verdict.UNCERTAIN
        rationale = f"LLM call failed: {e}"

    adjusted = finding.get("_adjusted_confidence", raw_conf)
    if verdict == Verdict.TRUE_POSITIVE:
        adjusted = apply_verdict(finding, verdict)

    return VerificationResult(
        finding=finding,
        verdict=verdict,
        rationale=rationale,
        original_confidence=raw_conf,
        adjusted_confidence=adjusted,
    )


_FIXTURE_DECORATORS = {"fixture", "pytest.fixture"}
_FRAMEWORK_REGISTRATION_MARKERS = {
    "route",
    "app.route",
    "blueprint.route",
    "router.get",
    "router.post",
    "router.put",
    "router.patch",
    "router.delete",
    "router.options",
    "router.head",
    "click.command",
    "click.group",
    "typer.command",
    "typer.callback",
    "celery.task",
    "shared_task",
    "task",
}
_AMBIGUOUS_SYMBOL_NAMES = {
    "get",
    "set",
    "run",
    "main",
    "load",
    "save",
    "read",
    "write",
    "close",
    "open",
    "process",
    "handle",
    "create",
    "update",
    "delete",
    "info",
    "debug",
    "warning",
    "error",
}
_RUNTIME_DUNDER_HOOKS = {
    "__enter__",
    "__exit__",
    "__aenter__",
    "__aexit__",
    "__iter__",
    "__next__",
    "__aiter__",
    "__anext__",
    "__call__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__contains__",
    "__len__",
    "__bool__",
    "__fspath__",
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__str__",
    "__repr__",
}
_SOFT_SUPPRESSION_CODES = {
    "dynamic_dispatch",
    "test_reference",
}

_NON_PACKAGE_DIRS = {
    "tests",
    "test",
    "docs",
    "doc",
    "scripts",
    "examples",
    "benchmarks",
    "bench",
    "tools",
}


def _is_public_library_symbol(finding: dict, project_root: str) -> bool:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    if simple_name.startswith("_"):
        return False

    kind = finding.get("type", "")
    full_name = finding.get("full_name", "")

    if kind == "method":
        parts = full_name.split(".")
        if len(parts) >= 2:
            class_name = parts[-2]
            if class_name.startswith("_"):
                return False

    file_path = finding.get("file", "")
    if not file_path:
        return False

    rel = _repo_relative_path(file_path, project_root)
    rel_parts = rel.split("/")
    package_root = Path(project_root)

    if rel_parts[0] == "src" and len(rel_parts) > 1:
        package_root = package_root / "src"
        rel_parts = rel_parts[1:]

    if not rel_parts:
        return False

    if rel_parts[0] in _NON_PACKAGE_DIRS:
        return False

    pkg_dir = package_root / rel_parts[0]
    if not (pkg_dir / "__init__.py").exists():
        return False

    return True


def _normalize_names(values: list[str] | None) -> list[str]:
    return [str(v).strip().lower() for v in (values or []) if str(v).strip()]


def _is_test_context(file_path: str) -> bool:
    lower = (file_path or "").replace("\\", "/").lower()
    parts = [p for p in lower.split("/") if p]
    if parts:
        base = parts[-1]
    else:
        base = lower
    return (
        base == "conftest.py"
        or base.startswith("test_")
        or base.endswith("_test.py")
        or "tests" in parts
    )


def _conditional_import_reason(finding: dict, source: str) -> str | None:
    if finding.get("type") != "import" or not source:
        return None

    line_num = _parse_int(finding.get("line", 0))
    if line_num <= 0:
        return None

    lines = source.splitlines()
    start = max(0, line_num - 4)
    end = min(len(lines), line_num + 6)
    nearby = "\n".join(lines[start:end]).lower()

    if "if type_checking" in nearby or "if typing.type_checking" in nearby:
        return "Conditional TYPE_CHECKING import used only for typing"
    if "sys.version_info" in nearby or "platform.python_version" in nearby:
        return "Conditional version/platform import guarded by runtime check"
    if "try:" in nearby and (
        "except importerror" in nearby
        or "except modulenotfounderror" in nearby
        or "except exception" in nearby
    ):
        return (
            "Import is guarded by try/except fallback and may be loaded conditionally"
        )
    return None


def _get_cached_search_results(
    finding: dict,
    project_root: str,
    *,
    parallel: bool = False,
    max_workers: int = 4,
    cache: Any = None,
) -> dict[str, list[str]]:
    cached = finding.get("_search_results")
    if isinstance(cached, dict):
        return cached
    if not project_root:
        return {}
    simple_name = finding.get("simple_name", finding.get("name", ""))
    if not simple_name or len(simple_name) <= 1:
        return {}
    if parallel:
        results = _parallel_multi_strategy_search(
            finding,
            project_root,
            max_workers=max_workers,
            cache=cache,
        )
    else:
        results = _multi_strategy_search(finding, project_root)
    finding["_search_results"] = results
    return results


def _is_ambiguous_for_batching(finding: dict) -> bool:
    simple_name = str(finding.get("simple_name", finding.get("name", ""))).strip()
    kind = str(finding.get("type", "")).strip().lower()
    file_path = str(finding.get("file", "")).replace("\\", "/").lower()
    decorators = _normalize_names(finding.get("decorators"))
    framework_signals = _normalize_names(finding.get("framework_signals"))
    dynamic_signals = _normalize_names(finding.get("dynamic_signals"))

    if kind in {"method", "class", "import", "variable", "parameter"}:
        return True
    if (
        finding.get("heuristic_refs")
        or decorators
        or framework_signals
        or dynamic_signals
    ):
        return True
    if _is_test_context(finding.get("file", "")):
        return True
    if kind == "function" and simple_name.startswith("on_") and "hook" in file_path:
        return True
    if simple_name.startswith("__") and simple_name.endswith("__"):
        return True
    if len(simple_name) <= 4 or simple_name.lower() in _AMBIGUOUS_SYMBOL_NAMES:
        return True
    return False


def _deterministic_suppress(
    finding: dict,
    source_cache: dict[str, str],
    project_root: str = "",
    repo_facts: RepoFacts | None = None,
    defs_map: dict[str, Any] | None = None,
    *,
    grep_cache: Any = None,
) -> SuppressionDecision | None:
    import re

    kind = finding.get("type", "")
    full_name = finding.get("full_name", "")
    simple_name = finding.get("simple_name", finding.get("name", ""))
    file_path = finding.get("file", "")
    source = source_cache.get(file_path, "")
    decorators = _normalize_names(finding.get("decorators"))
    framework_signals = _normalize_names(finding.get("framework_signals"))
    repo_facts = repo_facts or RepoFacts()
    if project_root and file_path:
        rel_file = _repo_relative_path(file_path, project_root)
    else:
        rel_file = ""

    guarded_import = _conditional_import_reason(finding, source)
    if guarded_import:
        return SuppressionDecision(
            code="conditional_import",
            rationale=guarded_import,
            evidence=[f"{file_path}:{finding.get('line', 0)}"],
        )

    dynamic_family_evidence = _module_local_dynamic_dispatch_evidence(
        finding,
        source,
        defs_map=defs_map,
    )
    if dynamic_family_evidence:
        return SuppressionDecision(
            code="dynamic_dispatch",
            rationale="Module-local dynamic dispatch resolves this symbol by name family",
            evidence=dynamic_family_evidence,
            hard=True,
        )

    if kind in ("function", "method") and (
        any(d in _FIXTURE_DECORATORS for d in decorators)
        or (file_path and file_path.endswith("conftest.py"))
    ):
        return SuppressionDecision(
            code="pytest_fixture",
            rationale="Pytest fixture or conftest hook is discovered by pytest runtime",
            evidence=decorators or [file_path],
        )

    if source and _is_collectible_test_class(finding, source, repo_facts):
        return SuppressionDecision(
            code="pytest_collected_test_class",
            rationale="Pytest will collect this test class based on repo config and test_* methods",
            evidence=[rel_file or file_path, *repo_facts.pytest_class_patterns[:2]],
        )

    if source and _definition_executes_for_side_effect(finding, source):
        return SuppressionDecision(
            code="definition_side_effect",
            rationale="The class definition itself executes inside a raises/assertRaises block and is the behavior under test",
            evidence=[f"{file_path}:{finding.get('line', 0)}"],
        )

    if (
        kind in ("function", "method")
        and rel_file
        and rel_file in repo_facts.mkdocs_hook_files
        and str(simple_name).startswith("on_")
    ):
        return SuppressionDecision(
            code="mkdocs_hook",
            rationale="MkDocs hook file is registered in project config, so hook callbacks are runtime-reachable",
            evidence=[rel_file],
        )

    if (
        kind == "function"
        and str(simple_name).startswith("_")
        and not finding.get("is_exported")
        and not decorators
        and not framework_signals
        and not finding.get("heuristic_refs")
        and not finding.get("dynamic_signals")
        and not finding.get("called_by")
        and not _is_test_context(file_path)
    ):
        return None

    registration_hits = [
        name
        for name in decorators + framework_signals
        if name in _FRAMEWORK_REGISTRATION_MARKERS or name.startswith("route_on_")
    ]
    if registration_hits:
        return SuppressionDecision(
            code="framework_registered",
            rationale="Framework decorator or registration signal keeps this symbol alive",
            evidence=registration_hits,
        )

    if project_root:
        search_results = _get_cached_search_results(
            finding, project_root, cache=grep_cache
        )
    else:
        search_results = {}

    parameter_contract = _parameter_contract_evidence(finding, source, search_results)
    if parameter_contract:
        return SuppressionDecision(
            code="parameter_signature_contract",
            rationale="Parameter is required by a runtime callback or interface signature contract",
            evidence=parameter_contract[:3],
        )

    if search_results.get("cast_protocol"):
        return SuppressionDecision(
            code="protocol_required",
            rationale="Class is cast to a protocol/interface type, so protocol methods are runtime-reachable",
            evidence=search_results["cast_protocol"][:3],
        )

    if search_results.get("method_calls"):
        return SuppressionDecision(
            code="real_method_call",
            rationale="Direct method-call usage exists elsewhere in the project",
            evidence=search_results["method_calls"][:3],
        )

    if search_results.get("imports"):
        return SuppressionDecision(
            code="imported_elsewhere",
            rationale="This symbol is imported elsewhere in the project",
            evidence=search_results["imports"][:3],
        )

    if search_results.get("string_dispatch"):
        return SuppressionDecision(
            code="dynamic_dispatch",
            rationale="Dynamic dispatch evidence references this symbol by name",
            evidence=search_results["string_dispatch"][:3],
            hard=True,
        )

    if search_results.get("test_references"):
        return SuppressionDecision(
            code="test_reference",
            rationale="Project tests reference this symbol as executable API, so it is not dead code",
            evidence=search_results["test_references"][:3],
        )

    if not source:
        return None

    if kind == "variable":
        parts = full_name.split(".")
        if len(parts) >= 3:
            class_name = parts[-2]
            enum_pattern = re.compile(
                rf"class\s+{re.escape(class_name)}\s*\([^)]*\b(?:Enum|IntEnum|StrEnum|Flag|IntFlag)\b[^)]*\)"
            )
            if enum_pattern.search(source):
                return SuppressionDecision(
                    code="enum_member",
                    rationale=f"Enum member of {class_name} is accessed through the enum class at runtime",
                    evidence=[class_name],
                )

    if kind in ("method", "function"):
        line_num = finding.get("line", 0)
        if line_num > 0:
            lines = source.splitlines()
            check_start = max(0, line_num - 2)
            check_end = min(len(lines), line_num + 3)
            nearby = " ".join(lines[check_start:check_end])
            if "pragma: no cover" in nearby:
                class_parts = full_name.split(".")
                if len(class_parts) >= 2:
                    method_name = class_parts[-1]
                    if not method_name.startswith("_"):
                        return SuppressionDecision(
                            code="public_api_pragma",
                            rationale="Public API method marked with pragma for downstream/library use",
                            evidence=["pragma: no cover"],
                        )

    if kind == "method":
        io_protocol_methods = {
            "read",
            "readline",
            "readlines",
            "write",
            "writelines",
            "seek",
            "tell",
            "truncate",
            "close",
            "flush",
            "fileno",
            "isatty",
            "readable",
            "writable",
            "seekable",
            "readinto",
        }
        if simple_name in io_protocol_methods:
            parts = full_name.split(".")
            if len(parts) >= 2:
                class_name = parts[-2]
                io_bases = re.compile(
                    rf"class\s+{re.escape(class_name)}\s*\([^)]*\b(?:RawIOBase|BufferedIOBase|"
                    rf"TextIOBase|IOBase|TextIO|BinaryIO|IO)\b[^)]*\)"
                )
                if io_bases.search(source):
                    return SuppressionDecision(
                        code="protocol_required",
                        rationale=f"IO protocol method '{simple_name}' is invoked by Python IO infrastructure",
                        evidence=[class_name],
                    )
                stream_pattern = re.compile(
                    rf"{re.escape(class_name)}\s*\(.*\)|sys\.std(?:in|out|err)\s*=.*{re.escape(class_name)}"
                )
                if stream_pattern.search(source):
                    return SuppressionDecision(
                        code="protocol_required",
                        rationale=f"IO protocol method '{simple_name}' is part of a stream duck-typing contract",
                        evidence=[class_name],
                    )

    if (
        kind == "method"
        and simple_name in _RUNTIME_DUNDER_HOOKS
        and search_results.get("class_usage")
    ):
        return SuppressionDecision(
            code="dunder_runtime_hook",
            rationale=f"Runtime hook {simple_name} lives on a class that is instantiated/used elsewhere",
            evidence=search_results["class_usage"][:3],
        )

    if search_results.get("public_api_docs") and _is_public_library_symbol(
        finding, project_root
    ):
        if kind in ("function", "class", "variable", "import"):
            return SuppressionDecision(
                code="documented_public_api",
                rationale="Public symbol in importable package is documented in docs/, treat as library API",
                evidence=search_results["public_api_docs"][:3],
            )
        if kind == "method" and search_results.get("sphinx_directive"):
            return SuppressionDecision(
                code="documented_public_api",
                rationale="Public method with Sphinx/autodoc directive in docs/, treat as library API",
                evidence=search_results["sphinx_directive"][:3],
            )

    return None


def _batch_verify_findings(
    agent: DeadCodeVerifierAgent,
    findings: list[dict],
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
    project_root: str = "",
    repo_facts: RepoFacts | None = None,
) -> list[VerificationResult]:
    results = []
    batch = []
    batch_contexts = []
    batch_size = 0

    def _is_batch_failure(verdicts: list[dict]) -> bool:
        if not verdicts:
            return False
        failure_markers = (
            "LLM call failed",
            "Batch parse failed",
            "Missing from batch response",
        )
        return all(
            verdict.get("verdict", Verdict.UNCERTAIN) == Verdict.UNCERTAIN
            and any(
                marker in str(verdict.get("rationale", ""))
                for marker in failure_markers
            )
            for verdict in verdicts
        )

    def _append_batch_results(
        items: list[dict],
        contexts: list[str],
    ) -> None:
        if not items:
            return
        if len(items) == 1:
            results.append(
                verify_with_graph_context(
                    agent,
                    items[0],
                    defs_map,
                    source_cache,
                    project_root=project_root,
                    repo_facts=repo_facts,
                )
            )
            return

        combined = "\n\n---\n\n".join(
            f"### Symbol {i + 1}: `{f.get('full_name', f.get('name'))}`\n{ctx}"
            for i, (f, ctx) in enumerate(zip(items, contexts))
        )
        user_prompt = (
            f"{combined}\n\nVerify all {len(items)} symbols above. JSON array response:"
        )

        verdicts = _parse_batch_response(
            agent, BATCH_VERIFY_SYSTEM, user_prompt, len(items)
        )

        if _is_batch_failure(verdicts):
            mid = len(items) // 2
            _append_batch_results(items[:mid], contexts[:mid])
            _append_batch_results(items[mid:], contexts[mid:])
            return

        for finding, v_data in zip(items, verdicts):
            raw_conf = _parse_confidence(finding.get("confidence", 60))
            verdict = v_data.get("verdict", Verdict.UNCERTAIN)
            rationale = v_data.get("rationale", "")
            adjusted = apply_verdict(finding, verdict)
            results.append(
                VerificationResult(
                    finding=finding,
                    verdict=verdict,
                    rationale=rationale,
                    original_confidence=raw_conf,
                    adjusted_confidence=adjusted,
                )
            )

    def _flush_batch():
        nonlocal batch, batch_contexts, batch_size
        if not batch:
            return

        _append_batch_results(batch, batch_contexts)

        batch = []
        batch_contexts = []
        batch_size = 0

    for finding in findings:
        raw_conf = _parse_confidence(finding.get("confidence", 60))
        refs = _parse_int(finding.get("references", 0))

        if refs > 0:
            results.append(
                VerificationResult(
                    finding=finding,
                    verdict=Verdict.UNCERTAIN,
                    rationale=f"Has {refs} references; skipped",
                    original_confidence=raw_conf,
                    adjusted_confidence=raw_conf,
                )
            )
            continue

        if _is_ambiguous_for_batching(finding):
            _flush_batch()
            results.append(
                verify_with_graph_context(
                    agent,
                    finding,
                    defs_map,
                    source_cache,
                    project_root=project_root,
                    repo_facts=repo_facts,
                )
            )
            continue

        ctx = _build_graph_context(
            finding,
            defs_map,
            source_cache,
            project_root=project_root,
            repo_facts=repo_facts,
        )
        ctx_len = len(ctx)

        if batch and (
            batch_size + ctx_len > MAX_BATCH_CONTEXT_CHARS or len(batch) >= 5
        ):
            _flush_batch()

        batch.append(finding)
        batch_contexts.append(ctx)
        batch_size += ctx_len

    _flush_batch()
    return results


def _build_source_cache(
    findings: list[dict],
    defs_map: dict[str, Any],
    survivors: list[dict] | None = None,
) -> dict[str, str]:
    files_needed = set()

    for f in findings:
        fp = f.get("file", "")
        if fp:
            files_needed.add(fp)
        for caller in f.get("called_by", []):
            caller_def = defs_map.get(caller)
            if caller_def and isinstance(caller_def, dict):
                cf = caller_def.get("file", "")
                if cf:
                    files_needed.add(cf)

    if survivors:
        for s in survivors:
            fp = s.get("file", "")
            if fp:
                files_needed.add(fp)

    cache = {}
    for fp in files_needed:
        try:
            cache[fp] = Path(fp).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("Skipping unreadable verification source file %s: %s", fp, exc)

    return cache


def _create_haiku_agent(api_key: str) -> DeadCodeVerifierAgent:
    from skylos.llm.agents import AgentConfig

    haiku_config = AgentConfig(
        model="claude-haiku-4-5-20251001",
        api_key=api_key,
    )
    haiku_config.provider = "anthropic"
    return DeadCodeVerifierAgent(haiku_config)


def _build_haiku_context(finding: dict, source_cache: dict[str, str]) -> str:
    name = finding.get("name", "unknown")
    full_name = finding.get("full_name", name)
    file_path = finding.get("file", "")
    kind = finding.get("type", "function")
    decorators = finding.get("decorators", [])

    parts = [f"- Symbol: `{full_name}` ({kind})"]
    parts.append(f"- File: `{file_path}`")
    if decorators:
        parts.append(f"- Decorators: {', '.join(decorators)}")
    if finding.get("is_exported"):
        parts.append("- Exported: yes (in __all__ or __init__.py)")

    source = source_cache.get(file_path, "")
    if source:
        line = finding.get("line", 0)
        lines = source.splitlines()
        if 0 < line <= len(lines):
            start = max(0, line - 1)
            end = min(len(lines), line + 4)
            snippet = "\n".join(lines[start:end])
            parts.append(f"- Definition:\n```\n{snippet}\n```")

    return "\n".join(parts)


def _haiku_prefilter_exports(
    haiku_agent: DeadCodeVerifierAgent,
    findings: list[dict],
    source_cache: dict[str, str],
) -> tuple[list[dict], list[dict]]:
    if not findings:
        return [], []

    kept = []
    dismissed = []

    for batch_start in range(0, len(findings), HAIKU_PREFILTER_MAX_BATCH):
        batch = findings[batch_start : batch_start + HAIKU_PREFILTER_MAX_BATCH]

        contexts = []
        for i, f in enumerate(batch):
            ctx = _build_haiku_context(f, source_cache)
            contexts.append(
                f"### Symbol {i + 1}: `{f.get('full_name', f.get('name'))}`\n{ctx}"
            )

        combined = "\n\n---\n\n".join(contexts)
        user_prompt = f"{combined}\n\nClassify all {len(batch)} symbols above. JSON array response:"

        try:
            verdicts = _parse_batch_response(
                haiku_agent, HAIKU_PREFILTER_SYSTEM, user_prompt, len(batch)
            )
            for f, v_data in zip(batch, verdicts):
                public_api = str(v_data.get("public_api", "NO")).strip().upper()
                reason = v_data.get("reason", "")
                if public_api == "YES":
                    dismissed.append(f)
                    f["_llm_verdict"] = "FALSE_POSITIVE"
                    f["_llm_rationale"] = f"[haiku-prefilter] Public API: {reason}"
                    f["_verified_by_llm"] = True
                    f["_adjusted_confidence"] = 20
                    f["_haiku_prefiltered"] = True
                else:
                    kept.append(f)
        except Exception as e:
            logger.warning(f"Haiku pre-filter failed: {e}")
            kept.extend(batch)

    return kept, dismissed


def _apply_dead_code_defaults(
    items: list[dict[str, Any]],
    *,
    rule_id: str,
    default_source: str,
) -> None:
    for item in items:
        item.setdefault("_category", "dead_code")
        item.setdefault("rule_id", rule_id)
        item.setdefault("type", "function")
        item.setdefault("full_name", item.get("name", "unknown"))
        item.setdefault("references", 0)
        item.setdefault("_source", default_source)
        if not item.get("message"):
            item["message"] = (
                f"Unused {item.get('type', 'function')}: {item.get('name', 'unknown')}"
            )


def _build_verification_output(
    findings: list[dict[str, Any]],
    new_dead: list[dict[str, Any]],
    discovered_eps: list[EntryPoint],
    stats: VerifyStats,
    verification_mode: str,
) -> dict[str, Any]:
    _apply_dead_code_defaults(
        findings,
        rule_id="SKY-DEAD",
        default_source="static",
    )
    _apply_dead_code_defaults(
        new_dead,
        rule_id="SKY-DEAD-CHALLENGE",
        default_source="llm_survivor_challenge",
    )

    return {
        "verified_findings": findings,
        "new_dead_code": new_dead,
        "entry_points": [
            {"name": ep.name, "source": ep.source, "reason": ep.reason}
            for ep in discovered_eps
        ],
        "stats": {
            "total_findings": stats.total_findings,
            "verified_true_positive": stats.verified_true_positive,
            "verified_false_positive": stats.verified_false_positive,
            "deterministic_suppressed": stats.deterministic_suppressed,
            "uncertain": stats.uncertain,
            "suppression_challenged": stats.suppression_challenged,
            "suppression_reclassified_dead": stats.suppression_reclassified_dead,
            "survivors_challenged": stats.survivors_challenged,
            "survivors_reclassified_dead": stats.survivors_reclassified_dead,
            "entry_points_discovered": stats.entry_points_discovered,
            "haiku_prefiltered": stats.haiku_prefiltered,
            "llm_calls": stats.llm_calls,
            "prompt_tokens": stats.prompt_tokens,
            "completion_tokens": stats.completion_tokens,
            "total_tokens": stats.total_tokens,
            "elapsed_seconds": stats.elapsed_seconds,
            "verification_mode": verification_mode,
        },
    }


def _collect_feedback_adjustments(summary: dict[str, Any]) -> list[str]:
    tuned_types = []
    for htype, info in summary.get("heuristic_types", {}).items():
        if info["observations"] >= 5:
            change = info["weight_change_pct"]
            if abs(change) > 5:
                tuned_types.append(
                    f"{htype}: {info['default_weight']} → {info['tuned_weight']} ({change:+.0f}%)"
                )
    return tuned_types


def _attach_feedback_summary(output: dict[str, Any], log) -> None:
    try:
        from .feedback import record_verification_results, get_feedback_summary

        record_verification_results(output)
        summary = get_feedback_summary()

        tuned_types = _collect_feedback_adjustments(summary)
        if tuned_types:
            log("\nFeedback loop — heuristic weight adjustments:")
            for tuned in tuned_types:
                log(f"  {tuned}")

        output["feedback"] = summary
    except Exception as e:
        logger.debug(f"Feedback recording failed: {e}")


def _entry_discovery_planned_llm_calls(
    project_root: Path,
    _known_entry_points: list[str],
    repo_facts: RepoFacts,
) -> int:
    configs = repo_facts.config_files
    if not configs:
        return 0

    cache_path = _entry_point_cache_path(project_root)
    if cache_path.exists():
        try:
            from skylos.core.safe_cache_io import load_project_json_cache

            cached = load_project_json_cache(project_root, cache_path)
            if cached.get("hash") == _config_files_hash(configs):
                return 0
        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            AttributeError,
        ) as exc:
            logger.debug("Ignoring invalid entry point cache %s: %s", cache_path, exc)

    return 1



def run_verification(
    findings: list[dict],
    defs_map: dict[str, Any],
    project_root: str | Path,
    *,
    model: str = "gpt-4.1",
    api_key: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    max_verify: int = 50,
    max_challenge: int = 20,
    confidence_range: tuple[int, int] = (40, 100),
    enable_entry_discovery: bool = True,
    enable_suppression_challenge: bool = True,
    enable_survivor_challenge: bool = True,
    batch_mode: bool = True,
    max_suppression_audit: int = 20,
    quiet: bool = False,
    verification_mode: str = VERIFICATION_MODE_PRODUCTION,
    grep_workers: int = 4,
    parallel_grep: bool = False,
    harness_runner: Any | None = None,
    harness_budget: Any | None = None,
) -> dict[str, Any]:
    from skylos.llm.agents import AgentConfig

    from skylos.core.grep_cache import GrepCache

    start_time = time.time()
    project_root = Path(project_root)
    if verification_mode not in VALID_VERIFICATION_MODES:
        raise ValueError(
            f"Invalid verification_mode={verification_mode!r}. "
            f"Expected one of: {sorted(VALID_VERIFICATION_MODES)}"
        )
    judge_all_mode = verification_mode == VERIFICATION_MODE_JUDGE_ALL

    git_root = _find_git_root(project_root)
    if git_root:
        grep_root = str(git_root)
    else:
        grep_root = str(project_root)
    config_root = Path(grep_root)

    grep_cache = GrepCache()
    grep_cache.load(grep_root)

    config = AgentConfig(
        model=model,
        api_key=api_key,
        max_tokens=512,
        timeout=45,
        retry_attempts=1,
        stream=False,
    )
    if provider:
        config.provider = provider
    if base_url:
        config.base_url = base_url

    agent = DeadCodeVerifierAgent(config)
    stats = VerifyStats(total_findings=len(findings))

    log = _logger(quiet)
    log(f"Verification mode: {verification_mode}")
    source_cache = _build_source_cache(findings, defs_map)
    repo_facts = _build_repo_facts(config_root)

    def phase(name: str, input_summary: dict[str, Any] | None = None):
        return _verification_harness_phase(harness_runner, name, input_summary)

    def check_llm_budget(planned_calls: int, phase_name: str) -> None:
        _enforce_verification_llm_budget(
            current_calls=stats.llm_calls,
            planned_calls=planned_calls,
            harness_budget=harness_budget,
            phase=phase_name,
        )

    def decision_target(finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "fingerprint": finding.get("fingerprint"),
            "name": finding.get("full_name") or finding.get("name"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "type": finding.get("type"),
        }

    def record_decision(
        phase_name: str,
        code: str,
        finding: dict[str, Any],
        details: dict[str, Any] | None = None,
    ) -> None:
        if harness_runner is None:
            return
        harness_runner.record_decision(
            phase=phase_name,
            code=code,
            target=decision_target(finding),
            details=details or {},
        )

    def add_llm_calls(count: int) -> None:
        if count <= 0:
            return
        stats.llm_calls += count
        if harness_runner is not None:
            harness_runner.update_usage(llm_calls=count)

    def run_tool(
        name: str,
        fn,
        *,
        input_summary: dict[str, Any] | None = None,
        output_summary=None,
    ):
        if harness_runner is None:
            return fn()
        return harness_runner.run_tool(
            name,
            fn,
            input_summary=input_summary,
            output_summary=output_summary,
        )

    ops = VerificationOps(
        discover_entry_points=discover_entry_points,
        entry_discovery_planned_llm_calls=_entry_discovery_planned_llm_calls,
        record_prefilter_fact=_record_prefilter_fact,
        deterministic_suppress=_deterministic_suppress,
        create_haiku_agent=_create_haiku_agent,
        haiku_prefilter_exports=_haiku_prefilter_exports,
        estimate_batches=_estimate_batches,
        batch_verify_findings=_batch_verify_findings,
        build_graph_context=_build_graph_context,
        verify_with_graph_context=verify_with_graph_context,
        should_audit_suppression=_should_audit_suppression,
        audit_suppressed_finding=audit_suppressed_finding,
        find_local_on_emit_survivors=_find_local_on_emit_survivors,
        find_survivors=_find_survivors,
        build_source_cache=_build_source_cache,
        batch_challenge_survivors=_batch_challenge_survivors,
        challenge_survivor=challenge_survivor,
        build_verification_output=_build_verification_output,
        attach_feedback_summary=_attach_feedback_summary,
    )

    ctx = VerificationRuntime(
        agent=agent,
        defs_map=defs_map,
        grep_root=grep_root,
        config_root=config_root,
        grep_cache=grep_cache,
        source_cache=source_cache,
        repo_facts=repo_facts,
        stats=stats,
        log=log,
        phase=phase,
        check_llm_budget=check_llm_budget,
        record_decision=record_decision,
        add_llm_calls=add_llm_calls,
        run_tool=run_tool,
        ops=ops,
    )

    discovered_eps = run_entry_discovery_phase(
        ctx,
        enable_entry_discovery=enable_entry_discovery,
    )

    to_verify = run_candidate_selection_phase(
        ctx,
        findings,
        discovered_eps,
        max_verify=max_verify,
        confidence_range=confidence_range,
        judge_all_mode=judge_all_mode,
    )

    to_verify = run_haiku_prefilter_phase(
        ctx,
        to_verify,
        config=config,
    )

    run_verify_findings_phase(
        ctx,
        to_verify,
        batch_mode=batch_mode,
    )

    run_suppression_audit_phase(
        ctx,
        findings,
        enable_suppression_challenge=enable_suppression_challenge,
        max_suppression_audit=max_suppression_audit,
    )

    run_propagate_alive_phase(ctx, findings)

    haiku_note = (
        f", {stats.haiku_prefiltered} haiku-prefiltered"
        if stats.haiku_prefiltered
        else ""
    )
    log(
        f"  Results: {stats.verified_true_positive} confirmed dead, "
        f"{stats.verified_false_positive} LLM false positives{haiku_note}, "
        f"{stats.deterministic_suppressed} deterministically suppressed, "
        f"{stats.suppression_reclassified_dead} suppressions reopened as dead, "
        f"{stats.uncertain} uncertain"
    )

    new_dead = run_survivor_challenge_phase(
        ctx,
        findings,
        enable_survivor_challenge=enable_survivor_challenge,
        max_challenge=max_challenge,
        batch_mode=batch_mode,
    )

    return run_finalize_phase(
        ctx,
        findings,
        new_dead,
        discovered_eps,
        start_time=start_time,
        verification_mode=verification_mode,
    )


def _estimate_batches(
    findings: list[dict],
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
    repo_facts: RepoFacts | None = None,
) -> int:
    total_size = 0
    batch_count = 1
    items_in_batch = 0

    for f in findings:
        refs = _parse_int(f.get("references", 0))
        if refs > 0:
            continue
        if _is_ambiguous_for_batching(f):
            if items_in_batch > 0:
                batch_count += 1
                total_size = 0
                items_in_batch = 0
            batch_count += 1
            continue
        est_size = 500 + len(source_cache.get(f.get("file", ""), "")) // 4
        if items_in_batch > 0 and (
            total_size + est_size > MAX_BATCH_CONTEXT_CHARS or items_in_batch >= 5
        ):
            batch_count += 1
            total_size = 0
            items_in_batch = 0
        total_size += est_size
        items_in_batch += 1

    if items_in_batch == 0 and batch_count > 0:
        return batch_count - 1
    return batch_count


def _logger(quiet: bool):
    if quiet:
        return lambda msg: None

    import sys

    def _log(msg):
        print(msg, file=sys.stderr)

    return _log


class _NoopHarnessPhase:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def set_output_summary(self, **summary: Any) -> None:
        return None


def _verification_harness_phase(
    harness_runner: Any | None,
    name: str,
    input_summary: dict[str, Any] | None = None,
):
    if harness_runner is None:
        return _NoopHarnessPhase()
    return harness_runner.step(name, input_summary=input_summary)


def _enforce_verification_llm_budget(
    *,
    current_calls: int,
    planned_calls: int,
    harness_budget: Any | None,
    phase: str,
) -> None:
    if planned_calls <= 0:
        return
    max_calls = getattr(harness_budget, "max_llm_calls", None)
    if max_calls is None:
        return
    if current_calls + planned_calls <= max_calls:
        return

    from skylos.llm.harness.types import HarnessBudgetExceeded

    raise HarnessBudgetExceeded(
        "harness LLM call budget exceeded before "
        f"{phase}: {current_calls}+{planned_calls}>{max_calls}"
    )
