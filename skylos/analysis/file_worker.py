from __future__ import annotations

import ast
import logging
import os
import traceback
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.file_processing import (
    collect_python_raw_imports,
    scan_non_python_file,
    scan_python_quality,
    set_linter_node_types,
)
from skylos.analysis.finding_filter import finding_is_inline_ignored
from skylos.config import (
    get_noqa_codes_by_line,
    get_skylos_ignore_lines,
    get_skylos_ignore_rules_by_line,
    load_config,
)
from skylos.core.linter import LinterVisitor
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.quality.clones import extract_fragments
from skylos.visitors.base import Visitor
from skylos.visitors.framework_aware import FrameworkAwareVisitor
from skylos.visitors.test_aware import TestAwareVisitor


logger = logging.getLogger("Skylos")
MAX_PYTHON_SOURCE_BYTES = 2_000_000


@dataclass(frozen=True, slots=True)
class _WorkerOptions:
    extra_visitors: Iterable[type] | None
    full_scan: bool
    collect_clone_fragments: bool
    clone_cfg: object | None
    collect_architecture_metrics: bool
    enable_quality_rules: bool
    enable_danger_rules: bool
    project_root: str | Path | None
    visitor_class: type
    test_aware_visitor_class: type
    framework_aware_visitor_class: type


@dataclass(frozen=True, slots=True)
class _PreparedPython:
    source: str
    tree: ast.AST
    masked: int
    raw_imports: list
    empty_file_finding: dict | None
    ignore_lines: set
    ignore_rules_by_line: dict
    noqa_codes_by_line: dict
    framework_imports: tuple[ast.AST, ...]


@dataclass(frozen=True, slots=True)
class _FindingResults:
    quality: list
    danger: list
    custom: list
    suppressed: list


@dataclass(frozen=True, slots=True)
class _VisitorResults:
    visitor: object
    test_visitor: object
    framework_visitor: object


@dataclass(frozen=True, slots=True)
class _Artifacts:
    clone_fragments: list
    architecture_metrics: dict | None


def _is_truly_empty_or_docstring_only(tree: ast.AST) -> bool:
    if not isinstance(tree, ast.Module):
        return False
    if not tree.body:
        return True
    if len(tree.body) != 1:
        return False

    only = tree.body[0]
    return (
        isinstance(only, ast.Expr)
        and isinstance(only.value, ast.Constant)
        and isinstance(only.value.value, str)
    )


def _file_and_module(file_or_args, mod):
    if mod is None and isinstance(file_or_args, tuple):
        return file_or_args
    return file_or_args, mod


def _read_python_source(file, project_root=None) -> str:
    read_kwargs = {
        "max_bytes": MAX_PYTHON_SOURCE_BYTES,
        "encoding": "utf-8",
    }
    if project_root is None:
        source = read_text_no_symlink(file, **read_kwargs)
    else:
        source = read_project_text_no_symlink(project_root, file, **read_kwargs)
    if source is None:
        raise SourceReadError(
            "source must be a regular, non-symlink UTF-8 file no larger than "
            f"{MAX_PYTHON_SOURCE_BYTES} bytes"
        )
    return source


class SourceReadError(OSError):
    """Raised when an analyzer worker cannot safely read a source file."""


def _parse_python_source(source: str, file) -> ast.AST:
    tree = ast.parse(source, filename=str(file))
    # ast.parse() can accept ASTs that Python later rejects, such as functions
    # with duplicate argument names. Compile without executing so those errors
    # follow the incomplete-analysis path.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        compile(tree, str(file), "exec", dont_inherit=True)
    return tree


def _empty_file_finding(tree: ast.AST, file, cfg) -> dict | None:
    skip_names = {"__init__.py", "__main__.py", "main.py"}
    if (
        Path(file).name in skip_names
        or "SKY-E002" in cfg["ignore"]
        or not _is_truly_empty_or_docstring_only(tree)
    ):
        return None
    return {
        "rule_id": "SKY-E002",
        "message": "Empty Python file (no code, or docstring-only)",
        "file": str(file),
        "line": 1,
        "severity": "LOW",
        "category": "DEAD_CODE",
    }


def _masked_tree(tree: ast.AST, file, cfg) -> tuple[ast.AST, int]:
    from skylos.analysis.ast_mask import (
        apply_body_mask,
        default_mask_spec_from_config,
    )

    tree, masked = apply_body_mask(tree, default_mask_spec_from_config(cfg))
    if masked and os.getenv("SKYLOS_DEBUG"):
        logger.info(f"{file}: masked {masked} bodies (skipped inner analysis)")
    return tree, masked


def _quality_findings(
    file, prepared: _PreparedPython, cfg, options: _WorkerOptions
) -> list:
    if not options.full_scan or not options.enable_quality_rules:
        return []
    findings = scan_python_quality(prepared.tree, prepared.source, file, cfg)
    if Path(file).suffix == ".pyi":
        findings = [
            finding
            for finding in findings
            if finding.get("rule_id") not in {"SKY-L026", "SKY-L033"}
        ]
    return findings


def _danger_findings(
    file,
    prepared: _PreparedPython,
    options: _WorkerOptions,
) -> tuple[list, dict | None]:
    if not options.full_scan or not options.enable_danger_rules:
        return [], None

    danger_rules = [DangerousCallsRule()]
    set_linter_node_types(danger_rules)
    danger_linter = LinterVisitor(danger_rules, str(file))
    danger_linter.visit(prepared.tree)
    findings = danger_linter.findings

    from skylos.rules.danger.danger import scan_file_with_tree

    taint_findings = []
    analysis_error = None
    try:
        scan_file_with_tree(
            prepared.tree,
            Path(file),
            taint_findings,
            source=prepared.source,
        )
    except Exception as error:
        logger.debug("Taint analysis failed for %s", file, exc_info=True)
        analysis_error = analysis_error_payload(
            file,
            error,
            kind="security_scan_error",
        )
    findings.extend(taint_findings)
    return findings, analysis_error


def _custom_findings(tree, file, extra_visitors: Iterable[type] | None) -> list:
    findings = []
    for visitor_class in extra_visitors or ():
        checker = visitor_class(file, findings)
        checker.visit(tree)
    return findings


def _filter_inline_ignored(
    findings,
    category,
    ignore_lines,
    ignore_rules_by_line,
) -> tuple[list, list]:
    active = []
    suppressed = []
    for finding in findings:
        if not finding_is_inline_ignored(
            finding,
            ignore_lines,
            ignore_rules_by_line,
        ):
            active.append(finding)
            continue
        suppressed.append(
            {
                **finding,
                "category": category,
                "reason": "inline ignore comment",
            }
        )
    return active, suppressed


def _apply_inline_ignores(
    quality_findings,
    danger_findings,
    ignore_lines,
    ignore_rules_by_line,
) -> tuple[list, list, list]:
    quality_findings, suppressed_quality = _filter_inline_ignored(
        quality_findings,
        "quality",
        ignore_lines,
        ignore_rules_by_line,
    )
    danger_findings, suppressed_danger = _filter_inline_ignored(
        danger_findings,
        "security",
        ignore_lines,
        ignore_rules_by_line,
    )
    return (
        quality_findings,
        danger_findings,
        suppressed_quality + suppressed_danger,
    )


def _copy_framework_metadata(framework_visitor, visitor) -> None:
    attributes = (
        ("dataclass_fields", set()),
        ("first_read_lineno", {}),
        ("protocol_classes", set()),
        ("namedtuple_classes", set()),
        ("enum_classes", set()),
        ("attrs_classes", set()),
        ("orm_model_classes", set()),
        ("type_alias_names", set()),
        ("abc_classes", set()),
        ("abstract_methods", {}),
        ("abc_implementers", {}),
        ("protocol_implementers", {}),
        ("protocol_method_names", {}),
        ("version_conditional_lines", set()),
    )
    for attribute, default in attributes:
        setattr(framework_visitor, attribute, getattr(visitor, attribute, default))


def _run_visitors(
    file,
    mod,
    prepared: _PreparedPython,
    options: _WorkerOptions,
) -> _VisitorResults:
    test_visitor = options.test_aware_visitor_class(filename=file)
    test_visitor.visit(prepared.tree)
    test_visitor.ignore_lines = prepared.ignore_lines
    test_visitor.noqa_codes_by_line = prepared.noqa_codes_by_line

    # The already parsed tree supplies all framework import evidence. Avoid a
    # second path-based read after the worker's bounded no-follow read.
    framework_visitor = options.framework_aware_visitor_class()
    for import_node in prepared.framework_imports:
        framework_visitor.visit(import_node)
    framework_visitor.visit(prepared.tree)
    framework_visitor.finalize()
    visitor = options.visitor_class(mod, file)
    visitor.visit(prepared.tree)
    visitor.finalize()
    _copy_framework_metadata(framework_visitor, visitor)
    return _VisitorResults(visitor, test_visitor, framework_visitor)


def _architecture_metrics(
    file,
    prepared: _PreparedPython,
    enabled,
) -> dict | None:
    if not enabled:
        return None
    try:
        from skylos.analysis.architecture import (
            _compute_abstractness,
            _has_main_guard,
        )

        architecture_tree = (
            ast.parse(prepared.source) if prepared.masked else prepared.tree
        )
        return {
            "abstractness": _compute_abstractness(architecture_tree),
            "has_main_guard": _has_main_guard(architecture_tree),
            "loc": sum(
                1
                for line in prepared.source.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ),
        }
    except Exception:
        logger.debug(
            "Architecture metric extraction failed for %s",
            file,
            exc_info=True,
        )
        return None


def _clone_fragments(
    file, prepared: _PreparedPython, cfg, options: _WorkerOptions
) -> list:
    if (
        not options.collect_clone_fragments
        or options.clone_cfg is None
        or "SKY-C401" in cfg.get("ignore", [])
    ):
        return []
    try:
        clone_tree = None if prepared.masked else prepared.tree
        return extract_fragments(
            Path(file),
            prepared.source,
            options.clone_cfg,
            tree=clone_tree,
        )
    except Exception:
        logger.debug("Clone fragment extraction failed for %s", file, exc_info=True)
        return []


def _success_result(
    cfg,
    prepared: _PreparedPython,
    findings: _FindingResults,
    visitors: _VisitorResults,
    artifacts: _Artifacts,
    *,
    analysis_error: dict | None = None,
) -> tuple:
    visitor = visitors.visitor
    return (
        visitor.defs,
        visitor.refs,
        visitor.dyn,
        visitor.exports,
        visitors.test_visitor,
        visitors.framework_visitor,
        findings.quality,
        findings.danger,
        findings.custom,
        visitor.pattern_tracker,
        prepared.empty_file_finding,
        cfg,
        prepared.raw_imports,
        prepared.ignore_lines,
        findings.suppressed,
        visitor.inferred_types,
        visitor.instance_attr_types,
        getattr(visitor, "_used_attr_names", set()),
        getattr(visitor, "_used_attr_names_with_context", set()),
        prepared.source.splitlines(True),
        getattr(visitor, "param_method_refs", {}),
        getattr(visitor, "call_arg_types", {}),
        artifacts.clone_fragments,
        artifacts.architecture_metrics,
        getattr(visitor, "top_level_refs", set()),
        analysis_error,
        prepared.ignore_rules_by_line,
        bool(getattr(visitor, "has_explicit_all", False)),
    )


def _error_result(file, cfg, error, options: _WorkerOptions) -> tuple:
    logger.error(f"{file}: {error}")
    if os.getenv("SKYLOS_DEBUG"):
        logger.error(traceback.format_exc())
    test_visitor = options.test_aware_visitor_class(filename=file)
    test_visitor.ignore_lines = set()
    framework_visitor = options.framework_aware_visitor_class()
    return (
        [],
        [],
        set(),
        set(),
        test_visitor,
        framework_visitor,
        [],
        [],
        [],
        None,
        None,
        cfg,
        [],
        set(),
        [],
        {},
        {},
        set(),
        set(),
        [],
        {},
        {},
        [],
        None,
        set(),
        analysis_error_payload(
            file,
            error,
            kind="source_read_error" if isinstance(error, SourceReadError) else None,
        ),
        {},
        False,
    )


def _prepare_python(file, mod, cfg, source: str) -> _PreparedPython:
    ignore_lines = get_skylos_ignore_lines(source)
    ignore_rules_by_line = get_skylos_ignore_rules_by_line(source)
    noqa_codes_by_line = get_noqa_codes_by_line(source)
    tree = _parse_python_source(source, file)
    raw_imports = collect_python_raw_imports(tree, file, mod)
    empty_file_finding = _empty_file_finding(tree, file, cfg)
    framework_imports = tuple(
        node
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    )
    tree, masked = _masked_tree(tree, file, cfg)
    return _PreparedPython(
        source,
        tree,
        masked,
        raw_imports,
        empty_file_finding,
        ignore_lines,
        ignore_rules_by_line,
        noqa_codes_by_line,
        framework_imports if masked else (),
    )


def _process_python_file(file, mod, cfg, source, options: _WorkerOptions) -> tuple:
    prepared = _prepare_python(file, mod, cfg, source)
    quality = _quality_findings(file, prepared, cfg, options)
    danger, analysis_error = _danger_findings(file, prepared, options)
    custom = _custom_findings(prepared.tree, file, options.extra_visitors)
    quality, danger, suppressed = _apply_inline_ignores(
        quality,
        danger,
        prepared.ignore_lines,
        prepared.ignore_rules_by_line,
    )
    findings = _FindingResults(quality, danger, custom, suppressed)
    visitors = _run_visitors(file, mod, prepared, options)
    artifacts = _Artifacts(
        _clone_fragments(file, prepared, cfg, options),
        _architecture_metrics(
            file,
            prepared,
            options.collect_architecture_metrics,
        ),
    )
    return _success_result(
        cfg,
        prepared,
        findings,
        visitors,
        artifacts,
        analysis_error=analysis_error,
    )


def _process_python_entry(file, mod, config_file, options: _WorkerOptions) -> tuple:
    try:
        source = _read_python_source(file, options.project_root)
    except Exception as error:
        config_start = options.project_root or Path(file).parent
        cfg = load_config(config_start, config_file=config_file)
        return _error_result(file, cfg, error, options)

    cfg = load_config(file, config_file=config_file)
    try:
        return _process_python_file(file, mod, cfg, source, options)
    except Exception as error:
        return _error_result(file, cfg, error, options)


def process_file(
    file_or_args: Any,
    mod: Any = None,
    extra_visitors: Iterable[type] | None = None,
    full_scan: bool = True,
    collect_clone_fragments: bool = False,
    clone_cfg: object | None = None,
    collect_architecture_metrics: bool = False,
    enable_quality_rules: bool = True,
    enable_danger_rules: bool = True,
    config_file: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    visitor_class: type = Visitor,
    test_aware_visitor_class: type = TestAwareVisitor,
    framework_aware_visitor_class: type = FrameworkAwareVisitor,
) -> tuple | None:
    """Process one source file and return the analyzer worker result tuple."""
    file, mod = _file_and_module(file_or_args, mod)
    options = _WorkerOptions(
        extra_visitors=extra_visitors,
        full_scan=full_scan,
        collect_clone_fragments=collect_clone_fragments,
        clone_cfg=clone_cfg,
        collect_architecture_metrics=collect_architecture_metrics,
        enable_quality_rules=enable_quality_rules,
        enable_danger_rules=enable_danger_rules,
        project_root=project_root,
        visitor_class=visitor_class,
        test_aware_visitor_class=test_aware_visitor_class,
        framework_aware_visitor_class=framework_aware_visitor_class,
    )
    if str(file).endswith((".py", ".pyi", ".pyw")):
        return _process_python_entry(file, mod, config_file, options)

    cfg = load_config(file, config_file=config_file)
    return scan_non_python_file(
        file,
        cfg,
        enable_quality_rules=enable_quality_rules,
        enable_danger_rules=enable_danger_rules,
    )
