from __future__ import annotations

import ast
import json
import logging
import os
import traceback
from pathlib import Path

from skylos.core.linter import LinterVisitor
from skylos.rules.custom import load_community_rules, load_custom_rules
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.quality._readability import OpaqueIdentifierRule
from skylos.rules.quality.async_blocking import AsyncBlockingRule
from skylos.rules.quality.class_size import GodClassRule, GodFileRule
from skylos.rules.quality.cohesion import LCOMRule
from skylos.rules.quality.concurrency import LockOrderRule, ThreadSharedStateRule
from skylos.rules.quality.complexity import ComplexityRule, CognitiveComplexityRule
from skylos.rules.quality.coupling import CBORule
from skylos.rules.quality.logic import (
    BareExceptRule,
    BooleanTrapRule,
    BroadExceptionRule,
    BroadFilePermissionsRule,
    DangerousComparisonRule,
    DebugLeftoverRule,
    DisabledSecurityRule,
    DuplicateBranchRule,
    DuplicateStringLiteralRule,
    EmptyErrorHandlerRule,
    ErrorDisclosureRule,
    HardcodedCredentialRule,
    InsecureRandomRule,
    MissingNetworkTimeoutRule,
    MissingResourceCleanupRule,
    MockPlaceholderDataRule,
    MutableDefaultRule,
    NoEffectStatementRule,
    ReturnConsistencyRule,
    SecurityTodoRule,
    StaleMockRule,
    TooManyReturnsRule,
    TryBlockPatternsRule,
    UndefinedConfigRule,
    UnfinishedGenerationRule,
    UnusedExceptVarRule,
)
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.quality.performance import PerformanceRule
from skylos.rules.quality.practices import (
    FrameworkPracticeRule,
    TypeAnnotationPracticeRule,
)
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule
from skylos.rules.quality.unreachable import UnreachableCodeRule
from skylos.rules.vibe_dictionary import build_vibe_dictionary
from skylos.visitors.languages.csharp import scan_csharp_file
from skylos.visitors.languages.dart import scan_dart_file
from skylos.visitors.languages.go import scan_go_file
from skylos.visitors.languages.java import scan_java_file
from skylos.visitors.languages.kotlin import scan_kotlin_file
from skylos.visitors.languages.php import scan_php_file
from skylos.visitors.languages.rust import scan_rust_file
from skylos.visitors.languages.shell import SHELL_SOURCE_EXTS, scan_shell_file
from skylos.visitors.languages.typescript import scan_typescript_file


logger = logging.getLogger("Skylos")

TS_JS_SOURCE_EXTS = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
)
KOTLIN_SOURCE_EXTS = (".kt", ".kts")
TRY_NODE_TYPES = (ast.Try, getattr(ast, "TryStar", ast.Try))

LINTER_RULE_NODE_TYPES = {
    ComplexityRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    CognitiveComplexityRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    NestingRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    AsyncBlockingRule: (
        ast.Import,
        ast.ImportFrom,
        ast.AsyncFunctionDef,
        ast.FunctionDef,
        ast.Lambda,
        ast.Call,
    ),
    LockOrderRule: (ast.Module,),
    ThreadSharedStateRule: (ast.Module,),
    ArgCountRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    FunctionLengthRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    MutableDefaultRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BareExceptRule: (ast.ExceptHandler,),
    DangerousComparisonRule: (ast.Compare,),
    DuplicateBranchRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    TryBlockPatternsRule: (ast.Try,),
    UnusedExceptVarRule: (ast.ExceptHandler,),
    ReturnConsistencyRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    EmptyErrorHandlerRule: (ast.ExceptHandler, ast.With),
    MissingResourceCleanupRule: (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef),
    DebugLeftoverRule: (ast.Call,),
    SecurityTodoRule: (ast.Module,),
    DisabledSecurityRule: (ast.Call, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign),
    InsecureRandomRule: (ast.Assign,),
    HardcodedCredentialRule: (ast.Assign, ast.FunctionDef, ast.AsyncFunctionDef),
    ErrorDisclosureRule: (ast.ExceptHandler,),
    BroadFilePermissionsRule: (ast.Call,),
    UndefinedConfigRule: (ast.Module, ast.Call),
    StaleMockRule: (ast.Module, ast.Call),
    UnfinishedGenerationRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    DuplicateStringLiteralRule: (ast.Module,),
    TooManyReturnsRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BooleanTrapRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BroadExceptionRule: (ast.ExceptHandler,),
    MissingNetworkTimeoutRule: (ast.Call,),
    NoEffectStatementRule: (ast.Expr,),
    GodFileRule: (ast.Module,),
    GodClassRule: (ast.ClassDef,),
    CBORule: (ast.ClassDef,),
    LCOMRule: (ast.ClassDef,),
    UnreachableCodeRule: (
        ast.Module,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        *TRY_NODE_TYPES,
    ),
    PerformanceRule: (ast.Call, ast.For),
    TypeAnnotationPracticeRule: (ast.Module,),
    FrameworkPracticeRule: (ast.Module,),
    OpaqueIdentifierRule: (ast.Module,),
    DangerousCallsRule: (ast.Module, ast.Import, ast.ImportFrom, ast.Assign, ast.Call),
}


def set_linter_node_types(rules):
    for rule in rules:
        node_types = LINTER_RULE_NODE_TYPES.get(type(rule))
        if node_types:
            rule.node_types = node_types


def _enabled(cfg: dict, rule_id: str) -> bool:
    return rule_id not in cfg["ignore"]


def _build_builtin_quality_rules(cfg: dict) -> list:
    vibe_dictionary = build_vibe_dictionary(cfg.get("vibe"))

    specs = [
        ("SKY-Q301", lambda: ComplexityRule(threshold=cfg["complexity"])),
        ("SKY-Q306", CognitiveComplexityRule),
        ("SKY-Q302", lambda: NestingRule(threshold=cfg["nesting"])),
        ("SKY-Q401", AsyncBlockingRule),
        ("SKY-Q403", LockOrderRule),
        ("SKY-Q404", ThreadSharedStateRule),
        ("SKY-C303", lambda: ArgCountRule(max_args=cfg["max_args"])),
        ("SKY-C304", lambda: FunctionLengthRule(max_lines=cfg["max_lines"])),
        ("SKY-L001", MutableDefaultRule),
        ("SKY-L002", BareExceptRule),
        ("SKY-L003", DangerousComparisonRule),
        ("SKY-Q305", DuplicateBranchRule),
        ("SKY-L004", lambda: TryBlockPatternsRule(max_lines=15)),
        ("SKY-L005", UnusedExceptVarRule),
        ("SKY-L006", ReturnConsistencyRule),
        ("SKY-L007", EmptyErrorHandlerRule),
        ("SKY-L008", MissingResourceCleanupRule),
        ("SKY-L009", DebugLeftoverRule),
        ("SKY-L010", SecurityTodoRule),
        (
            "SKY-L011",
            lambda: DisabledSecurityRule(vibe_dictionary=vibe_dictionary),
        ),
        ("SKY-L013", lambda: InsecureRandomRule(vibe_dictionary=vibe_dictionary)),
        (
            "SKY-L014",
            lambda: HardcodedCredentialRule(vibe_dictionary=vibe_dictionary),
        ),
        (
            "SKY-L032",
            lambda: MockPlaceholderDataRule(vibe_dictionary=vibe_dictionary),
        ),
        ("SKY-L017", ErrorDisclosureRule),
        (
            "SKY-L020",
            lambda: BroadFilePermissionsRule(vibe_dictionary=vibe_dictionary),
        ),
        (
            "SKY-L016",
            lambda: UndefinedConfigRule(vibe_dictionary=vibe_dictionary),
        ),
        ("SKY-L024", StaleMockRule),
        ("SKY-L026", UnfinishedGenerationRule),
        (
            "SKY-L027",
            lambda: DuplicateStringLiteralRule(
                threshold=cfg.get("duplicate_strings", 3)
            ),
        ),
        ("SKY-L028", TooManyReturnsRule),
        ("SKY-L029", BooleanTrapRule),
        ("SKY-L030", BroadExceptionRule),
        (
            "SKY-L031",
            lambda: MissingNetworkTimeoutRule(vibe_dictionary=vibe_dictionary),
        ),
        ("SKY-L033", NoEffectStatementRule),
    ]

    q_rules = [factory() for rule_id, factory in specs if _enabled(cfg, rule_id)]

    # SKY-D260 (prompt injection) is handled by injection_scanner.
    if _enabled(cfg, "SKY-Q502"):
        q_rules.append(
            GodFileRule(
                max_lines=cfg.get("god_file_max_lines", 500),
                max_definitions=cfg.get("god_file_max_definitions", 40),
                max_top_level_definitions=cfg.get(
                    "god_file_max_top_level_definitions",
                    25,
                ),
            )
        )

    q_rules.extend(_build_structural_quality_rules(cfg))

    q_rules.append(PerformanceRule(ignore_list=cfg["ignore"]))
    return q_rules


def _build_structural_quality_rules(cfg: dict) -> list:
    q_rules = []
    specs = [
        ("SKY-Q501", GodClassRule),
        ("SKY-Q701", CBORule),
        ("SKY-Q702", LCOMRule),
        ("SKY-Q806", OpaqueIdentifierRule),
        ("SKY-U001", UnreachableCodeRule),
    ]
    q_rules.extend(factory() for rule_id, factory in specs if _enabled(cfg, rule_id))
    if _enabled(cfg, "SKY-T101") or _enabled(cfg, "SKY-T102"):
        q_rules.append(TypeAnnotationPracticeRule())
    if _enabled(cfg, "SKY-F101") or _enabled(cfg, "SKY-F102"):
        q_rules.append(FrameworkPracticeRule())
    return q_rules


def _extend_env_custom_quality_rules(q_rules: list, file) -> None:
    custom_rules_json = os.getenv("SKYLOS_CUSTOM_RULES")
    if os.getenv("SKYLOS_DEBUG"):
        logger.info(
            f"[DBG] {file}: SKYLOS_CUSTOM_RULES present={bool(custom_rules_json)} "
            f"size={len(custom_rules_json) if custom_rules_json else 0}"
        )

    if custom_rules_json:
        try:
            custom_rules_data = json.loads(custom_rules_json)
            custom_rules = load_custom_rules(custom_rules_data)
            if os.getenv("SKYLOS_DEBUG"):
                logger.info(
                    f"[DBG] {file}: load_custom_rules -> {len(custom_rules)} rules"
                )
                if custom_rules:
                    logger.info(
                        f"[DBG] {file}: custom rule ids = {[r.rule_id for r in custom_rules]}"
                    )
            q_rules.extend(custom_rules)
        except Exception as e:
            logger.error(f"[DBG] {file}: FAILED to load custom rules: {e}")
            if os.getenv("SKYLOS_DEBUG"):
                logger.error(traceback.format_exc())


def _extend_community_quality_rules(q_rules: list, file) -> None:
    try:
        community_rules_data = load_community_rules()
        if community_rules_data:
            community_rules = load_custom_rules(community_rules_data)
            if os.getenv("SKYLOS_DEBUG"):
                logger.info(
                    f"[DBG] {file}: community rules -> {len(community_rules)} rules"
                )
            q_rules.extend(community_rules)
    except Exception:
        pass


def scan_python_quality(tree: ast.AST, source: str, file, cfg: dict) -> list[dict]:
    q_rules = _build_builtin_quality_rules(cfg)
    _extend_env_custom_quality_rules(q_rules, file)
    _extend_community_quality_rules(q_rules, file)
    set_linter_node_types(q_rules)
    linter_q = LinterVisitor(q_rules, str(file))
    linter_q.context["source"] = source
    linter_q.visit(tree)
    quality_findings = [
        f for f in linter_q.findings if f.get("rule_id") not in cfg["ignore"]
    ]

    if os.getenv("SKYLOS_DEBUG"):
        custom_hits = [
            f
            for f in quality_findings
            if str(f.get("rule_id", "")).startswith("CUSTOM-")
        ]
        logger.info(
            f"[DBG] {file}: quality_findings={len(quality_findings)} "
            f"custom_hits={len(custom_hits)}"
        )
        if custom_hits:
            logger.info(f"[DBG] {file}: first_custom_hit={custom_hits[0]}")

    return quality_findings


def _normalize_language_scan_output(out):
    if isinstance(out, tuple) and len(out) < 13:
        return (*out, *([None] * (13 - len(out))))
    return out[:13]


def _scan_typescript_like_file(
    file,
    cfg,
    *,
    enable_quality_rules: bool,
    enable_danger_rules: bool,
):
    return scan_typescript_file(
        file,
        cfg,
        enable_quality_rules=enable_quality_rules,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_go_file(file, cfg, **_options):
    return scan_go_file(file, cfg)


def _scan_java_like_file(
    file,
    cfg,
    *,
    enable_quality_rules: bool,
    enable_danger_rules: bool,
):
    return scan_java_file(
        file,
        cfg,
        enable_quality_rules=enable_quality_rules,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_php_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_php_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_rust_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_rust_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_dart_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_dart_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_csharp_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_csharp_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_kotlin_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_kotlin_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


def _scan_shell_file(file, cfg, *, enable_danger_rules: bool, **_options):
    return scan_shell_file(
        file,
        cfg,
        enable_danger_rules=enable_danger_rules,
    )


NON_PYTHON_SCANNERS = (
    (TS_JS_SOURCE_EXTS, _scan_typescript_like_file),
    ((".go",), _scan_go_file),
    ((".java",), _scan_java_like_file),
    ((".php",), _scan_php_file),
    ((".rs",), _scan_rust_file),
    ((".dart",), _scan_dart_file),
    ((".cs",), _scan_csharp_file),
    (KOTLIN_SOURCE_EXTS, _scan_kotlin_file),
    (SHELL_SOURCE_EXTS, _scan_shell_file),
)


def scan_non_python_file(
    file,
    cfg,
    *,
    enable_quality_rules: bool = True,
    enable_danger_rules: bool = True,
):
    file_name = str(file)
    for suffixes, scanner in NON_PYTHON_SCANNERS:
        if file_name.endswith(suffixes):
            out = scanner(
                file,
                cfg,
                enable_quality_rules=enable_quality_rules,
                enable_danger_rules=enable_danger_rules,
            )
            return _normalize_language_scan_output(out)
    return None


def _current_package(file, mod: str | None) -> str:
    if Path(file).name == "__init__.py":
        return mod or ""
    return mod.rsplit(".", 1)[0] if mod and "." in mod else (mod or "")


def _absolute_imports(node: ast.Import):
    return [
        (
            alias.name,
            node.lineno,
            "import",
            [alias.asname or alias.name],
        )
        for alias in node.names
    ]


def _absolute_from_import(node: ast.ImportFrom):
    names = [a.name for a in node.names if a.name != "*"]
    return [(node.module, node.lineno, "from_import", names)]


def _relative_from_import(node: ast.ImportFrom, cur_pkg: str):
    parts = cur_pkg.split(".") if cur_pkg else []
    up = node.level - 1
    if up > len(parts):
        return []

    base = ".".join(parts[: len(parts) - up])
    resolved = f"{base}.{node.module}" if node.module and base else node.module or base
    if not resolved:
        return []

    names = [a.name for a in node.names if a.name != "*"]
    return [(resolved, node.lineno, "from_import", names)]


def _raw_imports_for_node(node: ast.AST, cur_pkg: str):
    if isinstance(node, ast.Import):
        return _absolute_imports(node)
    if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        return _absolute_from_import(node)
    if isinstance(node, ast.ImportFrom) and node.level and node.level > 0:
        return _relative_from_import(node, cur_pkg)
    return []


def collect_python_raw_imports(tree: ast.AST, file, mod: str | None):
    raw_imports = []
    cur_pkg = _current_package(file, mod)

    for node in ast.iter_child_nodes(tree):
        raw_imports.extend(_raw_imports_for_node(node, cur_pkg))

    return raw_imports
