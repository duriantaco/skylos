#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import importlib.util
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_renderer():
    """
    Load the repo-map HTML renderer from the local scripts directory.

    Args:
        None.

    Returns:
        The renderer module's `render_html` callable.

    Trust boundary:
        The renderer path is fixed relative to this repository, not supplied by
        a scanned project. Loading by file path avoids treating
        `repo_map_renderer` as an external package dependency.

    Failure mode:
        Raises RuntimeError if the renderer module cannot be loaded.

    Calls: importlib.util.spec_from_file_location;
        importlib.util.module_from_spec.

    Called from: scripts/build_repo_map.py module import.
    """
    renderer_path = REPO_ROOT / "scripts" / "repo_map_renderer.py"
    spec = importlib.util.spec_from_file_location("skylos_repo_map_renderer", renderer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load repo map renderer: {renderer_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.render_html


render_html = _load_renderer()


SOURCE_ROOTS = ("skylos", "test", "scripts", "benchmarks")
GENERATED_PATHS = {"docs/repo-map/index.html"}
MAX_SOURCE_BYTES = 1_000_000
SHARED_ENTRYPOINTS = {"skylos/cli.py", "skylos/analyzer.py", "skylos/pipeline.py", "skylos/config.py"}
PRIVATE_SYMBOL_ENTRYPOINTS = {"skylos/cli.py", "skylos/analyzer.py", "skylos/pipeline.py"}
EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".skylos",
    ".venv",
    "__pycache__",
    "dist",
    "skylos.egg-info",
    "venv",
}

FOLDER_META: dict[str, dict[str, Any]] = {
    "skylos": {
        "purpose": "Root entrypoints and shared scan orchestration.",
        "touch": "Start here when CLI behavior, scan flow, or global configuration changes.",
        "entrypoints": ["skylos/cli.py", "skylos/analyzer.py", "skylos/pipeline.py", "skylos/config.py"],
    },
    "skylos/adapters": {
        "purpose": "Provider adapters that let Skylos talk to model runtimes without coupling core logic to one vendor.",
        "touch": "Change this when adding or hardening an LLM provider boundary.",
        "entrypoints": ["skylos/adapters/base.py", "skylos/adapters/litellm_adapter.py"],
    },
    "skylos/agents": {
        "purpose": "Agent-facing payloads, service helpers, and review triage learning.",
        "touch": "Use this area for agent review workflows and normalized agent result handling.",
        "entrypoints": ["skylos/agents/service.py", "skylos/agents/payload.py"],
    },
    "skylos/analysis": {
        "purpose": "Reusable static-analysis primitives: architecture, reachability, control-flow, penalties, and implicit references.",
        "touch": "Change this when multiple scanners need the same code-understanding primitive.",
        "entrypoints": ["skylos/analysis/module_reachability.py", "skylos/analysis/control_flow.py"],
    },
    "skylos/api": {
        "purpose": "Public API facade and private helpers for payloads, snippets, findings, URLs, and AI-detection metadata.",
        "touch": "Keep compatibility in mind here; external users may import from skylos.api.",
        "entrypoints": ["skylos/api/__init__.py", "skylos/api/_findings.py", "skylos/api/_payloads.py"],
    },
    "skylos/audit": {
        "purpose": "Deep-audit candidate selection, processing, redaction, export, and revalidation.",
        "touch": "Use this for audit packets, changed-file audits, and post-scan review artifacts.",
        "entrypoints": ["skylos/audit/processor.py", "skylos/audit/candidates.py", "skylos/audit/revalidator.py"],
    },
    "skylos/benchmarks": {
        "purpose": "Benchmark fixtures and scoring code for security, quality, dead-code, and agent-review comparisons.",
        "touch": "Change this when proving scanner quality changed, not just when code still passes tests.",
        "entrypoints": ["skylos/benchmarks/security.py", "skylos/benchmarks/quality.py", "skylos/benchmarks/agent_review.py"],
    },
    "skylos/cicd": {
        "purpose": "CI workflow generation, annotations, review comments, evidence, and risk passport output.",
        "touch": "Use this when changing GitHub/GitLab integration behavior or CI gate messaging.",
        "entrypoints": ["skylos/cicd/workflow.py", "skylos/cicd/review.py", "skylos/cicd/evidence.py"],
    },
    "skylos/cli_core": {
        "purpose": "Smaller CLI parser and dispatch pieces peeled away from the main CLI module.",
        "touch": "Prefer this for new command wiring when it fits the newer CLI split.",
        "entrypoints": ["skylos/cli_core/main_parser.py", "skylos/cli_core/dispatch.py"],
    },
    "skylos/cloud": {
        "purpose": "Skylos Cloud login, credentials, policy sync, project context, and upload manifest support.",
        "touch": "Treat this as security-sensitive because local repo state and cloud policy meet here.",
        "entrypoints": ["skylos/cloud/sync.py", "skylos/cloud/credentials.py", "skylos/cloud/project_context.py"],
    },
    "skylos/commands": {
        "purpose": "Command modules used by the CLI for focused command behavior.",
        "touch": "Put command-specific behavior here instead of growing skylos/cli.py.",
        "entrypoints": ["skylos/commands/run_cmd.py", "skylos/commands/cicd_cmd.py", "skylos/commands/sync_cmd.py"],
    },
    "skylos/core": {
        "purpose": "Small shared core types and helpers used across scan paths.",
        "touch": "Use this only for concepts that are truly shared across the product.",
        "entrypoints": ["skylos/core/findings.py"],
    },
    "skylos/deadcode": {
        "purpose": "Dead-code specific analysis, framework liveness, and evidence support.",
        "touch": "Change this for dead-code false positives, framework awareness, and reachability fixes.",
        "entrypoints": ["skylos/deadcode/frameworks.py", "skylos/deadcode/evidence.py"],
    },
    "skylos/debt": {
        "purpose": "Technical-debt detection and reporting helpers.",
        "touch": "Use this for code-health signals that are not direct security findings.",
        "entrypoints": ["skylos/debt/"],
    },
    "skylos/defend": {
        "purpose": "Defensive scanning plugins and checks for suspicious package or code patterns.",
        "touch": "Use this for supply-chain or malicious-code detection extensions.",
        "entrypoints": ["skylos/defend/"],
    },
    "skylos/discover": {
        "purpose": "Source discovery and language/workspace detection.",
        "touch": "Change this when Skylos misses files or scans too much.",
        "entrypoints": ["skylos/discover/sources.py"],
    },
    "skylos/engines": {
        "purpose": "Language-specific engines and parsers beyond the Python AST path.",
        "touch": "Use this when adding or fixing non-Python language analysis.",
        "entrypoints": ["skylos/engines/"],
    },
    "skylos/integrations": {
        "purpose": "External-service integration helpers.",
        "touch": "Keep external contracts small and well-tested here.",
        "entrypoints": ["skylos/integrations/"],
    },
    "skylos/llm": {
        "purpose": "LLM security analysis, evidence grounding, provider runtime resolution, and prompt templates.",
        "touch": "Treat this as high-risk: changes can reduce hallucinations or create scanner false negatives.",
        "entrypoints": ["skylos/llm/analyzer.py", "skylos/llm/finding_evidence.py", "skylos/llm/runtime.py"],
    },
    "skylos/plugins": {
        "purpose": "Plugin interfaces and loading support.",
        "touch": "Use this when adding extension points without coupling them to core scan flow.",
        "entrypoints": ["skylos/plugins/"],
    },
    "skylos/remediation": {
        "purpose": "Autofix and cleanup support for selected findings.",
        "touch": "Use this only when a finding has a safe, narrow, testable edit path.",
        "entrypoints": ["skylos/remediation/"],
    },
    "skylos/reporting": {
        "purpose": "Output formatters and exports such as SARIF, compact JSON, and human-readable reports.",
        "touch": "Use this when scan results are right but the output is wrong or hard to consume.",
        "entrypoints": ["skylos/reporting/"],
    },
    "skylos/rules": {
        "purpose": "Rule catalog and concrete rule implementations for quality, security, config, and SCA findings.",
        "touch": "Start here when adding rule IDs, tuning scanner semantics, or changing rule docs parity.",
        "entrypoints": ["skylos/rules/catalog.py", "skylos/rules/danger", "skylos/rules/quality"],
    },
    "skylos/scale": {
        "purpose": "Scale and performance helpers for larger repositories.",
        "touch": "Use this when scan runtime, batching, or large-repo behavior changes.",
        "entrypoints": ["skylos/scale/"],
    },
    "skylos/security": {
        "purpose": "Security contract detection, secret handling, and security-specific analysis helpers.",
        "touch": "Treat this as gate-sensitive; regressions here can hide vulnerabilities.",
        "entrypoints": ["skylos/security_contracts.py", "skylos/security/"],
    },
    "skylos/ui": {
        "purpose": "Terminal UI and presentation helpers.",
        "touch": "Use this when the scan is correct but terminal interaction is confusing.",
        "entrypoints": ["skylos/ui/"],
    },
    "skylos/visitors": {
        "purpose": "AST/tree visitors that collect findings and semantic evidence.",
        "touch": "Use this when a language-specific scan is missing or over-reporting code patterns.",
        "entrypoints": ["skylos/visitors/"],
    },
    "skylos/web": {
        "purpose": "Optional web server helpers.",
        "touch": "Keep this separate from core CLI scanning.",
        "entrypoints": ["skylos/web/"],
    },
    "scripts": {
        "purpose": "Repository maintenance, benchmark, parity, and regression scripts.",
        "touch": "Use this for repeatable evidence and local automation that should not live in runtime package code.",
        "entrypoints": ["scripts/security_benchmark.py", "scripts/quality_benchmark.py", "scripts/check_rule_docs_parity.py"],
    },
    "test": {
        "purpose": "Unit and regression tests covering CLI, analyzer, rules, integrations, and benchmarks.",
        "touch": "Add narrow tests here before trusting analyzer or policy changes.",
        "entrypoints": ["test/"],
    },
    "benchmarks": {
        "purpose": "Benchmark data and generated comparison artifacts.",
        "touch": "Use this when storing benchmark fixtures or outputs that explain scanner quality.",
        "entrypoints": ["benchmarks/"],
    },
}

WORKFLOWS: list[dict[str, Any]] = [
    {
        "title": "I want to understand a normal scan",
        "goal": "Follow the main path from CLI input to findings and output.",
        "personas": "user contributor maintainer",
        "paths": ["skylos/cli.py", "skylos/config.py", "skylos/pipeline.py", "skylos/analyzer.py", "skylos/reporting/"],
        "tests": ["test/test_cli.py", "test/test_analyzer.py"],
        "steps": [
            "Read the CLI route first, then jump to config loading.",
            "Follow the handoff into pipeline/analyzer only after the inputs make sense.",
            "Verify with CLI and analyzer tests before trusting a behavior change.",
        ],
    },
    {
        "title": "I want to fix a false positive",
        "goal": "Find the detector, the evidence proof, and the regression test that should pin the behavior.",
        "personas": "debugger contributor maintainer",
        "paths": ["skylos/analyzer.py", "skylos/analysis/", "skylos/deadcode/", "skylos/visitors/", "test/"],
        "tests": ["test/test_analyzer.py", "test/test_framework_liveness.py"],
        "steps": [
            "Reproduce the wrong finding with the smallest possible fixture.",
            "Find whether the bug is rule logic, liveness evidence, framework handling, or output filtering.",
            "Add a regression test that fails before the fix and passes after it.",
        ],
    },
    {
        "title": "I want to add or tune a rule",
        "goal": "Change the catalog and implementation together so docs, IDs, and behavior stay aligned.",
        "personas": "contributor debugger maintainer",
        "paths": ["skylos/rules/catalog.py", "skylos/rules/danger/", "skylos/rules/quality/", "dictionary.md"],
        "tests": ["test/test_rule_catalog.py", "scripts/check_rule_docs_parity.py"],
        "steps": [
            "Start with the rule ID and public wording before touching detector code.",
            "Keep the catalog, implementation, tests, and docs parity together.",
            "Run parity checks so users do not see undocumented or mismatched rule IDs.",
        ],
    },
    {
        "title": "I want to touch LLM analysis",
        "goal": "Keep prompts, provider runtime, evidence grounding, and scanner integrity together.",
        "personas": "security maintainer",
        "paths": ["skylos/llm/analyzer.py", "skylos/llm/finding_evidence.py", "skylos/adapters/", "skylos/agents/"],
        "tests": ["test/test_llm_finding_evidence.py", "test/test_agent_service.py"],
        "steps": [
            "Treat the LLM as untrusted until code evidence proves the claim.",
            "Change prompts/runtime separately from evidence filters when possible.",
            "Benchmark against hard false-positive and false-negative fixtures.",
        ],
    },
    {
        "title": "I want to change cloud or CI policy",
        "goal": "Follow local config, synced policy, generated workflows, and gate output as one security boundary.",
        "personas": "security maintainer",
        "paths": ["skylos/config.py", "skylos/cloud/sync.py", "skylos/cicd/workflow.py", "skylos/security_contracts.py"],
        "tests": ["test/test_config.py", "test/test_security_contracts.py", "test/test_cicd_workflow.py"],
        "steps": [
            "Decide which side owns the policy: local repo, synced cloud policy, or CLI flag.",
            "Check merge precedence before changing analyzer behavior.",
            "Test the bypass case, not only the normal happy path.",
        ],
    },
    {
        "title": "I want to prove quality changed",
        "goal": "Run benchmarks and regression scripts instead of trusting a single happy-path fixture.",
        "personas": "contributor debugger security maintainer",
        "paths": ["scripts/security_benchmark.py", "scripts/quality_benchmark.py", "scripts/dead_code_benchmark.py", "skylos/benchmarks/"],
        "tests": ["test/test_security_benchmark.py", "test/test_quality_benchmark.py", "test/test_dead_code_benchmark.py"],
        "steps": [
            "Pick the benchmark closest to the behavior you changed.",
            "Record before/after scores and timing.",
            "Keep hard fixtures in the benchmark suite when they guard real regressions.",
        ],
    },
    {
        "title": "I want to use Skylos as a library",
        "goal": "Start with the public API facade before reaching into private helpers.",
        "personas": "user contributor",
        "paths": ["skylos/api/__init__.py", "skylos/api/_findings.py", "skylos/api/_payloads.py"],
        "tests": ["test/test_api.py"],
        "steps": [
            "Import from skylos.api first; treat underscore modules as implementation details.",
            "Check payload shape helpers before creating a new response format.",
            "Preserve public facade behavior even when private helpers move.",
        ],
    },
]

FIRST_STEPS = [
    {
        "title": "I am completely new",
        "time": "10 minutes",
        "personas": "user contributor",
        "steps": [
            "Open README.md to understand what Skylos does.",
            "Open this map and pick exactly one route card.",
            "Read only the first two files in that route before browsing deeper.",
        ],
        "paths": ["README.md", "docs/repo-map/index.html"],
    },
    {
        "title": "I need to make a small change",
        "time": "15 minutes",
        "personas": "contributor",
        "steps": [
            "Search this page for the thing you want to change.",
            "Open the matching folder card and check the nearby tests.",
            "Change one ownership area first; avoid drive-by refactors.",
        ],
        "paths": ["test/", "scripts/"],
    },
    {
        "title": "I am debugging a bad result",
        "time": "20 minutes",
        "personas": "debugger",
        "steps": [
            "Find the rule or finding category in the route cards.",
            "Build the smallest fixture that reproduces the bad result.",
            "Patch the detector and keep the fixture as a regression test.",
        ],
        "paths": ["skylos/rules/", "skylos/analyzer.py", "test/"],
    },
    {
        "title": "I am reviewing a risky PR",
        "time": "20 minutes",
        "personas": "security maintainer",
        "steps": [
            "Check whether the PR touches a hot zone.",
            "Follow the scan flow to see downstream output impact.",
            "Ask for benchmark or regression evidence before merging scanner semantics.",
        ],
        "paths": ["skylos/llm/", "skylos/security/", "skylos/cloud/", "skylos/cicd/"],
    },
    {
        "title": "I need the architecture",
        "time": "15 minutes",
        "personas": "maintainer",
        "steps": [
            "Read the Architecture section before opening shared core files.",
            "Check hot zones for files that can change many workflows.",
            "Use the docstring standard before reshaping public entrypoints.",
        ],
        "paths": ["skylos/pipeline.py", "skylos/analyzer.py", "skylos/cli.py", "skylos/config.py"],
    },
]

SHARP_EDGES = [
    {
        "title": "Safer first touches",
        "items": [
            "Focused command modules under skylos/commands/",
            "Rule fixtures and narrow regression tests",
            "Reporting copy or output formatting",
            "Benchmark fixture additions",
        ],
    },
    {
        "title": "Slow down here",
        "items": [
            "skylos/cli.py because it still dispatches many workflows",
            "skylos/analyzer.py because it owns core scanner semantics",
            "skylos/config.py because config precedence can become a security boundary",
            "skylos/llm/finding_evidence.py because filters can create false negatives",
        ],
    },
    {
        "title": "Proof expected",
        "items": [
            "False-positive fixes need a negative and positive fixture",
            "Security changes need a bypass or attacker-controlled input test",
            "LLM grounding changes need before/after benchmark evidence",
            "Public API changes need facade compatibility tests",
        ],
    },
]

PERSONAS = [
    {
        "id": "user",
        "title": "I just want to use Skylos",
        "summary": "Start with install, commands, output, and rule meanings. Skip internal ownership maps.",
        "paths": ["README.md", "docs/README.md", "dictionary.md"],
        "search": "install quick start cli output rules user docs",
    },
    {
        "id": "contributor",
        "title": "I want to contribute",
        "summary": "Pick a safe ownership area, find nearby tests, and keep the change narrow.",
        "paths": ["CONTRIBUTING.md", "test/", "scripts/"],
        "search": "contribute first pr tests safe change ownership",
    },
    {
        "id": "debugger",
        "title": "I am debugging a bad finding",
        "summary": "Reproduce the finding, locate the detector/evidence layer, and add a regression test.",
        "paths": ["skylos/analyzer.py", "skylos/rules/", "skylos/analysis/", "test/"],
        "search": "false positive false negative detector evidence regression",
    },
    {
        "id": "security",
        "title": "I am reviewing security or LLM behavior",
        "summary": "Follow trust boundaries: config policy, LLM evidence filters, CI, and cloud sync.",
        "paths": ["skylos/config.py", "skylos/llm/", "skylos/security/", "skylos/cloud/", "skylos/cicd/"],
        "search": "security llm policy cloud ci evidence bypass",
    },
    {
        "id": "maintainer",
        "title": "I need the architecture",
        "summary": "Use the layer map, hot zones, and docstring guide before reshaping shared paths.",
        "paths": ["skylos/pipeline.py", "skylos/analyzer.py", "skylos/cli.py", "skylos/config.py"],
        "search": "architecture maintainer hot zones boundaries main sequence",
    },
]

ARCHITECTURE_LAYERS = [
    {
        "title": "Interfaces",
        "purpose": "Where users, CI, agents, and library consumers enter Skylos.",
        "paths": ["skylos/cli.py", "skylos/api/", "skylos/commands/", "skylos/cicd/"],
        "depends_on": "Policy, discovery, analysis, reporting",
        "guardrail": "Keep interface code thin; move command-specific logic into focused modules.",
        "personas": "user contributor maintainer",
    },
    {
        "title": "Policy And Trust",
        "purpose": "Configuration, synced cloud policy, security contracts, and gate decisions.",
        "paths": ["skylos/config.py", "skylos/cloud/sync.py", "skylos/security_contracts.py"],
        "depends_on": "Interfaces and analyzer output",
        "guardrail": "Treat merge precedence and attacker-controlled repo config as security-sensitive.",
        "personas": "security maintainer",
    },
    {
        "title": "Discovery",
        "purpose": "Decides which files and languages enter the scanner.",
        "paths": ["skylos/discover/", "skylos/pipeline.py", "skylos/engines/"],
        "depends_on": "Config and filesystem state",
        "guardrail": "Too broad creates noise; too narrow creates false negatives.",
        "personas": "debugger contributor maintainer",
    },
    {
        "title": "Static Analysis Core",
        "purpose": "Owns liveness, rules, framework handling, quality checks, and dangerous-flow detection.",
        "paths": ["skylos/analyzer.py", "skylos/analysis/", "skylos/rules/", "skylos/visitors/"],
        "depends_on": "Discovery, config, language engines",
        "guardrail": "Every semantic change needs a small fixture and a regression test.",
        "personas": "debugger security maintainer",
    },
    {
        "title": "Evidence And AI Review",
        "purpose": "Grounds LLM/agent findings against source code and scanner evidence.",
        "paths": ["skylos/llm/", "skylos/agents/", "skylos/adapters/"],
        "depends_on": "Static analysis output and provider adapters",
        "guardrail": "Filters must prove safety; weak refutation creates scanner false negatives.",
        "personas": "security maintainer",
    },
    {
        "title": "Output And Feedback",
        "purpose": "Turns findings into terminal output, reports, uploads, annotations, and review comments.",
        "paths": ["skylos/reporting/", "skylos/cloud/", "skylos/cicd/", "skylos/ui/"],
        "depends_on": "Analyzer results and policy decisions",
        "guardrail": "Output changes should preserve machine-readable compatibility.",
        "personas": "user contributor maintainer",
    },
    {
        "title": "Proof Harness",
        "purpose": "Keeps behavior honest with tests, benchmarks, parity checks, and generated artifacts.",
        "paths": ["test/", "benchmarks/", "scripts/", "skylos/benchmarks/"],
        "depends_on": "All product layers",
        "guardrail": "Benchmark updates should explain score, timing, and regression intent.",
        "personas": "contributor debugger security maintainer",
    },
]

DOCSTRING_GUIDE = [
    {
        "title": "Intent",
        "body": "Why this function exists, in product terms. Prefer the user-visible or scanner-integrity reason over a paraphrase of the function name.",
    },
    {
        "title": "Trust Boundary",
        "body": "State whether inputs can come from a scanned repo, CI, cloud policy, LLM output, or local filesystem. This is mandatory for security-sensitive helpers.",
    },
    {
        "title": "Invariants",
        "body": "List conditions the function must preserve, such as policy precedence, no symlink writes, no HTML injection, or no LLM-only refutation.",
    },
    {
        "title": "Failure Mode",
        "body": "Say what happens when parsing, IO, provider calls, or analysis fails. Future maintainers need to know whether fail-open is intentional.",
    },
    {
        "title": "Evidence Contract",
        "body": "For scanners, explain what proof is enough to emit or suppress a finding. This reduces false positives and false negatives.",
    },
    {
        "title": "Performance Shape",
        "body": "Call out whole-repo walks, AST parsing, subprocesses, network calls, caching, or expected input size.",
    },
    {
        "title": "Extension Point",
        "body": "Name the safe place to add new rules, providers, languages, output formats, or framework conventions.",
    },
    {
        "title": "Validation",
        "body": "Point to the exact test family, benchmark, or parity check that should fail if the function regresses.",
    },
]

GLOSSARY = [
    ("Finding", "A normalized issue Skylos reports. Most output formats eventually render finding dictionaries."),
    ("Danger", "Security-sensitive findings such as injection, insecure config, secrets, or policy regressions."),
    ("Quality", "Maintainability findings like complexity, naming, god files, and readability issues."),
    ("Security contract", "A configured security expectation that should not be weakened by a PR."),
    ("Evidence grounding", "Code-backed proof used to keep LLM findings from drifting into hallucinations."),
    ("Rule catalog", "The source of rule IDs and public rule descriptions."),
    ("Benchmark", "A repeatable fixture that compares scanner behavior across versions or tools."),
]


@dataclass(frozen=True)
class SymbolInfo:
    """
    Top-level class or function discovered in one Python source file.

    Attributes:
        name: Symbol name exactly as it appears in source.
        kind: Human-readable symbol type, such as `class`, `def`, or
            `async def`.
        line: 1-based source line for stable in-file ordering. The renderer
            intentionally does not emit this value because line anchors churn
            whenever unrelated code moves.
        private: Whether the symbol name starts with `_`.

    Used by:
        scripts/build_repo_map.py _extract_symbols;
        scripts/build_repo_map.py _key_symbols;
        scripts/repo_map_renderer.py render_symbol_index.
    """
    name: str
    kind: str
    line: int
    private: bool


@dataclass(frozen=True)
class ModuleInfo:
    """
    Parsed facts for one Python module shown in the repo map.

    Attributes:
        path: Repository-relative POSIX path.
        summary: Module docstring summary or curated folder fallback.
        symbols: Top-level symbols extracted from the module AST.
        imports: Top-level import roots used by the module.

    Used by:
        scripts/build_repo_map.py collect_repo_map;
        scripts/repo_map_renderer.py render_hot_modules.
    """
    path: str
    summary: str
    symbols: list[SymbolInfo]
    imports: list[str]


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_source_files(root: Path) -> list[Path]:
    """
    Walk the repository roots that feed the generated map.

    Args:
        root: Repository root to scan.

    Returns:
        Sorted source/config/doc files under SOURCE_ROOTS that are regular,
        non-symlink files under the size cap.

    Trust boundary:
        Source paths may come from the repository being documented. Directory
        symlinks and oversized files are skipped before read/parsing.

    Calls: scripts/build_repo_map.py _include_directory;
        scripts/build_repo_map.py _safe_source_file.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    files: list[Path] = []
    for root_name in SOURCE_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        if base.is_file():
            files.append(base)
            continue
        for current, dirs, filenames in os.walk(base):
            current_path = Path(current)
            dirs[:] = sorted(
                dirname
                for dirname in dirs
                if _include_directory(current_path / dirname)
            )
            for filename in sorted(filenames):
                path = current_path / filename
                if path.suffix in {".py", ".md", ".toml", ".yml", ".yaml"} and _safe_source_file(path):
                    files.append(path)
    return sorted(files)


def _include_directory(path: Path) -> bool:
    name = path.name
    return name not in EXCLUDED_DIRS and not name.startswith(".") and not path.is_symlink()


def _safe_source_file(path: Path) -> bool:
    """
    Decide whether a path is safe for the repo-map generator to read.

    Args:
        path: Candidate file path.

    Returns:
        True only for regular non-symlink files no larger than
        MAX_SOURCE_BYTES.

    Invariants:
        Do not follow symlinks. Do not read unbounded file content.

    Calls: pathlib.Path.stat.

    Called from: scripts/build_repo_map.py _iter_source_files;
        scripts/build_repo_map.py _read_text;
        scripts/build_repo_map.py main.
    """
    try:
        file_stat = path.stat(follow_symlinks=False)
        return (
            stat.S_ISREG(file_stat.st_mode)
            and not path.is_symlink()
            and file_stat.st_size <= MAX_SOURCE_BYTES
        )
    except OSError:
        return False


def _first_sentence(text: str) -> str:
    normalized = " ".join(text.strip().split())
    if not normalized:
        return ""
    for marker in (". ", "? ", "! "):
        if marker in normalized:
            return normalized.split(marker, 1)[0].strip() + marker.strip()
    return normalized


def _read_text(path: Path) -> str:
    """
    Read a validated source file with symlink and size defenses.

    Args:
        path: Regular source file already expected to be inside the repo walk.

    Returns:
        UTF-8 text, replacing undecodable bytes.

    Trust boundary:
        Files are repository content and may be attacker-controlled in forks or
        PRs. Reads are guarded by _safe_source_file and O_NOFOLLOW where the OS
        supports it.

    Failure mode:
        Raises ValueError for unsafe paths. IO errors are allowed to propagate
        because a broken repo-map generation should fail loudly.

    Calls: scripts/build_repo_map.py _safe_source_file; os.open; os.fdopen.

    Called from: scripts/build_repo_map.py _parse_python_module;
        scripts/build_repo_map.py main.
    """
    if not _safe_source_file(path):
        raise ValueError(f"Refusing to read unsafe or oversized source file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)  # skylos: ignore O_NOFOLLOW and size cap guard repo-map source reads
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read(MAX_SOURCE_BYTES)


def _extract_imports(tree: ast.AST) -> list[str]:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".", 2)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            imports.add(".".join(parts[:2]) if parts[0] == "skylos" and len(parts) > 1 else parts[0])
    return sorted(imports)


def _extract_symbols(tree: ast.Module) -> list[SymbolInfo]:
    symbols: list[SymbolInfo] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            symbols.append(SymbolInfo(node.name, "class", node.lineno, node.name.startswith("_")))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            symbols.append(SymbolInfo(node.name, kind, node.lineno, node.name.startswith("_")))
    return symbols


def _fallback_summary(relpath: str) -> str:
    path = Path(relpath)
    if relpath in {
        "skylos/cli.py",
        "skylos/analyzer.py",
        "skylos/pipeline.py",
        "skylos/config.py",
    }:
        return FOLDER_META["skylos"]["purpose"]
    for group, meta in sorted(FOLDER_META.items(), key=lambda item: len(item[0]), reverse=True):
        if relpath == group or relpath.startswith(group + "/"):
            return str(meta["purpose"])
    return "Generated module facts are available, but no curated summary exists yet."


def _parse_python_module(path: Path, root: Path) -> ModuleInfo:
    """
    Parse one Python file into the module facts shown by the map.

    Args:
        path: Python source file to parse.
        root: Repository root used to compute display paths.

    Returns:
        ModuleInfo containing path, summary, imports, and top-level symbols.
        Syntax errors produce an empty-symbol ModuleInfo instead of aborting
        the whole map.

    Calls: scripts/build_repo_map.py _rel;
        scripts/build_repo_map.py _read_text;
        scripts/build_repo_map.py _first_sentence;
        scripts/build_repo_map.py _extract_symbols;
        scripts/build_repo_map.py _extract_imports.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    relpath = _rel(path, root)
    source = _read_text(path)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ModuleInfo(relpath, "Python file could not be parsed by ast.", [], [])
    doc_summary = _first_sentence(ast.get_docstring(tree) or "")
    return ModuleInfo(
        path=relpath,
        summary=doc_summary or _fallback_summary(relpath),
        symbols=_extract_symbols(tree),
        imports=_extract_imports(tree),
    )


def _group_for_path(relpath: str) -> str:
    parts = relpath.split("/")
    if not parts:
        return relpath
    if parts[0] == "skylos":
        if len(parts) >= 3:
            return f"skylos/{parts[1]}"
        return "skylos"
    return parts[0]


def _hot_module_score(module: ModuleInfo) -> int:
    shared = 1 if module.path in SHARED_ENTRYPOINTS else 0
    return shared * 1000 + len(module.symbols)


def _test_files_for_group(group: str, test_files: list[str]) -> list[str]:
    if group == "test":
        return test_files[:6]
    key = group.split("/", 1)[1] if group.startswith("skylos/") else group
    key = key.replace("_", "")
    matches = [
        path
        for path in test_files
        if key and key in path.replace("_", "").lower()
    ]
    return matches[:6]


def collect_repo_map(root: Path) -> dict[str, Any]:
    """
    Build deterministic repo-map data from code and a small curated folder map.

    Args:
        root: Repository root to scan.

    Returns:
        Dictionary consumed by `scripts.repo_map_renderer.render_html`. It
        includes persona cards, architecture layers, docstring guidance,
        folder cards, hot modules, symbol index, and repo-level counts.

    Invariants:
        Generated data must be deterministic for the same tree. This keeps
        `scripts/build_repo_map.py --check` useful in CI and avoids noisy PRs.

    Performance shape:
        Walks selected repository roots once, then parses Python files with
        `ast`. The scan is intentionally local-only and uses a per-file size cap.

    Calls: scripts/build_repo_map.py _iter_source_files;
        scripts/build_repo_map.py _parse_python_module;
        scripts/build_repo_map.py _sanitize_path_groups;
        scripts/build_repo_map.py _sanitize_workflows.

    Called from: scripts/build_repo_map.py write_repo_map;
        scripts/build_repo_map.py main.
    """
    root = root.resolve()
    source_files = _iter_source_files(root)
    python_modules = [
        _parse_python_module(path, root)
        for path in source_files
        if path.suffix == ".py"
    ]
    test_files = sorted(module.path for module in python_modules if module.path.startswith("test/"))

    groups: dict[str, dict[str, Any]] = {}
    for module in python_modules:
        group = _group_for_path(module.path)
        bucket = groups.setdefault(
            group,
            {
                "path": group,
                "files": 0,
                "symbols": 0,
                "public_symbols": 0,
                "modules": [],
            },
        )
        bucket["files"] += 1
        bucket["symbols"] += len(module.symbols)
        bucket["public_symbols"] += sum(1 for symbol in module.symbols if not symbol.private)
        bucket["modules"].append(module)

    folder_cards = []
    for group in sorted(groups):
        meta = FOLDER_META.get(group, {})
        modules = sorted(
            groups[group]["modules"],
            key=lambda item: (-len(item.symbols), item.path),
        )
        key_symbols = _key_symbols(modules)
        folder_cards.append(
            {
                "path": group,
                "purpose": meta.get("purpose", "Generated facts are available; this folder still needs a curated summary."),
                "touch": meta.get("touch", "Use the module list and tests to decide whether this is the right ownership area."),
                "entrypoints": [path for path in meta.get("entrypoints", []) if _path_exists_or_directory(root, path)],
                "tests": _test_files_for_group(group, test_files),
                "files": groups[group]["files"],
                "symbols": groups[group]["symbols"],
                "public_symbols": groups[group]["public_symbols"],
                "modules": modules[:8],
                "key_symbols": key_symbols,
            }
        )

    hot_modules = sorted(
        python_modules,
        key=lambda item: (-_hot_module_score(item), item.path),
    )[:14]
    symbol_index = _symbol_index(python_modules)

    return {
        "folder_cards": folder_cards,
        "glossary": GLOSSARY,
        "hot_modules": hot_modules,
        "source_file_count": len(source_files),
        "python_file_count": len(python_modules),
        "symbol_count": sum(len(module.symbols) for module in python_modules),
        "first_steps": _sanitize_path_groups(root, FIRST_STEPS),
        "personas": _sanitize_path_groups(root, PERSONAS),
        "architecture_layers": _sanitize_path_groups(root, ARCHITECTURE_LAYERS),
        "docstring_guide": DOCSTRING_GUIDE,
        "sharp_edges": SHARP_EDGES,
        "workflows": _sanitize_workflows(root),
        "symbol_index": symbol_index,
    }


def _sanitize_path_groups(root: Path, groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove stale links from curated card groups before rendering.

    Args:
        root: Repository root used to check whether paths still exist.
        groups: Curated persona, first-step, or architecture cards.

    Returns:
        Shallow-copied card dictionaries with `paths` filtered to existing
        files/directories or approved generated paths.

    Calls: scripts/build_repo_map.py _path_exists_or_directory.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    sanitized: list[dict[str, Any]] = []
    for group in groups:
        copy = dict(group)
        copy["paths"] = [path for path in group.get("paths", []) if _path_exists_or_directory(root, path)]
        sanitized.append(copy)
    return sanitized


def _sanitize_workflows(root: Path) -> list[dict[str, Any]]:
    """
    Remove stale file and test links from workflow cards.

    Args:
        root: Repository root used for path existence checks.

    Returns:
        Workflow dictionaries with non-existent `paths` and `tests` removed.

    Calls: scripts/build_repo_map.py _path_exists_or_directory.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    workflows: list[dict[str, Any]] = []
    for workflow in WORKFLOWS:
        copy = dict(workflow)
        copy["paths"] = [path for path in workflow["paths"] if _path_exists_or_directory(root, path)]
        copy["tests"] = [path for path in workflow["tests"] if _path_exists_or_directory(root, path)]
        workflows.append(copy)
    return workflows


def _path_exists_or_directory(root: Path, relpath: str) -> bool:
    if relpath in GENERATED_PATHS:
        return True
    if relpath.endswith("/"):
        return (root / relpath.rstrip("/")).is_dir()
    return (root / relpath).exists()


def _key_symbols(modules: list[ModuleInfo]) -> list[dict[str, Any]]:
    """
    Select a compact symbol sample for one folder card.

    Args:
        modules: ModuleInfo objects already sorted by local importance.

    Returns:
        Up to 14 dictionaries containing symbol name, kind, file path, and
        source line. Public symbols are preferred before private helpers.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    items: list[dict[str, Any]] = []
    for module in modules:
        public = [symbol for symbol in module.symbols if not symbol.private]
        private = [symbol for symbol in module.symbols if symbol.private]
        for symbol in (public + private)[:5]:
            items.append(
                {
                    "name": symbol.name,
                    "kind": symbol.kind,
                    "path": module.path,
                    "line": symbol.line,
                }
            )
        if len(items) >= 14:
            break
    return items[:14]


def _symbol_index(modules: list[ModuleInfo]) -> list[dict[str, Any]]:
    """
    Build the searchable symbol table shown near the bottom of the map.

    Args:
        modules: Parsed Python module facts.

    Returns:
        Up to 900 symbol dictionaries sorted by file and line. Private helpers
        are hidden except in the major shared entrypoint files.

    Invariants:
        Keep this bounded so the generated page stays usable and predictable.

    Called from: scripts/build_repo_map.py collect_repo_map.
    """
    symbols: list[dict[str, Any]] = []
    for module in sorted(modules, key=lambda item: item.path):
        for symbol in module.symbols:
            if symbol.private and module.path not in PRIVATE_SYMBOL_ENTRYPOINTS:
                continue
            symbols.append(
                {
                    "name": symbol.name,
                    "kind": symbol.kind,
                    "path": module.path,
                    "line": symbol.line,
                    "summary": module.summary,
                    "private": symbol.private,
                }
            )
    return sorted(symbols, key=lambda item: (item["path"], item["line"]))[:900]


def _resolve_output_path(root: Path, output: Path) -> Path:
    """
    Resolve and validate the generated HTML output path.

    Args:
        root: Repository root that must contain the output parent.
        output: Absolute or root-relative output path requested by the caller.

    Returns:
        Absolute output path under `root`.

    Trust boundary:
        Output paths can be supplied from CLI args. The generator refuses
        symlink parents, symlink targets, and paths outside the repository.

    Failure mode:
        Raises ValueError when the output path is unsafe.

    Called from: scripts/build_repo_map.py write_repo_map;
        scripts/build_repo_map.py main.
    """
    candidate = output if output.is_absolute() else root / output
    candidate_parent = candidate.parent
    candidate_parent.mkdir(parents=True, exist_ok=True)
    if candidate_parent.is_symlink() or candidate.is_symlink():
        raise ValueError(f"Refusing to write repo map through symlink: {candidate}")

    resolved_root = root.resolve()
    resolved_parent = candidate_parent.resolve()
    if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
        raise ValueError(f"Repo map output must stay inside the repository: {candidate}")
    return resolved_parent / candidate.name


def _write_text_safely(path: Path, content: str) -> None:
    """
    Write generated repo-map HTML without following symlink targets.

    Args:
        path: Validated output file path.
        content: Full HTML document to write.

    Returns:
        None.

    Trust boundary:
        This protects local and CI runs from writing generated content through
        an attacker-controlled symlink in a checked-out repository.

    Calls: os.open; os.fdopen.

    Called from: scripts/build_repo_map.py write_repo_map;
        scripts/build_repo_map.py main.
    """
    if path.is_symlink():
        raise ValueError(f"Refusing to write repo map through symlink: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)  # skylos: ignore O_NOFOLLOW used for generated repo-map output
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def write_repo_map(root: Path, output: Path) -> str:
    """
    Generate and write the repo-map HTML page.

    Args:
        root: Repository root to scan.
        output: HTML output path.

    Returns:
        The generated HTML string after it has been written to disk.

    Calls: scripts/build_repo_map.py _resolve_output_path;
        scripts/build_repo_map.py collect_repo_map;
        scripts.repo_map_renderer.render_html;
        scripts/build_repo_map.py _write_text_safely.

    Called from: tests and by callers that want generation without invoking
        the CLI parser.
    """
    output = _resolve_output_path(root.resolve(), output)
    data = collect_repo_map(root)
    page = render_html(data)
    _write_text_safely(output, page)
    return page


def main(argv: list[str] | None = None) -> int:
    """
    Command-line entrypoint for building or checking the repo map.

    Args:
        argv: Optional argument list. When None, argparse reads sys.argv.

    Returns:
        Process-style exit code: 0 for success, 1 when `--check` finds a
        missing or stale generated page.

    Behavior:
        Without `--check`, writes `docs/repo-map/index.html`. With `--check`,
        renders in memory and compares against the checked-in generated file.

    Calls: scripts/build_repo_map.py collect_repo_map;
        scripts.repo_map_renderer.render_html;
        scripts/build_repo_map.py _resolve_output_path;
        scripts/build_repo_map.py _read_text;
        scripts/build_repo_map.py _write_text_safely.

    Called from: shell, GitHub Pages workflow, and test/test_repo_map.py.
    """
    parser = argparse.ArgumentParser(description="Build Skylos' static repo navigator.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root to scan.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "repo-map" / "index.html",
        help="HTML file to write.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the output file is missing or stale.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    output = _resolve_output_path(root, args.output)
    page = render_html(collect_repo_map(root))

    if args.check:
        if not _safe_source_file(output):
            print(f"Repo map is missing: {output}", file=sys.stderr)
            return 1
        current = _read_text(output)
        if current != page:
            print(f"Repo map is stale: {output}", file=sys.stderr)
            print("Run: python scripts/build_repo_map.py", file=sys.stderr)
            return 1
        print(f"Repo map is current: {output}")
        return 0

    _write_text_safely(output, page)
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
