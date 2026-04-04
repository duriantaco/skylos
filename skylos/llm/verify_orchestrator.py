from __future__ import annotations

import ast
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_LLM_RETRIES = 3
RETRY_BACKOFF_BASE = 5

from .dead_code_verifier import (
    DeadCodeVerifierAgent,
    Verdict,
    VerificationResult,
    apply_verdict,
    _parse_confidence,
    _parse_int,
)

from skylos.grep_verify import (
    _run_grep,
    multi_strategy_search as _multi_strategy_search,
    parallel_multi_strategy_search as _parallel_multi_strategy_search,
    filter_grep_results as _filter_grep_results,
    is_definition_line as _is_definition_line,
    is_substring_match as _is_substring_match,
    repo_relative_path as _repo_relative_path,
    module_candidates as _module_candidates,
    parameter_owner_name as _parameter_owner_name,
    detect_language as _detect_language,
)

logger = logging.getLogger(__name__)

VERIFICATION_MODE_PRODUCTION = "production"
VERIFICATION_MODE_JUDGE_ALL = "judge_all"
VALID_VERIFICATION_MODES = {
    VERIFICATION_MODE_PRODUCTION,
    VERIFICATION_MODE_JUDGE_ALL,
}


@dataclass
class EntryPoint:
    name: str
    source: str
    reason: str


@dataclass
class EdgeResolution:
    caller: str
    callee: str
    is_real: bool
    reason: str


@dataclass
class SurvivorVerdict:
    name: str
    full_name: str
    file: str
    line: int
    heuristic_refs: dict
    verdict: Verdict
    rationale: str
    original_confidence: int
    suggested_confidence: int


@dataclass
class SuppressionDecision:
    code: str
    rationale: str
    evidence: list[str] = field(default_factory=list)
    hard: bool = False


@dataclass
class VerifyStats:
    total_findings: int = 0
    verified_true_positive: int = 0
    verified_false_positive: int = 0
    deterministic_suppressed: int = 0
    uncertain: int = 0
    suppression_challenged: int = 0
    suppression_reclassified_dead: int = 0
    survivors_challenged: int = 0
    survivors_reclassified_dead: int = 0
    entry_points_discovered: int = 0
    edges_resolved: int = 0
    edges_spurious: int = 0
    haiku_prefiltered: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class RepoFacts:
    config_files: dict[str, str] = field(default_factory=dict)
    pytest_class_patterns: list[str] = field(default_factory=lambda: ["Test"])
    pytest_function_patterns: list[str] = field(default_factory=lambda: ["test"])
    mkdocs_hook_files: set[str] = field(default_factory=set)


ENTRY_POINT_SYSTEM = """\
You are a Python project analyst. Given project configuration files, identify ALL \
entry points — functions or modules that are invoked externally (CLI commands, web \
routes, scheduled tasks, test hooks, plugin registrations).

Return JSON: {"entry_points": [{"name": "qualified.name", "source": "file", "reason": "..."}]}

Only include entry points you can confirm from the config. Do not speculate.\
"""

ENTRY_POINT_USER = """\
Analyze these project configuration files to find entry points that a static \
analyzer might miss.

{config_contents}

Known entry points already detected by static analysis:
{known_entry_points}

Find any ADDITIONAL entry points referenced in these configs that are NOT in the \
known list above. Focus on:
- console_scripts / gui_scripts in pyproject.toml or setup.cfg
- CMD / ENTRYPOINT in Dockerfile
- Celery tasks, APScheduler jobs
- MkDocs hooks registered in mkdocs.yml / mkdocs.yaml
- pytest plugins and fixtures registered in conftest.py
- Click/Typer command groups registered via entry_points
- ASGI/WSGI application references
- GitHub Actions workflow steps that invoke Python
- package.json "main", "bin", "scripts" entries (TypeScript/JS)
- Next.js/Vite/Webpack entry points and page routes
- Go main() functions referenced in go.mod or Dockerfile
- Java main classes in pom.xml/build.gradle, Spring Boot @SpringBootApplication
- Rust binary targets in Cargo.toml [[bin]] sections

JSON response:\
"""


def _gather_config_files(project_root: Path) -> dict[str, str]:
    candidates = [
        # Python
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pytest.ini",
        "tox.ini",
        "mkdocs.yml",
        "mkdocs.yaml",
        "conftest.py",
        "manage.py",
        "app.py",
        "wsgi.py",
        "asgi.py",
        # TypeScript/JS
        "package.json",
        "tsconfig.json",
        "tsconfig.*.json",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "vite.config.ts",
        "vite.config.js",
        "webpack.config.js",
        "jest.config.js",
        "jest.config.ts",
        ".eslintrc.json",
        ".eslintrc.js",
        # Go
        "go.mod",
        "go.sum",
        # Java
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        # Rust
        "Cargo.toml",
        "Cargo.lock",
        # Universal
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        "Makefile",
        "Procfile",
    ]

    configs = {}
    for pattern in candidates:
        if "*" in pattern:
            for p in project_root.glob(pattern):
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    if len(text) > 10_000:
                        text = text[:10_000] + "\n... (truncated)"
                    configs[str(p.relative_to(project_root))] = text
                except Exception:
                    pass
        else:
            p = project_root / pattern
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    if len(text) > 10_000:
                        text = text[:10_000] + "\n... (truncated)"
                    configs[pattern] = text
                except Exception:
                    pass

    return configs


def _load_pytest_patterns_from_text(raw_value: Any) -> list[str]:
    if isinstance(raw_value, list):
        return [str(v).strip() for v in raw_value if str(v).strip()]
    if isinstance(raw_value, str):
        lines = [
            line.strip().strip('"').strip("'")
            for line in raw_value.splitlines()
            if line.strip()
        ]
        return lines
    return []


def _parse_mkdocs_hook_files(configs: dict[str, str]) -> set[str]:
    hook_files: set[str] = set()
    for name in ("mkdocs.yml", "mkdocs.yaml"):
        text = configs.get(name, "")
        if not text:
            continue
        in_hooks = False
        hooks_indent = 0
        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if stripped == "hooks:":
                in_hooks = True
                hooks_indent = indent
                continue
            if in_hooks:
                if indent <= hooks_indent and not stripped.startswith("- "):
                    in_hooks = False
                    continue
                if stripped.startswith("- "):
                    hook_path = stripped[2:].strip().strip('"').strip("'")
                    if hook_path:
                        hook_files.add(hook_path.replace("\\", "/"))
    return hook_files


def _build_repo_facts(project_root: Path) -> RepoFacts:
    import configparser
    import tomllib

    configs = _gather_config_files(project_root)
    facts = RepoFacts(config_files=configs)

    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with pyproject_path.open("rb") as handle:
                pyproject = tomllib.load(handle)
            ini_options = (
                pyproject.get("tool", {}).get("pytest", {}).get("ini_options", {})
            )
            class_patterns = _load_pytest_patterns_from_text(
                ini_options.get("python_classes")
            )
            function_patterns = _load_pytest_patterns_from_text(
                ini_options.get("python_functions")
            )
            if class_patterns:
                facts.pytest_class_patterns = class_patterns
            if function_patterns:
                facts.pytest_function_patterns = function_patterns
        except Exception:
            pass

    parser = configparser.ConfigParser()
    for cfg_name, section in (
        ("pytest.ini", "pytest"),
        ("tox.ini", "pytest"),
        ("setup.cfg", "tool:pytest"),
    ):
        cfg_path = project_root / cfg_name
        if not cfg_path.exists():
            continue
        try:
            parser.read(cfg_path, encoding="utf-8")
            if not parser.has_section(section):
                continue
            class_patterns = _load_pytest_patterns_from_text(
                parser.get(section, "python_classes", fallback="")
            )
            function_patterns = _load_pytest_patterns_from_text(
                parser.get(section, "python_functions", fallback="")
            )
            if class_patterns:
                facts.pytest_class_patterns = class_patterns
            if function_patterns:
                facts.pytest_function_patterns = function_patterns
        except Exception:
            continue

    facts.mkdocs_hook_files = _parse_mkdocs_hook_files(configs)
    return facts


def _matches_pytest_pattern(name: str, patterns: list[str]) -> bool:
    import fnmatch

    for pattern in patterns:
        if name.startswith(pattern):
            return True
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatch(name, pattern):
            return True
    return False


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
    return project_root / ".skylos" / "cache" / "entry_points.json"


def _config_files_hash(configs: dict[str, str]) -> str:
    import hashlib

    content = json.dumps(configs, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def discover_entry_points(
    agent: DeadCodeVerifierAgent,
    project_root: Path,
    known_entry_points: list[str],
) -> list[EntryPoint]:
    configs = _gather_config_files(project_root)
    if not configs:
        return []

    cache_path = _entry_point_cache_path(project_root)
    current_hash = _config_files_hash(configs)
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            if cached.get("hash") == current_hash:
                return [
                    EntryPoint(
                        name=ep["name"], source=ep["source"], reason=ep["reason"]
                    )
                    for ep in cached.get("entry_points", [])
                    if ep.get("name") and ep["name"] not in known_entry_points
                ]
        except Exception:
            pass

    config_text = []
    for name, content in configs.items():
        config_text.append(f"=== {name} ===\n{content}\n")

    known_text = "\n".join(f"  - {ep}" for ep in known_entry_points[:50]) or "  (none)"

    user = ENTRY_POINT_USER.format(
        config_contents="\n".join(config_text),
        known_entry_points=known_text,
    )

    try:
        response = _call_llm_with_retry(agent, ENTRY_POINT_SYSTEM, user)
        if not response:
            return []
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        results = []
        all_discovered = []
        for ep in data.get("entry_points", []):
            name = ep.get("name", "")
            if name:
                all_discovered.append(
                    {
                        "name": name,
                        "source": ep.get("source", "config"),
                        "reason": ep.get("reason", ""),
                    }
                )
                if name not in known_entry_points:
                    results.append(
                        EntryPoint(
                            name=name,
                            source=ep.get("source", "config"),
                            reason=ep.get("reason", ""),
                        )
                    )

        # Save cache
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(
                    {"hash": current_hash, "entry_points": all_discovered}, indent=2
                )
            )
        except Exception:
            pass

        return results

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Entry point discovery failed: {e}")
        return []


GRAPH_VERIFY_SYSTEM = """\
You are verifying if code flagged as "unused" is actually dead or alive.

You will receive:
1. The flagged symbol's source code
2. Call graph context (callers, callees)
3. Inheritance context (parent class overrides)
4. Search results: grep across the ENTIRE project (source, tests, docs, configs)
5. File context around matches (actual source code, not just grep snippets)

Your job: READ the evidence and REASON about whether each match is a real usage.

What counts as ALIVE (FALSE_POSITIVE):
- Called somewhere: .name() pattern in actual code (not just in the definition file)
- Imported and used in another file
- Overrides a confirmed parent class method (look for CONFIRMED in inheritance context)
- Used in cast() or bound in TypeVar
- Referenced by a Sphinx directive (:func:, autofunction) — documented public API
- Used via dynamic dispatch: getattr(obj, "name"), dict["name"], .do("name")
- Conditional import inside try/except ImportError — the symbol IS used in the guarded code path
- File or module path is referenced by a loader/CLI/config entry and the symbol is the runtime entry surface
- Explicit changelog/docs note that a symbol was reintroduced, restored, or kept as an alias/synonym for compatibility counts as ALIVE when the symbol remains a top-level API/type alias surface
- A pytest-collected test class/function is alive even without direct imports or calls
- A hook function registered in repo config (e.g. mkdocs hooks) is alive
- A class definition inside pytest.raises()/assertRaises() is executed for its side effect
- Parameters required by a callback/hook signature or by an interface/base-method signature are ALIVE even if unused inside the body
- Method on a class that substitutes/replaces a standard object (e.g. assigned to sys.stdout, \
used as a file-like object, wraps a socket) — standard protocol methods are called by the runtime
- Enum members (FOO, BAR) on a class inheriting from Enum/IntEnum — accessed via iteration, \
Choice(), or member lookup at runtime even without explicit references
- A public symbol (no underscore prefix) in an importable package that is documented in the \
project's docs/ directory (rst, md, or autodoc) is ALIVE — it exists for downstream consumers \
even if unused internally. Look for the public_api_docs search results.
- A symbol marked as exported (is_exported=true) is part of the package's public API. \
It exists for downstream consumers. Unless you find strong evidence it's truly orphaned \
(e.g., the entire module is dead), treat it as ALIVE.
- TypeScript/JS: imported via `import {{ X }}` or `require()`, used as JSX `<Component />`, \
exported via barrel `export {{ X }}`, used with decorator `@X`, or `implements Interface`
- Go: called as `package.Func()`, referenced in interface method signatures, struct field access
- Java: imported, annotated with @Override/@Bean/@Autowired, implements/extends
- Rust: imported via `use crate::`, referenced in `impl Trait for`, `#[derive(X)]`

What counts as DEAD (TRUE_POSITIVE):
- ZERO references anywhere in the project (only the definition itself found)
- Only referenced in docstrings, comments, or string descriptions — these are NOT usages
- Keyword argument values are NOT usages: fg="green" does NOT mean a variable named \
green is used
- TypeVar definitions like T = TypeVar("T") are NOT usages of T
- A class docstring mentioning a name is NOT a usage of that name
- Listed in __all__ but NOT imported or used anywhere — __all__ can be stale, but when \
combined with is_exported=true, treat __all__ membership as meaningful public API intent.
- TypeScript: only re-exported from index.ts but never actually consumed downstream
- Go: only referenced in _test.go files with Test* prefix (test-only symbol)

Decision rules:
- COMMIT to a verdict. Use UNCERTAIN only if evidence genuinely conflicts.
- If you see a real code usage (call, import, dispatch), it is FALSE_POSITIVE — full stop.
- If ZERO real code usages exist, it is TRUE_POSITIVE — full stop.
- Read the file context around each match to distinguish real code from comments/docs.
- __all__ alone is NOT enough to call something alive — but __all__ combined with is_exported=true IS strong evidence for ALIVE.
- A generic docs mention is not enough, but an explicit compatibility-retention note is strong evidence for ALIVE.
- If public_api_docs results show the symbol documented in docs/ AND the symbol is public \
(no underscore) in an importable package, it is FALSE_POSITIVE — library public API.

IMPORTANT: Respond with ONLY JSON. No explanations, no preamble.
{"verdict": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"UNCERTAIN", "rationale": "brief explanation"}\
"""

SUPPRESSION_AUDIT_SYSTEM = """\
You are auditing a prior ALIVE (FALSE_POSITIVE) decision for code flagged as "unused".

Your job is to catch FALSE NEGATIVES: cases where the earlier verifier or suppressor \
incorrectly decided the symbol was alive and removed a real dead-code finding.

You will receive:
1. The flagged symbol's source code and graph context
2. Search results and file context around matches
3. The prior FALSE_POSITIVE rationale and any suppression evidence

Decision standard:
- Return TRUE_POSITIVE if the prior "alive" story is weak, speculative, or unsupported by \
concrete runtime usage.
- Return FALSE_POSITIVE only if the evidence shows a real, defensible usage that keeps the \
symbol alive.
- Return UNCERTAIN only if the evidence genuinely conflicts.

Evidence that is NOT enough to keep something alive:
- Comments, docstrings, or plain string mentions
- Vague "might be dynamic" claims without a concrete dispatch/registration path
- Generic test mentions that do not execute or import the symbol
- File/module mentions without evidence the symbol is actually the runtime entry surface
- __all__ exports without real imports or usage

Evidence that IS enough to keep something alive:
- A public symbol (no underscore prefix) documented in docs/ (rst, md, autodoc) in an \
importable package — this is library public API for downstream consumers, even if unused internally

IMPORTANT: Respond with ONLY JSON. No explanations, no preamble.
{"verdict": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"UNCERTAIN", "rationale": "brief explanation"}\
"""


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
    except Exception:
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
    if pip_name in _pip_install_cache:
        return _pip_install_cache[pip_name]
    import subprocess as _sp
    import tempfile

    td = tempfile.mkdtemp(prefix=f"skylos_dep_{pip_name}_")
    _pip_temp_dirs.append(td)
    try:
        result = _sp.run(
            ["pip3", "install", "--target", td, pip_name],
            capture_output=True,
            timeout=60,
        )
        if result.returncode == 0:
            _pip_install_cache[pip_name] = td
            return td
    except Exception:
        pass
    _pip_install_cache[pip_name] = None
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
            f"\n  Check if the parent framework/library defines this method externally."
        )

    return info


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

    class_pattern = re.compile(rf"class\s+{re.escape(class_name)}\s*\(([^)]+)\)")
    match = class_pattern.search(source)
    if not match:
        return None

    bases = [b.strip() for b in match.group(1).split(",")]
    info = f"Class `{class_name}` inherits from: {', '.join(bases)}."

    if project_root:
        found_in_parent = False
        for base in bases:
            base_name = base.split(".")[-1].strip()
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
            import subprocess as _sp

            for base in bases:
                base_name = base.split(".")[-1].strip()
                if base_name in ("object", "ABC", "Protocol"):
                    continue
                import_match = re.search(
                    rf"from\s+([\w.]+)\s+import\s+\([^)]*\b{re.escape(base_name)}\b[^)]*\)",
                    source,
                    re.DOTALL,
                ) or re.search(
                    rf"from\s+([\w.]+)\s+import\s+[^(\n]*\b{re.escape(base_name)}\b",
                    source,
                )
                if import_match:
                    module_path = import_match.group(1)
                    try:
                        python_cmd = "python3"
                        _root = Path(project_root)
                        _candidates = [
                            _root / ".venv" / "bin" / "python3",
                            _root / "venv" / "bin" / "python3",
                            _root / ".tox" / "dev" / "bin" / "python3",
                            _root / ".tox" / "py" / "bin" / "python3",
                            _root / ".nox" / "default" / "bin" / "python3",
                        ]
                        tox_dir = _root / ".tox"
                        if tox_dir.is_dir():
                            for sub in tox_dir.iterdir():
                                if sub.is_dir():
                                    p = sub / "bin" / "python3"
                                    if p not in _candidates:
                                        _candidates.append(p)
                        for _cand in _candidates:
                            if _cand.exists():
                                python_cmd = str(_cand)
                                break

                        result = _sp.run(
                            [
                                python_cmd,
                                "-c",
                                f"import {module_path}; import inspect; "
                                f"cls = getattr({module_path}, '{base_name}', None); "
                                f"print('HAS_METHOD' if cls and hasattr(cls, '{simple_name}') else 'NO_METHOD')",
                            ],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            cwd=project_root,
                        )
                        if "HAS_METHOD" in result.stdout:
                            info += f"\n  CONFIRMED (via importlib): Parent `{module_path}.{base_name}` defines `{simple_name}`"
                            found_in_parent = True
                            break
                    except Exception:
                        pass

            if not found_in_parent:
                _root = Path(project_root)
                _bases_to_check = []
                for base in bases:
                    base_name = base.split(".")[-1].strip()
                    if base_name in ("object", "ABC", "Protocol"):
                        continue
                    import_match = re.search(
                        rf"from\s+([\w.]+)\s+import\s+\([^)]*\b{re.escape(base_name)}\b[^)]*\)",
                        source,
                        re.DOTALL,
                    ) or re.search(
                        rf"from\s+([\w.]+)\s+import\s+[^(\n]*\b{re.escape(base_name)}\b",
                        source,
                    )
                    if import_match:
                        _bases_to_check.append((base_name, import_match.group(1)))

                if _bases_to_check:
                    _project_deps: list[str] = []
                    _pyproject = _root / "pyproject.toml"
                    if _pyproject.exists():
                        try:
                            import tomllib

                            with open(_pyproject, "rb") as _f:
                                _toml = tomllib.load(_f)
                            _project_deps = _toml.get("project", {}).get(
                                "dependencies", []
                            )
                        except Exception:
                            pass
                    if not _project_deps:
                        _req_file = _root / "requirements.txt"
                        if _req_file.exists():
                            try:
                                _project_deps = [
                                    line.strip()
                                    for line in _req_file.read_text().splitlines()
                                    if line.strip() and not line.startswith("#")
                                ]
                            except Exception:
                                pass

                    for base_name, module_path in _bases_to_check:
                        if found_in_parent:
                            break
                        top_module = module_path.split(".")[0]
                        pip_name = top_module.replace("_", "-")
                        dep_match = any(
                            pip_name.lower()
                            in dep.lower()
                            .split("[")[0]
                            .split(">")[0]
                            .split("<")[0]
                            .split("=")[0]
                            .split("!")[0]
                            .strip()
                            for dep in _project_deps
                        )
                        if not dep_match:
                            continue
                        try:
                            _td = _pip_install_to_temp(pip_name)
                            if not _td:
                                continue
                            _check = _sp.run(
                                [
                                    "python3",
                                    "-c",
                                    f"import sys; sys.path.insert(0, '{_td}'); "
                                    f"import {module_path}; "
                                    f"cls = getattr({module_path}, '{base_name}', None); "
                                    f"print('HAS_METHOD' if cls and hasattr(cls, '{simple_name}') else 'NO_METHOD')",
                                ],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            if "HAS_METHOD" in _check.stdout:
                                info += f"\n  CONFIRMED (pip install): Parent `{module_path}.{base_name}` defines `{simple_name}`"
                                found_in_parent = True
                                break
                        except Exception:
                            pass

            if not found_in_parent:
                import sys

                for site_dir in sys.path:
                    if "site-packages" not in site_dir:
                        continue
                    for base in bases:
                        base_name = base.split(".")[-1].strip()
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
                    info += f"\n  HINT: Code comments/pragmas suggest this is an ABC/interface override."
                    info += f"\n  Method `{simple_name}` is likely a required override — treat as NOT dead code."
                else:
                    info += f"\n  Method `{simple_name}` has parent classes but could not confirm it overrides a parent method."
                    info += f"\n  Check if the parent framework/library defines this method externally."
            else:
                info += f"\n  Method `{simple_name}` has parent classes but could not confirm it overrides a parent method."
                info += f"\n  Check if the parent framework/library defines this method externally."

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
        except Exception:
            pass

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
            dynamic_fragment = _match_dynamic_dispatch_name(
                simple_name, prefix, suffix
            )
            if not dynamic_fragment:
                continue

            for generator in comp.generators:
                if not (
                    isinstance(generator.target, ast.Name)
                    and generator.target.id == dynamic_name
                ):
                    continue
                literal_values = _literal_string_values(generator.iter)
                if (
                    dynamic_fragment in literal_values
                    and _map_used_later(map_name, getattr(assign, "lineno", 0))
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
            dynamic_fragment = _match_dynamic_dispatch_name(
                simple_name, prefix, suffix
            )
            if not dynamic_fragment:
                continue
            if not _dispatcher_alive(func.name):
                continue
            line_no = getattr(child, "lineno", getattr(func, "lineno", 0))
            return [
                f"{file_path}:{line_no}: `{func.name}` resolves `{simple_name}` via getattr(..., f\"{prefix}{{...}}{suffix}\")"
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
        and (
            not search_results
            or set(search_results).issubset(compact_search_keys)
        )
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
                parts.append(f"  (not found in defs_map)")
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


BATCH_VERIFY_SYSTEM = """\
You are verifying if multiple code symbols flagged as "unused" are actually dead or alive.

Each symbol includes: source code, call graph, inheritance info, and multi-strategy \
search results with file context. Definition-only matches have been pre-filtered — \
all grep results shown are USAGES, not the definition itself.

Your job: READ the evidence for each symbol and REASON about whether each match is a real usage.

What counts as ALIVE (FALSE_POSITIVE):
- Called somewhere: .name() pattern in actual code (not just in the definition file)
- Imported and used in another file
- Overrides a confirmed parent class method (look for CONFIRMED in inheritance context)
- Used in cast() or bound in TypeVar
- Referenced by a Sphinx directive (:func:, autofunction) — documented public API
- Used via dynamic dispatch: getattr(obj, "name"), dict["name"], .do("name")
- Conditional import inside try/except ImportError — the symbol IS used in the guarded code path
- File or module path is referenced by a loader/CLI/config entry and the symbol is the runtime entry surface
- Explicit changelog/docs note that a symbol was reintroduced, restored, or kept as an alias/synonym for compatibility counts as ALIVE when the symbol remains a top-level API/type alias surface
- A pytest-collected test class/function is alive even without direct imports or calls
- A hook function registered in repo config (e.g. mkdocs hooks) is alive
- A class definition inside pytest.raises()/assertRaises() is executed for its side effect
- Parameters required by a callback/hook signature or by an interface/base-method signature are ALIVE even if unused inside the body
- Method on a class that substitutes/replaces a standard object (e.g. assigned to sys.stdout, \
used as a file-like object, wraps a socket) — standard protocol methods are called by the runtime
- Enum members (FOO, BAR) on a class inheriting from Enum/IntEnum — accessed via iteration, \
Choice(), or member lookup at runtime even without explicit references
- A public symbol (no underscore prefix) in an importable package that is documented in the \
project's docs/ directory (rst, md, or autodoc) is ALIVE — it exists for downstream consumers \
even if unused internally. Look for the public_api_docs search results.
- A symbol marked as exported (is_exported=true) is part of the package's public API. \
It exists for downstream consumers. Unless you find strong evidence it's truly orphaned \
(e.g., the entire module is dead), treat it as ALIVE.

What counts as DEAD (TRUE_POSITIVE):
- ZERO references anywhere in the project (only the definition itself found)
- Only referenced in docstrings, comments, or string descriptions — these are NOT usages
- Keyword argument values are NOT usages: fg="green" does NOT mean a variable named \
green is used
- TypeVar definitions like T = TypeVar("T") are NOT usages of T
- A class docstring mentioning a name is NOT a usage of that name
- Listed in __all__ but NOT imported or used anywhere — __all__ can be stale, but when \
combined with is_exported=true, treat __all__ membership as meaningful public API intent.

Decision rules:
- COMMIT to a verdict. Use UNCERTAIN only if evidence genuinely conflicts.
- If you see a real code usage (call, import, dispatch), it is FALSE_POSITIVE — full stop.
- If ZERO real code usages exist, it is TRUE_POSITIVE — full stop.
- Read the file context around each match to distinguish real code from comments/docs.
- __all__ alone is NOT enough to call something alive — but __all__ combined with is_exported=true IS strong evidence for ALIVE.
- A generic docs mention is not enough, but an explicit compatibility-retention note is strong evidence for ALIVE.
- If public_api_docs results show the symbol documented in docs/ AND the symbol is public \
(no underscore) in an importable package, it is FALSE_POSITIVE — library public API.

IMPORTANT: You MUST respond with ONLY a JSON array. No explanations, no preamble.
[{"id": 1, "verdict": "TRUE_POSITIVE", "rationale": "..."}, {"id": 2, "verdict": "FALSE_POSITIVE", "rationale": "..."}]
"""

BATCH_SURVIVOR_SYSTEM = """\
You are checking if multiple functions are INCORRECTLY marked as alive by static \
analysis due to "heuristic attribute matches" (e.g. `obj.foo()` matching any \
function named `foo`).

For EACH function, determine if the heuristic matches are:
- REAL: the attribute access actually calls this specific function
- SPURIOUS: a different class/object has a method with the same name
- UNCERTAIN: cannot determine

IMPORTANT: You MUST respond with ONLY a JSON array. No explanations, no preamble, no markdown.
Output ONLY this format, nothing else:
[{"id": 1, "is_dead": true, "rationale": "...", "heuristic_assessment": "spurious"}, ...]
"""

MAX_BATCH_CONTEXT_CHARS = 50_000

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
            and any(marker in str(verdict.get("rationale", "")) for marker in failure_markers)
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


def _batch_challenge_survivors(
    agent: DeadCodeVerifierAgent,
    survivors: list[dict],
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
) -> list[SurvivorVerdict]:
    results = []
    batch = []
    batch_contexts = []
    batch_size = 0

    def _flush_batch():
        nonlocal batch, batch_contexts, batch_size
        if not batch:
            return

        combined = "\n\n---\n\n".join(
            f"### Function {i + 1}: `{s.get('full_name', s.get('name'))}`\n{ctx}"
            for i, (s, ctx) in enumerate(zip(batch, batch_contexts))
        )
        user_prompt = (
            f"{combined}\n\nAssess all {len(batch)} functions above. "
            f"Are their heuristic matches real or spurious? JSON array response:"
        )

        verdicts = _parse_batch_survivor_response(
            agent, BATCH_SURVIVOR_SYSTEM, user_prompt, len(batch)
        )

        for surv, v_data in zip(batch, verdicts):
            name = surv.get("name", "unknown")
            full_name = surv.get("full_name", name)
            confidence = surv.get("confidence", 0)
            is_dead = v_data.get("is_dead", False)
            rationale = v_data.get("rationale", "")
            assessment = v_data.get("heuristic_assessment", "uncertain")

            if is_dead:
                verdict = Verdict.TRUE_POSITIVE
                suggested = min(95, confidence + 30)
            elif assessment == "real":
                verdict = Verdict.FALSE_POSITIVE
                suggested = max(20, confidence - 20)
            else:
                verdict = Verdict.UNCERTAIN
                suggested = confidence

            results.append(
                SurvivorVerdict(
                    name=name,
                    full_name=full_name,
                    file=surv.get("file", ""),
                    line=surv.get("line", 0),
                    heuristic_refs=surv.get("heuristic_refs", {}),
                    verdict=verdict,
                    rationale=rationale,
                    original_confidence=confidence,
                    suggested_confidence=suggested,
                )
            )

        batch = []
        batch_contexts = []
        batch_size = 0

    for surv in survivors:
        simple_name = surv.get("simple_name", surv.get("name", "").split(".")[-1])
        full_name = surv.get("full_name", surv.get("name", ""))
        file_path = surv.get("file", "")
        line = surv.get("line", 0)
        heuristic_refs = surv.get("heuristic_refs", {})

        source = source_cache.get(file_path, "")
        if source:
            slines = source.splitlines()
            start = max(0, line - 6)
            end = min(len(slines), line + 20)
            snippet = "\n".join(f"{i + 1:4d} | {slines[i]}" for i in range(start, end))
        else:
            snippet = "(source not available)"

        match_sites = _find_heuristic_match_sites(
            full_name, simple_name, source_cache, defs_map
        )

        ctx = (
            f"- File: `{file_path}:{line}`\n"
            f"- Heuristic refs: {json.dumps(heuristic_refs)}\n"
            f"- Confidence: {surv.get('confidence', 0)}\n\n"
            f"Source:\n{snippet}\n\n"
            f"Match sites:\n{match_sites}"
        )
        ctx_len = len(ctx)

        if batch and (
            batch_size + ctx_len > MAX_BATCH_CONTEXT_CHARS or len(batch) >= 5
        ):
            _flush_batch()

        batch.append(surv)
        batch_contexts.append(ctx)
        batch_size += ctx_len

    _flush_batch()
    return results


def _is_error_response(response: str) -> bool:
    if response:
        lower = response.lower()
    else:
        lower = ""
    return any(
        marker in lower
        for marker in [
            "error:",
            "ratelimiterror",
            "rate_limit_error",
            "ratelimit",
            "unauthorized",
            "quota",
            "exceeded",
            "apiconnectionerror",
            "anthropicexception",
            "openaiexception",
            "no api key found",
            "set openai_api_key",
            "set anthropic_api_key",
            "timed out",
            "timeout",
        ]
    )


def _call_llm_with_retry(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
) -> str:
    for attempt in range(MAX_LLM_RETRIES):
        response = agent._call_llm(system, user)
        if not _is_error_response(response):
            return response
        if "rate_limit" in response.lower() or "ratelimit" in response.lower():
            wait = RETRY_BACKOFF_BASE * (2**attempt)
            logger.info(
                f"Rate limited, retrying in {wait}s (attempt {attempt + 1}/{MAX_LLM_RETRIES})"
            )
            time.sleep(wait)
        else:
            logger.warning(f"LLM returned error: {response[:200]}")
            return ""
    logger.warning(f"LLM rate limited after {MAX_LLM_RETRIES} retries")
    return ""


def _parse_batch_response(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
    expected_count: int,
) -> list[dict]:
    try:
        response = _call_llm_with_retry(agent, system, user)
        if not response:
            return [
                {"verdict": Verdict.UNCERTAIN, "rationale": "LLM call failed"}
            ] * expected_count

        logger.debug(f"Raw LLM response ({len(response)} chars): {response[:300]}")
        clean = _strip_markdown_fences(response)
        logger.debug(f"After strip_markdown_fences ({len(clean)} chars): {clean[:300]}")
        data = json.loads(clean)

        if isinstance(data, list):
            verdicts = []
            for i in range(expected_count):
                if i < len(data):
                    item = data[i]
                    verdict_str = item.get("verdict", "UNCERTAIN")
                    try:
                        verdict = Verdict(verdict_str)
                    except (ValueError, KeyError):
                        verdict = Verdict.UNCERTAIN
                    verdicts.append(
                        {
                            "verdict": verdict,
                            "rationale": item.get("rationale", ""),
                        }
                    )
                else:
                    verdicts.append(
                        {
                            "verdict": Verdict.UNCERTAIN,
                            "rationale": "Missing from batch response",
                        }
                    )
            return verdicts

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Batch verification parse failed: {e}")

    return [
        {"verdict": Verdict.UNCERTAIN, "rationale": "Batch parse failed"}
    ] * expected_count


def _parse_batch_survivor_response(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
    expected_count: int,
) -> list[dict]:
    try:
        response = _call_llm_with_retry(agent, system, user)
        if not response:
            return [
                {
                    "is_dead": False,
                    "rationale": "LLM call failed",
                    "heuristic_assessment": "uncertain",
                }
            ] * expected_count

        clean = _strip_markdown_fences(response)
        data = json.loads(clean)

        if isinstance(data, list):
            results = []
            for i in range(expected_count):
                if i < len(data):
                    results.append(data[i])
                else:
                    results.append(
                        {
                            "is_dead": False,
                            "rationale": "Missing",
                            "heuristic_assessment": "uncertain",
                        }
                    )
            return results

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Batch survivor parse failed: {e}")

    return [
        {
            "is_dead": False,
            "rationale": "Batch parse failed",
            "heuristic_assessment": "uncertain",
        }
    ] * expected_count


def _strip_markdown_fences(text: str) -> str:
    import re

    clean = text.strip()

    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1]
    if clean.endswith("```"):
        clean = clean.rsplit("```", 1)[0]
    clean = clean.strip()

    if clean and clean[0] in "[{":
        return clean

    match = re.search(r"\[[\s\S]*\]", clean)
    if match:
        return match.group(0)

    match = re.search(r"\{[\s\S]*\}", clean)
    if match:
        return match.group(0)

    return clean


SURVIVOR_SYSTEM = """\
You are checking if a function is INCORRECTLY marked as alive by static analysis.

The static analyzer gave this function a passing score because of "heuristic \
attribute matches" — meaning somewhere in the codebase, code like `obj.{name}()` \
was found, and the analyzer assumed it MIGHT call this function.

Your job: determine if those heuristic matches are REAL calls or SPURIOUS noise.

SPURIOUS example: `logger.info()` matches any function named `info` in the project.
REAL example: `self.handler.process()` where self.handler is an instance of HandlerClass.

Respond with JSON:
{{"is_dead": true/false, "rationale": "explanation", "heuristic_assessment": "real"|"spurious"|"uncertain"}}\
"""

SURVIVOR_USER = """\
- File: `{file}`
- Line: {line}
- Type: {kind}
- Static confidence: {confidence} (low = likely alive, high = likely dead)
- Heuristic refs that kept it alive: {heuristic_refs}

{source_snippet}

These are the attribute access sites that matched this function's name:
{match_sites}

Are the heuristic attribute matches REAL calls to this specific function, or \
SPURIOUS matches (e.g. a different class has a method with the same name)?

JSON response:\
"""


def _find_heuristic_match_sites(
    name: str,
    simple_name: str,
    source_cache: dict[str, str],
    defs_map: dict[str, Any],
) -> str:
    sites = []
    search_attr = f".{simple_name}"

    for file_path, source in source_cache.items():
        lines = source.splitlines()
        for i, line_text in enumerate(lines):
            if search_attr in line_text and "def " not in line_text:
                sites.append(f"  {file_path}:{i + 1} | {line_text.strip()}")
                if len(sites) >= 15:
                    break
        if len(sites) >= 15:
            break

    if sites:
        return "\n".join(sites)
    else:
        return "  (no match sites found)"


def challenge_survivor(
    agent: DeadCodeVerifierAgent,
    defn_info: dict,
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
) -> SurvivorVerdict:
    name = defn_info.get("name", "unknown")
    full_name = defn_info.get("full_name", name)
    simple_name = defn_info.get("simple_name", name.split(".")[-1])
    file_path = defn_info.get("file", "")
    line = defn_info.get("line", 0)
    kind = defn_info.get("type", "function")
    confidence = defn_info.get("confidence", 0)
    heuristic_refs = defn_info.get("heuristic_refs", {})

    source = source_cache.get(file_path, "")
    if source:
        source_lines = source.splitlines()
        start = max(0, line - 6)
        end = min(len(source_lines), line + 20)
        snippet = "\n".join(
            f"{i + 1:4d} | {source_lines[i]}" for i in range(start, end)
        )
    else:
        snippet = "(source not available)"

    match_sites = _find_heuristic_match_sites(
        full_name, simple_name, source_cache, defs_map
    )

    user = SURVIVOR_USER.format(
        full_name=full_name,
        file=file_path,
        line=line,
        kind=kind,
        confidence=confidence,
        heuristic_refs=json.dumps(heuristic_refs),
        source_snippet=snippet,
        match_sites=match_sites,
    )

    try:
        response = _call_llm_with_retry(agent, SURVIVOR_SYSTEM, user)
        if not response:
            raise ValueError("LLM call failed")
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        is_dead = data.get("is_dead", False)
        rationale = data.get("rationale", "")
        assessment = data.get("heuristic_assessment", "uncertain")

        if is_dead:
            verdict = Verdict.TRUE_POSITIVE
            suggested = min(95, confidence + 30)
        elif assessment == "real":
            verdict = Verdict.FALSE_POSITIVE
            suggested = max(20, confidence - 20)
        else:
            verdict = Verdict.UNCERTAIN
            suggested = confidence

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Survivor challenge failed for {name}: {e}")
        verdict = Verdict.UNCERTAIN
        rationale = f"LLM call failed: {e}"
        suggested = confidence

    return SurvivorVerdict(
        name=name,
        full_name=full_name,
        file=file_path,
        line=line,
        heuristic_refs=heuristic_refs,
        verdict=verdict,
        rationale=rationale,
        original_confidence=confidence,
        suggested_confidence=suggested,
    )


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
        except Exception:
            pass

    return cache


HAIKU_PREFILTER_SYSTEM = """\
You are a quick pre-filter for dead code analysis. For each symbol below, determine if it is \
a public API method meant to be called by external users of this package.

Answer YES if the symbol is clearly part of the public API (public method on a public class, \
exported in __init__.py or __all__, documented for external use).
Answer NO if the symbol appears to be internal implementation detail, private, or orphaned.

IMPORTANT: Respond with ONLY a JSON array. No explanations, no preamble.
[{"id": 1, "public_api": "YES", "reason": "brief reason"}, ...]
"""

HAIKU_PREFILTER_MAX_BATCH = 20


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
) -> dict[str, Any]:
    from skylos.llm.agents import AgentConfig

    from skylos.grep_cache import GrepCache

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

    discovered_eps = []
    if enable_entry_discovery:
        log("Pass 1: Discovering hidden entry points...")
        known_eps = []
        for name, info in defs_map.items():
            if isinstance(info, dict) and info.get("type") in ("function", "method"):
                known_eps.append(name)

        discovered_eps = discover_entry_points(agent, config_root, known_eps[:100])
        stats.entry_points_discovered = len(discovered_eps)
        stats.llm_calls += 1

        if discovered_eps:
            log(f"  Found {len(discovered_eps)} new entry points:")
            for ep in discovered_eps:
                log(f"    - {ep.name} (from {ep.source})")
        else:
            log("  No new entry points found.")

    lo, hi = confidence_range
    to_verify = []
    for f in findings:
        conf = _parse_confidence(f.get("confidence", 60))
        refs = _parse_int(f.get("references", 0))
        should_judge = refs == 0 and (judge_all_mode or lo <= conf <= hi)
        if should_judge:
            full_name = f.get("full_name", f.get("name", ""))
            matched_ep = next(
                (ep for ep in discovered_eps if ep.name == full_name), None
            )
            if matched_ep is not None:
                if judge_all_mode:
                    f["_judge_discovered_entry_point"] = (
                        f"{matched_ep.source}: {matched_ep.reason}"
                    )
                    _record_prefilter_fact(
                        f,
                        code="discovered_entry_point",
                        rationale="Project configuration references this symbol as an entry point",
                        evidence=[
                            f"source={matched_ep.source}",
                            f"reason={matched_ep.reason}",
                        ],
                    )
                    to_verify.append(f)
                else:
                    f["_llm_verdict"] = Verdict.FALSE_POSITIVE.value
                    f["_llm_rationale"] = "Discovered as entry point in project config"
                    f["_verified_by_llm"] = True
                    f["_adjusted_confidence"] = 20
                    stats.verified_false_positive += 1
            else:
                decision = _deterministic_suppress(
                    f,
                    source_cache,
                    project_root=grep_root,
                    repo_facts=repo_facts,
                    defs_map=defs_map,
                    grep_cache=grep_cache,
                )
                if decision is not None:
                    if judge_all_mode and not decision.hard:
                        _record_prefilter_fact(
                            f,
                            code=decision.code,
                            rationale=decision.rationale,
                            evidence=decision.evidence,
                        )
                        to_verify.append(f)
                    else:
                        f["_llm_verdict"] = Verdict.FALSE_POSITIVE.value
                        f["_llm_rationale"] = decision.rationale
                        f["_suppression_reason"] = decision.code
                        f["_suppression_evidence"] = list(decision.evidence)
                        f["_suppression_hard"] = bool(decision.hard)
                        f["_deterministically_suppressed"] = True
                        f["_verified_by_llm"] = False
                        f["_adjusted_confidence"] = 20
                        stats.deterministic_suppressed += 1
                else:
                    to_verify.append(f)
        else:
            if refs > 0:
                f["_llm_verdict"] = "SKIPPED_HAS_REFS"
                f["_llm_rationale"] = f"Has {refs} references"
            elif conf > hi:
                f["_llm_verdict"] = "SKIPPED_HIGH_CONF"
                f["_llm_rationale"] = "High confidence from static; skipped LLM"
            else:
                f["_llm_verdict"] = "SKIPPED_LOW_CONF"
                f["_llm_rationale"] = "Below threshold"

    to_verify = to_verify[:max_verify]

    if to_verify:
        haiku_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY")

        exported_candidates = [
            f
            for f in to_verify
            if f.get("is_exported") and _parse_confidence(f.get("confidence", 0)) >= 80
        ]
        if exported_candidates and haiku_key:
            log(
                f"Pass 1.5: Haiku pre-filter for {len(exported_candidates)} exported symbols..."
            )
            try:
                haiku_agent = _create_haiku_agent(haiku_key)
                kept, dismissed = _haiku_prefilter_exports(
                    haiku_agent,
                    exported_candidates,
                    source_cache,
                )
                stats.haiku_prefiltered = len(dismissed)
                stats.verified_false_positive += len(dismissed)
                stats.llm_calls += max(
                    1,
                    (len(exported_candidates) + HAIKU_PREFILTER_MAX_BATCH - 1)
                    // HAIKU_PREFILTER_MAX_BATCH,
                )
                dismissed_set = {id(f) for f in dismissed}
                to_verify = [f for f in to_verify if id(f) not in dismissed_set]
                if dismissed:
                    log(
                        f"  Haiku dismissed {len(dismissed)} exported symbols as public API"
                    )
            except Exception as e:
                logger.warning(f"Haiku pre-filter setup failed: {e}")

    if batch_mode and len(to_verify) > 1:
        log(
            f"Pass 2: Batch-verifying {len(to_verify)} findings "
            f"({_estimate_batches(to_verify, defs_map, source_cache, repo_facts=repo_facts)} LLM calls)..."
        )
        batch_results = _batch_verify_findings(
            agent,
            to_verify,
            defs_map,
            source_cache,
            project_root=grep_root,
            repo_facts=repo_facts,
        )
        stats.llm_calls += max(
            1,
            (
                len(
                    [
                        r
                        for r in batch_results
                        if r.rationale
                        != f"Has {_parse_int(r.finding.get('references', 0))} references; skipped"
                    ]
                )
                + 4
            )
            // 5,
        )

        for finding, result in zip(to_verify, batch_results):
            finding["_llm_verdict"] = result.verdict.value
            finding["_llm_rationale"] = result.rationale
            finding["_verified_by_llm"] = result.verdict != Verdict.UNCERTAIN
            finding["_original_confidence"] = result.original_confidence
            finding["_adjusted_confidence"] = result.adjusted_confidence

            if result.verdict == Verdict.TRUE_POSITIVE:
                stats.verified_true_positive += 1
            elif result.verdict == Verdict.FALSE_POSITIVE:
                stats.verified_false_positive += 1
                finding["_llm_challenged"] = True
            else:
                stats.uncertain += 1

        reverify_candidates = []
        for finding in to_verify:
            if finding.get("_llm_verdict") != "TRUE_POSITIVE":
                continue
            ctx = _build_graph_context(
                finding,
                defs_map,
                source_cache,
                project_root=grep_root,
                repo_facts=repo_facts,
                grep_cache=grep_cache,
            )
            has_rich_context = (
                "class_usage" in ctx.lower()
                or "Inheritance Context" in ctx
                or "CONFIRMED" in ctx
                or "cast(" in ctx
                or "pragma: no cover" in ctx
                or "Collectible pytest test class: yes" in ctx
                or "MkDocs hook registration: yes" in ctx
                or "Definition side effect: yes" in ctx
                or "Repo-relative file path references" in ctx
            )
            if has_rich_context:
                reverify_candidates.append(finding)

        if reverify_candidates:
            log(
                f"  Re-verifying {len(reverify_candidates)} batch TPs with rich evidence (individual mode)..."
            )
            for finding in reverify_candidates:
                result = verify_with_graph_context(
                    agent,
                    finding,
                    defs_map,
                    source_cache,
                    project_root=grep_root,
                    repo_facts=repo_facts,
                )
                stats.llm_calls += 1
                if result.verdict != Verdict.TRUE_POSITIVE:
                    old_verdict = finding["_llm_verdict"]
                    finding["_llm_verdict"] = result.verdict.value
                    finding["_llm_rationale"] = f"[re-verified] {result.rationale}"
                    finding["_verified_by_llm"] = result.verdict != Verdict.UNCERTAIN
                    finding["_adjusted_confidence"] = result.adjusted_confidence
                    if result.verdict == Verdict.FALSE_POSITIVE:
                        stats.verified_true_positive -= 1
                        stats.verified_false_positive += 1
                        finding["_llm_challenged"] = True
                        log(f"    Flipped: {finding.get('full_name', '')} TP → FP")
                    elif result.verdict == Verdict.UNCERTAIN:
                        stats.verified_true_positive -= 1
                        stats.uncertain += 1
    else:
        log(f"Pass 2: Verifying {len(to_verify)} findings with graph context...")
        for i, finding in enumerate(to_verify):
            result = verify_with_graph_context(
                agent,
                finding,
                defs_map,
                source_cache,
                project_root=grep_root,
                repo_facts=repo_facts,
            )
            stats.llm_calls += 1

            finding["_llm_verdict"] = result.verdict.value
            finding["_llm_rationale"] = result.rationale
            finding["_verified_by_llm"] = result.verdict != Verdict.UNCERTAIN
            finding["_original_confidence"] = result.original_confidence
            finding["_adjusted_confidence"] = result.adjusted_confidence

            if result.verdict == Verdict.TRUE_POSITIVE:
                stats.verified_true_positive += 1
            elif result.verdict == Verdict.FALSE_POSITIVE:
                stats.verified_false_positive += 1
                finding["_llm_challenged"] = True
            else:
                stats.uncertain += 1

            if (i + 1) % 10 == 0:
                log(f"  Verified {i + 1}/{len(to_verify)}...")

    if enable_suppression_challenge:
        suppression_candidates = [
            finding for finding in findings if _should_audit_suppression(finding)
        ][:max_suppression_audit]
        stats.suppression_challenged = len(suppression_candidates)

        if suppression_candidates:
            log(
                "Pass 3: Auditing "
                f"{len(suppression_candidates)} FALSE_POSITIVE decisions for false negatives..."
            )
            for finding in suppression_candidates:
                result = audit_suppressed_finding(
                    agent,
                    finding,
                    defs_map,
                    source_cache,
                    project_root=grep_root,
                    repo_facts=repo_facts,
                )
                stats.llm_calls += 1
                finding["_suppression_audited"] = True
                finding["_suppression_audit_verdict"] = result.verdict.value
                finding["_suppression_audit_rationale"] = result.rationale

                if result.verdict == Verdict.TRUE_POSITIVE:
                    finding["_llm_verdict"] = Verdict.TRUE_POSITIVE.value
                    finding["_llm_rationale"] = (
                        f"[suppression-audit] {result.rationale}"
                    )
                    finding["_verified_by_llm"] = True
                    finding["_adjusted_confidence"] = result.adjusted_confidence
                    finding["_llm_challenged"] = True
                    finding["_suppression_reopened"] = True

                    if finding.get("_deterministically_suppressed"):
                        stats.deterministic_suppressed -= 1
                        finding["_deterministically_suppressed"] = False
                        if finding.get("_suppression_reason"):
                            finding["_suppression_overruled_reason"] = finding.get(
                                "_suppression_reason"
                            )
                            finding.pop("_suppression_reason", None)
                        if finding.get("_suppression_evidence"):
                            finding["_suppression_overruled_evidence"] = finding.get(
                                "_suppression_evidence"
                            )
                            finding.pop("_suppression_evidence", None)
                    else:
                        stats.verified_false_positive -= 1

                    stats.verified_true_positive += 1
                    stats.suppression_reclassified_dead += 1
                elif result.verdict == Verdict.FALSE_POSITIVE:
                    if finding.get("_deterministically_suppressed"):
                        finding["_verified_by_llm"] = True

    fp_names = set()
    tp_findings = []
    for f in findings:
        verdict = f.get("_llm_verdict", "")
        full_name = f.get("full_name", f.get("name", ""))
        if verdict == "FALSE_POSITIVE":
            fp_names.add(full_name)
        elif verdict == "TRUE_POSITIVE":
            tp_findings.append(f)

    propagated = 0
    for f in tp_findings:
        full_name = f.get("full_name", f.get("name", ""))
        called_by = f.get("called_by", [])
        calls = f.get("calls", [])

        alive_callers = [c for c in called_by if c in fp_names]
        if alive_callers:
            f["_llm_verdict"] = "FALSE_POSITIVE"
            f["_llm_rationale"] = (
                f"Transitive alive: called by {alive_callers[0]} which is confirmed alive (FALSE_POSITIVE). "
                f"Original rationale: {f.get('_llm_rationale', '')}"
            )
            f["_llm_challenged"] = True
            f["_adjusted_confidence"] = 50
            fp_names.add(full_name)
            stats.verified_true_positive -= 1
            stats.verified_false_positive += 1
            propagated += 1
            continue

        for callee in calls:
            if callee in fp_names:
                for other_f in findings:
                    if other_f.get("full_name", "") == callee:
                        if full_name in other_f.get("called_by", []):
                            f["_llm_verdict"] = "FALSE_POSITIVE"
                            f["_llm_rationale"] = (
                                f"Transitive alive: mutual dependency with {callee} which is alive. "
                                f"Original rationale: {f.get('_llm_rationale', '')}"
                            )
                            f["_llm_challenged"] = True
                            f["_adjusted_confidence"] = 50
                            fp_names.add(full_name)
                            stats.verified_true_positive -= 1
                            stats.verified_false_positive += 1
                            propagated += 1
                            break
                if f.get("_llm_verdict") == "FALSE_POSITIVE":
                    break

    if propagated:
        log(f"  Transitive alive propagation: {propagated} findings reclassified as FP")

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

    new_dead = []
    if enable_survivor_challenge:
        log("Pass 4: Challenging survivors with heuristic refs...")

        local_on_emit_survivors = _find_local_on_emit_survivors(
            defs_map,
            findings,
            grep_root,
        )
        if local_on_emit_survivors:
            stats.survivors_challenged += len(local_on_emit_survivors)
            stats.survivors_reclassified_dead += len(local_on_emit_survivors)
            for surv in local_on_emit_survivors:
                owner = surv.get("_registry_owner", "registry")
                event_name = surv.get("_event_name", "")
                new_dead.append(
                    {
                        "name": surv["name"],
                        "simple_name": surv["simple_name"],
                        "full_name": surv["full_name"],
                        "file": surv["file"],
                        "line": surv["line"],
                        "type": surv.get("type", "function"),
                        "confidence": min(
                            95, int(surv.get("confidence", 50) or 50) + 25
                        ),
                        "references": 0,
                        "message": f"Unused {surv.get('type', 'function')}: {surv['name']}",
                        "_category": "dead_code",
                        "_llm_verdict": "TRUE_POSITIVE",
                        "_llm_rationale": (
                            f"Registered via @{owner}.on('{event_name}') but no "
                            f"{owner}.emit('{event_name}') call exists in app/tests."
                        ),
                        "_source": "registry_survivor_challenge",
                    }
                )
            log(
                f"  Reclassified {len(local_on_emit_survivors)} local on/emit listeners as dead"
            )

        survivors = _find_survivors(defs_map, findings)
        survivors = survivors[:max_challenge]
        stats.survivors_challenged += len(survivors)

        if survivors:
            survivor_cache = _build_source_cache([], defs_map, survivors)
            source_cache.update(survivor_cache)

            if batch_mode and len(survivors) > 1:
                batch_results = _batch_challenge_survivors(
                    agent, survivors, defs_map, source_cache
                )
                stats.llm_calls += max(1, (len(survivors) + 4) // 5)

                for surv, sv in zip(survivors, batch_results):
                    if sv.verdict == Verdict.TRUE_POSITIVE:
                        stats.survivors_reclassified_dead += 1
                        new_dead.append(
                            {
                                "name": sv.name,
                                "full_name": sv.full_name,
                                "file": sv.file,
                                "line": sv.line,
                                "type": surv.get("type", "function"),
                                "confidence": sv.suggested_confidence,
                                "references": 0,
                                "heuristic_refs": sv.heuristic_refs,
                                "message": f"Unused {surv.get('type', 'function')}: {sv.name}",
                                "_category": "dead_code",
                                "_llm_verdict": "TRUE_POSITIVE",
                                "_llm_rationale": sv.rationale,
                                "_source": "llm_survivor_challenge",
                            }
                        )
            else:
                for surv in survivors:
                    sv = challenge_survivor(agent, surv, defs_map, source_cache)
                    stats.llm_calls += 1

                    if sv.verdict == Verdict.TRUE_POSITIVE:
                        stats.survivors_reclassified_dead += 1
                        new_dead.append(
                            {
                                "name": sv.name,
                                "full_name": sv.full_name,
                                "file": sv.file,
                                "line": sv.line,
                                "type": surv.get("type", "function"),
                                "confidence": sv.suggested_confidence,
                                "references": 0,
                                "heuristic_refs": sv.heuristic_refs,
                                "message": f"Unused {surv.get('type', 'function')}: {sv.name}",
                                "_category": "dead_code",
                                "_llm_verdict": "TRUE_POSITIVE",
                                "_llm_rationale": sv.rationale,
                                "_source": "llm_survivor_challenge",
                            }
                        )

            log(
                f"  Challenged {len(survivors)}, "
                f"reclassified {stats.survivors_reclassified_dead} as dead"
            )
        else:
            log("  No survivors with heuristic refs to challenge.")

    stats.elapsed_seconds = round(time.time() - start_time, 1)

    try:
        usage = getattr(agent.get_adapter(), "total_usage", {}) or {}
    except Exception:
        usage = {}
    stats.prompt_tokens = int(usage.get("prompt_tokens") or 0)
    stats.completion_tokens = int(usage.get("completion_tokens") or 0)
    stats.total_tokens = int(usage.get("total_tokens") or 0)

    log(f"\nDone in {stats.elapsed_seconds}s ({stats.llm_calls} LLM calls)")

    for f in findings:
        f.setdefault("_category", "dead_code")
        f.setdefault("rule_id", "SKY-DEAD")
        f.setdefault("type", "function")
        f.setdefault("full_name", f.get("name", "unknown"))
        f.setdefault("references", 0)
        f.setdefault("_source", "static")
        if not f.get("message"):
            f["message"] = (
                f"Unused {f.get('type', 'function')}: {f.get('name', 'unknown')}"
            )

    for f in new_dead:
        f.setdefault("_category", "dead_code")
        f.setdefault("rule_id", "SKY-DEAD-CHALLENGE")
        f.setdefault("type", "function")
        f.setdefault("full_name", f.get("name", "unknown"))
        f.setdefault("references", 0)
        f.setdefault("_source", "llm_survivor_challenge")
        if not f.get("message"):
            f["message"] = (
                f"Unused {f.get('type', 'function')}: {f.get('name', 'unknown')}"
            )

    output = {
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

    try:
        from .feedback import record_verification_results, get_feedback_summary

        feedback = record_verification_results(output)
        summary = get_feedback_summary()

        tuned_types = []
        for htype, info in summary.get("heuristic_types", {}).items():
            if info["observations"] >= 5:
                change = info["weight_change_pct"]
                if abs(change) > 5:
                    tuned_types.append(
                        f"{htype}: {info['default_weight']} → {info['tuned_weight']} ({change:+.0f}%)"
                    )

        if tuned_types:
            log("\nFeedback loop — heuristic weight adjustments:")
            for t in tuned_types:
                log(f"  {t}")

        output["feedback"] = summary
    except Exception as e:
        logger.debug(f"Feedback recording failed: {e}")

    grep_cache.save(grep_root)

    return output


def _find_survivors(
    defs_map: dict[str, Any],
    already_flagged: list[dict],
) -> list[dict]:
    flagged_names = set()
    for f in already_flagged:
        flagged_names.add(f.get("full_name", f.get("name", "")))

    survivors = []
    for name, info in defs_map.items():
        if not isinstance(info, dict):
            continue
        if name in flagged_names:
            continue
        if info.get("type") not in ("function", "method"):
            continue

        heuristic_refs = info.get("heuristic_refs", {})
        if not heuristic_refs:
            continue

        refs = info.get("references", 0)
        if refs > 3:
            continue

        total_heuristic = sum(
            v if isinstance(v, (int, float)) else 0 for v in heuristic_refs.values()
        )
        if total_heuristic > 0:
            survivors.append(
                {
                    "name": name.split(".")[-1],
                    "full_name": name,
                    "simple_name": name.split(".")[-1],
                    "file": str(info.get("file", "")),
                    "line": info.get("line", 0),
                    "type": info.get("type", "function"),
                    "confidence": info.get("confidence", 50),
                    "heuristic_refs": heuristic_refs,
                    "references": refs,
                }
            )

    survivors.sort(
        key=lambda s: sum(
            v if isinstance(v, (int, float)) else 0
            for v in s.get("heuristic_refs", {}).values()
        ),
        reverse=True,
    )

    return survivors


_LOCAL_ON_DECORATOR_RE = re.compile(
    r"""@(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\.on\(\s*(['"])(?P<event>[^'"]+)\2\s*\)"""
)


def _extract_local_on_listener_registration(
    file_path: str, line: int
) -> tuple[str, str] | None:
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    lines = source.splitlines()
    start = max(0, line - 6)
    end = max(0, line - 1)
    for idx in range(end - 1, start - 1, -1):
        text = lines[idx].strip()
        if not text:
            continue
        if not text.startswith("@"):
            break
        match = _LOCAL_ON_DECORATOR_RE.search(text)
        if match:
            return match.group("owner"), match.group("event")
    return None


def _supports_local_on_emit_registry(file_path: str, owner: str) -> bool:
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    if not re.search(rf"\bclass\s+{re.escape(owner)}\b", source):
        return False

    return bool(re.search(r"\bdef\s+emit\s*\(", source))


def _search_local_emit_sites(
    owner: str, event_name: str, project_root: str | Path
) -> list[str]:
    pattern = (
        re.escape(owner)
        + r"""\.emit\(\s*['"]"""
        + re.escape(event_name)
        + r"""['"]"""
    )
    matches: list[str] = []
    for subdir in ("app", "tests"):
        root = Path(project_root) / subdir
        if not root.exists():
            continue
        matches.extend(
            _run_grep(
                pattern,
                str(root),
                use_regex=True,
                include_globs=["*.py"],
                max_results=20,
            )
        )
    return matches[:20]


def _find_local_on_emit_survivors(
    defs_map: dict[str, Any],
    already_flagged: list[dict],
    project_root: str | Path,
) -> list[dict]:
    flagged_names = {f.get("full_name", f.get("name", "")) for f in already_flagged}
    survivors: list[dict] = []

    for name, info in defs_map.items():
        if not isinstance(info, dict):
            continue
        if name in flagged_names:
            continue
        if info.get("type") not in ("function", "method"):
            continue
        if info.get("called_by"):
            continue

        file_path = str(info.get("file", "") or "")
        line = int(info.get("line", 0) or 0)
        if not file_path or line <= 0:
            continue

        registration = _extract_local_on_listener_registration(file_path, line)
        if not registration:
            continue
        owner, event_name = registration

        if not _supports_local_on_emit_registry(file_path, owner):
            continue

        emit_sites = _search_local_emit_sites(owner, event_name, project_root)
        if emit_sites:
            continue

        survivors.append(
            {
                "name": name.split(".")[-1],
                "full_name": name,
                "simple_name": name.split(".")[-1],
                "file": file_path,
                "line": line,
                "type": info.get("type", "function"),
                "confidence": info.get("confidence", 50),
                "references": int(info.get("references", 0) or 0),
                "_registry_owner": owner,
                "_event_name": event_name,
            }
        )

    return survivors


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
