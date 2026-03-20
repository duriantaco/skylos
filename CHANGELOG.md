## Changelog

## [4.1.0] - 2026-03-20

### Added
- Security regression detection — SKY-L021 expanded to 13 categories: input validation, security headers, encryption, logging/audit, sanitization, permission checks. Findings include `control_type` field
- Web scanner — public scan page at `skylos.dev/scan`, paste a GitHub URL, get a vibe code risk score. No signup, rate-limited (10/IP/hr)
- MCP guardrails — `validate_code_change` (diff validation for regressions, dangerous patterns, secrets) and `get_security_context` (project security posture for agents)
- Community rules — `skylos rules install|list|remove|validate` for YAML rule packs from `duriantaco/skylos-rules` or any URL. Taint-flow pattern support in YAML rules
- AI provenance — `--provenance` flag annotates findings with AI authorship (cursor, copilot, claude, etc.). Per-agent and per-severity breakdowns
- TypeScript dead code detection — cross-file analysis with SKY-E003 (unused files with transitive propagation), SKY-E004 (unnecessary exports), wildcard re-export chain resolution, `.js`→`.ts` path resolution
- TypeScript export graph — aliased imports, default re-exports, namespace re-exports all tracked correctly
- Next.js security — SKY-D280 (missing auth in API routes), SKY-S102 (server secrets in `"use client"` files), SKY-D281 (SQL injection in `"use server"` actions)
- SKY-S102: Client-side secret exposure in `static/`, `public/`, `.next/`, `dist/`, `build/` paths
- D230 enhanced: catches `redirect(request.args.get("next", "/"))` with `urlparse`/`startswith` guard suppression
- SKY-Q306: Cognitive complexity (SonarQube S3776)
- SKY-L027 (duplicate strings), SKY-L028 (too many returns), SKY-L029 (boolean trap)
- Go quality rules (Q301, Q302, C303, C304) via tree-sitter-go
- `skylos[fast]` — optional Rust accelerator
- `skylos provenance` — detect AI-authored code in PRs
- Agent-aware quality gate (`[tool.skylos.gate.agent]`)
- `skylos agent watch`, `agent pre-commit`, `agent verify --fix --pr`
- Grep-based verification pass with parallel workers, GrepCache, CWE tagging + SARIF taxonomy

### Changed
- Agent CLI consolidated from 16 to 8 commands
- TS definitions use `filename:name` as dict key (prevents collisions)

### Fixed
- `Definition.to_dict()` now includes `is_exported` flag
- TS def key collisions and cross-file import resolution

## [4.0.0] - 2026-03-15

### Added
- `-a` / `--all` flag — enables `--danger`, `--secrets`, `--quality`, and `--sca` in one shot
- `addopts` config — set default CLI flags in `pyproject.toml` under `[tool.skylos]`
- LLM verification agent — `skylos agent verify <path>` with 3-pass dead code verification
- Batch LLM calls — up to 8 findings per call
- Confidence feedback loop — auto-tunes heuristic weights across runs (`~/.skylos/feedback.json`)
- MCP `verify_dead_code` tool
- `--verification-mode` flag — `judge_all` and `production` modes
- AI defense cloud dashboard — `skylos defend . --upload` sends results to Skylos Cloud
- `skylos cicd init --defend` and `skylos-defend` pre-commit hook
- Public API detection — documented API symbols suppressed without LLM calls

### Changed
- Dead-code verifier defaults to `judge_all` mode
- Deterministic suppressors attached as verifier evidence

### Fixed
- Quality Gate step runs with `if: always()`
- `--upload` on empty project prints "skipping upload"

## [3.5.10] - 2026-03-10

### Changed
- Breaking: Removed `skylos . --fix`, `skylos agent fix`, `skylos agent analyze --fix` — use `skylos agent remediate`

### Fixed
- `LiteLLMAdapter.complete()` forwards `response_format` to litellm
- `create_llm_adapter()` passes `base_url` from `AgentConfig`
- Attribute context matching bug, `_mark_refs()` O(n) fallback replaced with lookup
- Narrowed broad `except Exception` blocks to specific types
- Git subprocess calls now have timeouts

## [3.5.9] - 2026-03-10

### Fixed
- `skylos cicd init` no longer crashes with `TypeError` on `generate_workflow()`

## [3.5.8] - 2026-03-10

### Fixed
- SKY-D260: multiline HTML comment duplicates, overly broad patterns, fenced code block exclusion, homoglyph false positives, single-line string regex
- SKY-Q301: counts comprehension `for`/`if` and match case guards; threshold `>=10` → `>10`

## [3.5.7] - 2026-03-09

### Added
- `skylos cicd init --upload` for cloud dashboard workflows
- SKY-L016 (undefined config), SKY-L023 (phantom decorator), SKY-L024 (stale mock), SKY-L026 (unfinished generation)
- SKY-D260: AI supply chain security — multi-file prompt injection scanner
- Vibe confidence metadata (`vibe_category`, `ai_likelihood`)
- `--llm` flag for LLM-optimized reports

### Fixed
- SKY-C401 clone detection false positives reduced

## [3.5.6] - 2026-03-07

### Added
- `--diff [BASE_REF]` — line-level precision filtering using unified diff hunk headers
- Git blame attribution on findings
- Auto-upload for linked projects (`--no-upload` to skip)
- SKY-L010 (security TODOs), SKY-L011 (disabled security controls), SKY-L012 (phantom calls), SKY-L013 (insecure randomness), SKY-L014 (hardcoded credentials), SKY-L017 (error info disclosure), SKY-L020 (overly broad permissions)
- Dynamic signal tracking (`inspect.getmembers`, `dir()`)
- Expanded default exclude folders for Go, TypeScript, VCS, IDE

### Fixed
- `--exclude-folder` with trailing slashes and CWD-relative paths

### Changed
- Table output is now the default (TUI opt-in via `--tui`)
- MCP credit checks fail-open on network errors

## [3.5.5] - 2026-03-04

### Added
- Claude Code Security integration — `skylos ingest claude-security` CLI subcommand
- `skylos cicd init --claude-security` generates 3-job GitHub Actions workflow
- Blue "Claude Security" badges on dashboard

### Changed
- Credit deduction is format-aware (2 credits for Claude Security, 1 for native)

## [3.5.4] - 2026-03-03

### Added
- LLM-generated code-level fix suggestions with before/after snippets
- PR inline comments with fenced code blocks, collapsible `<details>` in summary
- Rule-based text suggestion fallback when LLM not used

### Fixed
- Phase 3 matching for findings without `rule_id`
- `_merge_llm_findings` passes through `vulnerable_code` and `fixed_code`

## [3.5.3] - 2026-03-03

### Added
- CVE reachability analysis via ca9 engine — proves whether vulnerable deps are actually reachable
- `skylos whoami` command

### Fixed
- `--json -o <file>` writes to file instead of only stdout
- CI/CD workflow: `agent review` uses `--format json`, auto-adds `ANTHROPIC_API_KEY`
- PR review inline comments: absolute vs relative path mismatch fixed

## [3.5.2] - 2026-03-01

### Added
- Go dead code detection

### Fixed
- `engines/__init__.py` missing

## [3.5.1] - 2026-02-28

### Added
- TypeScript analysis 6.7x faster via batched tree-sitter queries
- 11 new TypeScript security rules: SKY-D245 through SKY-D253, SKY-D270, SKY-D271, SKY-D510
- SKY-Q305 (duplicate condition), SKY-Q402 (await in loop), SKY-UC002 (unreachable code)
- Shannon entropy-based secret detection
- Smarter attribute resolution, `__init__.py` re-export tracking
- Expanded Django/DRF framework dictionaries
- Go language support

### Fixed
- TUI category list focusable again

## [3.4.3] - 2026-02-25

### Added
- Multi-path CLI support (`skylos app/ tests/`)
- `@abstractmethod` suppression, framework dictionaries for Starlette, Flask-RESTful, Tornado, Marshmallow, SQLAlchemy, Celery, Click

### Fixed
- Pattern tracker double-counting, `private_name` penalty 80→60

## [3.4.2] - 2026-02-22

### Added
- Next.js/React TypeScript dead code detection (convention exports, route handlers, hooks)
- Dynamic dispatch: `getattr(module, f"prefix_{var}")` and `globals()` f-string detection
- `__init_subclass__` registry pattern detection, indirect enum inheritance

### Fixed
- Pattern tracker regex compilation, inline f-string handling, enum method/class variable detection

## [3.4.1] - 2026-02-21

### Added
- BFS from entry points through import graph for false positive elimination
- `__getattr__` package handling, relative import resolution
- `skylos credits` command, MCP server auth + rate limiting + credit deduction

### Fixed
- `--trace --json` and `--pytest-fixtures --json` producing invalid JSON

## [3.4.0] - 2026-02-18

### Added
- TypeScript: interface, enum, and type alias dead code detection
- TUI language display and severity bar chart
- CI/CD visibility: `skylos badge` command, "30-second setup" in README
- CBO coupling (SKY-Q701) and LCOM cohesion (SKY-Q702)
- Architecture metrics: SKY-Q802 (distance from Main Sequence), SKY-Q803 (Zone of Pain/Uselessness), SKY-Q804 (Dependency Inversion violations)

### Fixed
- TypeScript class name capture, `regex.exec()` false positives, lifecycle method exclusion
- `export default function`, `export { name }`, `extends Base` tracking
- Callbacks, array storage, object shorthand, return values, spread, type annotations as references

### Changed
- TypeScript scanner uses `Query()` constructor instead of deprecated `TS_LANG.query()`

## [3.3.0] - 2026-02-13

### Added
- Remediation agent — `skylos agent remediate` with `--dry-run`, `--max-fixes`, `--auto-pr`, `--test-cmd`, `--severity`
- CI/CD integration — `skylos cicd init|gate|annotate|review`
- MCP server — `analyze`, `security_scan`, `quality_check`, `secrets_scan`, `remediate` tools
- SKY-D230 (open redirect), SKY-D231 (CORS), SKY-D232 (JWT), SKY-D233 (deserialization), SKY-D234 (mass assignment)
- Sanitizer framework for taint analysis (XSS, CMD, URL, PATH)
- TypeScript security: SKY-D503 through SKY-D507, SKY-D240 through SKY-D244
- SKY-L005 (unused exception var), SKY-L006 (inconsistent return), SKY-Q501 (god class)
- TypeScript quality: SKY-Q601 through SKY-Q604
- Go language support via pluggable engine architecture
- Secrets scanning expanded to `.env`, `.yaml`, `.json`, `.toml`, `.ini`, `.cfg`, `.ts`, `.tsx`, `.js`, `.go`

### Fixed
- `import json` inside `main()` shadowing module-level import
- LLM false-aliving all `_`-prefixed dead code

### Changed
- Taint-flow scanners accept context-specific sanitizer sets
- `danger.py` shares parsed AST tree across scanners

## [3.2.5] - 2026-02-09

### Fixed
- `exclude_folders` wired through `run_pipeline` and `run_static_on_files`

## [3.2.4] - 2026-02-08

### Changed
- Agent analyze/review refactored from parallel execution to pipeline architecture (static analysis as source of truth, LLM verifies)
- LLM no longer independently discovers dead code

### Added
- `DeadCodeVerifierAgent` with call graph evidence and defs_map context
- `pipeline.py` with `run_pipeline` and `run_static_on_files`

### Fixed
- Circular dependency checker feeding `.ts`/`.go` files to `ast.parse()`

## [3.2.3] - 2026-02-07

### Fixed
- Hallucination detection PyPI "missing" status
- Dependency parsing for pyproject.toml and setup.py (extras, project name inclusion)

## [3.2.1] - 2026-02-05

### Fixed
- Import usage counting: aliases no longer mark the wrong module as used

## [3.2.0] - 2026-02-05

### Added
- `graph.py` for taint analysis, data flow, and context slicing
- `FalsePositiveFilterAgent` for LLM-based static finding verification
- CI auto-detection (GitHub Actions, Jenkins, CircleCI, GitLab CI) with PR number extraction
- Type2 clone detection, circular dependency display
- CLI entrypoint decorator patterns, post-scan upload CTA, upload prompt with "don't remind me" preference
- SKY-Q401 (async blocking)

### Changed
- `visitor.py` with call graph construction and dynamic string reference detection
- `analyzer.py` uses `CodeGraph` for deep security audits
- Hardened SKY-L001 (catches `list()`, `dict()`, `set()` constructors, comprehensions)

### Fixed
- Parent dir search for pyproject.toml/requirements.txt, dist-info name parsing, Python 3.13 AST compat

## [3.1.3] - 2026-01-27

### Added
- Centralized LLM runtime resolver with auto-detection from `--model`
- Symbol context tracking in taint visitors
- `skylos key` command

### Changed
- Two-level dependency hallucination: SKY-D222 (CRITICAL, confirmed hallucinated) and SKY-D223 (MEDIUM, exists but undeclared)

## [3.1.2] - 2026-01-25

### Added
- Console entrypoint parsing from `pyproject.toml` `[project.scripts]`
- `--pytest-fixtures` flag for unused fixture detection
- Dependency hallucination detection
- Custom rules and compliance from web app (beta)

### Changed
- CLI displays paths relative to CWD
- Switched to `uv` in CI workflows, `litellm` adapter, upload made optional

### Removed
- `cache.py` (unstable outputs), anthropic/openai adapters (replaced by litellm)

## [3.1.1] - 2026-01-20

### Added
- `--provider`, `--base-url` flags and env variable support for LLM providers
- Auto API key bypass for local endpoints
- LLM-assisted detection agent

### Fixed
- `--gate` uploads before exiting, pre-commit hook exit codes, Protocol interface false positives

### Changed
- `OpenAIAdapter` uses Chat Completions API, provider resolution priority chain

## [3.0.3] - 2026-01-10

### Added
- Protocol and ABC detection with duck typing (≥70% method overlap)
- Mixin, base class, and framework lifecycle method confidence penalties
- Data class field detection (dataclass, NamedTuple, Enum, attrs, Pydantic)
- Optional dependency import handling (`try`/`except ImportError`)

### Changed
- `# noqa` comment support for line-level suppression

## [3.0.1] - 2026-01-08

### Added
- `--trace` flag for runtime call tracing via `sys.settrace()`
- Progress indicator during analysis
- SKY-U002: dead file detection for empty Python files
- AST body masking, framework-aware entrypoint detection
- Config-based dead code suppression (`pyproject.toml` whitelists with patterns, reasons, expiration dates)
- `skylos whitelist` command
- Confidence column in output
- Expanded soft patterns (visitor, pytest hooks, plugins)

### Changed
- Replaced `--coverage` with `--trace`
- Penalty system: hard entrypoints (confidence=0), framework entrypoints (with context), soft patterns (proportional)

### Fixed
- Flask route detection, `@login_required` handling, Pydantic route type hints
- `ComplexityRule` visitor, Python 3.13 compat, `skylos init` duplicate config sections

## [2.7.1] - 2025-12-23

### Fixed
- Missing `skylos.visitors.languages` in package, `--version` crash, pre-commit gate script

## [2.7.0] - 2025-12-19

### Added
- Instance attribute type tracking, expanded dunder methods
- SKY-L004 (nested try blocks), SKY-U001 (unreachable code)
- `--coverage` flag, `ImplicitRefTracker` for dynamic patterns

### Fixed
- `Class(1).method()`, `self.attr.method()`, `super().method()` patterns
- Flask/FastAPI route false positives

## [2.6.0] - 2025-12-05

### Added
- TypeScript support (dead code, security, quality) via tree-sitter
- Language-specific config overrides in `pyproject.toml`
- Multi-provider AI adapters (OpenAI, Anthropic) with keyring credential storage
- AI-powered code repair (`--fix`)

## [2.5.3] - 2025-11-28

### Fixed
- Exclusion patterns ignored in analyzer, nested directory exclusion support

## [2.5.2] - 2025-11-24

### Added
- Quality gate (`--gate`) for CI/CD pipeline blocking
- Config support via `pyproject.toml` `[tool.skylos]`
- SKY-C303 (too many args), SKY-C304 (function too long), SKY-L001 (mutable default), SKY-L002 (bare except), SKY-L003 (dangerous comparison)

### Fixed
- Python 3.13 AST crash, JSON serialization of `pathlib.Path`, `DangerousComparisonRule` false positives

## [2.5.1] - 2025-11-19

### Added
- `--tree` flag for ASCII tree output
- Relative file paths in CLI

## [2.5.0] - 2025-11-12

### Added
- Code quality scanner: cyclomatic complexity and nesting depth rules

### Fixed
- Dataclass schema class false positives, multi-part module import detection

## [2.4.0] - 2025-10-14

### Added
- SKY-D211 (SQL injection), SKY-D217 (SQL raw API), SKY-D216 (SSRF), SKY-D215 (path traversal), SKY-D212 (command injection)

## [2.3.0] - 2025-09-22

### Added
- VSCode extension on marketplace
- Dangerous patterns scanner (SKY-D201 through D210), `--danger` flag, `--table` output

### Fixed
- Non-JSON prints breaking CI/CD, secrets regex false positives

## [2.2.3] - 2025-09-18

### Fixed
- Interactive remove/comment for dotted imports and class/async methods

## [2.2.2] - 2025-09-17

### Added
- Secrets scanning (SKY-S101): provider patterns + high entropy detection, `--secrets` flag
- GitHub Actions CI workflow

## [2.1.2] - 2025-08-27

### Added
- Dataclass field detection, `first_read_lineno` tracking, `visit_Global` binding

### Fixed
- Missing `_dataclass_stack` init, dataclass/global singleton false positives

## [2.1.1] - 2025-08-23

### Added
- Pre-commit hooks

## [2.1.0] - 2025-08-21

### Added
- CST-based safe edits for import/function removal via `libcst`

### Changed
- Visitor improvements: locals and types per function scope, constants handling

### Fixed
- `self.attr`/`cls.attr` false positives

## [2.0.1] - 2025-08-11

### Fixed
- Framework-aware pass: route endpoints no longer clamped to low confidence
- `_mark_refs()` rewritten for clarity

## [2.0.0] - 2025-07-14

### Added
- Front end integration (Skylos Cloud dashboard)

## [1.2.2] - 2025-07-03

### Fixed
- `self.ignored_lines` overwrite in loop

## [1.2.1] - 2025-07-03

### Added
- Comment directives: `# pragma: no skylos`, `# pragma: no cover`, `# noqa`
- `proc_file()` returns 7-tuple with ignored lines set

## [1.2.0] - 2025-06-12

### Added
- Framework detection (Flask, Django, FastAPI) with confidence scoring
- `--confidence` flag

### Fixed
- Flask/Django routes incorrectly flagged, test file exclusion improvements

## [1.1.12] - 2025-06-10

### Added
- Test file auto-detection (patterns, imports, decorators)

### Fixed
- Private item (`_`-prefix) and `__future__` import false positives

## [1.1.11] - 2025-06-08

### Added
- `--exclude-folder`, `--include-folder`, `--no-default-excludes`, `--list-default-excludes`

### Fixed
- Test class identification false positives

## [1.0.11] - 2025-05-27

### Added
- Unused parameter and variable detection

## [1.0.10] - 2025-05-24

### Changed
- Rewritten from Rust to Python (faster), benchmark infrastructure, confidence system
