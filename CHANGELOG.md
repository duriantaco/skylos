## Changelog

## [3.2.3] - 2026-02-07

## Fixed
- Fixed hallucination detection by making PyPI "missing" status behave correctly
- Improved dependency parsing for pyproject.toml and setup.py, including extras like pkg[extra], and updated parsers to return (deps, name)
- Ensured the project's own package name is included in declared dependencies
- Fixed tests to reflect above changes

## [3.2.1] - 2026-02-05

## Fixed 
- Fix import usage counting by mapping imports to the correct original def using the full qualified import target. We matched ref keys so aliases don’t mark the wrong mod as used.

## [3.2.0] - 2026-02-05

## Added 
- Added `graph.py` to handle taint analysis, data flow, and context slicing for the LLM.
- Added `FalsePositiveFilterAgent` in `agents.py` to verify static findings using the LLM
- Added typing for `visitor.py`, `base.py`, `merger.py`, `schemas.py`, `framework_aware.py`, and `test_aware.py` 
- Added CI auto-detection for GitHub Actions, Jenkins, CircleCI, and GitLab CI in `api.py`
- Added automatic PR/MR number extraction from CI environments
- Added environment variable overrides: `SKYLOS_COMMIT`, `SKYLOS_BRANCH`, `SKYLOS_ACTOR`, `SKYLOS_PR_NUMBER`
- Added comprehensive tests for CI detection, PR extraction, and branch normalization in `test_api.py`
- Added Type2 bucket to detect clones with different variable names. Clone type now displays in Quality Issues table (type1, type2, type3)
- Added CLI display table for circular dependency findings
- Functions decorated with `@*.command`, `@*.default`, `@*.callback`, `@*.group`, `@*.subcommand` no longer flagged as unused
- Added generic decorator patterns to detect CLI entrypoints regardless of framework
- Added tests for monorepo layout, framework aware and circular dep
- Added a post scan upload CTA footer that prints the exact commands to upload results to Skylos Cloud and view the dashboard
- Added a security-only "upload now?" prompt that triggers only when secrets are detected 
- Added a "Don’t remind me again" preference (no_upload_prompt) stored in pyproject.toml under [tool.skylos]
- Added `async_blocking.py` SKY-Q401 as well as new tests

## Changes
- Changed static `visitor.py` with call graph construction, lambda tracking and dynamic string reference detection
- Changed `analyzer.py` to use the new `CodeGraph` for deep security audits instead of dumb chunking.
- Changed `get_git_info()` to return CI metadata alongside commit, branch, and actor
- Changed `upload_report()` to include CI metadata in payload for better Jenkins/CircleCI/GitLab support
- Changed module name computation for `src-layout` projects in `analyzer.py`
- Hardened `MutableDefaultRule` (SKY-L001). Now catches `list()`, `dict()`, `set()` constructor calls. List comprehensions, Dict comprehensions etc
- Improved CLI API token prompt with clearer instructions

## Fixed
- Fixed parent dir search for pyproject.toml/requirements.txt
- Fixed dist-info name parsing by reading METADATA file instead of folder name
- Fixed Python 3.13 AST compatibility in `circular_deps.py`

Note: Formalized a dual pipeline architecture that keeps the static analyzer separate from the LLM

## [3.1.3] - 2026-01-27

## Added 
- Added a centralized LLM runtime resolver that auto-detects provider from `--model`
- Added `_symbol_stack` and `_current_symbol()` to `TaintVisitor` for tracking function/class context
- Added `"symbol": self._current_symbol()` to all findings in sql_flow.py, sql_raw_flow.py, cmd_flow.py, ssrf_flow.py, path_flow.py, xss_flow.py
- Added test for dependency hallucination
- Added `skylos key` command and route skylos key (no args) to open the interactive menu.

## Removed
- Removed keyring/API-key resolution from `LiteLLMAdapter`. Adapters now only consume the resolved api_key/base_url passed in.
- Deprecated `skylos login` to stop it from running analysis.

## Changes
- Updated skylos agent commands to use the centralized resolver so normal runs automatically prompt+store credentials when needed.
- Two levels detection logic for dependency hallucination:
  - SKY-D222 (CRITICAL): Now raised when high confidence that package is hallucinated
  - SKY-D223 (MEDIUM): Raised for packages that exist but not declared in requirements


## [3.1.2] - 2026-01-25

### Added
- Parse pyproject.toml for console entrypoints via `[project.scripts]` (and optionally `[tool.poetry.scripts]`) and treat them as implicit usage
- Added `--pytest-fixtures` flag which should be run in the test directory. This will allow Skylos to detect pytest fixtures that are defined but never used
- Added dependency hallucination to catch packages that do not exist
- Allow customrules and compliance from main webapp (beta)

### Fixed
- Fixed tests that were breaking because of cache
- Fixed `conftest.py` that had duplicate function
- Fixed `--strict` flag for gating in CLI

### Changed
- Changed CLI to display paths relative to CWD, not project root. Example: 

```
## Users run app.py from 
/Users/duriantaco/skylos

## Displayed
app.py:16

## Users run from
/Users/duriantaco/

## Displayed
skylos/app.py:16
```

- Upgraded yaml files in `.github` folder to use `uv` instead of `pip`
- Changed agents to use `litellm_adapter.py` instead of our independent wrapper 
- Changed upload to be optional instead of automatic everytime a check is being run

### Removed
- Removed `cache.py` due to unstable outputs. If changes are made to the structure of objects returned by `proc_file()` then users with old cached results will get errors or wrong data. Dropped it, not worth the trouble
- Removed anthropic and openai adapter. Switched to `litellm`

## [3.1.1] - 2026-01-20

### Added
- Added new `--provider` flag to force `openai` or `anthropic` provider
- New `--base-url` flag for OpenAI compatible endpoints (eg. Ollama etc)
- env variable support: `SKYLOS_LLM_PROVIDER`, `SKYLOS_LLM_BASE_URL`, `OPENAI_BASE_URL`
- Auto API key bypass for local endpoints (localhost, 127.0.0.1, 0.0.0.0)
- Added agent for LLM assisted detection 
- Added new cache and parallel processing functionalities
- More unit tests for LLM agents, cache and parallel processing


### Fixed
- `--gate` flag now uploads scan results before exiting, enabling GitHub App check updates for Pro users
- Pre-commit hook now correctly returns exit code 1 when issues are found (use `skylos . --gate`)
- False positives for methods called via Protocol interface
- Fixed gatekeeper check_gate(..., strict=False) support so strict mode can be driven from config
- Fixed gatekeeper mismatch with tests
- Progress callback bug. Wrong variable name (progress vs progress_callback) fixed

### Changed
- `OpenAIAdapter` now uses Chat Completions API (`chat.completions.create`) instead of Responses API
- Provider resolution now follows priority chain: CLI flag -> env variable -> model name inference
- Changed CLI to use left truncate instead of right truncate to display paths

### Removed
- Removed `cache.py` due to unstable outputs. If changes are made to the structure of objects returned by `proc_file()` then users with old cached results will get errors or wrong data. Dropped it, not worth the trouble
 
## [3.0.3] - 2026-01-10

### Added

- Added protocol and ABC detection. Things include protocol class and member skipping. Classes inhering from `abc.ABC` or `ABC` classes are tracked. `@abstractmethod` decorators are also collected per ABC class. Methods implementing parent ABC's abstract methods as well as classes explicitly inheriting from Protocol classes will get a confidence of 0
- Added `visit_ClassDef` tracking inside `visitor.py` for ABC/Protocol inheritance chains
- Added auto duck typing recognition. Classes implementing >=70% of a Protocol's methods (with min 3 of matching) are detected
- Added global tracking where all protocol method signatures are collected across codebase
- Added `Mixin` class methods penalty. Methods in `*Mixin` classes get a -60% confidence penalty
- Added base class skipping. Methods in `Base*`, `*Base`, `*ABC`, `*Interface`, `*Adapter` classes
- Added framework lifecycle methods for `on_*`, `watch_*`, `compose` methods. They will face a -30%, -30% and -40% penalty respectively
- Added data class field detection where `@dataclass` class attributes, `typing.NamedTuple` fields, `enum.Enum` class, `@attr.s`, Pydantic `BaseModel` fields all will get a confidence of 0
- Added optional dependency imports. Imports inside `try` blocks with `except ImportError` + `HAS_*`/`HAVE_*` flags will be marked as used

### Changes
- Extended `config.py` to include `# noqa` comments where any line with `# noqa` will be ignored. Supports the following formats. `# noqa`, `# noqa: F401`, `# noqa: F401, F402`, `#noqa`, `# NOQA`

### Fixed
- Fixed `visit_Try` to correctly construct import references for optional dependencies

## [3.0.1] - 2026-01-08

New year new me, and a new release! Happy new year everyone! 

### Added
- Added `--trace` flag for runtime call tracing using `sys.settrace()` to capture dynamic dispatch patterns (visitor patterns, getattr, plugins)
- Added `skylos/tracer.py` with `CallTracer` class to record function calls during test execution
- Added pytest plugin hooks (`pytest_configure`, `pytest_unconfigure`, `pytest_addoption`) for `--skylos-trace` integration
- Added `.skylos_trace` file generation containing JSON trace data with function calls, line numbers, and call counts
- Added trace data x-referencing in analyzer to eliminate false positives for dynamic codes
- Added progress callback support to `analyze()` for real-time file processing feedback
- Added progress indicator in CLI showing `[current/total] filename` during analysis
- Added dead code reporting for truly empty Python files (empty or docstring-only), tagged as SKY-U002 under unused_files
- Added `unused_files_count` to analysis_summary when empty-file findings are present
- Added unit test coverage for empty-file reporting
- Added AST body masking feature via `skylos/ast_mask.py` to support masking by name, decorator, and base-class globs
- Added `skylos/known_patterns.py` with framework pattern detection
- Added class context-aware framework entrypoint detection (e.g., `save()` only skipped if inside `Model` subclass)
- Added config-based dead code suppression
  - Config file support in `pyproject.toml`:
    - `[tool.skylos.whitelist].names` - Glob patterns (e.g., `"handle_*"`)
    - `[tool.skylos.whitelist.documented]` - Patterns with reasons for team visibility
    - `[tool.skylos.whitelist.temporary]` - Patterns with expiration dates to prevent whitelist rot
    - `[tool.skylos.overrides."path/*"]` - Per-file/folder whitelist rules
- Added new CLI commands. 1. `skylos whitelist <pattern>` 2. `skylos whitelist <pattern> --reason "why"` 3. `skylos whitelist --show`
- Added new helper functions in `config.py`: `is_whitelisted()`, `get_all_ignore_lines()`, `get_expired_whitelists()`

- Added "Conf" column showing confidence percentage for each flagged item. 100% = definitely dead, 60-80% = probably dead but check, <60% = not flagged
- **Expanded SOFT_PATTERNS** in `known_patterns.py`:
  - `visit_*`, `leave_*` (25) - AST visitor pattern dispatch
  - `pytest_*` (30) - pytest hook functions
  - `*Plugin` (20) - plugin discovery via `__subclasses__()`

- Added the following for reducing false positives:
  - ABC class tracking. Detects classes inheriting from `ABC`
  - Abstract method tracking. Records methods with `@abstractmethod` decorator
  - ABC implementer detection. Tracks classes inheriting from ABC classes
  - Protocol implementer detection. Tracks classes that are explicitly inheriting from Protocol classes
  - Protocol method name tracking
  - Duck-typed Protocol detection (≥70% method overlap with ≥3 methods)


### Changed
- Replaced `--coverage` flag with `--trace` for runtime analysis
- Updated `implicit_refs.py` to store traced function lines as lists
- Updated `should_mark_as_used()` to iterate over traced line lists with ~5 lines tolerance matching
- Added automatic suppression for pytest hook functions (`pytest_configure`, `pytest_unconfigure`, `pytest_addoption`, etc.)
- Added automatic suppression for abstract base class (abc) methods
- `Skylos.analyze()` accepts `progress_callback` parameter for progress reporting
- Updated the analyzer result schema to include `unused_files: []` in the top-level output 
- Updated `_apply_penalties()` in analyzer to use new known patterns system. 1. Hard entrypoints where `confidence = 0`. 2. Framework entrypoints `confidence = 0` only with class context + framework evidence 3. Soft patterns that reduce confidence proportionally
- Updated `visit_FunctionDef` in `framework_aware.py` to immediately add decorated lines to `framework_decorated_lines` (fixes Pydantic model detection in routes)
- Framework decorator patterns now set `is_route = True` during visiting (not just in `finalize()`)
- Reduced `dynamic_module` penalty from 40 to 10
- Updated `skylos init` to properly reset ALL `[tool.skylos*]` sections (fixed regex)
- Mixin method confidence penalty increased from -50 to -60
- Protocol class definitions now get confidence = 0
- Abstract method implementations now get confidence = 0 when parent ABC is tracked
- Duck-typed Protocol implementations now get confidence = 0
- Shifted `apply_penalties` function from `analyzer.py` into a separate script 

### Fixed
- Fixed import path in cli.py: `from skylos.skylos_trace` → `from skylos.tracer`
- Fixed false positives for dynamically dispatched methods (visitor patterns, plugin hooks)
- Fixed analyzer output JSON serialization edge case in tests by ensuring mocked definitions provide concrete line / filename fields (prevents TypeError: Object of type Mock is not JSON serializable)
- Fixed `proc_file()` tests to match the updated return signature
- Fixed Flask route detection bug where `app = Flask(__name__)` routes were incorrectly marked as unused
  - Root cause: `if is_passed or not is_created` evaluated to `False` when `is_created=True` and `is_passed=False`
  - Fix: Removed conditional, all routes are now unconditionally added to `framework_decorated_lines`
- Fixed `@login_required` and other framework decorators not adding functions to `framework_decorated_lines`
- Fixed Pydantic models used as route type hints not being marked as used
- Fixed `ComplexityRule` not counting complexity (visitor was returning early on FunctionDef)
- Fixed Python 3.13 compatibility issue in `ComplexityRule` with nested class `super()` scope
- Fixed test mock path: `skylos.framework_aware.Path` → `skylos.visitors.framework_aware.Path`
- Fixed `skylos init` not removing duplicate config sections when run multiple times
- Fixed `skylos whitelist` command writing to wrong section

### Removed
- Removed `--coverage` flag (replaced by `--trace`)


## [2.7.1] - 2025-12-23

### Fixed
- Fixed packaging bug where `skylos.visitors.languages` were missing from some installs, causing `ModuleNotFoundError: No module named 'skylos.visitors.languages'`
- Fixed bug where running `skylos --version` could crash by importing optional language scanners too early
- Fixed pre-commit integration issue where inline `python -c gate` scripts could fail with SyntaxError due to multi-statement if usage
- Fixed pre-commit integration reliability by moving the "fail-on-findings" logic into `scripts/skylos_gate.py` entry

## [2.7.0] - 2025-12-19
### Fixed
- Fixed bug where `Class(1).method()` patterns were incorrectly flagged
- Fixed bug where `self.attr.method()` patterns were flagged as dead code when `self.attr` was assigned a class instance (e.g., `self.helper = Helper()`)
- Fixed bug where `module.MyC lass().method()` was incorrectly resolving to wrong module
- **Super() Calls:** Fixed bug where `super().method()` calls weren't registering the overridden method as used
- Fixed Flask/FastAPI routes being incorrectly flagged

### Added
- Added `instance_attr_types` tracking in `Visitor` to infer types of instance attributes assigned in `__init__`
- Added `_get_decorator_name()` helper method for robust decorator name extraction
- Expanded `AUTO_CALLED` dunder methods
- Added `TryBlockPatternsRule (SKY-L004)`. `try` blocks nested inside other try blocks to prevent flow
- Added `UnreachableCodeRule (SKY-U001)`. Identifies codes that can never be executed because they follow a terminal statement
- Added `--coverage` CLI flag. Run tests with coverage before analysis
- Added `ImplicitRefTracker` for better dynamic pattern detection. This includes 1. f-string patterns 2. getattr 3. Framework decorators 
- Expanded entry point decorators inside `framework_aware.py` 
- Added test coverage for unreachable, cli coverage and implicit refs
- Added `control_flow.py` to better catch `is False`

### Changed
- Modified tests for `test_constants.py` and `test_visitor.py` to test changes above
- Changes for `@property`, `@x.setter`, `@x.deleter`, and `@cached_property` decorated methods
- Modified `analyzer.py` to register new rules. SKY-L004 and SKY-U001
- `_is_interpolated_string` flagged all f-strings, causing false positives on safe patterns. Added `_has_safe_base_url`
- Replaced nuclear mark all functions as used in `analyzer.py`

## [2.6.0] - 2025-12-05

### Added

- Added TypeScript support (dead code, security, and quality checks) using tree-sitter
- Modular structure for languages for better separation of concerns
- Added support for language-specific config overrides in `pyproject.toml` (e.g., [tool.skylos.languages.typescript])
- Added `DummyVisitor` adapter to prevent the analyzer from crashing when it expects Python-specific attributes on non-Python files
- Added `OpenAIAdapter` and `AnthropicAdapter` to support multi-provider AI fixes and auditing (you can call it using `skylos . --quality --danger --security-audit --model claude-haiku-4-5-20251001`)
- Added secure credential storage using keyring to persist API keys locally
- Added security detection in security-audit mode to identify dangerous functions
- Added `Fixer` engine for AI-powered code repair (you can call it using `skylos . --quality --danger --security-audit --fix --model claude-haiku-4-5-20251001`)

### Changed

- Refactored `analyzer.py` to route files based on extension (`.py` vs `.ts`/`.tsx`) instead of assuming everything is Python
- Moved load_config to the start of `proc_file` so all languages can access the configuration
- Updated `skylos init` template to include language-specific examples

## [2.5.3] - 2025-11-28

### Fixed
- Fixed a bug in `analyzer.py` where exclusion patterns were ignored 
- Fixed `UnboundLocalError` in `start_server` by correctly passing `exclude_folders` as an argument

### Added
- Added support in `analyzer.py` for excluding nested directories (e.g., `--exclude-folder src/legacy`) using normalized path matching

## [2.5.2] - 2025-11-24

### Added
- **Gatekeeper (`--gate`):** A new "Quality Gate" feature that blocks CI/CD pipelines or local deployments if critical issues are found.
  - Supports "Bypass" mode
  - Includes a deployment wizard that handles git staging/commit/push if the checks pass
- **Config Support:** Skylos now reads settings from `pyproject.toml` under `[tool.skylos]`.
  - Users can change the complexity thresholds, max arguments, and ignore specific rules without waiting for a release 
- **Quality Rules:** Added 5 new architectural checks:
  - `SKY-C303`: Too Many Arguments (detects functions with >5 args).
  - `SKY-C304`: Function Too Long (detects functions >50 lines).
  - `SKY-L001`: Mutable Default Arguments (catches `def foo(x=[])`).
  - `SKY-L002`: Bare Except Block (catches `except:` swallowing errors).
  - `SKY-L003`: Dangerous Comparison (catches `if x == True:`).

### Changed
- **Architecture Refactor:** Split the monolithic `analyzer.py` logic into a modular `LinterVisitor` that will run multiple rules in a single pass.
- CLI arguments now support command pass-through (e.g., `skylos . --gate -- git push`).

### Fixed
- Fixed `NameError: name 'ast' is not defined` crash in Python 3.13 by implementing manual AST traversal in `LinterVisitor`.
- Fixed JSON serialization crash where `pathlib.Path` objects were breaking the reporter
- Fixed false positives in `DangerousComparisonRule` where integer comparisons (`x == 1`) were flagged as Bool comparisons

## [2.5.1] - 2025-11-19

### Changed
- CLI now displays **relative file paths** (relative to the scanned root), reducing text overflow in CLI output

### Added
- Added `--tree` flag so users can display their results in an ASCII tree format 

### Downstream
- Analyzer returns richer metadata (`analysis_summary`, secrets/danger/quality wiring), preparing for FE UI integrations down the road

## [2.5.0] - 2025-11-12

### Added

- Code quality scanner with 2 new rules namely complexity and nesting
  - flags high cyclomatic complexity
  - flags deep nesting
- Added uv.lock for frozen dependency snapshot

### Changed
- CLI ui/ux polish

### Fixed 
- Fixed dataframely schema class reports class variables marked as unused
- Fixed multi-part module imports not detected correctly

### Developer Notes

Quality rules live under:

- `skylos/rules/quality/complexity.py`
- `skylos/rules/quality/nesting.py` (max depth across if/for/while/try/with)
- `skylos/rules/quality/quality.py` (entry point)

## [2.4.0] - 2025-10-14

### Added

- SKY-D211 (CRITICAL) + test –> SQL injection (cursor): tainted/string-built SQL into .execute etc
- SKY-D217 (CRITICAL) -> SQL injection (raw-api): tainted SQL 
- SKY-D216 (CRITICAL) + test –> SSRF: tainted URL into HTTP clients 
- SKY-D215 (HIGH) + test –> Path traversal: tainted file path into open(...), os.* etc
- SKY-D212 (CRITICAL) + test –> Cmd injection: tainted command to os.system(...) or subprocess.*(...).
- Added new UI materials into the VSC extension

## [2.3.0] - 2025-09-22

### Added
- You can now download the plugin via marketplace VSC
- Added dangerous patterns scanner (from SKY-D201 -> D210). Results appear in JSON under dangerous
- Danger flag for cli to trigger the dangerous pattern scanning `--danger`
- Added test for danger script
- `--table` flag to output results in table format

### Fixed
- Removed non JSON prints which was causing some CICD pipeline failures
- Fixed the REGEX for secrets which was causing a lot of false positives
- Analyzer now emits separate secrets and dangerous buckets

## [2.2.3] - 2025-09-18

### Fix
Interactive remove and comment out works for dotted imports (e.g. import pkg.subpkg.mod) and class/async methods (Class.method). There was a name mismatch in `codemods.py` script

## [2.2.2] - 2025-09-17

### Added
- Secrets scanning PoC (SKY-S101): provider patterns + generic high entropy
- `--secrets` CLI flag. Results shown in JSON output. To trigger secrets scanning run with `--secrets` flag
- Unit tests covering secrets
- GitHub Actions CI. Skylos Deadcode Scan workflow (.github/workflows/skylos.yml)

### Changed

- Lazy imports to avoid cycles

### Fixed

- Circular import causing scan_ctx import errors.
- Minor preview/test stability issues

## [2.1.2] - 2025-08-27

### Added

- `Dataclass` field detection in `visitor.py`. When a class has `@dataclass`, its annotated class attributes are tagged as dataclass fields
- `first_read_lineno` tracking. Record the first line where each variable is read.
- `visit_Global` to bind global names to module-level FQNs

### Changed
- Report `ALL_CAPS` constants. Previously we had a blanket mute which caused quite a bit of problems 
- `_apply_penalties` mute dataclass fields
- In `Definition` class, add `lineno` alias to `.line` for back-compat.

### Fixed
- Crash: missing `_dataclass_stack` init in `Visitor.__init__`
- False positives fixes. dataclass fields, `global` singletons (e.g., PROCESS_POOL)
- no “All variables…” when an “Unused Variables” section exists inside `cli.py`

## [2.1.1] - 2025-08-23

### Added
- Added pre-commit hooks

## [2.1.0] - 2025-08-21

### Added
- CST based safe edits for removals.. `remove_unused_import_cst` and `remove_unused_function_cst` using `libcst` + `PositionProvider`. Handles multiline imports, aliases, decorators, async defs etc ..
- Unit tests done for `codemode.py`  
- Added dependency: `libcst>=1.4` to project requirements.

### Changed
- `visitor.py` improvements by tracking locals and types per function scope 
- `logging.Formatter.format` credited as implicitly called by the logging subsystem.
- Cleaner constants handling. Module-level ALL_CAPS variables treated as constants, reducing noise.

### Fixed
- LibCST removal sentinel: returned `cst.RemoveFromParent()` to avoid transformer errors
- Removed the redundant `parse_exclude_folders` in `analyzer.py` 
- `self.attr` / `cls.attr` now credited to `CurrentClass.attr`. Fixed some false positives

### Known limitations
- Factory functions or some complex builders may still require a pragma (e.g., `# skylos: ignore`)
- Star imports are intentionally left untouched

## [2.0.1] - 2025-08-11

### Fixed 
- Patched framework aware pass now finalized and applied early. Route-decorated endpoints were clamped to very low confidence.. helpers/models require they're actually reference
- Improved matching
- `_mark_refs()` rewritten for more clarity. Lesser magic 
- Updated the manual test cases for frameworks

## [2.0.0] - 2025-07-14

### Added
- Front end integration! 

## [1.2.2] - 2025-07-03

### Fixed
- Patched bug because down in the loop accidentally overwrote `self.ignored_lines` so it never fires lmao

## [1.2.1] - 2025-07-03

### Added
-  Skylos now recognises comment directives that mark code as intentionally unreachable:  
  `# pragma: no skylos`, `# pragma: no cover`, and standard `# noqa`. Lines carrying these tags are skipped in all unused-code reports
- `proc_file()` returns a 7 tuple: the final item is the `set[int]` of ignored line
  numbers. Library users can consume it immediately. Legacy callers still work
- **Deprecation warning**  
  A `DeprecationWarning` is emitted when the legacy 6 tuple signature is used.
- **Back-compat shim**  
  `Skylos.analyze()` auto detects whether `proc_file()` yielded 6 or 7 items and
  remaps transparently

### Fixed
- Updated test suite to handle the new 7 value signature and ignore pragmas

### Changed
- `analyzer.py`- Switched `proc_file` call site to signature agnostic pattern and inserted the `DeprecationWarning`

### Technical Details
- `proc_file()` always returns seven values. The except path appends an empty
  `set()` for parity
- Environment variable **`SKYLOS_STRICT_APIS=1`** (optional) will raise an error
  if the legacy 6 tuple is encountered
- Unit-tests: added `TestIgnorePragmas`

## [1.2.0] - 2025-06-12

### Added
- Detection for web frameworks (Flask, Django, FastAPI) 
- Framework-specific patterns: `@app.route`, `@router.get`, `@task`, etc.
- More granular dead code detection using confidence. Eg, 0, 20, 40, 60, 100% confidence
- Regex patterns for `/test/` and `/tests/` directory detection
- Added new confidence flag in the CLI

### Fixed
- Fixed issue where Flask/Django routes were incorrectly flagged as unused
- Fixed regression where some test files weren't properly excluded
- Files in `/test/` directories now better detected and excluded
- Test files ending with `_test.py` should be filtered out
- Improved CLI argument parsing for confidence values

### Technical Details
- `framework_aware.py`: `FrameworkAwareVisitor` now should have better decorator detection
- `analyzer.py`: `_apply_penalties()` method for framework confidence scoring
- `cli.py`: Added confidence threshold validation
- `constants.py`: Framework detection patterns and test file regex

## [1.1.12] - 2025-06-10

### Added
- Auto identifies test files in `/tests/`, `/test/`, `test_*.py` patterns
- Detects test files by test library imports (unittest.mock, pytest, responses, etc.)
- Decorator detection
- Constants Module: New `skylos/constants.py` for centralized configuration management
- Test lifecycle methods: setUp, tearDown, setUpClass, tearDownClass, setup_method, teardown_method
- Test import patterns: `unittest`, `pytest`, `mock`, `responses`, `freezegun`, `hypothesis`, `faker`
- Test decorators: `@patch`, `@pytest.fixture`, `@pytest.mark`, `@responses.activate`

### Fixed
- Fixed false positives where private items starting with `_` were wrongly reported as unused
- Fixed false positives where from `__future__import annotations`
- Missing detection of test_* method patterns that were not being excluded from unused reports

### Changed
- Refactored constants into separate module
- Pattern matching for test classes eg. TestExample, ExampleTest, ExampleTestCase 

## [1.1.11] - 2025-06-08

### Added
- Folder Management: Control over folder exclusions/inclusions
`--exclude-folder`: Add custom folder exclusions to defaults
`--include-folder`: Include specific folders
`--no-default-excludes`: Disable default exclusions
`--list-default-excludes`: Display all default excluded folders

### Fixed
- Improved accuracy for test method identification
- Fixed false positives where classes containing "Test" were incorrectly identified as test classes
- Resolved issue where `NotATestClass` was incorrectly identified as test class
- Changed from "Test" in class_name to precise pattern matching
- Fixed module import issues in CLI components

### Changed
- Standardized default folder exclusions across all components

### Technical Details

`analyzer.py`: Updated _`apply_heuristics()` with better test class detection logic
`cli.py`: Folder management update
`analyzer.py`: Added `parse_exclude_folders()` function for more flexible folder handling

## [1.0.11] - 2025-05-27

### Added
- **Unused Parameter Detection**: Detects unused functions and method parameters
  - New `unused_parameters` and `unused_variables` category in analysis results
  - Detects parameters used in attribute access (e.g., `self.attribute`)
  - CLI now displays unused parameters

### Fixed
- **Parameter Usage Tracking**: Fixed false positives where `self` and other parameters were incorrectly flagged as unused
  - Now detects `self` usage in attribute access
  - Tracks parameters passed as arguments to other functions

### Changed
- Improved `visitor` to track parameter usage within function scopes
- Enhanced heuristics for magic method params
- Updated result format to include parameter and variables analysis

### Technical Details
- `visitor.py`: Added parameter tracking in `visit_Attribute` for proper `self` detection
- `skylos.py`: Added `unused_parameters` to result dictionary
- `cli.py`: Added display section for unused parameters with color coding

## [1.0.10] - 2025-05-24

### Fixed
Major Changes: Changed from Rust to Python. Surprisingly it's faster!
Accuracy Improvements: Constructed 2 full tests with ground truths
Technical Improvements: Benchmark infrastructure, confidence system, AST enhancements. Please read `BENCHMARK.md` for more
Beautified CLI to make reading much easier
