## Changelog

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
