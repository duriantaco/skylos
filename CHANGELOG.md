## Changelog

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
