## Changelog

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
