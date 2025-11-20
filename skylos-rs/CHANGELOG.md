# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2025-11-20
### 🎉 Initial Release: Skylos-RS
This release marks the complete rewrite of the static analysis tool in Rust (`skylos-rs`) for high-performance analysis.

### 🚀 New Features
* **Core Analyzer:** Implemented the primary AST visitor engine using `rustpython-parser` and `rayon` for parallel file processing.
* **CLI:** Added a command-line interface using `clap` with flags for confidence thresholds and rule selection (`--secrets`, `--danger`, `--quality`).
* **Rule Sets:**
    * **Secrets:** Regex-based scanning for AWS keys, generic API keys, and tokens.
    * **Danger:** Detection of dangerous patterns like `eval`, `exec`, and `subprocess` usage.
    * **Quality:** Code complexity checks, specifically flagging deeply nested code.
* **Pragma Support:** Added support for inline suppression. Lines marked with `# pragma: no skylos` are now ignored by the analyzer.
* **Entry Point Detection:** Added logic to detect function calls within `if __name__ == "__main__":` blocks to prevent false positives.

### 🧠 Intelligence & Analysis
* **Framework Awareness:** Implemented automatic detection for Python frameworks (Flask, FastAPI, Django, Celery, Pydantic) to prevent flagging routed functions as "unused."
* **Test Awareness:** Added heuristics to automatically identify test files (e.g., `test_*.py`, pytest fixtures) and adjust confidence scores accordingly.
* **Benchmarks:** Added benchmarking infrastructure to compare performance against the Python implementation.

### 🛠 Development & Testing
* **Architecture:** Structured the project with a clear library/binary split (`src/lib.rs` and `src/main.rs`).
* **Test Suite:** Established a comprehensive testing infrastructure covering Integration, Unit, and Fixture-based tests.
* **Documentation:** Added implementation docs for Entry Point detection, Pragma support, and Contribution guides.

---

## Legacy Skylos (Python Implementation)
*Below is the changelog for the original Python-based implementation (v1.0 - v2.5.1).*

## [2.5.1] - 2025-11-19
### Fixed
* Fixed relative path resolution in CLI.
* Fixed CLI test suite failures.
* Updated README with new screenshots.

### Added
* Added a `tree` flag for visualizing file structure during analysis.

## [2.5.0] - 2025-11-12
### Added
* **Quality Analysis:** Introduced a new `--quality` flag for code complexity analysis.
* Added `uv.lock` for dependency management (migrated to `uv`).

### Changed
* Refactored CLI output format for better readability.
* Improved symbol tracking logic.

### Fixed
* **Pydantic:** Fixed analysis logic for Pydantic-style classes.
* **False Positives:** Improved handling of class attribute overrides to prevent "unused variable" false positives.
* Removed duplicate print statements in output.
* Added missing docstrings and documentation for Quality modules.

## [2.4.0] - 2025-10-20
### Added
* **Security Rules:** Added detection for Server-Side Request Forgery (SSRF) and Raw SQL injection vulnerabilities.
* **Taint Tracking:** Added logic to catch Command Injection and SQL Injection flows.
* **VS Code Extension:** Added icon and feature enhancements for the accompanying VS Code extension (v0.1.1).

### Fixed
* **Sinks:** expanded coverage for DB-API, Pandas, and SQLAlchemy sinks.
* **Flow Analysis:** Strengthened taint tracking for command flow (`kwargs`).
* Enforced parameterization checks for SQL queries.

## [2.3.0] - 2025-09-22
### Added
* **VS Code Extension:** Initial release of the Skylos VS Code extension.
* **Danger Mode:** Added `--danger` flag to explicitly track dangerous code patterns.

### Changed
* Renamed internal modules and imports from `dangerous` to `danger` for consistency.
* Added `node_modules` to default `.gitignore`.

## [2.2.4] - 2025-09-22
### Added
* Added script to track list of dangerous code patterns.
* Added comprehensive list of tracked dangerous functions.

### Fixed
* Tightened regex patterns to reduce false positives on security checks.

## [2.2.0] - 2025-09-17
### Added
* **Secrets Detection:** Added new feature to scan for hardcoded secrets.
* **Commenting Feature:** Added capability to comment out unused code instead of deleting it.
* Added pre-commit hooks for CI/CD integration.

### Changed
* Refactored core logic into a `visitor` pattern directory structure.
* Integrated interactive import and method actions to handle dotted names.

## [2.1.2] - 2025-08-28
### Added
* **Pragma Support:** Added support for `# pragma: no skylos` to ignore specific lines.
* Added `--version` flag.

### Fixed
* **Dead Stores:** Fixed logic to suppress dataclass fields and dead-store false positives.
* **Scope:** Fixed recording of loads for locals/globals to improve reference tracking.
* **Ref Matching:** Improved bare-name reference matching.

## [2.1.0] - 2025-08-21
### Added
* **LibCST Integration:** Implemented `libcst` for safer line removals and code modifications.
* Added unit tests for codemods.

### Fixed
* **False Positives:** Reduced FPs via improved call site resolution and implicit dispatch handling.
* **Type Resolution:** Fixed resolution of `self`, `cls`, and constructor types.

## [2.0.1] - 2025-08-11
### Fixed
* **Major:** Rewrote Framework Awareness logic to better detect usage in frameworks (Flask/Django/etc).
* **Major:** Fixed issue where everything was marked as "used" due to simple name matching.
* Cleaned up debug code and manual test scripts.

## [1.2.0] - 2025-06-13
### Added
* **Docker:** Added `Dockerfile` for containerized execution.
* **Confidence Scores:** Added `--confidence` flag and penalty system (starts at 100, reduces based on heuristics).
* **Security Policy:** Added `SECURITY.md`.

### Changed
* Refactored regex constants into a separate file.
* Improved test file detection based on file paths/names.

## [1.0.0] - 2025-05-03
* Initial Python implementation release.
* Basic AST traversal and unused code detection.