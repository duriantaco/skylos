# Skylos-RS Test Suite

This directory contains tests for the Rust implementation of Skylos.

## Test Structure

- `integration_test.rs` - End-to-end tests running the binary
- `visitor_test.rs` - Unit tests for AST visitor
- `framework_test.rs` - Tests for framework detection (Flask, Django, FastAPI)
- `test_utils_test.rs` - Tests for test file detection
- `security_test.rs` - Tests for secrets and dangerous code detection
- `quality_test.rs` - Tests for code quality checks

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test visitor_test

# Run with output
cargo test -- --nocapture

# Run in release mode (faster)
cargo test --release
```

## Current Status

⚠️ **Note**: Some tests are currently failing due to API mismatches between test expectations and actual implementation. This is expected during active development.

**Working Tests:**
- Line index accuracy
- Basic AST parsing
- Secrets detection
- Quality nesting detection

**Known Issues:**
- Integration tests require test fixtures to be set up
- Some visitor tests need API adjustments
- Framework detection tests need refinement

## Adding New Tests

1. Create a new file in `tests/` directory
2. Use the existing test files as templates
3. Import required modules: `use skylos_rs::*;`
4. Write test functions with `#[test]` attribute

## Test Data

Test fixtures are located in `../test/cases/` directory, mirroring the Python test suite structure.
