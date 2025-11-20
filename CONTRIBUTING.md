# Contributing to Skylos

Thank you for your interest in contributing to Skylos! This project has both **Python** and **Rust** implementations.

## How Can I Contribute?

### Reporting Bugs
- If you find a bug, please open an issue on GitHub.
- Include a clear title and description.
- Specify which version you're using: **Python** or **Rust** (or both).
- Describe the steps to reproduce the bug.
- Include details about your environment (OS, Python/Rust version, Skylos version).
- Provide any relevant error messages or logs.

### Suggesting Enhancements
- Open an issue on GitHub to discuss your ideas.
- Clearly describe the feature and why it would be useful.
- Specify if it applies to Python, Rust, or both implementations.

---

## Contributing to Python Version

### Prerequisites
- Python >= 3.9
- pip

### Setup Development Environment

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/skylos.git
   cd skylos
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -e .
   pip install inquirer pytest flask flask-cors libcst
   ```

4. **Run Tests:**
   ```bash
   pytest tests/
   ```

### Making Changes

1. Create a branch: `git checkout -b feature/your-feature`
2. Make your changes (primarily in `skylos/` directory)
3. Add tests in `tests/`
4. Run tests: `pytest tests/`
5. Commit and push: `git commit -am 'Add feature'` → `git push origin feature/your-feature`
6. Open a Pull Request

---

## Contributing to Rust Version

### Prerequisites
- Rust >= 1.70 (install from [rustup.rs](https://rustup.rs))
- Cargo (comes with Rust)
- Git

### Setup Development Environment

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/skylos.git
   cd skylos/skylos-rs
   ```

2. **Build the Project:**
   ```bash
   cargo build
   ```

3. **Run Tests:**
   ```bash
   cargo test
   ```

4. **Run Skylos-RS:**
   ```bash
   cargo run -- /path/to/python/project
   ```

### Project Structure

```
skylos-rs/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── analyzer.rs      # Main analysis orchestration
│   ├── visitor.rs       # AST traversal and definition collection
│   ├── framework.rs     # Framework-aware visitor (Flask, Django, etc.)
│   ├── test_utils.rs    # Test file detection
│   ├── utils.rs         # Utilities (LineIndex for line number calculation)
│   └── rules/
│       ├── mod.rs       # Rules module
│       ├── secrets.rs   # Secrets scanning
│       ├── danger.rs    # Dangerous code detection
│       └── quality.rs   # Code quality checks
├── Cargo.toml           # Dependencies
└── target/              # Build artifacts (gitignored)
```

### Development Workflow

1. **Create a Branch:**
   ```bash
   git checkout -b feature/your-rust-feature
   ```

2. **Make Your Changes:**
   - Follow Rust best practices and idioms
   - Use `rustfmt` for formatting: `cargo fmt`
   - Use `clippy` for linting: `cargo clippy`

3. **Test Your Changes:**
   ```bash
   # Run all tests
   cargo test
   
   # Check compilation
   cargo check
   
   # Run on test data
   cargo run -- ../test/sample_repo
   ```

4. **Build Release Version:**
   ```bash
   cargo build --release
   ```

5. **Benchmark (Optional):**
   ```bash
   # Compare with Python
   python -m skylos.cli . --json
   ./target/release/skylos-rs .. --json
   ```

6. **Commit and Push:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feature/your-rust-feature
   ```

7. **Open Pull Request**

### Priority Areas for Contribution

See [`future.md`](future.md) for detailed roadmap. **Quick wins:**

1. **🔴 Critical Fixes:**
   - Implement class/method context tracking (eliminate false positives)
   - Module resolution system
   - Advanced heuristics (visitor patterns, auto-called methods)

2. **🟡 Feature Additions:**
   - Pragma support (`# pragma: no skylos`)
   - Config file support (`.skylos.toml`)
   - Unused parameter detection
   - Entry point detection

3. **🟢 Nice to Have:**
   - Better error handling
   - Performance optimizations
   - More comprehensive tests

### Rust Coding Guidelines

- **Use rustfmt:** `cargo fmt` before committing
- **Use clippy:** `cargo clippy` to catch common mistakes
- **Lifetime annotations:** Keep them minimal and clear
- **Error handling:** Use `anyhow::Result` for complex errors
- **Comments:** Document complex logic and design decisions
- **Tests:** Add unit tests for new functionality

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run tests with coverage (requires tarpaulin)
cargo tarpaulin --out Html
```

### Common Issues

**Build Errors:**
- Clear build cache: `cargo clean`
- Update dependencies: `cargo update`
- Check Rust version: `rustc --version` (should be >= 1.70)

**False Positives:**
- Check `future.md` for known limitations
- Compare output with Python version: `python -m skylos.cli <path>`

---

## Code Style

### Python
- Follow PEP 8
- Use meaningful variable names
- Add docstrings for public functions

### Rust
- Run `cargo fmt` before committing
- Follow Rust API Guidelines
- Use descriptive variable names
- Add doc comments (`///`) for public APIs

---

## Pull Request Guidelines

1. **Clear Description:** Explain what changes you made and why
2. **Reference Issues:** Link related issues with `Fixes #123` or `Relates to #456`
3. **Tests:** Include tests for new features or bug fixes
4. **Documentation:** Update `README.md`, `future.md`, or inline docs as needed
5. **Benchmarks:** For performance changes, include before/after benchmarks
6. **Breaking Changes:** Clearly mark breaking changes and update migration guide

---

## Getting Help

- **Questions:** Open an issue with the `question` label
- **Discussions:** Use GitHub Discussions for design proposals
- **Rust Help:** See [`future.md`](future.md) for implementation guidance

---

Thank you for contributing to Skylos! 🚀