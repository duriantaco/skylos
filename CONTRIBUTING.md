# Contributing to Skylos

## How Can I Contribute?

### Reporting Bugs
- If you find a bug, please open an issue on GitHub.
- Include a clear title and description.
- Describe the steps to reproduce the bug.
- Include details about your environment (OS, Python version, Skylos version).
- Provide any relevant error messages or logs.

### Suggesting Enhancements
- Open an issue on GitHub to discuss your ideas.
- Clearly describe the feature and why it would be useful.

### Pull Requests

1.  **Fork the repo:** Click the "Fork" button at the top right of the [Skylos GitHub page](https://github.com/duriantaco/skylos).
2.  **Clone your fork:** `git clone https://github.com/YOUR_USERNAME/skylos.git`
3.  **Create a separate branch:** `git checkout -b feature/your-changes` or `bugfix/the-bug-you-fixed`
4.  **Set Up Development Environment:**
    * Please ensure that you have Python (>=3.9) installed.

    * Install Python development dependencies (like `inquirer` for interactive mode testing, `pytest`): `pip install inquirer pytest`
    * Build Skylos in development mode: `pip install -e .`
5.  **Make Your Changes:**
    * For Python CLI changes, primarily in `skylos/cli.py`.
6.  **Add Tests:**
    * For Python integration tests: `pytest tests/` from the project root.
    * For static-analysis precision changes: `python3 scripts/corpus_ci.py --manifest corpus/manifest.json`
    * Ensure your changes are covered by new or existing tests.
7.  **Update Documentation:** If your changes affect user-facing features or the API, please update `README.md` or other relevant documentation.
8.  **Commit Your Changes:** `git commit -am 'your changes'`
9.  **Push to Your Branch:** `git push origin feature/your changes`
10. **Open a Pull Request:** Go to the original Skylos repo and open a pull request from your forked branch.
    * Provide clear description of your changes.
    * Reference any related issues.

## Code Style
- You can look at our code and just follow it accordingly. Try your best to follow best practices. 

## Precision Policy

- Treat the corpus as a required regression guard for dead-code precision.
- If you fix a confirmed false positive or precision regression, add a minimal fixture under `corpus/fixtures/` that isolates the runtime contract or language pattern.
- Register the case in `corpus/manifest.json` with narrow expectations and a source link to the upstream framework or library pattern that motivated it.
- Keep fixtures small and pattern-focused. The corpus should protect specific contracts, not attempt to model an entire framework in one file.
- Prefer explicit contracts over broad heuristic suppression. If a pattern is plausible but not proven, keep the rule narrow or lower confidence instead of hard-suppressing it.
- Do not relax or remove an existing corpus expectation unless the original pattern was invalid or the contract changed.

## Getting Help
If you have questions or need help, feel free to open an issue with the "question" label.

Thank you for contributing!
