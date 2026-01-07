<div align="center">
   <img src="assets/DOG_1.png" alt="Skylos Logo" width="300">
   <h1>Skylos: Guard your Code</h1>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![PyPI version](https://img.shields.io/pypi/v/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
![Security Policy](https://img.shields.io/badge/security-policy-brightgreen)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

> Skylos is a static analysis tool for Python codebases which locates dead code, performs quality checks, and finds security vulnerabilties.

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Performance](#performance)
- [How It Works](#how-it-works)
- [Gating](#gating)
- [Integration and Ecosystem](#integration-and-ecosystem)
- [Auditing and Precision](#auditing-and-precision)
- [Coverage Integration](#coverage-integration)
- [Filtering](#filtering)
- [CLI Options](#cli-options)
- [FAQ](#faq)
- [Limitations and Troubleshooting](#limitations-and-troubleshooting)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

## Quick Start

| Objective | Command | Outcome | Remarks |
| :--- | :--- | :--- | :--- |
| **Hunt Dead Code** | `skylos .` | Prune unreachable functions and unused imports instantly. | |
| **Precise Hunt** | `skylos . --trace` | Cross-reference results with actual runtime data | Run `skylos . --trace` first then run your actual scan `skylos . --danger` |
| **Audit Risk & Quality** | `skylos . --secrets --danger --quality` | Kill security leaks, tainted data, and architectural rot. | You can run one of the flags, or all 3 |
| **Automated Repair** | `skylos . --audit --fix` | Let the watchdog handle the labor of cleaning your code. | |
| **Secure the Gate** | `skylos --gate` | Block risky code from merging with hard-coded standards. | |
| **Whitelist False Positives** | `skylos whitelist 'handle_*'` | Suppress known dynamic patterns from future scans. |


## Features

### Security & Vulnerability Audit

* **Taint-Flow Tracking**: Follows untrusted input from the API edge to your database to stop SQLi, SSRF, and Path Traversal
* **Credentials Detection**: Detects API keys & secrets (GitHub, GitLab, AWS, Google, SendGrid, private key blocks)
* **Vulnerability Detection**: Flags dangerous patterns including eval/exec, unsafe yaml/pickle loads, and weak cryptographic hashes
* **Implicit Reference Detection**: Catches dynamic patterns like `getattr(mod, f"handle_{x}")`, framework decorators (`@app.route`, `@pytest.fixture`), and f-string dispatch patterns

### Codebase Optimization

* **CST-safe removals:** Uses LibCST to remove selected imports or functions (handles multiline imports, aliases, decorators, async etc..)
* **Logic Awareness**: Deep integration for Python frameworks (Django, Flask, FastAPI) and TypeScript (Tree-sitter) to identify active routes and dependencies.
* **Granular Filtering**: Skip lines tagged with `# pragma: no skylos`, `# pragma: no cover`, or `# noqa`

### Operational Governance & Runtime

* **Coverage Integration**: Auto-detects `.skylos-trace` files to verify dead code with runtime data
* **Quality Gates**: Enforces hard thresholds for complexity, nesting, and security risk via `pyproject.toml` to block non-compliant PRs
* **Interactive CLI**: Manually verify and remove/comment-out findings through an `inquirer`-based terminal interface
* **Audit Mode**: Leverages an independent reasoning loop to identify "hallucinations" and broken dependencies

### Multi-Language Support

| Language | Parser | Dead Code | Security | Quality |
|----------|--------|-----------|----------|---------|
| Python | AST | ✅ | ✅ | ✅ |
| TypeScript | Tree-sitter | Limited | Limited | Limited |

No Node.js required - parser is built-in.

## Installation

### Basic Installation

```bash
## from pypi
pip install skylos

## or from source
git clone https://github.com/duriantaco/skylos.git
cd skylos

pip install .
```

## Performance

For dead code detection benchmarks vs Vulture, Flake8, Ruff, see [BENCHMARK.md](BENCHMARK.md).

To run the benchmark:
`python compare_tools.py /path/to/sample_repo`


## How it works

Skylos builds a reference graph of your entire codebase - who defines what, who calls what, across all files.

```
Parse all files -> Build definition map -> Track references -> Find orphans (zero refs = dead)
```

### Confidence Scoring

Not all dead code is equally dead. Skylos assigns confidence scores to handle ambiguity:

| Confidence | Meaning | Action |
|------------|---------|--------|
| 100 | Definitely unused | Safe to delete |
| 60 | Probably unused (default threshold) | Review first |
| 40 | Maybe unused (framework helpers) | Likely false positive |
| 20 | Possibly unused (decorated/routes) | Almost certainly used |
| 0 | Show everything | Debug mode |

```bash
skylos . -c 60  # Default: high-confidence findings only
skylos . -c 30  # Include framework helpers  
skylos . -c 0  # Everything
```

### Framework Detection

When Skylos sees Flask, Django, or FastAPI imports, it adjusts scoring automatically:

| Pattern | Handling |
|---------|----------|
| `@app.route`, `@router.get` | Entry point → marked as used |
| `@pytest.fixture`, `@celery.task` | Entry point → marked as used |
| `getattr(mod, "func")` | Tracks dynamic reference |
| `getattr(mod, f"handle_{x}")` | Tracks pattern `handle_*` |

### Test File Exclusion

Tests call code in weird ways that look like dead code. By default, Skylos excludes:

| Detected By | Examples |
|-------------|----------|
| Path | `/tests/`, `/test/`, `*_test.py` |
| Imports | `pytest`, `unittest`, `mock` |
| Decorators | `@pytest.fixture`, `@patch` |

```bash
# These are auto-excluded (confidence set to 0)
/project/tests/test_user.py
/project/test/helper.py  

# These are analyzed normally
/project/user.py
/project/test_data.py  # Doesn't end with _test.py
```

Want test files included? Use `--include-folder tests`.

### Philosophy

> When ambiguous, we'd rather miss dead code than flag live code as dead.

Framework endpoints are called externally (HTTP, signals). Name resolution handles aliases. When things get unclear, we err on the side of caution.

## Gating

Block bad code before it merges. Configure thresholds, run locally, then automate in CI.

### 1. Initialize Configuration
```bash
skylos init
```

Creates `[tool.skylos]` in your `pyproject.toml`:
```toml
[tool.skylos]
# Quality thresholds
complexity = 10
nesting = 3
max_args = 5
max_lines = 50
ignore = [] 
model = "gpt-4.1"

# Language overrides (optional)
[tool.skylos.languages.typescript]
complexity = 15
nesting = 4

# Gate policy
[tool.skylos.gate]
fail_on_critical = true
max_security = 0      # Zero tolerance
max_quality = 10      # Allow up to 10 warnings
strict = false
```

### 2. Run the Gate
```bash
skylos . --quality --danger --gate
```

If thresholds exceeded, Skylos exits non-zero (blocking CI/CD or git push). You'll be prompted to select files manually or push all at once.

Use `--force` to bypass in emergencies.

### 3. GitHub Actions

<details>
<summary><b>Full workflow (click to expand)</b></summary>

Create `.github/workflows/skylos.yml`:
```yaml
name: Skylos Deadcode Scan

on:
  pull_request:
  push:
    branches: [ main, master ]
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      SKYLOS_STRICT: ${{ vars.SKYLOS_STRICT || 'false' }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Skylos
        run: pip install skylos

      - name: Run Skylos
        env:
          REPORT: skylos_${{ github.run_number }}_${{ github.sha }}.json
        run: |
          echo "REPORT=$REPORT" >> "$GITHUB_OUTPUT"
          skylos . --json > "$REPORT"
        id: scan

      - name: Fail if there are findings
        continue-on-error: ${{ env.SKYLOS_STRICT != 'true' }}
        env:
          REPORT: ${{ steps.scan.outputs.REPORT }}
        run: |
            python - << 'PY'
            import json, sys, os
            report = os.environ["REPORT"]
            data = json.load(open(report, "r", encoding="utf-8"))
            count = 0
            for value in data.values():
                if isinstance(value, list):
                    count += len(value)
            print(f"Findings: {count}")
            if count > 0:
              print(f"::warning title=Skylos findings::{count} potential issues found. See {report}")
            sys.exit(1 if count > 0 else 0)
            PY

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ${{ steps.scan.outputs.REPORT }}
          path: ${{ steps.scan.outputs.REPORT }}

      - name: Summarize in job log
        if: always()
        run: |
          echo "Skylos report: ${{ steps.scan.outputs.REPORT }}" >> $GITHUB_STEP_SUMMARY
```

</details>

**Strict mode:** Go to GitHub → Settings → Secrets and variables → Actions → Variables → Add `SKYLOS_STRICT` with value `true`.

### 4. Pre-commit

Pick one approach:

<b>Option A: Skylos hook repo</b>
```yaml
## .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skylos-scan
        name: skylos report
        entry: python -m skylos.cli
        language: system
        pass_filenames: false
        require_serial: true
        args: [".", "--output", "report.json", "--confidence", "70", "--danger"]

      - id: skylos-fail-on-findings
        name: skylos gate
        language: system
        pass_filenames: false
        require_serial: true
        entry: python scripts/skylos_gate.py
```


<b>Option B: Self-contained local hook</b>
```yaml
repos:
  - repo: local
    hooks:
      - id: skylos-scan
        name: skylos report
        language: python
        entry: python -m skylos.cli
        pass_filenames: false
        require_serial: true
        additional_dependencies: [skylos==2.8.0]
        args: [".", "--output", "report.json", "--confidence", "70"]

      - id: skylos-fail-on-findings
        name: skylos (soft)
        language: python
        language_version: python3
        pass_filenames: false
        require_serial: true
        entry: >
          python -c "import os, json, sys, pathlib;
          p=pathlib.Path('report.json');
          if not p.exists(): sys.exit(0);
          data=json.loads(p.read_text(encoding='utf-8'));
          count = sum(len(v) for v in data.values() if isinstance(v, list));
          print(f'[skylos] findings: {count}');
          sys.exit(0 if os.getenv('SKYLOS_SOFT') or count==0 else 1)"
```

If you chose option A, then do remember to put this script below in a folder `scripts/sylos_gate.py`

```python
#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

REPORT = Path("report.json")

def main() -> int:
    if not REPORT.exists():
        print("[skylos] report.json missing (skipping gate)")
        return 0

    txt = REPORT.read_text(encoding="utf-8", errors="ignore").strip()
    if not txt:
        print("[skylos] report.json empty (skipping gate)")
        return 0

    try:
        data = json.loads(txt)
    except Exception as e:
        print(f"[skylos] report.json invalid JSON (skipping gate): {e}")
        return 0

    if isinstance(data, dict):
        vals = data.values()
    elif isinstance(data, list):
        vals = data
    else:
        vals = []

    count = 0
    for v in vals:
        if isinstance(v, list):
            count += len(v)

    print(f"[skylos] findings: {count}")
    soft = os.getenv("SKYLOS_SOFT", "").strip()
    if soft or count == 0:
        return 0
    else:
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
```

**Install:**
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

<details>
<summary><b>Run pre-commit in CI</b></summary>

Create `.github/workflows/pre-commit.yml`:
```yaml
name: pre-commit
on: [push, pull_request]
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11", cache: "pip" }
      - uses: pre-commit/action@v3.0.1
        with: { extra_args: --all-files }
```

</details>

**Note:** The second hook is soft by default (`SKYLOS_SOFT=1`) - prints findings but passes. Remove the env to block commits on findings. 

## Integration and Ecosystem

Skylos is designed to live everywhere your code does—from your IDE to your deployment pipeline.

### 1. Integration Environments

| Environment | Tool | Use Case |
|-------------|------|----------|
| VS Code | Skylos Extension | Real-time guarding. Highlights code rot and risks on-save. |
| Web UI | `skylos run` | Launch a local dashboard at `localhost:5090` for visual auditing. |
| CI/CD | GitHub Actions / Pre-commit | Automated gates that audit every PR before it merges. |
| Quality Gate | `skylos --gate` | Block deployment if security or complexity thresholds are exceeded. |

### 2. Output Formats

Control how you consume the watchdog's findings.

| Flag | Format | Primary Use |
|------|--------|-------------|
| `--table` | Rich Table | Default human-readable CLI summary. |
| `--tree` | Logic Tree | Visualizes code hierarchy and structural dependencies. |
| `--json` | Machine Raw | Piping results to `jq`, custom scripts, or log aggregators. |
| `-o, --output` | File Export | Save the audit report directly to a file instead of `stdout`. |


## Auditing and Precision

By default, Skylos finds dead code. Enable additional scans with flags.

### Security (`--danger`)

Tracks tainted data from user input to dangerous sinks.

```bash
skylos . --danger
```

| Catches | Example |
|---------|---------|
| SQL injection | `cur.execute(f"SELECT * FROM users WHERE name='{name}'")` |
| Command injection | `os.system("zip -r out.zip " + folder)` |
| SSRF | `requests.get(request.args["url"])` |
| Path traversal | `open(request.args.get("p"))` |
| Unsafe deserialize | `pickle.load()`, `yaml.load()` without SafeLoader |
| Weak crypto | `hashlib.md5()`, `hashlib.sha1()` |

Full list in `DANGEROUS_CODE.md`.

### Secrets (`--secrets`)

Detects hardcoded credentials.
```bash
skylos . --secrets
```

Providers: GitHub, GitLab, AWS, Stripe, Slack, Google, SendGrid, Twilio, private keys.

### Quality (`--quality`)

Flags functions that are hard to maintain.
```bash
skylos . --quality
```

| Rule | ID | What It Catches |
|------|-----|-----------------|
| **Complexity** | | |
| Cyclomatic complexity | SKY-Q301 | Too many branches/loops (default: >10) |
| Deep nesting | SKY-Q302 | Too many nested levels (default: >3) |
| **Structure** | | |
| Too many arguments | SKY-C303 | Functions with >5 args |
| Function too long | SKY-C304 | Functions >50 lines |
| **Logic** | | |
| Mutable default | SKY-L001 | `def foo(x=[])` - causes state leaks |
| Bare except | SKY-L002 | `except:` swallows SystemExit |
| Dangerous comparison | SKY-L003 | `x == None` instead of `x is None` |
| Anti-pattern try block | SKY-L004 | Nested try, or try wrapping too much logic |
| **Performance** | | |
| Memory load | SKY-P401 | `.read()` / `.readlines()` loads entire file |
| Pandas no chunk | SKY-P402 | `read_csv()` without `chunksize` |
| Nested loop | SKY-P403 | O(N²) complexity |
| **Unreachable** | | |
| Unreachable Code | SKY-UC001 | `if False:` or `else` after always-true |
| **Empty** | | |
| Empty File | SKY-E002 | Empty File |

To ignore a specific rule:
```toml
# pyproject.toml
[tool.skylos]
ignore = ["SKY-P403"]  # Allow nested loops
```

Tune thresholds and disable rules in `pyproject.toml`:
```toml
[tool.skylos]
# Adjust thresholds
complexity = 15        # Default: 10
nesting = 4            # Default: 3
max_args = 7           # Default: 5
max_lines = 80  
```

### AI Auditing (`--audit`)

LLM-powered logic review.
```bash
skylos . --audit
skylos . --audit --model claude-haiku-4-5-20251001
```

Finds:
  - Hallucination Detection: Finds calls to functions that don't actually exist in your repo.
  - Logic Flaws: Detects "confident but wrong" logic, bare exceptions, and architectural rot.
  - Using a specific model: `--model claude-haiku-4-5-20251001`


### Autonomous Fix (`--fix`)

Let the LLM fix what it found.
```bash
skylos . --fix
```

API keys stored in your system keychain (macOS Keychain, Windows Credential Locker). Never plaintext.

### Combine Everything
```bash
skylos . --danger --secrets --quality  # All static scans
skylos . --danger --quality --audit --fix  # Full AI-assisted cleanup
```

## Smart Tracing

Static analysis can't see everything. Python's dynamic nature means patterns like `getattr()`, plugin registries, and string-based dispatch look like dead code—but they're not.

**Smart tracing solves this.** By running your tests with `sys.settrace()`, Skylos records every function that actually gets called.

### Quick Start
```bash
# Run tests with call tracing, then analyze
skylos . --trace

# Trace data is saved to .skylos_trace
skylos .
```

### How It Works

| Analysis Type | Accuracy | What It Catches |
|---------------|----------|-----------------|
| Static only | 70-85% | Direct calls, imports, decorators |
| + Framework rules | 85-95% | Django/Flask routes, pytest fixtures |
| + `--trace` | 95-99% | Dynamic dispatch, plugins, registries |

### Example
```python
# Static analysis will think this is dead because there's no direct call visible
def handle_login():
    return "Login handler"

# But it is actually called dynamically at runtime
action = request.args.get("action")  
func = getattr(module, f"handle_{action}")
func()  # here  
```

| Without Tracing | With `--trace` |
|-----------------|----------------|
| `handle_login` flagged as dead | `handle_login` marked as used |

### When To Use

| Situation | Command |
|-----------|---------|
| Have pytest/unittest tests | `skylos . --trace` |
| No tests | `skylos .` (static only) |
| CI with cached trace | `skylos .` (reuses `.skylos_trace`) |

### What Tracing Catches

These patterns are invisible to static analysis but caught with `--trace`:
```python

# 1. Dynamic dispatch
func = getattr(module, f"handle_{action}")
func()

# 2. Plugin or registry patterns  
PLUGINS = []
def register(f): 
  PLUGINS.append(f)
return f

@register
def my_plugin(): ...  

# 3. Visitor patterns
class MyVisitor(ast.NodeVisitor):
    def visit_FunctionDef(self, node): ...  # Called via getattr

# 4. String-based access
globals()["my_" + "func"]()
locals()[func_name]()
```

### Important Notes

- **Tracing only adds information.** Low test coverage won't create false positives. It just means some dynamic patterns **may** still be flagged.
- **Commit `.skylos_trace`** to reuse trace data in CI without re-running tests.
- **Tests don't need to pass.** Tracing records what executes, regardless of pass/fail status.

## Filtering

Control what Skylos analyzes and what it ignores.

### Inline Suppression

Silence specific findings with comments:
```python
# Ignore dead code detection on this line
def internal_hook():  # pragma: no skylos
    pass

# this also works
def another():  # pragma: no cover
    pass

def yet_another():  # noqa
    pass
```

### Folder Exclusion

By default, Skylos excludes: `__pycache__`, `.git`, `.pytest_cache`, `.mypy_cache`, `.tox`, `htmlcov`, `.coverage`, `build`, `dist`, `*.egg-info`, `venv`, `.venv`
```bash
# See what's excluded by default
skylos --list-default-excludes

# Add more exclusions
skylos . --exclude-folder vendor --exclude-folder generated

# Force include an excluded folder
skylos . --include-folder venv

# Scan everything (no exclusions)
skylos . --no-default-excludes
```

### Rule Suppression

Disable rules globally in `pyproject.toml`:
```toml
[tool.skylos]
ignore = [
    "SKY-P403",   # Allow nested loops
    "SKY-L003",   # Allow == None
    "SKY-S101",   # Allow hardcoded secrets (not recommended)
]
```

### Summary

| Want to... | Do this |
|------------|---------|
| Skip one line | `# pragma: no skylos` |
| Skip one secret | `# skylos: ignore[SKY-S101]` |
| Skip a folder | `--exclude-folder NAME` |
| Skip a rule globally | `ignore = ["SKY-XXX"]` in pyproject.toml |
| Include excluded folder | `--include-folder NAME` |
| Scan everything | `--no-default-excludes` |

## Whitelist Configuration

Suppress false positives permanently without inline comments cluttering your code.

### CLI Commands
```bash
# Add a pattern
skylos whitelist 'handle_*'

# Add with reason
skylos whitelist dark_logic --reason "Called via globals() in dispatcher"

# View current whitelist
skylos whitelist --show
```

### Inline Ignores
```python
# Single line
def dynamic_handler():  # skylos: ignore
    pass

# Also works
def another():  # noqa: skylos
    pass

# Block ignore
# skylos: ignore-start
def block_one():
    pass
def block_two():
    pass
# skylos: ignore-end
```

### Config File (`pyproject.toml`)
```toml
[tool.skylos.whitelist]
# Glob patterns
names = [
    "handle_*",
    "visit_*",
    "*Plugin",
]

# With reasons (shows in --show output)
[tool.skylos.whitelist.documented]
"dark_logic" = "Called via globals() string manipulation"
"BasePlugin" = "Discovered via __subclasses__()"

# Temporary (warns when expired)
[tool.skylos.whitelist.temporary]
"legacy_handler" = { reason = "Migration - JIRA-123", expires = "2026-03-01" }

# Per-path overrides
[tool.skylos.overrides."src/plugins/*"]
whitelist = ["*Plugin", "*Handler"]
```

### Summary

| Want to... | Do this |
|------------|---------|
| Whitelist one function | `skylos whitelist func_name` |
| Whitelist a pattern | `skylos whitelist 'handle_*'` |
| Document why | `skylos whitelist x --reason "why"` |
| Temporary whitelist | Add to `[tool.skylos.whitelist.temporary]` with `expires` |
| Per-folder rules | Add `[tool.skylos.overrides."path/*"]` |
| View whitelist | `skylos whitelist --show` |
| Inline ignore | `# skylos: ignore` or `# noqa: skylos` |
| Block ignore | `# skylos: ignore-start` ... `# skylos: ignore-end` |

## CLI Options

### Flags
```
Usage: skylos [OPTIONS] PATH

Arguments:
  PATH  Path to the Python project to analyze

Options:
  -h, --help                   Show this help message and exit
  --json                       Output raw JSON instead of formatted text  
  --tree                       Output results in tree format
  --table                      Output results in table format via the CLI
  -c, --confidence LEVEL       Confidence threshold 0-100 (default: 60)
  --comment-out                Comment out code instead of deleting
  -o, --output FILE            Write output to file instead of stdout
  -v, --verbose                Enable verbose output
  --version                    Checks version
  -i, --interactive            Interactively select items to remove
  --dry-run                    Show what would be removed without modifying files
  --exclude-folder FOLDER      Exclude a folder from analysis (can be used multiple times)
  --include-folder FOLDER      Force include a folder that would otherwise be excluded
  --no-default-excludes        Don't exclude default folders (__pycache__, .git, venv, etc.)
  --list-default-excludes      List the default excluded folders and
  --secrets                    Scan for api keys/secrets
  --danger                     Scan for dangerous code
  --quality                    Code complexity and maintainability
  --coverage                   Run tests with coverage first
  --audit                      LLM-powered logic review
  --fix                        LLM auto-repair
  --model MODEL                LLM model (default: gpt-4.1)
  --gate                       Fail on threshold breach (for CI)
  --force                      Bypass quality gate (emergency override)
```

### Commands 
```
Commands:
  skylos PATH                  Analyze a project
  skylos init                  Initialize pyproject.toml config
  skylos whitelist PATTERN     Add pattern to whitelist
  skylos whitelist --show      Display current whitelist
  skylos run                   Start web UI at localhost:5090

Whitelist Options:
  skylos whitelist PATTERN           Add glob pattern (e.g., 'handle_*')
  skylos whitelist NAME --reason X   Add with documentation
  skylos whitelist --show            Display all whitelist entries
```

### CLI Output

Skylos displays confidence for each finding:
```
────────────────── Unused Functions ──────────────────
#   Name              Location        Conf
1   handle_secret     app.py:16       70%
2   totally_dead      app.py:50       90%
```

Higher confidence = more certain it's dead code.

### Interactive Mode

The interactive mode lets you select specific functions and imports to remove:

1. **Select items**: Use arrow keys and `spacebar` to select/unselect
2. **Confirm changes**: Review selected items before applying
3. **Auto-cleanup**: Files are automatically updated

## FAQ 

**Q: Why doesn't Skylos find 100% of dead code?**
A: Python's dynamic features (getattr, globals, etc.) can't be perfectly analyzed statically. No tool can achieve 100% accuracy. If they say they can, they're lying.

**Q: Are these benchmarks realistic?**
A: They test common scenarios but can't cover every edge case. Use them as a guide, not gospel.

**Q: Why doesn't Skylos detect my unused Flask routes?**
A: Web framework routes are given low confidence (20) because they might be called by external HTTP requests. Use `--confidence 20` to see them. We acknowledge there are current limitations to this approach so use it sparingly.

**Q: What confidence level should I use?**
A: Start with 60 (default) for safe cleanup. Use 30 for framework applications. Use 20 for more comprehensive auditing.

**Q: What does `--coverage` do?**
A: It runs `pytest` (or `unittest`) with coverage tracking before analysis. Functions that actually executed are marked as used with 100% confidence, eliminating false positives from dynamic dispatch patterns.

**Q: Do I need 100% test coverage for `--coverage` to be useful?**
A: No. However, we **STRONGLY** encourage you to have tests. Any coverage helps. If you have 30% test coverage, that's 30% of your code verified. The other 70% still uses static analysis. Coverage only removes false positives, it never adds them.

**Q: My tests are failing. Can I still use `--coverage`?**
A: Yes. Coverage tracks execution, not pass/fail. Even failing tests provide coverage data.

## Limitations and Troubleshooting

### Limitations

- **Dynamic code**: `getattr()`, `globals()`, runtime imports are hard to detect
- **Frameworks**: Django models, Flask, FastAPI routes may appear unused but aren't
- **Test data**: Limited scenarios, your mileage may vary
- **False positives**: Always manually review before deleting code
- **Secrets PoC**: May emit both a provider hit and a generic high-entropy hit for the same token. All tokens are detected only in py files (`.py`, `.pyi`, `.pyw`)
- **Quality limitations**: The current `--quality` flag does not allow you to configure the cyclomatic complexity. 
- **Coverage requires execution**: The `--coverage` flag only helps if you have tests or can run your application. Pure static analysis is still available without it.

### Troubleshooting

1. **Permission Errors**
   ```
   Error: Permission denied when removing function
   ```
   Check file permissions before running in interactive mode.

2. **Missing Dependencies**
   ```
   Interactive mode requires 'inquirer' package
   ```
   Install with: `pip install skylos[interactive]`

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap
- [x] Expand our test cases
- [x] Configuration file support 
- [x] Git hooks integration
- [x] CI/CD integration examples
- [x] Deployment Gatekeeper
- [ ] Further optimization
- [ ] Add new rules
- [ ] Expanding on the `dangerous.py` list
- [x] Porting to uv
- [x] Small integration with typescript
- [ ] Expand and improve on capabilities of Skylos in various other languages
- [ ] Expand the providers for LLMs
- [x] Coverage integration for runtime verification
- [x] Implicit reference detection (f-string patterns, framework decorators)

More stuff coming soon!

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: oha
- **Email**: aaronoh2015@gmail.com
- **GitHub**: [@duriantaco](https://github.com/duriantaco)