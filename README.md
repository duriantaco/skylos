<div align="center">
   <img src="assets/DOG_1.png" alt="Skylos Logo" width="300">
   <h1>Skylos: Guard your Code</h1>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Skylos](https://img.shields.io/badge/Skylos-PR%20Guard-2f80ed?style=flat&logo=github&logoColor=white)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![PyPI version](https://img.shields.io/pypi/v/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
![Security Policy](https://img.shields.io/badge/security-policy-brightgreen)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

⭐ If Skylos saves you time (or has helped you in any way), please star the repo — it helps a lot.

💬 Join the Discord (support + contributors): https://discord.gg/Ftn9t9tErf

> Skylos is a static analysis tool for Python codebases which locates dead code, performs quality checks, and finds security vulnerabilities.

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Performance](#performance)
- [How It Works](#how-it-works)
- [AI-Powered Analysis](#ai-powered-analysis)
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

| Objective | Command | Outcome |
| :--- | :--- | :--- |
| **Hunt Dead Code** | `skylos .` | Prune unreachable functions and unused imports |
| **Precise Hunt** | `skylos . --trace` | Cross-reference with runtime data |
| **Audit Risk & Quality** | `skylos . --secrets --danger --quality` | Security leaks, taint tracking, code rot |
| **Detect Unused Pytest Fixtures** | `skylos . --pytest-fixtures` | Find unused `@pytest.fixture` across tests + conftest |
| **AI-Powered Analysis** | `skylos agent analyze . --model gpt-4.1` | Hybrid static + LLM analysis with project context |
| **AI Audit** | `skylos agent security-audit .` | Deep LLM review with interactive file selection |
| **Automated Repair** | `skylos agent analyze . --fix` | Let the LLM fix what it found |
| **PR Review** | `skylos agent review` | Analyze only git-changed files |
| **Local LLM** | `skylos agent analyze . --base-url http://localhost:11434/v1 --model codellama` | Use Ollama/LM Studio (no API key needed) |
| **Secure the Gate** | `skylos --gate` | Block risky code from merging |
| **Whitelist** | `skylos whitelist 'handle_*'` | Suppress known dynamic patterns |


## Features

### Security & Vulnerability Audit

* **Taint-Flow Tracking**: Follows untrusted input from the API edge to your database to stop SQLi, SSRF, and Path Traversal
* **Credentials Detection**: Detects API keys & secrets (GitHub, GitLab, AWS, Google, SendGrid, private key blocks)
* **Vulnerability Detection**: Flags dangerous patterns including eval/exec, unsafe yaml/pickle loads, and weak cryptographic hashes
* **Implicit Reference Detection**: Catches dynamic patterns like `getattr(mod, f"handle_{x}")`, framework decorators (`@app.route`, `@pytest.fixture`), and f-string dispatch patterns

## AI-Powered Analysis

* **Hybrid Architecture**: Combines static analysis with LLM reasoning for best-of-both-worlds detection
* **Multi-Provider Support**: OpenAI, Anthropic, and local LLMs (Ollama, LM Studio, vLLM)
* **Hallucination Detection**: Finds calls to functions that don't exist in your codebase
* **Logic Bug Detection**: Catches issues that static analysis misses (off-by-one, missing edge cases)
* **Confidence Scoring**: Findings validated by both engines get HIGH confidence

### Codebase Optimization

* **CST-safe removals:** Uses LibCST to remove selected imports or functions (handles multiline imports, aliases, decorators, async etc..)
* **Logic Awareness**: Deep integration for Python frameworks (Django, Flask, FastAPI) and TypeScript (Tree-sitter) to identify active routes and dependencies.
* **Granular Filtering**: Skip lines tagged with `# pragma: no skylos`, `# pragma: no cover`, or `# noqa`

### Operational Governance & Runtime

* **Coverage Integration**: Auto-detects `.skylos-trace` files to verify dead code with runtime data
* **Quality Gates**: Enforces hard thresholds for complexity, nesting, and security risk via `pyproject.toml` to block non-compliant PRs
* **Interactive CLI**: Manually verify and remove/comment-out findings through an `inquirer`-based terminal interface
* **Security-Audit Mode**: Leverages an independent reasoning loop to identify security vulnerabilities

### Pytest Hygiene

* **Unused Fixture Detection**: Finds unused `@pytest.fixture` definitions in `test_*.py` and `conftest.py`
* **Cross-file Resolution**: Tracks fixtures used across modules, not just within the same file

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
| `@pytest.fixture` | Treated as a pytest entrypoint, but can be reported as unused if never referenced |
| `@celery.task` | Entry point → marked as used |
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

## Unused Pytest Fixtures

Skylos can detect pytest fixtures that are defined but never used.

```bash
skylos . --pytest-fixtures
```

This includes fixtures inside conftest.py, since conftest.py is the standard place to store shared test fixtures.


## AI-Powered Analysis

Skylos uses a **hybrid architecture** that combines static analysis with LLM reasoning:

### Why Hybrid?

| Approach | Recall | Precision | Logic Bugs |
|----------|--------|-----------|------------|
| Static only | Low | High | ❌ |
| LLM only | High | Medium | ✅ |
| **Hybrid** | **Highest** | **High** | ✅ |

Research shows LLMs find vulnerabilities that static analysis misses, while static analysis validates LLM suggestions. However, LLM is extremely prone to false positives in dead code because it doesn't actually do real symbol resolution. 

**Note**: Take dead code output from LLM solely with caution

### Agent Commands

| Command | Description |
|---------|-------------|
| `skylos agent analyze PATH` | Hybrid analysis with full project context |
| `skylos agent security-audit PATH` | Security audit with interactive file selection |
| `skylos agent fix PATH` | Generate fix for specific issue |
| `skylos agent review` | Analyze only git-changed files |

### Provider Configuration

Skylos supports cloud and local LLM providers:

```bash
# Cloud - OpenAI (auto-detected from model name)
skylos agent analyze . --model gpt-4.1

# Cloud - Anthropic (auto-detected from model name)
skylos agent analyze . --model claude-sonnet-4-20250514

# Local - Ollama
skylos agent analyze . \
  --provider openai \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b
```

**Note**: You can use the `--model` flag to specify the model that you want. We support Gemini, Groq, Anthropic, ChatGPT and Mistral.

### Keys and configuration

Skylos can use API keys from **(1) `skylos key`**, or **(2) environment variables**.

#### Recommended (interactive)
```bash
skylos key
# opens a menu:
# - list keys
# - add key (openai / anthropic / google / groq / mistral / ...)
# - remove key
```

### Environment Variables

Set defaults to avoid repeating flags:

```bash
# API Keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Default to local Ollama
export SKYLOS_LLM_PROVIDER=openai
export SKYLOS_LLM_BASE_URL=http://localhost:11434/v1
```

### What LLM Analysis Detects

| Category | Examples |
|----------|----------|
| **Hallucinations** | Calls to functions that don't exist |
| **Logic bugs** | Off-by-one, incorrect conditions, missing edge cases |
| **Business logic** | Auth bypasses, broken access control |
| **Context issues** | Problems requiring understanding of intent |

### Local LLM Setup (Ollama)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a code model
ollama pull qwen2.5-coder:7b

# Use with Skylos
skylos agent analyze ./src \
  --provider openai \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b
```

### Recommended Models

| Model | Provider | Use Case |
|-------|----------|----------|
| `gpt-4.1` | OpenAI | Best accuracy |
| `claude-sonnet-4-20250514` | Anthropic | Best reasoning |
| `qwen2.5-coder:7b` | Ollama | Fast local analysis |
| `codellama:13b` | Ollama | Better local accuracy |


## VS Code Extension

Real-time AI-powered code analysis directly in your editor.

<img src="assets/screenshot1.png" alt="Skylos VS Code Extension" width="700" />

### Installation

1. Search "Skylos" in VS Code marketplace or run:
```bash
   ext install oha.skylos-vscode-extension
```

2. Make sure the CLI is installed:
```bash
   pip install skylos
```

3. (Optional) Add your API key for AI features in VS Code Settings → `skylos.openaiApiKey` or `skylos.anthropicApiKey`

### How It Works

| Layer | Trigger | What It Does |
|-------|---------|--------------|
| **Static Analysis** | On save | Runs Skylos CLI for dead code, secrets, dangerous patterns |
| **AI Watcher** | On idle (2s) | Sends changed functions to GPT-4/Claude for bug detection |

### Features

- **Real-time Analysis**: Detects bugs as you type — no save required
- **CodeLens Buttons**: "Fix with AI" and "Dismiss" appear inline on error lines
- **Streaming Fixes**: See fix progress in real-time
- **Smart Caching**: Only re-analyzes functions that actually changed
- **Multi-Provider**: Choose between OpenAI and Anthropic

### Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `skylos.aiProvider` | `"openai"` | `"openai"` or `"anthropic"` |
| `skylos.openaiApiKey` | `""` | Your OpenAI API key |
| `skylos.anthropicApiKey` | `""` | Your Anthropic API key |
| `skylos.idleMs` | `2000` | Wait time before AI analysis (ms) |
| `skylos.runOnSave` | `true` | Run Skylos CLI on save |
| `skylos.enableSecrets` | `true` | Scan for hardcoded secrets |
| `skylos.enableDanger` | `true` | Flag dangerous patterns |

### Usage

| Action | Result |
|--------|--------|
| Save a Python file | Skylos CLI scans the workspace |
| Type and pause | AI analyzes changed functions |
| Click "Fix with AI" | Generates fix with diff preview |
| `Cmd+Shift+P` -> "Skylos: Scan Workspace" | Full project scan |

### Privacy

- Static analysis runs 100% locally
- AI features send only changed function code to your configured provider
- We DO NOT collect any telemetry or data

**[Install from VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=oha.skylos-vscode-extension)**


## Gating

Block bad code before it merges. Configure thresholds, run locally, then automate in CI.

### Initialize Configuration
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

### Free Tier

Run scans locally with exit codes:

```bash
skylos . --danger --gate
```

- Exit code `0` = passed
- Exit code `1` = failed

Use in any CI system:

```yaml
name: Skylos Quality Gate

on:
  pull_request:
    branches: [main, master]

jobs:
  skylos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install skylos
      - run: skylos . --danger --gate
```

> **Limitation:** Anyone with repo access can delete or modify this workflow.

---

### Pro Tier

Server-controlled GitHub checks that **cannot be bypassed** by developers.

### Quick Setup

```bash
pip install skylos
skylos sync setup
```

### How It Works

1. Developer opens PR → GitHub App creates required check ("Queued")
2. Scan runs → Results upload to Skylos server
3. Server updates check → Pass ✅ or Fail ❌
4. Developer **cannot merge** until check passes

### Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Local scans | ✅ | ✅ |
| `--gate` exit codes | ✅ | ✅ |
| GitHub Actions | ✅ (DIY) | ✅ (auto) |
| Developer can bypass? | Yes | **No** |
| Server-controlled check | ❌ | ✅ |
| Slack/Discord alerts | ❌ | ✅ |

### GitHub App Setup

1. **Dashboard -> Settings -> Install GitHub App**
2. Select your repository
3. In GitHub repo settings:
   - Settings -> Branches -> Add rule -> `main`
   - Require status checks
   - Select "Skylos Quality Gate"

### Add Token to GitHub

Repo **Settings → Secrets → Actions → New secret**
- Name: `SKYLOS_TOKEN`  
- Value: *(from Dashboard → Settings)*

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
| `--sarif` | SARIF | GitHub Code Scanning, IDE integration |
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

### Legacy AI Flags (These will be deprecated in the next updated)

These flags work on the main `skylos` command for quick operations:

```bash
# LLM-powered audit (single file)
skylos . --audit

# Auto-fix with LLM
skylos . --fix

# Specify model
skylos . --audit --model claude-haiku-4-5-20251001
```

> **Note:** For full project context and better results, use `skylos agent analyze` instead.

### Combine Everything
```bash
skylos . --danger --secrets --quality  # All static scans
skylos agent analyze . --fix           # Full AI-assisted cleanup
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

### Main Command Flags
```
Usage: skylos [OPTIONS] PATH

Arguments:
  PATH  Path to the Python project to analyze

Options:
  -h, --help                   Show this help message and exit
  --json                       Output raw JSON instead of formatted text  
  --tree                       Output results in tree format
  --table                      Output results in table format via the CLI
  --sarif                      Output SARIF format for GitHub/IDE integration
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
  --list-default-excludes      List the default excluded folders
  --secrets                    Scan for api keys/secrets
  --danger                     Scan for dangerous code
  --quality                    Code complexity and maintainability
  --trace                      Run tests with coverage first
  --audit                      LLM-powered logic review (legacy-will be deprecated)
  --fix                        LLM auto-repair (legacy-will be deprecated)
  --model MODEL                LLM model (default: gpt-4.1)
  --gate                       Fail on threshold breach (for CI)
  --force                      Bypass quality gate (emergency override)
```

### Agent Command Flags
```
Usage: skylos agent <command> [OPTIONS] PATH

Commands:
  analyze             Hybrid static + LLM analysis with project context
  security-audit      Deep LLM security audit
  fix                 Generate fix for specific issue
  review              Analyze only git-changed files

Options (all agent commands):
  --model MODEL                LLM model to use (default: gpt-4.1)
  --provider PROVIDER          Force provider: openai or anthropic
  --base-url URL               Custom endpoint for local LLMs
  --format FORMAT              Output: table, tree, json, sarif
  -o, --output FILE            Write output to file

Agent analyze options:
  --min-confidence LEVEL       Filter: high, medium, low
  --fix                        Generate fix proposals
  --apply                      Apply fixes to files
  --yes                        Auto-approve prompts

Agent fix options:
  --line, -l LINE              Line number of issue (required)
  --message, -m MSG            Description of issue (required)
```

### Commands 
```
Commands:
  skylos PATH                  Analyze a project (static analysis)
  skylos agent analyze PATH    Hybrid static + LLM analysis
  aud PATH      Deep LLM audit with file selection
  skylos agent fix PATH        Fix specific issue
  skylos agent review          Review git-changed files only
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

**Q: What does `--trace` do?**
A: It runs `pytest` (or `unittest`) with coverage tracking before analysis. Functions that actually executed are marked as used with 100% confidence, eliminating false positives from dynamic dispatch patterns.

**Q: Do I need 100% test coverage for `--trace` to be useful?**
A: No. However, we **STRONGLY** encourage you to have tests. Any coverage helps. If you have 30% test coverage, that's 30% of your code verified. The other 70% still uses static analysis. Coverage only removes false positives, it never adds them.

**Q: Why are fixtures in `conftest.py` showing up as unused?**
A: `conftest.py` is the standard place for shared fixtures. If a fixture is defined there but never referenced by any test, Skylos will report it as unused. This is normal and safe to review.

**Q: My tests are failing. Can I still use `--trace`?**
A: Yes. Coverage tracks execution, not pass/fail. Even failing tests provide coverage data.

**Q: What's the difference between `skylos . --audit` and `skylos agent audit`?**
A: `skylos agent audit` uses the new hybrid architecture with full project context (`defs_map`), enabling detection of hallucinations and cross-file issues. The `--audit` flag is legacy and lacks project context.

**Q: Can I use local LLMs instead of OpenAI/Anthropic?**
A: Yes! Use `--base-url` to point to Ollama, LM Studio, or any OpenAI-compatible endpoint. No API key needed for localhost.

## Limitations and Troubleshooting

### Limitations

- **Dynamic code**: `getattr()`, `globals()`, runtime imports are hard to detect
- **Frameworks**: Django models, Flask, FastAPI routes may appear unused but aren't
- **Test data**: Limited scenarios, your mileage may vary
- **False positives**: Always manually review before deleting code
- **Secrets PoC**: May emit both a provider hit and a generic high-entropy hit for the same token. All tokens are detected only in py files (`.py`, `.pyi`, `.pyw`)
- **Quality limitations**: The current `--quality` flag does not allow you to configure the cyclomatic complexity. 
- **Coverage requires execution**: The `--trace` flag only helps if you have tests or can run your application. Pure static analysis is still available without it.
- **LLM limitations**: AI analysis requires API access (cloud) or local setup (Ollama). Results depend on model quality.

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

3. **No API Key Found**
   ```bash
   # For cloud providers
   export OPENAI_API_KEY="sk-..."
   export ANTHROPIC_API_KEY="sk-ant-..."
   
   # For local LLMs (no key needed)
   skylos agent analyze . --base-url http://localhost:11434/v1 --model codellama
   ```

4. **Local LLM Connection Refused**
   ```bash
   # Verify Ollama is running
   curl http://localhost:11434/v1/models
   
   # Check LM Studio
   curl http://localhost:1234/v1/models
   ```

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
- [x] Expand the providers for LLMs (OpenAI, Anthropic, Ollama, LM Studio, vLLM)
- [x] Expand the LLM portion for detecting dead/dangerous code (hybrid architecture)
- [x] Coverage integration for runtime verification
- [x] Implicit reference detection (f-string patterns, framework decorators)

More stuff coming soon!

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: oha
- **Email**: aaronoh2015@gmail.com
- **GitHub**: [@duriantaco](https://github.com/duriantaco)
- **Discord**: https://discord.gg/Ftn9t9tErf