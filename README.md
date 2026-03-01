<div align="center">
    <img src="assets/DOG_1.png" alt="Skylos - Python SAST and Dead Code Detection Tool" width="300">
    <h1>Skylos: Python SAST, Dead Code Detection & Security Auditor</h1>
    <h3>The hybrid static analysis tool for Python. Finds dead code, security leaks, quality rot with agentic AI options and MCP integration.</h3>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Skylos](https://img.shields.io/badge/Skylos-PR%20Guard-2f80ed?style=flat&logo=github&logoColor=white)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
![CI/CD Ready](https://img.shields.io/badge/CI%2FCD-30s%20Setup-brightgreen?style=flat&logo=github-actions&logoColor=white)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![PyPI version](https://img.shields.io/pypi/v/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
![Security Policy](https://img.shields.io/badge/security-policy-brightgreen)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

⭐ If Skylos saves you time (or has helped you in any way), please star the repo — it helps a lot.

💬 Join the Discord (support + contributors): https://discord.gg/Ftn9t9tErf

📖 **[Website](https://skylos.dev)** · **[Documentation](https://docs.skylos.dev)** · **[Blog](https://skylos.dev/blog)** · **[VS Code Extension](https://marketplace.visualstudio.com/items?itemName=oha.skylos-vscode-extension)**

---

### Why Skylos over Vulture?

| | Skylos | Vulture |
|:---|:---|:---|
| **Recall** | **98.1%** (51/52) | 84.6% (44/52) |
| **False Positives** | **220** | 644 |
| **Framework-aware** (FastAPI, Django, pytest) | Yes | No |
| **Security scanning** (secrets, SQLi, SSRF) | Yes | No |
| **AI-powered analysis** | Yes | No |
| **CI/CD quality gates** | Yes | No |
| **TypeScript + Go support** | Yes | No |

> Benchmarked on 9 popular Python repos (350k+ combined stars) + TypeScript ([consola](https://github.com/unjs/consola)). Every finding manually verified. [Full case study →](#skylos-vs-vulture-benchmark)

---

# What is Skylos?

> Skylos is a privacy-first SAST tool for Python, TypeScript, and Go that bridges the gap between traditional static analysis and AI agents. It detects dead code, security vulnerabilities (SQLi, SSRF, Secrets), and code quality issues with high precision.

Unlike standard linters (like Vulture or Bandit) that struggle with dynamic Python patterns, Skylos uses a **hybrid engine** (AST + optional Local/Cloud LLM). This allows it to:

1.  **Eliminate False Positives:** Distinguishes between truly dead code and framework magic (e.g., `pytest.fixture`, `FastAPI` routes).
2.  **Verify via Runtime:** Optional `--trace` mode validates findings against actual runtime execution.
3.  **Find Logic Bugs:** Goes beyond linting to find deep logic errors that regex-based tools miss.

---

### 🚀 **New to Skylos? Start with CI/CD Integration**

```bash
# Generate a GitHub Actions workflow in 30 seconds
skylos cicd init

# Commit and push to activate
git add .github/workflows/skylos.yml && git push
```

**What you get:**
- Automatic dead code detection on every PR
- Security vulnerability scanning (SQLi, secrets, dangerous patterns)
- Quality gate that fails builds on critical issues
- Inline PR review comments with file:line links
- GitHub Annotations visible in the "Files Changed" tab

**No configuration needed** - works out of the box with sensible defaults. See [CI/CD section](#cicd) for customization.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Skylos vs Vulture](#skylos-vs-vulture-benchmark)
- [Projects Using Skylos](#projects-using-skylos)
- [How It Works](#how-it-works)
- [Agent Analysis](#agent-analysis)
- [CI/CD](#cicd)
- [MCP Server](#mcp-server)
- [Baseline Tracking](#baseline-tracking)
- [Gating](#gating)
- [VS Code Extension](#vsc-extension)
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
| **Auto-Remediate** | `skylos agent remediate . --auto-pr` | Scan, fix, test, and open a PR — end to end |
| **PR Review** | `skylos agent review` | Analyze only git-changed files |
| **Local LLM** | `skylos agent analyze . --base-url http://localhost:11434/v1 --model codellama` | Use Ollama/LM Studio (no API key needed) |
| **Secure the Gate** | `skylos --gate` | Block risky code from merging |
| **Whitelist** | `skylos whitelist 'handle_*'` | Suppress known dynamic patterns |
| **🚀 Setup CI/CD** | `skylos cicd init` | Generate GitHub Actions workflow in 30 seconds |
| **Quality Gate (CI)** | `skylos cicd gate -i results.json` | Fail builds when issues found |
| **PR Review (CI)** | `skylos cicd review -i results.json` | Post inline comments on PRs |

### Demo
[![Skylos demo](https://img.youtube.com/vi/BjMdSP2zZl8/0.jpg)](https://www.youtube.com/watch?v=BjMdSP2zZl8)

Backup (GitHub): https://github.com/duriantaco/skylos/discussions/82

## Key Capabilities

### Python Security Scanner (SAST)
* **Taint Analysis:** Traces untrusted input from API endpoints to databases to prevent SQL Injection and XSS.
* **Secrets Detection:** Hunts down hardcoded API keys (AWS, Stripe, OpenAI) and private credentials before commit.
* **Vulnerability Checks:** Flags dangerous patterns like `eval()`, unsafe `pickle`, and weak cryptography.

### Dead Code Detection & Cleanup
* **Find Unused Code:** Identifies unreachable functions, orphan classes, and unused imports with confidence scoring.
* **Smart Tracing:** Distinguishes between truly dead code and dynamic frameworks (Flask/Django routes, Pytest fixtures).
* **Safe Pruning:** Uses LibCST to safely remove dead code without breaking syntax.

### Agentic AI & Hybrid Analysis
* **Context-Aware Audits:** Combines static analysis speed with LLM reasoning to validate findings and filter noise.
* **Automated Fixes:** `skylos agent fix` autonomously patches security flaws and removes dead code.
* **End-to-End Remediation:** `skylos agent remediate` scans, fixes, tests, and opens PRs — fully autonomous DevOps agent.
* **100% Local Privacy:** Supports Ollama and Local LLMs so your code never leaves your machine.

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
| TypeScript/TSX | Tree-sitter | ✅ | ✅ | ✅ |
| Go | Standalone binary | ✅ | - | - |

No Node.js required — TypeScript parser is built-in via Tree-sitter. Languages are auto-detected by file extension. Mixed-language repos (e.g. Python + TypeScript) work out of the box.

#### TypeScript Rules

| Rule | ID | What It Catches |
|------|-----|-----------------|
| **Dead Code** | | |
| Functions | - | Unused functions, arrow functions, and overloads |
| Classes | - | Unused classes, interfaces, enums, and type aliases |
| Imports | - | Unused named, default, and namespace imports |
| Methods | - | Unused methods (lifecycle methods excluded) |
| **Security** | | |
| eval() | SKY-D201 | `eval()` usage |
| Dynamic exec | SKY-D202 | `exec()`, `new Function()`, `setTimeout` with string |
| XSS | SKY-D226 | `innerHTML`, `outerHTML`, `document.write()`, `dangerouslySetInnerHTML` |
| SQL injection | SKY-D211 | Template literal / f-string in SQL query |
| Command injection | SKY-D212 | `child_process.exec()`, `os.system()` |
| SSRF | SKY-D216 | `fetch()`/`axios` with variable URL |
| Open redirect | SKY-D230 | `res.redirect()` with variable argument |
| Weak hash | SKY-D207/D208 | MD5 / SHA1 usage |
| Prototype pollution | SKY-D510 | `__proto__` access |
| Dynamic require | SKY-D245 | `require()` with variable argument |
| JWT bypass | SKY-D246 | `jwt.decode()` without verification |
| CORS wildcard | SKY-D247 | `cors({ origin: '*' })` |
| Internal URL | SKY-D248 | Hardcoded `localhost`/`127.0.0.1` URLs |
| Insecure random | SKY-D250 | `Math.random()` for security-sensitive ops |
| Sensitive logs | SKY-D251 | Passwords/tokens passed to `console.log()` |
| Insecure cookie | SKY-D252 | Missing `httpOnly`/`secure` flags |
| Timing attack | SKY-D253 | `===`/`==` comparison of secrets |
| Storage tokens | SKY-D270 | Sensitive data in `localStorage`/`sessionStorage` |
| Error disclosure | SKY-D271 | `error.stack`/`.sql` sent in HTTP response |
| Secrets | SKY-S101 | Hardcoded API keys + high-entropy strings |
| **Quality** | | |
| Complexity | SKY-Q301 | Cyclomatic complexity exceeds threshold |
| Nesting depth | SKY-Q302 | Too many nested levels |
| Function length | SKY-C304 | Function exceeds line limit |
| Too many params | SKY-C303 | Function has too many parameters |
| Duplicate condition | SKY-Q305 | Identical condition in if-else-if chain |
| Await in loop | SKY-Q402 | `await` inside for/while loop |
| Unreachable code | SKY-UC002 | Code after return/throw/break/continue |

**Framework-aware:** Next.js convention exports (`page.tsx`, `layout.tsx`, `route.ts`, `middleware.ts`), config exports (`getServerSideProps`, `generateMetadata`, `revalidate`), React patterns (`memo`, `forwardRef`), and exported custom hooks (`use*`) are automatically excluded from dead code reports.

TypeScript dead code detection tracks: callbacks, type annotations, generics, decorators, inheritance (`extends`), object shorthand, spread, re-exports, and `typeof` references. Benchmarked at 95% recall with 0 false positives on alive code.

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

### 🎯 What's Next?

After installation, we recommend:

1. **Set up CI/CD (30 seconds):**
   ```bash
   skylos cicd init
   git add .github/workflows/skylos.yml && git push
   ```
   This will automatically scan every PR for dead code and security issues.

2. **Run your first scan:**
   ```bash
   skylos .                              # Dead code only
   skylos . --danger --secrets           # Include security checks
   ```

3. **Try AI-powered analysis:**
   ```bash
   skylos agent analyze . --model gpt-4.1
   ```

4. **Add a badge to your README:**
   ```markdown
   [![Analyzed with Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python&logoColor=white)](https://github.com/duriantaco/skylos)
   ```
   Shows others you maintain clean, secure code!

[See all commands in the Quick Start table](#quick-start)

---

## Skylos vs. Vulture Benchmark

We benchmarked Skylos against Vulture on **9 of the most popular Python repositories on GitHub** — 350k+ combined stars, covering HTTP clients, web frameworks, CLI tools, data validation, terminal UIs, and progress bars. Every single finding was **manually verified** against the source code. No automated labelling, no cherry-picking.

### Why These 9 Repos?

We deliberately chose projects that stress-test dead code detection in different ways:

| Repository | Stars | What It Tests |
|:---|---:|:---|
| [psf/requests](https://github.com/psf/requests) | 53k | `__init__.py` re-exports, Sphinx conf, pytest classes |
| [pallets/click](https://github.com/pallets/click) | 17k | IO protocol methods (`io.RawIOBase` subclasses), nonlocal closures |
| [encode/starlette](https://github.com/encode/starlette) | 10k | ASGI interface params, polymorphic dispatch, public API methods |
| [Textualize/rich](https://github.com/Textualize/rich) | 51k | `__rich_console__` protocol, sentinel vars via `f_locals`, metaclasses |
| [encode/httpx](https://github.com/encode/httpx) | 14k | Transport/auth protocol methods, zero dead code (pure FP test) |
| [pallets/flask](https://github.com/pallets/flask) | 69k | Jinja2 template globals, Werkzeug protocol methods, extension hooks |
| [pydantic/pydantic](https://github.com/pydantic/pydantic) | 23k | Mypy plugin hooks, hypothesis `@resolves`, `__getattr__` config |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | 82k | 100+ OpenAPI spec model fields, Starlette base class overrides |
| [tqdm/tqdm](https://github.com/tqdm/tqdm) | 30k | Keras/Dask callbacks, Rich column rendering, pandas monkey-patching |

No repo was excluded for having unfavorable results. We include repos where Vulture beats Skylos (click, starlette, tqdm).

### Results

| Repository | Dead Items | Skylos TP | Skylos FP | Vulture TP | Vulture FP |
|:---|---:|---:|---:|---:|---:|
| psf/requests | 6 | 6 | 35 | 6 | 58 |
| pallets/click | 7 | 7 | 8 | 6 | 6 |
| encode/starlette | 1 | 1 | 4 | 1 | 2 |
| Textualize/rich | 13 | 13 | 14 | 10 | 8 |
| encode/httpx | 0 | 0 | 6 | 0 | 59 |
| pallets/flask | 7 | 7 | 12 | 6 | 260 |
| pydantic/pydantic | 11 | 11 | 93 | 10 | 112 |
| fastapi/fastapi | 6 | 6 | 30 | 4 | 102 |
| tqdm/tqdm | 1 | 0 | 18 | 1 | 37 |
| **Total** | **52** | **51** | **220** | **44** | **644** |

| Metric | Skylos | Vulture |
|:---|:---|:---|
| **Recall** | **98.1%** (51/52) | 84.6% (44/52) |
| **False Positives** | **220** | 644 |
| **Dead items found** | **51** | 44 |

Skylos finds **7 more dead items** than Vulture with **3x fewer false positives**.

### Why Skylos Produces Fewer False Positives

Vulture uses flat name matching — if the bare name `X` appears anywhere as a string or identifier, all definitions named `X` are considered used. This works well for simple cases but drowns in noise on framework-heavy codebases:

- **Flask** (260 Vulture FP): Vulture flags every Jinja2 template global, Werkzeug protocol method, and Flask extension hook. Skylos recognizes Flask/Werkzeug patterns.
- **Pydantic** (112 Vulture FP): Vulture flags all config class annotations, `TYPE_CHECKING` imports, and mypy plugin hooks. Skylos understands Pydantic model fields and `__getattr__` dynamic access.
- **FastAPI** (102 Vulture FP): Vulture flags 100+ OpenAPI spec model fields (Pydantic `BaseModel` attributes like `maxLength`, `exclusiveMinimum`). Skylos recognizes these as schema definitions.
- **httpx** (59 Vulture FP): Vulture flags every transport and auth protocol method. Skylos suppresses interface implementations.

### Where Skylos Still Loses (Honestly)

- **click** (8 vs 6 FP): IO protocol methods (`readable`, `readinto`) on `io.RawIOBase` subclasses — called by Python's IO stack, not by direct call sites.
- **starlette** (4 vs 2 FP): Instance method calls across files (`obj.method()`) not resolved back to class definitions.
- **tqdm** (18 vs 37 FP, 0 vs 1 TP): Skylos misses 1 dead function in `__init__.py` because it suppresses `__init__.py` definitions as potential re-exports.

> *Reproduce any benchmark: `cd real_life_examples/{repo} && python3 ../benchmark_{repo}.py`*
>
> *Full methodology and per-repo breakdowns in the [skylos-demo](https://github.com/duriantaco/skylos-demo) repository.*

### Skylos vs. Knip (TypeScript)

We also benchmarked Skylos against [Knip](https://knip.dev) on a real-world TypeScript library:

| | [unjs/consola](https://github.com/unjs/consola) (7k stars, 21 files, ~2,050 LOC) |
|:---|:---|
| **Dead items** | 4 (entire orphaned `src/utils/format.ts` module) |

| Metric | Skylos | Knip |
|:---|:---|:---|
| **Recall** | **100%** (4/4) | **100%** (4/4) |
| **Precision** | **36.4%** | 7.5% |
| **F1 Score** | **53.3%** | 14.0% |
| **Speed** | **6.83s** | 11.08s |

Both tools find all dead code. Skylos has **~5x better precision** — Knip incorrectly flags package entry points as dead files (its `package.json` exports point to `dist/` not `src/`) and reports public API re-exports as unused.

> *Reproduce: `cd real_life_examples/consola && python3 ../benchmark_consola.py`*

---

## Projects Using Skylos

Show you're maintaining clean, secure code! Add your project:

[![Analyzed with Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python&logoColor=white)](https://github.com/duriantaco/skylos)

**Featured Projects:**

| Project | Description | Badge |
|---------|-------------|-------|
| [Skylos](https://github.com/duriantaco/skylos) | Python SAST & dead code detection | [![Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python)](https://github.com/duriantaco/skylos) |
| *Your project here* | [Add yours!](https://github.com/duriantaco/skylos/issues/new?title=Add%20my%20project%20to%20showcase&body=Project:%20%0AURL:%20%0ADescription:%20) | |

**Why share?**
- Show commitment to code quality
- Get a backlink to your project
- Join the community of quality-focused developers

[Add your project →](https://github.com/duriantaco/skylos/issues/new?title=Add%20my%20project%20to%20showcase&body=Project:%20%0AURL:%20%0ADescription:%20)

---

## How it works

Skylos builds a reference graph of your entire codebase - who defines what, who calls what, across all files.

```
Parse all files -> Build definition map -> Track references -> Find orphans (zero refs = dead)
```

### High Precision & Confidence Scoring
Static analysis often struggles with Python's dynamic nature (e.g., `getattr`, `pytest.fixture`). Skylos minimizes false positives through:

1.  **Confidence Scoring:** Grades findings (High/Medium/Low) so you only see what matters.
2.  **Hybrid Verification:** Uses LLM reasoning to double-check static findings before reporting.
3.  **Runtime Tracing:** Optional `--trace` mode validates "dead" code against actual runtime execution.

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

When Skylos sees Flask, Django, FastAPI, Next.js, or React imports, it adjusts scoring automatically:

| Pattern | Handling |
|---------|----------|
| `@app.route`, `@router.get` | Entry point → marked as used |
| `@pytest.fixture` | Treated as a pytest entrypoint, but can be reported as unused if never referenced |
| `@celery.task` | Entry point → marked as used |
| `getattr(mod, "func")` | Tracks dynamic reference |
| `getattr(mod, f"handle_{x}")` | Tracks pattern `handle_*` |
| Next.js `page.tsx`, `layout.tsx`, `route.ts` | Default/named exports → marked as used |
| Next.js `getServerSideProps`, `generateMetadata` | Config exports → marked as used |
| `React.memo()`, `forwardRef()` | Wrapped components → marked as used |
| Exported `use*` hooks | Custom hooks → marked as used |

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


## Agent Analysis

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
| `skylos agent remediate PATH` | End-to-end: scan, fix, test, and create PR |

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

### Remediation Agent

The remediation agent automates the full fix lifecycle. It scans your project, prioritizes findings, generates fixes via the LLM, validates each fix by running your test suite, and optionally opens a PR.

```bash
# Preview what would be fixed (safe, no changes)
skylos agent remediate . --dry-run

# Fix up to 5 critical/high issues, validate with tests
skylos agent remediate . --max-fixes 5 --severity high

# Full auto: fix, test, create PR
skylos agent remediate . --auto-pr --model gpt-4.1

# Use a custom test command
skylos agent remediate . --test-cmd "pytest test/ -x"
```

**Safety guardrails:**
- Dry run by default — use `--dry-run` to preview without touching files
- Fixes that break tests are automatically reverted
- Low-confidence fixes are skipped
- After applying a fix, Skylos re-scans to confirm the finding is actually gone
- `--auto-pr` always works on a new branch, never touches main
- `--max-fixes` prevents runaway changes (default 10)

### Recommended Models

| Model | Provider | Use Case |
|-------|----------|----------|
| `gpt-4.1` | OpenAI | Best accuracy |
| `claude-sonnet-4-20250514` | Anthropic | Best reasoning |
| `qwen2.5-coder:7b` | Ollama | Fast local analysis |
| `codellama:13b` | Ollama | Better local accuracy |

# CI/CD

Run Skylos in your CI pipeline with quality gates, GitHub annotations, and PR review comments.

## Quick Start (30 seconds)

```bash
# Auto-generate a GitHub Actions workflow
skylos cicd init

# Commit and activate
git add .github/workflows/skylos.yml && git push
```

That's it! Your next PR will have:
- Dead code detection
- Security scanning (SQLi, SSRF, secrets)
- Quality checks
- Inline PR comments with clickable file:line links
- Quality gate that fails builds on critical issues

## Commands

### `skylos cicd init`

Generates a ready-to-use GitHub Actions workflow.

```bash
skylos cicd init
skylos cicd init --triggers pull_request schedule
skylos cicd init --analysis security quality
skylos cicd init --python-version 3.11
skylos cicd init --llm --model gpt-4.1 
skylos cicd init --no-baseline
skylos cicd init -o .github/workflows/security.yml
```

### `skylos cicd gate`

Checks findings against your quality gate. Exits `0` (pass) or `1` (fail). Uses the same `check_gate()` as `skylos . --gate`.

```bash
skylos . --danger --quality --secrets --json > results.json 2>/dev/null
skylos cicd gate --input results.json
skylos cicd gate --input results.json --strict
skylos cicd gate --input results.json --summary
```

You can also use the main CLI directly:

```bash
skylos . --gate --summary
```

Configure thresholds in `pyproject.toml`:

```toml
[tool.skylos.gate]
fail_on_critical = true
max_critical = 0
max_high = 5
max_security = 10
max_quality = 10
```

### `skylos cicd annotate`

Emits GitHub Actions annotations (`::error`, `::warning`, `::notice`). Uses the same `_emit_github_annotations()` as `skylos . --github`, with sorting and a 50-annotation cap.

```bash
skylos cicd annotate --input results.json
skylos cicd annotate --input results.json --severity high
skylos cicd annotate --input results.json --max 30

skylos . --github
```

### `skylos cicd review`

Posts inline PR review comments and a summary via `gh` CLI. Only comments on lines changed in the PR.

```bash
skylos cicd review --input results.json
skylos cicd review --input results.json --pr 20
skylos cicd review --input results.json --summary-only
skylos cicd review --input results.json --max-comments 10
skylos cicd review --input results.json --diff-base origin/develop
```

In GitHub Actions, PR number and repo are auto-detected. Requires `GH_TOKEN`.

## How It Fits Together

The gate and annotation logic lives in the core Skylos modules (`gatekeeper.py` and `cli.py`). The `cicd` commands are convenience wrappers that read from a JSON file and call the same functions:

| `skylos cicd` command | Calls |
|-----------------------|-------|
| `gate` | `gatekeeper.run_gate_interaction(summary=True)` |
| `annotate` | `cli._emit_github_annotations(max_annotations=50)` |
| `review` | New — `cicd/review.py` (PR comments via `gh api`) |
| `init` | New — `cicd/workflow.py` (YAML generation) |

## Tips

- **Run analysis once, consume many times** — use `--json > results.json 2>/dev/null` then pass `--input results.json` to each subcommand.
- **Baseline** — run `skylos baseline .` to snapshot existing findings, then `--baseline` in CI to only flag new issues.
- **Local testing** — all commands work locally. `gate` and `annotate` print to stdout. `review` requires `gh` CLI.

## MCP Server

Skylos exposes its analysis capabilities as an MCP (Model Context Protocol) server, allowing AI assistants like Claude Desktop to scan your codebase directly.

### Setup

```bash
pip install skylos
```

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "skylos": {
      "command": "python",
      "args": ["-m", "skylos_mcp.server"]
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `analyze` | Dead code detection (unused functions, imports, classes, variables) |
| `security_scan` | Security vulnerability scan (`--danger` equivalent) |
| `quality_check` | Code quality and complexity analysis (`--quality` equivalent) |
| `secrets_scan` | Hardcoded secrets detection (`--secrets` equivalent) |
| `remediate` | End-to-end: scan, generate LLM fixes, validate with tests |

### Available Resources

| Resource | URI | Description |
|----------|-----|-------------|
| Latest result | `skylos://results/latest` | Most recent analysis run |
| Result by ID | `skylos://results/{run_id}` | Specific analysis run |
| List results | `skylos://results` | All stored analysis runs |

### Usage in Claude Desktop

Once configured, you can ask Claude:

- "Scan my project for security issues" → calls `security_scan`
- "Check code quality in src/" → calls `quality_check`
- "Find hardcoded secrets" → calls `secrets_scan`
- "Fix security issues in my project" → calls `remediate`

## Baseline Tracking

Baseline tracking lets you snapshot existing findings so CI only flags **new** issues introduced by a PR.

```bash
# Create baseline from current state
skylos baseline .

# Run analysis, only show findings NOT in the baseline
skylos . --danger --secrets --quality --baseline

# In CI: compare against baseline
skylos . --danger --baseline --gate
```

The baseline is stored in `.skylos/baseline.json`. Commit this file to your repo so CI can use it.

## VS Code Extension

Real-time AI-powered code analysis directly in your editor.

<img src="editors/vscode/media/vsce.gif" alt="Skylos VS Code Extension — inline dead code detection, security scanning, and CodeLens actions" width="700" />

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

#### New Features
- **MCP Server Support**: Connect Skylos directly to Claude Desktop or any MCP client to chat with your codebase.
- **CI/CD Agents**: Autonomous bots that scan, fix, test, and open PRs automatically in your pipeline.
- **Hybrid Verification**: Eliminates false positives by verifying static findings with LLM reasoning.

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
| `--table` | Rich Table | Classic Rich table output instead of TUI. |
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

| Rule | ID | What It Catches |
|------|-----|-----------------|
| **Injection** | | |
| SQL injection | SKY-D211 | `cur.execute(f"SELECT * FROM users WHERE name='{name}'")` |
| SQL raw query | SKY-D217 | `sqlalchemy.text()`, `pandas.read_sql()`, Django `.raw()` with tainted input |
| Command injection | SKY-D212 | `os.system()`, `subprocess(shell=True)` with tainted input |
| SSRF | SKY-D216 | `requests.get(request.args["url"])` |
| Path traversal | SKY-D215 | `open(request.args.get("p"))` |
| XSS (mark_safe) | SKY-D226 | Untrusted content passed to `mark_safe()` / `Markup()` |
| XSS (template) | SKY-D227 | Inline template with autoescape disabled |
| XSS (HTML build) | SKY-D228 | HTML built from unescaped user input |
| Open redirect | SKY-D230 | User-controlled URL passed to `redirect()` |
| **Dangerous Calls** | | |
| eval() | SKY-D201 | Dynamic code execution via `eval()` |
| exec() | SKY-D202 | Dynamic code execution via `exec()` |
| os.system() | SKY-D203 | OS command execution |
| pickle.load | SKY-D204 | Unsafe deserialization |
| yaml.load | SKY-D206 | `yaml.load()` without SafeLoader |
| Weak hash (MD5) | SKY-D207 | `hashlib.md5()` |
| Weak hash (SHA1) | SKY-D208 | `hashlib.sha1()` |
| shell=True | SKY-D209 | `subprocess` with `shell=True` |
| TLS disabled | SKY-D210 | `requests` with `verify=False` |
| Unsafe deserialization | SKY-D233 | `marshal.loads`, `shelve.open`, `jsonpickle.decode`, `dill` |
| **Web Security** | | |
| CORS misconfiguration | SKY-D231 | Wildcard origins, credential leaks, overly permissive headers |
| JWT vulnerabilities | SKY-D232 | `algorithms=['none']`, missing verification, weak secrets |
| Mass assignment | SKY-D234 | Django `Meta.fields = '__all__'` exposes all model fields |
| **Supply Chain** | | |
| Hallucinated dependency | SKY-D222 | Imported package doesn't exist on PyPI (CRITICAL) |
| Undeclared dependency | SKY-D223 | Import not declared in requirements.txt / pyproject.toml |
| **MCP Security** | | |
| Tool description poisoning | SKY-D240 | Prompt injection in MCP tool metadata |
| Unauthenticated transport | SKY-D241 | SSE/HTTP MCP server without auth middleware |
| Permissive resource URI | SKY-D242 | Path traversal via MCP resource URI template |
| Network-exposed MCP | SKY-D243 | MCP server bound to `0.0.0.0` without auth |
| Hardcoded secrets in MCP | SKY-D244 | Secrets in MCP tool parameter defaults |

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
| Async Blocking | SKY-Q401 | Detects blocking calls inside async functions that kill server throughput |
| God class | SKY-Q501 | Class has too many methods/attributes |
| Coupling (CBO) | SKY-Q701 | High inter-class coupling (7 dependency types: inheritance, type hints, instantiation, attribute access, imports, decorators, protocol/ABC) |
| Cohesion (LCOM) | SKY-Q702 | Low class cohesion — disconnected method groups that should be split (LCOM1/4/5 metrics with Union-Find) |
| **Architecture** | | |
| Distance from Main Sequence | SKY-Q802 | Module far from ideal balance of abstractness vs instability |
| Zone warning | SKY-Q803 | Module in Zone of Pain (rigid) or Zone of Uselessness (throwaway) |
| DIP violation | SKY-Q804 | Stable module depends on unstable module (Dependency Inversion Principle) |
| **Structure** | | |
| Too many arguments | SKY-C303 | Functions with >5 args |
| Function too long | SKY-C304 | Functions >50 lines |
| **Logic** | | |
| Mutable default | SKY-L001 | `def foo(x=[])` - causes state leaks |
| Bare except | SKY-L002 | `except:` swallows SystemExit |
| Dangerous comparison | SKY-L003 | `x == None` instead of `x is None` |
| Anti-pattern try block | SKY-L004 | Nested try, or try wrapping too much logic |
| Unused exception var | SKY-L005 | `except Error as e:` where `e` is never referenced |
| Inconsistent return | SKY-L006 | Function returns both values and `None` |
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
  --table                      Rich table output instead of TUI
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

Agent remediate options:
  --dry-run                    Show plan without applying fixes (safe preview)
  --max-fixes N                Max findings to fix per run (default: 10)
  --auto-pr                    Create branch, commit, push, and open PR
  --branch-prefix PREFIX       Git branch prefix (default: skylos/fix)
  --test-cmd CMD               Custom test command (default: auto-detect)
  --severity LEVEL             Min severity filter: critical, high, medium, low
```

### Commands
```
Commands:
  skylos PATH                  Analyze a project (static analysis)
  skylos agent analyze PATH    Hybrid static + LLM analysis
  skylos agent security-audit PATH  Deep LLM audit with file selection
  skylos agent fix PATH        Fix specific issue
  skylos agent review          Review git-changed files only
  skylos agent remediate PATH  End-to-end scan, fix, test, and PR
  skylos baseline PATH         Snapshot current findings for CI baselining
  skylos cicd init             Generate GitHub Actions workflow
  skylos cicd gate             Check findings against quality gate
  skylos cicd annotate         Emit GitHub Actions annotations
  skylos cicd review           Post inline PR review comments
  skylos init                  Initialize pyproject.toml config
  skylos key                   Manage API keys (add/remove/list)
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
- **Secrets PoC**: May emit both a provider hit and a generic high-entropy hit for the same token. Supported file types: `.py`, `.pyi`, `.pyw`, `.env`, `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`, `.ts`, `.tsx`, `.js`, `.jsx`, `.go`
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
- [x] Expanded TypeScript dead code detection (interfaces, enums, type aliases, 95% recall)
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