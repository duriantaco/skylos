<div align="center">
    <img src="assets/DOG_1.png" alt="Skylos" width="160">
    <h1>Skylos</h1>
    <p><strong>Code checks that show their work.</strong></p>

[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
[![MCP Toplist](https://mcptoplist.com/badge/io.github.duriantaco%2Fskylos.svg)](https://mcptoplist.com/server/io.github.duriantaco%2Fskylos)

[Docs](https://docs.skylos.dev) · [Quick start](#quick-start) · [Website](https://skylos.dev) · [VS Code](./editors/vscode/README.md) · [Discord](https://discord.gg/Ftn9t9tErf)

**English** | [Deutsch](./docs/i18n/README.de.md) | [简体中文](./docs/i18n/README.zh-CN.md)

</div>

## What is Skylos?

Skylos is a free, open-source (Apache-2.0) checker for the code you and your
coding agents write. It runs on your machine, inside your agent's loop and as a
pull-request gate. No account, no API key and no LLM needed.

Coding agents such as Claude Code, Codex and Cursor write code faster than
anyone can review it, and they repeat the same mistakes. They say "done" after
deleting or skipping a failing test. They install packages that don't exist and
import functions nobody wrote. They leave injection bugs and hard-coded keys
behind. Linters and security scanners each catch a slice of this, after the
fact. Skylos checks all of it in one tool, at the points where it can still be
stopped.

It is built for:

- **Developers who let agents write code**, and want the agent checked while it
  works, not after.
- **Maintainers** who want one free check on every pull request.
- **Existing codebases** that need security, secrets, dependency, quality and
  dead-code findings from one scan, in Python, TypeScript, Java, Go and
  [more](#language-support).

## How it works

Skylos steps in at four points:

| When | Command | What it stops |
|:---|:---|:---|
| While the agent works | `skylos agent install-hooks` | Made-up package installs, reads of files holding secrets, git-hook bypasses; checks every edit |
| When the agent says "done" | `skylos done --base main` | Deleted or skipped tests, loosened CI steps, silenced lint or type checks, test-only special cases; runs your tests |
| On every pull request | `skylos cicd init` | Critical security issues, secrets and critical AI-code mistakes, plus anything over your limits |
| Any time, on the whole repo | `skylos . -a` | Security flaws, secrets, vulnerable dependencies, quality regressions, AI-code mistakes, dead code |

## See it work

A 20-line Flask app, scanned with every check (excerpt):

```text
$ skylos . -a --format concise
app.py:15  SKY-D211  Possible SQL injection: tainted or string-built query.
app.py:5  SKY-L012  Import from local module 'billing' requests 'issue_refund', but that name is not defined or re-exported there.
app.py:8  SKY-S101  Potential stripe secret detected
requirements.txt:1  SKY-SCA-GHSA-68rp-wp8r-4726  flask@3.1.2: Flask session does not add `Vary: Cookie` header when accessed in some ways
billing.py:1  SKY-U001  unused function: charge_card
```

Every finding names the file, line and rule. Security findings show the
source-to-sink path when one was recorded; `--format json` keeps the full
evidence.

## Quick start

```bash
pip install skylos
skylos . -a               # run every check on this repo
skylos done --base main   # did the agent really finish? runs your tests, compares with main
skylos cicd init          # add a Skylos check to every pull request
```

Working with a coding agent? Two commands:

```bash
skylos setup   # once per repo: connects Claude Code and Codex, installs their hooks, lets Done run your tests, writes the PR check
skylos open    # every day: diagram of your code, what changed in plain English, every check run
```

The [tutorial](./docs/workflow.md) walks through a real session: the agent
makes a change, gets blocked, and fixes it from Skylos's fix brief.

`skylos .` on its own runs the fast dead-code scan. `skylos cloud` uploads
results to track each branch on Skylos Cloud; it is optional.

## Check every agent edit

Install hooks so the agent is checked while it works:

```bash
skylos agent install-hooks            # Claude Code
skylos agent install-hooks --codex    # Codex
skylos agent install-hooks --cursor   # Cursor
```

- **After each edit:** checks the changed lines for security issues, secrets
  and AI-code mistakes, and tells the agent what to fix.
- **Before a file read:** blocks files that contain hard-coded secrets.
- **Before a package install** (`pip`, `uv`, `npm`, `pnpm`, `bun`, `go`, ...):
  blocks made-up or typosquatted packages, and asks before installs it cannot
  verify.
- **Before a git command:** blocks `--no-verify` and other ways around your
  git hooks.
- **At stop:** blocks "done" while issues the agent added are still open.

If Skylos itself errors, the action is allowed and both you and the agent are
told it went unchecked. See [agent hooks](./docs/agent-hooks.md).

## Is the agent really done?

```bash
skylos done --base main
```

`skylos done` compares the branch with `main` and runs your tests. It flags:

- deleted, skipped or weakened tests
- loosened test settings and CI test steps
- silenced lint or type checks
- code that special-cases the tests
- code the branch left with no callers (advice, not a block)

When a test fails, it reruns it on `main` and labels the failure "introduced"
or "already failing". It writes a receipt to `.skylos/receipts/`. pytest runs
automatically; other runners need one line:

```toml
[tool.skylos.done]
test_command = "npm test"
```

It reads its settings from `main`, so a branch cannot loosen its own check.
Exit codes: `0` pass, `1` blocked, `2` could not run. See the
[done gate](./docs/done-gate.md) and what it [misses](./docs/done-gate-benchmark.md).

<a id="cicd"></a>

## Gate pull requests

No account or token needed:

```bash
git checkout -b add-skylos-gate
skylos cicd init --no-upload
git add .github/workflows/skylos.yml
git commit -m "Add Skylos pull request gate"
git push -u origin add-skylos-gate
```

The workflow reviews the changed lines of each pull request and runs
`skylos done` when it finds your tests. `skylos cicd init` also sets up GitLab
CI, Jenkins, Bitbucket Pipelines, Azure Pipelines and CircleCI
([any CI](./docs/ci-platforms.md)).

The gate always fails on a critical security issue, a secret, or a critical
AI-code issue such as an import of a package that doesn't exist. Everything
else fails only above your limits:

```toml
[tool.skylos.gate]
max_high = 5          # high-severity security issues allowed
max_quality = 10      # quality issues allowed
max_ai_defects = 10   # AI-code issues allowed
```

The policy is read from the base branch, so a pull request cannot loosen its
own gate. Each run ends with `Quality Gate: PASSED`, `FAILED` (exit 1) or
`INCOMPLETE` (exit 2) and the reasons. Walkthrough:
[your first gated pull request](./docs/first-gated-pr.md).

Need a person to sign off on risky changes? `skylos cicd init --risk-review`
adds a check that waits for a human approval when a pull request deletes
tests, removes auth checks, changes dependencies or weakens CI. See
[risk review](./docs/risk-review.md).

## Scan a repository

```bash
skylos .                         # dead code (fast, default)
skylos . -a                      # every check
skylos . -a --diff origin/main   # only findings on changed lines
skylos . --format pretty         # grouped report with code snippets
skylos . --tui                   # keyboard-driven triage
skylos . -a --format json        # full evidence for scripts and agents
skylos . --format sarif          # GitHub code scanning
skylos cleanup . --top 5         # a prioritized fix list
```

Python dead code can be removed for you: `skylos clean . --dry-run` shows the
plan, `--apply` edits files. Output modes and exit codes:
[CLI output](./docs/cli-output.md).

## What Skylos catches

| Category | Examples |
|:---|:---|
| AI-code mistakes | imports of functions that don't exist, invented package APIs, packages that don't exist, impossible versions, unfinished stubs, disabled controls |
| Security flaws | SQL injection, XSS, SSRF, path traversal, command injection, unsafe deserialization, ReDoS |
| Secrets | API keys, tokens, private credentials, high-entropy strings |
| Dependencies | known CVEs, malicious packages, license policy, offline SBOM (CycloneDX, SPDX) |
| Quality | complexity, deep nesting, duplicate branches, long functions, inconsistent returns |
| Dead code | unused functions, classes, imports, files and dependencies, framework-aware (FastAPI, Django, Flask, Next.js, React, Laravel, ...) |
| CI/CD and deployment | risky GitHub Actions and GitLab CI, Dockerfiles, Docker Compose, systemd, Kubernetes |
| LLM apps | unsafe tool use, prompt-injection exposure, missing output validation |

Every rule: [Rules Reference](https://docs.skylos.dev/rules-reference) and
[rule dictionary](./dictionary.md).

## Verify the AI apps you build

If your code calls an LLM, Skylos checks the guardrails around it, with no
model in the loop:

```bash
skylos discover .                    # list LLM calls, agent tools and prompt sites
skylos defend .                      # score the guardrails around them
skylos defend . --fail-on critical   # CI gate
skylos defend . --format md -o evidence.md   # evidence report with OWASP LLM Top 10 coverage
```

It covers Python and TypeScript/JavaScript; `--owasp-framework agentic` reports
against the OWASP Agentic Top 10. To test a running agent against
expected answers and tool calls, use `skylos agent test`. See
[agent verification](./docs/agent-verification.md) and
[agent behavior testing](./docs/agent-behavior-testing.md).

## Language Support

| Language | Dead code | Security | Quality |
|:---|:---:|:---:|:---:|
| Python | Yes | Yes | Yes |
| TypeScript / JavaScript | Yes | Yes | Yes |
| Java | Yes | Yes | Yes |
| Go | Yes | Partial | Partial |
| PHP | Yes | Yes | No |
| Rust | Experimental | Partial | Partial |
| Ruby | Partial | Partial | No |
| Dart | Yes | Partial | No |
| C# | Partial | Partial | Partial |
| C++ | Partial | No | No |
| Kotlin | Partial | Partial | No |
| Swift | Partial | No | No |
| Shell | No | Partial | No |

- Python has the deepest coverage.
- Go needs the native `skylos-go` engine. It ships in the PyPI wheels for
  Linux, macOS and Windows; elsewhere `skylos doctor` prints the build command.
- Dart needs `pip install "skylos[dart]"`.
- Rust dead code is hidden by default; `--confidence 40` shows it.

Full matrix and per-language limits:
[language support](https://docs.skylos.dev/language-support).

## Configuration

`skylos init` adds a starter config to `pyproject.toml`. Projects without one
can use `skylos.toml` with the same keys at the top level:

```toml
# skylos.toml
exclude = ["generated", "dist"]

[gate]
max_high = 5

[done]
test_command = "npm test"
```

In a monorepo, each package can have its own file; the nearest one wins per
key. `skylos doctor` shows which files are in use.

Silence one finding with a reason:

```python
query = build_query(user_id)  # skylos: ignore[SKY-D211] user_id is an int from the router
```

To accept existing findings and gate only new ones, run `skylos baseline .`
and scan with `--baseline`. More: [configuration](https://docs.skylos.dev/configuration).

## Integrations

| Integration | What it does |
|:---|:---|
| [GitHub Action](./action.yml) | Pull-request gate, optional container-image gate |
| [GitLab, Bitbucket, Azure, Jenkins, CircleCI](./docs/ci-platforms.md) | Pull-request gate for that CI |
| [Agent hooks](./docs/agent-hooks.md) | Claude Code, Codex and Cursor checked on every edit |
| [MCP server](https://docs.skylos.dev/mcp-server) | Skylos scans as tools for AI assistants |
| [VS Code extension](./editors/vscode/README.md) | Findings in the editor |
| [Skylos Cloud](./docs/skylos-cloud.md) | Optional: findings and the gate per branch, over time |

## Install options

```bash
pip install skylos              # core checks
pip install "skylos[llm]"       # agent commands that use an LLM
pip install "skylos[all]"       # every optional extra
```

Or run the container image:

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . -a
```

Other extras (`lint`, `verdict`, `dart`), Python-specific image tags and
source installs: [installation](https://docs.skylos.dev/installation).

## What leaves your machine

Your code and findings reach Skylos Cloud only when you run a command that
says it uploads, such as `skylos cloud` or `--upload`. A saved login alone
never uploads anything. There are no analytics.

Dependency and package checks send package names and versions to OSV and the
public registries, never source. LLM commands send code to the model provider
you configure. Every request, its trigger and how to turn it off:
[privacy and network](./docs/privacy-and-network.md).

## Results

10 Skylos-assisted dead-code cleanup PRs have been merged in 9 open-source
projects, including [Black](https://github.com/psf/black/pull/5041),
[NetworkX](https://github.com/networkx/networkx/pull/8572),
[Optuna](https://github.com/optuna/optuna/pull/6547),
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136) and
[pypdf](https://github.com/py-pdf/pypdf/pull/3685).
[Real-World Results](./REAL_WORLD_RESULTS.md) lists all 26 PRs we recorded,
including the ones that were closed or reverted. These are accepted cleanups,
not endorsements.

Methods, dated results and competitor comparisons: [BENCHMARK.md](./BENCHMARK.md).

<a id="common-questions"></a>

## FAQ

**Does Skylos replace Semgrep, CodeQL, Bandit or Vulture?**
No. It runs alongside them. It adds agent checks, framework-aware dead code and
one gate across security, secrets, dependencies and quality.

**Does it need an LLM?**
No. The core checks run locally with no model. LLM features are optional
(`skylos[llm]`).

**Is it free?**
The CLI is free and open source. Skylos Cloud is optional and has a free plan;
see [pricing](https://skylos.dev/pricing).

**Can I check only my changes?**
Yes: `skylos . -a --diff origin/main`. A removed security check, such as a
deleted auth decorator, is still reported.

**What about code that is only called dynamically?**
Use inline ignores, a baseline, or `--trace` to record what actually runs. See
[smart tracing](https://docs.skylos.dev/smart-tracing).

More: [FAQ](https://docs.skylos.dev/faq).

## Documentation

| Need | Read |
|:---|:---|
| Every command and flag | [CLI reference](https://docs.skylos.dev/cli-reference) |
| Install, extras, Docker | [Installation](https://docs.skylos.dev/installation) |
| Config files, ignores, baselines | [Configuration](https://docs.skylos.dev/configuration) |
| Output formats and exit codes | [CLI output](./docs/cli-output.md) |
| Agent hooks | [Agent hooks](./docs/agent-hooks.md) |
| `skylos done` | [Done gate](./docs/done-gate.md) |
| Pull-request gates | [First gated PR](./docs/first-gated-pr.md), [any CI](./docs/ci-platforms.md) |
| Security and taint analysis | [Security](https://docs.skylos.dev/security-analysis) |
| Dependencies, SBOM, licenses | [Dependency scanning](./docs/dependency-scanning.md), [licenses](./docs/license-compliance.md) |
| AI-code checks | [AI code verification](./docs/ai-code-verification.md) |
| Network requests | [Privacy and network](./docs/privacy-and-network.md) |
| Rule IDs | [Rule dictionary](./dictionary.md) |

## Contributing

- Read [CONTRIBUTING.md](./CONTRIBUTING.md) before sending a pull request.
- Report a bug with `skylos feedback` (no account needed), or open an issue
  with a minimal repro.
- Report security issues through [SECURITY.md](./SECURITY.md).
- Analyzer changes are tested on real projects with
  [liveness_primer](https://github.com/mcdigman/liveness_primer), built by
  [Matthew Digman](https://github.com/mcdigman). See the
  [guide](./docs/liveness-primer.md).
- Ideas to work on: [ROADMAP.md](./ROADMAP.md). Chat: [Discord](https://discord.gg/Ftn9t9tErf).

## License

Apache License 2.0. See [LICENSE](./LICENSE).

<!-- mcp-name: io.github.duriantaco/skylos -->
