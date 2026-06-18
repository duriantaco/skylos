<div align="center">
    <img src="assets/DOG_1.png" alt="Skylos" width="260">
    <h1>Skylos</h1>
    <h3>Open-source, local-first checks for dead code, security issues, secrets, quality regressions, and AI-code mistakes before merge.</h3>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
[![Astronomer Trust](https://img.shields.io/badge/Astronomer%20Trust-A-brightgreen?style=flat&logo=github&logoColor=white)](#star-authenticity-audit)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

[Website](https://skylos.dev) |
[Docs](https://docs.skylos.dev) |
[Repo Map](https://duriantaco.github.io/skylos/repo-map/) |
[Quick Start](https://docs.skylos.dev/quick-start) |
[GitHub Action](./action.yml) |
[VS Code Extension](./editors/vscode/README.md) |
[Real-World Results](./REAL_WORLD_RESULTS.md) |
[Benchmarks](./BENCHMARK.md) |
[Roadmap](./ROADMAP.md) |
[Contributing](./CONTRIBUTING.md)

**English** | [Deutsch](./docs/i18n/README.de.md) | [简体中文](./docs/i18n/README.zh-CN.md) | [Translations](./docs/i18n/README.md)

## What Is Skylos?

Skylos is an open-source static analysis CLI for Python, TypeScript,
JavaScript, Java, Go, Kotlin, PHP, Rust, Dart, C#, Shell, and deployment config. It
runs locally by default and can also be used as a CI/CD PR gate.

Use Skylos when you want one command to check a repo or pull request for:

- dead code and unused files
- security flaws and dangerous data flows
- secrets and dependency CVEs
- CI/CD and edge-device deployment misconfigurations
- quality regressions such as complexity, duplicate branches, and deep nesting
- common AI-generated code mistakes, including missing guards, fake helpers,
  invented package APIs, and impossible dependency versions
- LLM app risks such as unsafe tool use and missing output validation

## Start In 60 Seconds

```bash
pip install skylos
skylos .
```

The default scan focuses on dead code. Add security, secrets, quality, and
dependency checks with `-a`:

```bash
skylos . -a
```

Verify a changed file or range before an agent hands it to review:

```bash
skylos verify . --file src/app.py --range 40:75 --project-context
```

Create a project config with thresholds, ignores, template hooks, and vibe
dictionary extensions:

```bash
skylos init
```

Create a starter local rule pack:

```bash
skylos rules init
skylos rules validate .skylos/rules/local.yml
skylos rules list --json
skylos rules list cross --json
skylos rules list --packs --json
skylos cache stats
```

Generate a GitHub Actions PR gate:

```bash
skylos cicd init
git add .github/workflows/skylos.yml
git commit -m "Add Skylos CI gate"
git push
```

Need more commands? Read the [CLI Reference](https://docs.skylos.dev/cli-reference).

## Common Workflows

| Goal | Command | What You Get | More Detail |
|:---|:---|:---|:---|
| First dead-code scan | `skylos .` | Finds unused functions, classes, imports, files, and framework entrypoint mistakes | [Dead code docs](https://docs.skylos.dev/dead-code-detection) |
| Deterministic cleanup preview | `skylos clean . --dry-run --types import,function --confidence 80` | Shows safe import/function removals before writing; add `--apply` to edit files | [Dead code docs](https://docs.skylos.dev/dead-code-detection) |
| Security and quality audit | `skylos . -a` | Adds dangerous flow, secrets, dependency, config, and quality checks | [Security docs](https://docs.skylos.dev/security-analysis) |
| PR gate | `skylos cicd init` | Generates a GitHub Actions workflow with annotations and failure thresholds | [CI/CD guide](https://docs.skylos.dev/ci-cd) |
| Readable terminal report | `skylos . --format pretty` | Groups findings by file with severity badges, snippets, and copyable `file:line` locations | [CLI output modes](./docs/cli-output.md) |
| Selectable terminal triage | `skylos . --tui` | Opens a keyboard-driven category list, finding list, and detail pane | [CLI output modes](./docs/cli-output.md) |
| IDE/test-script output | `skylos --format concise src/test.py` | Prints only `file:line` findings and exits non-zero when findings exist | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| In-loop AI-code verification | `skylos verify . --file src/app.py --range 40:75` | Returns narrow JSON for hallucinated helpers, unfinished code, stale references, disabled controls, and API/dependency hallucinations | [AI features](https://docs.skylos.dev/ai-features) |
| Changed-lines review | `skylos . -a --diff origin/main` | Keeps findings focused on active work instead of legacy debt | [Quality gate docs](https://docs.skylos.dev/quality-gate) |
| Runtime-assisted dead-code check | `skylos . --trace` | Uses runtime traces to reduce dynamic-code false positives | [Smart tracing](https://docs.skylos.dev/smart-tracing) |
| Local rule pack | `skylos rules init` | Scaffolds YAML rules for project-specific security and quality checks | [Custom rules](https://docs.skylos.dev/custom-rules) |
| Security agent quick scan | `skylos agent security-quick .` | One-shot LLM security audit; compatibility alias for `skylos agent scan . --security` | [AI features](https://docs.skylos.dev/ai-features) |
| Security agent deep scan | `skylos agent security-deep .` | Three-stage security workflow with threat-model context, static threat traces, discovery/validation, and remediation handoff | [AI features](https://docs.skylos.dev/ai-features) |
| AI-assisted review | `skylos agent scan .` | Static analysis plus optional LLM review and fix suggestions | [AI features](https://docs.skylos.dev/ai-features) |
| Verification-backed remediation | `skylos agent scan . --fix` | Re-scans fixed security findings and records proof-test metadata for supported fixes | [AI features](https://docs.skylos.dev/ai-features) |
| MCP agent verification | `verify_change` MCP tool | Lets Claude, Cursor, and other MCP clients verify an edited file/range with the same schema as `skylos verify` | [MCP server](https://docs.skylos.dev/mcp-server) |
| LLM app defense | `skylos defend .` | Finds missing AI app guardrails mapped to OWASP LLM risks | [AI defense](https://docs.skylos.dev/ai-defense) |
| Technical debt triage | `skylos debt .` | Ranks hotspots and debt trends | [Technical debt](https://docs.skylos.dev/technical-debt) |

## What Skylos Catches

| Category | Examples | Why It Matters |
|:---|:---|:---|
| Dead code | unused functions, classes, imports, package entrypoints, route handlers | reduces maintenance cost without breaking dynamic frameworks |
| Security flaws | SQL injection, XSS, SSRF, path traversal, command injection, unsafe deserialization | catches exploitable flows before code reaches main |
| Secrets | API keys, tokens, private credentials, high-entropy strings | prevents credentials from leaking through commits and PRs |
| CI/CD workflows | GitHub Actions and GitLab CI dangerous triggers, unpinned actions/includes, broad tokens, OIDC misuse, cache poisoning, mutable images | reduces CI/CD supply-chain risk before release jobs run |
| Edge deployment config | Docker Compose privileged device access, host networking, systemd root services, broad capabilities, missing sandboxing | catches repo-controlled settings that turn app bugs into device compromise |
| Quality regressions | complexity, deep nesting, duplicate branches, long functions, inconsistent returns | keeps AI-assisted refactors from adding brittle code |
| AI code mistakes | phantom security calls, missing decorators, unfinished stubs, disabled controls, real packages called with invented APIs, impossible npm/Go versions | catches common hallucinated or incomplete code paths before they reach review |
| LLM app risks | unsafe tool use, prompt injection exposure, missing output validation, missing rate limits | helps teams ship AI features with guardrails |

See the full [Rules Reference](https://docs.skylos.dev/rules-reference).

## How Skylos Fits

Skylos is not a replacement for every specialized scanner. It is a local-first
repo and PR checker that puts several common review checks behind one CLI.

- **Framework-aware dead code detection:** FastAPI, Django, Flask, pytest,
  SQLAlchemy, Next.js, React, package entrypoints, and common plugin patterns.
- **PR-focused output:** diff scanning, CI thresholds, GitHub annotations, and
  baselines for existing findings.
- **Local-first operation:** core static analysis does not require cloud upload
  or LLM calls.
- **AI-assisted change review:** checks for removed validation, auth, logging,
  CSRF, rate limiting, timeouts, real-package API hallucinations, and other
  guardrails in generated or edited code.
- **Agent-loop verification:** `skylos verify` and MCP `verify_change` return
  versioned JSON for only AI-code trust findings, so coding agents can
  self-correct before a human sees the change.
- **Verification-backed remediation:** security fixes are checked by re-running
  analysis, and supported findings can include targeted regression-test proof
  metadata.
- **Project-specific rules:** add local YAML rules and extend prompt, credential,
  sensitive-file, and timeout dictionaries from config.
- **One command surface:** dead code, security, secrets, dependency, quality,
  technical debt, agent review, and AI defense commands share the same CLI.

## Install Options

```bash
# Core static analysis
pip install skylos

# LLM-powered agent workflows
pip install "skylos[llm]"

# All published optional extras
pip install "skylos[all]"
```

Container image:

```bash
docker pull ghcr.io/duriantaco/skylos:latest
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . --json --no-provenance
```

See [Installation](https://docs.skylos.dev/installation) for source installs,
container usage, and optional dependencies.

## Configure Templates And Vibe Checks

Run `skylos init` to add these sections to `pyproject.toml`:

```toml
[tool.skylos.templates]
# security = ".skylos/templates/security.md"
# quality = ".skylos/templates/quality.md"
# security_audit = ".skylos/templates/security_audit.md"
# review = ".skylos/templates/review.md"

[tool.skylos.vibe]
extra_phantom_names = ["verify_enterprise_auth"]
extra_phantom_decorators = ["tenant_admin_required"]
extra_credential_names = ["tenant_signing_secret"]
extra_network_timeout_calls = ["vendor_sdk.fetch"]

[tool.skylos.dead_code]
entrypoints = []

[[tool.skylos.dead_code.entrypoints]]
type = "method"
name = ["create", "pre_hook", "post_hook"]
parent = { name = "Main", base_classes = ["Application"] }
path = "src/**"
reason = "project framework lifecycle hook"

[tool.skylos.contribution]
collect_local_signals = false
contribute_public_corpus = false
structural_signatures_only = true
include_source = false
```

Template files extend Skylos' built-in prompts; they do not replace the
JSON-only output contract or untrusted-code safety rules. Vibe dictionary
extensions let teams teach Skylos about local fake-auth helpers, project
credential names, sensitive files, and network calls that must set timeouts.
Dead-code entrypoints let teams mark proprietary framework classes, lifecycle
methods, and decorator-registered functions as live using precise rules for
type, name, path, decorators, base classes, and parent classes.
Rules must include a symbol selector such as `name`, `decorators`,
`base_classes`, or `parent`; `path` and `module` only narrow the match.
Contribution signals are off by default; when enabled, Skylos records local
structural accept/dismiss/learn events under `.skylos/contribution/` without raw
source.

By default Skylos discovers `[tool.skylos]` in `pyproject.toml` by walking up
from the scan path. To use a dedicated TOML config, pass `--config-file PATH`
or set `SKYLOS_CONFIG_FILE`; standalone files may use either `[tool.skylos]`
or top-level `[skylos]`. Synced Skylos Cloud policy keeps its protected
precedence over repository-controlled config.

## Language Support

| Language | Dead Code | Security | Quality | Notes |
|:---|:---:|:---:|:---:|:---|
| Python | Yes | Yes | Yes | strongest coverage; framework-aware static analysis and optional tracing |
| TypeScript / JavaScript | Yes | Yes | Yes | Tree-sitter parsing, package graph reachability, framework conventions |
| Java | Yes | Yes | Yes | Tree-sitter parsing and structured security-flow analysis |
| Go | Yes | Partial | Partial | dead-code and selected security benchmark coverage |
| PHP | Yes | Yes | Partial | PHP parser coverage plus taint-style security sinks and sources |
| Rust | Yes | Yes | Partial | Rust parser coverage plus security sink/source checks |
| Dart | Yes | Yes | Partial | Dart parser coverage plus selected security sinks and sources |
| C# | Yes | Yes | Partial | C# symbol coverage plus selected ASP.NET, process, SQL, HTTP, and file sinks |
| Shell | No | Yes | Partial | shell-script security checks for command injection, SSRF, and path traversal |

See [Rules Reference](https://docs.skylos.dev/rules-reference) for rule families
and scanner scope.

## Config And Deployment Support

| Surface | Files | Security Scope |
|:---|:---|:---|
| GitHub Actions | `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `action.yml`, `action.yaml` | dangerous triggers, token permissions, unpinned actions, template injection, secrets, OIDC, cache, and artifact policy |
| GitLab CI | `.gitlab-ci.yml` | mutable images, unpinned includes, literal secrets, untrusted eval, Docker-in-Docker, OIDC, cache, timeout, and runner-tag policy |
| Dockerfile | `Dockerfile`, `Dockerfile.*`, `*.dockerfile` | dangerous `RUN` commands, remote `ADD` without checksum, and literal build `ARG` / `ENV` secrets |
| Edge Docker Compose | `compose*.yml`, `compose*.yaml`, `docker-compose*.yml`, `docker-compose*.yaml` | privileged containers, broad host device/control mounts, GPU/device runtime, and host networking |
| Edge systemd | `*.service` | root edge services, mutable `ExecStart` paths, missing sandboxing, broad capabilities, and broad device access |

## Benchmark Snapshot

Skylos has checked-in regression benchmarks for dead code, security, quality,
and agent review. These are strict regression gates, not broad proof that any
tool is universally state of the art.

| Suite | Current Skylos Result | Baseline |
|:---|:---|:---|
| Dead code regression | 16 cases, TP=36 FP=0 FN=0 TN=59, score 100.0 | Ruff score 62.67; Vulture not installed in latest local rerun |
| Security regression | 56 cases, TP=35 FP=0 FN=0 TN=23, score 100.0 | Bandit score 47.14 on Python-applicable cases |
| Quality regression | 13 cases, score 100.0 | regression gate only |
| Agent review | 25 cases, score 100.0 | regression gate only |
| AI-code defect regression | curated verifier cases for hallucinated references, package APIs, and dependency versions | run `python scripts/ai_code_defect_benchmark.py` |

Frozen `golden-v0.2` highlights:

| Frozen Suite | Skylos Result | Caveat |
|:---|:---|:---|
| Dead code seeded dev | overall score 96.28; TS/JS/Go/Java score 100.0; Python score 93.33 | Python residuals are label-review items |
| Security seeded dev | overall score 96.52; full recall with one Python `urljoin` false positive | label should be reviewed |
| OWASP Java security dev | TP=105 FP=0 FN=15 TN=120, score 94.37 | request-wrapper, LDAP, XPath, and property weak-hash gaps remain |
| Quality seeded dev | TP=1 FP=0 FN=0 TN=1, score 100.0 | one seeded case only |

For methodology, commands, competitor rows, and caveats, see
[BENCHMARK.md](./BENCHMARK.md).

## Project Evidence

Skylos-assisted dead-code cleanup PRs have been merged in
[Black](https://github.com/psf/black/pull/5041),
[NetworkX](https://github.com/networkx/networkx/pull/8572),
[Optuna](https://github.com/optuna/optuna/pull/6547),
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136),
[pypdf](https://github.com/py-pdf/pypdf/pull/3685),
[beets](https://github.com/beetbox/beets/pull/6473), and
[Flagsmith](https://github.com/Flagsmith/flagsmith/pull/6953). These are
accepted cleanup PRs, not project endorsements. See
[Real-World Results](./REAL_WORLD_RESULTS.md).

<a id="star-authenticity-audit"></a>

A local Astronomer scan on April 26, 2026 computed 420 stargazers and returned
**overall trust: A**. StarGuard also reported **low fake-star risk**.

## Integrations

| Integration | Link | Purpose |
|:---|:---|:---|
| GitHub Action | [GitHub Action](./action.yml) | PR gates, annotations, and CI enforcement |
| VS Code extension | [VS Code extension](./editors/vscode/README.md) | in-editor findings and AI-assisted fixes |
| MCP server | [MCP setup](https://docs.skylos.dev/mcp-server) | expose Skylos scans to AI agents and coding assistants |
| Docker image | [Installation](https://docs.skylos.dev/installation) | run Skylos without a local Python install |
| Skylos Cloud | [Cloud workflow](https://docs.skylos.dev/cloud-workflow) | optional upload and dashboard workflows |

Generate a GitHub Actions workflow from the CLI:

```bash
skylos cicd init --upload
skylos cicd init --upload --scan-path apps/api
```

The generated upload workflow uses GitHub OIDC, sends PR head commit/branch
metadata, and supports monorepo subprojects through `--scan-path`.

## Documentation Map

| Need | Read This |
|:---|:---|
| Install options, source install, and Docker | [Installation](https://docs.skylos.dev/installation) |
| First scan and core workflows | [Quick Start](https://docs.skylos.dev/quick-start) |
| CLI commands, flags, and examples | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| CLI output modes, pretty reports, and TUI controls | [CLI Output Modes](./docs/cli-output.md) |
| CI setup, PR gates, annotations, and branch protection | [CI/CD](https://docs.skylos.dev/ci-cd) |
| Dead-code behavior and framework awareness | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| Security scanning and taint analysis | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Rule ID prefixes and product terminology | [Rule Dictionary](./dictionary.md) |
| Agent scan, verification, remediation, and model setup | [AI Features](https://docs.skylos.dev/ai-features) |
| AI defense checks and LLM guardrails | [AI Defense](https://docs.skylos.dev/ai-defense) |
| MCP server setup | [MCP Server](https://docs.skylos.dev/mcp-server) |
| Real-world merged cleanup PRs | [Real-World Results](./REAL_WORLD_RESULTS.md) |
| Baselines, filtering, suppressions, and whitelists | [Configuration](https://docs.skylos.dev/configuration) |
| Smart tracing | [Smart Tracing](https://docs.skylos.dev/smart-tracing) |
| Rule families and language support | [Rules Reference](https://docs.skylos.dev/rules-reference) |
| Cloud uploads and dashboard flow | [CLI to Dashboard](https://docs.skylos.dev/cloud-workflow) |
| VS Code extension | [VS Code Extension](https://docs.skylos.dev/vscode) |
| Benchmarks and methodology | [BENCHMARK.md](./BENCHMARK.md) |
| Security policy | [SECURITY.md](./SECURITY.md) |
| Release process | [RELEASE_WORKFLOW.md](./RELEASE_WORKFLOW.md) |
| Contribution priorities | [ROADMAP.md](./ROADMAP.md) |
| Contributing | [CONTRIBUTING.md](./CONTRIBUTING.md) |

## Common Questions

**Does Skylos replace Bandit, Semgrep, CodeQL, or Vulture?**

No. Skylos can run alongside them. It focuses on framework-aware dead-code
signal, PR gating, AI-era regression checks, and a combined workflow across
dead code, security, secrets, and quality.

**Does Skylos require an LLM?**

No. Core static analysis runs locally without API keys. LLM features are
optional through `skylos[llm]` and agent commands.

**Can I use it only on changed code?**

Yes. Use `skylos . -a --diff origin/main` locally or configure CI gates to focus
on new findings.

**How should I handle intentional dynamic code?**

Use baselines, whitelists, inline suppressions, or runtime tracing. See the
[configuration docs](https://docs.skylos.dev/configuration) and
[smart tracing docs](https://docs.skylos.dev/smart-tracing).

## Contributing And Support

- Report security issues through [SECURITY.md](./SECURITY.md).
- Open bugs and false-positive reports with minimal repros.
- Check [ROADMAP.md](./ROADMAP.md) for useful contribution areas.
- Read [CONTRIBUTING.md](./CONTRIBUTING.md) before sending a pull request.
- See [QUALITY.md](./QUALITY.md) for project quality and gate expectations.
- Join the [Discord](https://discord.gg/Ftn9t9tErf) for community support.

## License

Skylos is licensed under the [Apache License 2.0](./LICENSE).

<!-- mcp-name: io.github.duriantaco/skylos -->
