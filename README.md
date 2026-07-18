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

The default scan focuses on dead code. Add security, secrets, quality,
dependency, and AI-defect checks with `-a`:

```bash
skylos . -a
```

Run only evidence-backed AI defect checks with:

```bash
skylos . --ai-defects
```

Verify a changed file or range before an agent hands it to review:

```bash
skylos verify . --file src/app.py --range 40:75 --project-context
```

`skylos verify` schema version 2 returns `pass`, `fail`, or `incomplete`.
`incomplete` means a requested proof could not be established, such as a
third-party TS/JS import, computed namespace member, unsupported language-local
API check, or parser surface that Skylos could not prove; it exits `2` unless
`--no-fail` is set. The `coverage` object lists detected languages, expected
checks, language support, missing checks, completed/skipped checks, checked
references, and deterministic skip reasons.

Deterministic local/workspace API verification currently covers Python,
TypeScript/JavaScript, Go, and Java without executing target code. PHP, Rust,
Dart, C#, Kotlin, and Shell retain their existing static-analysis coverage,
but their local API proof is reported as unsupported and therefore incomplete.
See [AI Code Verification Coverage](./docs/ai-code-verification.md).

Create a local AI hallucination contract for repo-specific generated-code
truth. `skylos verify` auto-discovers `.skylos/ai-contract.yml`:

```bash
skylos contract init
skylos contract inspect
skylos verify .
```

Test a running agent against deterministic response and tool-use scenarios:

```bash
skylos agent init
skylos agent test --allow-contract-endpoint
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
| Security and quality audit | `skylos . -a` | Adds dangerous flow, secrets, dependency, config, quality, and AI-defect checks | [Security docs](https://docs.skylos.dev/security-analysis) |
| PR gate | `skylos cicd init` | Generates a GitHub Actions workflow with annotations and failure thresholds | [CI/CD guide](https://docs.skylos.dev/ci-cd) |
| Readable terminal report | `skylos . --format pretty` | Groups findings by file with severity badges, snippets, and copyable `file:line` locations | [CLI output modes](./docs/cli-output.md) |
| Selectable terminal triage | `skylos . --tui` | Opens a keyboard-driven category list, finding list, and detail pane | [CLI output modes](./docs/cli-output.md) |
| IDE/test-script output | `skylos --format concise src/test.py` | Prints only `file:line` findings and exits non-zero when findings exist | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| In-loop AI-code verification | `skylos verify . --file src/app.py --range 40:75` | Returns narrow JSON for hallucinated helpers, unfinished code, stale references, disabled controls, and API/dependency hallucinations | [AI features](https://docs.skylos.dev/ai-features) |
| AI hallucination contracts | `skylos contract init && skylos verify .` | Auto-discovers `.skylos/ai-contract.yml` and verifies generated code against repo-specific symbols, dependencies, APIs, route guards, and test requirements | [AI Hallucination Contracts](./docs/ai-hallucination-contracts.md) |
| Changed-lines review | `skylos . -a --diff origin/main` | Keeps findings focused on active work instead of legacy debt | [Quality gate docs](https://docs.skylos.dev/quality-gate) |
| Runtime-assisted dead-code check | `skylos . --trace` | Uses runtime traces to reduce dynamic-code false positives | [Smart tracing](https://docs.skylos.dev/smart-tracing) |
| Local rule pack | `skylos rules init` | Scaffolds YAML rules for project-specific security and quality checks | [Custom rules](https://docs.skylos.dev/custom-rules) |
| Security agent quick scan | `skylos agent security-quick .` | One-shot LLM security audit; compatibility alias for `skylos agent scan . --security` | [AI features](https://docs.skylos.dev/ai-features) |
| Security agent deep scan | `skylos agent security-deep .` | Three-stage security workflow with threat-model context, static threat traces, discovery/validation, and remediation handoff | [AI features](https://docs.skylos.dev/ai-features) |
| AI-assisted review | `skylos agent scan .` | Static analysis plus optional LLM review and fix suggestions | [AI features](https://docs.skylos.dev/ai-features) |
| Agent harness replay | `skylos agent replay .skylos/runs/<run-id>` | Validates and summarizes saved agent verification phases, tool calls, decisions, and budgets | [Agent harness artifacts](#agent-harness-artifacts) |
| Runtime agent behavior test | `skylos agent init && skylos agent test --allow-contract-endpoint` | Checks final responses, tool selection, explicit refusals, and source IDs against a versioned contract | [Agent Behavior Testing](./docs/agent-behavior-testing.md) |
| Verification-backed remediation | `skylos agent scan . --fix` | Re-scans fixed security findings and records proof-test metadata for supported fixes | [AI features](https://docs.skylos.dev/ai-features) |
| MCP agent verification | `verify_change` MCP tool | Lets Claude, Cursor, and other MCP clients verify an edited file/range with the same schema as `skylos verify` | [MCP server](https://docs.skylos.dev/mcp-server) |
| LLM integration inventory | `skylos discover .` | Maps every LLM call, agent tool, prompt site, and input source in the codebase | [Agent verification](./docs/agent-verification.md) |
| Pre-deployment agent verification | `skylos defend . --format md -o evidence.md` | Verifies agent guardrails, scores OWASP LLM/Agentic coverage, and emits an attested evidence report | [Agent verification](./docs/agent-verification.md) |
| Agent verification CI gate | `skylos defend . --fail-on critical` | Blocks deploys with unguarded LLM integrations; SARIF for code scanning via `--format sarif` | [Agent verification](./docs/agent-verification.md) |
| MCP agent pre-flight | `verify_agent` MCP tool | Lets coding agents statically verify the agents they build — scores, failed checks, attestation digest | [MCP server](https://docs.skylos.dev/mcp-server) |
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

## Verify AI Agents Before They Ship

Runtime guardrails are the WAF; Skylos is the SAST. `skylos discover`
inventories every LLM integration in a codebase (provider SDKs, agent
frameworks including the OpenAI Agents SDK, Claude Agent SDK, and Google ADK,
MCP servers and their tools, direct HTTP calls to LLM APIs or
OpenAI-compatible gateways, plus agent tools, prompt sites, and input
sources), and `skylos defend` verifies the guardrails around them —
deterministically, locally, with no model in the loop — then gates CI and
emits auditor-ready evidence.

```bash
skylos discover .                               # inventory LLM integrations and agent tools
skylos defend .                                 # score guardrails (13 weighted checks)
skylos defend . --format md -o evidence.md      # auditor evidence report + attestation
skylos defend . --format sarif -o defend.sarif  # GitHub code scanning upload
skylos defend . --fail-on critical              # CI gate: exit 1 on critical gaps
skylos defend . --owasp-framework agentic       # report against OWASP Agentic ASI Top 10
```

Per integration it verifies: dangerous output sinks (eval/exec/subprocess),
agent tool scope and typed schemas, prompt-injection exposure (delimiters,
untrusted input paths, RAG context isolation), output validation, PII
filtering, and model pinning — plus ops checks (logging, cost controls, rate
limiting) scored separately so they never inflate the security score.

- **OWASP mapping:** LLM Top 10 (2024/2025) and Agentic ASI Top 10 (2026).
- **Evidence report (`--format md`):** integration inventory, per-check
  results, OWASP coverage, regulatory framework evidence (EU AI Act, NIST AI
  RMF, ISO/IEC 42001 — "evidence toward" mappings, never compliance claims),
  and a remediation appendix.
- **Attestation:** JSON/md/SARIF reports carry a reproducible SHA-256 digest
  over file contents, policy, plugin set, integration inventory, scores, and
  full check evidence — re-run on the same tree with the same flags and Skylos
  version, and the digest must match.
- **CI-native:** `skylos cicd init --defend` generates the workflow step, the
  `skylos-defend` pre-commit hook gates locally, and `$GITHUB_STEP_SUMMARY`
  gets a score summary automatically in Actions.
- **Policy as code:** `skylos-defend.yaml` pins gate thresholds and severity
  overrides (`--policy`).
- **Agent-native:** the `verify_agent` MCP tool lets coding agents verify the
  agents they build — deterministic verification, not AI checking AI.

Static pre-deployment verification complements runtime controls (gateways,
policy engines, human approval flows); it does not replace them. Full guide:
[docs/agent-verification.md](./docs/agent-verification.md).

## Test Running Agent Behavior

Skylos separates generated-code truth, static agent guardrails, and observed
runtime behavior:

| Command | Verification question |
|:---|:---|
| `skylos verify` | Did the agent generate valid, non-hallucinated code? |
| `skylos defend` | Does the agent implementation contain the required guardrails? |
| `skylos agent test` | Did the running agent behave according to its contract? |

Create `.skylos/agent-test.yml`, then test a live OpenAI-compatible endpoint:

```bash
skylos agent init
skylos agent test --allow-contract-endpoint
```

Or evaluate captured evidence without a network call:

```bash
skylos agent test --observations agent-observations.json
skylos agent test --observations agent-observations.json \
  --format json --output agent-results.json
```

Version 1 deterministically checks exact response substrings, required,
allowed, and forbidden tool calls, tool arguments and sequence, maximum call
count, explicit refusals, and explicit source IDs. Missing typed evidence is
`incomplete`, never `pass`; exit codes are `0` pass, `1` violation, and `2`
incomplete/invalid. Tool selection and final-answer source-ID checks are separate
one-turn scenarios: Skylos records local replayable evidence but never executes
tools returned by the target agent. Offline observations are marked as
unverified fixtures rather than runtime proof.

For an authenticated remote endpoint, keep the destination and secret choice
in the trusted CLI invocation:

```bash
skylos agent test --endpoint https://agent.example.com/v1/chat/completions \
  --allow-remote --auth-env MY_AGENT_API_KEY
```

Full guide: [docs/agent-behavior-testing.md](./docs/agent-behavior-testing.md).

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
- **Evidence-backed AI defects:** `--ai-defects` and full scans put strict
  AI-code failure checks under `ai_defects`, including phantom references, fake
  package APIs, nonexistent packages, impossible dependency versions, and
  weakened test assertions.
  The category/tag is `ai_defect`; several rules intentionally keep historical
  `SKY-L` or `SKY-D` IDs for suppression and baseline compatibility, while new
  AI-defect-only checks use `SKY-A`.
- **Verification-backed remediation:** security fixes are checked by re-running
  analysis, and supported findings can include targeted regression-test proof
  metadata.
- **Project-specific rules:** add local YAML rules and extend prompt, credential,
  sensitive-file, and timeout dictionaries from config.
- **One command surface:** dead code, security, secrets, dependency, quality,
  technical debt, agent review, and pre-deployment agent verification commands
  share the same CLI.

## Agent Harness Artifacts

`skylos agent verify .` and `skylos agent test` record replayable artifacts
under `.skylos/runs/<run-id>` and print the run directory in table output. JSON
output includes the same harness summary under the `harness` key.

Use `skylos agent replay .skylos/runs/<run-id>` to validate and inspect a saved
run without making LLM calls. Add `--format json` when another agent or CI job
needs machine-readable status. A valid replay exits `0`; an invalid or corrupt
artifact set exits `1` with issue codes. Replay output includes
`schema_version` so CI and agents can detect artifact-contract changes.
Replay checks internal consistency and corruption; artifacts are not signed and
are not proof against an actor that can rewrite the entire run directory.

Each run directory contains:

- `events.jsonl`: chronological run, phase, and tool-call events.
- `state.json`: full observable state, including phases, tool calls, decisions,
  and budget usage.
- `summary.json`: compact status, counts, budget, and artifact paths.
- `behavior-results.json`: normalized runtime assertions, provenance, coverage,
  and a digest-bound evidence report for `skylos agent test` runs.

The current harness state is observable and replay-validated. It is not yet a
resume mechanism for continuing interrupted verification runs.

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
[tool.skylos]
exclude = ["node_modules", "dist"]

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
precedence over repository-controlled config. The top-level
`[tool.skylos].exclude` list applies to the main scan and commands such as
`skylos debt` and `skylos clean`; pass `--exclude` for command-local additions
or `--include-folder` to override an excluded folder.

## Language Support

| Language | Dead Code | Security | Quality | Local API Proof (`verify`) | Notes |
|:---|:---:|:---:|:---:|:---:|:---|
| Python | Yes | Yes | Yes | Supported | strongest coverage; framework-aware static analysis and optional tracing |
| TypeScript / JavaScript | Yes | Yes | Yes | Supported | Tree-sitter parsing, package graph reachability, framework conventions |
| Java | Yes | Yes | Yes | Supported | Tree-sitter parsing, structured security-flow analysis, conservative static-member proof |
| Go | Yes | Partial | Partial | Supported | native engine status remains separate from deterministic workspace API proof |
| PHP | Yes | Yes | Partial | Unsupported | PHP parser coverage plus taint-style security sinks and sources |
| Rust | Yes | Yes | Partial | Unsupported | Rust parser coverage plus security sink/source checks |
| Dart | Yes | Yes | Partial | Unsupported | Dart parser coverage plus selected security sinks and sources |
| C# | Yes | Yes | Partial | Unsupported | C# symbol coverage plus selected ASP.NET, process, SQL, HTTP, and file sinks |
| Kotlin | Yes | Partial | Partial | Unsupported | Kotlin symbol extraction with conservative static-analysis coverage |
| Shell | No | Yes | Partial | Unsupported | shell-script security checks for command injection, SSRF, and path traversal |

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
dead code, security, secrets, quality, and AI-defect checks.

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
