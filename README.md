[![MCP Toplist](https://mcptoplist.com/badge/io.github.duriantaco%2Fskylos.svg)](https://mcptoplist.com/server/io.github.duriantaco%2Fskylos)

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
JavaScript, Java, Go, Kotlin, PHP, Rust, Dart, C#, C++, Shell, and deployment config. It
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

## Choose the Right Command

Each command answers a different question. The source scan requires `PATH`.
Bracketed paths on `verify`, `suite`, `defend`, and `clean` default to the
current directory. `suite` and `defend` require a directory; `verify` and
`clean` also accept a file.

| Question | Command | Input checked |
|:---|:---|:---|
| What problems are in this source tree? | `skylos PATH` | Source files and project configuration; dead code by default, every main source analyzer with `-a` |
| Does this code contain AI-code mistakes? | `skylos verify [PATH]` | AI-defect checks over the selected file or tree, plus a separate Git HEAD behavior comparison for supported Python working changes |
| Will this exact local GPU build fit the machines we ship to? | `skylos preflight [ARTIFACT]` | A local built file or directory and `.skylos/gpu-targets.yml`; an OCI reference is identity-only and returns `UNKNOWN` in the CLI |
| What vulnerabilities are in this container image? | `skylos image scan IMAGE@sha256:<digest> --platform os/arch` | A remote registry image scanned by a separately installed Trivy; `--fail-on` turns findings into a gate |
| What does the combined repo suite report? | `skylos suite [DIRECTORY]` | Static analysis, technical debt, AI defense, and provenance; local findings are report-only by default |
| Does an agent implementation have deployment guardrails? | `skylos defend [DIRECTORY]` | Recognized Python and TypeScript/JavaScript LLM integrations; gating requires a threshold flag or policy |
| Which Python dead code can Skylos remove? | `skylos clean [PATH] --dry-run` | Python import/function cleanup candidates; `--dry-run` never writes |

Run `skylos --help` for this chooser, `skylos <command> --help` for one
command, and `skylos commands` for the command-family map.

The report commands have different gate and network behavior:

- `image scan` requires Trivy on trusted `PATH` and uses Trivy's remote image
  source, so registry network access and any required registry credentials must
  already be available. Without `--fail-on`, a completed scan exits `0` even
  when it reports vulnerabilities.
- `suite` runs in the local process and does not upload unless `--upload` is
  set, but its dependency scan can query OSV. Findings are report-only: the
  command exits `0` regardless of their count. Operational and output failures
  are nonzero; `--upload` can also fail for an upload error or Cloud quality
  gate.
- `defend` reports guardrail findings by default. It becomes a gate with
  `--fail-on`, `--min-score`, or gate settings in an explicit policy.
- `clean` without `--dry-run` or `--apply` is interactive and can write after
  the final confirmation. Its current codemods support Python imports and
  functions. An apply pass still exits `0` if an individual edit prints a
  failure, so review the completion output.

## Start In 60 Seconds

```bash
pip install skylos
skylos .
```

The default scan focuses on dead code. Run every main source analyzer,
including security, secrets, quality, dependency, and AI-defect checks, with
`-a`:

```bash
skylos . -a
```

Run only evidence-backed AI defect checks with:

```bash
skylos . --ai-defects
```

Verify a repository, file, or range before an agent hands it to review:

```bash
skylos verify . --file src/app.py --range 40:75 --project-context
```

For a directory such as `.`, the AI-defect scan covers the selected tree. The
separate `behavior` result models supported Python working-tree changes against
Git HEAD; it is not the scope selector for the AI-defect scan. Dependency
hallucination checks are enabled for path targets and can query package
registries; use `--no-dependency-hallucinations` to disable those lookups.
Interactive terminals get a human report. Redirected stdout and `-o` produce
the versioned JSON result.

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

## Check an Exact GPU Release Artifact

`skylos preflight` checks the built artifact itself against the repository's
declared GPU fleet. This is separate from the `SKY-GPU*` source scan, which
checks Dockerfiles, CUDA build settings, and TensorRT packaging intent before
the artifact exists.

Declare every machine that receives the same release:

```yaml
# .skylos/gpu-targets.yml
version: 1
targets:
  - name: inference-t4
    vendor: nvidia
    driver: "535.104.05"
    compute_capability: "7.5"
    platform: "linux/amd64"
```

The canonical filename is `.skylos/gpu-targets.yml`; the same schema is also
accepted as `.skylos/gpu-targets.yaml`.

Then inspect a local build. Skylos uses a trusted system `cuobjdump`, takes a
private snapshot, and never loads or executes the artifact:

```bash
skylos preflight build/app
```

To make the command argument-free in CI, bind it to a project-relative
artifact with a strict release receipt:

```json
{"version": 1, "artifact": "build/app"}
```

Save that file as `.skylos/release.json`, then run `skylos preflight`.
For requests that reach report generation, terminal output is concise and
redirected output is schema-versioned JSON. Argument or adapter errors can be
plain text and exit `2`.

| Status | Exit | Meaning |
|:---|:---:|:---|
| `PASS` | `0` | Every declared target is compatible within the stated static evidence scope, and the exact artifact identity is verified |
| `FAIL` | `1` | Artifact evidence proves at least one declared target incompatible |
| `UNKNOWN` | `2` | Required evidence is missing, ambiguous, unsupported, or incomplete; it never silently becomes a pass |

`cuobjdump` can report several code-object groups, identified by the producer
label in its selected executable fatbin. Skylos requires a compatible route
for every reported group. A PTX-only route stays `UNKNOWN` because static
inspection cannot prove that the deployment driver will JIT it successfully.
The overall result is `FAIL` if any target or required check fails; otherwise
it is `UNKNOWN` if any result is unknown, and `PASS` only when all results pass.

Version 1 proves the local artifact identity, Linux ELF platform, selected
executable-fatbin architecture routes, a static packaged `$ORIGIN` CUDA
runtime route, and documented CUDA driver-family compatibility. It does not
prove runtime execution, workload correctness, memory demand, performance,
nonselected or relocatable fatbins, or per-kernel symbol parity. Windows PE
runtime import proof is not implemented. Digest-pinned OCI references are
accepted as identities but are never pulled or started, so the CLI always
reports `UNKNOWN` for them; trusted callers can supply digest-bound inspection
facts through `skylos.preflight.run_preflight(...)`.

## Common Workflows

| Goal | Command | What You Get | More Detail |
|:---|:---|:---|:---|
| First dead-code scan | `skylos .` | Finds unused functions, classes, imports, files, and framework entrypoint mistakes | [Dead code docs](https://docs.skylos.dev/dead-code-detection) |
| Deterministic cleanup preview | `skylos clean . --dry-run --types import,function --confidence 80` | Shows planned Python import/function removals without writing; add `--apply` to edit files | [Dead code docs](https://docs.skylos.dev/dead-code-detection) |
| Security and quality audit | `skylos . -a` | Adds dangerous flow, secrets, dependency, config, quality, and AI-defect checks | [Security docs](https://docs.skylos.dev/security-analysis) |
| Combined repo report | `skylos suite .` | Reports static findings, technical debt, AI defense, and provenance; SCA can query OSV, and findings alone exit `0` | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| Optional Python linting | `pip install "skylos[lint]" && skylos lint .` | Runs Ruff with its native configuration, output, fixes, and exit codes through the Skylos CLI | [Python linting](./docs/python-linting.md) |
| PR gate | `skylos cicd init` | Generates a GitHub Actions workflow with annotations and failure thresholds | [CI/CD guide](https://docs.skylos.dev/ci-cd) |
| GitLab merge request report | `skylos . --format gitlab -o gl-code-quality-report.json` | Exports a native Code Quality report for GitLab CI artifacts | [GitLab Code Quality](./docs/gitlab-code-quality.md) |
| Offline dependency SBOM | `skylos sbom . -o sbom.cdx.json` | Lists supported recorded dependencies as CycloneDX 1.6 JSON without network requests | [Dependency scanning](./docs/dependency-scanning.md#export-an-sbom-offline) |
| Container-image scan | `skylos image scan IMAGE@sha256:<digest> --platform linux/amd64 --fail-on high` | Uses separately installed Trivy, registry network/auth, and an explicit severity gate for a pinned remote image | [Container-image scanning](./docs/container-image-reports.md) |
| Built GPU artifact preflight | `skylos preflight build/app` | Verifies the exact local artifact identity, selected CUDA architectures, packaged runtime route, and declared fleet compatibility; returns `PASS`, `FAIL`, or `UNKNOWN` | [Release reliability](https://docs.skylos.dev/release-reliability) |
| Container-image report import | `skylos ingest trivy --input trivy.json --sarif image.sarif` | Converts an existing Trivy image vulnerability report to Skylos JSON/SARIF; optional digest-bound severity check | [Container-image scanning](./docs/container-image-reports.md#import-an-existing-trivy-report) |
| Readable terminal report | `skylos . --format pretty` | Groups findings by file with severity badges, snippets, and copyable `file:line` locations | [CLI output modes](./docs/cli-output.md) |
| Single-rule review | `skylos . --select SKY-L012 --format concise` | Enables the matching analyzer family and reports only that exact rule with its full message | [CLI output modes](./docs/cli-output.md) |
| Selectable terminal triage | `skylos . --tui` | Opens a keyboard-driven category list, finding list, and detail pane | [CLI output modes](./docs/cli-output.md) |
| IDE/test-script output | `skylos --format concise src/test.py` | Prints untruncated `file:line  RULE_ID  message` findings and exits non-zero when findings exist | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| In-loop AI-code verification | `skylos verify . --file src/app.py --range 40:75` | Reports a narrow set of hallucinated helpers, unfinished code, stale references, disabled controls, and API/dependency hallucinations; JSON is used for redirected or `-o` output | [AI features](https://docs.skylos.dev/ai-features) |
| AI hallucination contracts | `skylos contract init && skylos verify .` | Auto-discovers `.skylos/ai-contract.yml` and verifies generated code against repo-specific symbols, dependencies, APIs, route guards, and test requirements | [AI Hallucination Contracts](./docs/ai-hallucination-contracts.md) |
| Changed-lines review | `skylos . -a --diff origin/main` | Keeps findings focused on active work instead of legacy debt | [Quality gate docs](https://docs.skylos.dev/quality-gate) |
| Incumbent scanner comparison | `skylos compare . --against incumbent.sarif [--upload]` | Runs Skylos beside the current scanner and produces a revision-aware scorecard: active overlap, raw unique findings by category, and eligible findings inside evidence-backed unused symbols—without replacing the current gate. `--upload` preserves a project-bound Cloud receipt. | [Scanner comparison](./docs/scanner-comparison.md) |
| Kubernetes exposure proof | `skylos . --select SKY-DEP001,SKY-DEP002,SKY-DEP003 --format concise` | Checks an explicitly external, explicitly plain-HTTP Ingress chain inside one rendered multi-document bundle; route checks compare exact framework wiring with the workload's declared source file and required guards | [Deployment exposure rules](./dictionary.md#kubernetes-deployment-exposure-sky-dep) |
| GPU source/build intent gate | `skylos . --select SKY-GPU000,SKY-GPU001,SKY-GPU002,SKY-GPU003 --gate --format concise` | Checks declared CUDA image, architecture, driver, and TensorRT packaging intent before the artifact is built | [GPU target contract](./dictionary.md#gpu-release-compatibility-sky-gpu) |
| Runtime-assisted dead-code check | `skylos . --trace` | Uses runtime traces to reduce dynamic-code false positives | [Smart tracing](https://docs.skylos.dev/smart-tracing) |
| Local rule pack | `skylos rules init` | Scaffolds YAML rules for project-specific security and quality checks | [Custom rules](https://docs.skylos.dev/custom-rules) |
| Security agent quick scan | `skylos agent security-quick .` | One-shot LLM security audit; compatibility alias for `skylos agent scan . --security` | [AI features](https://docs.skylos.dev/ai-features) |
| Security agent deep scan | `skylos agent security-deep .` | Three-stage security workflow with threat-model context, static threat traces, discovery/validation, and remediation handoff | [AI features](https://docs.skylos.dev/ai-features) |
| AI-assisted review | `skylos agent scan .` | Static analysis plus optional LLM review and fix suggestions | [AI features](https://docs.skylos.dev/ai-features) |
| Agent harness replay | `skylos agent replay .skylos/runs/<run-id>` | Validates and summarizes saved agent verification phases, tool calls, decisions, and budgets | [Agent harness artifacts](#agent-harness-artifacts) |
| Runtime agent behavior test | `skylos agent init && skylos agent test --allow-contract-endpoint` | Checks final responses, tool selection, explicit refusals, and source IDs against a versioned contract | [Agent Behavior Testing](./docs/agent-behavior-testing.md) |
| Verification-backed remediation | `skylos agent remediate .` | Scans and fixes supported findings, then re-scans them and records proof-test metadata when available | [AI features](https://docs.skylos.dev/ai-features) |
| MCP agent verification | `verify_change` MCP tool | Lets Claude, Cursor, and other MCP clients verify an edited file/range with the same schema as `skylos verify` | [MCP server](https://docs.skylos.dev/mcp-server) |
| LLM integration inventory | `skylos discover .` | Maps recognized LLM calls, agent tools, prompt sites, and input sources in Python and TypeScript/JavaScript | [Agent verification](./docs/agent-verification.md) |
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
| Kubernetes deployment exposure | Explicitly external Ingress paths reaching a sensitive FastAPI/Flask route without its deployment-required guard, Flask `--debug`, or an application server using `--reload` | reports only when the resources are in one rendered bundle and every deployment edge resolves unambiguously |
| GPU release compatibility | source/build contract mismatches plus built-artifact identity, selected CUDA architecture, packaged runtime, and fleet checks | catches declared intent errors early and verifies the resulting local artifact before release |
| Quality regressions | complexity, deep nesting, duplicate branches, long functions, inconsistent returns | keeps AI-assisted refactors from adding brittle code |
| AI code mistakes | phantom security calls, missing decorators, unfinished stubs, disabled controls, real packages called with invented APIs, impossible npm/Go versions | catches common hallucinated or incomplete code paths before they reach review |
| LLM app risks | unsafe tool use, prompt injection exposure, missing output validation, missing rate limits | helps teams ship AI features with guardrails |

See the full [Rules Reference](https://docs.skylos.dev/rules-reference).

## Verify AI Agents Before They Ship

Runtime guardrails are the WAF; Skylos is the SAST. `skylos discover` scans
Python and TypeScript/JavaScript for recognized LLM integrations (provider
SDKs, agent frameworks including the OpenAI Agents SDK, Claude Agent SDK, and
Google ADK, MCP servers and their tools, direct HTTP calls to LLM APIs or
OpenAI-compatible gateways, plus agent tools, prompt sites, and input
sources). `skylos defend` checks the guardrails around those detected
integrations deterministically, in the local process, with no model in the
loop. It emits evidence by default and becomes a CI gate only when a threshold
flag or policy supplies gate criteria.

```bash
skylos discover .                               # inventory LLM integrations and agent tools
skylos defend .                                 # score guardrails (13 weighted checks)
skylos defend . --format md -o evidence.md      # auditor evidence report + attestation
skylos defend . --format sarif -o defend.sarif  # GitHub code scanning upload
skylos defend . --fail-on critical              # CI gate: exit 1 on critical gaps
skylos defend . --owasp-framework agentic       # report against OWASP Agentic ASI Top 10
```

These commands do not inspect integrations in other languages. If discovery
finds no supported integration, `defend` returns an empty inventory; do not
treat the resulting score by itself as proof that an unsupported or
unrecognized agent implementation has guardrails.

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
- **Local-first operation:** core analysis executes locally and does not upload
  source or call an LLM. Dependency/CVE checks can query OSV or package
  registries, and direct container scanning contacts a registry through Trivy.
- **AI-assisted change review:** checks for removed validation, auth, logging,
  CSRF, rate limiting, timeouts, real-package API hallucinations, and other
  guardrails in generated or edited code.
- **Agent-loop verification:** `skylos verify` and MCP `verify_change` use a
  versioned result schema for AI-code trust findings, so coding agents can
  self-correct before a human sees the change. The CLI renders a human report
  on a terminal and JSON when redirected or written with `-o`.
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

# Ruff Python linting through `skylos lint`
pip install "skylos[lint]"

# All published optional extras
pip install "skylos[all]"
```

Container image:

```bash
docker pull ghcr.io/duriantaco/skylos:latest
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . --json --no-provenance
```

The unqualified image uses Python 3.14. Runtime-specific tags are also
published for Python 3.11 through 3.14, so container scans can match a local or
CI parser exactly:

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest-python3.13 . --json --no-provenance
```

If a Python file cannot be parsed, Skylos reports `analysis_errors`, omits the
grade, and exits with code 2 instead of treating the skipped file as clean.

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
| C++ | Partial | No | No | Unsupported | conservative unused file-local functions in `.cpp`, `.cc`, `.cxx`; C++ headers are parsed for references |
| Kotlin | Yes | Partial | Partial | Unsupported | Kotlin symbol extraction with conservative static-analysis coverage |
| Shell | No | Yes | Partial | Unsupported | shell-script security checks for command injection, SSRF, and path traversal |

Java security analysis follows directly implemented request-data helpers in
same-package files or source files identified by exact imports or fully qualified
names under a verified local source root. Helper reads are bounded and reject
symlinks; no Java code or build scripts are executed. This is not full classpath
or recursive helper analysis. Unknown helpers are not assumed to be request
sources or sanitizers.

C++ analysis covers `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, and `.hxx`. The first
release reports only apparently unused file-local free functions. Without a
build configuration, it cannot fully resolve templates, overloads, macros, or
external usage; these findings are a conservative heuristic, not a proof of
C++ deadness. Ambiguous `.h` files and C files are not analyzed as C++.

Java weak-hash checks also follow local algorithm variables and values loaded
through `java.util.Properties` from literal classloader resources. Resource
lookup stays within the matching `src/main/resources` or `src/test/resources`
directory. Missing resources, unsupported loaders/layouts, conflicting branch
values, and unresolved mutations remain unknown. Properties are used only as
crypto evidence, never to prove a security guard or choose a safe branch. This
does not resolve arbitrary runtime classpaths, JAR resources, or environment
overrides.

TypeScript and JavaScript dead code analysis recognizes `package.json` entry
fields, including `bin`. For targets under `dist/` or `out/`, it checks the
matching `src/` location first, then the package root, before the declared
output. This also covers `dist/bin/palee.js` mapping to `bin/palee.ts` and
`dist/src/index.js` mapping to `src/index.ts`. If both source locations exist,
the `src/` mapping keeps priority; unrelated files are not treated as entries.

For ESM build scripts invoked by package scripts, Skylos also follows top-level
esbuild calls using unchanged constants, spreads, templates, Node path helpers,
and simple literal-array maps. Build scripts are never executed. Nested build
calls and filesystem-generated entry lists remain unsupported and may still
produce unused-file findings.

VitePress configs at `.vitepress/config.*` and `.vitepress/config/index.*`
are recognised as development entrypoints for `.js`, `.ts`, `.mjs` and `.mts`.
Other files in `.vitepress` still need a reference or another entrypoint rule.
Existing directory conventions such as `scripts/` work with native Windows
separators too; this does not add general discovery of commands in CI workflows.

Vue single file components (`.vue`) are skipped by source analysis, including
when passed explicitly. Skylos does not yet parse their `<script>` or
`<script setup>` blocks; separate JavaScript, TypeScript and backend source
files are still analyzed. Existing browser script and event references in
templates are unaffected.

Go dead-code and security checks require the native `skylos-go` engine. If
Skylos discovers Go files but cannot run that engine, the report is marked
incomplete, no grade or clean result is produced, and the CLI exits with status
`2`. Run `skylos doctor` to verify engine availability and configure
`SKYLOS_GO_BIN` when using a separately built engine. The official GitHub
Action builds the matching native engine automatically.

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
| Rendered Kubernetes exposure | one multi-document `*.yml` or `*.yaml` bundle plus a contracted Python source file | opt-in proof from an Ingress annotated `skylos.dev/network-scope: external` (or `public`) and `skylos.dev/backend-protocol: http` through its Service and workload; `SKY-DEP001` checks direct top-level FastAPI/Flask routes against `skylos.dev/source-file` and `skylos.dev/required-guards`, `SKY-DEP002` catches an effective Flask debugger, and `SKY-DEP003` catches effective reload mode |
| GPU release contract | `.skylos/gpu-targets.yml`, Dockerfiles, CMake/CUDA build files, TensorRT source | static target-fleet checks for driver, compute-architecture, and serialized-engine compatibility; no hardware probing |

## Benchmark Snapshot

Skylos has checked-in regression benchmarks for dead code, security, quality,
and agent review. These are strict regression gates, not broad proof that any
tool is universally state of the art.

| Suite | Current Skylos Result | Baseline |
|:---|:---|:---|
| Dead code regression | 21 cases, TP=47 FP=0 FN=0 TN=77, score 100.0 | Ruff and Vulture are optional comparison installs |
| Security regression | 56 cases, TP=35 FP=0 FN=0 TN=23, score 100.0 | Bandit score 47.14 on Python-applicable cases |
| Quality regression | 13 cases, score 100.0 | regression gate only |
| Agent review | 25 cases, score 100.0 | regression gate only |
| AI-code defect regression | curated verifier cases for hallucinated references, package APIs, and dependency versions | run `python scripts/ai_code_defect_benchmark.py` |

Frozen `golden-v0.2` highlights:

| Frozen Suite | Skylos Result | Caveat |
|:---|:---|:---|
| Dead code seeded dev | overall score 96.28; TS/JS/Go/Java score 100.0; Python score 93.33 | Python residuals are label-review items |
| Security seeded dev | overall score 96.52; full recall with one Python `urljoin` false positive | label should be reviewed |
| OWASP Java security dev | TP=120 FP=0 FN=0 TN=120, score 100.0 | 240-case development subset, not general Java coverage; direct static analysis plus focused CLI checks |
| Quality seeded dev | TP=1 FP=0 FN=0 TN=1, score 100.0 | one seeded case only |

For methodology, commands, competitor rows, and caveats, see
[BENCHMARK.md](./BENCHMARK.md).

An experimental Jev runner can blindly score the pinned `jev-1.13.0` typed
decision model against the checked-in 124 dead-code labels or the frozen
`skylos-benchmarks` corpus. It withholds labels and review reasons from the
request, retains golden label IDs locally for exact classifier comparison, and
repeats the test with answer-signaling identifiers neutralized. Live mode sends
fixture source to TypeSafe, requires an explicit flag and a separate
`TYPESAFE_API_KEY`, and records request versus local contract-validation
latency. No live Jev result is claimed here yet. See the
[dead-code benchmark guide](./benchmarks/dead_code/README.md#jev-semantic-research-benchmark).

### Real-project regression testing

[liveness_primer](https://github.com/mcdigman/liveness_primer), created and
maintained by [Matthew Digman](https://github.com/mcdigman), is Skylos's official
real-project regression testing tool. On every PR, it compares the base and
proposed merge result against the same pinned Python projects and reports
which findings were added, removed, or changed.

Read the **Analyzer Blast Radius** check for the comparison and downloadable
reports. These results complement the labeled benchmarks above; a change in
finding counts alone does not establish accuracy. See the
[liveness_primer guide](./docs/liveness-primer.md) for scope, review steps, and
reproduction commands.

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
| GitHub Action | [GitHub Action](./action.yml) | Repository PR gates or optional digest-pinned container-image gates |
| GitLab Code Quality | [GitLab setup](./docs/gitlab-code-quality.md) | merge request report artifacts; no comment-posting bot or API token |
| VS Code extension | [VS Code extension](./editors/vscode/README.md) | in-editor findings and AI-assisted fixes |
| MCP server | [MCP setup](https://docs.skylos.dev/mcp-server) | expose Skylos scans to AI agents and coding assistants |
| Ruff | [Python linting](./docs/python-linting.md) | optional Python linting through `skylos lint` |
| Docker image | [Installation](https://docs.skylos.dev/installation) | run Skylos without a local Python install |
| Skylos Cloud | [Cloud workflow](https://docs.skylos.dev/cloud-workflow) | optional upload and dashboard workflows |

Generate a GitHub Actions workflow from the CLI:

```bash
skylos cicd init --upload
skylos cicd init --upload --scan-path apps/api
```

The generated workflow reviews changed lines on pull requests and uploads full
scans on pushes using GitHub OIDC. It supports monorepo subprojects through
`--scan-path`.

To scan a built image with the composite Action, install a pinned Trivy version
in the caller's job and set `image` to a trusted `repository@sha256:<digest>`
build output plus `image-platform`. This runs an image-only scan; `mode: gate`
uses `image-fail-on` (default `high`), while `mode: scan` only reports findings.
See [container-image scanning](./docs/container-image-reports.md#scan-an-image-with-the-github-action).

## Documentation Map

| Need | Read This |
|:---|:---|
| Install options, source install, and Docker | [Installation](https://docs.skylos.dev/installation) |
| First scan and core workflows | [Quick Start](https://docs.skylos.dev/quick-start) |
| CLI commands, flags, and examples | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| CLI output modes, pretty reports, and TUI controls | [CLI Output Modes](./docs/cli-output.md) |
| Optional Ruff linting through the Skylos CLI | [Python Linting](./docs/python-linting.md) |
| CI setup, PR gates, annotations, and branch protection | [CI/CD](https://docs.skylos.dev/ci-cd) |
| GitLab merge request reports and CI example | [GitLab Code Quality](./docs/gitlab-code-quality.md) |
| Dead-code behavior and framework awareness | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| Security scanning and taint analysis | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Dependency CVEs, uv/npm/pnpm/Poetry/Yarn lockfiles, offline SBOM, and SCA in CI | [Dependency Scanning](./docs/dependency-scanning.md) |
| Digest-pinned container-image scanning and GitHub Action setup | [Container-image scanning](./docs/container-image-reports.md) |
| Source GPU contracts and built-artifact preflight | [Release Reliability](https://docs.skylos.dev/release-reliability) |
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

**Does Skylos replace Ruff?**

No. `skylos lint` is an optional convenience entry point that delegates to
Ruff. Install it with `pip install "skylos[lint]"`; normal Skylos scans do not
run Ruff or merge Ruff violations into `SKY-*` findings.

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
