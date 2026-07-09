# Pre-Deployment Agent Verification

Statically verify an AI agent's guardrails before it ships. `skylos discover`
inventories every LLM integration in the tree — provider SDK calls, agent
frameworks (LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Claude
Agent SDK, Google ADK, and more), MCP servers and their tools, and direct
HTTP calls to LLM APIs or OpenAI-compatible gateways. `skylos defend` runs 13
deterministic checks against each integration, scores the result, gates CI,
and emits auditor-ready evidence with a reproducible attestation digest.

Runtime guardrails are the WAF; this is the SAST. Verification is AST-based,
runs locally, and involves no model — the same tree with the same flags,
policy, plugin set, and Skylos version produces the same verdict and digest.

## Quick start

```bash
skylos discover .                               # what LLM integrations exist?
skylos defend .                                 # are they guarded? (table)
skylos defend . --format md -o evidence.md      # evidence report + attestation
skylos defend . --format sarif -o defend.sarif  # GitHub code scanning
skylos defend . --json                          # machine-readable (schema 1.1)
skylos defend . --fail-on critical              # CI gate
```

`skylos defend` exits `1` when the gate fails (`--fail-on`, `--min-score`, or
policy `gate.*`), otherwise `0`. Format never changes gating: a SARIF or md
run with `--fail-on high` still writes the report and exits non-zero.

## The 13 checks

Defense checks (weighted; drive the defense score and the gate):

| Check | Severity (weight) | OWASP LLM | Verifies |
|---|---|---|---|
| `no-dangerous-sink` | critical (8) | LLM02 | No `eval`/`exec`/`subprocess` sink in the LLM output scope |
| `tool-scope` | critical (8) | LLM04 | Agent tools avoid dangerous calls |
| `tool-schema-present` | critical (8) | LLM04 | Every agent tool has a typed schema |
| `untrusted-input-to-prompt` | critical (8) | LLM01 | Untrusted input cannot reach prompts unguarded |
| `prompt-delimiter` | high (5) | LLM01 | Untrusted input is delimited inside prompts |
| `output-validation` | high (5) | LLM02 | Model output is validated before use |
| `rag-context-isolation` | high (5) | LLM01 | Retrieved context is isolated from instructions |
| `output-pii-filter` | high (5) | LLM06 | PII filtering guards model output |
| `model-pinned` | medium (3) | LLM03 | Model version is pinned, not floating |
| `input-length-limit` | low (1) | LLM01 | Input length is limited before prompting |

Ops checks (scored separately as the ops score; never gate CI and never
inflate the defense score):

| Check | Severity | OWASP LLM | Verifies |
|---|---|---|---|
| `logging-present` | medium | — | LLM calls are logged |
| `cost-controls` | medium | LLM10 | `max_tokens`/cost limits are set |
| `rate-limiting` | medium | LLM10 | LLM-facing input paths are rate limited |

Scoring: defense score = passed weight / total weight, rated `SECURE` (≥90),
`LOW` (≥75), `MEDIUM` (≥50), `HIGH` (≥25), `CRITICAL` (&lt;25). Checks apply
per integration only where relevant (`applies_to`), so a tool-less chat app
is not penalized for agent-tool checks. MCP server integrations get the tool
checks (`tool-scope`, `tool-schema-present`) but are exempt from call-shaped
checks (`model-pinned`, `cost-controls`, `output-validation`,
`no-dangerous-sink`) that have no meaning for a server exposing tools.

## OWASP frameworks

Coverage is reported against OWASP LLM Top 10 **2024** or **2025** (default)
and the OWASP **Agentic ASI Top 10 2026**:

```bash
skylos defend . --owasp-framework agentic          # ASI01–ASI10
skylos defend . --owasp-framework llm --owasp-version 2024
skylos defend . --owasp LLM01,LLM04                # filter to specific risks
```

The md evidence report always includes both the selected framework and its
counterpart, so one artifact answers both "LLM risks" and "agentic risks".

## Output formats

`--format table` (default), `--format json` (alias: `--json`), `--format md`,
`--format sarif`. `-o/--output` writes any format to a file.

- **json** — schema `1.1`: `version`, `skylos_version`, `timestamp`,
  `project`, `summary` (scores, by-severity), `integrations[]` (inventory +
  per-integration scores), `findings[]` (every check result with remediation),
  `owasp_coverage`, `framework_evidence`, `ops_score`, `attestation`.
- **md** — the auditor evidence report: executive summary, integration
  inventory, per-check results, OWASP coverage (both frameworks), regulatory
  framework evidence, remediation appendix, attestation, methodology.
- **sarif** — SARIF 2.1.0 with only failed defense checks (ops results and
  passes excluded); ready for GitHub code scanning upload. Rule IDs are the
  check ids above; the attestation rides in `runs[0].properties`.

## Attestation

Every non-table report carries an attestation block:

```json
"attestation": {
  "algorithm": "sha256",
  "digest": "9f2c…",
  "generated_at": "2026-07-05T08:14:03+00:00",
  "inputs": {
    "files_hashed": 42,
    "files_digest": "ab41…",
    "policy_hash": null,
    "plugin_set": ["cost-controls", "…"],
    "owasp_framework": "llm",
    "owasp_version": "2025",
    "skylos_version": "4.27.0",
    "results_digest": "31bb…",
    "integrations_digest": "47e2…",
    "run_evidence_digest": "ce90…"
  }
}
```

The digest is SHA-256 over a canonical JSON document containing: the
attestation schema tag, the Skylos version, the sorted list of scanned files
(target-relative POSIX paths + per-file SHA-256), the policy file hash (or
null), the sorted active plugin ids, the OWASP selection, the CLI filters,
the integration inventory, defense/ops scores, selected OWASP coverage,
framework evidence, and the sorted full check evidence (all public result
fields including messages, remediation, weights, and OWASP ids).
`generated_at` is **not** part of the digest input.

Consequences:

- Re-running on an identical tree with identical flags, policy, plugin set,
  and Skylos version reproduces an identical digest — on any machine.
- Any file edit, policy change, plugin-set change, or result change produces
  a different digest, so changed run evidence is detectable by re-running.

To re-verify a report: `skylos defend <path> --format json` on the same tree
with the same flags and Skylos version; compare `attestation.digest`.

## Regulatory framework evidence

JSON and md reports include `framework_evidence`: check results mapped to
controls in the **EU AI Act (Regulation (EU) 2024/1689)** (Art. 12
record-keeping, Art. 15 accuracy/robustness/cybersecurity, Art. 15(5)
resilience against AI-specific attacks), the **NIST AI RMF 1.0**
(trustworthiness characteristics), and **ISO/IEC 42001:2023** (Annex A
control themes).

The semantics are strictly **"evidence toward"** the referenced control —
never a compliance determination, certification, or legal advice. Each
report states this disclaimer, and the md report lists obligations static
verification cannot address (e.g. EU AI Act Art. 14 human oversight,
organizational risk-management processes). Passing every check does not make
a system compliant with anything; it gives an auditor deterministic,
reproducible evidence about the state of the agent's code-level guardrails
at a point in time.

## Policy as code

```yaml
# skylos-defend.yaml (loaded only via --policy, never auto-discovered)
rules:
  output-pii-filter:
    severity: critical      # raise severity for your context
  input-length-limit:
    enabled: false          # disable a check
gate:
  min_score: 75             # exit 1 below this defense score
  fail_on: high             # exit 1 on any failed check at/above this severity
```

```bash
skylos defend . --policy skylos-defend.yaml
```

The policy file's hash is part of the attestation digest, so evidence is
bound to the exact policy it was scored against.

## CI and pre-commit

```bash
skylos cicd init --defend        # generate a workflow with a defend step
```

Pre-commit hook (ships with the repo's `.pre-commit-hooks.yaml`):

```yaml
repos:
  - repo: https://github.com/duriantaco/skylos
    rev: <version>
    hooks:
      - id: skylos-defend        # runs: skylos defend . --fail-on critical
```

GitHub code scanning:

```yaml
- run: skylos defend . --format sarif -o defend.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: defend.sarif
```

Inside GitHub Actions, `skylos defend` automatically appends a score summary
(failed checks, OWASP coverage, gate result) to the job's step summary via
`$GITHUB_STEP_SUMMARY` — no extra flags.

## MCP: agents verifying agents

The Skylos MCP server exposes `verify_agent`, so Claude Code, Cursor, and
other MCP clients can verify an agent codebase they just wrote or modified:

```
verify_agent(path=".", fail_on="critical", owasp_framework="agentic")
```

Returns compact JSON: `defense_score`, `ops_score`, `failed_checks[]` (with
remediation), OWASP coverage summary, the attestation digest, and the gate
verdict. The verification itself is deterministic static analysis — the
calling agent gets a ground-truth verdict, not another model's opinion.

## Scope and honesty

What this verifies: the presence and placement of guardrail code patterns at
LLM integration points, before deployment, deterministically.

What it does not do: observe runtime behavior, evaluate prompt quality, catch
semantic failures (an agent doing an allowed-but-wrong action), or replace
runtime controls. Pair pre-deployment verification with runtime measures
(gateways, policy engines, human approval for high-stakes actions) — the two
layers catch different failure classes.
