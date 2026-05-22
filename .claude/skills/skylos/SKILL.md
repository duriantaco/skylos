---
name: skylos
description: >-
  Run Skylos static analysis on a codebase and interpret its findings. Skylos
  detects dead code, security flaws, secrets, dependency CVEs, quality
  regressions, and AI-generated-code mistakes for Python, TS/JS, Java, Go, PHP,
  Rust, and Dart. Use this skill when asked to scan code, find unused/dead
  code, audit security or secrets, gate a PR/diff, or read Skylos output.
---

# Skylos

Skylos is the local-first static analysis CLI built in this repository. It is
both the product and the codebase here. This skill explains how to run it and
read its results.

## Setup

Skylos is **not installed by default** in this environment — only the source is
present. Install it editable from the repo root before use:

```bash
pip install -e .            # core CLI; installs the `skylos` command + deps
pip install -e ".[llm]"     # add LLM-powered `skylos agent` / `skylos defend`
pip install -e ".[all]"     # add web dashboard + test extras too
```

Verify: `skylos --version` then `skylos doctor` (checks install health).

Notes:
- `inquirer` is a required dependency. If the CLI crashes with
  `module 'skylos.cli' has no attribute 'inquirer'`, the install is incomplete —
  rerun `pip install -e .`.
- Do not run `python -m skylos`; the package has no `__main__`. The entry point
  is the `skylos` console script (`skylos.cli:main`).
- Pinned/release install instead of source: `pip install skylos`.

## Core usage

```bash
skylos .                       # dead-code scan of the current dir
skylos . -a                    # all checks: --danger --secrets --quality --sca
skylos path/to/pkg             # scan a specific path (one or more)
```

Individual check flags (all off by default except dead code):
`--danger` (security flows), `--secrets`, `--quality`, `--sca` (dependency CVEs
via OSV.dev). `-a` / `--all` enables all four.

## Output formats — pick by consumer

| Need | Flag | Behavior |
|:---|:---|:---|
| Default human report | *(none)* / `--format rich` | Full `rich` terminal report |
| Compact human review | `--format pretty` | File-grouped, severity badges, snippets |
| **Agent/programmatic** | `--format json` (or `--json`) | Raw JSON; parse this |
| Findings for an LLM to fix | `--format llm` | Markdown with code context per finding |
| IDE / test scripts | `--format concise` | Only `file:line`; **exits non-zero if findings exist** |
| GitHub Actions | `--format github` | `::warning` / `::error` annotations |
| SARIF | `--sarif [path]` | SARIF 2.1.0 file |
| Interactive triage | `--tui` | Keyboard-driven; screen-only, no `--output` |

Write any non-TUI report to disk with `--output FILE` / `-o FILE`.

**When running Skylos as part of a task, prefer `--format json`** and parse the
result. Finding arrays in the JSON: `unused_functions`, `unused_imports`,
`unused_variables`, `unused_classes`, `unused_parameters`, `unused_files`,
`danger`, `secrets`, `quality`, `dependency_vulnerabilities` — plus
`custom_rules` and `circular_dependencies` when those apply. The top level also
carries `grade`, `provenance`, and `analysis_summary`. Some arrays are omitted
entirely when empty, so read keys with `.get(key, [])` rather than `d[key]`.

## Filtering & focus

- `--diff origin/main` — only findings on **lines** changed since a ref (best
  for PR review). `--diff` alone auto-detects the base.
- `--diff-base REF` — only findings in **files** changed since a ref.
- `--baseline` — only findings not in the saved baseline (run
  `skylos baseline .` first to create it).
- `--severity high` — minimum severity (`critical|high|medium|low`).
- `--category security,secret` — limit to categories (`security`, `secret`,
  `quality`, `dead_code`, `dependency`).
- `--file-filter auth/` — substring match on file path.
- `--confidence N` (`-c`, default 60) — dead-code confidence threshold; lower
  surfaces more candidates.
- `--exclude-folder NAME` / `--include-folder NAME` — folder scope.
- `--limit N` — cap findings shown per category.

## Gating (CI / pass-fail)

- `skylos . --gate` — run as a quality gate; non-zero exit blocks deployment.
  Thresholds live in `pyproject.toml` under `[tool.skylos.gate]`.
- `--strict` — fail if **any** issue is found.
- `--force` / `-f` — bypass the gate (always exit 0).
- `--format concise` also exits non-zero whenever findings exist.

## Key subcommands

Run `skylos commands` for the full flat list, `skylos tour` for a walkthrough,
or `skylos <command> --help`.

- `skylos init` — write `[tool.skylos]` config (thresholds, ignores, templates,
  vibe dictionary) into `pyproject.toml`.
- `skylos suite .` — full local analysis bundle.
- `skylos discover .` — map LLM/AI integrations in the codebase.
- `skylos defend .` — check LLM integrations for missing guardrails (OWASP LLM).
- `skylos debt .` — rank technical-debt hotspots and trends.
- `skylos agent scan|verify|remediate|audit|watch|pre-commit|triage .` — hybrid
  static + LLM analysis (needs the `[llm]` extra and a model key).
- `skylos rules init|validate|list` — scaffold/manage local YAML rule packs
  under `.skylos/rules/`.
- `skylos cicd init` — generate a GitHub Actions PR-gate workflow.
- `skylos baseline .` — save current findings as a baseline.
- `skylos whitelist <pattern>` — manage whitelisted symbols.
- `skylos clean` — interactively remove dead code (`-i` / `--comment-out` /
  `--dry-run` on the main scan also act on dead code).
- `skylos cache stats|clear [path]` — manage cached run data.
- `skylos doctor` — check installation health.

## Reducing dead-code false positives

Skylos is framework-aware (FastAPI, Django, Flask, pytest, SQLAlchemy, Next.js,
React, package entrypoints). For genuinely dynamic code, use, in order of
preference: inline suppressions, whitelists, a baseline, or runtime tracing
(`skylos . --trace`, optionally `--cache`).

Suppression syntax:
- `# skylos: ignore` — suppress findings on that line.
- `# skylos: ignore-start` / `# skylos: ignore-end` — suppress a block.
- `ignore = ["SKY-XXX"]` in `[tool.skylos]` — suppress a rule project-wide.

## Reading rule IDs

Finding IDs are prefixed by family (see `dictionary.md` for the full table):

| Prefix | Family |
|:---|:---|
| `SKY-U`, `SKY-DC`, `SKY-UC` | Dead code / unreachable code |
| `SKY-D` | Security / dangerous flows |
| `SKY-S` | Secrets |
| `SKY-SCA` | Dependency (CVE) vulnerabilities |
| `SKY-SC` | Security-contract regressions (removed auth/CSRF/etc.) |
| `SKY-L` | Logic & AI-code mistakes / resilience |
| `SKY-Q`, `SKY-C`, `SKY-P` | Quality, structure/clones, performance |
| `SKY-CIRC` | Circular dependency |

## Reference docs in this repo

- `README.md` — overview, workflow table, language support.
- `docs/cli-output.md` — output modes and TUI keys.
- `dictionary.md` — every rule ID and product term.
- `BENCHMARK.md` — benchmark methodology. `QUALITY.md` — gate expectations.
- `llms.txt` / `llms-full.txt` — condensed machine-readable summary.
- Full docs: https://docs.skylos.dev — CLI reference, configuration, CI/CD.
