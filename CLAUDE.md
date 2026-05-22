# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this repo is

**Skylos** — a local-first static analysis CLI for Python, TS/JS, Java, Go,
PHP, Rust, and Dart. It detects dead code, security flaws, secrets, dependency
CVEs, quality regressions, and AI-generated-code mistakes. The CLI entry point
is `skylos.cli:main`, exposed as the `skylos` command.

## Install

Skylos is not installed by default — only the source is present. Install it
editable from the repo root:

```bash
pip install -e .            # core CLI + dependencies
pip install -e ".[llm]"     # also enables `skylos agent` / `skylos defend`
```

Then verify with `skylos --version` and `skylos doctor`.

Notes:
- Do **not** run `python -m skylos` — the package has no `__main__`. Use the
  `skylos` command.
- A `module 'skylos.cli' has no attribute 'inquirer'` error means the install
  is incomplete; rerun `pip install -e .`.

## Use

```bash
skylos .                 # dead-code scan of the current directory
skylos . -a              # all checks: security, secrets, quality, deps
skylos . -a --format json   # machine-readable output (best for automation)
skylos . --diff origin/main # only findings on changed lines (PR review)
skylos . --gate          # quality gate; non-zero exit blocks on failure
```

Run `skylos commands` for the full command list and `skylos <cmd> --help` for
details on any subcommand.

## Skill For Using Skylos

A detailed agent skill for installing, running, and interpreting Skylos lives
at:

```
.claude/skills/skylos/SKILL.md
```

It is auto-discovered by Claude Code. Consult it for output formats, JSON
result keys, filtering flags, gating/exit codes, suppression syntax, security
guardrails, CI behavior, dead-code false-positive triage, and repo workflow.

Keep Claude skill files under `.claude/skills/`. Do not put them under
`skylos/agents` or `skylos/llm`; those are Skylos runtime modules.

## Reference docs

- `README.md` — overview, workflow table, language support.
- `docs/cli-output.md` — output modes and TUI keys.
- `dictionary.md` — every rule ID and product term.
- `CONTRIBUTING.md` / `QUALITY.md` — repo workflow and quality-gate expectations.
- Full docs: https://docs.skylos.dev
