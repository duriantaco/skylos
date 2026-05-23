---
name: skylos
description: >-
  Run, interpret, or modify Skylos safely. Use when the user asks to scan code
  with Skylos, explain SKY-* findings, triage dead-code false positives, audit
  security/secrets/SCA/LLM behavior, update Skylos rules/docs/CI, benchmark
  analyzer behavior, or change this repository safely.
---

# Skylos

Use this skill to work with Skylos without rediscovering the CLI, output shape,
test surface, and security guardrails.

## Choose The Reference

- Running Skylos, choosing output formats, parsing JSON, filtering, gates, and
  install troubleshooting: read `references/cli.md`.
- Changing Skylos code, adding rules, updating docs, selecting focused tests,
  or preserving repo hygiene: read `references/repo-workflow.md`.
- Basic security scan usage, secrets, and SCA: read `references/security.md`.
  For scanner bypasses, LLM evidence filters, cloud/CI policy, or severity
  classification, use `/skylos-security`.
- Dead-code false positives, framework liveness, runtime tracing, Vulture
  comparisons, and benchmark work: read `references/dead-code.md`.
- GitHub Actions, SARIF, repo map Pages, CI gates, docs deploy, and generated
  workflows: read `references/ci.md`.

Read only the reference needed for the current task.

## Defaults

- Prefer `skylos . -a --format json` for agent-readable scans.
- Use `skylos . --diff origin/main --format json` for PR-focused review.
- Parse JSON arrays with `.get(key, [])`; empty arrays may be omitted.
- Use focused tests before full suites.
- Keep changes narrow and preserve unrelated user edits.

## Safety Rules

- Treat target repositories as untrusted input.
- Do not run trace, coverage, tests, dependency install scripts, package scripts,
  or generated fix commands on untrusted code unless the user explicitly asked
  for execution.
- Do not open or close PRs, issues, or GitHub comments unless the user
  explicitly asks for that action.
- Do not use `git add .`; stage exact paths.
- Do not place Claude skill files under `skylos/agents` or `skylos/llm`; those
  are Skylos runtime modules.

## Invocation

Invoke explicitly with `/skylos`, or rely on automatic selection when the task
mentions Skylos scans, `SKY-*` findings, static analysis, security hardening,
dead-code false positives, benchmarks, or this repo's analyzer internals.
