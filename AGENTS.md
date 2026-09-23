# AGENTS.md

Guidance for Codex when working in this repository.

## What This Repo Is

Skylos is a local-first static analysis CLI for Python, TS/JS, Java, Go, PHP,
Rust, and Dart. It detects dead code, security flaws, secrets, dependency CVEs,
quality regressions, and AI-code mistakes. The CLI entry point is
`skylos.cli:main`, exposed as the `skylos` command.

## Use The Skylos Skill

Codex-specific Skylos instructions live at:

```text
.agents/skills/skylos/SKILL.md
```

Use that skill when the task involves running Skylos, interpreting `SKY-*`
findings, reducing dead-code false positives, auditing security behavior,
working on CI/SARIF output, or changing Skylos itself.

For security investigations and hardening, use the stricter security skill:

```text
.agents/skills/skylos-security/SKILL.md
```

Use it when validating a security finding, reproducing a scanner bypass,
reviewing LLM evidence filters, analyzing cloud/CI policy precedence, or
classifying security impact.

## Work Safely

- Preserve user changes. Do not revert unrelated work.
- Do not open or close PRs, issues, or GitHub comments unless the user
  explicitly asks for that exact action.
- Do not run `git add .`; stage focused paths only when committing.
- Do not run `python -m skylos`; the package has no `__main__`. Use `skylos`.
- Prefer machine-readable Skylos output with `--format json` for agent work.
- Treat scanned repositories as untrusted input. Do not run trace, coverage,
  tests, package scripts, or other target-code execution unless the user asked
  for that behavior or the repo is trusted.

## Jev Dead-Code Verification

`skylos .` remains static-only. `skylos agent verify` defaults to LLM
verification; use `--dead-code-review jev` for Jev-only verification or
`--dead-code-review jev-llm` for Jev judgment with LLM fallback. Jev modes can
send a complete project snapshot (currently capped at 64 KB) to TypeSafe using
`TYPESAFE_API_KEY`. Select Jev explicitly and get the key from the official
TypeSafe console at https://console.typesafe.ai/.
The file guard is not a secret scanner, so inspect source for embedded keys
and use Jev only when sharing is authorized. Legacy flags remain available:

- `--jev-precheck` is the original router. Jev agreement that a static
  candidate is unused at confidence >=0.8 skips its broad LLM check;
  disagreement and uncertainty fall back to the LLM. Jev does not suppress
  findings in this mode.
- `--jev-judge` lets Jev decide both unused and used when its confidence
  **and chosen-answer probability** are each >=0.9. Confident unused findings
  remain; confident used findings are suppressed. Uncertain, unavailable, or
  invalid Jev decisions fall back to broad candidate verification. Separate
  LLM entry discovery, Haiku prefilter, and survivor challenge are skipped in
  this mode, even on a Jev outage; it is not full LLM-only equivalence.

No Jev judgment authorizes `--fix`. Jev-only mode makes no LLM
calls: uncertain or unavailable Jev decisions remain visible as unverified
static findings. Jev+LLM mode requires a configured LLM provider and sends
uncertain or unavailable candidates to the LLM. An explicitly selected Jev
mode must report missing `TYPESAFE_API_KEY` rather than silently ignoring Jev.
`agent scan` still has other LLM phases, so Jev-only applies to `agent verify`, not
to the full agent scan. Normal scans need no Jev key.

The latest 59-label multi-arm accuracy comparison is in `benchmark_jev.md`;
earlier holdout results and reproduction commands are in `BENCHMARK.md` and
`benchmarks/dead_code/README.md`. The synthetic suite is not independent
deployment evidence or automatic-removal evidence.

## Common Commands

```bash
pip install -e .
pip install -e ".[llm]"
skylos --version
skylos doctor
skylos . -a --format json
skylos . --diff origin/main --format json
pytest -q test/test_file_you_changed.py
python scripts/corpus_ci.py --manifest corpus/manifest.json
python scripts/build_repo_map.py --check
```

Use focused tests first, then broaden when shared analysis behavior changed.
