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
