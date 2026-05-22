# Skylos Repo Workflow Reference

Use this reference when the user asks the agent to change Skylos itself.

## Repo Boundaries

- `skylos/analyzer.py`: main static analyzer orchestration.
- `skylos/cli.py` and `skylos/api/`: CLI and public API surface.
- `skylos/rules/`, `skylos/dangerous.py`, `skylos/security/`: rule and
  security detector logic.
- `skylos/llm/`: LLM adapters, prompts, evidence filters, and verification.
- `skylos/agents/`: Skylos product runtime state/service code, not Codex or
  Claude skill files.
- `skylos/cicd/`, `skylos/gatekeeper.py`: CI output, gates, workflows.
- `scripts/`: benchmarks, corpus guard, repo map generation, rule parity.
- `test/`: regression tests.
- `dictionary.md` and `docs/`: rule/user documentation.

## Change Workflow

1. Inspect existing patterns before editing.
2. Keep the change in the smallest ownership area that solves the task.
3. Add or update focused tests for analyzer behavior, rule behavior, or CLI
   behavior that changed.
4. Update docs when public rule IDs, output fields, commands, or workflows
   change.
5. Run focused tests first, then broader checks if the change touches shared
   analyzer paths.

## Focused Test Selection

Use these starting points:

- CLI behavior: `pytest -q test/test_cli*.py`
- Security rules: `pytest -q test/test_dangerous.py test/test_cmd_injection.py`
- Dead-code analysis: `pytest -q test/test_dead_code*.py test/test_framework_aware.py`
- CI/gates: `pytest -q test/test_cicd_*.py test/test_gatekeeper.py`
- Agent service/state: `pytest -q test/test_agent*.py`
- Repo map: `python scripts/build_repo_map.py --check`
- Rule docs parity:
  `python skylos/scripts/check_rule_docs_parity.py --docs dictionary.md --catalog skylos/rules/catalog.json`
- Corpus guard:
  `python scripts/corpus_ci.py --manifest corpus/manifest.json`

Prefer the exact file near the changed module when one exists.

## Rule And Docs Hygiene

When adding or renaming rule IDs:

1. Update the rule catalog.
2. Update `dictionary.md` and relevant docs.
3. Run rule docs parity.
4. Add a regression test with a minimal fixture.

Do not add rule IDs that overlap existing meanings. Keep severity and category
consistent with nearby rules.

## Git Hygiene

- Preserve unrelated user changes.
- Do not use `git add .`.
- Split commits by purpose when the user asks for commits.
- Use existing commit style, such as `feat(docs): ...`, `fix(cli): ...`, or
  `test(analyzer): ...`.
- Do not open PRs, close issues, add comments, or mutate GitHub state unless
  explicitly asked.

## Public Surface Caution

Treat these as public or semi-public surfaces:

- CLI command names, flags, output fields, and exit behavior.
- Rule IDs and dictionary descriptions.
- Public imports from `skylos.api` and documented modules.
- GitHub Action behavior.
- Generated docs and repo map output.

When changing a public surface, preserve compatibility unless the user
explicitly wants a breaking cleanup.
