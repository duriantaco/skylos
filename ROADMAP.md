# Skylos Roadmap

This roadmap lists areas where contributions are especially useful. It is not a
release promise. Priorities can change when users report false positives,
security gaps, or CI breakages.

If you want to work on a larger item, open an issue or draft PR first so the
scope can be confirmed.

## Current Direction

Skylos is focused on five product goals:

- Make static findings trustworthy enough for CI and PR review.
- Reduce dead-code false positives in dynamic frameworks.
- Catch security and AI-generated-code mistakes before they reach main.
- Keep the tool local-first and usable without mandatory LLM or cloud calls.
- Make findings easy to explain, reproduce, and fix.

## Good First Contributions

These are small, low-risk areas for new contributors. You can do the following:

- Add a minimal false-positive fixture to `corpus/fixtures/` and register it in `corpus/manifest.json`.
- Improve an unclear finding message or suggested fix.
- Add a missing negative test for an existing rule.
- Add a small benchmark case for an already-supported pattern.

## Near-Term Priorities

### PR Review Evidence

Goal: make PR comments explain why a finding is proven, likely, or speculative.

Useful work:

- Improve evidence-card wording for more rule families.
- Keep evidence labels conservative when LLM or verifier data is incomplete.
- Add better suggestions for high-signal security and quality rules.

Main files:

- `skylos/cicd/review.py`
- `skylos/cicd/evidence.py`
- `skylos/commands/cicd_cmd.py`
- `test/test_cicd_review.py`
- `test/test_cicd_evidence.py`

### Dead-Code Precision

Goal: reduce false positives without hiding real unused code.

Useful work:

- Add framework contracts for real entrypoints, decorators, callbacks, signals, serializers, and plugin hooks.
- Improve TS/JS workspace and export reachability
- Add/Improve cross-language test coverage for Java, Go, PHP, and Rust
- Add a small corpus fixtures for confirmed framework patterns.

Main files:

- `skylos/analyzer.py`
- `skylos/dead_code.py`
- `skylos/dead_code_liveness.py`
- `skylos/module_reachability.py`
- `skylos/visitors/framework_aware.py`
- `skylos/visitors/languages/**`
- `corpus/fixtures/**`
- `corpus/manifest.json`

### Security And Vibe-Coding Rules

Goal: catch common security mistakes from fast AI-assisted coding without turning the scanner into noise.

Useful work:

- Add narrow rules for missing verification, disabled controls, unsafe defaults prompt-injection exposure, tool-call misuse, and missing network timeouts.
- Improve webhook, SSRF, path traversal, command injection, SQL injection, XSS, JWT, CORS, and MCP checks.
- Add safe-pattern tests so rules do not punish correct code.
- Improve secret redaction in any user-facing output path.

Main files:

- `skylos/rules/danger/**/*.py`
- `skylos/rules/secrets.py`
- `skylos/rules/vibe_dictionary.py`
- `skylos/security_contracts.py`
- `skylos/injection_scanner.py`
- `test/test_*flow.py`
- `test/test_security*.py`

### Technical Debt Reports

Goal: make `skylos debt` useful for conservative cleanup planning.

Useful work:

- Improve hotspot explanations without inventing evidence.
- Add clearer changed-code and history views.
- Add tests for report rendering and baseline comparisons.
- Keep debt scoring stable and explainable.

Main files:

- `skylos/debt/*.py`
- `skylos/commands/debt_cmd.py`
- `test/test_debt.py`

### CI/CD And Quality Gates

Goal: make Skylos easy to adopt in GitHub Actions without surprising users.

Useful work:

- Improve generated workflow comments and defaults.
- Keep gate behavior predictable between local and CI runs.
- Add diff-aware tests for annotations and PR summaries.
- Improve failure messages with exact next steps.

Main files:

- `skylos/cicd/workflow.py`
- `skylos/cicd/review.py`
- `skylos/gatekeeper.py`
- `action.yml`
- `scripts/skylos_gate.py`
- `test/test_cicd_*.py`

### Performance

Goal: make scans faster without unsafe caching or stale results. (Cache is inherently tricky so got to approch this with a more conservative approach)

Useful work:

- Profile parser and visitor hot spots.
- Reduce repeated filesystem or dependency graph work.
- Add benchmark cases before changing scan strategy.
- Avoid broad persistent caching unless invalidation is explicit, tested, and easy to disable.

Main files:

- `skylos/file_discovery.py`
- `skylos/fast.py`
- `skylos/grep_cache.py`
- `skylos/pipeline.py`
- `scripts/analyzer_speed_check.py`
- benchmark scripts under `scripts/`

### Editor And Agent Integrations

Goal: make findings useful where users write and review code.

Useful work:

- Improve VS Code diagnostics, quick fixes, and rule metadata.
- Keep extension rule IDs and severity colors in sync with core Skylos.
- Improve MCP server responses for AI coding assistants.
- Add tests around agent/verifier behavior when evidence is incomplete.

Main files:

- `editors/vscode/src/**`
- `editors/vscode/package.json`
- `skylos_mcp/*.py`
- `skylos/llm/*.py`
- `skylos/agent_*.py`
- `test/test_agent*.py`
- `test/test_*verifier.py`


## How To Propose A Roadmap Item

If you will like to propose a roadmap item, open an issue with:

- The user problem.
- A minimal example or target workflow.
- The expected command/output behavior.
- The likely files that need to change.
- The tests or corpus cases that would prove the behavior.
- Known false-positive or compatibility risks.

For implementation guidance, see `CONTRIBUTING.md`.
