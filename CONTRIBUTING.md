# Contributing To Skylos

Skylos is a local-first static analysis tool and PR gate. Good contributions
make the scanner more correct, easier to run, or easier to trust in CI.

Start with the smallest change that proves the behavior. A narrow rule with a
strong regression test is better than a broad heuristic that creates false
positives. If you are unsure, please refer to `ROADMAP.md`

## Ways To Contribute

Useful contributions include:

- Bug reports with a minimal reproduction and the exact `skylos` command used.
- False-positive or false-negative reports with a small code sample.
- New security, secrets, quality, or dead-code rules with focused tests.
- Framework-awareness improvements for real entrypoints, callbacks, decorators,
  and generated code patterns.
- CI/CD and PR review improvements that make findings easier to understand.
- Documentation that helps users configure Skylos or understand a rule.
- Benchmark and corpus cases that protect a confirmed behavior.

Before starting large work, open an issue or draft PR so maintainers can confirm
the scope.

## Development Setup

Skylos supports Python 3.10 and newer.

```bash
git clone https://github.com/YOUR_USERNAME/skylos.git
cd skylos
python -m venv .venv
. .venv/bin/activate
pip install -e ".[test,llm]"
```

If you do not need LLM-related tests, `pip install -e ".[test]"` is enough for
most static-analysis work.

Run the CLI from the checkout:

```bash
skylos --help
skylos . --no-provenance
skylos . -a
```

## Choosing The Right Files

Use this map to keep changes in the right part of the repo.

| Contribution | Main Files | Common Tests |
|:---|:---|:---|
| CLI command parsing or dispatch | `skylos/cli.py`, `skylos/commands/*.py` | `test/test_cli*.py`, command-specific tests |
| GitHub Actions workflow generation | `skylos/cicd/workflow.py`, `action.yml` | `test/test_cicd_workflow.py` |
| PR review comments and summaries | `skylos/cicd/review.py` | `test/test_cicd_review.py`, `test/test_regression.py` |
| CI gate behavior | `skylos/gatekeeper.py`, `skylos/cicd/*`, `scripts/skylos_gate.py` | `test/test_cicd_gate.py`, `test/test_gatekeeper.py` |
| Python dead-code precision | `skylos/analyzer.py`, `skylos/dead_code.py`, `skylos/visitors/*.py`, `skylos/*reachability*.py` | `test/test_dead_code*.py`, `test/test_framework_aware.py`, corpus tests |
| TypeScript/JavaScript support | `skylos/visitors/languages/typescript/*.py` | `test/test_typescript*.py`, relevant language tests |
| Java support | `skylos/visitors/languages/java/*.py` | `test/test_java*.py` |
| Go support | `skylos/visitors/languages/go/*.py`, `skylos/engines/go_*.py` | `test/test_go*.py` |
| PHP support | `skylos/visitors/languages/php/*.py` | `test/test_php*.py` |
| Rust support | `skylos/visitors/languages/rust/*.py` | `test/test_rust*.py` |
| Python security rules | `skylos/rules/danger/**/*.py`, `skylos/security_contracts.py` | `test/test_*flow.py`, `test/test_security*.py` |
| Secrets rules | `skylos/rules/secrets.py`, `skylos/credentials.py` | `test/test_credentials.py`, secrets tests |
| Quality rules | `skylos/rules/quality/*.py`, `skylos/linter.py` | `test/test_complexity.py`, `test/test_*quality*.py` |
| Technical debt reports | `skylos/debt/*.py`, `skylos/commands/debt_cmd.py` | `test/test_debt.py` |
| AI defense checks | `skylos/defend/*.py`, `skylos/commands/defend_cmd.py` | `test/test_defend*.py` |
| Agent and verifier workflows | `skylos/llm/*.py`, `skylos/agent_*.py` | `test/test_agent*.py`, `test/test_*verifier.py` |
| VS Code extension | `editors/vscode/src/*.ts`, `editors/vscode/package.json` | extension build/lint commands |
| MCP server | `skylos_mcp/*.py` | MCP-related tests |
| Benchmarks | `benchmarks/**`, `scripts/*benchmark*.py` | benchmark scripts and focused unit tests |
| Corpus precision fixtures | `corpus/fixtures/**`, `corpus/manifest.json` | `python scripts/corpus_ci.py --manifest corpus/manifest.json` |

If you are unsure where a change belongs, open the issue first and describe the
rule or behavior you want to change.

## Rule Contributions

For new rules, include:

- A short rule name and stable rule ID if the rule emits user-facing findings.
- A positive test that proves Skylos catches the risky pattern.
- A negative test that proves Skylos does not flag the safe pattern.
- A clear message and suggested fix when possible.
- A narrow scope. Do not flag every similar-looking pattern unless the rule can
  distinguish safe from unsafe usage.

For security rules, prefer structured parsing, data-flow checks, or framework
contracts over string-only matching. If a heuristic is unavoidable, keep severity
and confidence conservative.

## Precision Policy

Treat false positives as serious regressions. A scanner that users cannot trust
will be ignored.

- If you fix a confirmed false positive, add a minimal fixture under
  `corpus/fixtures/` when the case describes a reusable framework or language
  contract.
- Register corpus fixtures in `corpus/manifest.json` with narrow expectations.
- Keep fixtures small and pattern-focused.
- Prefer explicit contracts over broad suppression.
- Do not relax or remove an existing corpus expectation unless the original
  expectation was invalid or the upstream contract changed.

Run the corpus gate when changing dead-code precision:

```bash
python scripts/corpus_ci.py --manifest corpus/manifest.json
```

## Tests And Checks

Run the narrowest relevant test first, then a broader check before opening a PR.

```bash
pytest -q test/test_file_you_changed.py
pytest -q
python -m ruff check skylos test
```

For PR review, CI, or gate changes, also run the relevant command-level tests:

```bash
pytest -q test/test_cicd_review.py test/test_cicd_gate.py test/test_cicd_workflow.py
```

For benchmark-sensitive work:

```bash
python scripts/dead_code_benchmark.py
python scripts/security_benchmark.py
python scripts/quality_benchmark.py
python scripts/agent_review_benchmark.py
```

Only run benchmark scripts that are relevant to your change. If a benchmark
result changes, explain why in the PR.

## Pull Request Checklist

Before opening a PR:

- Keep the PR focused on one behavior or one small feature.
- Add tests for the behavior changed.
- Update docs when commands, config, output, or rule behavior changes.
- Include before/after output when fixing CLI behavior or PR comments.
- Explain false-positive and false-negative risks for scanner changes.
- Mention any benchmark or corpus result that changed.

A useful PR description answers:

- What problem does this solve?
- What changed?
- Why did the bug or gap exist?
- What files or lines are important?
- What was tested?
- What risks remain?

## AI Use

Contributors are expected to understand and own their submitted work.

- Do not submit code, tests, issue reports, or review summaries that you cannot
  explain.
- If AI tools materially helped produce the contribution, disclose that in the
  PR.
- Maintainers may ask for an explanation, reproduction, or test evidence before
  reviewing generated-looking changes.

Assistive use for spelling, formatting, or research is fine. The quality bar is
correctness and demonstrated understanding.

## Reporting Security Issues

Do not open a public issue for a vulnerability in Skylos itself. Follow
`SECURITY.md` for responsible disclosure.

For scanner rule gaps, open a normal issue if the report does not expose a live
secret, private exploit path, or sensitive user code.

## Getting Help

Use GitHub issues for bugs, questions, feature proposals, and rule requests.
Include the command you ran, the expected behavior, the actual behavior, and a
minimal reproduction whenever possible.
