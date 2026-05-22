# Skylos Security Reference

Use this reference for security findings, hardening work, LLM evidence filters,
cloud policy, and CI trust boundaries.

## Threat Model Defaults

Skylos often scans attacker-controlled repositories or pull requests. Treat
scanned source code, repository config, package scripts, tests, and generated
artifacts as untrusted unless the user says the repo is trusted.

Avoid executing target code during security review. Static scans are safe by
default; trace, coverage, tests, dependency install scripts, or package scripts
can execute target-controlled code.

## Security Scan Commands

```bash
skylos . --danger --format json
skylos . --secrets --format json
skylos . --sca --format json
skylos . -a --format json
skylos defend . --format json
```

Use `--diff origin/main` for PR review when appropriate.

## LLM And Evidence Filter Reviews

For LLM security behavior, inspect:

- `skylos/llm/analyzer.py`
- `skylos/llm/finding_evidence.py`
- `skylos/llm/verify_orchestrator.py`
- `skylos/llm/security_verifier.py`
- `skylos/llm/prompts.py`
- `test/test_*llm*.py`, `test/test_*evidence*.py`, and targeted security tests.

Do not suppress a security finding unless the code proves safety, not merely a
plausible benign pattern. Safe-sink heuristics must prove trusted literals,
immutable allowlists, or framework guarantees. Uppercase variable names,
comments, or absence of local mutation are not sufficient proof.

## Cloud Policy And Config Trust

Security policy that comes from operator-controlled cloud sync must not be
overridden by attacker-controlled repository files in a CI/PR context. Review:

- `skylos/config.py`
- `skylos/cloud/`
- `skylos/cicd/`
- `skylos/cli.py`
- `skylos/analyzer.py`

When config precedence changes, add tests that show mandatory security
contracts cannot be disabled by PR-controlled `pyproject.toml` or local config.

## CI Security Boundaries

For GitHub Actions, check whether the workflow runs on `pull_request`,
`pull_request_target`, or trusted branch events. Fork PRs usually do not receive
secrets, but same-repo PRs may. Treat checked-out repository content as
attacker controlled before analysis.

Do not recommend workflows that execute untrusted scripts with secrets in
scope. Generated workflows should avoid placing tokens in steps that run
target-controlled code.

## Validation Pattern

For a suspected scanner bypass:

1. Reproduce the unsafe source pattern as a minimal fixture.
2. Confirm the finding appears before the filter or regression point.
3. Confirm the finding is removed or changed by the suspect logic.
4. Fix the proof condition or precedence issue.
5. Add an end-to-end regression test that would fail on the old behavior.
6. Run the focused security tests plus any affected analyzer tests.

Keep severity analysis tied to impact on scan integrity, CI gates, credentials,
or code execution.
