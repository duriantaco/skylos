# CI And Cloud Policy Security Reference

Use this for GitHub Actions, cloud policy sync, config precedence, secrets, PR
trust boundaries, and security gate bypasses.

## Trust Boundary Defaults

Checked-out repository contents are attacker-controlled in PR workflows. This
includes `pyproject.toml`, `.skylos/`, package manifests, tests, scripts,
generated files, and local config.

Operator-controlled security policy must have higher precedence than
repository-controlled config when the repository is under review.

## GitHub Actions Review

Check:

- Event type: `pull_request`, `pull_request_target`, `push`, scheduled, manual.
- Token permissions and whether secrets are available.
- Whether checkout points at attacker-controlled code.
- Whether any step runs target-controlled scripts before or after secrets are
  exposed.
- Whether generated annotations or SARIF can be spoofed or suppressed.

Avoid workflows that combine untrusted code execution with secrets.

## Config Precedence

Review:

- `skylos/config.py`
- `skylos/cloud/`
- `skylos/cicd/`
- `skylos/cli.py`
- `skylos/analyzer.py`
- tests for config, gates, and security contracts.

Security-sensitive keys include:

- `security_enabled`
- `secrets_enabled`
- `security_contracts`
- `ignore`
- `exclude`
- gate thresholds
- cloud policy settings

Repository config must not disable mandatory cloud policy in CI.

## Validation Pattern

For policy bypasses:

1. Create a cloud/operator policy fixture.
2. Create a PR-controlled config fixture that attempts to weaken it.
3. Load final config through the same path used by CLI/CI.
4. Assert mandatory security behavior remains enabled.
5. Run analyzer/gate path to prove the security contract or finding still
   affects output.

## CI Output And Gates

Check these files:

- `action.yml`
- `.github/workflows/`
- `skylos/cicd/`
- `skylos/gatekeeper.py`
- `scripts/skylos_gate.py`
- `test/test_cicd_*.py`
- `test/test_gatekeeper.py`

Preserve exit-code behavior unless the task explicitly changes it. Security
gate changes need tests for pass, fail, force/bypass, and ignored findings.
