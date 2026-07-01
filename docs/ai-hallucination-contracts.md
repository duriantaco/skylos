# AI Hallucination Contracts

AI hallucination contracts are local YAML files that tell `skylos verify` what
must be true for generated code in this repository. The first version compiles
contract clauses into existing Skylos checks instead of introducing a general
rule language.

Use this when a coding agent can invent helpers, packages, versions, API calls,
or route guardrails that look plausible but are not true for the repo.

## Quickstart

Create a starter contract:

```bash
skylos contract init
skylos contract validate .skylos/ai-contract.yml
skylos contract inspect
```

Run verify. If `.skylos/ai-contract.yml` exists in the target repo or an
ancestor directory, `skylos verify` applies it automatically:

```bash
skylos verify .
```

For agent or editor loops, scope the same check to a file or range:

```bash
skylos verify . --file apps/api/routes.py --range 10:40 --project-context
```

Use `--contract` only for a non-default contract path:

```bash
skylos verify . --contract policies/agent-contract.yml
```

Use `--no-contract` when a verify run should ignore auto-discovered contracts:

```bash
skylos verify . --no-contract
```

MCP clients get the same default discovery through the `verify_change` tool.
They can pass `contract_path` for a non-default path, or set
`contract_enabled` to `false` to opt out.

## Contract Shape

```yaml
version: 1

ai:
  phantom_symbols:
    names:
      - verify_enterprise_auth
    decorators:
      - tenant_admin_required

  dependencies:
    reject_nonexistent_packages: true
    reject_impossible_versions: true

  api_surface:
    reject_unknown_members: true
    reject_unknown_kwargs: true

security:
  routes:
    paths:
      - "apps/api/**"
    require_any_decorator:
      - login_required

tests:
  high_risk_changes_require_tests: true
```

## Evidence Fields

Contract-backed verify findings include optional fields:

| Field | Meaning |
|:---|:---|
| `contract_id` | Optional `id` from the contract file. |
| `contract_clause` | Contract clause that explains the finding. |
| `contract_path` | Contract file used for the run. |
| `contract_reason` | Human-readable reason for the clause match. |

Example clause values:

| Rule | Clause |
|:---|:---|
| `SKY-L012` | `ai.phantom_symbols.names` |
| `SKY-L023` | `ai.phantom_symbols.decorators` |
| `SKY-D222` | `ai.dependencies.reject_nonexistent_packages` |
| `SKY-D225` | `ai.dependencies.reject_impossible_versions` |
| `SKY-D224` | `ai.api_surface.reject_unknown_members` or `ai.api_surface.reject_unknown_kwargs` |
| `SKY-A102` | `tests.high_risk_changes_require_tests` |
| `SKY-A105` | `security.routes.require_any_decorator` |

## Local Demo

This repo includes a deterministic demo fixture:

```bash
skylos verify demo/ai_contract --file apps/api/routes.py --project-context
```

The demo intentionally contains:

- a contract-listed helper that is never defined
- an API route missing the contract-required guard decorator

Dependency/package and installed-API clauses are covered by deterministic
benchmark fixtures with offline status caches:

From a source checkout, run:

```bash
.venv/bin/python scripts/ai_code_defect_benchmark.py --case contract-phantom-helper --case contract-route-guard-missing --case contract-route-guard-clean --case contract-dependency-manifest --case contract-dependency-clean --json
```

## How This Differs From Generic Rules

Contracts are repo truth for generated code. They are not a replacement for
Semgrep, CodeQL, Sonar, Snyk, or GitHub Advanced Security. Those tools are
broad query engines, security analyzers, or platforms. Skylos contracts are a
local verification layer for agent-written code before review or merge.

Keep the local contract useful and free. Paid product surface should be built
around organization control: central policy registry, inheritance across repos,
SSO/RBAC, audit logs, signed verification artifacts, private package/API
intelligence, and review workflow integrations.
