# Skylos CLI Reference

Use this reference when running Skylos or interpreting CLI output.

## Install And Verify

```bash
pip install -e .
pip install -e ".[llm]"
pip install -e ".[all]"
skylos --version
skylos doctor
```

Use `pip install skylos` for a released install. Do not run `python -m skylos`;
the package exposes the `skylos` console script.

If the CLI crashes with `module 'skylos.cli' has no attribute 'inquirer'`, the
environment is incomplete. Reinstall from the repo root with `pip install -e .`.

## Common Scans

```bash
skylos .
skylos . -a
skylos . -a --format json
skylos path/to/pkg --format json
skylos . --diff origin/main --format json
skylos . --gate
```

Default scan behavior focuses on dead code. `-a` / `--all` enables danger,
secrets, quality, and SCA checks.

Individual check flags:

- `--danger`: security and dangerous flows.
- `--secrets`: leaked secret patterns.
- `--quality`: maintainability and AI-code mistakes.
- `--sca`: dependency CVEs through OSV.dev.

## Output Formats

| Need | Flag | Notes |
| :-- | :-- | :-- |
| Human terminal report | `--format rich` or no flag | Full rich report |
| Compact review | `--format pretty` | File grouped with snippets |
| Agent parsing | `--format json` or `--json` | Preferred for automation |
| LLM fix context | `--format llm` | Markdown with code context |
| File-line output | `--format concise` | Exits non-zero if findings exist |
| GitHub annotations | `--format github` | Emits workflow annotations |
| SARIF | `--sarif path` | Writes SARIF 2.1.0 |
| Interactive triage | `--tui` | Screen UI; no `--output` |

Write non-TUI output with `--output FILE`.

## JSON Shape

Expect finding arrays such as:

- `unused_functions`
- `unused_imports`
- `unused_variables`
- `unused_classes`
- `unused_parameters`
- `unused_files`
- `danger`
- `secrets`
- `quality`
- `dependency_vulnerabilities`
- `custom_rules`
- `circular_dependencies`

The top level may also include `grade`, `provenance`, and
`analysis_summary`. Empty arrays can be omitted, so use `.get(key, [])`.

## Filtering

```bash
skylos . --diff origin/main --format json
skylos . --diff-base origin/main --format json
skylos . --severity high --format json
skylos . --category security,secret --format json
skylos . --file-filter auth/ --format json
skylos . --confidence 80 --format json
skylos . --limit 50 --format json
```

Use `--diff REF` for findings on changed lines. Use `--diff-base REF` for
findings in changed files. Use `--baseline` after `skylos baseline .` to show
only new findings.

## Gating

- `skylos . --gate`: apply `[tool.skylos.gate]` thresholds.
- `--strict`: fail on any finding.
- `--force` / `-f`: bypass gate exit failure.
- `--format concise`: exits non-zero when findings exist.

## Useful Subcommands

- `skylos commands`: list commands.
- `skylos tour`: walkthrough.
- `skylos init`: write project config.
- `skylos suite .`: full local analysis bundle.
- `skylos discover .`: map LLM/AI integrations.
- `skylos defend .`: OWASP LLM guardrail checks.
- `skylos agent scan|verify|remediate|audit|watch|pre-commit|triage .`:
  hybrid static and LLM analysis, requiring `[llm]` extras and provider config.
- `skylos rules init|validate|list`: local YAML rule packs.
- `skylos cicd init`: generate CI workflow.
- `skylos baseline .`: save current findings baseline.
- `skylos clean`: interactively remove or comment dead code.
- `skylos cache stats|clear`: manage cache data.
- `skylos doctor`: installation health check.
