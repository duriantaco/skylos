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

- `--danger` (alias `--security`): security and dangerous flows.
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
With `--gate` (or `--strict` without `--force`), `gate` holds `passed`,
`reasons` (strings), `scope`, `status`, `forced`, the `verdict` (`passed`,
`failed`, `incomplete`), its `exit_code`, `reason_details` (`message`,
`details`, `hint` per reason), and `coverage_status` / `coverage_warnings`.
`analysis_summary.analysis_coverage` says what was not analysed (`status`
`complete` / `partial` / `incomplete`, `exit_blocking`, `unchecked_files`,
`unverified_dead_code_candidates`).

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

`--severity` also filters records without a severity, at the level the report
prints (dead code LOW). An unknown `--category` value exits 2 with a
suggestion (the secrets value is `secret`).

Full scans skip generated/vendored files (Django migrations, `static/**/lib`,
`*.min.js`, library banners). The count is in
`analysis_summary.generated_files`; add `--include-generated` to scan them.

## Gating

- `skylos . --gate`: apply `[tool.skylos.gate]` thresholds. Any critical
  AI-code issue fails by default; set `block_ai_defect_severities = []` to
  turn that off. Any critical security issue and any secret always fail:
  `max_critical`/`max_secrets` above 0 and `fail_on_critical = false` only
  print a warning. `rules = [...]` accepts any rule ID, multi-part
  `SKY-SCA-*` ones included; an entry that is not a rule ID prints a warning.
  `[tool.skylos.gate.agent] require_defend`/`min_defend_score` are not
  supported and fail the agent gate; gate AI defense with
  `skylos defend . --min-score N --fail-on critical`.
- A gate synced by `skylos sync pull` (`.skylos/config.yaml`, or
  `SKYLOS_SYNCED_POLICY_FILE` in CI) with Cloud's `mode`/`by_category`/
  `by_severity` is checked the way Skylos Cloud checks it: zero-new (every
  category at 0), category, severity or both; any critical security issue and
  any secret still fail. Findings map to Cloud categories (danger → SECURITY,
  secrets → SECRET, quality → QUALITY, dead code → DEAD_CODE, dependency
  vulnerabilities → DEPENDENCY; AI-code, reliability and custom findings by
  rule ID prefix, then message) and severities (UNKNOWN or missing → MEDIUM).
  Cloud counts new issues only: use `--diff origin/main` (or `--baseline`); a
  full scan prints `Skylos Cloud counts only new issues. ...`. An uncommitted
  pulled file applies to `--diff` gates; `enabled: false` keeps the built-in
  limits.
- `--strict`: fail on any finding.
- `--force` / `-f`: bypass gate exit failure.
- Every gate run ends with a verdict line and its reasons: `Quality Gate:
  PASSED`, `Quality Gate: FAILED` (exit 1), or `Quality Gate: INCOMPLETE —
  could not decide (exit 2)` when required analysis did not finish (the reason
  names the check, the counts, and the fix; `--force` does not override it).
  Concise, LLM, GitHub, and GitLab output print it on stderr.
- Coverage gaps (a file that does not parse, `.go`/`.dart` files without
  their engine, dead-code candidates grep verification did not reach) are
  warnings: the scan and gate are decided on the analysed code and end with
  `Coverage: INCOMPLETE — some code was not analysed`. They exit 2 only with
  `--strict`, `require_complete = true` under `[tool.skylos.gate.coverage]`,
  when most source files were not analysed, or for a changed file in a
  `--diff` scan.
- A missing path or mistyped command (`skylos donee`) exits 2 with a "did
  you mean" line.
- `--format concise`: exits non-zero when findings exist.

## Skylos Cloud

`skylos cloud [PATH] [scan flags]` is the one Cloud command: it runs
`skylos PATH -a --upload` (only the named checks when check flags are given)
and prints the findings tables, logs in through the browser first when there is no
token (in a terminal; outside CI without a terminal it exits 1 before
scanning), and prints a short receipt: the branch gate line
(`✓`/`✗ Quality gate on <branch>: PASSED|FAILED (<history>) · <reasons>`),
`  Open: <project Overview URL, ?branch= for non-default branches>` and a
`  Next:` line. Exit 0 on a failed gate unless `--gate`/`--strict`; its
`--gate` is the Cloud gate only (no local `[tool.skylos.gate]` evaluation).
`--no-upload` is refused (exit 2). It sends findings, not the repository.
Plain `skylos . --upload` keeps its full upload output. Other Cloud commands
(`login`, `whoami`, `project`, `upload --retry`, `sync`, `credits`) are for
control. Local rich scans with findings end with a `Next: skylos cloud` block.

## Useful Subcommands

- `skylos commands`: list commands.
- `skylos tour`: walkthrough.
- `skylos init`: write project config.
- `skylos suite .`: full local analysis bundle.
- `skylos discover .`: inventory LLM/AI integrations (providers, agent tools,
  prompt sites, input sources); `--json` for machines.
- `skylos defend .`: pre-deployment agent verification — 13 deterministic
  guardrail checks per LLM integration, weighted defense score + separate ops
  score. Formats: `--format table|json|md|sarif` (`--json` = `--format json`;
  md = auditor evidence report with attestation; sarif = failed checks for
  code scanning). Gate with `--fail-on <sev>` / `--min-score <pct>` or a
  `--policy skylos-defend.yaml` (exit 1 on failure). OWASP selection:
  `--owasp-framework llm|agentic` (`llm` 2024/2025, `agentic` ASI 2026),
  filter with `--owasp LLM01,ASI02`. JSON schema 1.1 includes `attestation`
  (reproducible sha256 digest over full run evidence; identical tree + flags +
  Skylos version → identical digest) and `framework_evidence` (EU AI Act /
  NIST AI RMF / ISO 42001, evidence-toward semantics only). Details:
  `docs/agent-verification.md`.
- `skylos agent scan|verify|remediate|audit|watch|pre-commit|triage .`:
  hybrid static and LLM analysis, requiring `[llm]` extras and provider config.
  Without the extra, LLM commands exit 2 with `pip install "skylos[llm]"`;
  `skylos doctor` shows `LLM support not installed`.
- `skylos rules init|validate|list`: local YAML rule packs. `init` writes
  `.skylos/rules/local.yml`; `--quality`/`-a` scans apply packs in
  `.skylos/rules/` up to the repository root (base-branch copy in PR CI).
- `skylos cicd init`: set up the pull request gate for the detected CI
  (`--ci github|gitlab|jenkins|bitbucket|azure|circleci|other`); writes a new
  CI file or prints the block for an existing one. On GitHub with uploads on,
  it also uploads pull requests to the default branch through
  `pull_request_target` jobs that run `skylos cicd pr-policy`, `pr-scan` and
  `pr-publish` (workflow steps, not for local use).
- `skylos done map [PATH] [--base REF] [--format text|json|markdown]`: the
  change map. Per changed Python or TS/JS function, method or class: old and
  new code, calls added/removed/moved, callers (`in_change`, `is_test`),
  removed security checks, breaking or compatible signatures and the callers
  they break, and `read_first` / `flagged` ids. Deterministic; no model, no
  network. `--base` defaults to HEAD (uncommitted changes only). Exit 0
  shown, 2 could not run. `skylos done --map` prints it after the verdict
  without changing it. MCP tool: `change_map`. Details: `docs/change-map.md`.
- `skylos baseline .`: save current findings baseline.
- `skylos clean`: interactively remove or comment dead code. Edits Python files
  only; other files are listed, never offered. Exit 1 if any edit fails.
- `skylos cache stats|clear`: manage cache data.
- `skylos doctor`: installation health check.
- `skylos verify-verdict BUNDLE [--commit SHA] [--repository HOST/OWNER/REPO]
  [--project ID] [--workspace ID] [--require-repository-verified]
  [--require-trusted-upload] [--max-age 7d] [--require-passed [--allow-override]] [--keys PATH_OR_URL]
  [--json]`: verify a Skylos Cloud signed check verdict (Ed25519 DSSE,
  in-toto/SLSA VSA) for deploy gates. Exit 0 verified, 1 not passing under
  `--require-passed` (FAILED, overridden without `--allow-override`, or gate
  disabled), 2 not verified or an expectation mismatch. Needs
  `skylos[verdict]`. Details: `docs/verify-verdict.md`.
