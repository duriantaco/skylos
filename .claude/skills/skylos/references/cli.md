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
- `--sca`: dependency CVEs through OSV.dev. Reads PyPI, npm, Go, Maven
  (`pom.xml`, `gradle.lockfile`), crates.io (`Cargo.lock`/`Cargo.toml`),
  Packagist (`composer.lock`/`composer.json`), RubyGems (`Gemfile.lock`), Pub
  (`pubspec.lock`/`pubspec.yaml`) and NuGet (`packages.lock.json`, `*.csproj`)
  files; `Gemfile` and `build.gradle(.kts)` are not evaluated. Unread files are
  in `sca_coverage.unsupported_inputs`, unparsable ones in
  `sca_coverage.parse_errors`, Git/path/private entries in
  `sca_coverage.lockfile_not_checked`. Malware advisories (`MAL-*`, CWE-506)
  are `CRITICAL` with `metadata.malicious` and are never dev-only demoted.
  Supply-chain checks via `ca9.api`: `SKY-SCA-SRC001` dependency confusion
  (needs `[tool.skylos.supply_chain] internal_packages`), `SKY-SCA-SRC003`
  unpinned Git / unhashed URL, `SKY-SCA-SRC004` (diff scans) a package moved to
  a source the repository did not use, `SKY-SCA-INT001` lockfile entry without
  integrity, `SKY-SCA-AGE001` (only with `min_release_age_hours`). Missing ca9
  is a note in `sca_coverage.supply_chain.notes`, not an error.
  `analysis_summary.dependency_inventory`, `supply_chain_posture`,
  `ci_inventory` and `agent_hooks` are uploaded next to `sca_coverage`
  (`supply_chain_checks` stays local and says what ca9 could not build).
  With `--diff`/`--diff-base`, `--sca` adds `SKY-SCA-HRD001` (install
  hardening weakened; exceptions only from the base commit's
  `[tool.skylos.supply_chain.hardening_exceptions]`) and, with
  `--review-upgrades` (implies `--sca`), `SKY-SCA-UPG001` (CRITICAL, blocks) /
  `SKY-SCA-UPG002` (MEDIUM, listed only) from ca9's old-vs-new package diff,
  mapped by ca9's `block`/`warn` list, never by kind; packages new at HEAD go
  with `old: None`. Unreviewed changes (timeout, unreachable registry, cap,
  `complete: false`) and changed lockfiles Skylos could not read (over 64 MB,
  a link, parser rejected) are an analysis error (diff gate exit 2); internal
  packages and private-registry entries are skipped with a warning; changed
  requirements pins, `pdm.lock` and `pylock.toml` are listed as not read
  (`checks.upgrades.limitations`). Receipt: `analysis_summary.supply_chain_diff`.
  `--review-upgrades` also adds `SKY-SCA-API001` (MEDIUM, advice: no gate counts
  it, not uploaded): your line uses a public name, module, method or keyword a
  Python upgrade removed, read statically from both releases via `ca9.artifacts`,
  never imported. Unreadable things (failed download, compiled module with no
  `.pyi`, module `__getattr__`, computed `__all__`) are listed as could not check
  in `checks.upgrade_api.could_not_check`, never as clean and never an analysis
  error. PR comment wording is fixed: `Review these N call sites` or `No API-level
  impact found in N call sites (behaviour changes not checked)`.
- Agent/editor config and publish jobs (`--danger`, via ca9):
  `SKY-D365` agent hook, `SKY-D366` folderOpen task, `SKY-D367` unpinned MCP
  server, `SKY-D368` hidden-path MCP server, `SKY-D369` impersonating MCP
  package, `SKY-D370` base-URL override, `SKY-D371`-`SKY-D374` publish-job
  rules, `SKY-D375` (diff only) publish job added/changed, `SKY-D376` secrets
  to a remote reusable workflow, `SKY-D377` duplicated keys in agent config.
  Full scans list D365-D374/D376/D377 without counting them (a CRITICAL hook
  still fails); diff scans fail on a new D365/D366/D368/D370; baseline scans
  only for rules the baseline's `rule_coverage` lists (older baselines: listed).
  "New" in `--diff` = not among the merge base's findings by rule, path and
  identity (name + unredacted command), so trigger-only edits count
  (`config_diff_basis`); baselines match the same identity digest, and under
  `SKYLOS_POLICY_BASE` supply-chain baseline entries must also be on the base
  commit. In-repo links to agent configs are followed (reported under the link
  path); a new link leaving the repo or dangling is exit 2. Subfolder scans
  include repository-level workflows/agent configs; uploads build
  `ci_inventory`/`agent_hooks` from the Git top.
  A diff touching agent configs, workflows or lockfiles without a usable ca9 is
  exit 2 ("upgrade ca9"). Commands in findings/uploads are redacted. Hooks written by
  `skylos agent install-hooks` are recognised by exact command grammar and
  not reported. A changed agent/workflow file with a ca9 that lacks the
  function is an analysis error (exit 2), never a pass. See
  `docs/agent-config-and-publish-rules.md`.

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
Every finding carries `fix` (one line, for its language) and `docs_url`.
`top_risks` lists up to five rows to fix first (`rule_id`, `severity`, `file`,
`line`, `blocking`, `in_tests`, `fix`, `docs_url`, `more_like_this`), and
`issue_summary` holds the one issue total (`total`, `by_category` with `null`
for a check that did not run, `not_checked`, `hidden_advice`, `suppressed`,
`dismissed`, `verdict`). Use `issue_summary.total`, not array lengths, when
reporting how many issues a scan found.

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
  supported and fail the agent gate; gate AI app safety with
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
`  Open: <project Overview URL, ?branch= for non-default branches>`, a
`  Sent:` line (`findings` or `findings and the Done receipt (<verdict>)`,
then the Done-table note or the upload standing) and a `  Next:` line. With a
committed `[tool.skylos.done]` table and a clean tree it attaches this
commit's `.skylos/receipts/latest.json` or runs `skylos done` first (not in
CI, not with `--done-receipt`). Exit 0 on a failed gate unless `--gate`/`--strict`; its
`--gate` is the Cloud gate only (no local `[tool.skylos.gate]` evaluation).
`--no-upload` is refused (exit 2). It sends findings, not the repository.
Plain `skylos . --upload` keeps its full upload output. Other Cloud commands
(`login`, `whoami`, `project`, `upload --retry`, `sync`, `credits`) are for
control. Local rich scans with findings end with a `Next: skylos cloud` block.

## Useful Subcommands

- `skylos commands`: list commands.
- `skylos tour`: walkthrough.
- `skylos init`: write project config.
- `skylos report .`: one-page HTML (`--format md` for Markdown, `-o -` for
  stdout) for a non-specialist: verdict, top five risks with fixes, counts by
  category, suppressed/dismissed counts, coverage gaps, date/commit/version.
  `skylos report scan.json` reuses a saved `-a --format json` scan.
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
- `skylos . -a --ai-review` (also `skylos cloud --ai-review`): AI review.
  Python security issues get the `--verify-security` votes; unused-code issues are
  reviewed by the LLM and, with `TYPESAFE_API_KEY`, by Jev. Each reviewed
  issue gets `metadata.ai_review.reviewers[]` (`name` llm|jev, `verdict`
  real|false_positive|unsure, `model`, `reason`). Display only: no issue is
  dropped and the gate and exit code never change. `--model`/`--api-base`
  pick the model. Without a key it prints one skip line. Details:
  `docs/ai-review.md`. Skylos uses three AI names: AI review, Coding agents,
  AI app safety (`docs/ai-review.md`).
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
- `skylos setup [PATH] [--base REF] [--ci CI] [--no-ci] [--no-codex] [--yes]`:
  once per repository. Writes a Skylos block between `<!-- skylos:start -->`
  and `<!-- skylos:end -->` in `CLAUDE.md` and `AGENTS.md` (skips `CLAUDE.md`
  when it only imports `@AGENTS.md`), adds `skylos` to `.mcp.json` (keeps
  other servers; leaves invalid JSON alone), runs `codex mcp add skylos` when
  Codex is installed (warns if Codex or PATH points at a different Skylos),
  writes the PR check through `skylos cicd init` (`--yes` replaces an existing
  workflow) and builds the graph. Idempotent. Exit 1 when a step needs
  attention; it still runs the others. Needs a git repository.
- `skylos open [PATH] [--base REF] [--port N] [--no-browser]`: `skylos graph
  open` compared with the branch pull requests merge into (`origin/HEAD`, else
  `origin/main`, `origin/master`, `main`, `master`; HEAD when on that branch).
  The page has Graph, Overview, Changes and Pipeline tabs and a Check this
  change button (POST `/api/check`, token, local Host and JSON only) that runs
  `skylos done --base REF --agent check-button` and rebuilds the graph.
- `skylos done map [PATH] [--base REF] [--format text|json|markdown]`: the
  change map. Per changed Python or TS/JS function, method or class: old and
  new code, calls added/removed/moved, callers (`in_change`, `is_test`),
  removed security checks, breaking or compatible signatures and the callers
  they break, `read_first` / `flagged` ids, and `review`: every production
  symbol in one bucket (`read_first`, `read`, `skim`, `skip`) with
  `review_why`, changed-line counts per bucket and `test_edits` (expected
  answers the change edited). `skip` only for proven same logic (Python
  docstring-only or local-rename-only; moves are `skim`, counted once); never for flagged
  code, edited test answers, runtime-read docstrings or dynamic local names.
  Deterministic; no model, no network. `--base` defaults to HEAD (uncommitted
  changes only). Exit 0 shown, 2 could not run. `skylos done --map` prints it
  after the verdict without changing it. MCP tool: `change_map` (no key, no
  limit). The GitHub workflow from `skylos cicd init` writes it to the Skylos
  Done job summary. Details: `docs/change-map.md`, flow: `docs/workflow.md`.
- `skylos graph [PATH] [--since REF] [--format text|json]`: builds
  `.skylos/graph/` (Python, TS/JS; Go/Java/Rust/PHP links matched by name as
  `name_edges`, never counted as callers): every function/method/class, call,
  create and inherit links, tests that reach each one, literal expected
  outputs read from tests, and per changed symbol a verdict: `same_moved`,
  `same_renamed` (only locals), `same_docs`, `changed`, `changed_binding`,
  `new`, `removed`. "Same" is only claimed when proven. `--since` defaults
  to HEAD; `none` skips it. Subcommands: `open` (127.0.0.1 viewer, token +
  HttpOnly cookie, rebuilds on file change; Pipeline tab = last 30 `skylos done`
  receipts as stage boxes with a copyable fix brief), `show NAME`, `find QUERY`,
  `impact NAME [--depth N]` (adds name-matched `possible_callers`),
  `areas [ID]` (folder-first areas, stable ids), `relevant FILE... [--budget N]`
  (code the files use or are used by, within a token budget), `changes [--base
  REF]` (review buckets), `describe` (your model
  key; `--changes` explains changed code; `--via skylos` (not live in Skylos Cloud yet) uses Skylos's key
  for credits: 1 per 100 functions or 20 changes, needs `skylos login`),
  `pending [--changes --base REF]` + `import FILE` (agent writes
  descriptions), `report --base REF
  [--output FILE]` (Cloud report: verdicts and reasons, no source).
  `--upload` sends that report to Skylos Cloud (not live in Skylos Cloud yet; committed changes only; the
  project must have Logic changes reports turned on, 1 credit per PR).
  Descriptions live in `.skylos/graph/notes.json` (commit it). MCP tools (no
  key, no limit): `graph_find`, `graph_show`, `graph_impact`, `graph_areas`,
  `graph_relevant`,
  `graph_pending` (`changes=true`, `base`), `graph_describe`; change verdicts
  come from `change_map`. Details: `docs/graph.md`.
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
