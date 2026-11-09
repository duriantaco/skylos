# Skylos Rule Dictionary and Product Glossary

This file is the repo-local glossary for public Skylos terminology and emitted
rule IDs. Keep it aligned with `README.md`, translated READMEs in
`docs/i18n/`, `docs/*.md`, CLI help text, and rule implementations.

Rule IDs use a stable public prefix:

| Prefix | Meaning |
|:---|:---|
| `SKY-D` | Security and danger findings |
| `SKY-S` | Secrets findings |
| `SKY-SCA` | Software composition findings, including dependency vulnerabilities and publisher review signals |
| `SKY-SC` | Security contract regression findings |
| `SKY-A` | AI-defect verification findings |
| `SKY-L` | Logic, AI-code mistake, and resilience findings |
| `SKY-Q` | Quality, complexity, coupling, and architecture findings |
| `SKY-C` | Structure and clone findings |
| `SKY-P` | Performance findings |
| `SKY-U`, `SKY-DC`, `SKY-UC` | Dead-code, LLM dead-code report, and unreachable-code findings |
| `SKY-T` | Typing practice findings |
| `SKY-F` | Framework practice findings |
| `SKY-R` | Repository policy findings |
| `SKY-E` | Analyzer inventory / export findings |
| `SKY-G` | Raw Go engine findings before remapping |
| `SKY-DEP` | Kubernetes deployment exposure findings |
| `SKY-GPU` | GPU release compatibility findings |
| `SKY-CIRC` | Circular dependency finding |

## Product Glossary

| Term | Meaning |
|:---|:---|
| Skylos | Local-first static analysis and PR gate for dead code, security, secrets, quality, dependency, and AI-code issues. |
| Local-first | Core static analysis runs on the developer machine or CI runner without requiring cloud upload or LLM calls. |
| Core scan | `skylos .`; dead-code focused scan. |
| Full audit | `skylos . -a`; enables security, secrets, dependency, quality, and AI-defect checks in addition to dead code. |
| Generated files | Django migrations, `static/**/lib/**`, `*.min.js`, `*.min.css` and JS/CSS files that open with a vendored-library licence banner. Skipped by default with a one-line count; migrations are still parsed for references and keep security and secret findings. Scan them with `--include-generated` or `[tool.skylos] include_generated = true`. |
| Ruff lint integration | `skylos lint`; optional Python-only delegation to `ruff check` with native Ruff configuration, output, fixes, and exit codes. Install with `skylos[lint]`; it is not part of normal Skylos scans. |
| Dead code | Unused functions, classes, imports, variables, parameters, files, unnecessary exports, and unreachable code. |
| Security / danger | Potentially exploitable code paths such as injection, SSRF, path traversal, weak crypto, unsafe deserialization, and CI/CD supply-chain risk. |
| Secrets | Hardcoded credentials, tokens, API keys, and client-side exposure of server-only values. |
| Quality | Maintainability, complexity, architecture, resilience, typing, framework practice, and repo policy issues. |
| AI defects | Evidence-backed AI-code failure modes such as hallucinated APIs, impossible dependencies, phantom references, and weakened tests. Run with `--ai-defects`; full audits include it. Output uses the `ai_defects` bucket; individual findings use category `ai_defect`. |
| AI code mistakes | Hallucinated security calls, phantom decorators, unfinished stubs, disabled controls, placeholder data, stale mocks, and missing timeouts. |
| AI review | `skylos . -a --ai-review`; an AI model (and Jev, when `TYPESAFE_API_KEY` is set) double-checks unused-code issues (every language) and security issues in Python files, and records `metadata.ai_review` with one verdict per reviewer (`real`, `false_positive`, `unsure`). Display only: nothing is hidden and blocking never changes. Skylos Cloud shows it as Confirmed by AI, AI disagrees, AI unsure or Found by AI only. |
| Coding agents | Skylos features for code written by AI coding agents: `skylos done`, agent-loop hooks, project standards, `skylos verify`, and in Skylos Cloud the Coding agents page, Agent checks, agent rules and Bot approvals. |
| AI app safety | Checks on the AI features of your own application: `skylos discover`, `skylos defend` and `skylos agent test`. Skylos Cloud shows `skylos defend` results under AI app safety. |
| Jev | An outside dead-code model (TypeSafe `jev-1.13.0`) that `--ai-review` and `skylos agent verify` can use as a second reviewer. Needs `TYPESAFE_API_KEY`. |
| Security quick | `skylos agent security-quick .`; one-shot LLM security audit, equivalent to `skylos agent scan . --security`. |
| Security deep | `skylos agent security-deep .`; three-stage security workflow for threat-model context, static threat tracing, discovery/validation, and remediation handoff, equivalent to `skylos agent audit . --deep`. |
| Threat trace | Static source-to-sink evidence showing how user-controlled input reaches a sensitive sink, recorded on security-deep findings and run artifacts. |
| Agent verification (pre-deployment) | Part of AI app safety. `skylos defend .`; deterministic static verification of AI-agent guardrails before deployment — tool safety, output validation, prompt-injection exposure, PII filtering, model pinning, and ops checks — scored and gateable in CI. Formerly described as "LLM app defense". Check ids are kebab-case plugin ids (e.g. `no-dangerous-sink`), distinct from the SKY-D260–D267 static rules. |
| LLM integration inventory | `skylos discover .`; maps every LLM call, agent tool, prompt site, input source, and output sink in the codebase — SDK calls, agent frameworks (incl. OpenAI Agents SDK, Claude Agent SDK, Google ADK), MCP servers and their tools, and direct HTTP calls to LLM APIs or OpenAI-compatible gateways. Feeds `skylos defend`. |
| Evidence report | `skylos defend . --format md`; auditor-facing markdown artifact with integration inventory, per-check results, OWASP LLM + Agentic coverage, regulatory framework evidence, remediation appendix, and attestation. |
| Attestation digest | Reproducible SHA-256 over scanned file contents, policy hash, plugin set, OWASP selection, filters, integration inventory, scores, and full check evidence; emitted in defend JSON/md/SARIF output. Identical trees, flags, policy, plugin set, and Skylos version reproduce identical digests; timestamps are excluded. |
| Framework evidence | Defend check results mapped to EU AI Act, NIST AI RMF, and ISO/IEC 42001 controls with strict "evidence toward" semantics — never a compliance determination. |
| Prompt templates | Trusted files passed with `--prompt-template KIND=PATH` to `skylos agent` commands that extend built-in LLM prompts without replacing safety and JSON-output contracts. Repository config cannot set them; `[tool.skylos.templates]` is not read. |
| Vibe dictionary | Project-specific keyword extensions under `[tool.skylos.vibe]` for phantom security names, credential names, sensitive files, timeout-required calls, and extra `random.*` functions that SKY-L013 treats as insecure for security values (`extra_insecure_random_funcs`). |
| Quality gate | A threshold-based pass/fail decision used locally or in CI. Critical security issues, secrets, and AI-code issues at `block_ai_defect_severities` (default `["CRITICAL"]`) fail it regardless of counts. Every run ends with a verdict line and its reasons: `PASSED`, `FAILED`, or `INCOMPLETE — could not decide (exit 2)` when required analysis did not finish; `--format json` carries it as the top-level `gate` object. Files that were not analysed (a parse error, a missing language engine) are a coverage warning under a PASSED or FAILED verdict, not exit 2, unless `--strict` or `require_complete = true` asks for complete coverage or most of the code was not analysed. |
| Risk review | `skylos cicd risk-review --base REF`; the GitHub check "Skylos risk review" (`skylos cicd init --risk-review`). Lists the risk classes a pull request contains. With risks, the check fails until a person with write access approves the head commit; approvals from bot accounts and approvals of older commits do not count. While it fails on a pull request, the job keeps the label `skylos:needs-human` on it and removes it when the check passes. Exit 0 pass, 1 needs a human approval, 2 could not decide. Settings: `[tool.skylos.approval]` at the base. See [docs/risk-review.md](./docs/risk-review.md). |
| Risk class | One of the nine facts the risk review reports, each needing a human approval: `tests_weakened`, `auth_removed`, `dependency_changed`, `ci_weakened`, `checks_silenced`, `secret_added`, `guardrail_config_changed`, `migration_changed`, `large_diff`. Rule findings map to classes by rule ID; findings `skylos done` reports only as advice are listed and need no approval. The names are shared with Skylos Cloud. |
| Eligible (risk review) | No risk class found and every class checked: an approval from anyone, a review bot included, is enough. An incomplete analysis is never eligible. |
| Needs-human label | `skylos:needs-human`, the GitHub label the risk review job adds to a pull request that exits 1 and removes when it exits 0 (exit 2 leaves it alone; merge-group and local runs never touch it). The job creates the label in the repository the first time. `is:pr is:open label:skylos:needs-human` lists every pull request waiting on a person. A failed label update prints `Could not update the skylos:needs-human label: <reason>` and never changes the exit code. |
| Change map | `skylos done map --base REF`; the MCP tool `change_map`. Lists each changed Python or TypeScript/JavaScript function, method and class with its old and new code, calls added and removed, callers (and whether they were updated), removed security checks, breaking or compatible signature changes and changed values. Computed from the code, not by a model; it has no verdict and never changes the done gate. See [docs/change-map.md](./docs/change-map.md). |
| Read first (change map) | The three highest-risk production changes in a change map plus every flagged change. |
| Flagged (change map) | A change a person should read before merging: a removed security check, a risky new call, deleted code still called, calls that now resolve elsewhere with unchanged text, a signature change that breaks or silently defaults a caller outside the change, a changed security setting, or a removed validation rejection. |
| Diff-aware scan | `--diff <base>` limits reporting to changed work so old debt does not drown out the current PR. |
| Baseline | A saved set of accepted existing findings so only new or changed findings fail a gate. |
| Failure origin | `skylos done` reruns each failing test on the base commit, in a temporary Git worktree, and labels it `preexisting` (the same test ran there and failed the same way), `introduced` (it passes there), `new_test` (it does not exist there; counts as introduced) or `undetermined` (the base run could not tell: a setup or import error, a different kind of failure, a timeout, changed dependencies). Shown on the receipt as `failure_origins` and in the Stop-hook message. |
| Suppression | An inline or config-level exception for an intentional finding, usually using `skylos: ignore[SKY-...]`. Skylos-specific markers (`# skylos: ignore[SKY-D211] reason`, `# skylos: ignore`, `# noqa: skylos`, `# pragma: no skylos`, `ignore-start`/`ignore-end`) suppress findings on their line: the bracketed form only the listed rules (dead code by its ID: `SKY-U001` functions and methods, `SKY-U002` imports, `SKY-U003` variables, `SKY-U004` classes, `SKY-U006` parameters), the bare form every rule. `skylos: ignore`, `skylos: ignore[...]` and `ignore-start`/`ignore-end` work in every analysed language for dead code, security, quality and secrets. In Go, Java, Kotlin, C#, PHP, Dart, Rust, C/C++, Shell and TS/JS they are read only from real comments (`#` in Shell and PHP; `//` or a one-line `/* */` in the others; the directive must open the comment): text inside a string literal never counts, and a file whose strings or comments cannot be followed to the end honours no directive. Python matches `# skylos: ignore` on the line. Other tools' markers (`#nosec`, `//nolint`, `NOSONAR`, `@SuppressWarnings`, `#pragma warning disable`) do not hide Skylos findings. `ignore = ["SKY-U001"]` in `[tool.skylos]` turns off exactly that rule project-wide (unused functions; `SKY-UC001` is unreachable code). A bare `# noqa` (no codes) is a generic linter marker: it still hides dead-code, quality and LOW/MEDIUM findings, but not a HIGH or CRITICAL security finding (`SKY-D*`, `SKY-S*`), which stays reported with `bare_noqa_ignored: true` and an advice line. `# noqa: <code>` with Ruff/flake8 codes never suppresses a Skylos security, secret or quality finding; F401/F841 only mark the matching unused import/variable. |
| Smart tracing | `--trace`; runtime-assisted dead-code verification used to reduce false positives in dynamic Python code. |
| Technical debt | `skylos debt .`; ranks maintainability hotspots and debt trends. |
| TUI | `--tui`; screen-only selectable terminal interface with category list, finding list, and detail pane. |
| Pretty output | `--format pretty`; compact file-grouped terminal output with severity rails, snippets, and copyable `file:line` locations. |
| Concise output | `--format concise`; untruncated `file:line  RULE_ID  message` output for editors, scripts, and agents. |
| Rule selection | `--select SKY-...`; exact, case-insensitive rule filtering across scan output formats with automatic analyzer-family enablement. |
| Finding type | Every built-in rule declares `finding_type`: `defect`, `review`, or `advice`. Type describes the purpose of a check; severity remains separate. Terminal reports group Advice by rule and `--expand-advice` shows every record. JSON retains complete records for the selected scan scope. Display grouping does not change the assessment or gate limits. See [docs/cli-output.md](./docs/cli-output.md#finding-types-and-advice). |
| Scan assessment | Four readouts: Risk, Maintainability, Dead code and Gate, with explicit coverage and scope. New source scans emit `assessment` version 1 instead of an overall numeric or A–F `grade`. Independent `debt` and `defend` scores are unchanged. See [scan assessment](./docs/cli-output.md#scan-assessment). |
| Risk readout | Highest unresolved severity and counts for Defect and Review findings outside dead-code candidate lists. Clean categories and repository size do not dilute it. A risk finding still needs contextual review. |
| Maintainability readout | Advice counts, affected units and measured threshold excess. A proportion is reported only when its relevant rule/language inventory is complete; otherwise its denominator is unavailable. No uncalibrated letter grade. |
| Coverage | Which checks completed, did not run, or could not finish. Not assessed and incomplete do not mean clean. |
| Structured output | `--format json`, `--format llm`, or `--format github` for machines, LLM consumers, and GitHub annotations. |
| Upload / Cloud workflow | Optional upload of scan results to Skylos Cloud; not required for local analysis. |
| Upload contract | `skylos/api/upload_contract/v1.json`, shared with Skylos Cloud; defines how each finding is normalized, which errors reject a whole upload, and the retry and idempotency rules. The CLI sends `X-Skylos-Upload-Contract: 1`. See [docs/cli-output.md](./docs/cli-output.md#uploading-to-skylos-cloud). |
| Idempotency key | A UUID v4 sent as `Idempotency-Key` on every request of one upload, its retries and its resends, so Cloud never saves or charges the same scan twice. |
| Saved upload | A scan whose upload failed for a temporary reason or was interrupted, kept outside the repository in `~/.skylos/pending-uploads/<repo-id>/` (0600, HMAC-signed with a per-user key, no token) as the exact bytes that were sent. It is resent unchanged, to the same endpoint and linked project, within 7 days; after that it moves to `failed/` ("too old to resend safely; rerun the scan"). Files an older version left in the repository's `.skylos/pending-uploads/` are never sent. |
| `skylos upload --retry` | Resends saved uploads with their original keys; `skylos upload --list` shows them. Sent scans are deleted; rejected ones move to the queue's `failed/` folder with the reason. |
| "N findings have no file location; uploading them anyway." | Printed before an upload when some findings have no usable path (none, a placeholder such as `unknown`, outside the repository, or a folder). They are uploaded with an empty path and stored without a location. |
| "Upload failed: <what went wrong> <what to do> (ref: <id>)" | The upload error format. The reference is Cloud's request id to quote to support. Raw server responses are never printed. |
| "still processing; checking again in Ns" | Cloud answered a retryable 409 (the same upload is still running); the CLI waits as asked, for up to 300 seconds in total. |
| "Scan was already saved by an earlier attempt" | Cloud recognised the idempotency key (`Idempotent-Replayed: true`); nothing was saved or charged twice. |
| Signed check verdict | The check result Skylos Cloud decided for one commit, signed as an in-toto Statement v1 with a SLSA Verification Summary predicate in an Ed25519 DSSE envelope, bundled with the check summary it commits to (`skylos.verdict-bundle/v1`). It proves the check ran under that policy with that result; it does not prove the code is safe, and only GitHub OIDC uploads (`repository_verified`) prove the results came from that commit's code. See [docs/verify-verdict.md](./docs/verify-verdict.md). |
| Upload trust | How far Skylos Cloud trusts an upload (`upload_trust`): `verified_ci` (GitHub or GitLab OIDC), `trusted_api_key` (a project key an owner or admin marked as a CI key; keys from before per-key trust count for 30 days unless confirmed) or `unverified`. Uploads with the `skylos login` key are always unverified, because any coding agent on that machine can read the key: they are stored and shown, but never publish a check or pull request status, mark issues fixed, set a baseline or get a signed verdict. The CLI prints the reason after the upload. |
| `skylos verify-verdict` | Verifies a signed check verdict offline against the published keys (`https://skylos.dev/.well-known/skylos-verdict-keys.json` or a local `--keys` file). `--commit`, `--repository`, `--project`, and `--workspace` bind it to what is being deployed; `--require-repository-verified` requires a GitHub OIDC upload bound to the repository; `--max-age` rejects old verdicts; `--require-passed` exits 1 unless the level is `SKYLOS_POLICY_PASSED` (`--allow-override` also accepts `SKYLOS_GATE_OVERRIDDEN`; `SKYLOS_GATE_DISABLED` never passes). Exit 2 means not verified. Needs `skylos[verdict]` (`cryptography`). |
| MCP server | Integration surface for AI agents and coding assistants. |
| SCA | Software composition analysis for dependency vulnerabilities and opt-in npm publisher review signals. |
| Not checked (SCA) | A lockfile entry that is the project's own local code, so no advisory database can describe it: pnpm `link:`/`file:` directories, local tarballs, peers satisfied by a workspace project, `runtime:` entries, Cargo workspace members and path crates, Composer path repositories, Bundler `PATH` gems, pub `path` and `sdk` packages, and NuGet `Project` entries. Listed in `sca_coverage.lockfile_not_checked` (count `not_checked_lockfile_dependency_count`); it does not make the dependency scan incomplete or stop the gate. In every lockfile format except `gradle.lockfile` and `packages.lock.json`, validated Git, URL, private-registry and Composer branch (`dev-*`) entries are also not checked and give `complete_with_non_registry_sources`; contradictory records (a public-registry tarball that does not match its package, an alternate pnpm `id`, an unrecorded Yarn `virtual:` peer) stay unresolved and make the scan incomplete. |
| SCA dependency files | Files `--sca` reads: lockfiles `uv.lock`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pubspec.lock`, `gradle.lockfile`, `packages.lock.json`; manifests (exact pins only) `requirements.txt`, `pyproject.toml`, `setup.cfg`, `setup.py`, `package.json`, `go.mod`, `*.csproj`, `pom.xml`, `Cargo.toml`, `composer.json`, `pubspec.yaml`. `Gemfile` and `build.gradle(.kts)` are code and are not read. A file that cannot be parsed is named in `sca_coverage.parse_errors`. |
| Informational advisory (SCA) | A RustSec notice (`unmaintained`, `notice`, `unsound`) served by OSV, recorded as `metadata.advisory_informational`. `unmaintained` and `notice` get `low_risk_context.reason = "informational-advisory"`: kept in JSON and gates, left out of the default listing. |
| npm publisher review | Opt-in `--scan-publisher-changes` checks direct npm dependencies in a lockfile for a newly observed publisher after a long release gap. `publisher_change_findings` are WARN review signals, not evidence of compromise or known vulnerabilities; they do not affect the vulnerability count or gate. |
| SBOM | `skylos sbom .`; offline dependency inventory as CycloneDX 1.6 (default) or SPDX 2.3 (`--format spdx-json`) JSON, including declared licenses. |
| License policy | `[tool.skylos] license_deny` / `license_allow` / `license_exceptions` / `license_severity`; flags dependencies whose declared SPDX license violates policy as `SKY-SCA-LIC001`. Unknown licenses are `NOASSERTION` and never fire. |
| Malicious package (SCA) | An OSV advisory with an `MAL-*` ID or alias, a `malicious-packages-origins` record, or CWE-506. Reported `CRITICAL` under its `SKY-SCA-<id>` rule with `metadata.malicious: true`; never demoted as dev-only and never given a reachability verdict. When OSV is unreachable, the installed ca9 malware feed is checked (`metadata.malware_source: "ca9_feed"`). |
| Supply-chain policy | `[tool.skylos.supply_chain]` (`internal_packages`, `private_registries`, `trusted_registries`, `min_release_age_hours`, `block_malware`, `check_provenance`), merged with the synced Skylos Cloud `supply_chain` block, which can only tighten it. Read by `--sca` scans (SKY-SCA-SRC001/AGE001) and the install hook. |
| Dependency inventory | `analysis_summary.dependency_inventory` (`skylos.dependency_inventory.v1`): up to 10,000 sorted, de-duplicated packages (`ecosystem`, `name`, `version`, `direct`, `dev`, `file`) with `total`, `truncated` and `complete`; uploaded so Skylos Cloud can match new malware advisories after the scan. |
| Supply-chain posture | `analysis_summary.supply_chain_posture` (`skylos.supply_chain_posture.v1`): checks `lockfile_committed`, `frozen_install_ci`, `install_scripts_disabled`, `release_age_cooldown`, `actions_pinned` (from SKY-D292) and `no_pr_target_checkout` (from SKY-D290), each `pass`, `fail`, `not_applicable` or `unknown`; `pass` needs evidence in the repository. Committed values from `ca9.api.hardening_settings` are read first. Knows npm 12 and pnpm 10+ script blocking, pnpm 11 `allowBuilds`/`strictDepBuilds` and its one-day default cooldown, Yarn 4.15's one-day default, Bun `minimumReleaseAge` in seconds and pip `--uploaded-prior-to`; Dependabot's cooldown is named but does not pass it. |
| CI inventory | `analysis_summary.ci_inventory` (`ca9.ci_inventory.v1`, from `ca9.api.ci_inventory`): per GitHub Actions / GitLab CI job its triggers, runner, environment, token write scopes, `id-token`, secret names, installs, actions, tools, download hosts and publish steps; bounded (200 workflows, 500 jobs) and names only. Uploaded so Skylos Cloud can tell which jobs could have installed a package and what they could reach. |
| Agent hooks inventory | `analysis_summary.agent_hooks` (`ca9.agent_hooks.v1`, from `ca9.api.agent_config`): committed agent/editor hooks, MCP servers and base-URL overrides with redacted commands; `skylos_hook: true` marks hooks `skylos agent install-hooks` wrote. Uploaded next to the dependency inventory. |
| Saved OSV answers | The last good OSV answer per exact package version, kept in the user cache and used only when OSV cannot be reached, up to 7 days old. Status `complete_with_saved_answers`, `complete: false`. Never read from inside a scanned repository. |
| Reachability tier | `metadata.reachability_tier` on PyPI advisories: `used`, `imported`, `unknown`, `not_imported` or `unreachable`. It orders terminal output and never changes what the gate counts. |
| Upgrade review | `--review-upgrades` (implies `--sca`; on in pull request scans from `skylos cicd init` when dependency checks are selected): with `--diff`/`--diff-base`, each npm/PyPI lockfile version change is downloaded old and new by ca9 and compared as data, and a newly added package is reviewed on its own (SKY-SCA-UPG001/UPG002). Never installs or runs the packages. |
| Upgrade API comparison | Part of `--review-upgrades`: compares the public API of the old and new release of each Python package whose locked version changed, and names your lines that use what was removed (`SKY-SCA-API001`). The pull request comment says `Review these N call sites` or `No API-level impact found in N call sites (behaviour changes not checked)`, and `Could not check` with a reason for anything it could not read. Receipt: `analysis_summary.supply_chain_diff.checks.upgrade_api`. |
| Hardening exception | `[tool.skylos.supply_chain.hardening_exceptions]` `package = "reason"`, read from the diff base commit only: SKY-SCA-HRD001 regressions that name that package are skipped and listed in `analysis_summary.supply_chain_diff`. |
| Symlink safety | Checks for file operations that follow repository-controlled symbolic links across the intended scan or output boundary. |

## CLI Output Modes

| Mode | Command | Intended Use |
|:---|:---|:---|
| Rich/default | `skylos .` | Existing full terminal report. |
| Pretty | `skylos . --format pretty` | Human terminal triage with grouped findings and copyable locations. |
| Concise | `skylos . --format concise` | Editors, test scripts, and agents that need untruncated `file:line  RULE_ID  message` findings. |
| JSON | `skylos . --format json` or `skylos . --json` | Structured machine output. |
| LLM | `skylos . --format llm` or `skylos . --llm` | LLM-oriented structured report with code context. |
| GitHub | `skylos . --format github` or `skylos . --github` | GitHub annotation output. |
| TUI | `skylos . --tui` | Screen-only selectable keyboard-driven terminal triage. |

See [docs/cli-output.md](./docs/cli-output.md).

## Security / Danger (SKY-D)

Rule IDs are unified across languages where the same vulnerability exists.

| ID | Severity | Name | Languages / Scope | CWE / OWASP |
|:---|:---|:---|:---|:---|
| D200 | varies | Dangerous function call family | Python | wrapper for D201-D210, D233, D235, D250 |
| D201 | HIGH-CRITICAL | Dynamic code execution: `eval` (PHP: `eval`, `create_function`, `preg_replace` with the `/e` modifier, and `assert()` of request data; CRITICAL with request data, HIGH for other non-constant code) | Python, TS/JS, PHP, audit | CWE-95 / A03 |
| D202 | HIGH-CRITICAL | Dynamic code execution: `exec`, `new Function`, string timers | Python, TS/JS | CWE-95 / A03 |
| D203 | CRITICAL | OS command execution: `os.system`, `os.popen` / process sinks; Java/Kotlin `Runtime.getRuntime().exec(...)` (HIGH; LOW and hidden by default for a fixed command string or array); PHP `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks and `pcntl_exec` with a command that is not request data but not constant either (HIGH; LOW and hidden by default when the command is fixed and every inserted value is a number or an `escapeshellarg()` argument outside quotes) | Python, Java, Kotlin, PHP | CWE-78 / A03 |
| D204 | CRITICAL | Unsafe deserialization: `pickle.load`, `pickle.Unpickler(...).load()` (also through a subclass that does not define `find_class`), `cloudpickle.load`, `pandas.read_pickle` and language equivalents | Python, Java, Kotlin, PHP, audit | CWE-502 / A08 |
| D205 | CRITICAL | Unsafe deserialization: `pickle.loads`, `cloudpickle.loads` | Python | CWE-502 / A08 |
| D206 | HIGH | Unsafe YAML load: `yaml.load`/`load_all` without a data-only loader (`SafeLoader`, `CSafeLoader`, `BaseLoader`, `CBaseLoader`), `yaml.unsafe_load(_all)`, `yaml.full_load(_all)`, ruamel `YAML(typ="unsafe")` | Python | CWE-502 / A08 |
| D207 | MEDIUM | Weak hash: MD5 | Python, TS/JS, Go, Java | CWE-328 |
| D208 | MEDIUM | Weak hash: SHA1 | Python, TS/JS, Go, Java | CWE-328 |
| D209 | HIGH | Shell execution: `subprocess` with `shell=True`, `subprocess.getoutput`/`getstatusoutput`, `asyncio.create_subprocess_shell` | Python | CWE-78 / A03 |
| D210 | HIGH | TLS verification disabled (`requests` `verify=False`, `ssl._create_unverified_context()`, TS/JS `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED=0`, Go `InsecureSkipVerify: true`). Like D346, not reported in test code: Python test modules (`test_*`, `*_test.py`, `conftest.py`, under `tests/` or `test/`), TS/JS test files (`.test.`/`.spec.`, `test`/`tests`/`__tests__` directories), Go `_test.go` files and test-support files (import `testing` and take a `testing.TB`/`*testing.T`) | Python, TS/JS, Go | A02 |
| D211 | CRITICAL | SQL injection | Python, TS/JS, Go, Java, Kotlin, C#, PHP, audit | CWE-89 / A03 |
| D212 | CRITICAL | Command injection. In TS/JS, `X.exec(...)` is a command sink only when the file loads a command-execution module: `child_process`, `node:child_process`, `shelljs`, or remote/container exec (`ssh2`, `node-ssh`, `dockerode`; there `conn`/`connection` are not treated as database handles unless a database driver is also loaded). Without one it is `RegExp.prototype.exec` or another library method; a proven RegExp receiver is never a command sink | Python, TS/JS, Go, Java, Kotlin, C#, PHP, Rust, Ruby (explicit Kernel calls), Dart, Shell, audit | CWE-78 / A03 |
| D215 | HIGH | Path traversal and archive extraction traversal | Python, TS/JS, Go, Java, Kotlin, C#, PHP, Rust, Dart, Shell | CWE-22 / A01 |
| D216 | CRITICAL | Server-side request forgery | Python, TS/JS, Go, Java, Kotlin, C#, PHP, Dart, Shell, audit | CWE-918 / A10 |
| D213 | HIGH | Hugging Face `trust_remote_code=True`: loading the model or dataset imports and runs Python files from its repository. MEDIUM when `revision=` pins a commit SHA or the path is a local directory; a non-literal value is the caller's choice and is not reported | Python | CWE-94, CWE-829 / A08 |
| D217 | CRITICAL | Raw SQL / ORM SQL injection: Django `.objects.raw()`, `QuerySet.extra()` (`select` values, `where`/`tables`/`order_by` entries) and `RawSQL()`, peewee `Model.raw()`. SQLAlchemy `text()` and pandas `read_sql` are reported once, as D211 | Python | CWE-89 / A03 |
| D218 | MEDIUM | Conditional URL scheme audit; unresolved cases are diagnostics | Python | CWE-918 |
| D220 | CRITICAL | SQL injection in added code / diff validation | MCP code-change validator | CWE-89 / A03 |
| D223 | MEDIUM | Undeclared third-party dependency | Python | supply-chain |
| D226 | CRITICAL | XSS: unsafe DOM or HTML rendering (Go: request input converted to an `html/template` safe type such as `template.HTML`; Java/Kotlin: request data written to a servlet response writer (HIGH), Kotlin also Ktor `respondText(..., ContentType.Text.Html)`; C#: request input in `HtmlString`, `Html.Raw` or `MarkupString`, HIGH; PHP: Drupal `Markup::create()` and Blade `{!! !!}` of request data, HIGH) | Python, TS/JS, Go, Java, Kotlin, C#, PHP, audit | CWE-79 / A03 |
| D227 | HIGH | XSS: unsafe template rendering | Python | CWE-79 / A03 |
| D228 | HIGH | XSS: unescaped HTML output (Go: request input written to an HTML HTTP response; PHP: request data printed by `echo`, `print`, `<?= ?>`, `printf`, `die`/`exit`, `print_r`/`var_export`/`var_dump`) | Python, TS/JS, Go, C#, PHP | CWE-79 / A03 |
| D229 | CRITICAL | XPath injection: request data in a `javax.xml.xpath.XPath` `compile`/`evaluate` expression or dom4j `DocumentHelper.createXPath` | Java | CWE-643 / A03 |
| D230 | HIGH | Open redirect (Java/Kotlin: Spring `"redirect:"` views, `RedirectView`, servlet `sendRedirect`; Kotlin also Ktor `respondRedirect`) | Python, TS/JS, Go, Java, Kotlin, C#, audit | CWE-601 / A01 |
| D231 | HIGH | CORS misconfiguration: wildcard origin with credentials; wildcard origin (`CORSMiddleware`, flask-cors) in a module whose app has state-changing routes without an auth guard (reported on the origin setting; HIGH when one of those routes is a SKY-D283 privileged route, MEDIUM otherwise; open means the SKY-D283 test without the action word); a literal `Access-Control-Allow-Origin: *` key in a response dict (any module); a header (dict, subscript or `set`/`add`/`setdefault`, including an f-string) echoing the request's `Origin` without a membership, equality or `fullmatch` allowlist check that guards the header, an early reject or a reset to a fixed origin, or a same-module helper returning such a check. A substring test against a string, a prefix check, an ignored result, the wrong branch, a `fullmatch` pattern with a `.*`/`.+` run, or an allowlist containing `*` or `null` does not count. A wildcard middleware in a module that only serves reads, or whose routes something may authenticate, is not reported | Python | CWE-942 / A05 |
| D232 | CRITICAL | JWT verification disabled or unsafe algorithm | Python | A02 |
| D233 | MEDIUM-CRITICAL | Unsafe deserialization: `marshal.load(s)`, `shelve.open`, `jsonpickle.decode`, `dill.load(s)`, `dill.Unpickler`; Java `XMLDecoder`, XStream `fromXML` with `AnyTypePermission` (HIGH, CRITICAL with request data) or without explicit type permissions (MEDIUM, HIGH with request data: XStream has an allowlist by default from 1.4.18), SnakeYAML `load` without `SafeConstructor` (MEDIUM, HIGH with request data: safe by default from SnakeYAML 2.0), Jackson `enableDefaultTyping` or `activateDefaultTyping` with `LaissezFaireSubTypeValidator`, `@JsonTypeInfo(use = Id.CLASS/MINIMAL_CLASS)` (MEDIUM), Kryo `setRegistrationRequired(false)`; C# `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter` and `ObjectStateFormatter` deserialization (HIGH, CRITICAL with request data), Json.NET `TypeNameHandling` other than `None` (HIGH, MEDIUM with a `SerializationBinder`), `new JavaScriptSerializer(new SimpleTypeResolver())` (HIGH) | Python, Java, Kotlin, C# | CWE-502 / A08 |
| D234 | HIGH | Mass assignment | Python | A01 |
| D235 | HIGH | Remote command execution via `exec_command` | Python | CWE-78 |
| D236 | HIGH-CRITICAL | XML external entity (XXE): an XML parser created and used without disabling DTDs or external entities | Java, Kotlin | CWE-611 / A05 |
| D237 | CRITICAL | Expression, JNDI or script injection: request data evaluated as SpEL, OGNL, MVEL, EL or JEXL, looked up through JNDI, or run by a script engine or Groovy | Java, Kotlin | CWE-917 / CWE-94 / CWE-74 / A03 |
| D238 | HIGH | NoSQL injection: request data as a MongoDB/Mongoose query object or `$where` | TS/JS | CWE-943 / A03 |
| D239 | CRITICAL | LDAP injection: request data in the base DN or filter of a JNDI `DirContext`, Spring `LdapTemplate` or UnboundID `LDAPConnection` search | Java | CWE-90 / A03 |
| D240 | CRITICAL | MCP tool description poisoning | Python | A03 |
| D241 | HIGH | MCP unauthenticated transport | Python | A07 |
| D242 | HIGH | MCP permissive URI / path traversal | Python | A01 |
| D243 | CRITICAL | MCP server bound to `0.0.0.0` | Python | exposure |
| D244 | CRITICAL | MCP hardcoded secrets in tool params | Python | CWE-798 |
| D245 | HIGH | Dynamic `require()` with variable argument | TS/JS | CWE-94 / A03 |
| D246 | HIGH | JWT decode without verification | TS/JS | CWE-347 / A02 |
| D247 | MEDIUM | CORS wildcard origin | TS/JS | CWE-942 / A05 |
| D248 | MEDIUM | Hardcoded internal URL | TS/JS | CWE-798 |
| D250 | MEDIUM | Insecure randomness for security-sensitive values | Python, TS/JS, Go, Java | CWE-330 |
| D251 | HIGH | Sensitive data in logs | Python, TS/JS | CWE-532 |
| D252 | MEDIUM | Insecure cookie flags | TS/JS, Go, Java | CWE-614 |
| D253 | MEDIUM | Timing-unsafe comparison | TS/JS | CWE-208 |
| D254 | HIGH | HTTP session trust boundary violation | Java | CWE-501 |
| D255 | CRITICAL | File inclusion: request data chooses the path of PHP `include`/`require`/`include_once`/`require_once` (reported as D215 before this release) | PHP | CWE-98 / A03 |
| D257 | HIGH | Android WebView JavaScript bridge: `addJavascriptInterface` in a class (or file, for top-level code) that sets `javaScriptEnabled = true` / `setJavaScriptEnabled(true)`; every page the WebView loads can call the bridge's `@JavascriptInterface` methods | Kotlin | CWE-749 / A05 |
| D258 | MEDIUM | Android WebView file URL access: `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` set to `true` (property or setter form), so a `file://` page can read other local files or any origin | Kotlin | CWE-200 / A05 |
| D260 | HIGH-CRITICAL | Prompt injection scanner | Text, config, prompt, and source files | AI supply-chain |
| D261 | HIGH | Untrusted input to LLM prompt | Python | OWASP LLM01 |
| D262 | CRITICAL | Unsafe LLM output handling | Python | OWASP LLM05 |
| D263 | HIGH | Sensitive data sent to LLM | Python | OWASP LLM02 |
| D264 | HIGH | Excessive agent tool privilege | Python | OWASP LLM06 |
| D265 | HIGH-CRITICAL | Unsafe ML model deserialization | Python | OWASP LLM04 |
| D266 | CRITICAL | AI config instruction injection | Agent config and instruction files | OWASP LLM01 |
| D267 | MEDIUM | Unbounded LLM consumption | Python | OWASP LLM10 |
| D270 | MEDIUM | Sensitive data in `localStorage` / `sessionStorage` | TS/JS | CWE-922 |
| D271 | MEDIUM | Error information disclosure in HTTP responses | TS/JS | CWE-209 |
| D280 | HIGH | Next.js mutating API route missing auth checks | TS/JS | A01 |
| D281 | CRITICAL | Untrusted server action input reaching raw SQL text | TS/JS | CWE-89 |
| D282 | HIGH | Webhook handler missing signature verification | Python, TS/JS | CWE-347 |
| D283 | HIGH-CRITICAL | Unauthenticated route that controls a device or the host, deletes data, administers or runs commands (see the SKY-F102 notes) | Python (FastAPI, Flask, Quart, Starlette, Sanic) | CWE-306, CWE-862 / A01 |
| D510 | HIGH | Prototype pollution: request data chooses the key of a nested write or reaches an unguarded recursive merge | TS/JS | CWE-1321 |

For D251, a bare `sessionId` name is not treated as credential evidence by
itself. Explicit authentication-qualified names (such as `authSessionId`) and
direct member expressions with authentication or cookie-qualified paths remain
findings. D270 storage checks are unchanged.

Python D251 follows credential environment reads, credential prompts and
`getpass` results through local containers, assigned object fields, aliases and
string formatting into `print` and logging calls. It requires source evidence;
a variable name alone does not
prove that its value contains a credential. Literal replacements are safe;
unknown helpers named `redact` are not automatically trusted.

D218 requests review of the intended URL schemes because urllib also supports
local-file and other non-HTTP resources. It does not establish attacker control
or an exploitable file read. Explicit literal URLs and proven HTTP/HTTPS prefixes
or dominating scheme guards do not produce this audit. D216 independently checks
whether untrusted input can choose the request host.

For Python D203, `os.system` or `os.popen` with a fixed command string (no
dynamic formatting or Python/shell variables) is LOW: there is no input to
inject. It stays CRITICAL when the fixed command itself deletes broadly,
exfiltrates data, pipes a remote script into a shell, or reads host
credentials. D209 uses the same rule for its shell-string sinks.

Python D212 reports untrusted data reaching a shell command string
(`os.system`, `os.popen`, `subprocess.getoutput`/`getstatusoutput`,
`asyncio.create_subprocess_shell`, `subprocess.*` with `shell=True`), the
program of `os.exec*`, `os.spawn*`, `os.posix_spawn*` and `pty.spawn`, and
the script after `-c` when the program is a shell (`["bash", "-c", script]`,
`os.execl("/bin/sh", "sh", "-c", script)`). Import aliases are resolved
(`import subprocess as sp`, `from os import system`); a local function with
the same name is not a sink. A `shell=` value that is not a literal `False`,
`None` or `0` may enable the shell, so a tainted command is reported there
too. An untrusted argument to a fixed program (`["git", "fetch", ref]`) is not
command injection and is not reported. `shlex.quote`/`shlex.join` clear taint.

Python D201/D202, D205 and command-call rules also follow captured function
values within the module's bounded flow analysis. Capturing `pickle.loads`,
the builtin `eval`, or `subprocess.run` retains that callable's identity even
if its original module name is later rebound. A known data-only replacement
or source-owned function with the same name does not retain the obsolete
library identity. Unknown bindings keep the existing conservative warnings;
this does not add arbitrary cross-file callable tracing.

Python D205 suppresses only proven local `pickle.dumps` / `pickle.loads`
round-trips over built-in data. Unknown objects can define reduction hooks;
attributes and cross-function state therefore remain review candidates. The
warning describes pickle's execution capability without asserting that an
unknown input is definitely attacker-controlled.

Python D206 trusts a loader only when it is a data-only PyYAML loader. A name
such as `SafeLoader` counts only if the module never rebinds it to something
else (`SafeLoader = yaml.UnsafeLoader` is still reported); an assignment of
`yaml.SafeLoader` or `getattr(yaml, "CSafeLoader", yaml.SafeLoader)` is safe.

Python D204 treats a module class that subclasses `pickle.Unpickler` without
defining `find_class` like `pickle.Unpickler`; a subclass that overrides
`find_class` follows the documented way to restrict loadable globals and is
not reported.

Python D230 preserves tainted redirect targets across conditional assignments.
An unrelated `urlparse` check or a leading slash alone does not prove safety.
An enforced literal destination allowlist or an unconditional internal route
assignment remains safe. Django's `url_has_allowed_host_and_scheme(url, ...)`
(or `is_safe_url`), imported from `django.utils.http`, clears the checked name
on the branch where it returned true; a redirect on the failing branch, after
the result is ignored, of a different value, or through a local function with
the same name is still reported. `redirect` and
`HttpResponseRedirect`/`HttpResponsePermanentRedirect` with a positional target
keep the rule above: any tainted target, including a plain function parameter.

The other sinks need request data proven to reach the target: Starlette/FastAPI
`RedirectResponse`, aiohttp/Pyramid `HTTPFound`, `HTTPSeeOther`,
`HTTPMovedPermanently`, `HTTPTemporaryRedirect`, `HTTPPermanentRedirect`, the
legacy sinks given only a keyword target (`to`/`redirect_to`/`location`/`url`),
and a `Location` header set on `.headers[...]`, a response built in the same
function, a `headers={"Location": ...}` argument of a `*Response` call, or
`.headers.set/add(...)` (a response class setting its own `self.headers`
defines a sink and is not reported). Request data is a read from the request,
a route parameter or a Tornado argument. It flows through locals, f-strings,
`%`, string methods, `str()`, `urljoin` and other `urllib.parse` helpers, and
functions defined in the same file. A call into another module (a project
helper such as `get_next_url(request)`) or any other library ends the flow.
Request data appended after a value (`url += "&q=" + q`) does not choose the
target, as with CodeQL's string-concatenation sanitizer; after a literal that
does not fix the origin (`"https://" + host`) it does. The root path's query
or fragment (`f"/?next={target}"`, `"/#" + target`) and the absolute URL of the
request being served (Flask/Quart `request.url`/`base_url`/`url_root`/
`host_url`, the same attributes of a parameter annotated as a
Starlette/FastAPI `Request`, Starlette `URL(scope=...)`, also after
`.replace(...)` with values that carry no request data) keep the origin. A
bare path such as `request.url.path` is still request data (`//evil.example`
is a path).

Proven Tornado `RequestHandler` argument reads also count as redirect sources,
including values assigned with `:=`. Local overrides and unrelated methods with
the same name do not establish a request source. A fixed local path segment
such as `"/entry/" + slug` cannot change the redirect origin; `"/" + target`
alone is insufficient.

For Python D207/D208, `hashlib.md5` / `hashlib.sha1` remain findings when
their purpose is unclear; names such as `cache_key` do not prove the digest
is unrelated to security. An explicit `usedforsecurity=False` suppresses the
finding.

For Python D211, a query executed on a chained connection or cursor call
(`sqlite3.connect(...).execute(q)`, `conn.cursor().execute(q)`,
`engine.connect().execute(q)`, `get_db().executescript(q)`) is reported only
when `q` carries data from a real untrusted source: a web-route, CLI or MCP
tool parameter, `request.*`, `input()`, `sys.argv`, `sys.stdin` or the
environment. On any receiver, bound parameters, `text("... :id")` over a
constant (also with `.bindparams(...)`), SQLAlchemy/SQLModel
`select`/`insert`/`update`/`delete` constructs, and statements built from a
locally proven SQLAlchemy Table object (`notes.insert().values(...)`,
`notes.delete().where(...)`) are not findings. Neither is query text built only
from string literals and numbers: a placeholder run such as
`",".join("?" * len(ids))` or `", ".join(["%s"] * len(rows))`, `int()`,
`float()` and `len()` values, or a name bound to such text in the same scope
(not one rebound in a branch or by a closure's enclosing function). A call
counts as the builtin only when that name resolves to the builtin under
Python's scoping rules: not when a local, enclosing function or module binding
shadows it, after a star import, or when the module writes to `builtins`
(directly or through an alias), `globals()` or `setattr`.
`executescript()` takes no parameters, so only a tainted or string-built
script is reported there. A Table constructor must resolve
to an unshadowed SQLAlchemy import; unresolved application imports and
function parameters retain findings. A construct with a string-built clause
(`.where(f"id = {x}")`) or a raw `request.*` value as a clause is still a
finding. Formatted values passed to `.values(...)` remain bound parameters.
A tainted `text()` inside `execute()` is reported once, on the
`text()` call. On a SQLite or DuckDB connection (`sqlite3.connect()`,
`duckdb.connect()` or its `.cursor()`, bound in the same scope), a `str` whose
single quotes were doubled (`str(v).replace("'", "''")`) placed inside a plain
single-quoted literal is not a finding: those engines do not treat a backslash
as an escape. On other or unknown connections (MySQL and PostgreSQL can),
outside a literal, inside a quoted identifier, after a prefix such as `E'`,
with a `!r` conversion or next to a comment marker it still is.

Python D211 and D230 require an identified input source before a completed
project analysis presents a security claim. Unresolved candidates remain in
JSON `suppressed` with `sql_provenance` or `redirect_provenance` marked
`unknown` and `safety_proven: false`. They do not fail a security gate. A
truncated or changed source index keeps candidates visible as incomplete;
it never proves safety. D218 is a conditional scheme audit and remains an
unknown diagnostic; D216 still reports source-backed SSRF separately.
Operator-owned CLI/environment redirect targets do not establish remote input.

Python D251 follows proven credential inputs into print/logging. Native HTTP
response bodies and verified payloads do not inherit the signing key or
request credential merely because it was supplied to the API. Request URLs,
request headers, response history, whole response objects, unknown transforms
and project wrappers retain credential evidence.

For Python D215, Starlette/FastAPI `FileResponse` and Flask/Werkzeug
`send_file` are path sinks. `send_from_directory` is a sink only for its
`directory` argument, because it joins `path` with `safe_join`. Accepted guards: a
resolved path (`resolve()`, `realpath`, `abspath`, `normpath`) checked with
`is_relative_to`, `relative_to`, `startswith` or `commonpath` before a
rejecting branch; a membership check against a constant allowlist;
`safe_join`; and `basename`. A prefix check on an unnormalized path does not
count as a guard.

Python D215, D324 and D325 check tainted paths from web routes, MCP/agent
tools, request data and standard input. A path built from a helper's
parameter is followed through the scanned source (imports, assignments,
calls, returns, constructor and dataclass bindings, aliases,
`functools.partial`, executors, lambdas, containers and their local aliases,
JSON/YAML decoding, Celery `delay`/`apply_async` and RQ `enqueue` arguments)
to every caller that can be resolved. It is reported when a resolved chain
starts at request data, a route or MCP tool argument, a Django class-based
view registered by a URL pattern or DRF router, a FastAPI `Depends`
dependency of a resolved route, a function a deployment file names as a
server or handler, standard input, a CGI request variable, a network response,
asyncio stream or `recv_into` buffer, a downloaded file's content or an
archive member name; `metadata.path_provenance` lists the steps. A parameter
named `request`/`req` counts as request data only in a module that imports a
web framework, and a `@<group>.command` decorator counts as a CLI when the
group resolves to Click/Typer or the function has Click/Typer parameter
decorators; findings resting on these conventions or on no source at all are
traced the same way. When a caller budget, depth limit, file size budget or
analysis error cuts a chain off, the finding stays reported as `incomplete`.
Otherwise it moves to `suppressed` as `safe` (complete scan, no hidden caller,
and every caller passes literals, the module's location, clock or numeric
values, temporary paths, test values or operator input) or `unknown` (a
caller, receiver, callback, decorator, external base class or public package
API that cannot be resolved); unknown is neither proof of an attack nor of
safety. A path whose only proven source is the program operator (a CLI
argument or environment variable) is suppressed, unless a project process
launch passes untrusted arguments. An exclusive create (`open(p, "x")`,
`os.open` with the `os` module's `O_CREAT | O_EXCL`) cannot follow a final
symlink, so D324/D325 skip it while D215 still checks it. D326 needs an
`extract` call that can pass a member (BeautifulSoup's `tag.extract()`
cannot) and reports `shutil.unpack_archive` without `filter="data"`. Test
files are scanned too; the literal pytest parameter proof below still applies.

Python D211, D215, D217, D324 and D325 findings reached by such a source carry
`metadata.security_evidence` (`source`, `sink`, `path`), which SARIF output
renders as `codeFlows`.

Python D211 also checks the query argument of asyncpg `fetch`/`fetchrow`/
`fetchval`, `databases` `fetch_all`/`fetch_one`/`fetch_val` and peewee
`execute_sql` on a database-like or pool receiver. These need data from a
parameter or another untrusted source in the query text: SQL built only from
the module's own values (identifiers it quotes, counts, rows of a constant
table) is not reported there. Because HTTP and cache clients share these
names, a string-built query must also read as SQL, and a plain tainted query
counts only in a module that imports asyncpg, `databases` or peewee. A
SQLAlchemy `text()` or pandas `read_sql` call is reported once, as D211 (no
second D217 finding).

On every D211 sink, a quoted identifier may fill the query text where no
quoted literal is open: psycopg2 `quote_ident`, or a function in the same
module whose whole body returns its argument wrapped in `"` with every `"`
doubled. A psycopg `sql.SQL("...")` literal composed with `sql.Identifier`,
`sql.Literal` or `sql.Placeholder` is also safe. Calling the quoting function
without using its result, quoting a value placed inside `'...'`, or a lookalike
helper that does not double `"` is still reported. Numeric values do not carry
SQL: `int()`, `float()`, `len()`, `round()`, `abs()`, `bool()`,
`random.randint/randrange/getrandbits` and `math.floor/ceil/trunc/isqrt`.

Python D215 treats `werkzeug.utils.secure_filename(...)` (imported from
werkzeug, not a local function of that name) as a sanitizer for its return
value; calling it and then using the raw filename is still reported.

Every Python security finding carries its rule's CWE ids in `cwe`
(`[{"id": "CWE-89", "name": ...}]`), which SARIF output turns into rule
relationships, `external/cwe/...` tags and CWE taxa.

Python D216 reads the URL from the `url=` keyword, the first argument of a
verb method (`get(url)`), or the second argument of `request(method, url)`
(requests, httpx, aiohttp, urllib3 `PoolManager`), also on a client created in
the same expression (`urllib3.PoolManager().request(...)`). An untrusted HTTP
method with a fixed URL is not SSRF, and `http.client` connections, whose host
is fixed by the constructor, are not checked through `request(method, path)`.
Python D216 needs a real untrusted source (route, CLI or MCP-tool argument,
request data, `input()`, stdin) that can choose the request host. Not SSRF:
calls through in-process test clients (Django `Client`/`RequestFactory`, DRF
`APIClient`, Flask `test_client()`, Starlette/FastAPI `TestClient`,
pytest-django `client` fixtures in `test*` functions of test files that have no
route decorator, `self.client` in Django test cases; a client name counts only when every
binding it resolves to, in the current function, an enclosing function or the
module, creates a test client, and a binding in a nested function or class does
not count; `self.client` or another `self` attribute counts only in a Django/DRF
test-case class whose bases are all known test cases or same-module classes,
when every write to that attribute that can reach the instance creates a test
client and the module never rewrites it through `setattr`, `__dict__`, `vars()`,
a `client_class` assignment or a `_pre_setup` override; a test-client class name
the module rebinds is not trusted); parameters of a function
decorated with `unittest.mock.patch` (it is not a PATCH route); methods of a
receiver proven to be an SQLAlchemy/SQLModel session (`session.get(Item, id)`,
`session.delete(item)`: the parameter is annotated with an ORM `Session`/
`AsyncSession`, directly, through `Annotated[...]` or a same-module alias, or
with an annotation another function in the module uses as one; it is bound
from `Session(engine)`, a `sessionmaker()` factory or Flask-SQLAlchemy's
`db.session`; or the same receiver also calls `commit`, `add`, `flush`,
`refresh`, `rollback`, `exec`, `execute`, `scalars` or `query`, which HTTP
clients do not have; a receiver bound from `requests`/`httpx`/`aiohttp` stays
an HTTP client); and URLs whose
host is fixed by a literal or by a module-level setting followed by `/`, `?` or
`#` (not `//`), written directly or returned by every path of a same-module
helper that has no decorator other than `functools.cache`/`lru_cache`. A setting
counts only when its value is a literal `scheme://host` URL, an environment
variable (`os.getenv`/`os.environ`, resolved through the module's imports) or
CLI argument (`sys.argv`) with a literal name and either no fallback, a `None`
fallback or such a literal, another such setting, or a name imported from
another module; `"https:"`, `"https://"` and `""` do not fix the host. A name imported from
a web-framework or request-scoped module (`flask`, `werkzeug`, `quart`,
`starlette`, `fastapi`, `django.http`, `django.contrib.sessions`,
`django.core.handlers`, `rest_framework.request`, `aiohttp.web*`, `tornado.web`,
`sanic`, `bottle`, `falcon`, `pyramid.request`, `litestar`, `contextvars`, or any
of their submodules) is never a setting. A setting
or helper name does not count where the current or an enclosing function shadows
it (parameter, assignment, `for`/`with`/`except` target, comprehension variable,
lambda argument, import, nested definition, `global`/`nonlocal`), nor when the
module rebinds it (a second binding, assignment under `global`,
`setattr(module, "NAME", ...)`, `module.NAME = ...`). A module that can rewrite its
globals at run time has no fixed settings: a star import, `exec`/`eval`,
`reload`, a write through `globals()`/`vars()`/`builtins.globals()` or a
module-level `locals()`, any use of `__globals__`, `f_globals` or a module
`__dict__`, `sys._getframe`, `globals` used other than as a call, `setattr` on
the module with a computed name, a dunder attribute of the module object or
`sys.modules` (`__setattr__`, `__getitem__`, `__dict__`), `getattr(x,
"__dict__")`-style lookups of those names, a module obtained through
`import_module`/`__import__`/`inspect.getmodule` under any name or
`import __main__`, or the module object passed to other code. Only the setting's own module is checked: an
assignment from another module (`import app; app.BASE = ...`) is not seen, and a
setting imported from another module is trusted as is. A fixed-host URL that carries request data in its
query (`f"{RENDERER}/render?url={...}"`) is not reported. `urllib.parse.quote`
with a `safe=` argument is not a URL sanitizer.

TS/JS D216 (`fetch`, `axios`) reads a URL through names that can only hold
one value: a `const`, or a `let`/`var` that is the name's only binding, found
by lexical scope (also inside template substitutions and `+` chains). A URL
built only from literals and such names (conditionals included when every
branch is), or one whose literal `scheme://host/` prefix fixes the host, is not
reported; a bound call, member, `||`/`??` or `new URL(...)` value is dynamic. A name assigned anywhere in the file, shadowed
by a parameter, loop or `catch` variable, destructured, imported, hoisted by a
`var` next to other bindings, or in a file using `eval`/`with` is not resolved.

TS/JS request taint (D211, D212, D215, D216, D228, D230, D238, D510) follows
request data inside one handler of one file. Handlers: Express, Fastify, Hapi
and Next.js pages-API functions (`(req, res)`, `(request, reply)`,
`(request, h)`, or a first parameter typed `Request`, `FastifyRequest`,
`NextApiRequest`, `NextRequest`; a function whose only parameter is an untyped
or `any` `req`/`request` is read only through `query`, `body`, `params`,
`headers`, `cookies` and `get()`/`header()`/`param()`, so a helper's
`req.path` or `request.url` is not request data), Koa and `getServerSideProps` functions (first
parameter `ctx`/`context`), NestJS methods with `@Body()`, `@Query()`,
`@Param()`, `@Headers()`, `@HostParam()`, `@UploadedFile()` or `@Req()`
parameters (routing-controllers equivalents too), exported `GET`/`POST`/...
functions in a Next.js App Router `route` file, and exported Remix
`loader`/`action` functions. Sources: `req.body/query/params/headers/cookies/
files/url/originalUrl/path/hostname`, `req.get()/header()/param()`, Hapi
`payload`/`state`, Koa `ctx.request.body`, `ctx.query`, `ctx.params`,
`ctx.headers`, `ctx.cookies.get()`, Next.js `await request.json()/formData()/
text()`, `request.nextUrl.searchParams.get()`, `request.headers`, and the route
`params` argument. A NestJS parameter piped through `ParseIntPipe`,
`ParseFloatPipe`, `ParseBoolPipe`, `ParseUUIDPipe` or `ParseEnumPipe` is not a
source; a TypeScript annotation such as `id: number` is not proof. Sinks:
SQL text in `query`/`execute`/`raw`/`prepare`/`all`/`get`/`run` calls whose
literal text is SQL, `$queryRawUnsafe`, knex `whereRaw`-style calls and
TypeORM query-builder `where`/`orderBy` conditions (D211, CRITICAL);
`child_process.exec` (D212, CRITICAL); `fs`/`fs/promises`/`fs-extra` paths
and `res.sendFile`/`download` without `root` (D215, HIGH); the URL or
`host`/`url` option of `fetch`, axios (also `axios.create()` instances and
NestJS `HttpService`), got, undici, superagent, needle, request and
`http(s).get/request` (D216, HIGH); Express `res.send(text)` (Express answers
strings as `text/html`) and HTML literals sent with `res.send/write/end`, and
Koa `ctx.body` text that can start with request data or `<` (D228, HIGH);
`res.redirect(url)`, `res.redirect(302, url)`, `ctx.redirect`,
`reply.redirect`, `h.redirect`, `NextResponse.redirect`, `Response.redirect`,
`redirect()` from `next/navigation` or Remix, `res.location` and `Location`
headers (D230, HIGH); MongoDB/Mongoose filters (D238, HIGH); nested writes and
same-file recursive merges (D510, HIGH). Taint follows local bindings in
source order (a plain reassignment in the same block replaces the old value;
one inside a branch adds to it), destructuring, `+`, templates, string
methods, `||`/`??`, ternaries, `path.join/resolve/normalize`, `new URL`,
`JSON.parse` (an object), `Object.keys/values/entries/assign`, `qs.parse`,
same-file helper functions and methods of same-file `const` objects. Calls into
other modules stop taint, so a validator such as zod `.parse()`,
`mongo-sanitize` or `escape-html` ends it, and so does any unmodelled library
call. Sanitizers are proved, never named: `Number`/`parseInt`/`parseFloat`/
`Boolean` (global, not rebound), `path.basename` with `path` imported from
`path`, `encodeURIComponent` (XSS, path, command, redirect, SSRF), and a
same-file helper whose result replaces `<` with `&lt;` globally (a later
replace that writes `<` back cancels it); a local function named `escapeHtml`,
`quote` or `basename` that returns its input is followed, not trusted. Guards
count only when the failing branch returns, throws, breaks or continues before
the sink (or the sink sits inside the passing branch), and only for the value
that reaches the sink, unless it is reassigned after the guard: a
`startsWith(root)` check on a `path.resolve`/`normalize`/`join` result,
`path.relative(root, p).startsWith('..')`, or rejecting `..` when the value is
joined under a prefix and not `path.resolve`d (D215); an allowlist of string
literals (`['a.com'].includes(u.hostname)`, `new Set([...]).has()`, `===`)
on the hostname, host or origin of the URL, or a `startsWith` with a fixed
`scheme://host/` (D216, D230); `startsWith('/')` together with a `//` check, or
a literal allowlist (D230); `typeof x === 'string'` or an ObjectId check
(D238); an anchored character-class regex such as `/^[a-z_]+$/.test(x)`
without the `m` flag (any rule). An allowlist read from the environment, a
mutated array, or a check that only logs is not a guard. A literal
`scheme://host/` or relative-path prefix (`/users/` + id, not `/` alone) keeps
D216 and D230 quiet; `new URL('/path', request.url)` stays on the site.

TS/JS D238 (NoSQL injection, CWE-943) needs a file that imports `mongoose`,
`mongodb`, `@nestjs/mongoose`, `@typegoose/typegoose`, `mongojs` or `monk`.
It reports a `find`, `findOne`, `findOneAndUpdate/Delete/Replace`,
`updateOne/Many`, `deleteOne/Many`, `replaceOne`, `countDocuments`, `exists`,
`where`, `distinct` (its filter) or `aggregate` `$match` filter that is the
request object itself (`find(req.body)`, `find(filter)` with
`filter = req.query`) or holds a request value that can be an object (`{
password: req.body.password }`, a spread of `req.body`), and any `$where` built
from request data. Objects come from Express `req.body`, `req.query` (the `qs`
parser) and `req.cookies` (JSON cookies), Fastify/Hapi/Next bodies,
`request.json()`, `JSON.parse` and `qs.parse`; route params, headers,
`searchParams.get()`, Koa/Fastify/Next query strings, `String(x)`, templates
and `.toString()` are text and are not reported. A NestJS `@Body()` typed with a
DTO class counts as validated text (Skylos assumes the usual global
`ValidationPipe`, which it cannot see from the controller file); an untyped,
`any`, inline-object or primitive-typed parameter is not. Option objects with a
`where`/`select`/`include` key (Sequelize, TypeORM, Prisma) are not Mongo
filters. `app.use(mongoSanitize())` from `express-mongo-sanitize` or
`sanitizeFilter: true` in the same file clears the file.

TS/JS D212 also checks `spawn`, `spawnSync`, `execFile` and `execFileSync`
from Node's `child_process` modules when their effective `shell` option is
literal `true` or a nonempty shell path. Request data in either the command
or its arguments can then become shell syntax. Import aliases, captured
callables and source-visible option objects are resolved, including spread
property order and visible reassignment. Fixed commands and separate arguments
with the shell absent or disabled stay quiet for this rule. Arbitrary
executable argument injection, unknown dynamic options and cross-file wrappers
are not general supported proofs.

For TS/JS D230, an intact operator environment lookup with a fixed key,
literal suffix or default, including a proven `const` alias, is not HTTP
request input. Request-dependent keys/suffixes, visible provider replacement,
environment writes or exposed aliases do not qualify for that proof. This
does not certify operator configuration itself or trace arbitrary writes
across files.

TS/JS D510 reports `obj[a][b] = v` when request data chooses `a` (`a =
'__proto__'` makes the write change `Object.prototype`), unless a dominating
guard rejects `'__proto__'`, allowlists `a`, checks `hasOwnProperty`, or the
base is `Object.create(null)`/a `Map`; and a call that passes request data to a
same-file function that copies keys recursively (`for (k in src)` with
`dst[k] = ...` and a recursive call) without a `'__proto__'`/`'constructor'`
check, `hasOwnProperty` or `Object.create(null)`. Reading `__proto__` is not
reported, and neither is a single-level `obj[key] = value`. Library merges
(lodash `merge`/`defaultsDeep`/`set`) are not reported: current releases
reject `__proto__`.

TS/JS D226 also covers `insertAdjacentHTML`, `document.writeln`,
`createContextualFragment`, `setHTMLUnsafe`, `innerHTML`/`outerHTML +=`,
jQuery `.html(x)` and `.append/.prepend/.after/.before/.replaceWith/.wrap*`
of a template or `+` string that contains markup, on a `$(...)`/`jQuery(...)`
chain or a `$name` variable. `dangerouslySetInnerHTML={{ __html: x }}`, like
`innerHTML`, is quiet only for inert literal markup or an import-proven
DOMPurify/`isomorphic-dompurify`/`sanitize-html` call (directly or through a
`const`); a sanitizer imported from a local `./dompurify` file, or a sanitized
copy that is never rendered, does not count. DOM `element.append(text)` inserts
text and is not reported.

TS/JS D327 reports a POST, PUT or PATCH (`fetch` with a literal `method`,
`axios.post/put/patch`, `axios({method, url, data})`, `axios.request`) whose
body carries `process.env` data to a URL that is not local (like Python, which
checks `data`/`json`). Environment values in headers, such as
`Authorization: Bearer ${process.env.TOKEN}`, are how an API key reaches its
own API and are not reported; neither is `process.env` used as the URL, or
only `NEXT_PUBLIC_` names.

Java security findings (`--danger`) come from an intra-procedural taint engine. Request data is: servlet `HttpServletRequest` getters (parameters, headers, cookies, query string, path info, `getInputStream`/`getReader`/`getPart(s)`); Spring parameters annotated `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@RequestBody`, `@RequestPart`, `@ModelAttribute` or `@MatrixVariable`; JAX-RS `@QueryParam`, `@PathParam`, `@FormParam`, `@HeaderParam`, `@CookieParam`, `@MatrixParam` and `@BeanParam`; `MultipartFile`/`Part` parameters; Spring `WebUtils.getCookie(request, ...)`-style accessors; same-file or imported helpers, including static `Util.read(request)` calls, that return request data; and, as in CodeQL, every other parameter of a `@*Mapping` method in a `@Controller`/`@RestController` class or of a JAX-RS `@GET`/`@POST`/... method, except framework objects (`Model`, `BindingResult`, `Principal`, `HttpSession`, `Pageable`, `Locale`, `@AuthenticationPrincipal`, `@Context`, ...). Primitive, boxed-number, boolean, `UUID` and date parameters never carry injection text. Getters on a request-bound object (a `@RequestBody` DTO) return request data. Sinks with an ambiguous name need the receiver's type (a local, parameter or field declaration, or a known factory call): SQL `execute`/`query`/`update`/`batchUpdate`/`createQuery` need a JDBC `Statement`/`Connection`, `JdbcTemplate`, `NamedParameterJdbcTemplate`, JPA `EntityManager` or Hibernate `Session`; LDAP `search` needs `DirContext` (SKY-D239) and is not reported for values escaped by `LdapEncoder.filterEncode`/`nameEncode`, `Rdn.escapeValue`, UnboundID `Filter.encodeValue`/`createEqualityFilter`, Spring LDAP filter objects other than `HardcodedFilter`, `LdapQueryBuilder.query().where(...).is(...)`, or passed as `{0}` filter arguments, XPath `compile`/`evaluate` needs `XPath` (SKY-D229), so `Pattern.compile(input)` and `service.search(input)` are not reported; D237 `lookup` needs a JNDI `Context`, `JndiTemplate` or `LdapTemplate`; SpEL `parseExpression` is not reported when every evaluation of the result passes a `SimpleEvaluationContext` (CodeQL's barrier). Until this release Java reported LDAP and XPath injection as SKY-D240 and SKY-D241, which are MCP rules. D216 and D230 use CodeQL's fixed-host barrier: input after a constant prefix that already chooses the host (`"https://api.example.com/users/" + id`, `"redirect:/owners/" + id`, anything after `?` or `#`) is not reported, while `"redirect:" + next` and `"redirect:/" + next` are. Spring `return "redirect:" + x`, `new ModelAndView("redirect:" + x)`, `new RedirectView(x)`, `ResponseEntity...location(...)`, `HttpHeaders.setLocation`, a `Location` header and JAX-RS `Response.seeOther`/`temporaryRedirect` are D230 sinks. D216 also covers WebClient/RestClient `uri`/`baseUrl`/`create` (not URI templates or builder lambdas), OkHttp `Request.Builder.url`, Apache HttpClient request constructors and `Jsoup.connect`. D236 (XXE) follows CodeQL's per-parser rules on the same factory variable, in statement order: `DocumentBuilderFactory` is safe with `disallow-doctype-decl` true, both external entity features false, or `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` set to `""`; SAX, `XMLReader`, Commons `Digester`, JDOM `SAXBuilder` and dom4j `SAXReader` need `disallow-doctype-decl` true or both entity features plus `load-external-dtd` false (SAX, `XMLReader` and JDOM also accept the `ACCESS_EXTERNAL_*` pair); StAX needs `SUPPORT_DTD` or `IS_SUPPORTING_EXTERNAL_ENTITIES` false (FindSecBugs); `TransformerFactory` needs `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_STYLESHEET` set to `""`; `SchemaFactory` needs `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` set to `""`. `FEATURE_SECURE_PROCESSING` alone does not count, a setting applied after `newDocumentBuilder()` does not protect that builder, and hardening in only one branch does not count. A factory passed to a helper in the same file takes that helper's settings; one passed elsewhere, or given a custom entity resolver, is not judged. DOM serialization (`transform(new DOMSource(...))`), `newDocument()` and parsing a classpath resource or literal path are not reported. D236 is CRITICAL when request data is parsed, HIGH otherwise; dom4j `DocumentHelper.parseText` (a plain `SAXReader` before dom4j 2.1.3, `SAXReader.createDefault()` since) is MEDIUM, HIGH with request data, and `SAXReader.createDefault()` counts as hardened. D204 (`ObjectInputStream`) is CRITICAL for request or socket input, HIGH for an unproven source and MEDIUM with an `ObjectInputFilter` (`setObjectInputFilter`, `ObjectInputFilter.Config.setSerialFilter`) or a `resolveClass` override.

C# security findings (`--danger`) come from a lexical taint scan of each method, with one level of same-file call flow. Request data is: parameters of public, non-static, non-override actions of a controller (a class with `[ApiController]`/`[Controller]`, a base named `Controller`, `ControllerBase`, `ApiController` or ending in `Controller`/`ControllerBase`, also through a class in the same file, or a public class whose own name ends in `Controller` and whose bases are only interfaces or controller-named types, so a Unity `PlayerController : MonoBehaviour` is not one; never `[NonController]` or `[NonAction]`); Razor Page `On*` handler parameters and `[BindProperty]`/`[BindProperties]` properties; SignalR `Hub` methods; Blazor `[SupplyParameterFromQuery]`/`[SupplyParameterFromForm]` properties; minimal API handlers (`MapGet`/`MapPost`/`MapPut`/`MapDelete`/`MapPatch`/`MapMethods`/`MapFallback` lambdas and same-file method groups); any parameter marked `[FromQuery]`, `[FromBody]`, `[FromRoute]`, `[FromForm]`, `[FromHeader]`, `[AsParameters]` or Azure Functions `[HttpTrigger]`; and `Query`, `Form`, `Headers`, `Cookies`, `Body`, `RouteValues`, `Path`, `QueryString`, `Params`, `RawUrl`, `Url`, `Files`, `InputStream` or `[...]` on `Request`, `HttpContext.Request` or a parameter typed `HttpRequest`/`HttpRequestData`/`HttpRequestBase`. Command-line `args[...]`, `Console.ReadLine()` and `Environment.GetEnvironmentVariable(...)` also count. Constructor parameters (dependency injection), `[FromServices]`/`[FromKeyedServices]` parameters, framework and service types (`CancellationToken`, `HttpContext`, `ILogger<T>`, interfaces other than `IFormFile` and collections, `HttpClient`, `*Service`, `*Repository`, `*DbContext`), scalar values (numbers, `bool`, `Guid`, dates, and `int.Parse`/`Convert.ToInt32` results) and plain helper or service parameters are not request data. A method in the same file that is called with request data (unqualified, `this.`, `Type.Method`, or through a field, local or parameter whose declared type is a class in that file) is checked with those parameters as request data. Sinks whose names ordinary methods share need the receiver's declared type: D216 `GetAsync`/`PostAsync`/`PutAsync`/`PatchAsync`/`DeleteAsync`/`GetStringAsync`/`GetStreamAsync`/`GetByteArrayAsync`/`GetFromJsonAsync`/`PostAsJsonAsync` count only on an `HttpClient` (field, property, parameter, local, `new HttpClient()` or `IHttpClientFactory.CreateClient()`), as do `WebClient` `Download*`/`Upload*`/`OpenRead`; `WebRequest.Create(Http)`, `new HttpRequestMessage(method, url)`, `.BaseAddress =` and RestSharp `new RestClient/RestClientOptions/RestRequest(url)` are sinks too. A repository's `GetAsync(id)` is therefore not SSRF, while an `HttpClient` field named `_repo` is. D211 is CRITICAL with request data in `SqlCommand`-family and `*DataAdapter` constructors, `.CommandText =`, EF `FromSqlRaw`/`ExecuteSqlRaw(Async)`/`SqlQueryRaw`, EF6 or EF Core 2 string `SqlQuery`/`ExecuteSqlCommand`/`FromSql`, and Dapper `Query*`/`Execute*` on an `IDbConnection`-typed receiver; `FromSqlInterpolated`, `ExecuteSqlInterpolated`, an interpolated string passed straight to EF Core `FromSql`/`SqlQuery`/`ExecuteSql`, and values passed as parameters are safe. SQL text built by concatenation, interpolation, `string.Format` or `StringBuilder` from a non-scalar method parameter with no proven request source is D211 HIGH (as in Java and Roslyn CA2100); a parameter that is only an argument of another call (`ClauseFor(option)`, `Encode(password)`) does not count. D212 (CRITICAL) covers `Process.Start`, `new ProcessStartInfo` and `FileName`/`Arguments` of a `ProcessStartInfo` or `.StartInfo`. D215 covers `File.*`, `Directory.*`, `new FileStream/FileInfo/DirectoryInfo`, `new StreamReader/StreamWriter` with a path (not a stream) and `PhysicalFile`; `Path.GetFileName(x)` as the last `Path.Combine` part is contained under a fixed or configured directory, but not under `/`, `.`, the working directory or the content root alone. D230 covers `Redirect`, `RedirectPermanent`, `RedirectPreserveMethod`, `Response.Redirect`, `Results.Redirect`, `new RedirectResult` and the `Location` header. `LocalRedirect*`, `Results.LocalRedirect` and `RedirectToAction`/`RedirectToRoute`/`RedirectToPage` are not reported, nor is a redirect of a variable on a path where the framework `Url.IsLocalUrl(x)` (the controller or page `Url`, `this.Url`, or an `IUrlHelper`/`UrlHelper` receiver) returned true: inside `if (Url.IsLocalUrl(x))` (also `== true`, `is true`, an `&&` conjunct or a ternary), or after `if (!Url.IsLocalUrl(x))` (also `== false`, `is false`, or an `||` disjunct) whose branch returns or throws on every path, up to the end of that block or switch section. A check of another variable, inside an `||` condition, a negated check whose branch can fall through, an `else if` or a nested `if` without braces, and an `IsLocalUrl` helper of the controller or another type do not count. C# D216 and D230 use the fixed-host barrier described for Java. D233: `Deserialize`/`UnsafeDeserialize`/`ReadObject` on `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter` or `ObjectStateFormatter` (CRITICAL with request data, HIGH otherwise; Roslyn CA2300-CA2315), Json.NET `TypeNameHandling` other than `None` (HIGH, MEDIUM when a `SerializationBinder` is set in the same initializer or block; CA2326-CA2330), and `new JavaScriptSerializer(new SimpleTypeResolver())` (HIGH; CA2321). D226 (HIGH) reports request data in `new HtmlString(...)`, `Html.Raw(...)`, `new MarkupString(...)` or a `(MarkupString)` cast; `HtmlEncoder`/`WebUtility`/`HttpUtility` encoding and HTML sanitizers clear it. D228 (HIGH) reports request data in `Content(x, "text/html")`, `Results.Content(x, "text/html")` or `Response.Write(x)` unless every path to the write last set the response content type to a literal other than HTML. Every C# security finding carries its CWE. `.cshtml` and `.razor` markup is not read, and flow across files is not followed.

PHP security findings (`--danger`) come from an intra-procedural, flow-sensitive taint engine (one function or file; branches, loops, `switch`, `try`, early `return`/`exit`/`die`). Request data is: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`; `$_FILES[...]['name'|'type'|'full_path']` (not `tmp_name`, `size` or `error`); the `$_SERVER` keys the client sends (Psalm's list: `HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`, `PATH_INFO`, `REQUEST_METHOD`, `CONTENT_TYPE`, `PHP_AUTH_*`, ... and any non-literal key; not `REQUEST_TIME`, `REMOTE_ADDR`, `DOCUMENT_ROOT` or `SERVER_NAME`); `file_get_contents('php://input')`; `getallheaders()`; `filter_input()` unless it validates an int, float or boolean; Laravel `$request->input/query/get/post/all/only/except/route/header/cookie/string/json/validated/getContent`, `request('x')`, `request()->...`, `Request::input(...)` and `old('x')`; Symfony request bags (`query`, `request`, `cookies`, and `headers`/`attributes`/`files` on a request object); PSR-7 `getQueryParams`/`getParsedBody`/`getCookieParams`/`getHeader*`/`getBody`; CodeIgniter `$this->input->get/post/...` and `$this->request->getGet/getPost/...`; Drupal Form API input and `getClientOriginalName()`. A request object is a `$request`/`$req` variable, a `->request` property or a parameter typed `*Request`/`*RequestInterface`. Function and method parameters are never request data by themselves (a Laravel route parameter `show($id)` is not reported). Typed getters (`$request->integer()`, `boolean()`, `has()`), numeric casts and builtins that return numbers, booleans or hashes, and lookups (`User::find(...)`, `mysqli_fetch_*`, `->fetch*()`, `get_userdata()`) carry no request text. Sanitisers count only for the sink they protect: `escapeshellarg()` for commands, only as a whole unquoted argument (not inside quotes in the command, not as the program, and not as the code of `sh -c`/`bash -c`, `cmd /c`, `powershell -Command`, `eval` or an interpreter's `-c`/`-e`/`-r`, also behind `sudo`/`env`/`timeout`), where the command stays SKY-D212 (`escapeshellcmd()` is not one: it still lets input add arguments); `htmlspecialchars()`/`htmlentities()` (text and quoted attributes; `ENT_NOQUOTES` only text), `esc_html`, `esc_attr`, `e()`, `esc_url()`/`urlencode()` (also links) and `strip_tags()` (element text only) for HTML; `PDO::quote()`, `$wpdb->prepare()` and `pg_escape_literal()` for SQL anywhere, and SQL escaping (`mysqli_real_escape_string`, `addslashes`, `esc_sql`, ...) only inside a quoted SQL literal; `basename()` for paths and includes. Allow-list checks clean a variable or array element in the guarded branch and after an early exit: `in_array(...)`, `array_key_exists(...)`, `ctype_digit`/`ctype_alnum`, `is_numeric`, `filter_var(..., FILTER_VALIDATE_INT)`, `=== 'literal'` (also through `strtolower`/`trim`) and `preg_match()` with a pattern anchored at both ends that only allows letters, digits, `_` and `-` (not with `/m`). Each echo is checked against the HTML context it lands in, following the page's literal HTML and `<?= ?>` tags: `htmlspecialchars()` inside `href` or a `<script>` block is still reported. Output after `header('Content-Type: application/json')` (or a `*content_type*` helper with a non-HTML type) on every path is not HTML and not reported. SQL sinks: `mysqli_query`/`mysql_query`/`pg_query`/`sqlsrv_query`/..., any `->query/prepare/multi_query/real_query/executeQuery/executeStatement/createQuery/whereRaw/orWhereRaw/havingRaw/orderByRaw/groupByRaw/selectRaw/fromRaw`, `->exec()` on a database-named receiver, `$wpdb->get_results/get_row/get_var/get_col`, and Laravel `DB::raw/select/statement/unprepared/insert/update/delete`; `->where()` only for an SQL string, not an array of conditions. Bound parameters (`DB::select($sql, [$v])`, `$stmt->execute([$v])`) are not reported. D216 covers `curl_init`, `curl_setopt(CURLOPT_URL)`, `curl_setopt_array`, `get_headers`, `fsockopen` and Laravel `Http::`, with the same fixed-host barrier as Java. D204 `unserialize()` is not reported with `['allowed_classes' => false]` or a class list. Values passed through other functions keep their taint, so an application's own sanitiser (for example `yourls_sanitize_version()`) is not recognised; mark such a line with `// skylos: ignore[SKY-D228] reason`. Not covered: taint across functions, files, properties (`$this->x`) or into Blade variables set by a controller, Twig `|raw`, Guzzle, `call_user_func`/variable functions, `extract()`, mass assignment, open redirect and XXE.

Go D216 and D212 (Go engine) also need untrusted input: an incoming `*http.Request` (URL, form, headers, decoded body; not `r.Context()`), a gin, echo or fiber request context and the structs they bind (gin `ShouldBind*`/`Bind*` including `ShouldBindQuery`/`ShouldBindUri`, echo `Bind`, fiber `BodyParser`/`QueryParser`/`ParamsParser`), or network input (`net.Conn`, `Accept()`, `Read`/`Decode`/`Unmarshal` from such a reader), followed through locals, concatenation, `fmt.Sprintf`, calls and same-file helper parameters. Literals, loopback URLs, config structs, flags, `os.Args` and `os.Executable()` are the program's own inputs. Numbers and booleans carry no taint: the results of `strconv.Atoi`/`ParseInt`/`ParseUint`/`ParseFloat`/`ParseBool` and `uuid.Parse`, and values whose declared type is numeric (an `int` field of a bound struct). D216 also needs the host to be choosable: a leading literal `scheme://host/` fixes it. Go D216 sinks are `http.Get`/`Post`/`Head`/`PostForm`, `http.NewRequest(WithContext)`, the same methods on an `*http.Client` (package variable, struct field or `http.DefaultClient`), `client.Do(req)` after `req.URL` or `req.URL.Host` is set from input, and `httputil.NewSingleHostReverseProxy`. D212 is CRITICAL for an untrusted program path or shell command string, HIGH for a shell (`sh -c`, `cmd /c`, PowerShell `-Command`) running a non-constant command that is not proven untrusted, and not reported for a constant or own program with argv elements (`exec.Command(os.Args[0], "run")`); Go D212 also covers `syscall.Exec` and `golang.org/x/crypto/ssh` `Session.Run`/`Start`/`Output`/`CombinedOutput` with an untrusted command. Go D215 (file paths in `os.Open`/`ReadFile`/`WriteFile`/`Create`/`Remove`/`MkdirAll`/`ReadDir`/`Rename`/`Chmod`/`Stat`..., `http.ServeFile`, gin `c.File`/`FileAttachment`, echo `c.File`/`Attachment`/`Inline`, fiber `c.SendFile`/`Download`) uses the same sources. A containment check protects only the accepted branch or code after a rejecting return, and only until the checked value changes. A `strings.HasPrefix` boundary must be fixed, end with a path separator and check the actual cleaned value; `filepath.Rel` needs its error and parent traversal checked. `filepath.IsLocal` also supports a rejecting guard. Existing `filepath.Base` and `securejoin.SecureJoin` path policies remain specific to filesystem sinks: they do not sanitize SQL, command text or network destinations. The Go engine's reliability checks follow their Python equivalent: unclosed resource (SKY-G260) and defer in a loop (SKY-G203) are MEDIUM like SKY-L008, and `unsafe` use (SKY-G206) is LOW like gosec G103; a defer followed by an unconditional `return` (or a `break` in an outermost loop) runs once and is not reported, and a handle that is closed explicitly, returned or stored in a field is not unclosed. Go D230 (open redirect: `http.Redirect`, gin and echo `c.Redirect(code, url)`, fiber `c.Redirect(url)`) needs untrusted input that can choose where the redirect goes: data after a literal `?` or `#` cannot, and a dominating same-origin check can clear it. This requires both the leading `/` and rejected `//`, or successful `url.Parse` with empty `Host` and `Scheme`, or a proven literal allowlist. A comparison that only logs, a later check, or an unrelated value does not protect the redirect. Mutable package state is not a fixed boundary or allowlist merely because its initializer is literal. Go D211 is CRITICAL when request or network input reaches the query text, HIGH when the query is string-built from a non-constant value with no proven source (Python D211 reports that case too), directly in the call or in a variable built with `+` or `fmt.Sprintf` in the same function (like gosec G201/G202), and not reported for placeholders, constants, or values of numeric type or placed with a numeric verb (`%d`) that are not request input (request text formatted with `%d` stays CRITICAL). The receiver is resolved from declarations (parameters, struct fields of the package, package variables, constructor calls such as `sql.Open`, `sqlx.Connect`, `pgxpool.New`, `gorm.Open`): `database/sql` `DB`/`Tx`/`Conn`; `jmoiron/sqlx` (also `Select`/`Get` after the destination, `NamedExec`, `Queryx`, `MustExec` and their `Context` forms, and the package functions); `jackc/pgx` and `pgxpool` (the query is the argument after the context); GORM `Where`/`Raw`/`Exec`/`Order`/`Group`/`Having`/`Select`/`Joins`/`Table`/`Not`/`Or`/`Distinct`/`Pluck` and the inline condition of `First`/`Find`/`Take`/`Last`/`Delete` (a struct, map, slice or pointer argument is bound as parameters and not reported); a local struct embedding one of these, or a local interface with query methods (sqlc's `DBTX`). `*sql.Stmt` arguments are parameters, not query text. When the receiver cannot be resolved, a database-like name is accepted: a plain variable (`db`, `tx`, `conn`, `sqldb`, `database`) always, a field (`s.db`, `r.DB`) only when the package imports a SQL library; a package of the scanned module named `sqlx` is not `jmoiron/sqlx`. Go D226 reports request input converted to `html/template`'s `HTML`, `JS`, `URL`, `HTMLAttr`, `CSS`, `JSStr` or `Srcset` (CRITICAL). Go D228 reports request input written to an HTML response: `fmt.Fprint`/`Fprintf`/`Fprintln`, `io.WriteString` or `Write`/`WriteString` on an `http.ResponseWriter` (also gin `c.Writer`, echo `c.Response()`), gin `c.Data` and echo `c.Blob` with an HTML content type, echo `c.HTML`/`HTMLBlob`, and gin `c.String` or fiber `SendString`/`Send`/`Write` after an HTML content type was set on that context. Following CodeQL `go/reflected-xss`, a write is not reported after a non-HTML `Content-Type` was set on the same writer (a value taken from the request counts as HTML), or when every write to that response up to this one starts with constant text whose first character is not `<` (net/http then sniffs `text/plain`); `html.EscapeString`, the `html/template` escapers, `url.QueryEscape`/`PathEscape`, `json.Marshal` and a `bluemonday` policy's `Sanitize` clear the value, request cookies are not reflected input, and gin `c.String`/`c.JSON`, echo `c.String`/`c.JSON` and fiber's default `text/plain` responses are not HTML. Not covered: `text/template` used for HTML, and taint across files or packages. Go D210 (`InsecureSkipVerify: true`) is not reported in Go test-support code (a file that imports `testing` and takes a `testing.TB`/`*testing.T`/`B`/`F`/`M`), like D346 in Python test modules; `_test.go` files are not scanned by the Go engine. For L012, an external test file (`package pkg_test`) sees the exports of its own directory's internal test files (`package pkg`, the `export_test.go` convention), because `go test` compiles them into the package.

`bleach.linkify` (it only adds links) and `cgi.escape` (it leaves quotes alone)
are not XSS sanitizers. Path traversal (D215) also accepts a sanitizer imported by name
(`from os.path import basename`), but only when the module can't swap it out: no
local function with the same name, no star import, `exec`/`eval` or other write
to its own namespace, and no attribute write of the same name on any object
(`os.path.basename = …`, `setattr(x, "basename", …)`, `del x.basename`) or
`setattr` with a computed name. D325 uses the same sanitizer handling. Other checks recognise sanitizers only by their qualified name.

D338 reports reading sensitive files. It also reports a sensitive-file reader
(`cat`, `sed`, `base64`, `tar`, ...) whose redirect writes into a sensitive path
such as `~/.ssh/config`, `~/.aws/config`, `~/.kube/config`, `~/.npmrc`,
`~/.claude/settings*.json`, `~/.codex/config.toml`, `~/.docker/config.json`,
`~/.config/gh/` or `/run/secrets/`, because those files run code, steer
authentication or installs, or hold secrets. Redirect parsing is quote-aware: a
quoted `">"` is an argument, `<> file` is a read, and a here-string's `$(...)`
still reads. Routine credential setup is not reported, and only in GitHub Actions run steps:
a reader command writing `~/.ssh/known_hosts`, `~/.ssh/id_*` (SSH key files,
including `.pub`, `-cert.pub` and `.pem` forms), `~/.netrc` or `~/.pypirc` under the home directory (`~`, `$HOME`, `/root`, `/home/<user>`),
when no workflow, job, container or step `env` sets HOME and no run block in the
job assigns HOME or writes it to `$GITHUB_ENV`; and a project-relative `.env`, in
a bash/sh step on a Linux or macOS runner whose working directory is in the
workspace, with no `BASH_ENV`/`ENV` set, and whose script has nothing that may
change directory or hide a command (`cd`, `pushd`, `popd`, `source`, `.`, `eval`,
`exec`, `ln`, `trap`, `case`, `alias`, function definitions, PowerShell location
cmdlets, `env -C`, or a command word built from a variable, glob or brace
expansion, including escaped or quoted spellings). Shell scripts, GitLab CI and
Dockerfiles report these writes as before. TLS certificate writes (`*.pem`,
`*.crt`, `*.cer` outside `~/.ssh/id_*`), targets with `..`, a glob or a
variable, and every other sensitive path stay reported. A
reader writing into a persistence file that is also sensitive
(`~/.ssh/authorized_keys`, `~/.ssh/rc`) is reported as both D338 and D339. A redirect (`>`,
`>>`, `>&`, `&>`) from any command into a persistence target is D339 (HIGH):
`authorized_keys`, `~/.ssh/rc`, `~/.ssh/environment`, shell startup files,
`/etc/profile*`, cron files, systemd units, sudoers, `/etc/ld.so.preload`,
`/etc/rc.local`, `/etc/init.d/`, or git hook folders outside the project. A glob
target that could name one of these (for example `~/.ssh/authorized_ke*`) is
D339, and redundant `//`, `/./` and `..` segments do not hide one.

### AI Supply Chain Security

| ID | Severity | Name | File Types | Details |
|:---|:---|:---|:---|:---|
| D260 | HIGH-CRITICAL | Prompt injection scanner | `.py`, `.md`, `.rst`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.env` | Multi-file scanner with text canonicalization. Bidirectional control characters in Python source are reported once, as D344; D260 keeps them in other files. In YAML and TOML, comments document settings and are not scanned. YAML comment boundaries come from PyYAML's scanner (a `#` inside any scalar, quoted, block or flow, is value text); TOML ones from a string-aware lexer checked by `tomllib`. A file that does not parse keeps every line except whole-line comments. Terminology about generated LLM response text is distinguished from credential disclosure. Access tokens, environment credentials and API keys remain covered by the disclosure patterns |

Finding types:

- `literal_payload`: direct instruction override, role hijacking, suppression, or exfiltration phrase.
- `hidden_char`: zero-width or invisible Unicode.
- `obfuscated_payload`: encoded string that decodes to injection content.
- `mixed_script`: Cyrillic or Greek homoglyphs mixed with Latin text.
- `risky_placement`: injection in a high-risk README, prompt field, YAML, or JSON field.

Literal-pattern messages quote the matching clause. Their JSON
`metadata.instruction_pattern` records up to 16 matching signals, their base
severity and line offsets in the extracted, normalized text. Those offsets are
not source line numbers; `segment_start_line` identifies the extracted segment's
source location. `complete: false` means additional signals were omitted from
the evidence. Each match and its context are limited to 240 characters;
`matched_text_truncated` marks a shortened match. The strongest matched signal
determines severity, including when multiple strings begin on the same source
line. Application prompts still
require review; their names or message roles do not establish safety.

### AI Application Security

| ID | Severity | Name | Languages | Details |
|:---|:---|:---|:---|:---|
| D261 | HIGH | Untrusted input to LLM prompt | Python | Request-controlled data reaches an LLM prompt or message without a clear instruction/data boundary |
| D262 | CRITICAL | Unsafe LLM output handling | Python | Model output flows into code execution, shell, SQL, or network sinks without validation |
| D263 | HIGH | Sensitive data sent to LLM | Python | Secrets, credential fields, or sensitive environment values flow into LLM or embedding API input |
| D264 | HIGH | Excessive agent tool privilege | Python | Agent frameworks are granted shell, code execution, unrestricted HTTP, or broad file-management tools |
| D265 | HIGH-CRITICAL | Unsafe ML model deserialization | Python | Pickle-backed model/checkpoint loading such as `torch.load`, `joblib.load`, or `numpy.load(..., allow_pickle=True)` |
| D266 | CRITICAL | AI config instruction injection | Agent config and instruction files, AI code reviewer config files | D260-style hidden, obfuscated, or instruction-override payloads in AI assistant rule/config files. In AI code reviewers' own files (the SKY-A122 list, apart from `.github/copilot-instructions.md`, which stays a full agent instruction file), only HIGH signals become D266: instruction overrides, role changes, requests to reveal or send data, encoded payloads and invisible characters (an emoji joiner is not one). Reviewing vocabulary such as "do not flag" or "skip review" is what those files say, so it stays D260 at its usual severity, and a full scan that reaches a reviewer file inside a tool folder (`.gemini/`, `.cursor/`, `.github/`, `.greptile/`, `.macroscope/`), which it did not read before, reports only the HIGH signals there; a diff scan of a changed file reads it in full as before |
| D267 | MEDIUM | Unbounded LLM consumption | Python | LLM calls or agent executors lack token, timeout, iteration, or obvious loop bounds. Keys of a local dict unpacked into the call (`completion(**params)`) count as keywords when the dict is built and changed only where the checker can read it (a literal, `dict(...)`, `params["k"] = v`, `del`, `pop`, `setdefault`, `update`, `clear`, `|=`). A key counts only if it holds a value other than `None`/`False` on every path (`if`, loops, `try`, `match`); setting it under `if max_tokens:` or `if max_tokens is not None:` counts like passing `max_tokens=max_tokens`. When the mapping cannot be read (a parameter, an attribute, a call's result, a dict passed to another function, aliased or used by a nested function) a missing limit is not claimed |

### MCP Server Security

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| D240 | CRITICAL | MCP tool description poisoning | Python |
| D241 | HIGH | MCP unauthenticated transport | Python |
| D242 | HIGH | MCP permissive URI / path traversal | Python |
| D243 | CRITICAL | MCP server bound to `0.0.0.0` | Python |
| D244 | CRITICAL | MCP hardcoded secrets in tool params | Python |

### Filesystem And Archive Safety

| ID | Severity | Name | Languages / Scope |
|:---|:---|:---|:---|
| D324 | HIGH | Symlink-following file write | Python |
| D325 | MEDIUM | Symlink-following file read | Python |
| D326 | HIGH | Unsafe archive extraction | Python |

`Path(name).name` strips directory components but can still select an existing
final symlink. D325 does not exempt a read solely because that basename is
joined to a fixed base directory.

Python open-mode checks distinguish read, write and update (`+`) modes,
including bounded sets of literal modes assigned in the same function before
the call. Shared namespaces, captured cells and visible reflection keep named
modes unknown. An unknown mode keeps both operations possible. Literal update
modes add a read warning when the same handle is observed reading or being
iterated; named or conditional update modes preserve existing read checks even
when their handle escapes or is rebound. Explicit modes captured before
`**kwargs` expansion cannot be replaced by that mapping.

For Python path checks (`D215`, `D324`, `D325`), direct
`pytest.mark.parametrize` decorators can establish that a filename parameter
contains only literal relative paths. Supported forms include import aliases,
multiple columns, stacked decorators, and `pytest.param(..., id="...")`.
Only the proven columns lose parameter taint; other inputs remain checked.

This is a narrow static check for top-level `test_*` functions in test files.
It requires unchanged pytest API bindings and straight-line test bodies.
Indirect fixture values, dynamic lists, reassigned parameters, unknown
decorators, class/module parametrization, and unsupported control flow keep
the existing conservative behavior. Absolute paths and parent-directory
components are not accepted as evidence. Interpolation checks are unchanged.
Proof is limited to 256 rows per decorator, 32 parameter names, and 4096
characters per filename; larger inputs keep the normal parameter taint.
Skylos does not execute pytest or load `conftest.py` to resolve these values.

### Agent And Build Command Safety

| ID | Severity | Name | Languages / Scope |
|:---|:---|:---|:---|
| D327 | CRITICAL | Data exfiltration command | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D328 | HIGH | Remote script piped to shell | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D329 | HIGH | Broad destructive command | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D337 | HIGH | Package registry or index override | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D338 | CRITICAL | Sensitive host scope access | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D339 | HIGH | Persistent environment mutation | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D340 | HIGH | Unapproved package or artifact publish | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D341 | HIGH | Untrusted package-managed tool execution | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D342 | HIGH | Dockerfile remote ADD without checksum | Dockerfile |
| D343 | HIGH | Dockerfile literal secret build value | Dockerfile |
| D344 | HIGH | Trojan Source bidirectional Unicode (U+202A-U+202E, U+2066-U+2069), one finding per line, test files included | Python |
| D345 | HIGH | Mutable Hugging Face artifact revision | Python |
| D346 | HIGH | Flask debug mode enabled | Python |
| D347 | MEDIUM | Unsafe logging config listener | Python |
| D348 | HIGH | Insecure temporary filename | Python |
| D349 | CRITICAL | Server-side template injection (request data compiled as Jinja template source; Java Velocity `evaluate`, FreeMarker `new Template(...)` source, `StringTemplateLoader.putTemplate`, Groovy `TemplateEngine.createTemplate`; PHP Drupal `inline_template` render arrays) | Python, Java, PHP |
| D355 | HIGH | Jinja environment with omitted or explicitly disabled autoescape | Python |
| D356 | MEDIUM | Cleartext outbound HTTP request | Python |
| D357 | HIGH | Untrusted input used as a dynamic Python import name | Python |
| D358 | HIGH | Public Gradio launch without configured authentication | Python |
| D359 | MEDIUM | Cached Flask external URL derived from the request host | Python |

D355–D359 require review of deployment and input context. D356 records a
cleartext transport choice; it does not establish that sensitive data is sent.
D357 requires an identified input source, rather than reporting every plugin
import. D359 requires cache and request-host evidence. Related D215/D324/D325
checks at the same filesystem operation appear together in terminal reports;
JSON, SARIF and gates retain each raw finding. Missing request timeouts remain
SKY-L031 quality findings and should be reported separately in comparisons.

D329 flags `rm -rf` of `/`, `~`, `$HOME`, `.`, `*`, `.git`, any other absolute
path, and `$VAR/` or `$VAR/*` (an empty variable makes it `/`). Split flags
(`-r -f`) and `--recursive --force` receive the same checks. Removing
package-manager caches and scratch space is not a finding: `/tmp/...`,
`/var/tmp/...`, `/var/cache/...`, `/var/lib/apt/lists/...`, and `.cache` or
`.npm` under `/root`, `~` or `$HOME`. Cleanup targets containing parent traversal
or expansions after the cache prefix retain findings because they can escape
that directory.

### Config And Deployment Security

Terraform checks read `.tf` and `.tf.json` without running Terraform or contacting
cloud accounts. `SKY-D400` reports a declaration allowing worldwide TCP SSH/RDP
ingress; `SKY-D401` reports explicit disabled storage encryption for a directly
created AWS RDS DB instance. These are declaration policies, not evidence of
live Internet reachability or deployed state. Literal locals can be resolved;
runtime variables, external modules and unsupported expressions stay unknown.
Snapshot and replica encryption stays unknown. File/resource coverage and
safe/unsafe/unknown/not-applicable checks are recorded under
`analysis_summary.configuration_coverage.terraform`. Unknown is never a safe
policy result. See [the cloud corpus](benchmarks/cloud/README.md).

| ID | Severity | Name | Provider |
|:---|:---|:---|:---|
| D400 | HIGH | Terraform AWS worldwide administrative ingress (TCP 22/3389, IPv4/IPv6, inline and standalone security-group rules) | Terraform / AWS |
| D401 | HIGH | Terraform AWS new database storage encryption explicitly disabled (direct `aws_db_instance`; restores and replicas unresolved) | Terraform / AWS |
| D290 | HIGH | Dangerous trigger (`pull_request_target`, `workflow_run`). `issue_comment` counts only when a job that accounts without write access can start checks out pull request code (a `refs/pull/` ref, a step output assigned the pull request's head ref or SHA, `gh pr checkout`, a `git fetch` of a pull ref) and then runs it (a later command, `run:` step or local action) while holding a write or undeclared token, secrets, a write-capable `cache-mode` or a possibly self-hosted runner. Reach follows the job's `if:` and `needs`. Only a verified permission check stops outsiders: a known check action (actions-cool/check-user-permission with `error-if-missing: true`, prince-chrismc/check-actor-permissions-action, sushichop/action-repository-permission without `relax`, xt0rted/slash-command-action, lannonbr/repo-permission-check-action, skjnldsv/check-actor-permission, TheModdingInquisition/actions-team-membership, as their sources fail) that demands more than read access of the triggering account, or a script that looks the permission or association up and exits non-zero, with no `continue-on-error` and a later step that runs only on success; or a known check whose 'allowed' output the later step's `if:` requires. An action or step whose name or text only mentions permissions does not count, and a needed job gates only through such a failing check. `github.event.pull_request` and `github.head_ref` are empty on comment runs, so a checkout of them gets the default branch. | GitHub Actions |
| D291 | MEDIUM-HIGH | Missing or excessive permissions. A job's own `permissions` replaces the workflow's, so workflow-level values are judged by the jobs that inherit them: missing permissions are one finding per workflow naming those jobs (none when every job declares its own), `read-all`/`write-all` need an inheriting job, and a workflow-level `X: write` needs two (with one it is already job-scoped). A job's own `read-all`/`write-all` is reported on that job | GitHub Actions |
| D292 | HIGH (LOW for GitHub-owned) | Unpinned action or reusable workflow (not a full commit SHA). Valid same-repository job calls using `./.github/workflows/...` or `$/.github/workflows/...` already select the caller's commit and need no additional SHA pin. GitHub-owned `actions/*` and `github/*` at a tag or branch are LOW (GitHub runs the workflow and owns them); a path with `.`, `..` or empty segments gets no such discount. Every other owner, dynamic `${{ }}` refs and refs with no `@` are HIGH | GitHub Actions |
| D293 | MEDIUM | Checkout persists credentials where they can reach someone new: a later `actions/upload-artifact` of the checkout (`.git` included: before v4.4, or with `include-hidden-files: true`, or a SHA pin), a pull request's code checked out in a job accounts without write access can start, or an explicitly write-scoped token beside a later third-party action. GitHub-owned and local actions already hold the token; an undeclared token scope is D291's finding | GitHub Actions |
| D294 | HIGH-LOW | Template injection: a `${{ }}` expression in code (`run:`, container and service `options`, code inputs of known actions such as `actions/github-script` `script`) whose value an attacker can shape. Each expression is parsed (`format()`, `toJSON()`, `fromJSON()`, `join()`, `case()` values, `a && b || c`, `github['event']`); a comparison or `contains()` result is not a value. What a context can hold comes from GitHub's webhook payload schemas (PR number or SHA: fixed, not reported). `env` and `matrix` values are followed to the expressions that set them; step outputs to the `$GITHUB_OUTPUT` line that writes them (a direct `${{ }}` or a `$VAR` from `env`), job outputs through `needs`, and reusable-workflow inputs to the local callers that pass them. A payload field counts only for the events that carry it (`github.event.inputs` exists on `workflow_dispatch`, `head_commit` on `push`); base-repository, organization and installation fields are set by maintainers. Severity is who can make the job run: HIGH (MEDIUM for structured text) when an account without write access can, after `if:`/`needs` gates; MEDIUM when it is not known (composite actions, reusable workflows without a local caller); LOW when only writers can or a fork's own sandboxed `pull_request` run sets it. Writer-set values not listed as untrusted by GitHub (`github.ref`, `ref_name`, `base_ref`, `vars.*`) and step/job outputs are not reported | GitHub Actions |
| D295 | HIGH | Self-hosted runner exposure | GitHub Actions |
| D296 | MEDIUM | Unpinned container image | GitHub Actions |
| D297 | HIGH | Secrets inheritance into reusable workflow | GitHub Actions |
| D298 | MEDIUM | Overprovisioned secrets | GitHub Actions |
| D299 | MEDIUM | Secret used outside protected environment in a job that accounts without write access can start (`issues`, `issue_comment`, `pull_request_target`, `discussion`, review events, `workflow_run` after a fork-reachable run), after the job's `if`, `needs` and approval environment are applied. Writer-started events and `pull_request` (no secrets for forks) are not reported | GitHub Actions |
| D300 | HIGH | Unsafe environment file write | GitHub Actions |
| D301 | HIGH | Hardcoded container credentials | GitHub Actions |
| D302 | HIGH | Broad GitHub App token permissions | GitHub Actions |
| D303 | MEDIUM | Unsound `contains()` condition | GitHub Actions |
| D304 | MEDIUM | Spoofable bot condition | GitHub Actions |
| D305 | MEDIUM | Unsound multiline condition | GitHub Actions |
| D306 | HIGH | Insecure commands enabled | GitHub Actions |
| D307 | MEDIUM | Anonymous action/workflow definition | GitHub Actions |
| D308 | MEDIUM-HIGH | Cache poisoning risk. Read side (MEDIUM): a step that runs on the `release` or tag-push event of a release-like workflow restores a cache, either because an input enables it or because the action caches without being asked: `actions/setup-go` v4+ (`cache`), `jdx/mise-action`, `actions-rust-lang/setup-rust-toolchain`, `mlugg/setup-zig`, `Swatinem/rust-cache` (unless `lookup-only`), `oven-sh/setup-bun` (unless `no-cache`), `gradle/actions/setup-gradle` (unless `cache-disabled`), `ramsey/composer-install` (unless `ignore-cache`), `astral-sh/setup-uv` v5-v9 on GitHub-hosted runners (`enable-cache: auto`; v10+ skips release and tag runs) and `actions/setup-node` v5+ after a checkout when the root `package.json` names npm in `packageManager` or `devEngines.packageManager`. A job whose `cache-mode` is `none` or `write-only` restores nothing; a commit pin needs a version comment to count. Write side (HIGH): GitHub gives low-trust runs that resolve to the default branch (`pull_request_target`, `issue_comment`, `workflow_run`, issue and discussion events) read-only caches unless `cache-mode: write` or `write-only` is declared; `pull_request_review` runs, like `pull_request`, write only to the merge ref. Reported when such a job, reachable by accounts without write access, has a step they reach that checks out pull request code, downloads the triggering run's artifacts or expands event text into a script. A called workflow gets the local caller's explicit `cache-mode` when it sets none, may request more when the caller sets none, and does not start when it requests more than the caller's. Defaults from each action's action.yml and GitHub's dependency-caching reference, 2026-10-21 | GitHub Actions |
| D309 | HIGH | Broad secret environment exposure | GitHub Actions |
| D310 | HIGH | OIDC token exposed to local build script | GitHub Actions |
| D311 | MEDIUM | Lax artifact upload | GitHub Actions |
| D312 | MEDIUM | JavaScript install scripts in CI | GitHub Actions |
| D313 | LOW | Privileged job missing a bounded timeout while reachable accounts without write access can run pull request code. The default is 360 minutes on both GitHub-hosted and self-hosted runners; trusted jobs and jobs that do not run PR code are not reported | GitHub Actions |
| D350 | MEDIUM-CRITICAL | AI agent on an untrusted trigger with no actor gate | GitHub Actions |
| D351 | MEDIUM-CRITICAL | AI agent action's write-access check widened (`*`) | GitHub Actions |
| D352 | MEDIUM-HIGH | AI agent can run any shell command on an untrusted trigger | GitHub Actions |
| D353 | MEDIUM-HIGH | Untrusted event text interpolated into an AI agent prompt | GitHub Actions |
| D354 | LOW-HIGH | AI agent action or CLI version with a published advisory | GitHub Actions |
| D360 | HIGH | Dependabot `insecure-external-code-execution: allow` on a `bundler`, `mix` or `pip` entry that uses private `registries`. Code from the manifests then runs with those registries' credentials. Without registries the option changes nothing (these tools already run manifest code, and GitHub turns it off only when registries are configured), and other ecosystems ignore it | Dependabot (`.github/dependabot.yml` or `.yaml` at the scanned root) |
| D361 | LOW | Dependabot version updates proposed less than 7 days after a release. The shortest wait per entry counts: SemVer-bump days where GitHub supports them for the ecosystem, else `default-days`, else GitHub's 3-day default; `exclude: ["*"]` removes the cooldown and an `include` list without `*` leaves the other dependencies on the default. Entries with `open-pull-requests-limit: 0` (version updates off) are skipped. One finding per file listing the entries; an ignore comment on an entry's own line drops that entry. Security updates are never delayed | Dependabot |
| D362 | MEDIUM | `fromJSON()` of a secret whose result reaches a value GitHub prints or shows: `run:`, step and job `with:`, `env:`, `strategy.matrix`, job `outputs`, names, `runs-on`, `environment`, container and service image, options, env, entrypoint and args. Covers `fromJSON(secrets.X).field`, `fromJSON(secrets.X)`, and an `env` variable holding the secret. GitHub masks the stored text only. Conditions, comparisons, `contains()`, timeouts, `max-parallel`, `continue-on-error` and `secrets:` passed to a reusable workflow are not reported | GitHub Actions |
| D363 | LOW-MEDIUM | Obfuscation. MEDIUM: a `uses:` path with `.`, `..` or empty segments, which GitHub resolves but name-matching rules and allow lists do not. LOW: a `${{ }}` part that folds to a constant (`format('{0}', 'x')`, `'a' == 'a'`, `toJSON('x')`), `fromJSON(toJSON(x))`, or `format('{0}', x)`. A literal alone (`${{ true }}`) and `fromJSON()` of a literal, the language's only way to write a list, object or typed number, are not reported. Folding stops, with no finding, past 2,000 steps or a 4,096-character value (`format('{0}{0}', x)` doubles its input) | GitHub Actions |
| D364 | LOW-MEDIUM | Publishing with a stored token where the registry offers trusted publishing: `pypa/gh-action-pypi-publish` with `password`, `twine upload`, `uv publish`, `poetry`/`hatch`/`pdm`/`flit publish`, `maturin publish` to PyPI or TestPyPI, and `npm`/`pnpm`/`yarn`/`bun publish`, `changeset publish` and `semantic-release` to registry.npmjs.org, when a secret-backed token reaches the step (env such as `TWINE_PASSWORD`, `NODE_AUTH_TOKEN`, `NPM_TOKEN`, a `--password`/`--token` argument, or an `.npmrc`/`.pypirc` written earlier in the job). Not reported for other indexes and registries, npm on runners not proven GitHub-hosted, PyPI from `pull_request_target`/`issue_comment` workflows (PyPI refuses them), or PyPI from `workflow_call`-only workflows (PyPI does not support reusable workflows; npm checks the caller and is reported). A `password` that is not a stored secret (one minted through OIDC) is not a long-lived token. When the job grants `id-token: write`, npm tries trusted publishing first and the token is a fallback: LOW | GitHub Actions |
| D314 | HIGH | Mutable container image | GitLab CI |
| D315 | HIGH | Unpinned external include | GitLab CI |
| D316 | HIGH | Literal secret variable | GitLab CI |
| D317 | HIGH | Untrusted eval | GitLab CI |
| D318 | HIGH | Docker-in-Docker TLS disabled | GitLab CI |
| D319 | HIGH | OIDC local-script exposure | GitLab CI |
| D320 | HIGH | Release cache poisoning risk | GitLab CI |
| D321 | MEDIUM | Privileged job missing timeout | GitLab CI |
| D322 | MEDIUM | Dynamic runner tag | GitLab CI |
| D323 | MEDIUM | Ambiguous secret token | GitLab CI |
| D330 | HIGH | Privileged edge container | Docker Compose |
| D331 | HIGH | Host device exposure | Docker Compose |
| D332 | MEDIUM | Host networking on edge service | Docker Compose |
| D333 | HIGH | Edge service runs as root | systemd |
| D334 | HIGH | Root service executes mutable path | systemd |
| D335 | MEDIUM | Edge service missing sandboxing | systemd |
| D336 | HIGH | Broad edge service privilege | systemd |

For GitHub Actions, D290 and D295 point to the relevant trigger or job's
`runs-on` declaration. Their inline ignores apply to that line or an immediately
preceding standalone YAML comment, not to other declarations or text inside
quoted values and script blocks.

D295 reports at HIGH severity. Runner-label order does not affect the check.
Simple literal matrices are exempt only when every possible runner value can be
proved to be a known GitHub-hosted label. Runner groups, unknown expressions and
matrix combinations that cannot be resolved conservatively still produce a warning.

### Agent, Editor And Publish-Job Configuration (D365-D377)

Decided by the ca9 engine (`ca9.api.agent_config`, `audit_workflows`,
`ci_inventory`); Skylos keeps only rows naming a file inside the scanned folder
that Git lists (a diff scan: files Git tracks; a full scan: files Git tracks or
does not ignore). Links to agent folders or configs that stay inside the
repository are followed and reported under the path the client opens, once per
real file; a new or changed link that leaves the repository or points nowhere
is an analysis error in a diff (exit 2). A subfolder scan also reports the
repository-level workflows and agent configs at the Git top. See
[docs/agent-config-and-publish-rules.md](./docs/agent-config-and-publish-rules.md).

| ID | Severity | Name | Files |
|:---|:---|:---|:---|
| D365 | HIGH-CRITICAL | Agent hook command committed in the repository. CRITICAL when the command downloads remote code, decodes and runs a payload, or runs a script disguised as a font or image. Hooks `skylos agent install-hooks` wrote are not reported: the whole command must be `skylos hook <event> --client claude\|codex\|cursor` with one of Skylos's fixed `\|\|` fallbacks and nothing else, the program `skylos` on PATH or an absolute `/…/skylos` outside the repository and temp folders, and the settings file's `env` must not set PATH or loader variables; `python -m skylos.entry` is reported | `.claude/settings(.local).json`, `.gemini/settings.json`, `.cursor/hooks.json`, `.codex/hooks.json`, `.codex/config.toml` |
| D366 | HIGH-CRITICAL | Editor task that runs when the folder opens (`runOptions.runOn: "folderOpen"`); severities as D365 | `.vscode/tasks.json`, `*.code-workspace` |
| D367 | MEDIUM | MCP server launched without an exact version (`npx -y pkg`, `@latest`, `uvx pkg`, an image without a digest) | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.kiro/settings/mcp.json`, `mcpServers` blocks |
| D368 | HIGH | MCP server launched from a hidden home-directory or temp path outside the repository | MCP configs |
| D369 | MEDIUM | MCP server package whose name imitates a vendor it is not published by | MCP configs |
| D370 | HIGH | Agent API base URL (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) overridden in committed settings | agent settings |
| D371 | HIGH | Tool installed without a pinned version or hash in a job holding publish credentials or `id-token: write` | GitHub Actions, GitLab CI |
| D372 | HIGH | Download without a checksum or signature check reaching the publish step | GitHub Actions, GitLab CI |
| D373 | HIGH | OIDC publish job without a deployment `environment:` | GitHub Actions (`id-token: write`), GitLab CI (`id_tokens`) |
| D374 | HIGH | Publishing workflow startable by `workflow_dispatch` or a push to any branch | GitHub Actions |
| D375 | MEDIUM | `--diff` only: the change adds or modifies a CI job that publishes packages (base `ci_inventory` against head, line numbers ignored) | GitHub Actions, GitLab CI |
| D376 | MEDIUM | Secrets (`secrets: inherit` or named) passed to a reusable workflow from another repository | GitHub Actions |
| D377 | MEDIUM | Agent or editor config with duplicated keys, so what you read is not what runs | agent and editor settings, MCP configs |

Built-in gate: in a whole-repository scan D365-D374, D376 and D377 are listed
and not counted, except a CRITICAL D365/D366. In a diff scan D365, D366, D368
and D370 fail the gate on their own; D367, D369 and D371-D377 count under the
normal limits. With `--diff` a finding is new when its rule, path and identity
(event, task, server or job name plus the whole unredacted command) are not
among the merge base's findings, not by changed lines, so a `folderOpen`
trigger added to an existing task or a hook moved to `SessionStart` is new;
without a comparable base every such finding in a changed file counts
(`analysis_summary.config_diff_basis`). A baseline scan does the same only for
the rules its baseline covered (`rule_coverage`, recorded by `skylos baseline`
from the installed ca9); with an older baseline these findings are listed, not
new. They match the baseline by rule, file and a SHA-256 digest of that
identity (kept local, never uploaded), not by line or the redacted shown value.
Under `SKYLOS_POLICY_BASE` (pull-request CI and gated diffs) a baseline entry
for D365-D377, malware, UPG001, HRD001 or AGE001 counts only when the base
commit's baseline has it too. A diff that changes agent/editor configs,
workflows or lockfiles without a usable ca9 (missing, too old, or lacking the
function) is an analysis error ("upgrade ca9"), never a pass. Commands in
findings and uploads are redacted.

### AI Agents In GitHub Actions (D350-D354)

These rules look at steps that run an AI coding agent:
`anthropics/claude-code-action`, `anthropics/claude-code-base-action`,
`openai/codex-action`, `google-github-actions/run-gemini-cli`,
`actions/ai-inference`, the opencode action (`anomalyco/opencode/github`), and
`claude`, `codex exec`, `gemini` or `copilot` CLIs started from a `run:` block.
Input names and built-in checks were read from each action's `action.yml` and
source on 13 Oct 2026.

An event is untrusted when an account without write access can start it:
`issues` (opened, edited, closed, reopened), `issue_comment`,
`pull_request_target` (fork pull requests), `pull_request_review`,
`pull_request_review_comment`, `discussion`, `discussion_comment`, and
`workflow_run` when an upstream workflow (resolved by name, through chained
`workflow_run`s) runs on pull requests or other untrusted events. Types such as
`labeled` or `assigned` need triage access, so they count as trusted. A local
reusable workflow inherits its caller's events and gate (`via caller.yml`).

A finding needs a path for attacker-written text to reach the agent: the action
loads the triggering thread itself (claude-code-action without `prompt`, the
opencode action), the prompt interpolates event text, an earlier step or job
writes that text to a file or output the agent reads, an env var holds it, the
agent has a tool that reads issues or pull requests (`gh`, GitHub MCP, shell),
or the job checks out the pull request's code. A fixed prompt over the base
branch with no such tool is not reported.

**Gates.** The `if:` conditions on the job, its `needs` chain and the step are
evaluated per event. These count as gates: `author_association` of the account
that triggered the event equal to, or in a `fromJSON` list of, OWNER, MEMBER or
COLLABORATOR; an exact `github.actor` or `sender.login`; a same-repository
pull request check (`head.repo.full_name == github.repository`, `!fork`) under
`pull_request_target`; `workflow_run.event` of a trusted event;
`workflow_run.pull_requests` (GitHub leaves it empty for fork pull requests);
`github.event.repository.private == true`; a gated `needs` job; an earlier step
that calls a collaborator or membership API, a known permission-check action,
or a script comparing `author_association` with a member value; and an
expression-valued `environment` (the fork-approval pattern). A fixed
`environment:` name is noted in the message, not treated as a gate, because
required reviewers are a repository setting Skylos cannot see; such findings
are capped at HIGH. Another entity's association (for example
`github.event.issue.author_association` on a comment event), `!= 'NONE'`, or
CONTRIBUTOR does not gate. A job that runs only for one value of a dispatcher
job's output, when that job reads the event type, is not assumed to run for
every event (a deliberate false-negative risk).

**Built-in checks.** claude-code-action refuses accounts without write access
on issue, comment, review and pull request events (and on `workflow_run` from
v1.0.185); `allowed_non_write_users` turns this off only when `github_token`
is passed, and `allowed_bots: "*"` lets any GitHub App through.
codex-action checks write access on every event unless `allow-users: "*"`.
The opencode action checks write access. claude-code-base-action,
run-gemini-cli, ai-inference and the CLIs have no check.

**Capability.** shell (any command: `Bash`, `Bash(*)`, wildcard rules on an
interpreter or package manager such as `Bash(python:*)`, `Bash(npm:*)` or
`Bash(bash -c:*)` (an exact rule such as `Bash(bun install)` is not),
`--dangerously-skip-permissions`, permission mode
`bypassPermissions`, codex `sandbox: danger-full-access` or
`safety-strategy: unsafe`, Gemini YOLO with no `tools.core` allowlist or a
pinned CLI before 0.39.1, Copilot `--allow-all-tools`); tools (can change
things: claude-code-action tag mode, edit or write tools, write-capable `gh` or
MCP tools, codex sandbox with network access); read (read-only tools, codex's
default sandbox without network, Gemini without
`GEMINI_CLI_TRUST_WORKSPACE`, which ignores workspace settings and turns off
auto-approval); none (no tools: `tools.core: []`, ai-inference without MCP or
`copilot-allow-tools`, every built-in tool denied). Agents with no tools are
not reported by D350 to D353.

- **D350** — an untrusted event reaches the agent with no gate while the job
  holds secrets, a write token, undeclared token permissions or
  `id-token: write`. CRITICAL with shell, HIGH with tools, MEDIUM with
  read-only tools. The message gives the path, for example
  `issue_comment (anyone who can comment) → run-gemini-cli (...) with shell
  commands (...) and secrets GEMINI_API_KEY`.
- **D351** — the action's own check is widened with `"*"`; same severity model,
  capped at HIGH for `allowed_bots` alone.
- **D352** — the agent can run any shell command and an untrusted event can
  start it (HIGH), or a maintainer starts it on a comment or review thread that
  others wrote (MEDIUM).
- **D353** — untrusted event text (`issue.title/body`, `comment.body`,
  `review.body`, `pull_request.title/body/head.ref`, `github.head_ref`,
  `discussion.title/body`, `workflow_run.head_branch/display_title`,
  `toJSON(github.event...)`) is interpolated into a prompt input. Text written
  by the gated account that starts the agent does not count. HIGH when anyone
  can trigger it and the agent can act, otherwise MEDIUM.
- **D354** — the pinned release (tag or known release commit) is affected by
  GHSA-8q5r-mmjf-575q (CVE-2026-47751, claude-code-action 1.0.0-1.0.73, fixed
  in 1.0.74) or GHSA-wpqr-6v78-jr5g (CVE-2026-12537, run-gemini-cli before
  0.1.22, or `gemini_cli_version` before 0.39.1). The claude advisory range
  says `< 1.0.74`, but its text says `@beta` (which is v0.0.63) is fixed, so v0
  is not reported. HIGH for a critical advisory on a workflow with an untrusted
  event, MEDIUM otherwise; LOW for the medium advisory without one.

Suppress with `# skylos: ignore[SKY-D35x]` on the reported line or the line
above it. SKY-D355 to SKY-D359 cover the Python checks described above.

## Kubernetes Deployment Exposure (SKY-DEP)

Skylos correlates resources in one rendered multi-document Kubernetes file.
The scan is deliberately opt-in: the `Ingress` must declare
`skylos.dev/network-scope: external` (or `public`) and
`skylos.dev/backend-protocol: http`. Skylos then emits a finding only when it
can construct one unambiguous static chain inside that same file:

```text
annotated Ingress path -> Service port -> selected workload -> one container
-> matching target port -> bare Flask/Uvicorn/Gunicorn executable, target, and binding
```

For `SKY-DEP001`, the workload Pod template also supplies the route contract:

```yaml
metadata:
  annotations:
    skylos.dev/source-file: app/main.py
    skylos.dev/required-guards: require_admin, require_employee
```

`skylos.dev/source-file` is a repository-relative Python file that must match
the server's literal module target. `skylos.dev/required-guards` is a
comma-separated list of guard names. Skylos checks direct, top-level literal
routes on the resolved FastAPI or Flask application symbol. A route is reported
only when its Ingress-reachable path contains a sensitive segment such as
`admin`, `internal`, `debug`, `manage`, `metrics`, or `pprof` and one or more
declared guards are missing. Recognized guard locations are application or
route dependencies, handler dependency parameters, and handler decorators.
Guard names match the declared expression identity exactly; for example,
`auth.require_admin` does not match `other.require_admin`. Sensitive route
names do not bypass an explicit required-guards contract.

`SKY-DEP002` is narrower: it reports an effective Flask debugger enabled by
literal `--debug` / `--no-debug` and `--debugger` / `--no-debugger` precedence on
the resolved externally routed container. `SKY-DEP003` separately reports a
literal `--reload` flag on a resolved Flask, Uvicorn, or Gunicorn container, or
Flask debug mode when it implies reload and `--no-reload` is absent.
These two command checks do not require the source-file or required-guards
annotations. All three rules require a literal `0.0.0.0` or `::` server bind,
numeric server port, and a Service target port that reaches that binding.
Backend transport evidence must be explicitly plain HTTP; HTTPS, H2, gRPC,
passthrough, controller TLS/path rewrites, snippets, middleware chains, and
other unproved protocols make the scanner abstain. An Ingress
`defaultBackend` is correlated only when the Ingress has no explicit rules,
because explicit paths take precedence before the default backend.

The scanner abstains when a proof edge is missing, dynamic, invalid, or
non-unique. Scope, backend-protocol, source-file, and required-guards
annotations are repository-owned declarations, and emitted evidence remains a candidate
correlated-static proof. Skylos verifies exact framework wiring, not the
guard implementation's semantics. The source annotation also does not prove
that the analyzed file was built into the referenced container image, and a
literal executable name does not attest the server binary's provenance inside
the image. Direct route ordering and obvious route-graph mutation are checked;
ambiguous router composition makes the scanner abstain. It does not join
resources split across different files, inspect nested routers or
factory-registered routes for `SKY-DEP001`, render Helm or Kustomize, execute a
manifest, query a cluster, or infer live network policy. Direct `LoadBalancer`
and `NodePort` Services without an annotated Ingress are outside this rule
family. Kubernetes `List` wrappers and resources whose metadata cannot be
positioned precisely are also outside the proof surface. For security gates,
keep the annotations in protected deployment
policy because removing an opt-in contract makes this rule family abstain.

| ID | Severity | Category | Name | Correlated static evidence |
|:---|:---|:---|:---|:---|
| SKY-DEP001 | HIGH | Security | Externally deployed route is missing a required auth guard | Annotated Ingress, Service, workload/container, explicit entrypoint, contracted source, direct FastAPI/Flask route, and exact required guard |
| SKY-DEP002 | HIGH | Security | External Ingress exposes the Flask development debugger | Annotated Ingress, Service, workload/container, matching Flask binding, and an effective literal debugger flag |
| SKY-DEP003 | MEDIUM | Reliability | External Ingress routes to a reload-mode application server | Annotated Ingress, Service, workload/container, matching Flask/Uvicorn/Gunicorn binding, and a literal flag that effectively enables reload |

## GPU Release Compatibility (SKY-GPU)

Skylos treats `.skylos/gpu-targets.yml` version 1 as the repository's explicit
deployment truth. A target declares the NVIDIA driver, CUDA compute capability,
and platform that a release must support:

```yaml
version: 1
targets:
  - name: inference-t4
    vendor: nvidia
    driver: "535.104.05"
    compute_capability: "7.5"
    platform: linux/amd64
```

These rules statically cross-check that target profile against Docker image,
CUDA build, and TensorRT packaging evidence before release. They do not probe
installed hardware or drivers, and they do not perform package CVE analysis.
All targets in one profile are treated as recipients of the same release;
repositories with separate per-device artifacts should scan each deployable
with its own target contract.

The contract is fail-closed once present: malformed YAML, duplicate or unknown
keys, empty targets, invalid driver values, deletion in a changed-file scan,
unsupported platform values, and bounded evidence discovery that cannot finish
emit `SKY-GPU000`. Platforms are limited to `linux` or `windows`, optionally
with `/amd64` or `/arm64`. The
default quality gate allows zero Reliability findings, so a proved GPU release
break blocks `--gate` without requiring `--strict`.

Explicitly selecting any `SKY-GPU` rule opts the scan into this contract: a
missing profile emits `SKY-GPU000`, and selecting `SKY-GPU001`, `SKY-GPU002`,
or `SKY-GPU003` automatically retains that prerequisite finding. This prevents
a narrow `--select ... --gate` command from hiding an invalid or absent
contract and passing open.

`SKY-GPU001` evaluates the effective final Docker stage, including its resolved
stage-alias ancestry, when it is an NVIDIA CUDA image
and compares the declared target driver with NVIDIA's CUDA-major
minor-compatibility branch floor. Windows targets use the Windows branch floor;
an omitted platform defaults to Linux. Skylos deliberately does not treat a
`cuda-compat-*` token as a waiver: NVIDIA forward compatibility also depends on
the exact package/driver matrix, loader configuration, supported GPU class, and
feature use. Teams relying on that path must document an explicit inline rule
waiver at the CUDA `FROM` instruction.

`SKY-GPU002` models output kind and direction: unsuffixed CMake architectures
produce both real SASS and virtual PTX, `-real` and `-virtual` are distinct, and
PTX covers only equal-or-newer compute capabilities. A cubin covers compatible
devices in its compute-capability major family. An actual `nvcc -arch=sm_*`
command proves both cubin and PTX output; quoted examples and `echo` text do not
count as build evidence. Dynamic/conditional values, `native`, target-level
overrides, or multiple independent architecture evidence files produce
`SKY-GPU000` rather than a confident compatibility result.

`SKY-GPU003` ties a syntactically valid Python TensorRT build call to the exact
config object, a later binary write of that result, an exact repository-relative
engine path, and a `COPY`/`ADD` in the final Docker stage. C++ matching requires
`NvInfer.h` and ordered builder/config/output evidence. `AMPERE_PLUS` counts only
when applied to that config before serialization; it does not imply portability
across different operating-system/CPU platforms.

| ID | Severity | Name | Cross-file evidence |
|:---|:---|:---|:---|
| SKY-GPU000 | HIGH | GPU release contract is invalid or incomplete | Contract schema/deletion or bounded evidence proof could not complete |
| SKY-GPU001 | HIGH | CUDA image requires newer NVIDIA driver | CUDA container image and declared target driver |
| SKY-GPU002 | HIGH | CUDA target architecture missing from build | CUDA architecture flags and declared compute capability |
| SKY-GPU003 | HIGH | TensorRT engine is not portable across target GPUs | Serialized engine packaging, compatibility flags, and heterogeneous target GPUs |

## Secrets (SKY-S)

| ID | Severity | Name | Languages / Scope | CWE |
|:---|:---|:---|:---|:---|
| S101 | HIGH-CRITICAL | Hardcoded secret / API key | Python, TS/JS, Java, Kotlin, Go, PHP, Rust, Swift, Dart, C#, C/C++, shell scripts (including extensionless files with a shell `#!` line), Dockerfiles, Terraform (`.tf`, `.tfvars`, `.hcl`), `.properties`, XML, Gradle, `.npmrc`, `.pypirc` and config files | CWE-798 |
| S102 | HIGH* | Secret material or server-only environment variable exposed to client-accessible code | TS/JS, HTML, client bundles | CWE-200 |

`SKY-S101` is `CRITICAL` for provider tokens and for high-entropy values
under a secret-like name (`key`, `token`, `secret`, `password`, `auth`,
`credential`, `private`, `api`, `session`, `cookie`, `signature`/`sig`
before the value on its line, or the user-info, secret-named parameter or
webhook path of a URL), including when a type annotation sits between the
name and the value (`API_TOKEN: &str = "..."` in Rust, `apiToken: string =
"..."` in TypeScript, `API_TOKEN: str = "..."` in Python,
`var apiToken string = "..."` and `apiToken := "..."` in Go). The Go engine's
own `SKY-S101` (HIGH) needs a credential-named variable, struct field or map
key assigned a literal value; a keyword inside a message, format string, flag
name, case label or environment-variable name is not a secret. A generic high-entropy value with no such name is
`HIGH` with `"severity_reason": "no_secret_name"`; the default gate still
counts it under `max_secrets`. Two other lower-certainty shapes are `HIGH`:
a password embedded in a connection URL
(`provider: url_credentials`, e.g. `postgres://app:<pw>@db/app`) and a
non-placeholder literal under a password/secret/token/api-key field in YAML,
JSON, TOML, INI, `.env`, `.properties`, `.tfvars`, `.npmrc` or `.pypirc` files
(`provider: config_credential`). Env-var and template references
(`${DB_PASSWORD}`, `{{ .Values.x }}`, shell `${TOKEN:?message}` and
`$(command)`; a `${TOKEN:-literal}` default is still checked), placeholders
(`changeme`, `<password>`, `your_password_here`) and secret *names*
(`existingSecret`, `secretName`, `password_file`) are not reported, and
previews are always fully masked.

Values that are public by structure are not reported as generic
high-entropy secrets, in `skylos . --secrets` and in `skylos done` alike:
hex digests that name their algorithm (`sha256:<64 hex>` in `integrity` or
`contentHash` fields; a bare hex value in an `integrity` field is still
reported), public keys and certificates (PEM `PUBLIC KEY`/`CERTIFICATE`
blocks whose body is DER, OpenPGP or SSH key data; `ssh-ed25519 AAAA...`
lines; the `x`/`y`/`n`/`e` members of a JSON Web Key), `0x` + 40-hex
contract and wallet addresses, ids in the path of Google Docs/Forms/Drive,
YouTube, Figma and Notion share URLs, CSP source and subresource-integrity
hashes outside lockfiles (`'sha256-<base64 digest>'`, `integrity="sha384-..."`
with a digest of the algorithm's exact length, unless a secret- or
session-named value holds it), parts of URLs other than user info,
secret-named query/fragment parameters (`api_key=`, `access_token=`, `sig=`,
`X-Amz-Signature=`) and webhook/bot/token paths, file paths (`/srv/x/y`,
`./a/b`, `C:\\x\\y`, `dir/name.ext`; not `ab/<token>` or a base64 value with
`+`/`=`), word slugs (`What-is-the-build-volume`, `INTRA-001-amendment-v2`),
lines of minified `.js` bundles over 1,000 characters, `&anchor`/`!!tag`
decorated values outside YAML files (`&mut DecompressionMatcherBuilder` in
Rust is a reference to a type), and, under a
secret-sounding name, a whole file path, a URL with no credential and no
random component, whole-value references
(`${{ secrets.X }}`, `${X}`, `$X`, `%X%`, `{{ .Values.x }}`; not
`${X:-literal}` or `|| 'literal'`), lists of environment variable names
(`GH_TOKEN,NPM_TOKEN`), the key's own name in another case
(`ADMIN_PASSWORD: "adminPassword"`), URLs assigned to `*_URL`/`*_URI`/
`*_ENDPOINT` names (the URL's own parts are still scanned) and Secret Manager
references (`NAME:latest`). In JS/TS test files (`*.test.*`, `*.spec.*`,
`__tests__/`, `__mocks__/`), Go test files (`*_test.go`) and test-fixture
directories (`testdata/`) only provider-shaped tokens are reported, as in
Python test directories. Minified and vendored front-end files (a `.min`
suffix, an average line length above 110 characters, or a library folder
under `static/` or `public/`) are skipped like other generated files and
named in the scan's skip line. A private-key header in prose, markup or
before a placeholder (`<code>-----BEGIN RSA PRIVATE KEY-----</code>`,
`\n...\n`) is not a key, nor is a key body cut short by an elision line
(`...`, `…`, `[...]`, `<snip>`); PKCS#8 (`-----BEGIN PRIVATE KEY-----`), encrypted PKCS#8 and
OpenPGP private keys are reported when key data follows the header.
Provider-shaped tokens (AWS, GitHub, GitLab, Slack, Stripe, Google,
SendGrid, Twilio) are never filtered by these shapes.

Descriptive `*_token` labels are also excluded from generic entropy
findings when the key has at least three words and the complete lowercase
literal restates every word in order, with ordinary spaces, slashes or hyphens.
One interior metadata qualifier, such as `model`, `input` or `type`, is
allowed; arbitrary extra words, prefixes, suffixes, digits and encoded
values and computed expressions are still scanned. Credential terms such as
`api`, `access`, `secret` or `password` prevent this exclusion. Spaces alone never exempt
a value: high-entropy passphrases and provider-shaped credentials remain
eligible for reporting. This behavior applies across the secret scanner's
supported source and configuration formats.

`SKY-S102` preserves the `SKY-S101` severity when it reclassifies a concrete
hardcoded credential; environment-reference exposure is `HIGH`.

## Security Contracts (SKY-SC)

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| SC001 | HIGH | Security contract regression | Diff-aware CI/CD review |

## Go-Specific Raw Rules (SKY-G)

The Go engine may emit `SKY-G` IDs. Cross-language equivalents are remapped to
`SKY-D` before normal reporting where possible.

| Go Output | Unified ID | Vulnerability |
|:---|:---|:---|
| SKY-G203 | SKY-G203 | Defer in loop / resource leak risk |
| SKY-G206 | SKY-G206 | Unsafe package usage |
| SKY-G207 | SKY-D207 | Weak MD5 |
| SKY-G208 | SKY-D208 | Weak SHA1 |
| SKY-G209 | SKY-D250 | Weak random source |
| SKY-G210 | SKY-D210 | TLS verification disabled |
| SKY-G211 | SKY-D211 | SQL injection |
| SKY-G212 | SKY-D212 | Command injection |
| SKY-G215 | SKY-D215 | Path traversal |
| SKY-G216 | SKY-D216 | SSRF |
| SKY-G220 | SKY-D230 | Open redirect |
| SKY-G221 | SKY-D252 | Insecure cookie flags |
| SKY-G226 | SKY-D226 | XSS: request input marked safe for `html/template` |
| SKY-G228 | SKY-D228 | XSS: request input written to an HTML response |
| SKY-G260 | SKY-G260 | Unclosed resource |
| SKY-G280 | SKY-G280 | Weak TLS version |
| SKY-G305 | SKY-D215 | Archive extraction path traversal |

## AI Defects

AI-defect grouping is based on finding category, not only the rule-ID prefix.
The CLI flag is `--ai-defects`, JSON reports use the top-level `ai_defects`
bucket, and individual findings use category `ai_defect`. Some hallucination
rules keep historical `SKY-L` or `SKY-D` IDs for compatibility with existing
suppressions, baselines, CI policies, and docs links; new AI-defect-only rules
use the `SKY-A` prefix.

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| A101 | MEDIUM | Test assertion weakening: a specific assertion replaced by a broad one, an exception assertion removed or loosened (`toThrow("message")` to `toThrow()`/`toThrow(/./)`/`not.toThrow()`, `pytest.raises` losing `match=` or widened to `Exception`, `assertRaisesRegex` to `assertRaises`), mocks or expected values broadened | Diff-aware tests |
| A102 | LOW | High-risk change without tests | Diff-aware PR signal |
| A103 | HIGH | CI permission expansion | GitHub Actions |
| A104 | MEDIUM | Public CLI surface drift | Diff-aware CLI |
| A105 | HIGH | Contract route guard missing | Python contract verify |
| A106 | LOW | Suspicious dependency version bump | Python manifests and lock files in Git changes |
| A110 | HIGH | Test deleted (`skylos done`): a test that existed at the base is gone and no moved, renamed or rewritten test replaces it (a pasted copy of a test that is still there never does), it lost literal parametrize/`.each` cases, it is left with no countable assertion, or it was overwritten in place by a test of something else while the code it tested is still there. Advice: a test renamed, merged or rewritten with a different body, fewer countable assertions, a new `return` before assertions, a deletion that goes with removed code (feature removal: a deleted module, export, function, method, object member, checked text, or a module the change stopped using) | Python and JS/TS tests |
| A111 | HIGH | Test newly skipped (`skylos done`): skip, skipif, xfail, `pytest.skip()`, `importorskip` or `skipTest` added to an existing test; for JS/TS `.skip`, `xit`/`xdescribe`, `.todo`, `.fixme`, `skipIf`/`runIf`, `.failing`/`.fails`, or a runtime skip, and any newly added focus (`.only`, `fit`, `fdescribe`), which stops the other tests in the file from running | Python and JS/TS tests (Jest, Vitest, Mocha, node:test, Playwright Test) |
| A112 | HIGH | Test settings loosened (`skylos done`): pytest selection options, `conftest.py` hooks that drop tests or rewrite results, coverage floors, CI test steps that may fail; Jest/Vitest ignore, exclude, `testMatch`/`testRegex`/`roots`/`include`/`dir` and `projects` changes that stop running existing test files, `passWithNoTests`, lower coverage thresholds, package.json test scripts that filter tests, may fail or no longer run a test runner. Not reported: a brand-new pytest config or a filter that leaves out no existing test file, a project's first `test` script, ignored tests that run in their own CI step, a new advisory CI step | pytest, coverage, Jest, Vitest, package.json, GitHub Actions |
| A113 | HIGH | Tests fail when Skylos runs them (`skylos done`), or an expected Python test did not run. Each failing test is rerun on the base commit and labeled with its failure origin (`preexisting`, `introduced`, `new_test` or `undetermined`); every failure still blocks unless `allow_preexisting_failures` is set | Any test command; JUnit XML for details |
| A114 | HIGH | Skylos settings or hooks changed (`skylos done`): protected paths, `[tool.skylos]`, the CI workflow that runs Skylos | Repository files |
| A115 | HIGH | Test answer hard-coded in code (`skylos done`): an added branch, `match`/`switch` case, conditional expression or lookup table answers one test assertion's literal input with that assertion's literal expected value (`if n == 3: return 6` for `assert factorial(3) == 6`), in a function that otherwise computes its answer, for an assertion that existed at the base. Advice: the same pattern for a test added in the change, a function that is only a table, a test that does not call the function, an input the code or docs already use, a word mapped to a word, an input a test passes with a different answer, small pairs a real edge case could produce, code in generated files or in a new script nothing imports or runs, a result that depends on a call count | Python and JS/TS non-test code; Python/JS/TS tests and JSON input/output test data |
| A116 | HIGH | Code detects the test run (`skylos done`): added non-test code reads the variables pytest sets while it runs (`PYTEST_CURRENT_TEST`), checks `"pytest" in sys.modules`, `sys.argv`, `sys._called_from_test` or the call stack for a test, reads `process.env.JEST_WORKER_ID`/`VITEST`/other variables a runner sets, `typeof jest`/`globalThis.vi` and other runner globals, `import.meta.vitest` outside an in-source test block, or opens the tests' own files. Advice: `NODE_ENV`/`import.meta.env.MODE` or an environment variable compared with `"test"`, and test files read by a new script nothing imports or runs or by repository tooling (`scripts/`, `tools/`, `bin/`, `.github/`, `validate-*`) that no production code imports. Test helpers, setup, config files and pytest plugins are left out | Python and JS/TS non-test code |
| A117 | HIGH | Comparison rigged to always pass (`skylos done`): added `__eq__` that always returns True or ignores the other value, `__ne__` always False, `__contains__` always True, JS `equals()`/`isEqual()` always true or ignoring its argument, `compareTo()` always 0, `valueOf()`/`[Symbol.toPrimitive]` returning a constant. Advice: constant ordering methods, constant `__hash__`, constant `__str__`/`__repr__`/`toString()` equal to text a test expects, wildcard classes such as `ANY` | Python and JS/TS non-test code |
| A118 | LOW | Inline suppression added (`skylos done`, advice): a comment or attribute on an added line of non-test code that tells a linter, type checker, coverage tool or scanner to look away: `# noqa`, `# type: ignore`, `# pyright: ignore`, `# pylint: disable`, `# nosec`, `NOSONAR`, `# pragma: no cover`, `eslint-disable*`, `@ts-ignore`/`@ts-expect-error`/`@ts-nocheck`, `istanbul`/`c8`/`v8 ignore`, `biome-ignore`, `//nolint`, `//lint:ignore`, `#nosec`, `#[allow(...)]`, `@SuppressWarnings`, `# skylos: ignore` and others. Says whether a reason is given and whether it covers a whole file. Also `_ = x` / `void x;` added only to hide an unused variable. Suppressions already at the base, moved or kept on an edited line, in test files or in generated files are not reported | Python, JS/TS, Go, Rust, Java/Kotlin, C# |
| A119 | HIGH | Linter or scanner settings weakened (`skylos done`, advice by default; blocks with `silenced_checks = "block"`): a rule ignored, disabled, turned off or lowered, a path excluded that holds checked source files, `strict` or a strictness flag turned off, a type-checking mode or level lowered, a preset or selected rule dropped, a secret or finding allow-listed. Paths holding only test files are advice; `skipLibCheck` and new rules are not weakening | ruff, flake8, pylint, mypy, pyright, bandit, tsconfig, ESLint, Biome, SonarQube, Semgrep, CodeQL, Snyk, gitleaks, detect-secrets, Trivy, OSV-Scanner, golangci-lint, Cargo lints, pre-commit, Checkstyle/SpotBugs suppressions |
| A120 | MEDIUM | Changed line not checked by tests (`skylos done`, advice by default): no test runs the line, or no test fails when Skylos deliberately changes it | Python with pytest |
| A121 | HIGH | CI check weakened (`skylos done`, advice by default; blocks with `silenced_checks = "block"`): a lint, type-check, format-check, scan or test step or job that can now fail without failing the build (`continue-on-error`, `\|\| true`, `--exit-zero`, `--max-warnings` raised, `allow_failure`, `when: manual`), was removed and nothing else runs that tool, is disabled (`if: false`, `when: never`), whose workflow no longer runs on pull requests, or that an aggregate job no longer needs | GitHub Actions, GitLab CI |
| A122 | MEDIUM | AI-reviewer settings changed (`skylos done` advice by default, blocks with `guardrail_tampering = "block"`; also in diff-aware scans): the change edits a file an AI code reviewer reads its instructions or settings from: `.coderabbit.yaml`, `.coderabbit.config.ts`, root `REVIEW.md`, `.cursor/BUGBOT.md` (any folder), `.cursor/config/bugbot.yaml`, `greptile.json`, `.greptile/`, `.gemini/styleguide.md`, `.gemini/config.yaml`, `.pr_agent.toml`, root `best_practices.md`, `.macroscope/`, `macroscope_approvability.md`, `.macroscope-ignore`, `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/skills/`, `.bito.yaml`, `.ellipsis/code-review.yaml`. The message names each changed setting and says which branch the reviewer reads (Copilot, CodeRabbit, Macroscope and Bito read the pull request's head). Changes that narrow the review come first: exclusions or ignore patterns added, review or a review tool turned off, a higher comment threshold, fewer comments, a quieter profile, approval turned on, added "do not flag"/"ignore"/"approve" instructions. In root `AGENTS.md`/`GEMINI.md` and any `CLAUDE.md`, which Copilot code review and Claude Code Review also read, only added lines aimed at the reviewer count. Not reported: edits to comments, whitespace, formatting, key or line order, or reformatted YAML/JSON/TOML with the same settings, or a skill moved between `.github/skills/`, `.agents/skills/` and `.claude/skills/`. Findings are kept by `--diff` off added lines, run when no supported source file changed, and are not hidden by a local baseline | Any repository |
| A125 | MEDIUM | Scanner suppression marker added (`skylos done` advice by default, blocks with `guardrail_tampering = "block"`; also in diff-aware scans): a comment on an added line that tells a code-scanning platform to stop reporting: DeepSource `skipcq`, JetBrains/Qodana `noinspection`, Qlty `qlty-ignore`, CodeScene `@codescene(disable...)`, CodeQL alert-suppression `codeql[...]`/`lgtm[...]`, Checkov `checkov:skip=`, Trivy `trivy:ignore:`/`tfsec:ignore:`, KICS `kics-scan`; and `NOSONAR`/`nosemgrep` in languages SKY-A118 does not read (PHP, Ruby, Swift, Scala, Dart, C/C++, shell, Terraform, YAML, SQL and others). Says what stops being reported (line, next statement, function, resource block or file) and whether a reason is given. Not reported: markers SKY-A118 covers, markers in strings or documentation, `NOSONAR` on a comment-only line (prose), prose mentions of `noinspection` or `qlty-ignore` without their directive form, markers moved or kept on an edited line, test files in any language (counted), generated and vendored files. Not covered: Snyk Code `deepcode ignore` (undocumented) and Codacy (no marker of its own) | Any language with comments |
| A135 | MEDIUM | Code left unused by the change (`skylos done`, advice by default; blocks with `branch_orphans = "block"`): a function, method or class (or a JS/TS file) that production code used at the base and that no production code calls at the head, most often in a file the change did not touch, where line-based diff checks never look. The message names the removed or changed line that called it (``"`price_label` (not touched by this change) lost its last caller when app/checkout.py:6 changed"``) and says when only tests still call it. Liveness comes from the dead-code engine with test files left out on both sides (confidence 75 or more). A symbol the engine abstains on (for example a weak helper name) is still reported, as advice that never blocks, when a removed line used it and no static reference is left. Not reported: code already unused at the base, code moved with its callers, renames whose callers were all updated, and anything whose name appears in a file the analyzer could not parse or in a template or configuration file (counted as not judged) | Languages the dead-code engine covers: Python, JS/TS, Java (private and package-private members), Kotlin (private members), Go (unexported, needs the skylos-go engine), PHP, Rust and others; an engine that is not installed is listed as not checked |
| A136 | LOW | New code nothing calls (`skylos done`, advice; blocks with `branch_orphans = "block"`): a function, method, class or JS/TS file the change added that nothing calls, or whose only callers are themselves unused. Entry points, framework roots (routes, views, fixtures, commands), exported public API and dispatch the dead-code engine recognizes are alive; a definition moved or renamed from elsewhere in the change is not new; a name that appears in a template or configuration file, or a symbol a decorator may register (`@app.route(...)`, `@bus.subscribe(...)`, a Java annotation), is not judged | Languages the dead-code engine covers: Python, JS/TS, Java (private and package-private members), Kotlin (private members), Go (unexported, needs the skylos-go engine), PHP, Rust and others; an engine that is not installed is listed as not checked |
| A137 | LOW | New code only tests call (`skylos done`, advice even with `branch_orphans = "block"` unless listed in `branch_orphans_block_rules`): a symbol or JS/TS file the change added whose only callers are test files ("added `foo()` and a test for it, and no production caller"). The message names the test. Test files: `tests/`, `test_*.py` using a test framework, `conftest.py`, `*.test.*`/`*.spec.*`, `__tests__/`, `*_test.go`, `src/test/` | Languages the dead-code engine covers: Python, JS/TS, Java (private and package-private members), Kotlin (private members), Go (unexported, needs the skylos-go engine), PHP, Rust and others; an engine that is not installed is listed as not checked |
| L012 | CRITICAL | Phantom function, import, or module-member reference | Python, TS/JS, Go, Java |
| L023 | CRITICAL | Phantom decorator | Python |
| D222 | CRITICAL | Dependency hallucination (imports and manifests; Go modules are looked up on the module proxy with its case-encoding, `github.com/!burnt!sushi/toml`) | Python, manifests (`go.mod`, `package.json`, requirements) |
| D224 | HIGH | API signature hallucination | Python |
| D225 | HIGH | Dependency version hallucination | Python, npm, Go |

Python import names can differ from distribution names. Skylos maps declared
distributions to import paths from installed distribution metadata, a curated
table of well-known mismatches (`beautifulsoup4` -> `bs4`, `djangorestframework`
-> `rest_framework`, `PyYAML` -> `yaml`, `Pillow` -> `PIL`), the pipreqs table
and conservative name rules (`django-guardian` -> `guardian`), then checks
bounded PyPI wheel indexes for the rest. Requirements files are read like pip
reads them: `-r`/`-c` includes inside the project, `\` continuations and
`--hash` options (pip-compile and `uv pip compile` lock files). Declared
dependencies come from requirements files, `pyproject.toml` (dependencies,
optional dependencies, dependency groups, Poetry), `setup.cfg` (`[options]`
`install_requires`/`setup_requires`/`tests_require`, `[options.extras_require]`,
`file:` requirement lists inside the project) and literal `setup.py` keywords
(including module-level lists). These files are parsed, never run; a
`setup(**kwargs)`, `attr:` or computed list leaves the declarations open-ended.
Nested projects use their own manifests.
Namespace packages require the imported portion's full path: a distribution
providing `sphinxcontrib.applehelp` does not establish
`sphinxcontrib.serializinghtml`. Target packages are never installed or executed.
`setuptools` and other build-backend imports in `setup.py` are not runtime
dependencies.

A missing PyPI project for an import name alone does not prove a hallucinated
dependency. "Could not verify" is never a finding: when a declared provider that
is related to the import (by name, mapping or partial inventory) is source-only,
private, dynamic, unsupported or unavailable, or the declarations are open-ended
(private index, dynamic metadata), the import is only counted in
`analysis_summary.dependency_imports`. An import that no declared distribution
resembles stays visible: MEDIUM `SKY-D223` "Possible hallucinated import" while
some declared distributions are uninspected, `SKY-D222` once all are. Installed
metadata naming a different, undeclared distribution is reported as an
undeclared import. An exact compatible pin with an unambiguous artifact
inventory can support absence evidence. Compatible platform wheels can confirm import paths
they contain, but cannot prove an import is absent, even with an exact pin.
Editable-install inventories can use compatible wheel paths as positive
evidence, but their incomplete RECORDs cannot prove that an import is absent,
even with an exact pin. Provider inventories and registry
answers are reused within the current analysis, and
repository cache files are not accepted as trusted evidence. Provider checks do
not resolve lockfiles into a deployed environment.

Additional Python environment definitions can supply positive declaration
evidence: plain Pipfile `[packages]` entries, `environment.yml`/`environment.yaml`
dependencies, supported straight-line setup-script installs and the unambiguous
final Dockerfile stage that copies the code. A nearer Python manifest sets the
environment boundary. Conditional shell execution, install-target changes and
ambiguous build stages do not establish that an import is provided. These files
are read as bounded text, never executed or installed; unsupported shapes
retain the normal import check.

A single unambiguous Compose configuration can also declare packages for the
exact Python file named by a service's command. The supported shape uses a
literal read-only repository mount, a selected official Python Dockerfile stage
and straight-line `python -m pip install` commands, optionally with literal
versions sourced from a copied `.env` file. This evidence applies only to that
entry file, not its siblings or imports. Overrides, interpreter changes and
unsupported build or runtime configuration retain the warning. Sourced shell
settings that change word splitting and alternate service launchers whose
environment cannot be resolved also retain it. This affects
undeclared-import checks (SKY-D223); it does not clear SKY-D222 hallucinations,
verify an installed image or change dependency vulnerability checks.

A distribution that a declared one requires unconditionally also provides its
imports (SKY-D223 only, never a hallucination): an edge recorded in the nearest
`uv.lock`, `poetry.lock` or `pdm.lock` (with the extras the lockfile's project
entry requests), or the `Requires-Dist` of an installed declared distribution
whose version satisfies the declaration. A locked package no such edge reaches,
an edge under a marker, an extra nobody requests and the project's own lock
entry do not count. Test, example and benchmark code that an explicit pyproject
package selection (setuptools `packages`/`packages.find`/`py-modules`, hatch
wheel `packages`/`only-include`, Poetry `packages`) does not ship has no
declared dependency scope, so a missing declaration there is not reported; a
hallucinated import still is. Automatic discovery, glob patterns, a requirements
file, `setup.py`/`setup.cfg` or an environment definition in scope keep the
normal check, and so does unshipped code outside test, example and benchmark
directories (a root-level `app.py`).

SKY-D224 rejects explicit keyword arguments that are not parameters of the
installed API's known signature (for example `jwt.encode(..., expires_in=...)`
with PyJWT). The inspected packages default to `requests`, `pandas`, `boto3`,
`openai` and `jwt`. Keyword checks are skipped when the signature is
unavailable. APIs accepting `**kwargs` remain supported, and
dynamic `**payload` contents are not inferred.

SKY-A106 warns when a dependency version change exactly matches the project's
own old and new versions in the same change. For example, a release from
`3.4.1` to `3.4.2` that also changes `inquirer==3.4.1` to `inquirer==3.4.2`
deserves a check. This is an advisory, not proof that the dependency version is
invalid. It does not query package registries or change dependencies.

Run `skylos . --ai-defects --diff-base origin/main --format json` for committed
PR changes, or omit `--diff-base` to compare local files with HEAD. PR checks
compare the merge base with HEAD and do not include uncommitted edits. Existing
gate thresholds still apply; the finding recommends review rather than blocking.

The initial rule supports literal project versions in `pyproject.toml` and
`setup.py`, dependency declarations in those files and requirements files, and
package versions in `uv.lock` and `poetry.lock`. It includes version exclusions
such as `!=3.4.1`, skips project self references, and keeps nested projects
separate. Dynamic project versions and other manifest formats are not inferred.
To disable this advisory, add `SKY-A106` to `[tool.skylos].ignore`. This rule
uses project ignores, not inline comments, consistently across supported files.

## Logic and AI-Code Mistakes (SKY-L)

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| L001 | HIGH | Mutable default argument | Python |
| L002 | MEDIUM | Bare `except` block | Python |
| L003 | LOW | Dangerous comparison (`== True`, `== False`, `== None`) | Python |
| L004 | MEDIUM | Anti-pattern try block / too broad scope | Python |
| L005 | LOW | Unused exception variable | Python |
| L006 | MEDIUM | Inconsistent return paths | Python |
| L007 | MEDIUM-HIGH | Empty error handler | Python, TS/JS |
| L008 | MEDIUM | Missing resource cleanup: an `open`/connection/socket/session not in a `with`, including inside `if`/`for`/`while`/`try`/`except`/`finally`/`match` blocks. Not reported when closed on the next statement or in a `finally` that encloses the open or runs after it (a `finally` before the open closes an earlier handle), entered by the next `with`, returned or yielded (also inside a wrapper such as `return Reader(f)` or `ctx.wrap_socket(s)`; a `Reader` class defined in the same module must store, close or pass on `f` in its `__init__`), stored on an attribute or container, registered with `enter_context`/`callback`/`addCleanup`, or assigned to `self.x` when the same class, a base or a subclass closes `self.x`, or any code closes `x` on another receiver such as `conn.x.close()` (also after taking it off the object, as in Flask's `g.pop("db").close()` teardown); statements inside another `with` block are not checked | Python |
| L009 | LOW-HIGH | Debug leftover | Python |
| L010 | MEDIUM | Security TODO/FIXME marker left in code | Python |
| L011 | MEDIUM-HIGH | Disabled security control | Python |
| L013 | HIGH | Insecure randomness for security values | Python |
| L014 | HIGH | Hardcoded credential in code | Python |
| L016 | MEDIUM | Undefined config / ghost feature flag | Python |
| L017 | MEDIUM | Error information disclosure | Python |
| L020 | HIGH | Overly broad file permissions | Python |
| L021 | HIGH | Security control regression | Diff-aware review |
| L024 | HIGH | Stale mock target | Python |
| L026 | MEDIUM | Unfinished code or placeholder default | Python, TS/JS |
| L027 | LOW-MEDIUM | Duplicate string literal | Python |
| L028 | MEDIUM | Too many return statements | Python |
| L029 | MEDIUM | Boolean positional parameter trap | Python |
| L030 | HIGH | Broad exception with trivial handler | Python |
| L031 | MEDIUM | Missing network timeout | Python |
| L032 | MEDIUM | Mock or placeholder production data | Python |
| L033 | MEDIUM | No-effect statement | Python |
| L034 | MEDIUM | Repeated mutable alias from sequence multiplication | Python |
| L035 | HIGH | File-wide blanket ESLint disable | TS/JS |
| L036 | LOW | Import repeated inside function | Python |
| L037 | LOW | Conditional returning bool literals | Python |
| L038 | LOW | Conversion call inside f-string | Python |
| L039 | LOW | Except clause that only re-raises | Python |

SKY-L006 accepts an explicit `return None` next to value returns (PEP 8); only a
bare `return` is inconsistent. SKY-L014 does not treat raw `${NAME}` or
`{{ name }}` strings under credential names as safe: Python does not expand
them, and they can become the literal password. Reference forms are accepted
under location names with no credential word, such as `DATABASE_URL`, `DSN`
or `CONNECTION_STRING`, unless a credential use establishes otherwise.
A name such as `APP_URL_KEY` and matching value `"APP_URL"` does not by itself
establish a credential. A resolved credential use still takes precedence over
a setting-key use. SKY-L016 is
not reported when the read declares a default other than
`None` (`os.getenv("ENABLE_X", "False")`).
An exact module-level declaration such as
`ENABLE_X = os.getenv("ENABLE_X")` also defines that external setting.
This says nothing about whether enabling the setting is secure; unrelated
environment reads and differently named assignments retain their checks.

SKY-L001 accepts an empty literal default used exclusively to construct fresh
copies through a supported, unmodified constructor. The proof checks imports,
shadowing, parameter uses and constructor replacement. Mutation, alias escape,
nested captures, nonempty shallow copies and uncertain constructor identity
retain the finding; ordinary unused mutable defaults are still reported.

SKY-L014 distinguishes credential names from ambiguous names ending in `_key`.
Credential-use or secret-literal evidence distinguishes known credentials from
ambiguous keys. Being exported, stored in a field, or used as a default is not
credential evidence. Static project import and reexport resolution connects
literal sources to credential consumers across files; a benign routing,
lookup or statistics use never cancels a credential use of the same source.
The same evidence checks apply to assignments,
annotated assignments and argument defaults. Conditional writes retain
possible credential sources; an uncertain overwrite cannot establish safety.
Lookup fallbacks follow their actual argument contracts: the attribute name in
`getattr(obj, "password", "")` is not a password. Anonymous FTP defaults
remain reviewable: one anonymous consumer cannot prove that every use is
public, or that a request cannot override only the username.

SKY-L024 checks module bindings without importing the target. Annotated values
and destructured assignments define valid patch targets, as do bindings in
evaluated definition headers. Explicit `create=True` allows a missing target.
Unresolved dynamic module attributes do not establish that a target is missing.

SKY-L026 recognizes resolved abstract/overload declarations and stub files.
An empty body alone does not establish an unfinished implementation. A body
finding requires an explicit local unfinished marker, a return-contract
mismatch, or evidence of an ineffective runtime security contract. Empty
FastAPI Security dependencies and placeholder results that bypass a denial
branch remain visible; uncertain wrappers or bindings require verification.
Optional hooks, null implementations,
matching empty return values and bare `NotImplementedError` are legitimate.
Unsafe Ellipsis defaults remain independently reportable. Silence for an
unknown empty hook does not certify that required side effects are present.

SKY-L033 does not assume that arithmetic, membership or overloaded operators are
free of effects. Small literal expressions can be checked without executing
target code; deliberate exception probes remain valid. Discarded comparisons,
including ordering checks, still merit review for an intended assertion or
branch; their diagnostic does not claim that overloaded operands are pure.

SKY-L036 to SKY-L039 are optional style advice. Their complete records stay
in JSON with listing metadata; `--all-advice` or an explicit rule selection
shows them and includes them in the gate. Explicit gate rule configuration
also includes them; they stay out of the default gate otherwise.

SKY-L036 to SKY-L039 report roundabout code that has a direct
form, and only when the file proves it and the suggested rewrite keeps the
behaviour. A builtin (`str`, `repr`, `isinstance`, ...) counts only when
the name resolves to the builtin in that scope, so a local `def str`, a
parameter or an assignment turns the check off. Golden test fixtures (input
and `# output` data a test reads as text) are not code and are skipped. When
the project's nearest ruff configuration ignores the ruff rule that suggests
the same rewrite (SIM103, SIM210 and SIM211 for L037, RUF010 for L038, TRY203
for L039), globally or for the file, the maintainers have already declined it
and the check stays silent; inline `noqa` comments still do not suppress these
findings. SKY-L036 reports an import inside a function that repeats an earlier
unconditional module-level import binding the same module object to the same
name: `import m` (one object per module in `sys.modules`), or
`from pkg import sub` when `sub` is a module file of a project package. A
function, class or constant imported with `from m import n` is not reported,
because a later import reads `m.n` again and tests patch it (`mock.patch`) on
purpose. Imports under `if TYPE_CHECKING`, `try`/`except ImportError` or other
blocks do not count, nor do names bound twice, declared `global`, exposed to
`globals()`/`exec`, or bound again in the function or an enclosing one, nor
modules this file writes through, passes to `setattr`-style calls or
`reload`s. Test and sample code is not checked, nor is a file that reads
function source (`inspect.getsource`), since it may run those functions
elsewhere where module imports do not exist. SKY-L037 reports
`True if c else False`, its negation and `if`/`else` blocks that return or
assign opposite bool literals; links of an `elif` chain are left alone. It
suggests `bool(c)` unless `c` is always a bool (`is`, `in`, `not`,
`isinstance`, `hasattr`, `any`, ...): `==` and ordering comparisons can be
overloaded to return other values (numpy arrays, SQLAlchemy expressions).
`False if a == b else True` and other negated comparisons of that kind are not
reported: `a != b` need not be the opposite, and `not (a == b)` is itself a
lint finding. SKY-L038 reports `{str(x)}`, `{repr(x)}` and `{ascii(x)}`
fields, which `!s`, `!r` and `!a` replace. SKY-L039 reports the trailing except
clauses of a `try` whose only statement is `raise` (or `raise e` of the caught
name); an earlier re-raise that keeps a later handler away is not reported, nor
is `except*`, nor clauses with a comment in them (a documented placeholder).

## Quality, Structure, Architecture, and Performance

| ID | Severity | Name | Languages / Scope | Threshold / Notes |
|:---|:---|:---|:---|:---|
| Q301 | WARN-HIGH | Cyclomatic complexity | Python, TS/JS, Java, Go | default >10 |
| Q302 | MEDIUM | Deep nesting | Python, TS/JS, Java, Go | default >3 |
| Q305 | MEDIUM | Duplicate condition / duplicate branch body | Python, TS/JS | control-flow correctness |
| Q306 | MEDIUM | Cognitive complexity | Python | Boolean operator sequences and control-flow nesting |
| Q401 | HIGH | Async blocking call | Python | blocking calls inside async code |
| Q402 | LOW | Await in loop | TS/JS | review bounded parallelism only when iterations are independent and ordering/rate limits allow |
| Q403 | HIGH | Inconsistent lock acquisition order | Python | potential deadlock from reversed lock order in nested or compound `with` / `async with` statements; includes non-adjacent pairs |
| Q404 | MEDIUM | Thread shared state mutation | Python | thread target mutates module state without an obvious lock |
| Q405 | HIGH | Async Promise executor | TS/JS | `new Promise(async ...)` ignores the executor's async result |
| Q406 | HIGH | Async callback passed to built-in `Array.forEach` | TS/JS | callback promises are not awaited |
| Q407 | HIGH | Discarded result from built-in `Array.map(async ...)` | TS/JS | mapped promises are not consumed |
| Q501 | MEDIUM | God class | Python | excessive methods or attributes |
| Q502 | MEDIUM-HIGH | God file | Python | excessive file size / definitions |
| Q701 | MEDIUM | High coupling | Python | resolved dependency edges; sharing an abstract base does not create sibling dependencies |
| Q702 | MEDIUM | Low cohesion | Python | LCOM-style signal |
| Q801 | MEDIUM | High architectural instability | Reserved | no current finding emission |
| Q802 | ADVISORY by default | Distance from main sequence | Python, TS/JS | included in actionable quality only with `enforce_iad = true` |
| Q803 | ADVISORY by default | Zone of Pain / Zone of Uselessness | Python, TS/JS | grouped with Q802 per module by default |
| Q804 | MEDIUM | Dependency Inversion Principle violation | Python, TS/JS |
| Q805 | MEDIUM | Architecture layer policy violation | Python, TS/JS |
| C303 | MEDIUM | Too many arguments | Python, TS/JS, Java, Go | default >5 required / >10 total; Python compares required positional arguments (keyword-only arguments count toward the total only) and accounts for implicit receivers |
| C304 | MEDIUM | Function too long | Python, TS/JS, Java, Go | default >50 lines; Python counts code lines (blank, comment-only and docstring lines excluded); direct test and suite callbacks in TS/JS test files are excluded |
| C401 | MEDIUM | Duplicated implementation fragments | Python |
| P401 | LOW | Potential unbounded `read()` / `readlines()` | Python |
| P402 | LOW | Memory risk: resolved `pandas.read_csv` without a chunk or row bound | Python |
| P403 | LOW | Repeated iterable scans in nested loops | Python / generic | an inner collection repeatedly searched for the outer item (equality, membership or a predicate relating both items); exclusions require evidence of bounded work, partition traversal or required output for every pair |
| P404 | MEDIUM | Unbounded SQLAlchemy-style ORM `.all()` query | Python |
| T101 | LOW | Missing public parameter type annotation | Python |
| T102 | LOW | Missing public return type annotation | Python |
| T103 | MEDIUM | Chained assertion through `any`, `unknown`, `object`, or `{}` | TypeScript |
| T104 | MEDIUM-HIGH | Effective `@ts-ignore` or file-wide `@ts-nocheck` | TS/JS |
| T105 | MEDIUM | Unvalidated JSON result asserted as a domain type | TypeScript |
| T106 | MEDIUM | Unsafe exported API type | TypeScript |
| F101 | MEDIUM | FastAPI response model / return typing practice | Python |
| F102 | MEDIUM/HIGH | Framework route auth guard or defeated ownership check; privileged action routes are SKY-D283 | Python |
| R101 | MEDIUM | Repository missing Python type-check command | Repo policy (advice: listed after Defect/Review findings, never in the first-screen measurements, the Risk headline or a concise exit code on its own) |
| R102 | MEDIUM | Repository missing Python lint command | Repo policy (advice: listed after Defect/Review findings, never in the first-screen measurements, the Risk headline or a concise exit code on its own) |
| R103 | MEDIUM | Repository missing Skylos quality gate | Repo policy (advice: listed after Defect/Review findings, never in the first-screen measurements, the Risk headline or a concise exit code on its own) |
| R104 | MEDIUM | Repository missing pre-commit config | Repo policy (advice: listed after Defect/Review findings, never in the first-screen measurements, the Risk headline or a concise exit code on its own) |
| R105 | LOW | Repository missing TypeScript type-check command | Repo policy | recognizes `tsc` and Next builds with type errors enabled |
| CIRC | LOW | Circular dependency between modules (top-level imports). A design finding: severity does not grow with cycle length | Python |

T101/T102 report missing public-signature annotations required by an applicable
declared mypy policy. `strict` and `disallow_untyped_defs` require complete
signatures; `disallow_incomplete_defs` applies only to definitions that already
have signature typing intent. Checker presence, `check_untyped_defs`, a partial
signature, a typed sibling or a typing import alone establishes no requirement.
Missing annotations are LOW-priority policy or coverage advice, not type errors.
Valid function and parameter type comments
count as contracts alongside inline annotations. Supported mypy settings include
the standard project config precedence, literal file/directory selections,
structured module overrides and inline options. Package markers and declared
package bases determine module identity; directory names alone do not. Checked-in
literal mypy commands can replace a default file selection, with supported
allow/disallow annotation flags and `--strict` taking precedence over global
config; output-only flags and literal `--platform` / `--python-version` values
do not change file selection. Missing, invalid or dynamic values remain unknown.
Command discovery reads tox
command values (including `{posargs:DEFAULT}` defaults and `{[section]key}`
references), Make recipes and workflow `run` entries; environment names and
workflow titles do not establish checker scope. Non-root or unknown Tox/workflow
working directories and directory-changing shell blocks do not establish
root-relative selections. A strict setting with neither a
`files` selection nor a discovered invocation has unknown scope. An explicit
`allow_incomplete_defs` without a required-annotation setting is an opt-out.
An applicable `ignore_errors` also disables annotation-policy advice unless
the effective inline policy explicitly re-enables diagnostics.
Unsupported or unresolved policy contributes coverage information rather than
default per-function advice. Standard `.pre-commit-config.yaml` selections can
establish scope for the official `pre-commit/mirrors-mypy` hook with explicit
arguments, or a local hook whose entry directly invokes mypy. Global and hook
file filters, supported Python type filters, argument overrides and exclusions
determine applicability. Hook scope uses the declared project root for a
standalone source tree; an enclosing Git root, when present, must match it.
A nested project's config is not silently treated as the parent repository's
default hook config. Historical reads require the reader's matching Git root
context instead of current filesystem metadata.
Filename passing and supported file-bearing stages
must be established; manual-only hooks and filename-less invocations remain
unknown. Implicit mirror defaults establish ordinary `.py` selection only;
stub selection needs explicit supported type filters. Unknown providers,
wrappers or unsupported filters do not add a
requirement or erase independently established policy.
Extra files or directories named in hook arguments are not independently
inferred as policy scope outside the hook's filename selection.
Non-mypy checker policy formats are not interpreted as mypy requirements.
Pyright's missing-parameter and unknown-type diagnostics have different
semantics, and its strict mode does not require return annotations on all functions.
Those settings must not enable both T101 and T102 through a generic strict flag.
Diff comparisons read policy at the base
revision rather than applying the current checkout's policy to old source.
The rules exclude pytest fixtures resolved from imports and test-support
helpers reached from a non-root conftest suite when no production importer is
found; modules imported by a non-test package `__init__` are production code.
Test folders are judged relative to the project root. A directory named `t`
alone does not establish that role. Shared helpers
retain applicable policy advice. This typing-only scope does not filter security findings.

A complete literal `__all__` limits T101/T102 to the module's exported
functions and classes. Set `[tool.skylos] typing_coverage_advice = true` to opt
into optional API coverage advice. Optional advice requires a source-declared
boundary: a stable explicit export or an import-proven interface declaration.
Public spelling alone, dynamic/mutated exports, unknown decorators and replaced
owners are insufficient. Complete proven overloads and exact compatible sibling
stubs can supply the optional caller contract; explicit implementation-annotation
requirements still take precedence. Inherited/re-exported contracts and arbitrary
runtime class construction are not resolved by this bounded check.
Concrete procedures with
only implicit, bare or literal `None` returns do not receive redundant T102
advice unless an applicable mypy policy explicitly requires annotations.
Decorators, generators, abstract placeholders and unknown value returns do not
establish that inference. Missing parameter annotations remain independent.
T101/T102 on the same unambiguous function share one human entry, retaining both
original records in JSON and gate inputs. Coverage is separately disclosed in
`analysis_summary.typing_coverage` and one terminal summary. Its denominator is
public source definitions (including overload declarations), not runtime
callables; explicit missing annotations can coexist with a supplied stub or
overload contract. `--all-advice` expands generated advice but does not enable
optional annotation checks; use `typing_coverage_advice` for that opt-in.

Python C303, Q501 and Q702 resolve implicit receivers and distinguish instance,
class and static methods. Nested functions have their own bindings; captured
receivers and local aliases contribute to the owning method. Unknown decorators
leave receiver binding uncertain. C303 reports only when the minimum number of
required positional arguments exceeds its threshold; keyword-only parameters
count toward the total-parameter threshold only. Q501 does not count dunder
protocol methods toward its method threshold. Q702 checks possible receiver
connections before reporting disconnected implementation groups and includes
bounds for uncertain bindings. Methods connect through shared attributes, calls,
bound-method references (`self.m` passed as a callback or a property read),
constructor calls (`cls(...)`, `type(self)(...)`) to `__init__`/`__new__`, and
implicit dunder use (`len(self)`, `self[k]`, `k in self`, iteration, truth
tests, f-strings). A method that passes bare `self` out or writes attributes
dynamically has uncertain connections. Empty declarations (`pass`, ellipsis,
docstrings, or a proved builtin `NotImplementedError` stub) do not form
implementation groups, and Protocol classes and fully abstract ABCs are not
measured. A method that touches no receiver state is not a group on its own,
and a report needs at least two groups that each use attributes the class
assigns. Raw declared graph components remain available separately as
`declared_lcom4` in findings. These measurements alone do not prove that a
class should be split.

Q501 excludes proven declaration-only records, while unknown descriptors,
decorators and inherited constructors remain measured. Q702 distinguishes
immutable, read-only class configuration from owned mutable instance state;
writes and uncertain values retain the ordinary cohesion checks. Q701 resolves
class identities and shadowing in their lexical scope. Its incoming dependent
count is file-local, not a project-wide coupling measurement. Q804 excludes
proven import/export-only facades from concrete-collaborator advice; dynamic
exports and runtime consumers remain subject to the check.

Q501 reads pytest's configured `python_classes` patterns without executing the
project, and recognizes collected classes only in evidenced test modules.
Quality scope also reads root pytest TOML/INI settings for `python_files` and
`python_functions`, including native `[tool.pytest]`. Custom paths require a
matching file pattern and actual collected functions or classes; `testpaths`
alone does not establish test code. Configuration is selected by pytest's
precedence without merging, and invalid or symlinked files add no exemptions.
Fixture-only files, collection opt-outs and unresolved class inheritance add no
new exemptions. Existing convention-based scope remains available independently.
Typing advice (T101/T102) uses the same guarded configured-test evidence, so
custom collected filenames are not treated as public library APIs. Unknown
function decorators, rebound or shadowed pytest aliases and patched marker
names cannot establish configured collection evidence. This quality-only
classification does not change security or dead-code scope.
When `testpaths` is configured, a broad `python_files` pattern alone cannot
exempt production files outside those root-discovery selections. Unknown or
escaping selections add no test-only evidence; conventional test rules remain
independent.
Import-proven `typing.overload` signatures with a concrete implementation in
the same class do not add runtime methods; property accessor counting is
unchanged. Ordinary helpers and uncertain decorator bindings remain measured.
Q502 counts consecutive, import-proven overload declarations and their runtime
implementation as one callable; `.pyi` overload groups need no implementation.
Raw `code_lines` remains an inventory measurement. Q502 uses
`implementation_code_lines` for its size threshold, excluding literal catalog
spans and proven declaration-only classes; unknown declaration mechanisms and
behavioral code remain measured. Literal catalogs receive the same exclusion
at module and class scope; computed catalogs and method bodies remain measured.
C303 reports one warning per such group,
preserving the strongest violation and each signature's parameter layout in
`overload_signatures`. Custom decorators and incomplete runtime groups retain
their separate measurements.

Design, size and memory advice (C303, Q501, Q502, Q702, C401, P401, L027 and
L029) is not reported for test, example, benchmark, documentation-build or
packaging-script code: files the project-relative test convention identifies,
`test_*.py`/`*_test.py` modules that define test functions, `examples`/
`benchmarks` folders, a top-level `docs`/`doc` folder and the root `setup.py`.
This scope does not filter security, secret or correctness findings. C304 still
applies to tests. C304, Q502 and C401 count code lines: blank lines,
comment-only lines and docstrings are excluded. C401 also requires at least
four statements in each fragment body and names members by project-relative
path.
C401 distinguishes test-suite helper imports from production importers and
preserves helpers reached by production, including package initializers.
Clone normalization uses an independent AST for each fragment, preserves literal
types and variable binding relationships, and keeps external API names and
member selectors distinct. Identifier normalization consistently renames proven
local bindings within their lexical scopes. Original function arguments remain
part of the unnormalized candidate identity, so identical bodies with different
positional bindings do not bypass the binding comparison.
Test-data input/expected-output pairs require a matching text-reader harness
before their clone groups are excluded. These branches apply to clone advice;
security and correctness rules still analyze those files.
T101 does not prescribe annotations for a possibly implicit method receiver;
proven static methods and free functions retain their first ordinary parameter.

P401 reports `read()`/`readlines()` calls that request everything: no size,
`None`, a negative size or `readlines(0)`, including sizes resolved from simple
local constants. A caller-chosen size is a bound by construction, so chunked
reads are not reported. Resolved `open(...)` receivers get file-specific advice.
`read()` on a proven standard-library `io.BytesIO`/`io.StringIO` receiver is
not reported, including synchronous `with` bindings to that same buffer.
The proof checks imports, aliases, method replacement and
visible field writes or object exposure; an earlier buffer assignment alone
does not establish the receiver's current type. Unbounded buffer `readlines()`
can allocate a new list and is reported with that explanation, unless the
contents are a fixed literal with no growth or escape. Other whole reads
remain LOW advice; the rule cannot know the source's size, and some consumers
need the whole value.
Lambda bodies are expression scopes. Resolving a captured read size considers
enclosing bindings without iterating the lambda's expression as statements;
unknown or shadowed sizes retain the ordinary P401 behavior.

P401 does not recommend chunking a direct read passed to a resolved whole-buffer
consumer: builtin `compile`, or standard-library `ast.parse`, `json.loads`,
`tomllib.loads`, `pickle.loads`, `marshal.loads`, `gzip.decompress` and
`zlib.decompress`. It also recognizes a direct returned read, optional `await`
or `.decode()`, in a nondecorated callable with a stable builtin `str`/`bytes`
return annotation, including supported optional/union aliases. Unknown helpers,
rebound types and read-then-process bodies retain advice. These contracts make
the chunking suggestion inapplicable; they do not prove that memory is bounded
or suppress separate security or resource findings.

P402 resolves pandas imports and aliases before advising on `read_csv`.
An unrelated object's same-named method is not evidence of pandas. A positive
`chunksize`, nonnegative `nrows` or caller-supplied row budget establishes a
bound for this advice; explicit `None` and nonpositive chunksizes do not.
With current project context, known local pandas providers and uncertain
filesystem paths do not establish the external pandas API. Provider checks use
metadata only. Source-only and historical readers retain their import evidence
instead of consulting another revision's filesystem.

L029 recommends named Boolean arguments and makes a keyword-only rewrite
conditional on the public or callback contract permitting it. `@overload`
stubs, `@override` methods, methods overriding a same-module base method and
functions used as values (callbacks, registrations, dispatch entries) are not
reported. Private and nested functions are reported only when a call in the
module passes a Boolean literal positionally, and the message names that call. A literal Boolean default remains independent signature
evidence even when an annotation contradicts it; the annotation does not enforce
runtime values. Definition-level advice does not establish an actual ambiguous
positional call, and changing an inherited or callback signature needs separate
compatibility evidence.
Positional-only Boolean parameters receive advice that does not suggest an
impossible named call. A private-method call requires a resolved receiver;
an unrelated object's same-named attribute is not evidence for that method.
Public signature findings also retain observed calls in `call_evidence`, so
focused advice does not hide a proven positional call as signature-only advice.
The static resolver accepts stable local bindings and bounded receiver chains,
including constructor fields assigned from same-module annotated parameters.
Rebinding, uncertain decorators, custom attribute hooks and ambiguous receivers
do not establish new call evidence. Familiar public flag names retain their
existing exemption; familiar private flags require a proven positional call.

L027 excludes import-proven `typing`/`typing_extensions` `cast` type strings and
matching declaration names in `TypeVar`, `ParamSpec`, `TypeVarTuple` and `NewType`.
Runtime values in `sqlalchemy.cast` remain eligible. It also excludes recognized
CLI declarations' standard action values and documentation fields, import-proven
operator selectors, gettext message-ID positions and SQLAlchemy schema-name
positions. Module/class declaration collections, uniform class-field catalogs
and formatting-only skeletons are excluded; outside these contexts, runtime
defaults and message text remain eligible. Mapping lookups and membership keys
require source evidence; an arbitrary `get` method is not enough. Builtin field
access and mutation require a proven builtin plus static attribute, method or
slot evidence, and preserve ordinary private state names. Immutable
`object.__setattr__`/`__getattribute__`/`__delattr__` operations and their proven
bound aliases use the same field-selector rule. Unknown, conditional or rebound
setters remain eligible. Import evidence rejects shadowing, rebinding and
recognized module mutations.
Identical literal defaults for the same named parameter on import-proven overload
signatures and their concrete implementation count once for that callable.
Distinct defaults, incomplete overload groups and uncertain decorators remain eligible.
These detector exclusions reduce raw occurrence counts and can remove findings
from JSON and gate inputs; the configured repetition threshold is unchanged.
Bounded occurrence context records function-body counts, non-function
occurrences and roles without extra literal values. L027 is counted, not
listed, unless `--all-advice` or `--select` asks for it. Secret masking evaluates opaque tokens
individually, so ordinary sentences stay readable while credential patterns
and sensitive values remain masked.

L028 counts returns in the measured function's branches, loops, exception
handlers and `match` cases, excluding nested function and class bodies. The
default limit remains five returns. Counting `match` cases corrects previously
missed returns; the count alone does not establish that refactoring would
improve the function.

C303 retains its required-positional and total-parameter measurements, limits
and overload evidence. Additive `argument_evidence` records the known caller
parameter shape and, when provable, an identical project-base signature.
Source-proven Click callbacks whose entire signature is supplied by declared
CLI inputs and plain record constructors that only assign parameters directly
to unique fields are excluded. Unknown decorators, custom command classes,
descriptors, behavioral constructors and ambiguous bindings retain findings.
Focused reports make total-only wide signatures and confirmed inherited
contracts optional. Unresolved bindings and independently widened signatures
stay visible. JSON, SARIF and uploads retain all records with a shared `listing`
mark and reason. Terminal views and gates use that mark; explicitly configured
or selected rules are always enforced. `--all-advice` lists every generated check.

`docs/cli-output.md` lists which advice the scan lists by default and which it
only counts.

L004 evaluates error-catching scopes. Handlerless `try/finally` cleanup, and
handlers that only clean up and re-raise, catch nothing and are not reported; a
`finally` that returns, breaks or continues swallows exceptions and is. The
length check requires both excess code lines and excess protected operations;
one multiline call with simple arguments remains one operation, while nested
calls count separately. An inner `try` that isolates items inside a
loop, only falls back between imports, or protects a narrow operation is not
confusing nesting. Broad nested catching remains reported. A
`try` that is the function's whole body, or its last statement after only a
docstring, imports, nested definitions or guard clauses, is an error boundary:
its length and control flow are left to C304/Q301/Q306. The same applies to
literal/name local initialization followed by the `try` and a plain result
return; arbitrary setup, transformation or persistence calls do not establish
that boundary. Broad nested catch scopes remain checked within boundaries.

L005 recognizes an exception variable read explicitly through proven builtin
`locals()` or no-argument `vars()`, using the exact variable name as a
subscription or `.get()` key. Shadowed or rebound namespace builtins and
lookups inside a different nested scope do not establish use. Genuinely unused
captures remain reported.

L007 distinguishes discarded errors from meaningful handler work and narrow
trivial fallbacks. Broad placeholder returns belong to L030 rather than a
second L007 report. A narrowly resolved filesystem deletion inside a `finally`
cleanup can be excluded when its callable and path evidence support that
purpose; a handler that swallows `BaseException`, `KeyboardInterrupt`,
`SystemExit` or `GeneratorExit` does not receive that cleanup exemption.

Q301 counts refutable `match` patterns and their guards. A wildcard or capture
pattern does not add a decision; its guard still does. A match without a default
retains the path where no case matches. Nested callable bodies stay independent.

Q306 scores only the measured function's body; a nested function's decorators,
defaults and annotations count at the enclosing level and its body one level
deeper (except the decorator-wrapper shape, which a leading docstring does not
break). Lambda bodies are one level deeper, and `match` subjects and guards are
scored. Q302 traverses `match` cases and treats a `with` around a top-level
`try` like the `try` alone.

Q306 records additive `cognitive_scope` evidence: its source end line, own-scope
score, nested contributions and nearest containing function. The numeric score,
threshold and original findings stay unchanged. Human reports can use this
evidence to present overlapping enclosing/nested metric entries together while
retaining every child location and measurement. No ownership proof means no
cross-function grouping.

Q804 does not report a package `__init__` importing its own submodules (a
package composing its public surface) or test modules. U005 reads dependency
declarations from the scanned project and does not climb past a directory that
has its own `pyproject.toml` or `.git`.

If a quality rule fails on a file, that file's quality findings are replaced by
a `quality_scan_error` analysis error; its security, secret and dead-code
results are kept.

F101/F102 do not exempt decorators based only on an import spelling such as
`unittest.mock.patch`: an attribute, exception binding or another project file
can replace that callable with a real route decorator. F102 describes matching
decorators as a conditional route review. Ordinary mock decorators can still
produce false positives; removing those requires stronger route-identity
analysis, not a name-based exemption.
One narrow F102 branch recognizes an unmodified stdlib mock patch decorator
with a literal Python attribute target on a collected `unittest.TestCase`
method. Import spelling alone, URL-like targets, rebound APIs and independent
route decorators do not satisfy that proof.
PUT, PATCH and DELETE remain state-changing methods for F102. POST can also
serve read-only query/RPC operations: a query-like route is checked for body
side effects, including supported same-module helpers, shared-state writes and
opaque calls. Constructing a local result or logging alone does not establish
a persistent state change. A state-changing route name or a POST outside the
query-like scope retains review. These heuristics do not prove authorization
or that an endpoint is safe to expose.
L010 scans actual comments and genuine module, class and function docstrings,
excluding ordinary string payloads. It recognizes credential components such
as `access_token` and `certificate_pinning`, and explicit `SQLi`/`SSLContext`
topics, without treating lexer `token_stream`, `tokenize`, `author`, `certainly`
or `oracle` as security terms.
Generic maintenance words such as `hack`, `workaround` and `temporary` require
an independent security subject. They do not make an ordinary formatter or
retry-maintenance TODO a security finding by themselves.
Docstring TODOs remain review markers even when surrounding text calls them
examples. L017 distinguishes exception text from a formatted stack trace and
names the call receiving it, without claiming the value was sent to a client.
It also reports `traceback.format_exc()` passed to an HTTP response constructor
from an unnamed handler. It does not suppress a response or nested helper
solely because it appears discarded or unused: indirect calls and constructor
mutation can still disclose the data.

SKY-F102 retains its MEDIUM review for mutating routes without an obvious auth
guard. It also reports a HIGH review when a FastAPI route contains an explicit
owner or tenant comparison but returns or changes a selected object without
that check protecting it. This includes identity changes through principal
aliases, replacing the checked object, and late-bound local presenters.
Copied authenticated IDs and captured, checked objects retain their proof.
Conditional assignments keep the identities from each reachable path;
literal branches that cannot run do not create findings. A checked literal
dictionary lookup also remains checked when repeated as `get(key, None)`.
Fetching an object without an ownership comparison does not alone trigger
this additional review. Arbitrary permission helpers, ORM query scoping,
Django/Flask ownership flows, and unsupported control flow remain outside
this narrow check; absence of F102 is not proof of authorization.

SKY-D283 is the security finding for a route SKY-F102 would review when its
function name, path (path parameters excluded) or HTTP method names a
privileged action: device or host control (`arm`, `disarm`, `takeoff`,
`fire`, `power`, `poweroff`, `reboot`, `shutdown`, `restart`, `halt`,
`control`), destruction (`delete`, `drop`, `destroy`, `purge`, `wipe`, `erase`,
`truncate`, or the DELETE method), administration (`admin`, `superuser`,
`sudo`, `impersonate`) or commands (`exec`, `execute`, `shell`, `command`,
`cmd`). Words are whole words, and letters with trailing digits stay one word
(`farm`, `alarms` and `arm64` are not `arm`). `launch` and `eval` are left out:
LTI launches, campaign launches and model evaluation are ordinary routes.
It is reported only when nothing can authenticate the caller, otherwise the
route keeps its SKY-F102 review:
- the route is registered on an app object the same module creates
  (`FastAPI()`, `Flask()`, `Quart()`, `Starlette()`, `Sanic()`), or on an
  `APIRouter`/`Blueprint` the module creates and mounts on that app with no
  guard options; routers mounted from another module are not judged, since
  the mounting site can add a guard;
- the route has no decorator besides its route decorators, no decorator
  option other than routing metadata (`auth=`, `guards=`, `dependencies=` and
  unknown options count as guards), and no `Depends`/`Security`/`Header`/
  `Cookie`/security-scheme parameter, including through a module alias such
  as `CurrentUser = Annotated[User, Depends(...)]`;
- the handler does not read request (or Flask `g`) headers, cookies,
  session, user or client, name authentication in an identifier or string
  (`url_for("login")`), reject with 401/403 (including `return body, 401`), or
  pass the request to other code;
- the module has no middleware other than CORS/GZip/TrustedHost/HTTPS
  redirect (including `app.wsgi_app = ...` wrapping), no app/router guard
  options, no hook registered by call, and no request hook
  (`@app.middleware`, `before_request`) that may authenticate. A hook another
  module registers on the same app object is not visible here.
It is CRITICAL when the module also starts the server on every interface
(`0.0.0.0` or `::`, literally or as the default of an `os.environ.get`/
`os.getenv` lookup bound once), shows no authentication anywhere (no name
reading as auth, including `session`), and the handler performs the action
(a call named for a specific action word, not `control`/`command`/`admin`,
or a process, signal or file-removal call). Unlike SKY-D280 (any Next.js
mutating route without auth), SKY-D283 needs the privileged action evidence;
other open mutating routes stay SKY-F102. `--diff` reports SKY-D283 only when
the route itself changed. A scan with
security checks reports SKY-D283 and drops the SKY-F102 review of the same
handler; a `--quality`-only scan keeps SKY-F102. `ignore[SKY-F102]` and a bare
`# noqa` do not hide SKY-D283. Plain reads (GET) are never reported.

P401 reports `read()`/`readlines()` calls that request everything: no size,
`None`, a negative size or `readlines(0)`, including sizes resolved from simple
local constants. A caller-chosen size is a bound by construction, so chunked
reads are not reported. Resolved `open(...)` receivers get file-specific advice.
For a proven `ZipFile` receiver, `read(name)` loads an archive member; its name
argument does not establish a byte bound.
`read()` on a proven standard-library `io.BytesIO`/`io.StringIO` receiver is
not reported, including synchronous `with` bindings to that same buffer.
The proof checks imports, aliases, method replacement and
visible field writes or object exposure; an earlier buffer assignment alone
does not establish the receiver's current type. Unbounded buffer `readlines()`
can allocate a new list and is reported with that explanation, unless the
contents are a fixed literal with no growth or escape. Other whole reads
remain LOW advice; the rule cannot know the source's size, and some consumers
need the whole value. Resolved whole-buffer consumers and stable, declared
`str`/`bytes` materialized-return contracts are excluded from the chunking
suggestion as described above; this does not prove memory safety.

SKY-P403 excludes proven fixed bounds, shared-iterator consumption, terminal
cleanup scans and bounded partition traversal only while that proof holds.
Repeated aliases and mutations that replenish an iterator invalidate it.
An outer-dependent expression can still return the same collection, and
assigning a collection to itself does not make the scan cheaper. Direct aliases
and builtin list/tuple copies retain size provenance across recurring iterations.
Aliases keep the value captured when assigned; phase flags, correlated exits and
opaque escapes do not establish new shared-source evidence. The inner
source must support repeated traversal: an independent iterable or a locally
resolved shared collection can establish it; an unknown per-item property or
helper alone cannot. Reopening a stable path or a finite literal path map also
establishes repeated file-search work; arbitrary per-item paths do not. Selection
inside a builtin `filter` lambda or single-source generator is checked as well
as the loop body. The inner scan must search for the outer item; ordinary all-pairs computation and
proven required output for every pair are excluded. A conditional value
that later gates a lookup still counts as a search, including comparisons
assigned to Boolean variables. Source aliases and dominating dictionary-cell
writes retain collection identity. Required-output checks summarize normal
and `continue` paths; transparent local writer methods require resolved
constructor bindings and an unconditional write to a fresh builtin list.
Findings include the
outer/inner iterable evidence and call for review: nesting alone does not
prove a performance bug. An index is appropriate only when the keys and
required duplicate or ordering behavior permit it.
Resolved standard-library regex `search`/`match`/`fullmatch` dispatch is not an
indexable equality join. This includes loop elements with source-resolved
`re.Pattern` sequence or tuple annotations. Unknown `.search()` methods and
unresolved pattern collections do not establish that exemption; independent
equality or membership searches remain checked.

SKY-L009 does not assume ordinary `print()` or `pprint()` output is debugging.
It reports explicit `DEBUG:`/`DBG:` labels, raw `locals()`/`globals()`/`vars()`
or `.__dict__` dumps, and source-confirmed f-string debug expressions such as
`f"{value=}"` as LOW advisories to review. Status messages, JSON, stderr output
and ordinary representation formatting are accepted. Unlabelled prints such
as `print(value)` can still be debugging, but intent cannot be established
from that call alone. Debugger calls remain HIGH in CLI, script and test files.

Architecture metrics include scanned TS/JS modules and use `package.json`
workspace boundaries for package aggregates. TS/JS Q802 and Q803 use parsed
interfaces, abstract classes, concrete classes, and functions as a file-level
abstractness heuristic. Default Q802/Q803 signals are grouped per module under
`architecture_metrics.advisories` and excluded from `quality_count` and local
gate inputs. Complete SARIF and Cloud uploads retain those records with their
Advice type; they remain in the maintainability assessment. Setting `[tool.skylos.architecture] enforce_iad = true`
places them in actionable `quality` instead. If a TS/JS source cannot be parsed or opened with
no-follow directory descriptors on the host platform, its module still
participates in the dependency graph, but Q802/Q803 are suppressed for that
module and its name appears in
`architecture_metrics.abstractness_unavailable_modules`. Q804 and Q805 can
still use its resolved imports. Q801 is cataloged but does not currently emit
findings in any language.

For Python modules with both `.py` and `.pyi` files, architecture measurements
come from the runtime file represented by the dependency graph. A stub cannot
overwrite its abstractness, line count or main-guard evidence. This can remove
an incorrect threshold warning or restore a previously missed one. Stub-only
typing analysis remains available. Focused human reports make advisory
file-level I/A/D optional with `--all-advice`; explicit enforcement and raw
report/gate policy remain unchanged.

## Dead Code and Reachability

TS/JS namespace imports keep only the exports selected by static member reads
such as `api.render()` and `api["render"]`, including stable `const` aliases and
literal destructuring. A parameter, block variable or other local binding with
the same name does not count as a read of the imported namespace. Unknown keys,
namespace escapes, reflection and mutation preserve the whole export surface.
This follows resolved module edges, including wildcard barrels. In a closed
source scope, named re-export chains propagate the selected original binding
through aliases and wildcard hops. Package APIs and escaping namespaces retain
their export surfaces. Competing wildcard providers, unmodeled local export
bindings and opaque source decline that narrowing. Enumerating a literal
module namespace also supplies positive reads through resolved export paths,
respecting explicit shadows and the exclusion of default from star exports.
Direct namespace exports (`export * as tools`) preserve member identity through
named, default, wildcard and nested forwarding. Selected literal member paths
leave unused exported siblings reportable; public APIs, mutation, dynamic keys
and escapes retain the possible exported surface. Escaped export spellings
behind wildcard barrels and cross-file classic JS globals remain limited.
Position-preserving parser repairs cover native-valid tagged template escapes
and generic import-type queries, including queries the grammar otherwise reads
as relational runtime expressions. Other syntax errors remain incomplete.

TS/JS local parameter and value reads do not reference unrelated module
functions with the same name. Function values passed or captured still count.
Imports from a proven disconnected ESM consumer do not keep its providers
alive. This requires resolved imports in the selected source scope and known
entry points; runtime loader capabilities such as computed imports, eval,
Function and createRequire prevent that negative proof. Test-inclusive scopes
retain consumers called by tests. Ordinary unused-import reporting still follows
lexical reads inside a disconnected file, alongside its unused-file finding.

Go uses a declaration-use graph for packages that can be fully type-checked.
Standard-library types are read from an installed host Go toolchain without
building export caches or running cgo.
Visible imports within the scanned Go module use the same static type proof.
Nested modules, external dependencies, opaque providers, excluded or unreadable
source and incomplete types retain conservative references. Private free helper
functions in internal `_test.go` packages are reportable only with complete
native unreachability evidence; test entries, callbacks, hooks, public APIs and
live helper chains remain roots. External test packages keep their prior policy.
An explicitly required dependency with a unique unversioned local replacement
can also supply type identity when its matching module and package sources are
already inside the native scan. Unsupported metadata, workspace overrides,
version-specific or remote replacements, excluded providers and paths outside
the scan retain conservative handling. This does not fetch dependencies or add
general external dependency resolution. An active contained `go.work` can supply
source identity for its ordinary `use` modules when the exact admitted file
inventory is available. Omitted package members, excluded or outside providers,
unsupported workspace metadata, invalid module requirements, unsupported Go
versions and type errors decline that additional proof. The module's declared
Go language version is honored; target commands and dependency fetching remain
disabled. This does not implement general workspace replacement or build-variant
resolution.
Private functions that only recurse or call one another are reported when no
entry point reaches them. Local variables and parameters with matching names
do not keep unrelated package functions alive. Exported APIs, interface methods,
`main`, `init`, test and generated consumers, package initializers and reachable
function values remain roots. Assembly, unresolved imports, conflicting build
variants and type errors retain the earlier conservative reference handling;
they do not establish that a function is unreachable.

Python liveness follows literal logging factory paths into a proven
`logging.config.dictConfig` consumer and callbacks on registered Flask
blueprints imported through project modules. A dotted string or an unregistered
blueprint alone is insufficient. Analysis is static and bounded; unresolved
dynamic configuration remains a limitation.

C# constructors are not reported as unused functions, except a `private`
constructor with at least one parameter that no `new T(...)`, target-typed
`new(...)`, `: this(...)` with a matching argument count or `typeof(T)`
reaches, and that is not the `(SerializationInfo, StreamingContext)`
deserialization constructor, has no attributes and is not in a `partial` type
(Roslyn IDE0051's rule). Controller, dependency-injection, model-binding and
serializer constructors are called by the framework; a class that nothing
references, instantiates or registers is still reported as an unused class.

Rust references include qualified function values passed as callbacks. Exact
matching `cfg` predicates can preserve imported filesystem providers inside the
same feature condition; this does not evaluate Cargo features or macros. Rust
also follows function values in `let` initializers. Reads of local variables and
parameters do not keep unrelated module functions with the same name alive.
Bindings apply within their lexical scope, including closures, match arms and
loop patterns; an initializer is read before its new binding applies. Rust
dead-code candidates retain their experimental confidence cap of 40.

Rust enum variant payloads and attribute expressions contribute import reads.
Scoped API contracts recognize imported extension traits and associated
constants, including calls inside macro arguments; strings and unrelated
inherent methods do not supply those uses. Unique root-module private free
functions can be reported as an unrooted group, including recursion cycles,
after project references are collected. Cross-file calls, function values,
static initializers, conditional entries and unknown macro expansion preserve
roots. These bounded checks do not add Cargo feature or macro expansion.

Within a closed Rust source file, local trait declarations and concrete receiver
types can establish which import supplies a method, including aliases and
borrowed receivers. Unknown or competing implementations, conditional items,
unexpanded macros and out-of-line modules decline that proof. Standard writer
macros can establish a `std::io::Write` import use for a proven writer receiver;
local `write_fmt` traits, inherent methods and shadowed macros/providers remain
separate controls. A feature-matched `cfg_attr` wrapper can read its attribute
import without treating predicate strings or inactive wrappers as uses. These
checks preserve Rust's experimental confidence cap of 40 and do not evaluate
Cargo's active feature set.

Ordinary `mod name;` source closures rooted at a fully scanned `main.rs` or
`lib.rs` can also establish local trait import use across files. Every module
must be admitted, readable and unambiguous; attributed, excluded, missing,
macro-generated or over-budget closures add no proof. Repeated import aliases
retain their own source-bound identities, so an inner read cannot hide an unused
outer import. Attributed repeated bindings keep conservative grouping without
guessing the active Cargo configuration.

Swift dead-code checks parse `.swift` sources and follow `private`/`fileprivate`
declarations, owner and lexical bindings, function values, callbacks and private
call cycles. Public/internal APIs and runtime or compiler-generated consumers
remain roots. Import usage is not inferred from textual module-name matches:
imports may supply extensions and operators. SwiftPM `.build` source products
are excluded from directory scans; an explicit file target is still inspectable.
Missing grammar, unreadable source and syntax errors report incomplete analysis.
Swift security-flow analysis, quality rules and local API verification are not
implemented; existing secret scanning also reads Swift sources.

A Python module or class variable is kept alive by an attribute read `x.NAME`
elsewhere only when `x` could be its owner. For a module variable that is the
module itself (import alias or dotted path), a module that star-imports it,
Django's `settings` object, or an unknown receiver (parameter, local, call
result) once the module object can reach one: it is imported as a module,
named by a dotted string such as `config_from_object("app.celeryconfig")`, or
the project loads modules dynamically (`import_module` with a computed name,
`sys.modules`, `runpy.run_path`). For a class variable it is `self`/`cls` of
the class, a subclass or a base, the class or a subclass by name, or an unknown
receiver. `self.NAME` in an unrelated class without `__getattr__`,
`other_module.NAME` and literals are proof of another object, so
`RETRY_LIMIT = 3` in `settings.py` is reported when the only `RETRY_LIMIT`
reads are `self.RETRY_LIMIT` on another class and `policy.RETRY_LIMIT` on a
parameter while `settings` is never imported as a module. Grep verification
then ignores those attribute-only lines in analysed `.py`/`.pyi` files.
Classes with a base outside the project, a decorator, a metaclass or an
enclosing scope keep name-only liveness, because code Skylos cannot see may
read their attributes.

Java, Kotlin, Rust and Dart definitions with the same name in different files
(two `Util` classes in different packages, private `helper` functions in two
crates) are separate definitions. A reference reaches the ones its file can
see: its own file, then (Java/Kotlin) its package and its imports, then (Rust)
its crate; with no such evidence it reaches all of them. Package and import
lines are read with comments and string literals blanked, so a commented-out
or quoted `import b.Util;` is not an import. Overloads in one file
share one definition, since name-only references cannot tell `format(int)`
from `format(String)`.

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| U001 | INFO | Unused function | Upload/API normalized dead-code category |
| U002 | INFO | Unused import | Upload/API normalized dead-code category |
| U003 | INFO | Unused variable | Upload/API normalized dead-code category |
| U004 | INFO | Unused class | Upload/API normalized dead-code category |
| U005 | MEDIUM | Declared dependency appears unused. Run-time declarations only: requirements files, `[project].dependencies`, and `install_requires` in `setup.cfg`/`setup.py` (extras, `setup_requires` and `tests_require` are not reported). Compiled lock entries (pip-compile/uv, `--hash`, `# via`) are never reported; their `.in` inputs are checked instead. Imports, Django settings strings, `import_module` strings, Procfile/Dockerfile/compose/Makefile commands, entry points and mypy plugins count as uses; type-stub and database-driver packages are skipped | Python dependencies |
| U006 | INFO | Unused parameter | Debt normalized dead-code category |
| DC001 | MEDIUM | Unused function | LLM report dead-code ID |
| DC002 | LOW | Unused import | LLM report dead-code ID |
| DC003 | MEDIUM | Unused class | LLM report dead-code ID |
| DC004 | LOW | Unused variable | LLM report dead-code ID |
| DC005 | LOW | Unused parameter | LLM report dead-code ID |
| DC006 | LOW | Empty or unused file | LLM report dead-code ID |
| UC001 | MEDIUM | Unreachable code after control-flow exit | Python |
| UC002 | MEDIUM | Unreachable code after return/throw/break/continue | TS/JS, Java |
| E002 | LOW | Empty or docstring-only file | Python |
| E003 | LOW | Unused TypeScript/JavaScript file | TS/JS |
| E004 | LOW | Unnecessary export | TS/JS |

SKY-UC001 preserves a sole unreachable `yield`/`yield None` that establishes
generator semantics in its enclosing function. Nested function/class bodies
do not supply that marker. Redundant markers and later unreachable statements
remain reportable.

SKY-U005 resolves namespace child imports, canonical distribution providers and
explicit plugin/tool use in fixtures, markers, commands and configuration.
Incomplete source/configuration evidence, unresolved dynamic imports and
ambiguous namespace ownership do not prove non-use. The rule abstains from an
unused-dependency finding when those limitations leave usage unresolved.
One `analysis_summary.unused_dependency_analysis` receipt records coverage,
reasons and abstentions. Candidates absent from a resolved usage inventory
retain `value = "unused"`. Dependency vulnerability inventory and scanning
remain independent of this usage decision.

### Framework entrypoints

Dead-code findings skip code a framework or tool loads by convention rather
than by an import. These conventions apply to TS/JS, PHP and Python:

| Convention | Scope | Kept live |
|:---|:---|:---|
| Next.js App Router | `app/`, or `src/app/` when there is no root `app/`, in a Next.js project, outside private `_folders` | `page`, `layout`, `template`, `loading`, `error`, `global-error`, `not-found`, `default`, `route` files (`.js`, `.jsx`, `.ts`, `.tsx`, or the literal `pageExtensions` of `next.config.*`), their default export, route handlers, `metadata`/`generateMetadata`/`viewport`/`generateViewport`/`generateStaticParams` and route segment config exports (`dynamic`, `revalidate`, `runtime`, ...) |
| Next.js metadata routes | `app/`, or `src/app/` when there is no root `app/`, in a Next.js project, outside private `_folders` | `robots`, `sitemap`, `manifest`, `icon`, `apple-icon`, `opengraph-image`, `twitter-image` files and their default export; `alt`, `size`, `contentType`, `generateImageMetadata` in image routes; `generateSitemaps` in sitemaps |
| Next.js Pages Router | `pages/**` | default exports, `getServerSideProps`, `getStaticProps`, `getStaticPaths`, `getInitialProps`, `_app`/`_document`/`_error`/`404`/`500`; `config` and `_app`'s `reportWebVitals` in a Next.js project |
| Next.js root files | project root or `src/` | `middleware`, `proxy`, `instrumentation`, `instrumentation-client`, `mdx-components` and their hook exports |
| Tool config files | any directory | `next.config.*`, `postcss.config.*` and `tailwind.config.*` (`.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`), the usual Vite, Vitest, ESLint, Jest, Playwright and tsup config names, and their default export, including `const config = {...}; export default config` |
| Package tool configs | `<tool>.config.<ext>` (`.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`) next to a `package.json`, and `turbo/generators/config.*` | every export: `metro`, `babel`, `drizzle`, `stylelint`, `openapi-ts`, Expo `app.config`, a `turbo gen` generator, ... |
| Expo Router | a package whose `dependencies`/`devDependencies` list `expo-router`; router root from `app.json` (`expo-router` plugin `root` / `extra.router.root`), else `src/app` if present, else `app` | every `.js`/`.jsx`/`.ts`/`.tsx` file under the root, its default export, `unstable_settings`, `ErrorBoundary`, `generateStaticParams`, `loader`; HTTP method exports of `+api` files; `redirectSystemPath`/`legacy_subscribe` of `+native-intent` |
| React Email | a package depending on `react-email`; `./emails` plus any `--dir`/`-d` in an `email dev\|build\|export` script | `.js`/`.jsx`/`.tsx` files with a default export, outside `_`-prefixed and `static` folders, and their default export |
| Jest manual mocks | any `__mocks__/` directory | the file and all its exports |
| esbuild entry points | `entryPoints` of a top-level `esbuild.build/context` call in a script a `package.json` script runs (also under an excluded folder such as `dev/build`), including `path.join(import.meta.dirname, ...)` values and objects that later gain new keys | the entry files and all their exports (the bundle's interface) |
| Laravel Vite plugin | `vite.config.*` | each `input` of `laravel(...)` from `laravel-vite-plugin` |
| Laravel | a `composer.json` whose `require` lists `laravel/framework` | `Illuminate\Console\Command` subclasses in `app/Console/Commands` (bases resolved through imports and the PSR-4 map); classes in `app/Listeners` with a `handle*`/`__invoke` method whose first parameter has a class type, when event discovery is on (a provider's `shouldDiscoverEvents()` returns true, or the Laravel 11 `Application::configure()` builder without `withEvents(discover: false)`); `*Factory` in `database/factories` when the model in `app/Models` or `app` uses `HasFactory` (directly or through a project parent); `*Policy` in `app/Policies` when the model exists; classes in `app/Livewire`, `app/Http/Livewire`, `app/View/Components`, `database/migrations`; `DatabaseSeeder` and any other `Illuminate\Database\Seeder` subclass in `database/seeders` (run by `db:seed --class`); and the public methods of those classes |
| Blade templates | `*.blade.php` | helper functions called in the template, classes named with `new`, `::` or a fully qualified name (`@inject`, `@use`), and methods called as `->name(...)` |
| PHP class strings | any PHP string literal | fully qualified class names (`'App\Services\Mailer'`, generated-PHP strings in Blade directives) |
| Flask | modules importing Flask | module-level `create_app`/`make_app` factories (Flask CLI discovery) and what they register; Blueprint `before_app_request`/`app_errorhandler`/... hooks once the blueprint is registered; functions passed to `app.teardown_appcontext(...)`, `before_request`, `register_error_handler`, ...; the parameters Flask passes to callbacks (`close_db(e)`) |
| Declarative class attributes | class bodies of classes with a base | attributes built by `Relationship`, `relationship`, `mapped_column`, `Column`, `column_property`, `association_proxy`, `backref`, `synonym`, `composite`, `deferred`, `ForeignKey`, `ParentalKey`, `GenericRelation`, `GenericForeignKey`, `TaggableManager`, `ClusterTaggableManager` or any `*Field(...)` constructor (Django model/form fields, Wagtail `RichTextField`/`StreamField`, DRF); `*Filter(...)` on a `*FilterSet`; `*Block(...)` children of a Wagtail `*Block`; every field of a `table=True` SQLModel class |
| `Meta` classes | any class named `Meta` | the class and its options (Django models/forms, DRF, django-filter, Wagtail blocks, factory_boy) |
| Wagtail | modules importing `wagtail` | Page attributes (`content_panels`, `promote_panels`, `settings_panels`, `search_fields`, `api_fields`, `template`, `subpage_types`, `parent_page_types`, `max_count`, `preview_modes`, ...), snippet/`ModelViewSet` options (`list_display`, `list_export`, `sort_order_field`, `menu_label`, ...), `Task.task_state_class`, `AccessibilityItem` `axe_*` options; the parameters of Page, preview, workflow-task and block hook methods (`serve`, `serve_preview`, `get_preview_template`, `get_context`, `user_can_access_editor`, `get_actions`, ...) |
| Django | modules importing `django` | parameters of class-based-view handlers (`get`, `post`, ..., `dispatch`, `setup`), of system checks registered with `register(...)` (`app_configs`, `**kwargs`), and of documented ModelAdmin/Inline, Widget, Field and Form hooks; model classes in an app's `models` module (fields or a model-like base); UPPERCASE names in `locale/<lang>/formats.py` and `FORMAT_MODULE_PATH` format files |
| Registration decorators | class decorators named `register*` | the class (`@register_setting`, `@register_snippet`, `@admin.register`) |
| Python registration decorators | any Python module | functions decorated `@<object>.<attribute>` where the attribute is a route or registration verb (`get`, `post`, `route`, `api_route`, `on`, `on_event`, or has an underscore-separated word such as `tool`, `resource`, `prompt`, `task`, `command`, `event`, `handler`, `listener`, `subscriber`, `hook`, `signal`, `register`, `fixture`, `job`: `@mcp.tool()`, `@server.call_tool()`, `@client.event`, `@sio.on("chat")`, `@celery_app.task`), and a bare `@tool`, `@function_tool`, `@task`, `@shared_task`, `@hookimpl`, `@hookspec`, `@register*` imported from outside the project (also through an import alias). Cache and wrapper decorators (`functools`, `contextlib`, `st.cache_*`) never make a function used; a decorator the project defines (in the module or imported from the project's own package) counts only when its body registers the function |
| Python package entry points | `pyproject.toml` `[project.scripts]`, `[project.gui-scripts]`, `[project.entry-points.<group>]`, Poetry `scripts` and `plugins`; `setup.cfg` `[options.entry_points]`; the literal `entry_points=` of `setup()` in `setup.py` (parsed, never run) | the named function or class (extras ignored), the class owning a `module:Class.attr` target, and the public methods and class attributes of a class that is itself an entry point (the plugin host calls them). A module-only entry (`pytest11 = "pkg.plugin"`) keeps no symbol by itself |

A project is a Next.js project when a `next.config.*` file or a `package.json`
that depends on `next` sits in the file's directory or a parent. Only the named
convention exports stay live: an unused helper exported from `page.tsx` or
`opengraph-image.tsx`, and an unused private method of a Laravel listener, are
still reported. A helper that only a convention root calls, such as a data
loader called by a page's default export, stays live; in JS/TS that applies
only when the file itself is one Next.js routes, Storybook loads or a tool
reads as config, not to name-only marks such as `use*` hooks or a `page.tsx`
outside `app/`. With discovery off, a Laravel listener stays live only through
its `::class` registration in `$listen` or `Event::listen`.

### Library public API (Python)

Code outside a repository imports a library's public API, so a public name that
nothing in the repository uses is not dead when the library declares it public.
Skylos recognizes a conservative static subset of common documentation, typing
and lazy-export declarations. Its exclusions below are Skylos policy; documentation
builders and type checkers have their own configurable selection rules.

| Declaration | Kept live |
|:---|:---|
| `__all__` | the names it lists (it is the module's exact API) |
| `__init__.py` re-exports | names imported into a package `__init__` without `__all__`, and `import x as x` aliases |
| Attribute docstring or `#:` comment | a public module-level name in a public module with no `__all__`: `URL = "..."` followed by `"""Doc."""`, `#: Doc.` on the line above, or `URL = "..."  #: Doc.` |
| Sphinx object directive or role | the named object: `.. autofunction::`, `.. autoclass::`, `.. autodata::`, `.. py:function::`, `autosummary` entries, `:func:`/`:class:`/`:data:`/`:const:`/`:obj:`/`:meth:` roles, resolved through `.. currentmodule::`; reST, `.txt` and MyST (`{eval-rst}`, ```` ```{autofunction} ````, `{py:func}`) |
| `automodule` and mkdocstrings `:::` | the module's selected documented public members; supported explicit member lists and undocumented-member options can also select undocumented members. Local mkdocstrings filters apply to automatic selection. None of these widen `__all__`. |
| `.pyi` stub | explicit declarations, including explicitly declared public methods, limited by the stub's and implementation's `__all__`; explicit re-exports in an `__init__.pyi`, or relative imports used by a proven `lazy_loader.attach_stub` getter |
| Lazy exports | names whose supported getter flow returns an attribute from the exact imported module, or names supplied to canonical `lazy_loader.attach` / `attach_stub` calls. Unused tables and unresolved owners supply no export evidence. |

Private `_names`, names in private `_modules`, tests, scripts, docs and
examples are never declared public this way, nor is a name marked
`:meta private:` or `@private`. Changelog, history and release-note files are
not read. A function docstring alone does not make a function public, and a
documented class does not make its undocumented methods public. A
`__getattr__` that only raises or warns does not export anything.

Literal examples, comments and escaped documentation markup do not declare API.
Evidence files must be regular files inside the scan root; symbolic links and
oversized files do not supply evidence. Skylos does not build documentation or
import the scanned package. Unsupported documentation options, complex filters,
custom lazy-module replacements and unresolved dynamic behavior remain available
for review rather than implicitly rescuing names.

A project can declare public API that has no such marker with a dead-code
entrypoint rule:

```toml
[[tool.skylos.dead_code.entrypoints]]
full_name = "mypkg.datasets.*"
reason = "public dataset catalog"
```

Generated sources (a leading comment such as `// Code generated ... DO NOT
EDIT.`, `@generated`, `This file was automatically generated by ...` or `This
file is auto-generated by ...`) are parsed for references, but their
dead-code, quality and AI-defect findings are not reported, like Django
migrations; `--include-generated` reports them.

Known limitations: tool config and Storybook story files are recognised by file
name, so a stale `scripts/old/vite.config.ts` or an unused `*.stories.tsx`
keeps its callees live; a Laravel policy stays live while its model file
exists, even if the model is dead; and a class referenced only from a dead
class (for example an event type-hinted only by an unregistered listener) is
not reported, as with any other reference from dead code.

PHP classes named only in type positions count as used: parameter, return and
property types (including nullable, union, intersection and promoted
constructor parameters), `instanceof`, `catch`, attributes, `::class`, and
PHPDoc types (`@param`, `@return`, `@var`, `@throws`, `@extends`,
`@implements`, `@use`, `@template ... of`, `@method`, `@property`, `@mixin`,
including generics and multi-line array shapes). As in PHP-CS-Fixer, an import
that a docblock only mentions in prose or in a cross-reference (`@see`,
`@uses`, PHPUnit `@covers`, `{@see}`, `{@link}`) stays used, but that mention
does not make the class itself used. A class's own docblock naming the class
(`@method static Builder|Self query()`, `@mixin Self`) does not make it used.

Pretty output and the TUI use short display labels such as
`dead-code/function`, `dead-code/import`, `dead-code/class`,
`dead-code/variable`, `dead-code/parameter`, and `dead-code/file`. Those labels
are UI grouping text, not stable rule IDs; use the `SKY-*` IDs above for
suppression, integrations, and public references.

## Dependency Vulnerabilities and Publisher Review

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| SCA-* | varies | Software composition analysis vulnerability | Dependency manifests / installed packages |
| SKY-SCA-LIC001 | HIGH (configurable via `license_severity`) | Dependency license policy violation | Declared dependency license (offline lockfile / installed metadata) cannot be satisfied without a license in `license_deny`, or outside `license_allow`; `NOASSERTION` never fires |
| SKY-SCA-NPM-PUB001 | WARN (review only) | npm publisher change after release dormancy | Direct npm dependency pinned in a package lockfile; verify the publisher and release provenance before upgrading or deploying |
| SKY-SCA-SRC001 | CRITICAL (direct) / HIGH (transitive) | Possible dependency confusion | A package matching `[tool.skylos.supply_chain] internal_packages` resolves from a public or merged index (`--extra-index-url`, a public lockfile registry); decided by the ca9 engine, reported only with configured patterns and registry evidence |
| SKY-SCA-SRC003 | MEDIUM | Mutable dependency source | A Git dependency not pinned to a full commit, or a URL dependency without a hash, in a requirements file, `pyproject.toml`, `package.json` without a lockfile, or a lockfile Git/URL entry; local paths are not reported |
| SKY-SCA-SRC004 | HIGH | Package moved to a source this repository did not use | In a pull request, a lockfile points a package at a private, Git or URL source it did not use, or at a new host. Advisory databases do not cover it. Packages matching `internal_packages` on the target branch are exempt |
| SKY-SCA-INT001 | MEDIUM | Lockfile entry without integrity hash | A registry entry in `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock` or `poetry.lock` with no (or an empty) integrity hash; never `requirements.txt` or npm `inBundle` entries |
| SKY-SCA-AGE001 | HIGH | Dependency version younger than the release-age window | The locked version was published less than `min_release_age_hours` ago; scans check this only when the policy sets it |
| SKY-SCA-MAL000 | CRITICAL | Malware feed match without an advisory ID | Offline fallback: the installed ca9 malware feed matched a package but named no advisory ID (matches with an ID use `SKY-SCA-<id>`) |
| SKY-SCA-UPG001 | CRITICAL | Dependency upgrade adds install-time or start-up code | `--diff`/`--diff-base` with `--review-upgrades`: an npm or PyPI lockfile version change whose new artifact adds a `.pth` or `sitecustomize` with code, an install/prepare hook, decode-and-exec, a Git/URL dependency, shipped agent/editor hooks, archive entries that install to the same path or differ only by case, an executable named like a system command, sourceless bytecode run at import or start-up, or an artifact that does not match the lockfile's integrity (`ca9.api.review_upgrades`); evidence names the file inside the package and a redacted snippet. Fails a diff gate on its own |
| SKY-SCA-UPG002 | MEDIUM | Dependency upgrade adds code worth reviewing | As UPG001 when only ca9's `warn` list has deltas (new import-time network or exec, obfuscation growth, a native binary, a publisher change, changed install-time code, or anything ca9 flags in a newly added package, `block` list included, since there is no earlier version to compare against); otherwise findings follow ca9's lists, never the delta kind. Listed, not counted by the built-in gate. Changes ca9 did not review (timeout, unreachable registry, size cap, over 100, `complete: false`) and changed lockfiles Skylos could not read (over 64 MB, a link, rejected by the parser) are an analysis error (diff gate incomplete); internal packages and entries the lockfile resolves from a private registry are skipped with a warning; changed requirements pins, `pdm.lock` and `pylock.toml` are listed as not read |
| SKY-SCA-API001 | MEDIUM | Your line uses API a dependency upgrade removed | `--diff`/`--diff-base` with `--review-upgrades`: a Python package's locked version changed and a line of yours uses a public name, module, method or keyword argument that exists in the old release and not the new one. Both releases are read statically through `ca9.artifacts`, never imported or run. Advice: no gate counts it, it is not uploaded to Cloud, and whatever could not be read is listed as could not check |
| SKY-SCA-HRD001 | HIGH | Change weakens install hardening | `--diff`/`--diff-base` with `--sca`: `ca9.api.hardening_regressions` between the merge base and the tracked working tree (cooldown removed, lowered or bypassed for a package, `ignore-scripts` off, `allowBuilds`/`allowScripts`/`trustedDependencies` additions, `strictDepBuilds` off, SHA-pinned action moved to a tag). Packages in the base commit's `[tool.skylos.supply_chain.hardening_exceptions]` with a reason are skipped. Fails a diff gate on its own; a `check_failed` comparison is an analysis error (incomplete), never a pass |

`SKY-SCA-LIC*` IDs are reserved for license policy and are not OSV advisory IDs.
`SKY-SCA-NPM-PUB001` is a publisher history review signal, not an OSV advisory ID.
`SKY-SCA-SRC*`, `SKY-SCA-INT*`, `SKY-SCA-AGE*`, `SKY-SCA-UPG*` and `SKY-SCA-HRD*`
are supply-chain checks from the ca9 engine (`ca9.api`), not OSV advisory IDs. OSV advisories for malware
(`MAL-*` IDs or aliases, `malicious-packages-origins`, CWE-506) keep their
`SKY-SCA-<id>` rule ID and are reported `CRITICAL` with `metadata.malicious`.
Declared licenses are normalized to SPDX; ambiguous values (for example `BSD`,
`GPLv3`) are `NOASSERTION`, never guessed.

## Aggregate, Alias, and Workflow IDs

These IDs appear in API normalization, audit workflows, LLM schemas, prompts, or
agent workflows. They are not always emitted as first-class static-analysis
findings.

| ID | Meaning |
|:---|:---|
| SKY-D000 | Generic security fallback ID for normalized external findings. |
| SKY-Q000 | Generic quality fallback ID for normalized external findings. |
| SKY-S000 | Generic secret fallback ID for normalized external findings. |
| SKY-SCA-000 | Generic dependency fallback ID for normalized external findings. |
| SKY-U000 | Generic dead-code fallback ID for agent workflows. |
| SKY-D101 | Legacy compliance alias for code injection. |
| SKY-D102 | Legacy compliance alias for code injection. |
| SKY-D103 | Legacy compliance alias for insecure deserialization. |
| SKY-AUDIT | Deep-audit candidate or artifact marker. |
| SKY-AUDIT-ENTRYPOINT | Deep-audit entrypoint candidate marker. |
| SKY-AUDIT-LOGIC | Deep-audit repository investigation logic finding. |
| SKY-AUDIT-PATH | Deep-audit security-sensitive path candidate marker. |
| SKY-AUDIT-SECURITY | Deep-audit repository investigation security finding. |
| SKY-DEAD | LLM dead-code verifier marker. |
| SKY-DEAD-CHALLENGE | LLM dead-code challenge marker. |
| SKY-DEBT | Agent command-center debt marker. |
| SKY-FIX | Agent remediation / fix generation marker. |
| SKY-L000 | Generic logic fallback ID for LLM schemas. |
| SKY-C399 | Structure placeholder ID used in prompt examples. |
| SKY-Q499 | Quality placeholder ID used in prompt examples. |
| SKY-P499 | Performance placeholder ID used in prompt examples. |
| SKY-S199 | Secret placeholder ID used in prompt examples. |

Prompt text may also use range notation such as `SKY-D226-228`,
`SKY-L001-004`, or `SKY-P401-404` to describe groups of concrete rule IDs.

## Custom Rules

Custom rule packs may emit project-defined IDs from `.skylos/rules/*.yml`.
Prefer a stable project prefix, for example `ORG-SEC001`, to avoid colliding
with Skylos-owned `SKY-*` IDs. Scans with `--quality` or `-a` load the packs
in every `.skylos/rules/` folder from the scanned file up to the repository
root (nearest pack wins per rule ID), plus `~/.skylos/rules/*.yml` and Cloud
rules. With `SKYLOS_POLICY_BASE` set (PR CI), project packs are read from that
commit only. A pack's rules only add findings; one with a `SKY-*` ID does not
replace or hide the built-in finding. Packs that are symlinks, over 1 MB,
invalid YAML, use YAML aliases or have no `rules` list are skipped and named
in a scan warning.
