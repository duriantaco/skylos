# CLI Output Modes

CLI output modes control how Skylos displays scan results in the terminal. Each mode is designed for a different workflow such as human review, automation, CI pipelines, or AI-assisted processing.

If you're unsure which mode to use, the table below provides a quick reference.
Most entries are `--format` values; the TUI is a separate `--tui` mode because
it opens an interactive screen instead of printing a report.

Choose a human format for review or JSON for a stable structured record of
findings, assessment and analysis limitations.

## Choosing an Output Mode

| Need | Command | Best For |
|------|---------|----------|
| Full terminal report | `skylos .` or `skylos . --format rich` | Deep inspection and existing terminal workflows |
| Compact human report | `skylos . --format pretty` | Quick local review and PR discussion |
| Copyable plain output | `skylos . --format concise` | CI logs, scripts, editors, and automation |
| Machine-readable results | `skylos . --format json` | Programmatic use and external integrations |
| Smaller machine-readable results | `skylos . --format json-ci` | CI jobs and agents that need findings without the full symbol inventory |
| AI-ready report | `skylos . --format llm` | Agent workflows and structured reasoning systems |
| GitHub Actions annotations | `skylos . --format github` | Inline workflow annotations in GitHub checks |
| GitLab Code Quality report | `skylos . --format gitlab -o gl-code-quality-report.json` | Findings in GitLab merge request reports |
| Offline dependency SBOM | `skylos sbom . -o sbom.cdx.json` | CycloneDX 1.6 dependency inventory with declared licenses; no advisory requests |
| SPDX dependency SBOM | `skylos sbom . --format spdx-json -o sbom.spdx.json` | SPDX 2.3 JSON inventory; unknown licenses are `NOASSERTION` |
| Interactive terminal triage | `skylos . --tui` | Keyboard-driven exploration of findings |

`sbom` is a separate inventory command, not a scan-output format. It includes
supported exact package versions whether or not they have known vulnerabilities.
See [dependency scanning](./dependency-scanning.md#export-an-sbom-offline) for
supported lockfiles, partial-inventory limits, and exit codes.

## Human Terminal Output

Use the default `rich` format when you want the existing full report:

```bash
skylos .
skylos . -a
```

The default table report shows separate assessment readouts rather than a
blended score badge. New source scans do not produce a codebase A–F grade.
See [scan assessment](#scan-assessment).

Use `pretty` when you want a compact, file-grouped terminal report:

```bash
skylos . --format pretty
skylos . -a --format pretty --limit 20
```

`--format pretty` groups findings by file, shows severity badges and rails, keeps `file:line` locations copyable, includes source snippets when available, and suppresses the large banner and follow-up prompts. It is intended for interactive terminal review, PR comments, and quick local triage.

To keep this view compact, each finding title, evidence summary, and source
snippet is capped at 140 characters. Use `--format concise` for the complete,
untruncated finding message, or `--format json` for every structured field.

Example shape:

```text
Skylos static analysis  3 issues  1 file analyzed
  unused functions: 2  unused variables: 1

  src/app.py · 3 issues

    █  LOW  dead-code/function  Unused function: old_handler
      Dead Code  src/app.py:42
      evidence: likely dead — no static references were found [analyzer] · symbol is not exported as public API [analyzer]
      def old_handler() -> None:
      Fix: Remove the unused function if it is not public API.
```

Dead-code reporting is evidence-gated. The configured confidence threshold
selects candidates, then the evidence decision determines the outcome:

- `alive`: rescued and omitted from unused-code findings.
- `uncertain`: recorded as an abstention and omitted from unused-code findings.
- `likely_dead` or `validated_dead`: reported as unused code.

The human formats show the classification plus the evidence reason and source.
The TUI includes the full event list in its detail pane. JSON includes the full
`dead_code_evidence` ledger, `dead_code_rescues`,
`dead_code_abstentions`, and per-finding `dead_code_decision` data. Candidate
outcome counts are available under
`analysis_summary.dead_code_evidence.candidate_decisions`.
Unverified same-name attribute matches are retained as contextual evidence;
they do not rescue a symbol unless a stronger liveness signal confirms the use.

Each reported candidate's confidence is capped by its weakest evidence, so
findings can be sorted and the top trusted first. The finding lists the
factor (`Confidence: 60% (default export ...)`) and JSON carries it in
`confidence_factors`:

| Evidence | Confidence |
|:---|---:|
| Unused import, or a private/local symbol with no reference anywhere | 100 |
| Public Python module-level name (importable from outside the scan) | 90 |
| Exported, but no file in the repository imports it (also SKY-E004) | 85 |
| Public method or class attribute (dynamic dispatch, framework-read attributes) | 80 |
| JS/TS file no file imports (SKY-E003) | 80 |
| JS/TS file imported only by unused files | 65 |
| A module's default export that nothing imports (routers, mailers and config loaders consume default exports) | 60 |
| An unused parameter (callback and override signatures often require it; like Ruff's opt-in `ARG` rules) | 50 |
| Rust (experimental) | 40 |

The default threshold (60) shows everything except unused parameters and
Rust; the scan says how many parameters it did not list, and
`--confidence 50` lists them. `--confidence 80` keeps the strongest findings; `skylos clean`'s non-interactive default (80)
does not delete default exports or class attributes. SKY-E003/E004 findings
carry a confidence for sorting and are not filtered by `--confidence`.

Rust dead code is experimental: trait methods, `pub` re-exports, macros and
`#[bench]` items are not resolved, so its candidates sit below the default
threshold and a scan says so in one line. Use `--confidence 40` to list them.

When a security finding carries analyzer-recorded evidence, `rich` and
`pretty` show the observed sources, sink, path and guards. These are static
observations, not confirmation of runtime exploitability. Partial analysis
is labeled explicitly. No flow is invented for findings without evidence;
JSON retains the complete packet, including additional sources and steps.

Dependency coverage also shows the number of packages queried, supported
lockfiles read and unresolved versions. A manifest range such as `>=2.0`
does not identify a version to query. Supply a
[supported lockfile](./dependency-scanning.md#supported-inventories) or exact
manifest versions, and inspect `analysis_summary.sca_coverage` for parsing,
source or advisory-service gaps. Skylos does not install dependencies or
resolve ranges. SBOM export is supported; SBOM import is not.

Validated non-registry sources in `uv.lock` are shown as **not checked** in
rich, pretty, LLM, concise and GitHub output, including scans with no findings.
Successful public-package queries can exit `0` unless a configured gate fails;
malformed inputs or advisory-service failures still exit `2`. The JSON receipt
keeps this limited coverage separate from a clean dependency assessment and
cannot establish absence-based resolution of dependency findings. See
[uv source coverage](./dependency-scanning.md#uv-source-coverage).

Expanded signature advice on conventional test functions explains that
pytest may supply fixtures and parametrized inputs by name. Review fixture
dependencies and case clarity before applying advice intended for manually
called functions. This context changes the human explanation only: the
finding, severity, JSON record and configured gate remain intact.

Write the same pretty report to a file with `--output`:

```bash
skylos . --format pretty --output skylos-report.txt
```

## Copyable And Machine Output

Use `concise` when an editor, test script, or agent needs plain
`file:line  RULE_ID  message` findings and a non-zero exit code when findings
exist. Concise messages are not truncated:

```bash
skylos . --format concise
```

Example:

```text
src/app.py:42  SKY-L012  Call to 'security.require_auth()' resolves to no definition on local modules.
```

Use `json`, `json-ci`, `llm`, or `github` for structured consumers:

```bash
skylos . --format json
skylos . --format json-ci
skylos . --format llm
skylos . --format github
```

`json-ci` keeps the same findings, per-finding evidence, and summary counts as
`json`. It omits only the top-level `dead_code_evidence` ledger and
`definitions` map, which can make a full scan report large. Use `json` when
you need those full symbol details.

When provenance is available, `ai_security_stats.by_category` groups the
included findings by their top-level JSON array (`danger`, `quality`, and so
on). A finding's own `category` field can be more specific, such as `SECURITY`
inside `danger`; that field is preserved.

Use `gitlab` to save a GitLab Code Quality JSON array:

```bash
skylos . --danger --quality --gate --format gitlab -o gl-code-quality-report.json
```

Declare the file as a GitLab `artifacts:reports:codequality` artifact. This
format creates a report, not bot comments or a GitLab SAST report. It keeps
the normal gate and incomplete-scan exit behavior. For a pinned scanner CI
example, comparison setup, and GitLab tier limits, see
[GitLab Code Quality](./gitlab-code-quality.md).

## Exit Codes And Incomplete Analysis

Skylos reserves exit status `0` for successful command completion, `1` for
finding or policy failures in modes that enforce them, and `2` when the scan
could not produce a usable result. A path that does not exist, or a mistyped
command (`skylos donee`), exits `2` with a "did you mean" line instead of
scanning nothing.

Code that could not be analysed is reported in one of two ways.

**Incomplete coverage (a warning).** Some files or candidates were not
analysed, but everything else was:

- a file that does not parse or cannot be read (for example newer Python
  syntax than the scanning interpreter, or a TypeScript construct the grammar
  does not support);
- files of a language whose engine is missing: `.go` files without the
  `skylos-go` engine, `.dart` files without `pip install "skylos[dart]"`;
- dead-code candidates that grep verification did not reach before
  `SKYLOS_GREP_BUDGET` ran out (see below).

Skylos reports every finding it produced, lists each file it did not analyse
with the reason and the fix (rich output: the **Not Analysed** table), and
ends with a `Coverage: INCOMPLETE — some code was not analysed` block (on
stderr for line-oriented formats; JSON on stdout carries it in
`analysis_summary.analysis_coverage` instead). The exit code and any gate are
decided on the code that was analysed: a scan with only coverage gaps exits
`0`, or `1` for findings in modes that enforce them. Each record stays in
`analysis_errors` as `SKY-ANALYSIS-INCOMPLETE`, the assessment reads
`Coverage: incomplete` with the number of files not analysed, and the scan is
never presented as clean.

**Incomplete analysis (exit `2`).** The scan cannot stand for the code:

- `--strict` was given, `strict = true` is set under `[tool.skylos.gate]`
  (gate runs), or `require_complete = true` is set under
  `[tool.skylos.gate.coverage]` (gate runs): any coverage gap exits `2`;
- more than half of the source files in scope could not be analysed, for
  example a Go repository without the Go engine, or a folder whose only file
  does not parse;
- a diff-scoped scan (`--diff`) could not analyse a changed file, so the code
  under review was not checked (files outside the diff are only warnings);
- a whole requested check failed: an unavailable or interrupted dependency
  scan (`--sca`), a custom-rule service the gate requires, the base
  comparison for removed security controls, or GitHub Actions YAML that could
  not be read (see below);
- an analysis error of a kind Skylos does not recognise (it fails closed).

`--force` and advisory gate settings do not convert incomplete analysis into a
passing result. Interactive removal (`-i`) needs a complete scan and refuses
to run with any coverage gap, because a file that was not analysed could
still reference a candidate.

`analysis_summary.analysis_coverage` records the decision for this run:

```json
"analysis_coverage": {
  "status": "partial",
  "exit_blocking": false,
  "diff_scoped": false,
  "source_file_count": 160,
  "unchecked_file_count": 1,
  "unchecked_files": [
    {"file": "backend/app/api/deps.py", "line": 36, "kind": "syntax_error",
     "reason": "multiple exception types must be parenthesized"}
  ],
  "unverified_dead_code_candidates": 0,
  "most_code_unchecked": false,
  "warnings": [{"message": "Incomplete coverage: 1 of 160 source files could not be analysed", "details": ["..."], "hint": "..."}],
  "blocking_reasons": []
}
```

`status` is `complete`, `partial` (coverage gaps only) or `incomplete` (exit
`2`). `exit_blocking` reflects this run's flags, so `--strict` turns a
`partial` result into `incomplete`.

Malformed or unreadable GitHub Actions YAML always produces incomplete
analysis: GitHub could still run a workflow Skylos cannot read, so its
security checks are never skipped with a warning.
When scanning a repository, Skylos recognizes nested Cookiecutter workflow
templates through a placeholder directory and an adjacent `cookiecutter.json`.
It statically decodes literal GitHub-expression escapes and accepts simple
placeholders in display names and trigger path filters. It does not execute
Jinja or generator hooks. Dynamic commands, permissions, action references,
template control flow, and unsupported expressions remain incomplete; scan
the generated workflow to check those. A repository's active workflows always
require valid YAML.

### Gate verdict

A gate run (`skylos . --gate`, `skylos . --strict`, `skylos cicd gate`) always
ends with one verdict line, then the reasons:

- `Quality Gate: PASSED` (exit `0`), with the limits the scan was held to.
- `Quality Gate: FAILED` (exit `1`, or `0` with `--force`), with each limit
  that failed and the findings counted toward it.
- Either verdict is followed by `Coverage: INCOMPLETE — some code was not
  analysed` and its reasons when the scan had coverage gaps: the limits were
  evaluated on the code that was analysed, and the block names what was not.
- `Quality Gate: INCOMPLETE — could not decide (exit 2)` when required
  analysis did not finish. Each reason names the check that stopped, how many
  files, lockfile entries, or OSV.dev query batches it could not cover, and
  the next step.
- `Quality Gate: ERROR — could not decide (exit 1)` when the run stopped
  before deciding, for example because analysis raised an error or
  `cicd gate --input` could not read its file.

For example, with a `pnpm-lock.yaml` entry the dependency scan cannot resolve:

```text
Quality Gate: INCOMPLETE — could not decide (exit 2)
   Required analysis did not finish, so the gate can neither pass nor fail. --force and advisory mode do not change this.
   • Dependency vulnerability scan incomplete (status: incomplete): 1 lockfile entry could not be resolved
       pnpm-lock.yaml:5  missing locked dependency: left-pad
       Dependency results are required whenever --sca is on (-a includes it). To scan or gate without them, run without --sca, for example --danger --secrets --quality --ai-defects instead of -a.
```

Rich and pretty output print the verdict last on the terminal. `concise`,
`llm`, `github`, and `gitlab` print it on stderr so stdout stays parseable.
`--format json` and `json-ci` carry it in the top-level `gate` object instead
(and also print the verdict on stderr when `--output` sends the JSON to a
file). The same object feeds the assessment's Gate readout and the SARIF run
properties:

```json
"gate": {
  "passed": false,
  "reasons": ["Dependency vulnerability scan incomplete (status: incomplete): 1 lockfile entry could not be resolved"],
  "scope": "local_configured_policy",
  "status": "incomplete",
  "forced": false,
  "verdict": "incomplete",
  "exit_code": 2,
  "strict": false,
  "headline": "Quality Gate: INCOMPLETE — could not decide (exit 2)",
  "hint": null,
  "reason_details": [
    {
      "message": "Dependency vulnerability scan incomplete (status: incomplete): 1 lockfile entry could not be resolved",
      "details": ["pnpm-lock.yaml:5  missing locked dependency: left-pad"],
      "hint": "Dependency results are required whenever --sca is on ..."
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `passed` | `true` only when the gate passed; `false` for a failed or incomplete gate. |
| `reasons` | One plain string per reason, in order. |
| `scope` | `local_configured_policy` (`--gate`, your `[tool.skylos.gate]` limits) or `local_strict_policy` (`--strict` without `--gate`: any finding fails). |
| `status` | `evaluated`, or `incomplete` when required analysis did not finish. |
| `forced` | `true` when `--force` was given and the gate did not pass. An incomplete gate still exits `2`. |
| `verdict` | `passed`, `failed`, or `incomplete`. |
| `exit_code` | The exit status the verdict produces: `0`, `1` (`0` with `--force`), or `2`. |
| `strict` | Whether strict rules applied (`--strict` or `strict = true` under `[tool.skylos.gate]`). |
| `headline` | The verdict line printed by human output. |
| `hint` | For a pass, a note about what the default limits allowed; otherwise `null`. |
| `reason_details` | One object per entry in `reasons`, same order: `message` (equal to the string), `details` (the literal lines shown under it: at most 10 findings, then `and N more`, then file, line or count details), and `hint` (the next step, or `null`). |
| `coverage_status` | `complete`, `partial` (the verdict was decided on the code that was analysed; some was not), or `incomplete`. |
| `coverage_warnings` | One plain string per coverage gap behind a `partial` status; empty otherwise. |
| `coverage_warning_details` | Same shape as `reason_details`, one object per entry in `coverage_warnings`. |

The object is decided on the full result, before `--severity`, `--category`,
or `--file-filter` narrow the displayed findings. It appears with `--gate`,
and with `--strict` unless `--force` is also given: `--strict --force`
without `--gate` skips the policy evaluation and records no `gate` object,
though human output still ends with the verdict it was forced past. With
`--upload`, a failing Skylos Cloud gate can still exit `1` after a local
`passed` verdict. A scan without `--gate` or `--strict` that exits `2` ends
with `Scan: INCOMPLETE — required analysis did not finish (exit 2)` and the
same reasons.

For a plain `skylos . --upload`, successful Cloud delivery returns `0` even
when the Cloud quality gate reports advisory violations. Use `--gate` or
`--strict` to enforce a failing exit. A scan with incomplete analysis (exit
`2`) does not upload, and rich output shows the analysis error that blocked
it. A scan with only coverage gaps uploads; its scan-coverage receipt says
`complete: false` with reason `analysis_incomplete`, so Skylos Cloud never
treats a missing finding from that scan as fixed.

When grep verification exceeds `SKYLOS_GREP_BUDGET` (120 seconds by default)
or a search cannot finish safely, Skylos keeps the result of every candidate
it did verify: candidates with a usage stay rescued, and candidates verified
as unused are reported. Only the candidates grep did not reach are withheld;
they are recorded as abstentions (`dead_code_abstentions`, reason "grep
verification did not complete") and never shown as dead code. The scan reports
this as a coverage gap (`SKY-ANALYSIS-INCOMPLETE`, kind
`grep_budget_exhausted` or `grep_verification_incomplete`), not exit `2`. JSON
consumers can read `analysis_summary.grep_verify.verified_candidate_count`
and `unverified_candidate_count`; increase the budget (and install ripgrep)
and rerun to check the rest.

Grep verification uses ripgrep when it is installed. Without ripgrep, Skylos
searches in-process when secure file reads are available: it reads the
git-visible source files once and checks
every pattern against them, so gitignored data (datasets, videos, build
output) is never read. On a 226-file project with 2.3 GB of gitignored data,
that took grep verification from about six minutes (one `grep` process per
pattern) to about ten seconds, with identical findings. Patterns it cannot
decide in Python (non-ASCII, multi-line or untranslatable regex) and matches
in files that are not valid UTF-8 still use the one-pattern `grep` path.
`analysis_summary.grep_verify.backend` says which ran (`ripgrep`,
`in_process`, or `serial_grep` when secure in-process reads are unavailable),
and `skylos doctor` reports whether ripgrep is available. The in-process
search limits its source bytes and materialized text to
`SKYLOS_GREP_MAX_BYTES` per scan (512 MiB by default); past that it falls
back to the one-pattern path.
If `rg` is absent from `PATH`, or Skylos refuses an executable inside the
scanned project, human scan output shows the fallback and links to the
[official ripgrep installation guide](https://github.com/BurntSushi/ripgrep#installation).
Install it for faster scans, ensure `rg` is on `PATH`, and check with
`rg --version` and `skylos doctor`. Skylos does not install system tools
during a scan.

Circular dependencies (`SKY-CIRC`) are shown in rich, pretty, and concise
output, and remain available in JSON under `circular_dependencies`. When
source evidence is available, the finding points to an actual import in the
cycle. Ordinary package re-exports do not by themselves form a cycle.
Every cycle is `LOW`: a module-level import cycle is a design finding, and its
length says nothing about its impact.

`--strict` counts circular dependencies and exits with status `1` when they
remain in the selected report. Without an explicit `--gate`, concise output
also exits `1` for cycles, as it does for other findings, except
repository-policy advice (`SKY-R101`–`SKY-R105`: no type-check, lint, gate or
pre-commit configuration), which alone does not fail a concise scan and is not
listed in the first-screen maintainability measurements. Ordinary non-strict
gates keep their existing thresholds: cycles do not contribute to
`max_quality`. Their Review findings remain visible in the risk assessment.
The existing `--force` override can bypass finding
failures, but incomplete analysis still exits `2`.

Ctrl-C stops a scan within a few seconds: queued files are dropped, worker
processes are stopped, and Skylos prints `Interrupted (Ctrl-C).` and exits
`130` without a traceback.

The legacy flags still work:

```bash
skylos . --json
skylos . --llm
skylos . --github
```

## Select Exact Rules

Use `--select` to report only exact rule IDs. Matching is case-insensitive, and
the required analyzer family is enabled automatically, so selecting an AI
defect or security rule does not also require `--ai-defects` or `--danger`:

```bash
skylos . --select SKY-L012 --format concise
skylos . --select SKY-D211,SKY-D215 --format pretty
skylos . --select SKY-L012 --select SKY-D225 --format json
```

`--select` applies to rich, pretty, concise, JSON, LLM, GitHub, GitLab, and SARIF
reports. It filters reported findings rather than promising that shared
analysis phases will not execute. A selected report must not reuse a
full-project assessment for its narrower scope. Analysis errors remain
visible regardless of selection and still exit with code 2, preventing an
incomplete scan from appearing clean.

## Finding Types And Advice

Each built-in rule declares `finding_type` in the rule catalog. Reports show
this as **Type**, separately from severity:

| Type | Meaning | Examples |
|---|---|---|
| Defect | A concrete correctness pattern; still verify the finding in context | Mutable defaults, blocking async calls, discarded async results |
| Review | A potential risk requiring context | Possible SSRF, dead code, unbounded ORM queries, unsafe type assertions |
| Advice | Maintainability or tooling conventions | Function length, complexity, duplicate literals, missing annotations |

When quality checks are enabled (`--quality` or `-a`), Advice is retained in
the report. Terminal output leads with counts by type, lists Defect and Review
individually, then shows one Advice row per rule with its count and top files.
Use `--expand-advice` for every Advice location and message:

```bash
skylos . -a
skylos . -a --expand-advice
skylos . -a --format json -o report.json
```

JSON and JSON-CI retain each finding record for the chosen scan scope,
including Advice and its evidence. Findings carry `finding_type`;
`analysis_summary.finding_type_counts` contains `defect`, `review`, `advice`
and `advice_groups`. Grouping and expansion never alter these records or gate
inputs. Finding Type does not suppress findings or change analyzer thresholds.

Deterministic LLM reports and MCP scan replies list Defect and Review in full
and summarize Advice by rule by default. `--expand-advice` expands Advice in
LLM reports. MCP callers can request `expand_advice` or read the complete scan
resource URI returned with the reply; the stored report retains all Advice.
An advice-only report says how much Advice exists rather than claiming there
are no findings.

The assessment is computed before display grouping and filtering. A
severity/category/file display filter retains the assessment and discloses
that it describes all analyzed findings, including rows outside that display.
An explicitly selected-rule or diff-only report must not reuse a full-project
assessment. Configured gate limits and `--strict` retain their existing
meanings: finding Type is not a gate exemption.

Changed-code analysis policies remain separate from display grouping. Diff
metrics still move to `code_health` as described below.

## Scan Assessment

Remember **Risk, Maintainability, Dead code, Gate**. These answer different
questions, so new source scans do not average them into one score or A–F letter.
JSON uses the top-level `assessment` object, version `1`; it no longer emits a
new numeric `grade`. Historical scores describe the older grading formula.
The separate `skylos debt` and `skylos defend` scores retain their own contracts.

| Readout | Meaning |
|---|---|
| Risk | Highest unresolved severity and counts among Defect and Review findings, excluding dead-code candidates. Correctness findings in `quality` are included. |
| Maintainability | Advice counts and groups, affected code units where measurable, and observed values against their rule limits. |
| Dead code | Candidate counts, confidence and evidence for deciding what to review or remove. |
| Gate | PASS or FAIL against the configured policy when a gate is evaluated, INCOMPLETE when required analysis did not finish; otherwise not evaluated. JSON: the top-level `gate` object ([Gate verdict](#gate-verdict)). |

One critical secret stays critical regardless of repository size, other clean
categories or the amount of Advice. A critical Review finding still requires
urgent assessment, but the label does not establish exploitability. Advice
does not dilute risk; dead-code candidates are kept in their own readout.

Maintainability describes **spread** and **excess**:

- **Spread:** affected units divided by units actually measured for the same
  rule and language. For example, 30 of 200 measured Python functions exceed
  a complexity limit: 15%. This is a prevalence measurement, not a bug probability.
- **Excess:** observed value relative to the configured threshold. Complexity
  11 against limit 10 is 1.1× the limit; complexity 45 is 4.5×. These do
  not receive the same description merely because each produced one finding.
- Multiple observations on the same unit count that unit once within a rule
  when measuring spread. Every observation remains in the report.
- Counts remain available when a rule lacks a complete unit inventory. Its
  denominator is unavailable and no percentage is guessed. Measurements for
  one language cannot be diluted by adding unrelated code in another.

Function inventories currently cover these measured checks when quality
analysis runs successfully:

| Language | Checks with function denominators |
|---|---|
| Python | Cyclomatic and cognitive complexity, nesting, argument count, function length |
| TypeScript / JavaScript | Cyclomatic complexity, nesting, argument count, function length |

Other Advice rules and languages retain counts and evidence, with unavailable
denominators where no matching inventory exists. Per-rule exclusions are
respected; for example, TS/JS test callbacks excluded from the function-length
check are also excluded from that check's denominator.

There is no maintainability letter or numeric health score until its bands
have been calibrated against manually reviewed repositories. A repository
with thousands of Advice findings cannot receive an A+ because Advice reached
a global penalty cap.

Coverage stays alongside the readouts. Disabled checks are **not assessed**;
failed or unavailable checks are **incomplete**. Known findings remain visible
when another check fails. Zero findings describes only the checks and scope
that completed. It does not prove a repository safe or certify a release.

Display grouping, expansion and severity/category/file views cannot improve
the assessment. True changes in analysis scope, such as exact rule selection
or a diff, do not borrow a whole-project assessment. Gate enforcement remains
independent: Advice in `quality` still counts toward applicable limits, while
the existing code-health and architecture exemptions below remain explicit.

## Repository CI Scope

With `--danger` or `-a`, full directory scans inside a verified Git worktree
include its active root GitHub Actions workflows and default `.gitlab-ci.yml`,
even when the selected directory is `src`. These CI files apply to the
repository's source. Source files, Dockerfiles, deployment configuration and
local actions remain within the selected directory.

The same workflow findings remain visible in clean, staged, unstaged and
untracked-only working trees. Uncommitted edits do not turn a full scan into
a diff scan. Explicit changed-file filters still select CI files: a source-only
diff does not add findings from unchanged root workflows.

Skylos uses the actual Git worktree root, including linked worktrees, rather
than a nearby `pyproject.toml`. Nested repositories use their own root CI;
file lists spanning separate worktrees do not gain an outer repository's CI
checks. Symlinked root CI files or workflow directories are not followed.
Single-file inputs and directories without a verified Git worktree retain
their existing local configuration scope.

## Review Changed Lines

`skylos . --diff origin/main --format json` analyzes the selected project for
context and reports code findings on changed lines. Use `--diff-base origin/main`
to report findings anywhere in changed files instead. Both modes compare the
merge base of the ref and `HEAD` with the **working tree**, so committed,
staged and unstaged edits all count, and untracked files that are not
gitignored count as fully changed. `skylos . -a --diff HEAD` therefore reviews
exactly your uncommitted work. In CI the working tree is clean, so this matches
a `REF...HEAD` comparison. `skylos cicd review` PR comments still use committed
changes only (`REF...HEAD`). A valid diff with no
changed lines or files has no diff findings. An unavailable base ref exits with
status 2 instead of returning the full scan as a PR result. Both scoped reports
do not reuse a full-project assessment for the narrower findings scope.
The JSON `definitions` and `dead_code_evidence` fields retain full-project
analysis context; the finding lists and their summary counts are scoped.
`--diff` with no value uses the pull request target branch from
`GITHUB_BASE_REF`, Bitbucket Pipelines or Azure Pipelines (see
[Bitbucket and Azure Pipelines](./bitbucket-azure-pipelines.md)), else
`origin/main`.
Diff-scoped reports cannot be combined with `--upload`, because Cloud treats
uploaded scans as full-project results. Run a separate full scan to upload.
Removing a call can make an unchanged function dead; neither diff mode currently
reports that function unless its definition is also in the selected scope.

### Code health metrics in diff scans

Size, complexity and style metrics are not reported as findings in diff-scoped
scans (`--diff`, `--diff-base`, `skylos cicd review`): function length
(`SKY-C304`), argument count (`SKY-C303`), cyclomatic and cognitive complexity
(`SKY-Q301`, `SKY-Q306`), nesting (`SKY-Q302`), return count (`SKY-L028`),
try-block size (`SKY-L004`), repeated literals (`SKY-L027`), boolean
parameters (`SKY-L029`), class cohesion (`SKY-Q702`) and missing annotations
(`SKY-T101`, `SKY-T102`).
They move to a separate `code_health` list in the JSON report:

- Skylos re-measures each changed Python file at the merge base. A metric the
  change introduced, or made worse (a higher value than at the base), is listed
  with `"code_health_change": "introduced"` or `"worsened"`.
- A metric that already exceeded its threshold at the base and did not get
  worse is dropped. `analysis_summary.code_health_preexisting_count` counts them.
- If the base cannot be measured (a non-Python file, or the base ref is
  unavailable), the metric is listed as `"unverified"`.

`code_health` entries are included in the type counts and remain available
as maintainability Advice. They never fail `--gate` or
`--fail-on`, and they are not posted as PR review comments. A full scan reports
the other code-health rules under `quality`; there they count toward the
gate, regardless of whether Advice is grouped or expanded in the display. To enforce one of those metrics in PR
checks, run a full scan with the gate. Default advisory architecture metrics
(`SKY-Q802`, `SKY-Q803`) are shown in full scans and omitted from diff-scoped
reports because their values depend on the whole dependency graph.

### What a full scan leaves out

A first scan should be quiet and believable. Generated and vendored files are
left out of a scan by default, and the scan says so in one line:

```text
Skipped 201 generated/vendored files (190 Django migrations, 11 web-root library files); use --include-generated to scan them.
```

**Generated and vendored files.** These are skipped by default:

- Django migrations: a `.py` file in a `migrations` package (with
  `__init__.py`) that imports `django.db` and defines
  `class Migration(...Migration)`. A test package or Alembic folder that is
  merely called `migrations` is scanned as usual. Migrations are still parsed,
  so code that only a migration uses is not reported as unused, and their
  security (`danger`, `reliability`), secret and custom-rule findings are kept,
  because migrations run at deploy time. Their dead-code, quality and AI-defect
  findings are not reported.
- Vendored and minified front-end files, removed from the scan like the
  `vendor` default exclude: JS/CSS in a library folder under a web root
  (`static/` or `public/`, then `lib/`, `libs/`, `vendor/` or `vendors/`,
  such as `public/libs/tinymce/**`), `*.min.js`, `*.min.css`, JS/CSS files
  whose first comment is a library licence banner (`/*!` or `@license` with a
  version and a licence or copyright line), and other minified JS/CSS: at
  least 1 KB with an average line length above 110 characters (GitHub
  Linguist's rule), such as a one-line bundle without a `.min` suffix.

`analysis_summary.generated_files` lists every skipped file by reason
(`skipped_count`, `by_reason`, `files`); `findings_not_reported` counts the
quality and AI-defect findings dropped from migrations (their definitions are
not dead-code candidates, so dead code there is not evaluated). Scan them
with `--include-generated`, `--no-default-excludes`, or
`[tool.skylos] include_generated = true`; keep one folder with
`--include-folder PATH`. A file named on the command line is never skipped,
and path rules only look below the directory you scan, so
`skylos app/migrations` scans those migrations. Synced Skylos Cloud policy can
set `include_generated`, and repository config cannot turn it back off.

**CRITICAL is for shipped code.** Complexity and nesting rules top out at
HIGH. A CRITICAL finding in a test file (`tests/`, `test_*.py`, `*.test.ts`,
`conftest.py`, ...) is reported as HIGH with `"original_severity": "CRITICAL"`
and `"severity_reason": "test_file"`; `analysis_summary.test_file_severity_capped`
counts them. Secrets keep CRITICAL wherever they are committed.

### Architecture advisories in full scans

By default, `SKY-Q802` (distance from the main sequence) and `SKY-Q803`
(architecture zone) are file-level advisory metrics. A full scan groups both
signals for the same module into one record in
`architecture_metrics.advisories`. Each record has `file`, `name`, `rule_ids`,
and `signals`; the signals retain their original rule IDs, evidence, and
severity. `architecture_metrics.advisory_count` counts modules, while
`advisory_signal_count` counts the underlying rule signals.

These advisories remain in the maintainability assessment and type counts.
They are excluded from local `quality`, `analysis_summary.quality_count` and
local gate inputs. Complete SARIF and Cloud uploads retain their individual
records with their Advice type. Cloud evaluates its configured policy over the
uploaded findings, so retained records may affect its count limits even when
local analyzer policy treats them as report-only.
Local `json` and `json-ci` also retain them, including when selected with
`--select SKY-Q802` or `--select SKY-Q803`. `concise` prints one advisory line
per module without treating it as a blocking finding. Set
`[tool.skylos.architecture] enforce_iad = true` to put both rules in `quality`
and make them eligible for enforcement. `SKY-Q805` (layer policy) remains an
Review finding in `quality`; `SKY-Q804` is Advice, displayed in the grouped
Advice section by default. See [finding types](#finding-types-and-advice).

## SARIF And GitHub Code Scanning

`skylos . -a --sarif skylos.sarif` writes a SARIF 2.1.0 log next to any other
output. Each result carries:

- `properties.finding_type`: `defect`, `review` or `advice`, independently of
  severity. Advice is retained as individual SARIF results where its existing
  analyzer policy makes it an issue finding.
- `partialFingerprints["skylosFindingHash/v1"]`: a SHA-256 of the rule ID, the
  normalized file path, and a line-independent anchor (symbol name, normalized
  snippet or source line, or dependency identity), plus an occurrence suffix.
  Line shifts from unrelated edits do not change it, so code scanning keeps
  alert history instead of closing and reopening alerts.
- `relatedLocations` when the finding records secondary locations (for example
  the Service and Deployment behind an exposed Ingress).
- `codeFlows` only when the analyzer recorded a source-to-sink path
  (`security_evidence.path`, for example SSRF and Server Action SQL taint).
  Steps without their own file and line are shown at the finding location.

Rules include `helpUri`, `properties.tags` (with `security` and
`external/cwe/cwe-N` tags), and, for security, secret, and dependency rules,
`properties["security-severity"]` so GitHub ranks alerts as critical (9.5), high
(8.0), medium (5.5), or low (3.0). Dependency rules use the advisory CVSS score
when one is available.

The GitHub Action can upload the SARIF to code scanning. It is off by default:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: duriantaco/skylos@main   # or a pinned release
    with:
      analysis: "security secrets sca"
      upload-sarif: "true"
      sarif-category: "skylos"   # optional; use distinct values for multiple runs
```

Upload applies to source scans (not `image:` scans) and uses
`github/codeql-action/upload-sarif`.

## Provenance Attribution

`skylos provenance` reads recorded contributions and declared commit
associations. Neither source is a cryptographic proof of an AI writer; local
metadata can be modified by its producer. Untagged code stays **unknown**.

Recorded line evidence is read from:

- Git AI `authorship/3.0.0` notes under `refs/notes/ai`, attached to HEAD.
- Agent Trace `0.1.0` JSON records in `.agent-trace/*.json` or
  `.skylos/agent-traces/*.json`. Agent Trace leaves storage to implementations.

The reader accepts ranges only when the current file matches the recorded Git
revision or a `sha256:` whole-file hash in
`metadata["dev.skylos"].files[path].content_hash`. Git AI notes must match both
HEAD and the current file. Shifted or modified files lose attribution until a
recorder reconciles them; ranges are never relocated by ambiguous text searches.
When current bytes match HEAD, the output includes HEAD as `revision`, allowing
Cloud to validate the content independently. Uncommitted records have no revision
and remain local assertions.

Skylos does not fetch notes automatically. Fetch them explicitly in CI when
your repository publishes them:

```bash
git fetch origin refs/notes/ai:refs/notes/ai
```

Reinstall `skylos agent install-hooks --claude` or `--codex` to enable before
and after capture for edit tools. Durable Agent Trace records contain hashes,
line ranges and tool/model/session identifiers, without source text or prompts.
Temporary before-images remain in the ignored `.skylos/cache/` directory.
Direct tool output must match its input before new lines receive agent
attribution. Missing checkpoints, failed tools, overlapping capture, ambiguous
duplicate lines, and shell-generated changes remain unknown. Cursor's existing
after-file-edit hook lacks a matching before-image, so it cannot establish line
ownership by itself. Capture is best effort: disabled hooks, missing clients,
concurrent external editors, files outside the repository, binary or oversized
files, and later manual edits limit coverage. The reader bounds record sizes,
counts, ranges and paths and rejects symlink traversal. The local history is
capped at 200 records. A valid `current.json` trace also retains the latest
state of up to 1,000 files within a 2 MB limit, so new capture can continue when
the history fills. These bounds are reported as partial coverage.

The supported formats are described by the
[Git AI specification](https://github.com/git-ai-project/git-ai/blob/main/specs/git_ai_standard_v3.0.0.md)
and [Agent Trace specification](https://agent-trace.dev/).

Commit metadata supplies **declared file associations**, using these signals:

- a `Co-authored-by` trailer (or the commit author) whose identity is a known
  agent: Claude (`noreply@anthropic.com`, `claude[bot]`), Copilot
  (`Copilot@users.noreply.github.com`, `copilot-swe-agent[bot]`), Cursor
  (`cursoragent@cursor.com`), Codex (`chatgpt-codex-connector[bot]`), Devin
  (`devin-ai-integration[bot]`), Aider (`noreply@aider.chat` or a `(aider)`
  author suffix), Jules, and Amazon Q bots;
- an explicit declaration trailer such as `Assisted-by:` or `Generated-by:`
  that names a known agent, or any `AI-Agent:` trailer;
- a subject that names an agent, such as `Generated with Claude Code`.

A person whose name contains "Claude" or "Cursor", web-UI commits using
`noreply@github.com` or a personal `users.noreply.github.com` address, and
staff addresses at agent vendors are not AI. Dependabot, Renovate,
github-actions, and other `[bot]` accounts are reported as automation in
`automation_files` and `summary.automation_seen`, never as AI. The
`agent_files` includes recorded agent contributions and declared associations.
`human_files` contains recorded human contributions; it does not mean the entire
file is human-written. `unknown_files` replaces the old assumption that every
unmarked file was human-written. `summary.recorded_count` and `declared_count`
count the two sources independently; a file can have both. Repeating a commit
label does not strengthen its evidence or create line ownership.

Each provenance file includes `evidence_source`, `attribution_level`
(`recorded`, `declared`, `automation`, or `unknown`), `attribution_scope`
(`line`, `file`, or `none`), `contributors`, `commit_contributors`,
`content_hash`, and `revision`.
Recorded contributors carry their own `agent_name` and `agent_lines`, so a file
with multiple agents does not arbitrarily select one author. Conflicting records
stay unknown. `commit_contributors` separately retains declared agents with
empty line ranges, including when later line records name another agent, a
human, or an unknown contributor. Such records do not erase commit declarations
or turn them into line authorship. `status.line_records_summary` reports
rejected and stale records, capture gaps, limits and partial coverage.

Finding `ai_authored` is `true` only inside recorded agent ranges, `false` for
recorded human ranges or automation, and `null` when authorship is unknown.
Declared file associations use `ai_declared: true` instead of claiming the
finding's line was written by that agent. `ai_declared_agents` names those
declared agents independently of the recorded line's `ai_agent`. A finding
outside recorded ranges can therefore have `ai_authored: null` and
`ai_declared: true`. `ai_security_stats` exposes
`unknown_findings`, `declared_ai_findings`, and `recorded_human_findings` alongside
the recorded agent counts.

## Uploading To Skylos Cloud

`skylos . --upload` (and `skylos debt . --upload`) sends the scan to Skylos
Cloud. The upload follows a versioned contract shared with the server
(`skylos/api/upload_contract/v1.json`).

New code-scan uploads send `metadata.assessment` with the separate risk,
maintainability and dead-code readouts, measurements and coverage. Type is
retained for findings; Cloud derives the canonical built-in classification
from its rule catalog. The Cloud gate evaluates project policy independently
of the local readouts. Historical numeric grades describe the legacy model
and do not become new assessment scores.

Code-scan uploads include a bounded `scan_coverage` receipt with the scan
scope, completeness, selected rules, and `resolution_covered_checks`. A
selected-rule, diff, suppressed, or incomplete scan covers no checks for
absence-based issue resolution. Dependency coverage can be omitted while
other checks remain complete. The upload also carries
`quality_rule_classification.architecture_iad` and aggregate
`architecture_advisories` counts. Advisory source paths and messages stay in
local output; they are not uploaded as actionable SARIF findings. Cloud
validates these client claims before using them for issue history. Local JSON
exposes `analysis_summary.resolution_scope_limited` and
`architecture_metrics.iad_enforced` for inspection.

For a full-scan upload, Skylos also sends `source_revision_state` as `clean`,
`dirty`, or `unknown`. `clean` means the local checkout matched the reported
Git HEAD when the upload was prepared. Partial scans, unavailable Git data,
unsupported repository entries, or a revision mismatch produce `unknown`.
This is local metadata, not proof that an API-key upload matches a remote
GitHub commit or that files were unchanged throughout the scan.

**Before sending**, every finding is checked against the contract. Findings are
never dropped:

- Repository-level findings (`SKY-R101`–`SKY-R104`, kind `repo_policy`) are
  sent at the project root (`.` at the repository root, otherwise the project
  subpath) on line 1.
- Paths are sent relative to the repository (or, outside a Git repository,
  to the working directory) and normalized inside it. The local checkout path
  is never uploaded, and neither is a path that climbs out with `..`.
- A finding without a usable location (no path, a placeholder such as
  `unknown`, a file outside the repository, or a folder) is still sent, with
  an empty path; Cloud stores it without a location. The CLI prints one line,
  for example `2 findings have no file location; uploading them anyway.`
- A `%` in a file name is sent as `%25`, because Cloud percent-decodes paths
  once.

**Retries.** Only connection errors, timeouts and HTTP 408, 425, 429, 500, 502,
503 and 504 are retried: at most 4 attempts, with exponential backoff and full
jitter (1s base, 30s cap). A `Retry-After` header (seconds or HTTP date) is
honoured; if it asks for more than 30 seconds the CLI stops and saves the scan
instead of waiting. A 409 that Cloud marks retryable (for example
`UPLOAD_IN_PROGRESS`: the same upload is still being processed, usually after a
slow first attempt) is retried after its `Retry-After` for up to 300 seconds in
total, without using up the 4 attempts; the finished scan then comes back as a
replay. Other 4xx responses are never retried. Requests to the report
endpoints wait up to 270 seconds for an answer (the contract's
`client_read_timeout_seconds`), so a slow but working upload is not cut off.
Every request of one
upload, including its retries, the large-scan `init`/`complete` calls and later
resends, carries the same `Idempotency-Key` (a UUID v4) plus
`X-Skylos-Upload-Contract: 1` and `X-Skylos-Cli-Version`, so Cloud can tell a
retry from a new scan and never saves it twice. Falling back from
the large-scan path to the compact inline upload is a different request and
gets a new key. When Cloud answers `Idempotent-Replayed: true`
the CLI prints `Scan was already saved by an earlier attempt`.

**Errors** are printed as one sentence, what to do, and a reference to quote
to support, never as a raw response body:

```text
Upload failed: Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.
Upload failed: Skylos Cloud had a temporary problem (HTTP 503). The scan was saved; run 'skylos upload --retry' to send it. (ref: req_8f2c)
```

**Saved uploads.** When an upload fails for a temporary reason (network,
timeout, 5xx, 429, or Cloud still processing the same upload) or is
interrupted with Ctrl-C or SIGTERM, the scan is saved outside the repository,
in your own state folder:
`~/.skylos/pending-uploads/<repo-id>/<idempotency-key>.json.gz` (`<repo-id>`
is derived from the repository's path; files 0600, folders 0700). Each file is
signed with HMAC-SHA256 using a key kept in
`~/.skylos/pending-uploads/.record-key` (0600), so a file you did not write,
for example one committed to a repository, is never sent under your token.
The file holds the exact request bytes that were sent (and, for large scans,
the exact artifact files), plus the project id, endpoint, key, time and CLI
version. It never holds your token, and SECRET findings never carry a code
snippet (they are removed before the first send). The next
`skylos . --upload` reminds you, and:

```bash
skylos upload --list    # show saved scans
skylos upload --retry   # resend them with their original keys
```

A resend sends the saved bytes unchanged with the original key, so Cloud
recognises it. A resent scan that Cloud accepts, or already had, is deleted.
One that Cloud rejects for a reason a retry cannot fix moves to the queue's
`failed/` folder with a `<key>.reason.json`. A scan is only sent to the same
endpoint and the same linked project it was saved for. Scans are only
resent within 7 days (the contract's `client_resend_window_days`; Cloud keeps
keys for 8); older ones move to `failed/` with the reason
`too old to resend safely; rerun the scan`. The folder keeps at most 20 scans
and 200 MB, dropping the oldest first. `skylos upload --retry` exits 1 while
any scan is still unsent.

Earlier versions of this feature saved uploads inside the repository, in
`.skylos/pending-uploads/`. Those files are never sent; `skylos upload` and
`skylos . --upload` print one line saying where they are. Rerun the scan to
upload, then delete that folder.

**Large scans** (more than 4 MB inline, `SKYLOS_INLINE_UPLOAD_LIMIT_BYTES`) use
the artifact path automatically: `init`, a gzip upload to storage, then
`complete`.

**Contract version.** While uploading, the CLI asks
`GET /api/report/contract` (2-second timeout, once per run, silent on any
error). If Cloud speaks a newer contract it prints one line suggesting
`pip install -U skylos`.

Managed GitLab uploads keep their own rules: one attempt, no retries, no saved
uploads and no automatic re-upload.

| Variable | Default | Effect |
|:---|:---|:---|
| `SKYLOS_UPLOAD_MAX_ATTEMPTS` | `4` | Attempts per request (1-10). |
| `SKYLOS_UPLOAD_RETRY_BASE_SECONDS` | `1` | Backoff base. |
| `SKYLOS_UPLOAD_RETRY_MAX_SECONDS` | `30` | Backoff and `Retry-After` cap. |
| `SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS` | `300` | How long a retryable 409 is waited out. |
| `SKYLOS_PENDING_UPLOAD_DIR` | `~/.skylos/pending-uploads` | Root of the per-user saved-upload queue. |
| `SKYLOS_UPLOAD_CONTRACT_CHECK` | `1` | `0` turns the contract-version check off. |

## Selectable Terminal UI

Use the TUI when you want keyboard-driven triage:

```bash
skylos . --tui
skylos . -a --tui
```

The TUI uses a category sidebar plus a selectable finding list and detail pane. Common controls:

| Key | Action |
|:---|:---|
| `j` / `k` | Move through findings |
| `/` | Search current findings |
| `f` | Cycle severity filter |
| `Tab` / `Shift+Tab` | Move between categories |
| `o` | Open the selected finding in `$EDITOR` |
| `q` | Quit |

`--tui` requires an interactive terminal and is screen-only, so it cannot be combined with `--output`. For saved reports, CI, scripts, and logs, prefer `--format concise`, `--format json`, or `--format pretty`.

## Common Workflows

- Local development review: `skylos . --format pretty`
- CI logs and scripts: `skylos . --format concise`
- Debugging full scan results: `skylos .`
- Tooling and integrations: `skylos . --format json`
- AI-assisted workflows: `skylos . --format llm`
- GitHub Actions annotations: `skylos . --format github`
- GitLab merge request reports: `skylos . --format gitlab -o gl-code-quality-report.json`
- Deep interactive investigation: `skylos . --tui`
