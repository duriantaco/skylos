# CLI Output Modes

CLI output modes control how Skylos displays scan results in the terminal. Each mode is designed for a different workflow such as human review, automation, CI pipelines, or AI-assisted processing.

If you're unsure which mode to use, the table below provides a quick reference.
Most entries are `--format` values; the TUI is a separate `--tui` mode because
it opens an interactive screen instead of printing a report.

Skylos keeps the default terminal output stable for existing scripts and copy/paste workflows, then offers opt-in formats for more focused use cases.

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

The default table report shows a score badge and copies its Markdown to the
clipboard only when stdout is an interactive terminal and no CI variable is
set. Redirected or piped output, CI runs and machine formats (`--format json`,
`--sarif`, `--llm`) never touch the clipboard. Opt out entirely with
`--no-clipboard` or `SKYLOS_NO_CLIPBOARD=1`.

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
you need those full symbol details; its output is unchanged.

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
finding or policy failures in modes that enforce them, and `2` when required
analysis could not complete. An unavailable native language engine is an
incomplete analysis: Skylos emits a `SKY-ANALYSIS-INCOMPLETE` diagnostic, omits
the grade and clean-code claim, and exits with status `2` in every output mode.
`--force` and advisory gate settings do not convert incomplete analysis into a
passing result.

The same contract applies when grep verification exceeds
`SKYLOS_GREP_BUDGET` (30 seconds by default). Skylos discards the partial grep
verdicts, records the affected dead-code candidates as abstentions, emits
`SKY-ANALYSIS-INCOMPLETE`, and exits with status `2`. JSON consumers can inspect
`analysis_summary.grep_verify.status` and `incomplete_reason`; increase the
budget and rerun before treating the dead-code result as complete.

Circular dependencies (`SKY-CIRC`) are shown in rich, pretty, and concise
output, and remain available in JSON under `circular_dependencies`. When
source evidence is available, the finding points to an actual import in the
cycle. Ordinary package re-exports do not by themselves form a cycle.

`--strict` counts circular dependencies and exits with status `1` when they
remain in the selected report. Without an explicit `--gate`, concise output
also exits `1` for cycles, as it does for other findings. Ordinary non-strict
gates keep their existing thresholds: cycles do not contribute to
`max_quality` or grades. The existing `--force` override can bypass finding
failures, but incomplete analysis still exits `2`.

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
analysis phases will not execute. A selected report omits the aggregate grade,
because that grade describes the unfiltered scan. Analysis errors remain
visible regardless of selection and still exit with code 2, preventing an
incomplete scan from appearing clean.

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
omit the full-project grade, which would describe findings that are not shown.
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
parameters (`SKY-L029`), class cohesion (`SKY-Q702`), architecture metrics
(`SKY-Q802`, `SKY-Q803`) and missing annotations (`SKY-T101`, `SKY-T102`).
They move to a separate `code_health` list in the JSON report:

- Skylos re-measures each changed Python file at the merge base. A metric the
  change introduced, or made worse (a higher value than at the base), is listed
  with `"code_health_change": "introduced"` or `"worsened"`.
- A metric that already exceeded its threshold at the base and did not get
  worse is dropped. `analysis_summary.code_health_preexisting_count` counts them.
- If the base cannot be measured (a non-Python file, or the base ref is
  unavailable), the metric is listed as `"unverified"`.

`code_health` entries are not counted as findings. They never fail `--gate` or
`--fail-on`, and they are not posted as PR review comments. A full scan
(`skylos .`) still reports these rules under `quality`, and there they count
toward the gate as before. To enforce a metric in PR checks, run a full scan
with the gate.

## SARIF And GitHub Code Scanning

`skylos . -a --sarif skylos.sarif` writes a SARIF 2.1.0 log next to any other
output. Each result carries:

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

`skylos provenance` counts a commit as AI-authored only from explicit agent
signals:

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
`agent_files`, `automation_files` and `human_files` lists (and
`summary.agent_count`, `automation_count`, `human_count`) are disjoint: a file
touched by any AI commit is AI, otherwise a file touched by a bot commit is
automation, otherwise it is human. For "everything not AI-authored", combine
`human_files` and `automation_files`.

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
