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
| AI-ready report | `skylos . --format llm` | Agent workflows and structured reasoning systems |
| GitHub Actions annotations | `skylos . --format github` | Inline workflow annotations in GitHub checks |
| Interactive terminal triage | `skylos . --tui` | Keyboard-driven exploration of findings |

## Human Terminal Output

Use the default `rich` format when you want the existing full report:

```bash
skylos .
skylos . -a
```

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

Use `json`, `llm`, or `github` for structured consumers:

```bash
skylos . --format json
skylos . --format llm
skylos . --format github
```

## Exit Codes And Incomplete Analysis

Skylos reserves exit status `0` for successful command completion, `1` for
finding or policy failures in modes that enforce them, and `2` when required
analysis could not complete. An unavailable native language engine is an
incomplete analysis: Skylos emits a `SKY-ANALYSIS-INCOMPLETE` diagnostic, omits
the grade and clean-code claim, and exits with status `2` in every output mode.
`--force` and advisory gate settings do not convert incomplete analysis into a
passing result.

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

`--select` applies to rich, pretty, concise, JSON, LLM, GitHub, and SARIF
reports. It filters reported findings rather than promising that shared
analysis phases will not execute. A selected report omits the aggregate grade,
because that grade describes the unfiltered scan. Analysis errors remain
visible regardless of selection and still exit with code 2, preventing an
incomplete scan from appearing clean.

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
- Deep interactive investigation: `skylos . --tui`
