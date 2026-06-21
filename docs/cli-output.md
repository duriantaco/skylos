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

Example shape:

```text
Skylos static analysis  3 issues  1 file analyzed
  unused functions: 2  unused variables: 1

  src/app.py · 3 issues

    █  LOW  dead-code/function  Unused function: old_handler
      Dead Code  src/app.py:42
      def old_handler() -> None:
      Fix: Remove the unused function if it is not public API.
```

Write the same pretty report to a file with `--output`:

```bash
skylos . --format pretty --output skylos-report.txt
```

## Copyable And Machine Output

Use `concise` when an editor, test script, or agent needs plain `file:line` findings and a non-zero exit code when findings exist:

```bash
skylos . --format concise
```

Use `json`, `llm`, or `github` for structured consumers:

```bash
skylos . --format json
skylos . --format llm
skylos . --format github
```

The legacy flags still work:

```bash
skylos . --json
skylos . --llm
skylos . --github
```

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
