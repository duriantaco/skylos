# Analysis profiling

When a scan is slow, `--profile` shows where Skylos spends its time. It
measures Skylos itself, not your code: nothing in the project is run, and
the findings, gate and exit code do not change.

```bash
skylos . -a --profile
skylos . -a --format json --profile-output skylos-profile.json
skylos verify . --profile
```

## What it measures

- **Phases.** Wall-clock time for each stage of the analysis, such as
  parsing, clone detection, the AI-defect scan or dead-code verification.
  Time before the first stage is shown as `analysis setup`.
- **Functions.** Python's `cProfile` run over the analysis, keeping the 20
  slowest Skylos functions by total time and the 20 by own time.

It covers the main analysis only. Start-up, output formatting, uploads and
`--type-check` happen outside it, and work in other processes or threads is
not measured.

## Where the output goes

- The tables are printed on standard error, so they do not mix with JSON on
  standard output.
- JSON output gains a top-level `profiling` key.
- `--profile-output PATH` writes the same JSON to a file and turns profiling
  on. It must differ from `--output`; a path Skylos cannot write exits 2.

The JSON holds `schema_version`, `wall_seconds`, `phases` (name, seconds,
visits), `functions` (`by_cumulative` and `by_self`, each row with file,
line, function, calls and seconds) and `notes` on what was not measured.
Attach it when you report a slow scan.
