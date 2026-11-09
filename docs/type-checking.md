# Run the project's type checker

Type checking is available to anyone running Skylos. Enable it explicitly:

```bash
skylos . --type-check
skylos . --type-check --format json
skylos verify src/app.py --type-check
skylos verify . --diff origin/main --type-check
skylos done --type-check
```

Skylos runs the installed **mypy, Pyright, Pyrefly or TypeScript compiler** using
the project's configuration. It does not implement its own type system, install
packages, or run a `package.json` script. Normal scans and verification remain
static unless you request execution with `--type-check`. A checker can execute
its configured plugins, so enable this on a repository you trust.

Skylos discovers declarations in `pyproject.toml`, `mypy.ini`, `.mypy.ini`,
`setup.cfg`, `pyrightconfig.json`, `pyrefly.toml` and `tsconfig.json`. Install the
checker using your project's normal setup. Skylos looks in the project's
`.venv`, `venv`, `node_modules/.bin`, then `PATH`. If several checkers are
configured, select one:

```bash
skylos . --type-check --type-checker mypy
```

Alternatively, declare the choice in the project:

```toml
[tool.skylos.type_check]
checker = "mypy"
```

The compiler checks the project with its actual configuration and import
context. Skylos does not pass a changed filename to `tsc` and thereby discard
`tsconfig.json`. A normal project check shows all diagnostics. A single-file
`verify` displays that canonical file's diagnostics, with counts for errors
elsewhere; another file with the same basename does not match.

## Read the result

Text reports show the tool, status, diagnostic locations, codes and origin
labels. JSON includes a separate top-level `type_check` object. Existing Skylos
findings keep their own rule IDs and severities.

Without a baseline, all current type errors block and have `unclassified`
origin. With `verify --diff REF`, a scan's `--diff REF`, or `done`, Skylos can
compare against Git's baseline using the same installed checker, configuration
and dependencies:

- **introduced:** the baseline did not have the diagnostic; it blocks.
- **preexisting:** the same diagnostic is confirmed on the corresponding
  unchanged source line; it remains visible and does not block.
- **unclassified:** attribution is uncertain; it blocks until reviewed.

An edit can break an unchanged caller. A comparable new diagnostic there is
retained with `scope: "dependency_impact"`, even during single-file verification.
Moving or rewriting a line with an existing error does not automatically earn
a `preexisting` label.

A comparable opted-in check also blocks newly added compiler escape hatches in
production code: Python type-ignore directives, TypeScript `@ts-ignore`,
`@ts-expect-error`, `@ts-nocheck`, and assertions to `any`. These appear as
`type-suppression` or `type-escape` diagnostics with `source: "suppression_guard"`.
Existing or moved suppressions, test code, generated code, and lookalike text
inside strings are excluded. This guard requires a comparable baseline;
`escape_guard.status` records whether it ran. Existing A118/T104 rule defaults
retain their current behavior when this opt-in check is absent.

The baseline is read into a temporary source snapshot. Skylos does not stage
edits, create Git worktrees, install old dependencies, or modify the checkout.
Comparison reuses the installed dependency environment and requires it to stay
stable throughout the run.
Changed dependency files or checker settings, source-path environment overrides,
unsupported configuration inheritance, unavailable baseline dependencies,
unsupported symlinks/submodules needed for a baseline run, a timeout or a checker crash produce an
**incomplete** comparison. Current diagnostics remain available; Skylos does
not claim they are preexisting. TypeScript project-reference builds are not
supported by this first project-check adapter.

A missing or ambiguous checker is incomplete, with setup information rather
than a silent pass. For scans and `verify`, type errors exit 1 and an incomplete
requested check exits 2. `--force` on scans can override type errors, but cannot
turn an incomplete check into a completed check. `verify --no-fail` retains its
explicit exit-code override.

For scans and `verify`, `--type-check-timeout SECONDS` sets the shared time
budget for the current run and any baseline run (default 120 seconds). This
does not impose a time limit on the separate static analysis.

## Enable it in Done and agent stop checks

For a trusted project policy:

```toml
[tool.skylos.done]
type_checker = "mypy"
type_check_timeout_seconds = 120

[tool.skylos.done.checks]
type_check = "block"
```

Done reads policy from the trusted baseline. An edit cannot disable that
policy or replace its checker. `type_check = "advise"` reports without blocking;
the default is `"off"`. `done --type-check` explicitly strengthens the check
to blocking. `--no-tests` does not disable type checking. The Done receipt
includes diagnostics and origin labels, so installed agent stop hooks and
people running the CLI see the same result.

Use [`--profile`](profiling.md) to investigate time spent inside Skylos's
static scanner. The external type checker has its own `type_check.seconds`
measurement; the scanner profile does not profile the compiler or application.
