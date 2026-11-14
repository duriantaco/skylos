# Type checking

Skylos can run your project's own type checker and report its errors next
to the scan. It has no type system of its own and never installs a checker:
it runs the one the project already uses. It is off unless you ask for it.

```bash
skylos . --type-check
skylos . --type-check --type-checker mypy --type-check-timeout 300
skylos . --type-check --diff origin/main
```

## What it runs

| Checker | Command Skylos runs |
|:--|:--|
| mypy | `mypy --no-pretty --no-color-output --show-column-numbers --show-error-codes --error-summary --config-file <your config> .` (the `.` is left out when the config names its files) |
| pyright | `pyright --project . --outputjson` |
| pyrefly | `pyrefly check --output-format json` |
| tsc | `tsc --project tsconfig.json --noEmit --pretty false` |

Skylos picks the checker from the project's configuration
(`[tool.mypy]`, `mypy.ini`, `.mypy.ini`, a `[mypy]` section in `setup.cfg`,
`pyrightconfig.json`, `[tool.pyright]`, `pyrefly.toml`, `[tool.pyrefly]`,
`tsconfig.json`), or from
`[tool.skylos.type_check] checker = "…"`, or `--type-checker`. If several are
configured, name one. It looks for the program in `.venv/bin`, `venv/bin`
and `node_modules/.bin` before `PATH`. This runs the checker and any plugins
it is configured with, so only use it on code you trust. The default time
limit is 120 seconds.

## What it reports

Errors keep the checker's own codes (mypy `assignment`, `TS2322` and so on);
there are no SKY rule IDs for them.

- **Without a base,** every error is listed as `unclassified`.
- **With `--diff REF`** (or in `skylos verify --diff` and `skylos done`),
  Skylos copies the base commit to a temporary folder and runs the same
  checker there with the same settings. Each error is then `introduced` by
  the change, `preexisting`, or still `unclassified` when Skylos cannot
  match it reliably. It also flags type-suppression comments the change
  added to production code, for the checker in use: `type: ignore` (all
  Python checkers), `mypy: ignore-errors` and `mypy: disable-error-code`,
  `pyright: ignore` and `pyright: basic`, `pyrefly: ignore`, and for tsc
  `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck` and `as any`.

The terminal shows up to 50 errors; JSON output carries everything under a
top-level `type_check` key.

## Exit codes and the gate

| Result | Exit code |
|:--|:--|
| No errors, or only pre-existing errors in a comparison | 0 |
| Introduced or unclassified type errors | 1 (`--force` turns this part into 0) |
| Not configured, checker missing, timed out, or unreadable output | 2 |

The type-check result is combined with the scan's own exit code (the higher
one wins). With `--gate`, type errors are a gate failure ("Type checking failed") and
an unfinished check makes the gate INCOMPLETE.

## In `skylos done`

`skylos done --type-check` runs the check and blocks on errors the change
introduced and on new suppression comments, keeping errors that were already
there. To make it part of every run, set it in the base branch's policy:

```toml
[tool.skylos.done.checks]
type_check = "block"        # or "advise", "shadow", "off" (the default)

[tool.skylos.done]
type_checker = "auto"
type_check_timeout_seconds = 120
```

`skylos verify` takes the same `--type-check` options.
