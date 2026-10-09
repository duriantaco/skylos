---
name: skylos
description: Run the local Skylos CLI to check code you changed for security issues, hard-coded secrets, made-up packages and APIs, and dead code, and to check whether a change is really finished (tests pass, none deleted, skipped or weakened). Use before telling the user a change is done, after adding dependencies, when a Skylos hook blocks an action, or when asked to scan for dead code or security issues.
---

# Using Skylos

Skylos is a local static-analysis CLI. This plugin's hooks already run it on
each edit, file read, package install and stop. Use the commands below to check
work yourself and to understand what a hook told you.

## 1. Check that it is installed

```bash
skylos --version   # the hooks need 4.44.0 or newer
skylos doctor      # installation health check
```

If `skylos` is missing, tell the user and suggest `pip install -U skylos`.
Don't install it without asking.

## 2. Check the lines you changed

```bash
skylos verify . --diff origin/main --format short   # one line per finding, then a verdict
skylos verify . --diff origin/main --format json    # machine-readable
skylos verify . --file app.py --range 10:40         # one file, one line range
```

`--diff REF` covers commits after REF plus staged, unstaged and untracked
files (use `--diff HEAD` for uncommitted work only). The JSON has `status`
(`pass`, `fail` or `incomplete`), `findings` and `summary`. Exit codes: 0 pass,
1 fail, 2 incomplete. **`incomplete` means unproven, not clean.** Say which
files were not checked.

## 3. Before you say "done"

The full check list below describes **Skylos 4.47.1 or newer**. The hooks work
with 4.44.0 or newer, but older CLIs can have fewer Done checks. Check
`skylos --version` before relying on the full list.

```bash
skylos done --base main          # the branch compared with its merge base (or --base origin/main)
skylos done                      # uncommitted changes only, compared with HEAD
skylos done receipt              # print the latest receipt again
```

Exit codes: 0 pass, 1 a blocking check failed or did not finish, 2 Skylos
could not run (for example, the base branch is not fetched). The receipt is in
`.skylos/receipts/latest.json`. Report failures to the user; don't describe a
1 or 2 as done.

What blocks by default:

| Check | Rules |
|:--|:--|
| Tests pass when Skylos runs them | SKY-A113 |
| No tests deleted, skipped or weakened | SKY-A110, A111, A112 |
| Skylos settings, protected paths and Skylos CI left alone | SKY-A114 |
| No secrets added | SKY-S101 |
| Code doesn't special-case the tests | SKY-A115, A116, A117 |

What only advises by default: weakened assertions (SKY-A101), imports that may
not be real (SKY-D222, D225, D223), changed lines no test checks (SKY-A120),
and silenced linters, scanners, CI steps or added inline suppressions
(SKY-A119, A121, A118). Mention advice to the user; it does not fail the run.
The stop hook runs Done only when the repository has a committed
`[tool.skylos.done]` table; the command above works without one.

Never edit `[tool.skylos]` or `[tool.skylos.done]` in `pyproject.toml`, files
under `.skylos/`, hook configuration, or a CI workflow that runs Skylos to make
a check pass. SKY-A114 reports exactly that.

## 4. When a hook blocks you

- **Edit finding** (security issue, secret or hallucinated import on lines you
  changed): fix it, then run the recheck command the message names, for
  example `skylos hook recheck app.py` (exit 0 means nothing blocking is left).
- **Read blocked** (the file holds a secret): don't read it another way, such
  as `cat` in the shell. If the message says so, read with an offset and limit
  that skip the secret lines.
- **Install blocked** (package doesn't exist, or is a one-edit look-alike of a
  popular package):
  check the spelling. If the name is correct (an internal package), tell the
  user they can add it to `hooks_allow_packages` under `[tool.skylos]`; don't
  add it yourself.
- **Stop blocked** (issues you added are still open): fix them, then run
  `skylos hook recheck --session`.

## 5. Whole-repository scans

```bash
skylos . -a --format json        # dead code, security, secrets, quality, dependency CVEs
skylos .                         # dead code only
```

Read the JSON with `.get(key, [])`, because empty arrays may be left out. Keys
include `unused_functions`, `unused_imports`, `unused_variables`,
`unused_classes`, `unused_files`, `danger`, `secrets`, `quality`,
`dependency_vulnerabilities` and `analysis_errors`. A non-empty
`analysis_errors` means some files were not analyzed. `-a` includes a
dependency check that queries OSV.dev.

Dead-code findings are candidates. Before deleting one, search for dynamic use:
`getattr`, string dispatch, entry points in `pyproject.toml`, framework
decorators, `__all__`, and tests.

## 6. Suppressions and limits

- `# skylos: ignore[SKY-XXXX]` silences one finding. Add one only when the
  user agrees the finding is intentional; `skylos done` reports new
  suppressions (SKY-A118).
- A clean result is not proof that code is secure or correct. Say what was
  checked and what was not.
- The hooks don't see reads or edits made through the shell (`cat`, `sed -i`,
  heredocs) at the time they happen.
