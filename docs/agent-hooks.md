# Agent-Loop Hooks (Claude Code, Codex, Cursor)

Skylos can run inside a coding agent's loop. It checks each edit when the agent
makes it, instead of waiting for CI:

- **After every edit**, Skylos verifies the lines the agent just changed and
  tells the agent what to fix.
- **Before the agent reads a file**, Skylos blocks the read if the file contains
  a hard-coded secret, so the key is never sent to the model provider.
- **Before a package install**, Skylos blocks `pip`/`uv`/`poetry`/`npm`/`pnpm`/
  `yarn`/`bun`/`go` installs of packages that do not exist (hallucinated) or
  are one-letter look-alikes of popular packages (typosquats).
- **When the agent says it is done**, Skylos blocks the stop while issues the
  agent added in this session are still open.

Everything runs locally. It needs no account, no Docker and no API key. The
only network calls are package-registry lookups, and only for install commands
and new imports.

## Install

```bash
pip install skylos
cd your-project

skylos agent install-hooks                 # Claude Code, this project (.claude/settings.json)
skylos agent install-hooks --user          # Claude Code, all projects (~/.claude/settings.json)
skylos agent install-hooks --codex         # Codex (.codex/hooks.json)
skylos agent install-hooks --cursor        # Cursor (.cursor/hooks.json)
```

The installer merges its entries into the existing file. It keeps every other
hook and setting, and running it again changes nothing. If the file is not
valid JSON, the installer stops and leaves the file unchanged. `--dry-run`
prints the result without writing it.

The hook command names the Skylos that ran the installer by absolute path
(its console script, or `<python> -m skylos.entry`), so an older `skylos`
earlier on the agent's PATH cannot shadow it. Before writing, the installer
runs that command once (`hook help`) and refuses to install if it does not
support `skylos hook`. `--skylos-bin PATH` picks another executable (a
relative path is made absolute; a bare name such as `skylos` means "resolve on
PATH at run time"). `--no-check` skips the check.

Every command is wrapped so that a Skylos that cannot run never blocks the
agent: `... hook post-edit --client claude || exit 0` (Stop hooks print `{}`,
Cursor permission hooks print `{"permission":"allow"}`). Skylos itself always
exits 0 and puts decisions in JSON, so a non-zero exit only means "not
installed / too old / broken here", which becomes a silent no-op.

**Committed settings.** `.claude/settings.json` (and `.codex/`, `.cursor/`) is
usually committed. The absolute path is this machine's; on a teammate's
machine without it the hooks silently do nothing. Teammates who want the
checks run `skylos agent install-hooks` themselves, or you install with
`--skylos-bin skylos` so each machine uses its own PATH (an old or missing
`skylos` there is still a no-op, never a block).

For a project install inside a Git repo, the installer also keeps hook state
out of Git: it appends `.skylos/cache/`, `.skylos/agent-session.*` and
`.skylos/hook.log*` to `.gitignore` (idempotent), or writes
`.skylos/.gitignore` if the repo has no `.gitignore`. It does not ignore all of
`.skylos/`, which also holds committed config and the AI contract.

- **Claude Code:** the new hooks load in the next session. Run `/hooks` to see
  them.
- **Codex:** Codex skips new hooks until you trust them. Open `/hooks` in Codex
  and trust the Skylos entries.
- **Cursor:** Cursor reloads `hooks.json` automatically.

## Uninstall

```bash
skylos agent install-hooks --uninstall            # add --user / --codex / --cursor to match the install
```

This removes only the Skylos entries: any hook whose command runs
`skylos hook <event>`. All other hooks stay.

## Turn one hook off

Set `SKYLOS_HOOKS_DISABLE` in the environment the agent runs in. Its value is a
comma-separated list of hook names, or `all`:

```bash
export SKYLOS_HOOKS_DISABLE=pre-read          # keep the others
export SKYLOS_HOOKS_DISABLE=pre-bash,stop
export SKYLOS_HOOKS_DISABLE=all
```

To remove one hook for good, delete its entry from the config file. The
entries are easy to find because every Skylos command contains
`skylos hook <name>`.

## What each hook does

| Hook | Claude Code | Codex | Cursor | What it does |
|:---|:---|:---|:---|:---|
| `post-edit` | `PostToolUse` on `Edit\|Write\|MultiEdit` | `PostToolUse` on `apply_patch` | `afterFileEdit` | Verifies the changed lines and reports failures to the agent |
| `pre-read` | `PreToolUse` on `Read` | not available (Codex reads files through the shell) | `beforeReadFile` | Blocks reading a file that contains secrets |
| `pre-bash` | `PreToolUse` on `Bash\|PowerShell` | `PreToolUse` on `Bash` | `beforeShellExecution` | Blocks installs of hallucinated or typosquatted packages |
| `stop` | `Stop` | `Stop` | `stop` | Blocks "done" while issues this session added are still open |

### post-edit

Skylos works out which lines the edit added:

- **Claude Code:** from the tool result's `structuredPatch`, or by finding
  `new_string` in the file.
- **Codex:** from the `+` lines of the `apply_patch` envelope.
- **Cursor:** from `edits[].new_string`.

A `Write` that creates a new file counts as all new lines. Skylos then runs
`skylos verify` on the file with security and secret checks on, and keeps only
the findings on the changed lines. Existing debt elsewhere in the file is never
reported. Findings on the same line are merged into one item.

#### What blocks, and what is only a note

`verify`'s taint rules treat every function parameter as tainted, so a plain
helper like `def load(path): return open(path).read()` is reported as path
traversal. The hook does not block on that. It blocks only on:

1. **Secrets** (SKY-S*).
2. **Real untrusted input reaching a sink** (SKY-D211/212/215/216/217/230/...):
   Skylos checks the enclosing function on the AST for a web-route, CLI or
   MCP-tool parameter (`@app.get`, `@router.post`, `@click.command`,
   `@mcp.tool`, ...), `request.*` / a `Request`-typed parameter, `input()`,
   `sys.argv`, `os.environ`/`os.getenv`, `sys.stdin`, or `parse_args()`, and
   follows simple assignments to the sink. For other languages it uses the
   finding's `security_evidence.source`.
3. **Sinks dangerous whatever the input:** unsafe deserialization
   (`pickle.loads`, SKY-D204/205/233), Trojan Source (SKY-D344), disabled TLS
   verification (SKY-D210 / Go SKY-G210: `verify=False`, `InsecureSkipVerify`)
   and disabled JWT verification (SKY-D232, JS/TS SKY-D246), which agents add
   to silence an error, and
   `eval`/`exec`/`os.system`/`shell=True`/`yaml.load` with a non-constant
   argument. `os.system("clear")` is not blocked.
4. **Hallucinations:** nonexistent dependencies, versions, APIs and
   references (SKY-D222/224/225, SKY-L012/L023), and violations of your own
   AI contract (SKY-A105).

Everything else on the changed lines is a **note**: Claude Code gets it as
non-blocking `additionalContext`; it is never re-raised at `stop`.

For source files (Python, TS/JS, Java, Go, PHP, Rust, Dart, C#, Kotlin, C++,
shell), Skylos runs the full `verify` check set. For config files (`.env`,
YAML, JSON, TOML and similar), it runs only the secrets scanner.

If an edit fails, Claude Code and Codex get a block message with at most 10
items:

```
Skylos found 2 issue(s) in the lines you just changed. Fix them before moving on:
- app.py:6 SKY-D212 Possible command injection (os.system): tainted input. -> Remove the unsafe sink or validate, escape, or parameterize the untrusted input.
- app.py:9 SKY-S101 Potential AWS secret access key detected -> Remove the hard-coded credential, load it from the environment or a secret manager, and rotate it if it was ever committed or shared.
Check again with: skylos hook recheck app.py
```

`skylos hook recheck FILE... [--range L1:L2]` applies exactly this policy to
the files on disk and prints a few lines: exit 0 when nothing blocking is left
(the hook will not block on it), 1 otherwise. `skylos hook recheck --session`
rechecks every file where agent edits introduced issues. The hint names the same Skylos
the hook runs, by path when `skylos` on PATH is a different one. (`skylos
verify` reports every finding and may say "needs review" after a correct fix,
so it is not the recheck command.)

If the edit passes, the hook prints nothing. Cursor's `afterFileEdit` has no
way to send feedback, so on Cursor this hook only records the result, and the
agent sees the findings at `stop`.

### pre-read

This hook runs the Skylos secrets scanner on the file the agent is about to
read. If it finds a secret, it blocks the read. The block message names the
file, the line numbers and the kind of secret, never the value or a preview of
it. If the agent's `Read` uses `offset`/`limit` to skip the secret lines, the
read is allowed, and the block message tells the agent it can do that. Unlike
`skylos -a`, test files are scanned too (a live key in `tests/conftest.py`
reaches the model provider just the same). Binary files and files over 2 MB
are skipped.

`post-edit` does not block writing a secret into a `.env*` file that Git
ignores (`git check-ignore`): that is where the key belongs. Writing it into a
tracked file (source, `.env.example`) is still blocked.

### pre-bash

This hook checks only package-install commands:

- `pip`/`pip3`/`pipx install`, `python -m pip install`, `uv pip install`,
  `uv add`, `poetry add`
- `npm install|i|add`, `pnpm add`, `yarn add`, `bun add`
- `go get`, `go install`

Every other command passes straight through without any lookup. For each named
package, Skylos checks that it exists on PyPI, npm or the Go module proxy (and,
for exact pins, that the version exists), and flags one-edit look-alikes of
popular packages. Well-known packages that sit one edit from a popular name
(`preact`, `pyaml`, `react-dom`, ...) are never flagged, and neither is any
package in the popular list itself. To allow your own names (internal
packages, deliberate look-alikes), list them in `pyproject.toml`:

```toml
[tool.skylos]
hooks_allow_packages = ["internal-pkg", "npm:my-reactt"]   # optional npm:/pypi:/go: prefix
```

Allowlisted packages skip every registry check. The block message names this
setting, so the agent can suggest it when a flagged package is correct. If the command uses a private index or registry
(`--index-url`, `--registry`, `PIP_INDEX_URL=`, and similar), the public
registry doesn't apply, so Skylos skips the check. An unreachable registry
never blocks the install. Answers are cached in
`.skylos/cache/dependency_versions.json`.

### stop

Each `post-edit` records a hashed identity (rule plus the hash of the source
line, never the text) for every issue the agent added. It saves these in
`.skylos/agent-session.json`, under the agent's session ID. At `stop`, Skylos
re-verifies every file that still has an issue the agent added, whether or not
that file changed: a fix can land in another file (defining a missing
`crud.delete_item` in `crud.py` fixes the call in `items.py`). This is the same
check `skylos hook recheck` runs, so the two always agree. If an issue the
agent added is still there, the stop is blocked with the list. The hint names
every file with open issues; past five it points to
`skylos hook recheck --session`, which rechecks all of them.

The hook doesn't loop forever. If the agent already continued once because of
this hook and the issues are unchanged:

- **Claude Code:** Skylos lets the agent stop and shows you a warning.
- **Codex:** Skylos lets the agent stop and shows you a warning.
- **Cursor:** Skylos sends no follow-up message. Cursor's own `loop_limit`
  also applies; the installer sets it to 3.

## Hook contract used

Every hook exits `0` and signals through JSON on stdout.

| Situation | Claude Code / Codex output | Cursor output |
|:---|:---|:---|
| pre-read / pre-bash block | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}` | `{"permission": "deny", "user_message": "...", "agent_message": "..."}` (`beforeReadFile`: `permission` + `user_message`) |
| pre-read / pre-bash allow | no output, so the normal permission flow applies (Skylos never sends `"allow"`, which would skip your permission prompt) | `{"permission": "allow"}` (Cursor treats empty output from permission hooks as a deny) |
| post-edit fail | `{"decision": "block", "reason": "..."}` | none (`afterFileEdit` can't send feedback) |
| post-edit, notes only | Claude: `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "..."}}`; Codex: none | none |
| post-edit pass | no output | no output |
| stop, issues open | `{"decision": "block", "reason": "..."}` | `{"followup_message": "..."}` |
| stop, clean | `{}` (Codex requires JSON from Stop) | `{}` |

References:

- Claude Code: <https://code.claude.com/docs/en/hooks>
- Codex: <https://developers.openai.com/codex/hooks> (now served from
  <https://learn.chatgpt.com/docs/hooks>)
- Cursor: <https://cursor.com/docs/agent/hooks>

## Failure behaviour and logs

Every hook fails open. If the JSON input is malformed, the event is unknown,
the analyzer crashes or a lock is busy, Skylos allows the action and logs the
error. It never blocks the agent because Skylos itself broke. Hook timeouts
set by the installer are 15 s (`pre-read`), 30 s (`pre-bash`), 120 s
(`post-edit`) and 180 s (`stop`). All three agents treat a timeout as a
non-blocking failure.

Each hook call appends one JSON line to `.skylos/hook.log` with the time,
event, client, outcome, counts and duration. The log never holds file
contents, secrets or shell commands. It rotates at 512 KB.

The session file and log live in the project's `.skylos/` only when the
project is inside a Git repo. A `--user` install also fires in directories
that are not repos (your home directory, a scratch folder); there they go
under `$XDG_CACHE_HOME/skylos/projects/<hash>/` (default `~/.cache`) instead,
together with every analyzer cache the hook would otherwise write to
`<dir>/.skylos/cache/` (module index, API surface, registry answers).

## Latency

These times were measured on an Apple Silicon laptop (Python 3.14) by running
`skylos hook` as a subprocess, the way the agent does, 10 runs each:

| Hook | Target | p50 | p95 |
|:---|:---|---:|---:|
| `post-edit` | 13-line Python file in a small project (fails: injection) | 0.54 s | 0.68 s |
| `post-edit` | 25-line file inside the Skylos repo (~1,300 Python files), warm index | 1.14 s | 1.21 s |
| `post-edit` | 330-line file inside the Skylos repo, warm index | 1.30 s | 1.49 s |
| `post-edit` | 60-line file with 14 security findings (blocking policy applied) | 0.61 s | 0.71 s |
| `post-edit` | same file, first run with no index (one-time) | 5.7 s | 6.5 s |
| `pre-read` | small file containing secrets (blocked) | 0.11 s | 0.11 s |
| `pre-bash` | unrelated command (`ls -la`) | 0.08 s | 0.08 s |
| `pre-bash` | `pip install requests fastapi` (registry answers cached) | 0.29 s | 0.40 s |
| `stop` | one edited file, unchanged since post-edit | 0.09 s | 0.14 s |

`post-edit` checks the edited file against the whole project's module surface
so it can catch calls to functions that don't exist. Skylos keeps that surface
in a per-file index at `.skylos/cache/module-facts.json`, so each edit
re-parses only files that changed since the last check. The first check in a
project builds the index. On a large repo, run this once after installing the
hooks so the first edit is fast too:

```bash
skylos agent warm-cache
```

An index entry is reused only while the file's size, mtime, ctime and inode
match, it maps to the same module name, and the imports it resolved still
resolve the same way (adding or removing a module invalidates the entries
that depend on it). A new Skylos or Python version rebuilds the whole index.
Cached and uncached checks report the same findings.

The installed-package map used for hallucinated-import checks is cached the
same way in `.skylos/cache/installed-modules.json`. It rebuilds when
anything on `sys.path` is installed, upgraded or removed.

`skylos hook` runs without loading the rest of the CLI. After upgrading from
an older Skylos, reinstall it (`pip install -U skylos`, or `pip install -e .`
for a source checkout) so the `skylos` command picks up the lighter entry
point.

Checking a very large edited file still takes longer, because the file itself
is analyzed in full on every edit. `skylos/analyzer.py` (about 5,000 lines)
takes about 3 s with a warm index.

## What it doesn't do

- It doesn't undo an edit. `PostToolUse` runs after the file is written. The
  hook reports; the agent fixes.
- It doesn't report pre-existing findings. Only lines the agent changed in this
  session count. A deletion that removes a sanitizer elsewhere in the file is
  not attributed to the edit.
- It doesn't guard every way to read a file. `pre-read` covers Claude Code's
  `Read` tool and Cursor's `beforeReadFile`, but `cat .env` through the shell
  and Codex file reads are not blocked.
- It doesn't check installs from requirement files, lockfiles or URLs
  (`pip install -r`, `npm ci`, `pip install git+https://...`). Use
  `skylos . -a` or `skylos verify` for manifests.
- It doesn't check edits made through the shell (`sed -i`, heredocs) at edit
  time. `stop` still re-checks files that earlier `post-edit` calls recorded,
  if they changed on disk.
- It doesn't check files outside the project root.
- It doesn't give feedback on each edit in Cursor. Findings arrive at `stop`
  as a follow-up message.
- It doesn't use Cursor's generic `preToolUse`/`postToolUse` events, or Codex
  MCP-tool hooks. Only the events listed above are used.
