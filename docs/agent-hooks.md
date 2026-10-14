# Agent-Loop Hooks (Claude Code, Codex, Cursor)

Skylos can run inside a coding agent's loop. It checks each edit when the agent
makes it, instead of waiting for CI:

- **After every edit**, Skylos verifies the lines the agent just changed and
  tells the agent what to fix.
- **Before the agent reads a file**, Skylos blocks the read if the file contains
  a hard-coded secret, so the key is never sent to the model provider.
- **Before a package install or one-shot run** (`pip`, `uv`/`uvx`, `poetry`,
  `pipx`, `npm`/`npx`, `pnpm dlx`, `yarn dlx`, `bun`/`bunx`, `go`, `deno`),
  Skylos blocks packages that do not exist (hallucinated) or are one-letter
  look-alikes of popular packages (typosquats), and asks you before installs
  it cannot verify: git and URL sources, registries it does not know, and
  lookups that fail.
- **Before a git command**, Skylos blocks ways around the repository's git
  hooks: `--no-verify`, `HUSKY=0`, `core.hooksPath=/dev/null` and similar.
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
| `pre-read` | `PreToolUse` on `Read` | not available (Codex reads files through the shell; `pre-bash` covers that) | `beforeReadFile` | Blocks reading a file that contains secrets |
| `pre-bash` | `PreToolUse` on `Bash\|PowerShell` | `PreToolUse` on `Bash` | `beforeShellExecution` | Blocks commands that would print a secret file or variable, installs of hallucinated or typosquatted packages, and git-hook bypasses; asks before installs it cannot verify |
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

Other findings on the changed lines are **notes**: Claude Code gets them as
non-blocking `additionalContext`; they are not re-raised at `stop`.

You can opt into blocking specific built-in quality rules with
`skylos agent install-standards --enforce RULE_ID`. Selected quality findings
then block on agent-added lines and remain open at `stop` until fixed. The
project-wide `skylos agent check-standards .` command checks the same selected
rules across the whole project for CI. See [project standards](./agent-standards.md).

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

This hook checks two things.

**Secrets the command would print.** Skylos works out what the command prints
from files and environment variables and scans that text with the same secrets
scanner as `pre-read`. If a secret would reach the output, the command is
blocked. The block message names the file and line numbers (or the variable)
and the kind of secret, never the value. This closes the shell route around
`pre-read`, and on Codex, which reads files through the shell, it is the read
check. It follows:

- programs that print files: `cat`, `less`, `nl`, `head`/`tail`,
  `grep`/`rg`/`ag`, `sed`, `awk`, `cut`, `base64`, `xxd`, `sort`, `diff` and
  similar, including `cmd < file`, `cat <<< "$VAR"`, globs and braces
  (`cat .env*`, `.env{,.local}`), `cd dir && ...`, `$(...)`, loops
  (`for f in .env*`, `while read ...; done < .env`), `bash -c '...'` and `eval`
- `grep -r` over a directory, and `rg`/`ag` with `--hidden` (except files Git
  ignores, which they skip), for `.env*` files
- the environment: `env`, `printenv`, `export -p`, `declare -p`, `set`, and
  `echo`/`printf` of `$NAME`, including values loaded by the same command
  (`source .env`, `export $(cat .env | xargs)`)

Only what is printed counts, after `grep`, `head`/`tail`, `cut`, simple
`sed` scripts (`-n '10,40p'`, `/re/p`, `s/=.*//`) and simple `awk` programs
(`NR<=40`, `-F= '{print $1}'`). So these run: `sed -n '1,200p' app.py` when
the secret is further down, `cat .env | grep PORT` when the PORT line holds
no secret, `grep -c`, `cut -d= -f1 .env`, `sed 's/=.*//' .env`,
`grep -rn KEY . | cut -d: -f1`, `> /dev/null`, `| wc -l`,
`echo ${TOKEN:+set}`, and `export $(cat .env | xargs)`, which loads values
without printing them. A pipe into a program Skylos does not know counts as
not printed. Only the printed lines are scanned, at most 2 MB per command.

This guards the commands agents usually write; it is not a sandbox. Not
followed: a program that opens the file itself
(`python -c "print(open('.env').read())"`), `find ... -exec cat`,
`... | xargs cat`, `git show HEAD:.env`, `docker compose config`, a copy read
back under another name, and files the secrets scanner does not read
(`.npmrc`, `~/.aws/credentials`), which `pre-read` does not check either.

**Package installs and one-shot runners.** Skylos reads the command the
way the shell would (pipes, `&&`/`;`, line continuations, `VAR=1 cmd`,
`export VAR=1`, `sudo`/`env`/`timeout`/`xargs`, `bash -c '...'`, `eval`,
`$(...)`) and finds every package it would fetch:

| Ecosystem | Commands |
|:---|:---|
| PyPI | `pip`/`pip3`/`pip3.12 install`, `python -m pip install`, `uv pip install`, `uv add`, `uv tool install`, `uv tool run`, `uvx`, `uv run --with`, `poetry add`, `pdm add`, `pipenv install`, `pipx install`/`run`/`inject` |
| npm | `npm install` (and its aliases, `i`, `add`, `install-test`), `npm exec`/`npm x`, `npm init`/`npm create <initializer>` (runs `create-<initializer>`), `npx`, `pnpm add`/`install <pkg>`/`dlx`/`create`, `pnpx`, `yarn add`/`global add`/`dlx`/`create`, `yarn workspace <ws> add`, `bun add`/`install <pkg>`/`x`/`create`, `bunx`, `deno run`/`install`/`add` with `npm:` specifiers |
| JSR | `deno add`/`install`/`run` with `jsr:` specifiers (and `deno add @scope/name`) |
| Go | `go get`, `go install`, `go run pkg@version` |

Options before the package name (`npx -y --package=foo bar`,
`uvx --from foo bar`, `pip install -U -r reqs.txt pkg`, `pnpm --filter web add
x`), several packages in one command, version pins, scoped npm names,
`pkg[extra]`, PEP 508 markers and npm aliases (`foo@npm:bar@1`) are handled.
For a runner, only the package is checked; the arguments after it belong to
the program it runs.

Each command gets one of these outcomes:

| Outcome | Examples | What happens |
|:---|:---|:---|
| Package does not exist, pinned version does not exist, or one-edit look-alike of a popular package (SKY-D222/D225) | `pip install fastapi-authz`, `npx -y cowsy`, `npm create foo` when `create-foo` is not published | **Blocked** on every agent |
| Direct source: code from outside a registry | `npm install github:user/repo#b181e0`, `npm install user/repo`, `pip install git+https://...`, `uvx --from git+https://...`, a tarball or wheel URL, `deno run https://...`, an archive outside the project, an archive downloaded by the same command (`curl -LO ... && npm i ./x.tgz`) | `direct_source` policy (default: ask) |
| Untrusted registry or index | `--index-url`/`--extra-index-url`/`-i`/`-f URL`, `--registry`, `--@scope:registry=`, `PIP_INDEX_URL=`, `UV_INDEX_URL=`, `NPM_CONFIG_REGISTRY=`, `GOPROXY=`, `GOSUMDB=off` on the command line | `direct_source` policy (default: ask), unless the registry is in `trusted_registries` |
| Could not verify | registry unreachable, timeout, HTTP 429/5xx; package named at run time (`pip install $PKG`, `xargs npm i`, `npx $(...)`); a name Skylos cannot read; more than 25 packages in one command; a package missing from the public registry while your configuration points at a private one; an install or git command longer than Skylos reads (16,384 characters, not counting here-document bodies) | `on_unverified` policy (default: ask) |
| Not fetched from a registry | `npx tsc` when `tsc` is the project's own `bin`, in `node_modules/.bin` (this directory or any parent) or a global npm bin, as npm itself resolves it; `npx --no`; local paths and archives inside the project (`pip install -e .`, `npm i ../lib`, `workspace:`/`file:`/`link:`); `pip install --no-index` | allowed |
| Manifest install | `npm ci`, `npm install`, `pip install -r requirements.txt`, `uv sync`, `poetry install`, `go mod download` | allowed; manifests are checked by `skylos . -a` and `skylos done` (SKY-D222), not here |

A git commit hash ref (`github:cline/cline#b181e0`) is called out in the
message: GitHub serves commits from any fork through the parent repository's
URL, so a commit ref can point at a fork's code.

What "ask" means for each agent:

| Agent | `ask` | `deny` | `allow` |
|:---|:---|:---|:---|
| Claude Code | `permissionDecision: "ask"`: you approve or reject in the permission prompt, which shows the reason; Claude also gets it as `additionalContext`. In auto mode the hook's ask still forces a prompt. In `-p` runs, where nobody can answer, Claude Code denies the call and Claude reads the reason | `permissionDecision: "deny"` | runs through your normal permission flow, with a note (`systemMessage` + `additionalContext`) |
| Cursor | `permission: "ask"` with `user_message`/`agent_message` | `permission: "deny"` | `permission: "allow"`; the note goes to the Hooks output channel |
| Codex | **denied**: Codex does not support `ask` in `PreToolUse` and would run the command, so Skylos denies and says so | `permissionDecision: "deny"` | runs, with a `systemMessage` note |

An `allow` is never silent: the agent and you are told the install was not
verified. Cursor documents `ask` for `beforeShellExecution`; if your Cursor
version or a cloud agent runs the command without asking, set
`direct_source = "deny"` and `on_unverified = "deny"`.

**Policy.** Set it in `pyproject.toml` at the project root:

```toml
[tool.skylos.hooks]
direct_source = "ask"        # git/URL/tarball installs and untrusted registries: "ask" | "deny" | "allow"
on_unverified = "ask"        # registry unreachable, run-time names: "ask" | "deny" | "allow"
block_hook_bypass = true     # see "Git hook bypass" below
trusted_registries = ["https://pypi.corp.example/simple", "npm.corp.example"]
```

A value that is not one of these falls back to the default (which never
allows), and the message says so. `trusted_registries` entries match a
registry by host, and by path prefix when the entry has a path. Packages
installed from a trusted registry (on the command line or in your
configuration) skip the public check.

**Your own registry configuration.** "Not on npmjs.org" is not evidence of a
hallucination when your configuration fetches from somewhere else. Skylos
reads `registry=` and `@scope:registry=` from `.npmrc` (from the working
directory up to the project root, and `~/.npmrc`), `npm_config_registry`,
`PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL`/`UV_*INDEX*` from the environment,
`pip.conf`/`pip.ini`, `uv.toml`, `[[tool.uv.index]]`, `[[tool.poetry.source]]`
and `[[tool.pdm.source]]`, and `GOPROXY`/`GOPRIVATE`/`GONOPROXY` (environment
or `go env -w`). With such a registry configured:

- a scoped npm package whose scope has its own registry is never sent to
  npmjs.org; it is allowed if that registry is trusted, otherwise it is
  "could not verify";
- a `GOPRIVATE` module is never sent to the Go proxy and is allowed;
- any other package missing from the public registry becomes "could not
  verify" (ask) instead of a block. Look-alikes of popular packages are still
  blocked.

To allow your own names (internal packages, deliberate look-alikes) without
any check, list them in `pyproject.toml`:

```toml
[tool.skylos]
hooks_allow_packages = ["internal-pkg", "npm:my-reactt"]   # optional npm:/pypi:/go:/jsr: prefix
```

Well-known packages that sit one edit from a popular name (`preact`, `pyaml`,
`react-dom`, ...) are never flagged, and neither is any package in the
popular list itself. Registry answers that settle the question (exists, does
not exist, version does not exist) are cached in
`.skylos/cache/dependency_versions.json`; "could not verify" answers are
retried next time. A PEP 440 local version (`torch==1.11.0+cu113`) is never on
PyPI, so only the public version (`1.11.0`) is checked.

**Git hook bypass.** Agents skip a failing pre-commit hook instead of fixing
it. With `block_hook_bypass = true` (the default), pre-bash blocks:

- `--no-verify` (and git's abbreviations such as `--no-veri`) on `git commit`,
  `merge`, `pull`, `push`, `rebase` and `am`; `-n` on `commit` and `am`,
  including short-option clusters (`-anm "msg"`; in `-amn` the `n` is the
  message, so it is not a bypass);
- `git -c core.hooksPath=...`, `--config-env=core.hooksPath=...`, and the
  `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_PARAMETERS`
  environment forms, when the new path has no hooks;
- hook managers' skip switches on a `git commit`/`push`/`merge`/`pull`/
  `rebase`/`am` command: `HUSKY=0` and `HUSKY_SKIP_HOOKS` (husky),
  `SKIP=...` and `PRE_COMMIT_ALLOW_NO_CONFIG` (pre-commit; `SKIP` is also
  overcommit's), `LEFTHOOK=0`/`false` and `LEFTHOOK_EXCLUDE` (lefthook),
  `SKIP_SIMPLE_GIT_HOOKS` (simple-git-hooks), `OVERCOMMIT_DISABLE`
  (overcommit), whether as a prefix (`HUSKY=0 git commit`) or exported earlier
  in the same command (`export HUSKY=0 && git commit`). A switch counts only
  when its manager is in use: its config file or folder is at the top of the
  repository (`.husky/`, `.pre-commit-config.yaml`, `.overcommit.yml`,
  `lefthook.yml` and the other lefthook names, `.simple-git-hooks.json` or a
  `simple-git-hooks` key in `package.json`), the hooks directory is inside
  `.husky`, or an installed hook script names the manager. A plain
  `.git/hooks/pre-commit` never reads `HUSKY`, so `HUSKY=0 git commit` is
  allowed there;
- persistent changes: `git config core.hooksPath <path without hooks>` (or
  `/dev/null`), `git config --unset core.hooksPath` when a hooks path is set,
  and a git alias whose value adds `--no-verify`;
- removing a hook, or taking away its execute bit, in the active hooks
  directory (`rm .git/hooks/pre-commit`, `chmod -x .husky/_/pre-commit`).

A bypass only counts when a hook it would skip is installed and executable
in the directory git runs hooks from (`git rev-parse --git-path hooks`, so
`core.hooksPath` and husky's `.husky/_` are followed; for husky, a hook counts
when its `.husky/<hook>` script exists). In a repository without hooks
`--no-verify` changes nothing and is allowed. `HUSKY=0 npm ci` (skipping hook
installation in CI) is allowed. The block is a `deny` on all three agents; the
message names the hooks that would not run and tells the agent to fix what the
hook reports, or to stop and tell you if the hook fails for an unrelated
reason.

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
| pre-bash ask (unverifiable install) | Claude: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "...", "additionalContext": "..."}}`; Codex: the deny shape above (Codex has no `ask`) | `{"permission": "ask", "user_message": "...", "agent_message": "..."}` |
| pre-bash allowed by policy (`"allow"`) | Claude: `{"systemMessage": "...", "hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "..."}}` (no `permissionDecision`); Codex: `{"systemMessage": "..."}` | `{"permission": "allow"}`; the note goes to stderr |
| pre-read / pre-bash allow | no output, so the normal permission flow applies (Skylos never sends `"allow"`, which would skip your permission prompt) | `{"permission": "allow"}` (Cursor treats empty output from permission hooks as a deny) |
| post-edit fail | `{"decision": "block", "reason": "..."}` | none (`afterFileEdit` can't send feedback) |
| post-edit, notes only | Claude: `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "..."}}`; Codex: none | none |
| post-edit pass | no output | no output |
| stop, issues open | `{"decision": "block", "reason": "..."}` | `{"followup_message": "..."}` |
| stop, clean | `{}` (Codex requires JSON from Stop) | `{}` |
| Skylos error (fails open) | the allow/stop output above plus `"systemMessage": "..."`; Claude `pre-read`/`pre-bash`/`post-edit` also get `hookSpecificOutput.additionalContext` (no `permissionDecision`) | the allow/stop output above; the message goes to stderr |

References:

- Claude Code: <https://code.claude.com/docs/en/hooks>
- Codex: <https://developers.openai.com/codex/hooks> (now served from
  <https://learn.chatgpt.com/docs/hooks>)
- Cursor: <https://cursor.com/docs/agent/hooks>

## Failure behaviour and logs

Runtime hook failures fail open. If the JSON input is malformed, the event is
unknown, the analyzer crashes or a lock is busy, Skylos allows the action and
logs the error.

A fail-open is never silent, so an unchecked action can't pass for a checked
one. When Skylos errors on a read, command, edit, prompt or stop, it says so:

```
Skylos could not check this edit: internal error (RuntimeError). It was allowed without a check.
```

- **Claude Code:** `systemMessage` (shown to you) and, for `pre-read`,
  `pre-bash` and `post-edit`, `additionalContext` (shown to the agent). No
  `permissionDecision` is sent, so your normal permission prompt still applies.
- **Codex:** `systemMessage`.
- **Cursor:** stderr, which appears in Cursor's Hooks output channel (Cursor
  shows no message on an allowed action).

The reason names only the exception type, never its text. Each unchecked
action is also recorded in `.skylos/cache/hook-fail-open.json`. At `stop`,
Skylos reports the session's unchecked actions once, as a warning that never
blocks:

```
3 actions were not checked by Skylos because it errored. They were allowed without a check:
- edit: internal error (RuntimeError) (2 times)
- command: internal error (OSError)
```

A hook turned off with `SKYLOS_HOOKS_DISABLE` stays silent and records
nothing. Two other cases are still silent: an unknown hook name, and the shell
wrapper's `|| exit 0` (a Skylos that is not installed or cannot start).

An explicitly configured but invalid agent standards policy
gives Claude Code and Codex a repair message at `post-edit` and reports the
problem to all three agents at `stop`; `skylos hook recheck` exits 2. Hook
timeouts set by the installer are 15 s (`pre-read`), 30 s
(`pre-bash`), 120 s (`post-edit`) and 180 s (`stop`). All three agents treat a
timeout as a non-blocking failure.

Each hook call appends one JSON line to `.skylos/hook.log` with the time,
event, client, outcome, counts and duration. `pre-bash` outcomes are `skip`,
`pass`, `ask`, `note` (allowed by policy), `block` and `block-bypass`, with
counts of `packages`, `findings`, `direct`, `unverified` and `bypasses`. The log never holds file
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

Install hook v2 was measured on 13 Oct 2026 on a heavily loaded machine (load
average 10-30), interleaving the new code with the previous release run by
run, so compare the columns rather than the absolute numbers (warm cache):

| `pre-bash` command | new p50 / p95 | previous p50 / p95 |
|:---|---:|---:|
| `ls -la` (unrelated) | 0.30 s / 0.39 s | 0.32 s / 0.39 s |
| `pip install requests fastapi` | 0.95 s / 2.59 s | 0.88 s / 2.40 s |
| `npx -y cowsay hi` (newly checked) | 0.84 s / 1.64 s | 0.40 s / 0.49 s (not checked) |
| `uvx ruff check .` (newly checked) | 0.78 s / 1.64 s | 0.41 s / 0.51 s (not checked) |
| `npx tsc --noEmit` (local binary) | 0.48 s / 0.68 s | 0.54 s / 0.72 s |
| `pip install -r requirements.txt` | 0.49 s / 0.74 s | 1.70 s / 2.17 s |
| `npm install github:cline/cline#b181e0` (asks) | 0.38 s / 0.43 s | 1.14 s / 1.22 s (not checked) |
| `git commit --no-verify -m x` (blocked) | 0.39 s / 0.54 s | 0.43 s / 0.55 s (not checked) |

Commands that need no registry lookup (local binaries, manifests, git
sources, hook bypasses) are decided without loading the registry checker.
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

Installed-package metadata used for hallucinated-import checks is reused in
memory during the current analysis session. The snapshot is keyed by the
interpreter and environment directory metadata; environment changes
invalidate it. Repository cache files do not supply trusted installed-package
mappings.

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
- It doesn't check the packages inside requirement files, manifests or
  lockfiles (`pip install -r`, `npm ci`, `uv sync`); `skylos . -a` and
  `skylos done` do. A requirements file named by URL (`pip install -r
  https://...`) is a direct source.
- It doesn't follow dependencies declared inside a script (`uv run
  script.py` with inline PEP 723 metadata), `cargo`, `gem` or `composer`
  installs, `conda`, or package managers' own lifecycle scripts.
- It is not a sandbox. A command that downloads and runs code in a way it does
  not parse (a script that calls `pip`, `npm run` scripts that install,
  `curl ... | sh`) is not checked; `npx`/`uvx` resolve the package at run
  time, so a package that exists but is malicious is not caught by an
  existence check.
- It doesn't check edits made through the shell (`sed -i`, heredocs) at edit
  time. `stop` still re-checks files that earlier `post-edit` calls recorded,
  if they changed on disk.
- It doesn't check files outside the project root.
- It doesn't give feedback on each edit in Cursor. Findings arrive at `stop`
  as a follow-up message.
- It doesn't use Cursor's generic `preToolUse`/`postToolUse` events, or Codex
  MCP-tool hooks. Only the events listed above are used.
