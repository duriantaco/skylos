# Skylos plugin for Claude Code and Cursor

![Skylos](assets/logo.png)

This plugin runs [Skylos](https://github.com/duriantaco/skylos), a local
static-analysis CLI, inside the coding agent's loop. It checks each edit when
the agent makes it, instead of waiting for CI:

- **After every edit**, Skylos checks only the lines the agent just changed
  and tells the agent what to fix: security issues reached by real untrusted
  input, hard-coded secrets, and imports, packages or APIs that don't exist.
- **Before the agent reads a file**, Skylos blocks the read if the file holds a
  hard-coded secret, so the key is not sent to the model provider.
- **Before a package install**, Skylos blocks installs of packages that don't
  exist or are one-edit look-alikes of popular packages (typosquats).
- **When the agent says it is done**, Skylos holds the stop while issues the
  agent added in this session are still open.

It also adds a skill that shows the agent how to run Skylos on its changes,
read the JSON output and run `skylos done` before calling a change finished.

The plugin contains no analysis code. Every hook calls the `skylos` command
installed on your machine.

## Requirements

- The `skylos` command, **version 4.44.0 or newer**, on the PATH that your
  agent runs hooks with. Check with `skylos --version`.
- Use **4.47.1 or newer** for the full Done check set described in the skill.
- Install it with `pip install skylos` (or `pipx install skylos`, which puts
  it on PATH outside any virtual environment).

If `skylos` is missing or cannot run, the affected hook allows the action
(it fails open). An older CLI may still run individual checks while missing
session-baseline support. A notice at session start says the full supported
hook set is unavailable and recommends installing or upgrading Skylos.
Claude Code shows the notice to the user; Cursor adds it to the agent's context.

## Install

**Claude Code**, from this repository's marketplace (Claude Code 2.1.275 or
later):

```bash
/plugin install skylos --marketplace duriantaco/skylos
```

Or in two steps: `/plugin marketplace add duriantaco/skylos`, then
`/plugin install skylos@skylos`. Once the plugin is in Anthropic's directory
you can also add it from **Customize > Plugins** on claude.ai or with
`/plugin directory`.

To try it from a checkout of this repository for one session:

```bash
claude --plugin-dir plugins/skylos
```

Run `/hooks` to see the Skylos entries.

**Cursor**: install Skylos from the Cursor Marketplace once it is listed. To
try it locally, copy this folder to `~/.cursor/plugins/local/skylos`, run
**Developer: Reload Window**, and check that **Customize** lists the hooks and
the skill.

## Don't also run `skylos agent install-hooks`

`skylos agent install-hooks` writes the same hooks into `.claude/settings.json`,
`.cursor/hooks.json` or your user settings. If you use it **and** this plugin,
every check runs twice, including two stop checks. Pick one. To remove the
installer's hooks and keep the plugin:

```bash
skylos agent install-hooks --uninstall            # Claude Code, this project
skylos agent install-hooks --uninstall --user     # Claude Code, all projects
skylos agent install-hooks --uninstall --cursor   # Cursor, this project
```

The uninstall removes only Skylos entries and leaves your other hooks alone.

## What each hook does

| Hook | Claude Code event | Cursor event | What it does | Can block? |
|:--|:--|:--|:--|:--|
| notice | `SessionStart` | `sessionStart` | Recommends installation or an upgrade when the full supported hook set is unavailable | No |
| `session-start` | `UserPromptSubmit` | `beforeSubmitPrompt` | Records the starting checkout, so later checks only count what the agent changed | No |
| `pre-read` | `PreToolUse` on `Read` | `beforeReadFile` | Blocks reading a file that contains a hard-coded secret | Yes |
| `pre-bash` | `PreToolUse` on `Bash\|PowerShell` | `beforeShellExecution` | Blocks installs of packages that don't exist or look like typosquats | Yes |
| `post-edit` | `PostToolUse` on `Edit\|Write\|MultiEdit` | `afterFileEdit` | Checks the changed lines and reports issues and notes | No; Claude gets immediate feedback. Cursor gets findings at stop |
| `stop` | `Stop` | `stop` | Holds the stop while issues the agent added are still open | Yes |

**What requires a fix after an edit:** secrets; untrusted input from a web
route, CLI argument, environment variable, stdin or similar reaching a dangerous sink;
sinks that are dangerous whatever the input (unsafe deserialization, disabled
TLS or JWT verification, `eval`/`exec`/`shell=True` with a non-constant
argument); and made-up packages, versions, APIs and references. These issues
are reported after the edit and can hold the stop. Other changed-line findings
are notes for the agent.

**At stop:** if the repository has a committed `[tool.skylos.done]` table in
`pyproject.toml`, the stop hook also runs the Skylos done gate (`skylos done`),
which runs the test command configured there and checks that tests were not
deleted, skipped or weakened. Without that table, stop only rechecks the
issues the agent added. The stop hook stops asking after a few unchanged
retries and lets the agent finish with a warning; that never counts as a pass.

The full behaviour, limits and latency measurements are in the
[agent hooks documentation](https://github.com/duriantaco/skylos/blob/main/docs/agent-hooks.md)
and the [done gate documentation](https://github.com/duriantaco/skylos/blob/main/docs/done-gate.md).

## Turn hooks off

Set `SKYLOS_HOOKS_DISABLE` in the environment your agent runs in. Its value is
a comma-separated list of hook names, or `all`:

```bash
export SKYLOS_HOOKS_DISABLE=pre-read
export SKYLOS_HOOKS_DISABLE=pre-bash,stop
export SKYLOS_HOOKS_DISABLE=all
```

To turn the plugin off completely, disable it in `/plugin` (Claude Code) or in
**Customize** (Cursor).

## Keep hook state out of Git

The hooks keep session state, a log and caches in the project's `.skylos/`
folder. `skylos agent install-hooks` adds these lines to `.gitignore`; with the
plugin, add them yourself:

```gitignore
.skylos/cache/
.skylos/agent-session.*
.skylos/hook.log*
.skylos/receipts/
```

## What the plugin runs, sends and stores

- **Runs:** only the `skylos` command on your PATH, plus `grep` and `echo` in
  the session-start notice. If the repository configures the done gate, the
  stop hook runs that repository's test command. That command's network
  behavior is determined by the repository.
- **Feedback:** findings and file locations are returned to the coding agent.
  The agent may send that feedback to its model provider according to its
  privacy settings.
- **Direct network calls:** analysis runs locally. These hooks do not directly
  upload project code or findings and need no Skylos account or API key.
  Their direct network calls are package-registry lookups: `pre-bash` asks
  PyPI (`pypi.org`), npm (`registry.npmjs.org`) or the Go module proxy
  (`proxy.golang.org`) whether
  the packages in an install command exist, and edit checks can do the same
  for newly added imports. These lookups send package names and versions.
  Install commands that use a private index skip these lookups. The skill's
  `skylos . -a` command also queries OSV.dev for known vulnerabilities in your
  dependencies.
- **Stores:** `.skylos/agent-session.json` (file paths and hashed issue
  identities, never source text), `.skylos/hook.log` (event, outcome, counts and timing; never
  file contents, secrets or commands), caches under `.skylos/cache/`, and done
  receipts under `.skylos/receipts/`. The done gate's starting snapshot is kept
  as local Git objects.

## What it doesn't do

- It doesn't undo an edit. The post-edit hook runs after the file is written;
  it reports and the agent fixes.
- It doesn't report findings that were there before the agent's change.
- It doesn't see reads or edits made through the shell (`cat`, `sed -i`,
  heredocs) when they happen, and it doesn't check installs from requirement
  files or lockfiles.
- It isn't a full security scan and doesn't replace CI. Keep a CI job that
  runs Skylos or your other scanners.
- It includes no MCP server.
- It hasn't been tested on Windows.

## License

Apache-2.0, the same as Skylos. Report problems at
<https://github.com/duriantaco/skylos/issues>.
