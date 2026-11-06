# Agent configuration and publish-job rules

`skylos . --danger` (and `-a`) reads the agent, editor and CI files committed
to the repository through the ca9 engine (`ca9.api.agent_config`,
`ca9.api.audit_workflows`, `ca9.api.ci_inventory`) and reports what runs
automatically when someone opens the repository with a coding agent or
editor, and what can reach a package registry's credentials.

These are the files the 2026 worm campaigns (Mini Shai-Hulud, Hades, keyv,
PolinRider) planted: a `SessionStart` hook or a `folderOpen` task survives
`--ignore-scripts`, because the agent or editor runs it, not the package
manager.

## Rules

| ID | Severity | Reported when |
|:---|:---|:---|
| `SKY-D365` | HIGH; CRITICAL when the command downloads remote code, decodes and runs a payload, or runs a script disguised as a font or image | A committed agent hook runs a command: `.claude/settings.json` and `settings.local.json` hooks, `.gemini/settings.json`, `.cursor/hooks.json`, `.codex/hooks.json` or `config.toml`. Hooks written by `skylos agent install-hooks` are not reported (see below) |
| `SKY-D366` | HIGH; CRITICAL as above | A `.vscode/tasks.json` (or `*.code-workspace`) task with `runOptions.runOn: "folderOpen"`: VS Code, Cursor and Windsurf run it when the folder opens once automatic tasks are allowed |
| `SKY-D367` | MEDIUM | An MCP server launched without an exact version: `npx -y pkg`, `pkg@latest`, `uvx pkg`, a Docker image without a digest (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.kiro/settings/mcp.json`, `mcpServers` blocks) |
| `SKY-D368` | HIGH | An MCP server launched from a hidden home-directory or temp path outside the repository (`~/.dev-utils/server.js`) |
| `SKY-D369` | MEDIUM | An MCP server package whose name imitates a vendor it is not published by (`postmark-mcp`) |
| `SKY-D370` | HIGH | Committed agent settings override the API base URL (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), which sends the API key to that host (the CVE-2026-21852 shape) |
| `SKY-D371` | HIGH | A tool is installed without a pinned version or hash (`curl \| sh`, `pip install x`, a `setup-*` action without a version) in a job that holds publish credentials or `id-token: write` |
| `SKY-D372` | HIGH | A download without a checksum or signature check reaches the publish step |
| `SKY-D373` | HIGH | A job that can mint OIDC tokens (`id-token: write`) publishes without a deployment `environment:` |
| `SKY-D374` | HIGH | A publishing workflow can be started by `workflow_dispatch` or a push to any branch |
| `SKY-D375` | MEDIUM | `--diff` only: the change adds or modifies a CI job that publishes packages (steps, triggers, permissions, secrets; moved lines alone do not count) |
| `SKY-D376` | MEDIUM | A job passes secrets (`secrets: inherit` or named secrets) to a reusable workflow from another repository |
| `SKY-D377` | MEDIUM | An agent or editor config repeats a key (for example two `hooks` blocks): JSON parsers keep different copies, so what you read is not what runs |

The message quotes the exact command or job; JSON keeps ca9's evidence in
`metadata.evidence` (bounded). Every row must name a regular file inside the
scanned folder: rows for paths outside it, symlinks or folders are dropped. A
full scan reads files Git tracks or does not ignore; a diff scan (`--diff`,
`--diff-base`) reads only files Git tracks. Suppress one rule project-wide with
`ignore = ["SKY-D367"]` under `[tool.skylos]`.

## Gate

| Scan | Built-in `--gate` |
|:---|:---|
| Whole repository | `SKY-D365`-`SKY-D374`, `SKY-D376` and `SKY-D377` are listed and not counted, so repositories that already commit agent hooks, unpinned MCP servers or a manually started release workflow keep passing after an upgrade. A CRITICAL `SKY-D365` or `SKY-D366` (a hook that downloads or decodes and runs code) still fails, like any critical issue |
| Diff (`--diff`, `--diff-base`) | A new or changed `SKY-D365`, `SKY-D366`, `SKY-D368` or `SKY-D370` fails the gate on its own ("supply-chain change to review"). `SKY-D367`, `SKY-D369` and `SKY-D371`-`SKY-D377` count under the normal limits |
| Baseline (`--baseline`) | As a diff, but only for the rules the baseline covered. `skylos baseline` records them (`rule_coverage` in `.skylos/baseline.json`: the rules the installed ca9 could decide). A baseline saved by an older Skylos, or without those ca9 checks, never saw the hooks and workflows they report, so their findings are listed like a whole-repository scan instead of failing as new. Agent-config and publish-job findings match the baseline by rule, file and the command or job they name, not by line, so editing other settings does not make an old hook new, and changing a hook's command in place does |

A synced Skylos Cloud gate counts every finding the way Cloud does, and the
diff blocks above still apply.

## Skylos's own hooks

`skylos agent install-hooks` writes commands such as
`/path/to/venv/bin/skylos hook pre-bash --client claude || exit 0`. Such a
hook is not reported only when its whole command matches that grammar:

- `<program> hook <event> --client claude|codex|cursor`, optionally followed
  by one of the fixed `||` fallbacks Skylos writes (`exit 0`, `echo '{}'`,
  `echo '{"permission":"allow"}'`, `echo '{"continue":true}'`), with no other
  shell syntax;
- `<program>` is `skylos` found on your own `PATH`, or an absolute path ending
  in `/skylos` that is outside the repository and outside `/tmp`, `/var/tmp`
  and `/dev/shm`, so the repository cannot supply the program;
- the settings file is JSON and its `env` does not set `PATH`, `PYTHONPATH`,
  `NODE_OPTIONS`, `BASH_ENV`, `LD_*`, `DYLD_*` or similar loader variables.

`python -m skylos.entry` is reported: `-m` imports from the working folder,
which the repository controls. A hook named `skylos` that does anything else
(`skylos hook stop --client claude; curl ...`) is reported like any other.
In the uploaded `agent_hooks` inventory these hooks carry `skylos_hook: true`.

## When ca9 cannot check

A diff scan (`--diff`, `--diff-base`, and `skylos cicd pr-scan`) that changes an
agent or editor config, a workflow or (with `--sca`) a lockfile, while ca9 is
not installed, is older than API version 1, or lacks the function that checks
it, records an analysis error ("… ca9 is not installed or too old. Upgrade ca9
(pip install -U ca9) and rerun."): the gate stops as incomplete (exit 2)
instead of passing unchecked. So does a baseline scan whose baseline covered
rules this run's ca9 cannot decide. A whole-repository scan without a usable
ca9 notes it in `analysis_summary.supply_chain_checks` and reports nothing for
these rules.

When a changed workflow calls a reusable workflow or includes a file from
another repository, ca9's audit is incomplete for it. The verdict shows
`Workflow audit incomplete for the changed workflows: …` and
`analysis_summary.supply_chain_diff.checks.agent_and_workflow_files.workflow_audit`
lists the reasons; this alone does not fail the gate, since such a call may
predate the change.

## Credentials in commands

Finding messages, values and evidence, and the uploaded `agent_hooks`
inventory, pass hook and MCP commands through a redactor: URLs keep only
`scheme://host`; `Authorization`/`Bearer`/`Basic` values, `user:password`
pairs (`-u admin:…`, `admin:…@host`), values of `--password`, `--token`,
`--secret`, `--api-key`, `--auth` and similar options, values of
`NAME=value` where NAME contains PASS, SECRET, TOKEN, KEY, AUTH or CREDENTIAL
(`$VAR` references are kept), `-p` passwords of MySQL clients, `sshpass` and
`… login` commands, and known token prefixes (`ghp_`, `gho_`, `github_pat_`,
`npm_`, `sk-`, `sk-ant-`, `AKIA…`, `xox…`) become `[redacted]`.

## Where settings come from

Hardening exceptions (`[tool.skylos.supply_chain.hardening_exceptions]`) are
always read from the diff's merge base. `ignore` and the rest of
`[tool.skylos.supply_chain]` (`internal_packages`, registries) come from the
base commit only under `--gate` with a diff base (or `SKYLOS_POLICY_BASE`, as
`skylos cicd init` workflows set); a plain `--diff` run without `--gate`
reads them from the working tree, so a change can still edit them there.

## Upload

`--sca` scans upload the `ci_inventory` and `agent_hooks` blocks next to the
dependency inventory; see
[Supply-chain posture and package inventory](./dependency-scanning.md#supply-chain-posture-and-package-inventory).
