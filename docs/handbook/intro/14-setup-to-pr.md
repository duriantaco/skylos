# From setup to the pull request comment

Two commands cover the daily flow: `skylos setup` once per repository, and
`skylos open` whenever you want to see the code and what changed. The pull
request check that setup writes runs the rest.

## `skylos setup`

Run it once at the top of a Git repository. It is safe to run again; it
only changes what is missing or out of date.

1. **Agent instructions.** Writes a Skylos block between
   `<!-- skylos:start -->` and `<!-- skylos:end -->` in `CLAUDE.md` and
   `AGENTS.md`. It tells the coding agent to look up the code map before a
   change, run `skylos done` when it finishes, and list the "Read first"
   items of `skylos done map` in its final message. The rest of each file is
   left alone.
2. **MCP.** Adds Skylos to `.mcp.json` for Claude Code, and runs
   `codex mcp add skylos` when Codex is installed (`--no-codex` skips it,
   and the Codex hooks too).
3. **Agent hooks.** Installs the Skylos hooks in `.claude/settings.json` and
   `.codex/hooks.json`: they check each edit, block reads and commands that
   would show a secret, check installs, and when the agent stops either run
   `skylos done` (once a committed `[tool.skylos.done]` table exists) or
   recheck the edited files.
4. **Tests.** Adds `[tool.skylos.done]` (to `pyproject.toml`, or to an
   existing `skylos.toml`) when it finds pytest, Vitest or Jest, so
   `skylos done` runs them; commit it for the hooks and CI to use it. An
   existing table is left alone.
5. **The pull request check.** Runs `skylos cicd init` for the CI it finds
   (`--ci` picks one, `--no-ci` skips it; `--yes` replaces an existing
   workflow). Cloud upload jobs are added only when this machine is
   connected to Skylos Cloud (a login, `SKYLOS_TOKEN` or a linked project).
6. **Required checks.** On a later run, once the workflow is merged on
   GitHub and `gh` is installed and logged in with admin rights, it creates
   a ruleset named "Skylos" that requires its checks.
7. **Code map.** Builds `.skylos/graph/`.

Steps that are waiting on something (a merge, a login, tests to find) are
shown as pending. Setup exits 1 only when a step failed, and still runs the
others.

## The pull request check

On GitHub, `.github/workflows/skylos.yml` has these jobs:

- **Skylos Quality Gate** scans the changed lines with security, quality,
  AI-code, secret and dependency checks (including `--review-upgrades`),
  applies the gate, and adds annotations.
- **Skylos Done**, when setup found tests, runs `skylos done` against the
  base branch, which runs your tests and checks the change, and writes the
  change map to the job summary.
- **Skylos PR summary** posts one summary comment, edited on every push,
  and up to 25 inline review comments.
- **Skylos Cloud** upload jobs, when the machine was connected to Skylos
  Cloud.

`skylos cicd init --risk-review` adds a risk-review job, which `setup`
does not.

## The comment

The comment starts with one verdict line: the result of the gate, and of
Done and the risk review when those jobs exist. Then a count of issues on
changed lines (and how many there were before), and short sections:

- **Blocking:** the gate's reasons and Done's blocking checks;
- **Read first:** the changed code to review first, from the change map
  (needs the Done job);
- **Not checked by tests:** changed lines no test runs (needs the Done job);
- **Needs a person:** risks a human must approve (needs the risk-review
  job);
- a link to the full receipt and change map.

A details block below has the findings by severity and category, any
removed security controls, the evidence for top issues (with a "View fix"
link when the fix has code), and code the change left unused.

## `skylos open`

`skylos open` builds the code map and opens a page served only to this
computer (127.0.0.1, with a random token). It compares your work with the
branch pull requests merge into (`origin/HEAD`, else `origin/main`,
`origin/master`, `main` or `master`; `--base` to change it; with none, only
uncommitted changes) and has tabs for the code's areas, what changed in
plain English, and the last 30 `skylos done` runs. Its "Check this change" button
runs `skylos done` again. It rebuilds as files change.
