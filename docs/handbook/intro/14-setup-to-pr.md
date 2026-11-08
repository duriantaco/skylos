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
   `codex mcp add skylos` when Codex is installed (`--no-codex` skips it).
3. **Agent hooks.** Installs the Skylos hooks in `.claude/settings.json` and
   `.codex/hooks.json`: they check each edit, block reads of secret files and
   risky installs, and run `skylos done` when the agent stops.
4. **Tests.** Adds `[tool.skylos.done]` to `pyproject.toml` when it finds
   pytest, Vitest or Jest, so `skylos done` runs them. An existing table is
   left alone.
5. **The pull request check.** Runs `skylos cicd init` for the CI it finds
   (`--ci` picks one, `--no-ci` skips it; `--yes` replaces an existing
   workflow). Cloud upload jobs are added only when this machine is logged
   in to Skylos Cloud.
6. **Required checks.** On GitHub, once the workflow is merged and `gh` is
   logged in, it creates a ruleset named "Skylos" that requires its checks.
7. **Code map.** Builds `.skylos/graph/`.

It exits 1 when a step needs attention, and still runs the others.

## The pull request check

On GitHub, `.github/workflows/skylos.yml` has three jobs:

- **Skylos Quality Gate** scans the changed lines with security, quality,
  AI-code, secret and dependency checks (including `--review-upgrades`),
  applies the gate, and adds annotations.
- **Skylos Done** runs `skylos done` against the base branch, which runs
  your tests and checks the change, and writes the change map to the job
  summary.
- **Skylos PR summary** posts one comment and edits it on every push.

## The comment

The comment starts with one verdict line: the result of the gate, Done and
the risk review. Then a count of issues on changed lines
(and how many there were before), and short sections:

- **Blocking:** the gate's reasons and Done's blocking checks;
- **Read first:** the changed code to review first, from the change map;
- **Not checked by tests:** changed lines no test runs;
- **Needs a person:** risks a human must approve;
- a link to the full receipt and change map.

A details block below has the findings by severity and category, any
removed security controls, the evidence for top issues with a "View fix"
link, and code the change left unused.

## `skylos open`

`skylos open` builds the code map and opens a page served only to this
computer (127.0.0.1, with a random token). It compares your work with the
branch pull requests merge into (`origin/HEAD`, else `main` or `master`;
`--base` to change it) and has tabs for the code's areas, what changed in
plain English, and every `skylos done` run. Its "Check this change" button
runs `skylos done` again. It rebuilds as files change.
