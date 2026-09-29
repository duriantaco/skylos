# Project standards for coding agents

Skylos can give coding agents a project skill and check the standards that its
built-in quality rules can measure. The skill file is named `SKILL.md` (singular),
inside a named directory. Write your team's guidance once in a Markdown file;
the installer creates small skill files that point to it.

## Set up a project

Create `.skylos/standards.md` with the conventions you want agents to follow.
For example:

```markdown
# Coding standards

- Keep functions focused and handle exceptions explicitly.
- Match the surrounding naming and formatting conventions.
- Add a focused test when changing behavior.
```

Then run:

```bash
skylos agent install-standards --enforce SKY-L002 SKY-C304
skylos agent install-hooks --codex   # use --cursor for Cursor, or omit for Claude Code
skylos agent check-standards .
```

The first command requires the Markdown file to exist. It writes:

| File | Purpose |
|:---|:---|
| `.agents/skills/skylos-project-standards/SKILL.md` | Project skill for Codex and Cursor |
| `.claude/skills/skylos-project-standards/SKILL.md` | Project skill for Claude Code |
| `.skylos/agent-standards.json` | Path to the Markdown file and quality rule IDs to enforce |

Commit the Markdown file, skills, and JSON policy so teammates get the same
guidance. The installer does not rewrite existing `AGENTS.md`, `CLAUDE.md`, or
Cursor rules. Run it again after changing the selected rule IDs; `--dry-run`
previews the files it would write. Use `--standards PATH` for another Markdown
file inside the project, and `--path PROJECT` to install from elsewhere.

The skill is available to agents working in the project. Agents choose when to
load a skill, so ask the agent to use `skylos-project-standards` when you want
the guidance in context. For always-present Codex instructions, add this to
your project's `AGENTS.md` yourself:

```markdown
When editing code, use the skylos-project-standards skill and follow
.skylos/standards.md.
```

## What enforcement covers

`--enforce` accepts one or more exact IDs of built-in Skylos quality rules. Use
`skylos rules list` to find them. You can repeat `--enforce` or give multiple
IDs after one flag. For example, `SKY-L002` detects bare `except:` blocks and
`SKY-C304` detects long functions. A non-quality or unknown rule ID is rejected.
If you omit `--enforce`, the skill is guidance only.

With agent hooks installed, Skylos checks selected rules on lines the agent
adds. A selected finding asks the agent to fix the edit; `stop` checks whether
the issues it recorded are still open. `skylos hook recheck FILE` applies the
same hook policy to a file on disk. Existing secret, security, and AI defect
hook checks still apply.

Run `skylos agent check-standards .` for an independent, project-wide static
check. It exits `1` when selected quality rules have findings, `0` when they
do not, and `2` when the policy is missing or invalid or the scan fails. Use
`--format json` for CI or other tooling:

```bash
skylos agent check-standards . --format json
```

The project-wide check includes existing findings in the scanned project.
Agent hooks cover only edits they can attribute to the agent; shell edits and
pure deletions may not trigger an edit check. A rule whose finding is anchored
on an unchanged line, such as a long function reported on its declaration,
may also escape the edit hook when the agent changes only its body. Run the
project-wide check in CI if the selected rules must hold for every change.
The policy file and Skylos scan configuration are repository data. Project
ignores, inline suppressions, and quality thresholds can affect findings, so
protect changes to those files and settings with the same review rules as
other CI policy.

Markdown instructions such as naming preferences or required tests remain
guidance unless a separate tool checks them. The JSON policy selects only
built-in quality rules; it does not execute commands from the Markdown file.

See [agent-loop hooks](./agent-hooks.md) for hook installation and behavior.
