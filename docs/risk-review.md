# Risk review (`skylos cicd risk-review`)

`skylos cicd risk-review` lists the risks in a pull request that should not be
merged on a review bot's approval alone, such as a deleted test, a removed
auth check or a new dependency. It runs as the GitHub check **Skylos risk
review**. The check fails while the pull request has risks. It passes when
there are none, or when a person with write access approves the head commit.
Approvals from review bots (Copilot, CodeRabbit and others) do not count.

Each fact is deterministic and fits in one line: the same commit gives the
same answer on every run. The check does not score or summarize the change.

```bash
skylos cicd risk-review --base origin/main               # text
skylos cicd risk-review --base origin/main --format json # for scripts
skylos cicd init --risk-review                           # add the GitHub job
```

Exit codes:

| Code | Meaning |
|:--|:--|
| `0` | No risk found, or a person with write access approved the head commit |
| `1` | Risks found and no person with write access approved the head commit. Outside GitHub Actions, risks found. |
| `2` | Could not decide: a check did not finish, the base is missing, or GitHub's API failed. This code never passes. |

## Risk classes

| Class | Fires on | Rules |
|:--|:--|:--|
| `tests_weakened` | A test that existed at the base was deleted (not moved, renamed or removed together with its feature), left with no assertion, lost parametrize or `.each` cases, gained a skip or xfail, or a `.only` focus. Also loosened test settings and quiet CI test steps, and code that special-cases the tests. | SKY-A110, SKY-A111, SKY-A112, SKY-A115, SKY-A116, SKY-A117 |
| `auth_removed` | An auth, CSRF or rate-limit control was removed from a route or handler. | SKY-L021 |
| `dependency_changed` | A dependency was added, or its version or source changed, in a manifest or lockfile. A lockfile was removed while its project stays. An added import names a package that does not exist on its registry. | SKY-D222, SKY-D225, or none (manifest and lockfile changes) |
| `ci_weakened` | A CI lint, type-check, scan or test step can now fail quietly or no longer runs. A workflow gained write permissions or a privileged trigger. A workflow the change adds or edits now runs an AI agent (claude-code-action, codex-action, run-gemini-cli, ai-inference and others) with a HIGH or CRITICAL finding that the base version of the file did not have: an untrusted trigger without an actor gate, a widened write-access check, shell tools on untrusted text, untrusted text in the prompt, or a version with a published advisory. | SKY-A121, SKY-A103, SKY-D350 to SKY-D354 |
| `checks_silenced` | Linter, type-checker or scanner settings were weakened (rules ignored, paths excluded, `strict` off, secrets allow-listed), test-only excludes included; or a suppression now stops a tool checking a whole file or region (`/* eslint-disable */`, `@ts-nocheck`, `# ruff: noqa`, `# mypy: ignore-errors`, `# pylint: skip-file`, a `# type: ignore` above all code, `// biome-ignore-all lint`, `//nolint` on the package clause, `#![allow(warnings)]`), test files included; or a scanner suppression marker that names no rule and covers more than a line or statement (`# kics-scan ignore`, `@codescene(disable-all)`). | SKY-A119, SKY-A118, SKY-A125 |
| `secret_added` | A secret on an added line. | SKY-S101, SKY-S102 |
| `guardrail_config_changed` | Skylos settings (`[tool.skylos]`, `.skylos/`), agent hook settings (`.claude/settings.json`, `.codex/`, `.cursor/hooks.json`, other `protected_paths`), or a CI workflow that runs Skylos changed. A file an AI code reviewer reads its instructions or settings from changed (`.coderabbit.yaml`, `.github/copilot-instructions.md`, `REVIEW.md`, `.cursor/BUGBOT.md` and others). | SKY-A114, SKY-A122 |
| `migration_changed` | A file under a `migrations/` directory, `db/migrate/` (Rails), `db/migration/` (Flyway), `db/changelog/` (Liquibase) or `alembic/versions/` was added, changed, moved or deleted. Documentation and images in those directories and vendored paths do not count. | none |
| `large_diff` | More than 800 changed lines or more than 40 changed files. Lockfiles do not count toward either limit. | none |

Most facts come from the checks [`skylos done`](./done-gate.md) runs. That
page explains in detail what counts as a deleted, moved or weakened test. The
risk review does not run your tests: SKY-A113 (failing tests) and SKY-A120
(untested lines) never appear. Nor does it look for code left without
callers (SKY-A135 to SKY-A137), which belongs to no risk class. Run
`skylos done` for those.

These rules map to their class as soon as a Skylos release emits them:
SKY-A123 to `guardrail_config_changed` and SKY-A124 to `ci_weakened`.

**Advice is listed, not counted.** Some findings `skylos done` reports only
as advice. They appear under `advisories` in the JSON and need no approval:

- weakened assertions (SKY-A101);
- a test deleted together with the code it tested;
- tests rewritten in place;
- suppressions of one line, or of named rules, such as `# noqa: F401`,
  `@ts-ignore`, `// eslint-disable-next-line no-console` and
  `# ruff: noqa: E501` (SKY-A118);
- scanner suppression markers of one line or statement, or of named rules,
  such as `// skipcq: JS-0002`, `// NOSONAR` in PHP and
  `# checkov:skip=CKV_DOCKER_3` (SKY-A125);
- imports that cannot be tied to a declared package (SKY-D223).

**Dependencies.** Changed manifests and lockfiles are compared entry by entry
at the base and at head. Bumping the project's own version, editing scripts,
reformatting and moving a package between sections or files are not
dependency changes. A dependency on a package the repository builds itself
is not one either: workspace and path dependencies, local `replace`
directives, and the repository's own crates, modules and packages. A
manifest or lockfile that changed but cannot be parsed counts as a change.
Supported formats:

- npm (`package.json`, `package-lock.json`, `npm-shrinkwrap.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`);
- Python (`requirements*.txt`, `constraints*.txt`, `pyproject.toml`,
  `setup.py`, `setup.cfg`, `Pipfile`, `Pipfile.lock`, `poetry.lock`,
  `uv.lock`, `pdm.lock`, `environment.yml`);
- Go (`go.mod`, `go.sum`);
- Rust (`Cargo.toml`, `Cargo.lock`);
- PHP (`composer.json`, `composer.lock`);
- Ruby (`Gemfile`, `*.gemspec`, `Gemfile.lock`);
- JVM (`pom.xml`, `build.gradle(.kts)`, `gradle/*.versions.toml`,
  `gradle.lockfile`);
- Dart (`pubspec.yaml`, `pubspec.lock`);
- .NET (`*.csproj`, `Directory.Packages.props`, `packages.lock.json`).

Any change to `bun.lockb`, `deno.lock`, `pixi.lock`, `mix.lock`,
`Package.resolved` or `flake.lock` counts. Skylos does not compare entries in
those formats.

## Human approval in GitHub Actions

When the job runs on a pull request with a token (`GITHUB_TOKEN`), it reads
the pull request's reviews through the GitHub REST API, but only when risks
were found. An approval counts when all of these hold:

- It is the reviewer's latest review that approves, requests changes or was
  dismissed. Requesting changes or dismissing the approval afterwards cancels
  it; a later comment does not.
- It was submitted on the head commit the check analysed. An approval of an
  earlier commit does not cover commits pushed after it.
- The reviewer is a person. GitHub App and bot accounts (type `Bot`, or a
  login ending in `[bot]`) are not, and neither are logins listed in
  `non_human_logins`.
- The reviewer can write to the repository: author association `OWNER`,
  `MEMBER` or `COLLABORATOR`, confirmed through the collaborator permission
  API. On a public repository anyone can leave an approving review.

The text and step summary name the approver, for example:
`Human-approved: alice approved these risks: tests_weakened (2), dependency_changed (1)`.
Without an approval, the message says what needs one:
`Needs a human approval: tests_weakened (tests/test_refund.py:41), auth_removed (api/views.py:88)`.

If the reviews cannot be read, the check exits 2 and fails. It also exits 2
when the checked-out commit is not the pull request head.

Without a token or a pull-request event, for example on your machine, the
command lists the risks and exits 1 when there are any.

## Setting it up on GitHub

```bash
skylos cicd init --risk-review --no-upload
```

This adds a job named **Skylos risk review** to `.github/workflows/skylos.yml`,
a second job named **Skylos risk review (re-check after review)**, and the
trigger `pull_request_review: types: [submitted, dismissed]`. Only the re-check
job runs on review events; the other jobs skip them. The risk review job:

- checks out the pull request head with full history;
- reads the base branch from the event;
- has `contents: read` and `pull-requests: read` permissions;
- passes `GITHUB_TOKEN` to the command;
- shares a concurrency group per pull request, so its runs finish in the
  order they started.

Then make it a required check: in branch protection or a ruleset for your
default branch, turn on **Require status checks to pass before merging** and
add **Skylos risk review**. GitHub lists a check there once it has run in the
repository.

### What GitHub then does

- GitHub evaluates required status checks and required approvals
  separately. A pull request with a failing **Skylos risk review** check
  cannot be merged, however many approvals it has, including approvals from
  review bots that count toward your required approvals.
- When a person with write access approves the head commit, GitHub sends a
  `pull_request_review` event. The re-check job waits for the pull request's
  own run to finish, then re-runs its **Skylos risk review** job, which finds
  the approval and passes. Because the re-run replaces the result inside the
  pull request's run, the merge button unblocks.
- Why not simply run the risk review again on the review event: GitHub
  treats every check run with a required name on the head commit as
  required. A passing run from the review event next to the failing run from
  the pull request event leaves the pull request blocked (verified on GitHub,
  14 Oct 2026).
- The re-check job needs `actions: write` to re-run a job. On pull requests
  from forks, GitHub gives the token read access only, so the re-check fails
  and the risk review stays failed: re-run the **Skylos risk review** job
  from the pull request's checks after approving.
- Pushing a new commit runs the check again on that commit. If it still has
  risks, the check fails until someone approves the new head commit, whether
  or not branch protection dismisses stale approvals.
- Updating the branch only with the base branch's changes ("Update branch",
  or merging the base in) keeps an existing approval: GitHub moves that
  review to the new head commit, so the check still passes.
- Dismissing the approval, or requesting changes after it, re-runs the job
  and the check fails again.
- People and apps on the bypass list of the branch protection rule or
  ruleset (by default, administrators when "Do not allow bypassing the
  above settings" is off) can still merge while the check fails.
- The check does not replace your required approvals. Keep **Require
  approvals**: the risk review only decides whether a person must be one of
  the approvers.

### Limits to know

- A `pull_request` workflow runs the workflow file from the pull request
  itself, so a pull request can edit or remove the job that checks it. The
  risk review reports edits to a workflow that runs Skylos
  (`guardrail_config_changed`), but only if the edited workflow still runs
  it. To close this gap, add `.github/workflows/` to `CODEOWNERS` and turn on
  **Require review from Code Owners**. GitHub Apps cannot be code owners.
  (Workflows required through rulesets do not run on `pull_request_review`
  events, so they cannot pick up an approval.)
- GitHub reports a skipped job as successful, and a skipped required check
  does not block merging. Keep the job's `if:` condition as generated. Do not
  add other triggers, such as `push` on pull request branches, that skip it
  on the pull request's head commit.
- On a `pull_request_review` event GitHub does not set `GITHUB_BASE_REF`.
  The generated step reads the base branch from the event instead.
- With a merge queue, required checks must also report on `merge_group`
  events. The generated workflow does not run on them.
- The check reads only the static facts above. A person still has to review
  the change.

## Settings

Settings are read from `pyproject.toml` at the tip of the base branch, never
from the pull request. A pull request that edits them is itself reported
under `guardrail_config_changed`.

```toml
[tool.skylos.approval]
# Classes that need a human approval (default: all nine).
veto_classes = [
  "tests_weakened", "auth_removed", "dependency_changed", "ci_weakened",
  "checks_silenced", "secret_added", "guardrail_config_changed",
  "migration_changed", "large_diff",
]
large_diff_lines = 800           # more than this many changed lines
large_diff_files = 40            # or more than this many changed files
migration_globs = ["db/schema/*.sql"]   # added to the built-in migration paths
non_human_logins = ["release-robot"]    # machine users that are not people

[tool.skylos.approval.exclude]    # per class: paths that never need approval
secret_added = ["tests/fixtures/"]
large_diff = ["docs/"]
```

Patterns ending in `/` match everything under that folder. Patterns with
`*`, `?` or `[` are globs, and `*` matches across folders. Any other pattern
matches that path or folder. The `skylos done` settings in
`[tool.skylos.done]` still apply to the checks the risk review reuses:
`protected_paths` and `test_command`, which test-exclusion rules read. The
modes under `[tool.skylos.done.checks]` do not apply to the risk review.
Settings that cannot be used are listed as "Setting ignored" and in
`settings.problems`.

## Output

`--format json` prints one object under `approval`:

```json
{
  "approval": {
    "schema": "skylos.approval/v1",
    "check": "Skylos risk review",
    "verdict": "needs_human_approval",
    "passed": false,
    "eligible": false,
    "complete": true,
    "needs_human_approval": ["tests_weakened"],
    "human_approval": {"status": "missing", "login": null, "review_id": null,
                       "detail": "no person with write access approved the head commit",
                       "ignored": ["copilot-pull-request-reviewer[bot] (not a person)"]},
    "vetoes": [{"class": "tests_weakened", "rule_id": "SKY-A110",
                "file": "tests/test_refund.py", "line": 41,
                "reason": "test_partial_refund was deleted; no test with the same body exists now"}],
    "advisories": [],
    "classes_checked": ["tests_weakened", "auth_removed", "..."],
    "classes_incomplete": [],
    "classes_disabled": [],
    "base": "<merge base sha>", "base_ref": "origin/main",
    "head": "<head sha>", "head_dirty": false,
    "diff": {"files": 3, "lines": 52},
    "excluded": 0,
    "settings": {"configured": false, "large_diff_lines": 800,
                 "large_diff_files": 40, "problems": []},
    "exit_code": 1
  }
}
```

The `verdict` field takes one of these values:

| Verdict | Meaning | Exit code |
|:--|:--|:--|
| `eligible` | No risks found | 0 |
| `human_approved` | Risks found, and a person approved the head commit | 0 |
| `needs_human_approval` | Risks found, and no person approved the head commit | 1 |
| `incomplete` | A risk class could not be checked; `classes_incomplete` says why | 2 |
| `review_check_failed` | Risks found, and the reviews could not be read | 2 |
| `error` | The comparison could not start, for example the base was not fetched; `error` says why | 2 |

In GitHub Actions the command also writes:

- the step summary;
- the step outputs `passed`, `eligible` (both `true` or `false`) and
  `classes` (the comma-separated classes that need approval).

Other workflow steps can read these outputs. For example, a step that
auto-merges dependency updates can run only when `eligible` is `true`.
