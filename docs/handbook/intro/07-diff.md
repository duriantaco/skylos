# Full scans and diff scans

A **full scan** (`skylos . -a`) reports every finding in the project. Use it
to learn what is there, and for a scheduled audit.

A **diff scan** reports only what a change brings in. It is what you want on
a pull request: reviewers see the new problems, not years of old ones.

| Command | Reports |
|:--|:--|
| `skylos . -a` | Every finding in the project. |
| `skylos . -a --diff origin/main` | Findings on lines changed since `origin/main`. |
| `skylos . -a --diff-base origin/main` | Findings anywhere in files changed since `origin/main`. |
| `skylos . -a --diff HEAD` | Findings on your uncommitted work only. |
| `skylos . -a --diff` | Like `--diff origin/main`, but against the pull request's target branch when it runs in GitHub Actions, GitLab CI, Jenkins, Bitbucket, Azure Pipelines, Buildkite, Travis CI, Drone or Woodpecker. |

Both diff modes compare the branch point (the merge base of the reference
and `HEAD`) with your working tree, so committed, staged and unstaged edits
all count. A new file that Git does not ignore counts as changed in full. A
reference that does not exist exits 2.

> A bare `--diff` reads `GITHUB_BASE_REF` whenever that variable exists. If
> it exists but is empty, as GitHub may leave it outside pull request
> events, the scan exits 2. Pass the base explicitly in those jobs.

## What each mode reads

- `--diff` runs every rule on every file, then keeps the findings on changed
  lines. A few change-level findings are kept even off the changed lines: a
  removed security control (SKY-L021), changed AI-reviewer settings
  (SKY-A122), added scanner markers (SKY-A125), a changed publish job
  (SKY-D375), and dependency upgrade and hardening findings. Agent
  configuration and publish-job findings (SKY-D365 to SKY-D377) are kept
  when they are new against the base, whichever line changed, and dropped
  when the base already had them.
- `--diff-base` still parses unchanged files, so facts that span files, such
  as who calls a function, stay correct, but it runs the security, secret
  and quality rules only on changed files.
- `--diff-mode impact` (with `--diff` only) scans the base version too and
  reports symbols that the change left unused outside the changed lines,
  such as a helper whose last caller was deleted.

## Rules that compare two versions

Some rules compare the old and new version of a file. Test assertion
weakening (SKY-A101), for example, reads the Git diff of each changed test
file. They run in diff scans, in `skylos done`, and in a full scan of a Git
checkout that has uncommitted edits (or, in CI, a known pull request base);
their pages say which.

## Differences to expect

- Size and complexity measurements (function length, complexity, nesting)
  that the change introduced or made worse are listed separately in a diff
  scan and never fail its gate.
- A diff scan that cannot analyse a changed file exits 2, because the code
  under review was not checked. A full scan only warns.
- Diff scans cannot be uploaded to Skylos Cloud with `--upload`.
