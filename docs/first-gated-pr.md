# Your First Skylos-Gated Pull Request

This takes about 8 minutes. At the end, every pull request in your repository
gets two GitHub checks, and a pull request that fails them cannot merge:

| Check | What it does |
|:---|:---|
| **Skylos Quality Gate** | Scans the lines the pull request changes for security issues, secrets, quality problems, AI-code mistakes and vulnerable dependencies. Fails on any critical security issue, secret or critical AI-code mistake (such as an import of a package that does not exist), and when other findings pass their limits. Posts a summary comment and inline comments. |
| **Skylos Done** | Runs your tests and checks that the change is finished: no deleted or skipped tests, no edits to Skylos settings, no added secrets. Added when Skylos can find your tests. |

No API key or repository secret is needed for either check.

## Before you start

- A GitHub repository where you can push branches. Step 5 needs admin access.
- Python 3.11 or newer, `git`, and the [GitHub CLI](https://cli.github.com)
  (`gh auth status` should show you logged in). The commands below use `gh`,
  but the GitHub website works too.
- Required checks need a public repository, or a private one on GitHub Pro,
  Team or Enterprise.

## 1. Install Skylos (1 minute)

```bash
pip install skylos
skylos --version
```

Expected: `skylos 4.46.0` or newer.

## 2. Generate the workflow (1 minute)

From your repository, on a new branch:

```bash
git checkout -b add-skylos-gate
skylos cicd init
```

This guide is for GitHub Actions. For GitLab CI, Jenkins, Bitbucket Pipelines,
Azure Pipelines or CircleCI, see [Skylos on any CI](./ci-platforms.md). A
repository with one of those CI files and no `.github/workflows/` gets that
CI's gate; run `skylos cicd init --ci github` to follow this guide instead.

Expected, for a repository with pytest tests:

```text
Workflow written to .github/workflows/skylos.yml

Pull requests
  Skylos Quality Gate     scans the changed lines; fails when the gate fails
  Skylos Done             runs your tests (pytest project found)
                          installs: python -I -m pip install -e . pytest
                          edit that step in the workflow if your tests need more
Pushes to main
  Skylos Cloud upload     full scan to Skylos Cloud with GitHub OIDC; no API key secret
                          needs the Skylos GitHub App on this repository
                          (without Cloud: rerun with --no-upload)
Pull requests to main
  Skylos Cloud PR upload  scans the PR head as data with no credentials; a job that
                          never checks it out uploads it with GitHub OIDC
                          starts with PRs opened or updated after this file is merged
```

Two choices to make here:

- **Not using Skylos Cloud?** Run `skylos cicd init --no-upload`. Otherwise
  the upload jobs fail until step 7 is done.
- **"Skylos Done: not added"?** Skylos found no pytest tests and no
  `test_command`. For a Vitest or Jest project, the message prints the exact
  `[tool.skylos.done]` settings to add. Continue without it, or see
  [Troubleshooting](#troubleshooting).

Check the `Install project test dependencies` step in the file. Skylos Done
runs your whole test suite with what that step installs.

If `.github/workflows/skylos.yml` already exists and is different, Skylos asks
before replacing it and keeps the old file as `skylos.yml.bak`. Without a
terminal (a script or an agent), it writes nothing unless you add `--force`.

## 3. Open the pull request (1 minute)

```bash
git add .github/workflows/skylos.yml
git commit -m "Add Skylos pull request gate"
git push -u origin add-skylos-gate
gh pr create --fill
```

Keep this pull request to the workflow file. Do not add `skylos init` or
other `[tool.skylos]` changes to it: Skylos Done fails a pull request that
changes Skylos settings.

## 4. Watch the checks (3 to 4 minutes)

```bash
gh pr checks --watch
```

Expected (the exact columns depend on your `gh` version):

```text
✓  Skylos Analysis/Skylos Quality Gate (pull_request)
✓  Skylos Analysis/Skylos Done (pull_request)
-  Skylos Analysis/Skylos Cloud upload (pull_request)
-  Skylos Analysis/Skylos Cloud PR policy (pull_request)
-  Skylos Analysis/Skylos Cloud PR scan (pull_request)
-  Skylos Analysis/Skylos Cloud PR upload (pull_request)
```

`-` means skipped: the upload job runs only on pushes to your default branch,
and the three PR upload jobs only on `pull_request_target` runs. GitHub runs
those from the workflow on your default branch, so they start with the pull
requests opened or updated after this one is merged.
The gate checks only the lines a pull request changes, so findings already in
your code do not fail this first pull request. On the pull request you will
also see:

- a **Skylos Analysis Summary** comment. Later pushes edit this same comment
  instead of adding new ones, and it says so when every issue it reported on
  the changed lines is fixed;
- the gate table and the Done receipt in each job's summary (click the check,
  then **Summary**);
- inline comments and file annotations when a changed line has a finding. A
  finding gets one inline comment: later pushes add comments only for new
  findings, up to `--max-comments` (default 25) per pull request.

If both checks pass, the gate works. Merge the pull request:

```bash
gh pr merge --squash --delete-branch
```

## 5. Make the checks required (1 minute)

This creates a ruleset on your default branch. Skip `"Skylos Done"` if
step 2 said it was not added.

```bash
gh api --method POST "repos/{owner}/{repo}/rulesets" --input - <<'EOF'
{
  "name": "Skylos",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [{
    "type": "required_status_checks",
    "parameters": {
      "strict_required_status_checks_policy": false,
      "required_status_checks": [
        {"context": "Skylos Quality Gate"},
        {"context": "Skylos Done"}
      ]
    }
  }]
}
EOF
```

`gh` fills in `{owner}/{repo}` from the current repository. Expected: JSON
for the new ruleset, including `"enforcement": "active"`. In the browser, the
same setting is **Settings → Rules → Rulesets → New branch ruleset → Require
status checks to pass**.

To accept these checks only from GitHub Actions, add
`"integration_id": 15368` to each entry. Leave it out if you use Skylos Cloud:
its dashboard only counts a "Skylos Quality Gate" requirement that accepts any
source or the Skylos GitHub App.

## 6. See it block a pull request (2 minutes)

Use your default branch name if it is not `main`.

```bash
git checkout main && git pull
git checkout -b try-skylos-gate
printf 'import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n' > skylos_gate_demo.py
git add skylos_gate_demo.py
git commit -m "Try the Skylos gate"
git push -u origin try-skylos-gate
gh pr create --fill
gh pr checks --watch
```

Expected: **Skylos Quality Gate** fails with `1 critical security issue(s)`
(SKY-D212, command injection through `shell=True`), the line gets an inline
comment, and GitHub shows **Merging is blocked**. That is your first
Skylos-gated pull request. Clean up:

```bash
gh pr close --delete-branch
git checkout main
```

To see an AI-code mistake blocked, repeat the steps with this file instead:

```bash
printf 'def handle(payload, signature):\n    if not verify_signature(payload, signature):\n        raise ValueError("bad signature")\n    return payload\n' > skylos_gate_demo.py
```

Expected: **Skylos Quality Gate** fails with
`1 critical AI-code issue (SKY-L012 phantom symbol reference)`, because
`verify_signature` is never defined or imported. Critical AI-code issues fail
the gate by default. To change that, set `block_ai_defect_severities` under
`[tool.skylos.gate]`; see the [gate settings](../README.md#cicd).

## 7. Optional: connect Skylos Cloud (3 to 5 minutes, needs the browser)

This sends full scans of your default branch, and of pull requests to it, to
the Skylos Cloud dashboard. The checks from steps 4 to 6 do not depend on it.

1. Run `skylos login` in the repository. In the browser, sign in with GitHub
   and choose or create the project for this repository. The CLI sends the
   repository URL from `git remote`.
2. In Skylos Cloud, open the project's settings and install the **Skylos
   GitHub App** on this repository. In an organization, an owner may have to
   approve the install.
3. Push to your default branch (or merge any pull request). The **Skylos Cloud
   upload** job runs `skylos cloud` and should end with the gate for your
   default branch, for example `✓ Quality gate on main: PASSED`, and an
   `Open:` link to it.
4. Open or update a pull request to the default branch. The **Skylos Cloud PR
   upload** job uploads its scan; Skylos Cloud then lists the pull request and
   publishes its own Cloud-verified "Skylos Quality Gate" check on it (paid
   plans also get the PR comment and review brief).

For a local scan with Cloud results, run `skylos cloud` (it runs every
check and uploads; add `--gate` to exit `1` on a failed gate). It prints the
Cloud gate result for the branch, how it changed since the last run, and one
link, for example
`✓ Quality gate on main: PASSED (was FAILED on 21 Oct 14:05 UTC, abc1234)`.
Follow the link to the branch's gate and results, signing in if asked. The
manual form, `skylos . -a --gate --upload`, uploads the same scan with the
full upload output. Formatted output keeps the link on stderr so
stdout remains machine-readable; JSON also includes it in `upload.url`.
`--gate` without `--upload` stays local.

Uploads from CI use GitHub OIDC, so there is no `SKYLOS_TOKEN` secret to add.
Scans uploaded with your laptop's `skylos login` key are stored as unverified
and do not publish GitHub checks.

On paid plans, installing the GitHub App can open a pull request named
**Add Skylos Quality Gate** or **Update Skylos Quality Gate**. It replaces
`.github/workflows/skylos.yml` with Skylos Cloud's own workflow, which
publishes a Cloud-verified "Skylos Quality Gate" check on pull requests and
has no Skylos Done job. Close it to keep the workflow from this guide. If you
merge it instead, remove "Skylos Done" from the ruleset or add Done back as
described in [Done gate in CI](./done-gate.md#in-ci).

## Troubleshooting

**1. Skylos Done fails or says UNFINISHED.**
Open the check. The first failing line names the problem.

- `ModuleNotFoundError` or a failing import: the
  `Install project test dependencies` step does not install what your tests
  need. Fix that step in the same pull request that adds the workflow; edits
  to a workflow that already runs Skylos are reported as SKY-A114 later.
- `No test command`: Skylos found no pytest project. Add
  `test_command` under `[tool.skylos.done]` in `pyproject.toml` and merge
  that first, because Done reads its settings from the base branch. Then run
  `skylos cicd init --done`. For Vitest or Jest, `skylos cicd init` prints the
  settings: a command that writes JUnit XML and the `junit_xml` path.
- The test run is too slow: raise `test_budget_seconds` in
  `[tool.skylos.done]`, or run `skylos cicd init --no-done` and require only
  Skylos Quality Gate.

Skylos Done is meant to fail a later pull request that edits the workflow,
`.skylos/` or `[tool.skylos]` (SKY-A114). A person should review and merge
those; add yourself to the ruleset's bypass list to do it.

**2. Skylos Cloud upload fails on the default branch.**

- `Skylos Cloud policy unavailable` on the `Pull Skylos Cloud Policy` step
  (above it, `404 Client Error` for `/api/sync/whoami`), or
  `No verified GitHub App project is linked to owner/repo`: Skylos Cloud does
  not know this repository yet. Do step 7, or run
  `skylos cicd init --no-upload` and commit the result.
- `Invalid token` (or `Invalid API token`) from the sync step, or `The GitHub Actions identity
  token could not be verified` from the upload: the job lost
  `id-token: write`, or `--upload` was moved into a pull request job. Skylos
  Cloud accepts tokenless uploads only from default-branch pushes and from
  `pull_request_target` runs of `.github/workflows/skylos.yml`.
- `UNVERIFIED_GITHUB_SCAN` from `Skylos Cloud PR upload`: the workflow file is
  not `.github/workflows/skylos.yml`, the pull request does not target the
  default branch, or its head moved while the scan ran (the next push uploads
  again). `GITHUB_APP_PERMISSION_MISSING`: give the Skylos GitHub App
  Actions read access.

**3. A required check stays "Expected — Waiting for status to be reported".**

- The ruleset requires a check the workflow does not have, usually
  "Skylos Done" after step 2 said it was not added. Remove it from the
  ruleset, or add Done and push again.
- The workflow is not on the pull request's branch yet. Rebase or merge the
  default branch into it.
- Actions are disabled for the repository, or a first-time contributor's
  fork pull request is waiting for a maintainer to approve the run.
- The pull request is in a merge queue and the workflow predates the
  `merge_group` trigger. Regenerate it with `skylos cicd init` (see
  [Merge queues and monorepos](#merge-queues-and-monorepos)).
- You added a `paths:` filter to the workflow. GitHub never reports a
  check from a workflow a path filter skipped, so a pull request outside
  those paths waits forever. Remove the filter; see below.

Pull requests from forks get a read-only token, so the summary and inline
comments are skipped there: the `PR Review Comments` step prints one line
saying it could not comment and does not fail. The checks still run and still
block.

## Merge queues and monorepos

**Merge queues.** GitHub merges a queued pull request only when its required
checks pass on the commit the queue builds, reported from a `merge_group`
event. The generated workflow has `merge_group: types: [checks_requested]`,
and each required check runs there under the same name:

- **Skylos Quality Gate** scans the merge-group commit against the queue's
  base commit (`merge_group.base_sha`), changed lines only, with policy from
  that base commit.
- **Skylos Done** runs your tests on the merge-group commit against the same
  base.
- **Skylos risk review** checks the risks in the merge group and the
  approvals of the pull requests that added them; see
  [Merge queues](./risk-review.md#merge-queues).

Review comments, the Cloud upload and the Claude jobs do not run on merge
groups. Turn the queue on in the same ruleset (**Require merge queue**); the
required checks stay the same.

**One required check per job, no path filters.** GitHub does not report a
check from a workflow that a `paths:` filter skipped, so a required check
on a path-filtered workflow blocks every pull request outside those paths.
The generated workflow has no path filter: every job runs on every pull
request and merge group, and scopes itself to the change. With
`--scan-path apps/api`, a pull request that touches only `apps/web/` still
gets a passing **Skylos Quality Gate** with a receipt in the log and job
summary, for example:

```text
Nothing in scope: none of the 3 changed file(s) is under apps/api (e.g. apps/web/page.tsx, apps/web/layout.tsx, apps/web/api.ts). Skylos had nothing to check in this change.
```

The receipt also appears when every changed file is an image, font, media
or extensionless licence file. Markdown, RST and text files are in scope:
Skylos reads them for hidden prompt-injection text (SKY-D260). The receipt
never changes the gate's result.

## What the workflow contains

`skylos cicd init` writes one file, `.github/workflows/skylos.yml`, with
these jobs:

| Job | Runs on | Permissions |
|:---|:---|:---|
| `skylos` (Skylos Quality Gate) | pull requests, merge groups (and default-branch pushes with `--no-upload`) | read code, write PR comments |
| `done` (Skylos Done) | pull requests, checking out the PR head with full history, and merge groups, checking out the merge-group commit | read code |
| `cloud-upload` (Skylos Cloud upload) | pushes to the default branch | read code, GitHub OIDC token |
| `pr-policy` (Skylos Cloud PR policy) | `pull_request_target` for pull requests to the default branch; no checkout | GitHub OIDC token |
| `pr-scan` (Skylos Cloud PR scan) | after `pr-policy`; installs Skylos, then checks out the PR head into `pr-source` without saved credentials and scans it as data | read code |
| `pr-publish` (Skylos Cloud PR upload) | after `pr-scan`; no checkout, uploads the prepared scan | GitHub OIDC token |

The PR upload jobs are how Skylos Cloud gets pull requests: Cloud accepts a
pull request upload only from a `pull_request_target` run of
`.github/workflows/skylos.yml`, then checks the run and the PR's current head
before it shows the check. `pull_request_target` runs the workflow from the
default branch with its token, so no job that reads PR files has an OIDC token,
a write permission or a secret. `pr-scan` removes every `.skylos` folder from
the checkout, takes `[tool.skylos]` and other Skylos settings from the PR's base
commit and the Cloud policy from `pr-policy`, and keeps findings that the PR
hides with inline ignore comments (except dead code). Without `--no-upload`,
`cicd init` writes them only when the output is
`.github/workflows/skylos.yml`.

Useful options: `--no-upload`, `--done` / `--no-done`, `--default-branch`,
`--scan-path apps/api` for one project in a monorepo, `--advisory-gate` to
report without failing, and `--python-version`. See
`skylos cicd init --help`.
