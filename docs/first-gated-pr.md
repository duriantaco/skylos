# Your First Skylos-Gated Pull Request

This takes about 8 minutes. At the end, every pull request in your repository
gets two GitHub checks, and a pull request that fails them cannot merge:

| Check | What it does |
|:---|:---|
| **Skylos Quality Gate** | Scans the lines the pull request changes for security issues, secrets, quality problems, AI-code mistakes and vulnerable dependencies. Fails when the gate fails. Posts a summary comment and inline comments. |
| **Skylos Done** | Runs your tests and checks that the change is finished: no deleted or skipped tests, no edits to Skylos settings, no added secrets. Added when Skylos can find your tests. |

No API key or repository secret is needed for either check.

## Before you start

- A GitHub repository where you can push branches. Step 5 needs admin access.
- Python 3.10 or newer, `git`, and the [GitHub CLI](https://cli.github.com)
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

Expected, for a repository with pytest tests:

```text
Workflow written to .github/workflows/skylos.yml

Pull requests
  Skylos Quality Gate  scans the changed lines; fails when the gate fails
  Skylos Done          runs your tests (pytest project found)
                       installs: python -I -m pip install -e . pytest
                       edit that step in the workflow if your tests need more
Pushes to main
  Skylos Cloud upload  full scan to Skylos Cloud with GitHub OIDC; no API key secret
                       needs the Skylos GitHub App on this repository
                       (without Cloud: rerun with --no-upload)
```

Two choices to make here:

- **Not using Skylos Cloud?** Run `skylos cicd init --no-upload`. Otherwise
  the upload job fails on your default branch until step 7 is done.
- **"Skylos Done: not added"?** Skylos found no pytest tests and no
  `test_command`. Continue without it, or see [Troubleshooting](#troubleshooting).

Check the `Install project test dependencies` step in the file. Skylos Done
runs your whole test suite with what that step installs.

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
```

`-` means skipped: the upload job runs only on pushes to your default branch.
The gate checks only the lines a pull request changes, so findings already in
your code do not fail this first pull request. On the pull request you will
also see:

- a **Skylos Analysis Summary** comment;
- the gate table and the Done receipt in each job's summary (click the check,
  then **Summary**);
- inline comments and file annotations when a changed line has a finding.

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

## 7. Optional: connect Skylos Cloud (3 to 5 minutes, needs the browser)

This sends full scans of your default branch to the Skylos Cloud dashboard.
Pull request checks do not depend on it.

1. Run `skylos login` in the repository. In the browser, sign in with GitHub
   and choose or create the project for this repository. The CLI sends the
   repository URL from `git remote`.
2. In Skylos Cloud, open the project's settings and install the **Skylos
   GitHub App** on this repository. In an organization, an owner may have to
   approve the install.
3. Push to your default branch (or merge any pull request). The **Skylos Cloud
   upload** job should print `✓ Scan uploaded` and a link to the scan.

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
  `skylos cicd init --done`.
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
- `Invalid API token` from the sync step, or `The GitHub Actions identity
  token could not be verified` from the upload: the job lost
  `id-token: write`, or `--upload` was moved into a pull request job. Skylos
  Cloud accepts tokenless uploads only from default-branch pushes and from
  its own pull request workflow.

**3. A required check stays "Expected — Waiting for status to be reported".**

- The ruleset requires a check the workflow does not have, usually
  "Skylos Done" after step 2 said it was not added. Remove it from the
  ruleset, or add Done and push again.
- The workflow is not on the pull request's branch yet. Rebase or merge the
  default branch into it.
- Actions are disabled for the repository, or a first-time contributor's
  fork pull request is waiting for a maintainer to approve the run.

Pull requests from forks get a read-only token, so the summary and inline
comments are skipped there. The checks still run and still block.

## What the workflow contains

`skylos cicd init` writes one file, `.github/workflows/skylos.yml`, with up
to three jobs:

| Job | Runs on | Permissions |
|:---|:---|:---|
| `skylos` (Skylos Quality Gate) | pull requests (and default-branch pushes with `--no-upload`) | read code, write PR comments |
| `done` (Skylos Done) | pull requests, checking out the PR head with full history | read code |
| `cloud-upload` (Skylos Cloud upload) | pushes to the default branch | read code, GitHub OIDC token |

Useful options: `--no-upload`, `--done` / `--no-done`, `--default-branch`,
`--scan-path apps/api` for one project in a monorepo, `--advisory-gate` to
report without failing, and `--python-version`. See
`skylos cicd init --help`.
