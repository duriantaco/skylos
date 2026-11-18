# Get a first scan

To see findings from your laptop, run `skylos . --upload` in your repository
and follow the browser prompt. See [the laptop walkthrough](#route-4-a-first-look-from-your-laptop).
For automated checks or compliance evidence, choose one of the CI or GitHub App routes below.

| Way | Trusted? | Use it for |
|:--|:--|:--|
| Let Skylos scan it (GitHub App) | Yes | The fastest first result. Default branch only. |
| CI with the Skylos workflow (GitHub OIDC) | Yes | Every push and pull request. Checks and comments on pull requests. |
| CI with a project token marked for CI | Yes | CI systems other than GitHub Actions, or no GitHub App. |
| `skylos . --upload` or `skylos cloud` from a laptop | Report only | Review your findings immediately. |

Uploading a scan never uses credits, on any plan.

## What “report only” means

A personal CLI login can upload a scan of your working tree, including
uncommitted edits. Open the saved scan to review findings and preview the
project's policy. CI and Cloud-hosted scans establish the shared gate verdict,
publish repository checks, and provide evidence for compliance reports.

## Add a repository

**For:** creating the project that will hold a repository's scans.

**Who:** a member, admin or owner. Free allows 1 project, the Workspace plan
10, Growth 50.

After you create a workspace, **Get started** opens.

![Get started. (1) The GitHub App route. (2) The CLI and CI route.](img/cloud/first-scan-add-repository.png)

Pick one of the two routes below.

## Route 1: let Skylos scan it

**For:** a first trusted scan with no CI change.

**Who:** an owner or admin, who can also install a GitHub App on the
repository.

1. On **Get started**, select **Add a repository**. GitHub opens.
2. Install the Skylos GitHub App on your account or organization, choose
   the repositories it may read, and select **Save**.
3. GitHub brings you back. Skylos reads the default branch and runs the
   scan itself.

**What happens next:** the page changes to "Your scan is ready to review"
with **Open your scan results**. A scan Skylos runs itself is trusted and
counts for a report.

**Limits:** a Cloud scan covers the default branch only. Pull request
checks come from the Skylos workflow in CI (route 2). Very large
repositories can be over the size limit of a Cloud scan; use CI for those.

> This guide's screenshots come from a local copy of Skylos Cloud that has
> no GitHub App, so the GitHub screens are not shown.

## Route 2: scan in CI on GitHub

**For:** a scan on every push and every pull request, with the Skylos check.

**Who:** an owner or admin.

1. Open the project's **Settings**. If you have no project yet: on **Get
   started** open **Prefer the CLI or CI?**, type a **Project name**, select
   **Add the repository**, then **Set up the scan in CI**.
2. Under **Repository & connection**, check the **Repository URL**.
3. Under **Merge blocking on GitHub**, select **Connect GitHub**. On
   GitHub, pick the repository and select **Save**.
4. **Add the Skylos workflow to the default branch.** Skylos opens a pull
   request that adds `.github/workflows/skylos.yml`. Merge it. Tick **Open
   the workflow pull request automatically after connecting** to have it
   opened for you.
5. **See the Skylos check on a pull request.** Open or update any pull
   request.
6. **Require the check on the default branch.** In GitHub's branch rules,
   require the "Skylos Quality Gate" check.

The workflow signs in to Cloud with GitHub's OIDC identity. There is no
secret to store. Cloud shows these scans as verified CI uploads.

If you would rather write the workflow yourself, the page
skylos.dev/tokenless-ci has the YAML and the checks to make before the
first upload. `skylos cicd init` writes a workflow from the CLI.

## Route 3: CI with a project token

**For:** GitLab CI, Jenkins, Bitbucket Pipelines, Azure Pipelines, CircleCI
and any other CI, or GitHub without the App.

**Who:** an owner or admin creates the token.

1. Open the project's **Settings**, then **Project tokens**. From **Get
   started**, **Set up the scan in CI** goes straight there when the
   project has no repository URL: a CI project token needs none.
2. Type a **Token name**, for example `github-actions`.
3. Tick **CI project token (store it only as a CI secret)**.
4. Select **Create project token**. Copy the token now: it is shown once.
5. Store it in your CI system as the secret `SKYLOS_TOKEN`.
6. In the CI job, on a full checkout of the commit, run:

```bash
pip install skylos
skylos cloud
```

![Project tokens. (1) The name. (2) The CI box. (3) Create project token.](img/cloud/first-scan-ci-token.png)

The project's **Settings** also link a step-by-step guide for this route
("Open the step-by-step guide").

**What happens next:** the scan appears with "CI project token" next to it
and counts as trusted. A token that is already listed can be changed with
**Mark for CI** or **Remove CI mark**. **Revoke** ends a token; **Rotate
primary token now** replaces the first token of the project.

**Common problems**

- **The scan shows "Unverified upload".** The token is not marked for CI.
  Select **Mark for CI** on its row and upload again.
- **A scan from CI has a check but no pull request comment.** Comments need
  the GitHub OIDC route (route 2) and the Workspace plan.
- **Keep the CI token out of laptops.** A token marked for CI makes every
  upload with it count. `skylos login` gives each person their own login
  token instead.

## Route 4: a first look from your laptop

**For:** seeing your issues in Cloud in a few minutes.

**Who:** a member, admin or owner.

From your repository folder, run these commands.

```bash
pip install skylos
skylos . --upload
```

1. On first use, sign in through the browser. Review the workspace and project
   and choose **Save scans here**. You can create the project during this step.
   Cloud offers an existing match for the same repository and project root.
2. Open the scan link printed in your terminal to review your findings.
3. Run the command again after making changes. The CLI reuses the destination.

For the full set of checks, use `skylos cloud`. A folder without a Git remote
can save reports to an unlinked project.

## Where to see the scan

- **Home** lists every repository with the gate result of its default
  branch. Select a repository to open its Overview.
- The project's **Scans** tab lists every scan of that project.
- **Pull requests**, then **All uploads**, lists every upload in the
  workspace with who or what uploaded it: "Verified CI project token",
  "Developer connection · report only" and so on.

![Home. (1) Repositories that need action. (2) Select a repository to open it.](img/cloud/first-scan-home.png)
