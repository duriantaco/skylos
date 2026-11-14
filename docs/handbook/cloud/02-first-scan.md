# Get a first scan

A scan reaches Cloud in one of four ways. They differ in one thing that
matters: whether Cloud can trust where the scan came from.

| Way | Trusted? | Use it for |
|:--|:--|:--|
| Let Skylos scan it (GitHub App) | Yes | The fastest first result. Default branch only. |
| CI with the Skylos workflow (GitHub OIDC) | Yes | Every push and pull request. Checks and comments on pull requests. |
| CI with a project token marked for CI | Yes | CI systems other than GitHub Actions, or no GitHub App. |
| `skylos cloud` from a laptop | No: an unverified upload | A first look at your issues. |

Uploading a scan never uses credits, on any plan.

## What "unverified upload" means

A scan uploaded from a laptop comes with a personal login token. Cloud
cannot tell it from a scan of edited code, so it marks it **Unverified
upload**. You can read the scan and its issues. It does not count for:

- the gate history of the project and the trends;
- the GitHub check and pull request comments;
- compliance reports and audit evidence;
- marking issues as fixed, or being the baseline for later scans;
- the README badge.

The scan page shows **UNVERIFIED** in place of PASS or FAIL, with "Shown
here only. Run Skylos in CI to verify it."

![An unverified upload. The gate result is shown on this page only.](img/cloud/first-scan-unverified.png)

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

1. On **Get started**, open **Prefer the CLI or CI?**, type a **Project
   name** and select **Add the repository**.
2. In your repository folder run:

```bash
pip install skylos
skylos cloud
```

3. The first run opens your browser to log in. Choose the workspace and the
   project.
4. When the command finishes, select **Refresh upload status**.

![After naming the project: the two trusted routes, then the laptop commands.](img/cloud/first-scan-setup.png)

`skylos cloud` runs every check, uploads the findings (not your source
tree) and prints the gate result with a link. This is an unverified upload.

## Where to see the scan

- **Home** lists every repository with the gate result of its default
  branch. Select a repository to open its Overview.
- The project's **Scans** tab lists every scan of that project.
- **Pull requests**, then **All uploads**, lists every upload in the
  workspace with who or what uploaded it: "Verified CI project token",
  "Unverified upload" and so on.

![Home. (1) Repositories that need action. (2) Select a repository to open it.](img/cloud/first-scan-home.png)
