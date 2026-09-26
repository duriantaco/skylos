# Bitbucket Pipelines and Azure Pipelines

Skylos detects Bitbucket Pipelines and Azure Pipelines by itself. When a scan
runs with `--upload`, Skylos adds the pull request number, the commit and the
repository identity to the upload's `ci` object. Skylos Cloud uses these
fields to post the `skylos-quality-gate` check on the pull request.

Posting to the pull request needs a Skylos Cloud project connected to the
repository: Project settings → Repository & connection → **Bitbucket Cloud
pull requests** or **Azure DevOps pull requests**. The cloud docs cover
tokens, required-check setup and delivery messages. Updating the CLI does not
create that connection.

## What the CLI sends

These values only help Cloud route the upload. Before writing anything, Cloud
reads the pull request again through the connected account and checks the
state, the repository and the head commit.

| `ci` field | Bitbucket Pipelines | Azure Pipelines |
|---|---|---|
| `provider` | `bitbucket_pipelines` | `azure_pipelines` |
| Detected when | `BITBUCKET_BUILD_NUMBER` or `BITBUCKET_COMMIT` is set | `TF_BUILD` is `True` |
| `pr_number` | `BITBUCKET_PR_ID` | `SYSTEM_PULLREQUEST_PULLREQUESTID` |
| `commit_sha` | `BITBUCKET_COMMIT` | `BUILD_SOURCEVERSION` (on pull request builds, the merge commit) |
| `source_commit_sha` | — | `SYSTEM_PULLREQUEST_SOURCECOMMITID` (pull request head) |
| `branch` | `BITBUCKET_BRANCH` | `SYSTEM_PULLREQUEST_SOURCEBRANCH`, else `BUILD_SOURCEBRANCH`, with `refs/heads/` removed. Tag and `refs/pull/…` refs are not sent |
| `target_branch` | `BITBUCKET_PR_DESTINATION_BRANCH` | `SYSTEM_PULLREQUEST_TARGETBRANCH`, with `refs/heads/` removed |
| Repository identity | `repo_full_name` (`BITBUCKET_REPO_FULL_NAME`), `workspace`, `repo_slug` | `collection_uri` (`SYSTEM_COLLECTIONURI`), `team_project` (`SYSTEM_TEAMPROJECT`), `repository_id` (`BUILD_REPOSITORY_ID`), `repository_uri` (`BUILD_REPOSITORY_URI`) |
| Build | `build_number` (`BITBUCKET_BUILD_NUMBER`) | `build_id` (`BUILD_BUILDID`) |

Fields left empty by the CI are not sent. On builds that are not for a pull
request (branch pushes, tags, manual runs), `pr_number`, `source_commit_sha`
and `target_branch` are missing, so Cloud does not post a pull request check.

You can still set `SKYLOS_PR_NUMBER`, `SKYLOS_COMMIT` and `SKYLOS_BRANCH`. They
take precedence over the values the CLI detects. On older Skylos versions,
which do not detect these CIs, they are the only way to pass the pull request
context, as in the `export` lines from the cloud docs.

On Azure Pipelines with a GitHub repository, `SYSTEM_PULLREQUEST_PULLREQUESTID`
is Azure's own ID, not the GitHub pull request number. Cloud posts Azure
pull request checks only for Azure Repos.

## `bitbucket-pipelines.yml`

Add `SKYLOS_TOKEN` (a Skylos project API key) as a **secured repository
variable**.

```yaml
image: python:3.12

pipelines:
  pull-requests:
    '**':
      - step:
          name: Skylos quality gate
          script:
            - pip install --no-cache-dir skylos
            - skylos . -a --upload
```

## `azure-pipelines.yml`

Add a secret pipeline variable `SKYLOS_TOKEN`. Azure does not pass secret
variables to scripts automatically, so map it with `env:`. Azure Repos ignores
`pr:` triggers in YAML. Pull request runs come from the target branch's
**Build validation** policy.

```yaml
trigger: none

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
  - script: pip install --no-cache-dir skylos
    displayName: Install Skylos
  - script: skylos . -a --upload
    displayName: Skylos quality gate
    env:
      SKYLOS_TOKEN: $(SKYLOS_TOKEN)
```

Azure Pipelines only sets the `System.PullRequest.*` variables when a branch
policy starts the build. Pipelines run by hand have no pull request context.

## Changed-line review (`--diff`)

With no value, `--diff` compares against the pull request's target branch in
these CIs, just as it uses `GITHUB_BASE_REF` on GitHub Actions. On Bitbucket it
uses `BITBUCKET_PR_DESTINATION_BRANCH`. On Azure it uses
`SYSTEM_PULLREQUEST_TARGETBRANCH` when the build is for a pull request. If the
value is missing or is not a plain branch name, it falls back to `origin/main`.
Pipelines clone shallowly, so fetch the target branch first:

```bash
# Bitbucket Pipelines
git fetch origin "+refs/heads/$BITBUCKET_PR_DESTINATION_BRANCH:refs/remotes/origin/$BITBUCKET_PR_DESTINATION_BRANCH"
skylos . -a --diff
```

```bash
# Azure Pipelines (script step; checkout: self with fetchDepth: 0 also works)
TARGET="${SYSTEM_PULLREQUEST_TARGETBRANCH#refs/heads/}"
git fetch origin "+refs/heads/$TARGET:refs/remotes/origin/$TARGET"
skylos . -a --diff
```

Diff-scoped reports cannot be uploaded. Use a separate full `skylos . -a
--upload` step for the pull request check.
