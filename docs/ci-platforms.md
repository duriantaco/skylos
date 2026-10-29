# Skylos on any CI

Skylos is a command-line tool, so it runs on any CI. A pull request gate is one
command:

```bash
skylos . -a --gate --diff
```

`--gate` makes the command exit non-zero when the gate fails, which fails the
CI step. `--diff` limits findings to the lines the pull request changes.

## Set it up

```bash
pip install skylos
skylos cicd init
```

`skylos cicd init` finds the CI your repository uses and sets up the gate for it:

| Repository has | `skylos cicd init` sets up |
|:---|:---|
| `.github/workflows/` | GitHub Actions: writes `.github/workflows/skylos.yml` |
| `.gitlab-ci.yml` | GitLab CI |
| `Jenkinsfile` | Jenkins |
| `bitbucket-pipelines.yml` | Bitbucket Pipelines |
| `azure-pipelines.yml` | Azure Pipelines |
| `.circleci/config.yml` | CircleCI |
| `.buildkite/`, `.travis.yml`, `.drone.yml`, `.woodpecker.yml`, `.teamcity/` | prints the commands to add |
| no CI file | the CI of origin's host (github.com, gitlab.com, bitbucket.org, dev.azure.com), else GitHub Actions |

If the CI file does not exist yet, Skylos writes it. If it exists, Skylos does
not edit it: it prints the block to add and where it goes. Pick a CI with
`--ci github|gitlab|jenkins|bitbucket|azure|circleci|other`.

A repository with `.github/workflows/` gets the GitHub workflow, as before.
Skylos also names any other CI file it found and the `--ci` command for it.
Without `.github/workflows/`, two or more of the GitLab, Jenkins, Bitbucket,
Azure and CircleCI files and no `--ci` make Skylos write nothing and ask you
to pick.

Then:

1. Commit the file, or the block it printed, on a branch and open a pull request.
2. Check that the Skylos gate runs on it.
3. Make that check required before merging, in your code host's branch
   protection.

`skylos doctor` shows which CI files run Skylos. Run in CI, it also shows which
branch `--diff` compares with.

## Which branch `--diff` compares with

With no value, `--diff` compares with the pull request's target branch:

| CI | Target branch from | Pull request build when |
|:---|:---|:---|
| GitHub Actions | `GITHUB_BASE_REF` | `GITHUB_BASE_REF` is set |
| GitLab CI | `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` | `GITLAB_CI=true` and the variable is set |
| Jenkins | `CHANGE_TARGET` | `CHANGE_ID` is set (Multibranch Pipeline) in a Jenkins build: `JENKINS_URL`, `JENKINS_HOME` or a `jenkins-` `BUILD_TAG` |
| Bitbucket Pipelines | `BITBUCKET_PR_DESTINATION_BRANCH` | the variable is set |
| Azure Pipelines | `SYSTEM_PULLREQUEST_TARGETBRANCH` | `SYSTEM_PULLREQUEST_PULLREQUESTID` is set |
| Buildkite | `BUILDKITE_PULL_REQUEST_BASE_BRANCH` | `BUILDKITE_PULL_REQUEST` is a number |
| Travis CI | `TRAVIS_BRANCH` | `TRAVIS_PULL_REQUEST` is a number |
| Drone | `DRONE_TARGET_BRANCH` | `DRONE_BUILD_EVENT=pull_request` |
| Woodpecker | `CI_COMMIT_TARGET_BRANCH` | `CI=woodpecker` and `CI_PIPELINE_EVENT=pull_request` |

Each variable counts only inside its own CI and only on a pull request build.
Anywhere else, `--diff` compares with `origin/main`. On CircleCI, TeamCity and
other CIs, pass the branch: `--diff origin/develop`.

The target branch has to be in the clone. Many CIs clone only the pull request
branch, or only recent history. When it is missing, Skylos stops with exit 2
and prints the command to run first, for example:

```text
On Jenkins, run this before the scan: git fetch --no-tags origin +refs/heads/develop:refs/remotes/origin/develop
```

In a shallow clone that command includes `--unshallow`.

## GitHub Actions

See [Your first Skylos-gated pull request](./first-gated-pr.md). The workflow
also posts pull request comments, adds annotations and uploads to Skylos Cloud.

## GitLab CI

The `skylos` job runs in merge request pipelines with `GIT_DEPTH: "0"`, fetches
the target branch and runs the gate. If your `.gitlab-ci.yml` declares
`stages:`, it needs a `test` stage. For the merge request Code Quality widget,
add the separate job in [GitLab Code Quality](./gitlab-code-quality.md).

## Jenkins

The `Skylos` stage runs only in pull request builds (`when { changeRequest() }`)
of a Multibranch Pipeline job. It installs Skylos in a virtualenv under
`$WORKSPACE_TMP`, outside the checkout, so the install is not part of the diff.
The agent needs `python3` 3.11 or newer.

The Jenkins and "other CI" commands install plain `skylos`. Dart support,
`skylos[dart]`, is built from source and needs a C compiler, which many Jenkins
agents do not have. To scan Dart files, install `skylos[dart]` on an agent that
has one; without it, Skylos reports the Dart files as not analyzed and the gate
stops with exit 2. The GitLab, Bitbucket, CircleCI and Azure templates run on
images with a compiler and install `skylos[dart]`.

The stage fetches the target branch only when the clone does not have it. If
that fetch fails on a private repository, the shell step has no Git
credentials. Use the "merge with the target branch" pull request strategy,
which fetches it during checkout, or give the step credentials.

Jenkins does not own the pull request; your code host does. Make the Jenkins
status check required there.

## Bitbucket Pipelines

The step runs in pull request pipelines with `clone: depth: full`. For Skylos
Cloud pull request checks, see [Bitbucket and Azure Pipelines](./bitbucket-azure-pipelines.md).

## Azure Pipelines

The pipeline checks out with `fetchDepth: 0`, which brings in the target branch.
It does not run its own `git fetch`, because Azure does not keep checkout
credentials for later steps. For Azure Repos, add the pipeline as the target
branch's Build validation policy. For Skylos Cloud pull request checks, see
[Bitbucket and Azure Pipelines](./bitbucket-azure-pipelines.md).

## CircleCI

The job skips builds without an open pull request. CircleCI does not expose the
pull request's target branch, so the job compares with your default branch
(origin's HEAD, else `main`). Change the branch in the file if pull requests go
elsewhere.

## Other CIs

`skylos cicd init --ci other` prints the three commands to add to a pull
request build step:

```bash
python -I -m pip install skylos
git fetch --no-tags origin "+refs/heads/main:refs/remotes/origin/main"
skylos . --danger --quality --ai-defects --secrets --sca --baseline --gate --diff origin/main
```

## Skylos Cloud

`skylos cicd init` adds Cloud uploads only for GitHub Actions, through GitHub
OIDC: default-branch pushes run `skylos cloud`, and pull requests to the
default branch upload through `pull_request_target` jobs that never give PR
files a credential (see
[what the workflow contains](./first-gated-pr.md#what-the-workflow-contains)).
On other CIs, add one step on your default
branch that runs `skylos cloud` with a `SKYLOS_TOKEN` secret (a CI project
token), as shown in [Bitbucket and Azure Pipelines](./bitbucket-azure-pipelines.md).
For GitLab, see [GitLab managed uploads](./gitlab-managed-uploads.md).
Diff-scoped reports cannot be uploaded.

## Options that apply to every CI

`--scan-path`, `--analysis`, `--no-baseline`, `--python-version` and
`--default-branch`. `--llm`, `--model`, `--defend`, `--risk-review`,
`--claude-security`, `--advisory-gate`, `--done`/`--no-done`, `--triggers` and
`--force` are GitHub Actions only. Other CIs say which of them were not used.

`--llm` adds a "Skylos Agent Review (LLM)" step on pull requests. The gate job
then installs `skylos[llm]` and passes the model provider's key from a
repository secret of the same name: `OPENAI_API_KEY` for the default
`gpt-4.1`, `ANTHROPIC_API_KEY` for Claude models, `GEMINI_API_KEY` for
`gemini/` models (`--model` picks the model). `ollama/` models need no secret.
