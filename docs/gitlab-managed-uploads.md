# GitLab.com managed uploads

Use [the managed CI example](examples/gitlab-managed-upload.yml) when you want
Skylos Cloud to receive scans and manage merge-request comments. The separate
[native Code Quality example](gitlab-code-quality.md) needs no Cloud account,
ID token, or server integration.

This requires a Cloud deployment with the GitLab integration enabled and a
project binding configured by your operator. Updating the CLI alone does not
deploy the Cloud integration or create that binding. Self-managed GitLab is not
supported by this automatic-auth path.

## Trusted job setup

An operator must supply `SKYLOS_SCANNER_IMAGE` as a reviewed, digest-pinned image
reference, for example `registry.example.invalid/security/skylos@sha256:<digest>`.
The example is a template, not a published image. The image must already contain
the reviewed scanner at `/opt/skylos/bin/skylos`, its Python interpreter, and
operator-owned configuration at `/opt/skylos-ci/pyproject.toml`. Do not install
the scanner from the merge-request checkout. Keep the job definition and image
selection under trusted CI administration; an MR-editable include or image
variable is not a trusted policy boundary.

The job runs installed Python in isolated mode, from outside the checkout. It
does not install project dependencies, run project scripts/tests, or enable
trace/coverage execution. It disables inherited hooks, services, caches and
downloaded job artifacts. `--all` includes dependency scanning, which contacts
OSV for advisory data; it does not execute downloaded dependencies.

Only same-project merge requests and protected default-branch push pipelines
are selected. Fork merge requests, tags, schedules and other pipeline sources
are excluded. These YAML rules are scheduling guards, not server authorization.
Skylos Cloud independently verifies the signed ID token and GitLab API state.

## Short-lived authentication

GitLab creates `SKYLOS_GITLAB_ID_TOKEN` using the job's `id_tokens` declaration
with audience `skylos`. Skylos automatically selects it only when `GITLAB_CI`
is exactly `true` and `CI_SERVER_URL` is exactly `https://gitlab.com`. An explicit
`SKYLOS_TOKEN` still takes priority; leave it unset for managed OIDC uploads.
Do not put Cloud API keys or GitLab server integration credentials in this job.
Never echo the ID token or save it as an artifact. See GitLab's
[ID token authentication documentation](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

The CLI uses `X-Skylos-Auth: gitlab_oidc` and a Bearer ID token for upload and
sync requests. The token is not report metadata. CI instance, project ID/full
namespace, MR source/target projects and branches, pipeline/job, and commit
fields are routing hints, not authentication claims. Cloud verifies them against
the signed identity and API; the CLI does not decode a JWT to authorize itself.
See the [GitLab predefined variables reference](https://docs.gitlab.com/ci/variables/predefined_variables/).

## Project roots and monorepos

The example sets `SKYLOS_PROJECT_ROOT: ""` for a project bound to the repository
root. For a project bound to `apps/api`, set it to `apps/api` and scan
`"$CI_PROJECT_DIR/apps/api"`. Use a separate job for each bound subproject.
This is a repository-relative path, not an absolute runner path or a URL.

Managed requests send this normalized value as `X-Skylos-Project-Root`, including
sync and WHOAMI requests. It must agree with the uploaded scan's `project_root`.
If omitted, a known Git-relative working directory may provide the hint; the
isolated example sets it explicitly because its working directory is outside
the checkout. Cloud routes by verified GitLab project ID and bound root and
rejects missing ambiguous roots or mismatches.

## Reports, completeness and limits

The managed example uses `--upload --format json` and saves `skylos-report.json`
as a plain job artifact. This retains repository-level policy findings, such
as a missing pre-commit policy, which do not have a source-file location.
Cloud stores these findings without inventing inline MR comment positions.
No pre-commit or type-checker setup is required merely to upload a report.

Use the separate native Code Quality job when you also need GitLab's native
artifact UI. `--format gitlab` alone does not auto-upload and rejects findings
without representable file locations. It can be combined with `--upload` when
all findings have valid source locations. The artifact is collected even when
the scan or gate fails. Local incomplete analysis remains exit code 2, and
`--force` cannot turn incomplete analysis into
a clean result. Incomplete native GitLab reports retain detected findings but
are not uploaded by that CLI output path.

After upload, stderr separately confirms that the scan was saved and reports
GitLab comment counts or a skip/failure reason. A protected push has no merge
request, so `not_merge_request` is an expected non-failing skip. Missing or
invalid delivery receipts, partial/failed delivery, unexpected skips such as a
stale diff, and `plan_required` return exit code 2 even with `--force`. A plan
failure includes an upgrade/setup message. The saved scan ID and quality-gate
result remain in the API response; the local artifact is retained. Partial
delivery never triggers automatic scan re-upload. Check the Cloud integration
status before deciding whether a later pipeline run is appropriate.

Managed HTTP POSTs use a 300-second timeout and are not automatically retried.
A timeout or server error can occur after the scan was saved or comments were
published: the CLI reports an unknown delivery outcome and exits 2. Check Cloud
before starting a fresh pipeline. The CLI does not switch upload protocols after
an ambiguous timeout/server failure. Managed uploads never use the lossy compact
compatibility fallback. If Cloud does not support the required artifact-upload
endpoint, the local report is retained and the CLI asks you to upgrade Cloud.

Managed uploads also carry a `gitlab_scan_receipt` with `complete` and
`full_scan` booleans. Completion is derived from analyzer errors and SCA,
language and grep-verification status, not from `--force` or a supplied JSON
receipt. A full scan requires the directory's default supported scope and all
scan categories. Baselines, diffs, selected rules, display filters, custom
exclusions/suppressions, confidence changes, unresolved dependency versions and
missing completion evidence conservatively prevent full-scan status. Cloud may
retain such reports without resolving previous comments merely because a
finding is absent. Default scanner exclusions and unsupported file formats
remain outside supported coverage; `full_scan` does not mean universal analysis.

An authenticated report identifies the job that submitted it. It does **not**
attest that an unmodified scanner analyzed the intended source, and this feature
does not automatically enforce an operator's CI policy. Keep scanner image,
configuration and job provenance trusted before relying on reported results.
