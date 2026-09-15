# GitLab Code Quality reports

Skylos can write findings directly to GitLab's Code Quality report format:

```bash
skylos . --danger --secrets --quality --ai-defects --gate \
  --format gitlab -o gl-code-quality-report.json
```

This adds a report to the merge request. It does not post bot comments, create
discussions, or upload to GitLab's separate SAST/vulnerability dashboard.
Skylos does not need a GitLab API token or administrator access to generate it.

## What appears in GitLab

GitLab supports Code Quality report import and merge request reports on its
Free, Premium, and Ultimate tiers. Line markers in the merge request Changes
view require Ultimate; the pipeline Code Quality tab requires Premium or
Ultimate. These are GitLab product limits, not Skylos settings.
[GitLab's feature table](https://docs.gitlab.com/ci/testing/code_quality/#features-per-tier)
describes the current tier requirements.

Run the job on the target branch as well as merge requests. GitLab needs its
target-branch report to compare existing and newly introduced findings. The
example below covers the default branch; add a corresponding branch rule if
you also target release branches. Keep the scanner version, enabled checks,
and configuration consistent between both reports.

Do not add `--diff`, `--baseline`, or `--limit` to this comparison job: GitLab
should compare full reports, not an already reduced list.

## CI starter

Copy the job from [the CI example](./examples/gitlab-code-quality.yml) into
your `.gitlab-ci.yml`. If your pipeline declares custom stages, ensure `test`
exists or change the job's stage. Existing top-level `workflow:rules` must also
allow merge request and default-branch push pipelines.

Before enabling the job, prepare a trusted scanner image outside the merge
request pipeline:

1. Build or obtain a reviewed Skylos wheel containing `--format gitlab` and
   install it, with reviewed dependencies, into `/opt/skylos` in the image.
   Do not install the target checkout or use `pip install -e .` in this job.
2. Include any Skylos native engines required for the languages you scan,
   plus Git and the shell needed by your GitLab runner.
3. Add `/opt/skylos-ci/pyproject.toml` owned by the image builder, containing
   at least `[tool.skylos]`. Put reviewed scan/gate settings there if needed.
4. Publish the image and set the operator-managed CI/CD variable
   `SKYLOS_SCANNER_IMAGE` to its full immutable digest reference
   (`registry/path@sha256:...`). The image must be available to both default
   branch and merge request jobs. Do not make this non-secret setting
   protected-only if that would hide it from merge request pipelines.

This feature must be present in that build. Do not assume an older published
Skylos version supports it or use a mutable `latest` tag. Check the installed
build's `skylos --help` for `gitlab` before publishing the image.

The job runs the installed console script through its own Python interpreter
with `-I`, from an image-owned directory. This keeps checkout modules and
`PYTHONPATH` from replacing the scanner and avoids reading checkout `addopts`.
Its explicit config file is also image-owned. The example clears inherited
job scripts, services, caches, and artifact dependencies; it does not run the
project's tests, package manager, or build scripts.

The default job enables dead-code, security, secrets, quality, and AI-defect
checks. Dependency scanning is optional: add `--sca` if the runner can reach
OSV and you want dependency findings in the same report. `--no-upload`
disables automatic Skylos Cloud report upload.

Use an isolated, unprivileged runner without deployment credentials or a
Docker socket. A scanner image pin does not make an editable MR pipeline a
mandatory security control. Repository suppressions and other supported
configuration still affect results; `--config-file` is not a blanket bypass
of all repository policy, including synced config. Centrally enforced policy
and protection of CI configuration are separate setup decisions.

## Reports and job failures

The example uses `--gate` and keeps the scan's exit status. It neither uses
`--force` nor hides failures with `allow_failure: true` or `|| true`.

- Exit `0`: the selected scan completed and passed the gate.
- Exit `1`: the scan completed but findings failed the gate.
- Exit `2`: required analysis or report creation could not complete.

`artifacts:when: always` retains a report when one was written, including
after a gate failure. It cannot create a missing report or make an incomplete
scan successful. Check the job status and logs: an empty array alone is not
evidence that all required analysis completed.

The report is a JSON array of findings with rule names, severities,
repository-relative paths, line numbers, and stable fingerprints. It is not
the full Skylos JSON result; use `--format json` separately when you need
analysis receipts and detailed metadata. Existing selectors and enabled
check families still determine which findings are eligible for export.

Secret findings omit the detected value and source snippets. Other descriptions
use Skylos's existing CI text redaction. The exporter accepts at most 20,000
input findings and writes at most 10,000 findings, 2,000 characters per
description, and 16 MiB of compact JSON. Invalid locations or exceeded limits
retain representable findings but produce diagnostics and exit `2`.

Fingerprints ignore checkout directories and line movement. Otherwise identical
occurrences are numbered in source order, so adding or removing one can change
the matching of those repeated occurrences. Renaming a file changes its identity.

## Check your integration

1. Run the job on the default branch and confirm the artifact downloads as
   JSON, not a terminal log.
2. Run it on a test merge request with a known finding and confirm GitLab
   compares it with the target-branch report.
3. Confirm a gate failure fails the job while preserving the artifact.
4. Confirm an incomplete scan fails the job instead of displaying a clean
   result. These are integration checks to perform on your GitLab instance;
   local formatter tests do not validate GitLab's hosted UI.

## Why reports first

Sonar users have requested
[GitLab inline review comments](https://community.sonarsource.com/t/gitlab-merge-request-inline-comments-decoration/106443).
This integration addresses the related need to see findings during review,
but is not that entire request: it uses GitLab report artifacts, not a
comment-posting bot. SonarQube's own
[GitLab documentation](https://docs.sonarsource.com/sonarqube-server/user-guide/issues/in-devops-platform/gitlab)
describes summary decoration without inline annotations. This is evidence of
a public workflow request, not measured demand from Skylos users.
