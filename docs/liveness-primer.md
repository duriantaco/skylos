# Real-project regression testing with liveness_primer

[liveness_primer](https://github.com/mcdigman/liveness_primer), created and
maintained by [Matthew Digman](https://github.com/mcdigman), is Skylos's official
real-project regression testing tool. Its source, adapters, and pinned project
corpus live in Matthew's repository. Skylos keeps the CI integration here.

It answers a specific question: **what changes for real projects if we merge
this PR?** It does not decide whether every finding is correct.

## What CI runs

The [Analyzer Blast Radius workflow](../.github/workflows/liveness-primer.yml)
runs when a PR is opened, updated with new commits, reopened, or marked ready
for review. There are no changed-path or draft filters: docs-only and draft
PRs get the same comparison. Fork PRs may need maintainer approval to run, and
GitHub cannot run this `pull_request` workflow while merge conflicts remain.
See [GitHub's event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request).

The primer builds two Skylos revisions in separate managed environments:

- Base: the PR's exact base commit (`pull_request.base.sha`).
- Head: GitHub's synthetic merge commit (`github.sha`), so the comparison
  includes the result of merging the PR into its base branch, including forks.

Both revisions scan the same commit-pinned corpus projects. The workflow uses
the primer's packaged corpus, `--all`, two concurrent detector processes, and
a 300-second default timeout per invocation. The job has a 45-minute limit.
The primer and Actions are pinned to full commits; uv is pinned to `0.12.5`,
Python to the `3.13` series, and the primer's dependencies use its lockfile.

The current primer pin is
[`d6f3118a2cfc465426500eab449005fe56845c58`](https://github.com/mcdigman/liveness_primer/tree/d6f3118a2cfc465426500eab449005fe56845c58).
It selects 15 Python projects for Skylos. Its adapter compares unused
functions, imports, classes, variables, and parameters. **File-level findings
(`SKY-E002` / `SKY-E003`) are not included at this pin.** This job does not
opt into security, secrets, quality, or AI-defect analyses, and is not a
cross-language benchmark.

## Read a PR report

1. Open the PR's **Analyzer Blast Radius** run and read its summary.
2. Check that both revisions completed. A crash, timeout, or unusable detector
   output fails the job; it is not a clean comparison.
3. Review added, dropped, and changed findings against the intent of the PR.
   Added findings can be useful coverage or false positives. Dropped findings
   can be fixed false positives or missed detections. Neither direction is
   automatically an improvement.
4. Download the `liveness-primer-report` artifact for
   `liveness-primer-report.md` and the complete `liveness-primer-report.json`.
   The Markdown display can be truncated; use JSON for the full comparison.
   Artifacts are retained for 14 days, so save evidence needed for later work.

Finding changes are advisory: the workflow does not use `--fail-on` gates.
It preserves the primer's nonzero exit status and requires a nonempty JSON
report. Available evidence is uploaded even if the comparison fails. A green
check means the comparison completed, not that someone has approved its
findings or proved the PR regression-free.

If a change looks wrong, inspect the pinned source and turn the confirmed bug
into a regression test or [Corpus Guard fixture](../corpus/README.md). Do not
accept or reject a PR solely because its total finding count went down or up.

## Reproduce a comparison

Use a disposable Linux environment without credentials, with Git, Python 3.13,
and uv 0.12.5 available. Managed runs build and execute the detector revisions;
do not run an unfamiliar PR on your everyday development machine. Corpus
projects are static-analysis inputs, not projects whose tests should be run.

Clone the same primer revision:

```bash
git clone https://github.com/mcdigman/liveness_primer.git liveness-primer-check
git -C liveness-primer-check checkout --detach d6f3118a2cfc465426500eab449005fe56845c58
```

Replace the two revision placeholders below with the full base and head SHAs
from the report, not mutable branch names. The head is the reported merge SHA,
not necessarily the PR branch tip.

```bash
uv run --project liveness-primer-check --python 3.13 --locked liveness-primer run \
  --tool skylos \
  --repo https://github.com/duriantaco/skylos \
  --old BASE_SHA_FROM_REPORT \
  --new MERGE_SHA_FROM_REPORT \
  --all \
  --output github \
  --json-out liveness-primer-report.json \
  --jobs 2 \
  --timeout 300
```

The pinned primer requires enforced network isolation for managed runs on
Linux and fails if it cannot establish it. CI uses a fresh GitHub-hosted
runner, read-only repository permission, no passed secrets, no persisted
checkout credentials, and no shared uv cache. Network isolation is not a
complete filesystem sandbox; do not add credentials or use a persistent
self-hosted runner for this job.

The report records dependency versions and environment differences. A later
run may resolve different detector dependencies even with the same source
commits, so retain the original JSON when investigating a discrepancy.

## Benchmarks and maintenance

Primer reports can support change reviews and supply cases for the public
[skylos-demo](https://github.com/duriantaco/skylos-demo) benchmarks. They do not
supply ground-truth labels or precision/recall scores. Public accuracy claims
still need labeled cases, pinned inputs, and the methodology in
[BENCHMARK.md](../BENCHMARK.md). Corpus Guard and the existing benchmark gates
remain in place.

Keep corpus and adapter improvements upstream with Matthew, rather than
copying the primer into Skylos. Propose threshold changes with examples and
review them together; this integration does not impose new finding-count
thresholds or transfer repository ownership.

Update the primer pin in a separate reviewed change, run a fresh comparison,
and inspect corpus, adapter, and report-schema changes before accepting it.
Do not replace the pin with `main`. For example, upstream v0.1.1 adds file-level
findings, so adopting it changes what this CI report covers.
