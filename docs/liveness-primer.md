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
the primer's packaged corpus, `--all`, one detector invocation at a time, and
a 300-second default timeout per invocation. Serial scheduling gives each
revision the runner's resources without another detector competing for them.
It keeps the detector's automatic worker count and default grep verification;
the adapter gives both revisions the same 150-second grep budget. Timeouts
remain failures. The job has a 45-minute limit.
The primer and Actions are pinned to full commits; uv is pinned to `0.12.5`.
Python `3.13` runs the harness. Docker builder/runtime images supply the
detector interpreter, whose version and image digests appear in the report.
The primer's dependencies use its lockfile.

The current primer pin is
[`1438a928dd00cbb3b1098a9edc82480f43daabdb`](https://github.com/mcdigman/liveness_primer/tree/1438a928dd00cbb3b1098a9edc82480f43daabdb).
Its packaged corpus selects 31 projects eligible for Skylos across multiple
languages. The adapter compares dead-code findings, including unused files,
and circular dependencies. Each project's corpus settings select its security,
secrets, quality, and AI-defect analyses; the adapter ingests only selected
diagnostic buckets. A neutral Skylos configuration keeps target repository
policy from changing that selection. Dependency SCA is not selected.

Both detector revisions receive the same Go engine built from the exact PR
base. Changes to the Go engine are outside this comparison's coverage. The
workflow also applies a checked compatibility overlay to install the named
Dart extra for the full corpus; other optional extras remain excluded.

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

Use a disposable Linux environment without credentials, with Docker, Git,
Python 3.13 for the harness, Go 1.22, and uv 0.12.5 available. Managed runs build
and execute the detector revisions;
do not run an unfamiliar PR on your everyday development machine. Corpus
projects are static-analysis inputs, not projects whose tests should be run.

Clone the same primer revision:

```bash
git clone https://github.com/mcdigman/liveness_primer.git _liveness_primer
git -C _liveness_primer checkout --detach 1438a928dd00cbb3b1098a9edc82480f43daabdb
```

Replace the two revision placeholders below with the full base and head SHAs
from the report, not mutable branch names. The head is the reported merge SHA,
not necessarily the PR branch tip.

Before running the comparison, follow the workflow's **Build trusted base Go
engine** and **Enable Dart support for the full corpus** steps. Build the Go
binary from a separate checkout at the exact base SHA, then set `SKYLOS_GO_BIN`
to its absolute path. Apply the workflow's Dart overlay to the pinned primer
checkout named `_liveness_primer`. These prerequisites are required to match
CI's coverage; an unmodified primer command does not reproduce them.

```bash
uv run --project _liveness_primer --python 3.13 --locked liveness-primer run \
  --tool skylos \
  --repo https://github.com/duriantaco/skylos \
  --old BASE_SHA_FROM_REPORT \
  --new MERGE_SHA_FROM_REPORT \
  --all \
  --container \
  --output github \
  --json-out liveness-primer-report.json \
  --jobs 1 \
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
Do not replace the pin with `main`; changes to the corpus, adapter buckets or
container recipe can change what the comparison covers.
