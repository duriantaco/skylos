# Scoped before/after evals

These checks evaluate Skylos against selected, reviewed security or dead-code
cases. They reuse the existing benchmark manifests and graders. Run them from the
source checkout being changed, using a Python environment with its test
dependencies installed. The entry point is `python scripts/eval_check.py`.

## Before coding

Choose cases relevant to the planned change, including real findings and safe
controls. For example:

```bash
python scripts/eval_check.py baseline \
  --suite security \
  --case ssrf-tainted-host \
  --case ssrf-fixed-host-path \
  --output .skylos/evals/runs/ssrf-before
```

This runs the selected cases and records the actual starting source, including
local edits. An existing failure returns a nonzero exit code and remains visible
in the saved results. Investigate it rather than assuming the starting point is
healthy. Output directories must be new; choose another name for a later run.

## After coding

```bash
python scripts/eval_check.py candidate \
  --baseline .skylos/evals/runs/ssrf-before \
  --output .skylos/evals/runs/ssrf-after
```

The candidate inherits the baseline's suite and selected cases, runs the changed
source and prints a comparison. Fixture, expectation, harness, options or
environment mismatches block a comparable result. A source change during a run
also prevents a clean result. If the evaluation definitions change, obtain both
source revisions' results under the same reviewed definitions; do not treat a new
dataset as an improvement to the scanner.

To print the saved comparison again without rerunning analysis:

```bash
python scripts/eval_check.py compare \
  --baseline .skylos/evals/runs/ssrf-before \
  --candidate .skylos/evals/runs/ssrf-after
```

Dead-code cases use a separate pair, for example before the change:

```bash
python scripts/eval_check.py baseline \
  --suite dead-code \
  --case fastapi-route-used \
  --output .skylos/evals/runs/fastapi-before
```

After the change, use `candidate --baseline .skylos/evals/runs/fastapi-before`
with a new `--output .skylos/evals/runs/fastapi-after` directory.

## Reading the result

The terminal summary distinguishes new, existing and resolved failures,
incomplete cases, unresolved findings and execution time. It also reports absolute
candidate health. An unchanged existing failure can mean no new regression while
the candidate still fails its required checks. Unexpected output remains visible
for review; an unresolved finding is not automatically a false positive.

Missing, skipped, malformed or incomplete required analysis cannot earn an overall
pass. Both source versions can share a bug, so a clean comparison only supports the
selected contracts. Add independently reviewed capability cases and run broader
required validation before accepting a change. Agents should expand scope when
their actual diff touches more than initially planned.

Case selection is explicit. The push check below automates a fixed smoke
scope; it does not infer all cases affected by a diff. Run relevant focused cases
during development and broader checks at completion; the full benchmark need not
run twice after every small edit.

## Files and evidence

Versioned cases and expected answers remain in `benchmarks/security/`,
`benchmarks/dead_code/` and their manifests; assertions and runner tests live in
`test/`. The entry point delegates to `skylos/benchmarks/` implementation code.
Expected answers are preserved constraints, not golden files regenerated from
the current scanner's output.

Local run directories contain a receipt (`receipt.json`), the frozen dataset, full
native JSON results, normalized case reports, stdout/stderr, timing and a source
archive. Checksums bind the saved artifacts; the receipt includes source and
input/environment identities. `.skylos/evals/runs/` is already ignored by Git.
These artifacts contain source and findings and stay local by default. The public
runner does not read or upload the private maintainer regression index.

The source inventory covers tracked/untracked inputs and effective ignored native
engines. It excludes private instructions, caches, generated reports and root
marketing/editor media (`assets/` and `editors/vscode/media/`). The non-analyzer
`skylos-demo` submodule is represented by its pinned Git revision; its generated
application and example checkouts are excluded. Fixture assets and runtime engine
submodules stay included. The archive preserves that inventoried source, rather than every byte
of an entire Git checkout. The receipt's SHA256 sidecar detects accidental edits;
it is not authentication of externally supplied evidence.

The initial workflow uses isolated fixture configuration and static, offline
analysis; it does not execute the fixture applications or make paid model calls.
External `SKYLOS_*` environment overrides are cleared for the worker; fixed worker
settings and fixture scan settings are recorded. Security labels initially check
rule presence/absence. Multiple distinct findings for one positive rule remain
unresolved pending finding-level review. All normalized finding changes remain in
`comparison.json`; a contract pass alone does not establish exhaustive precision.
Live-model explanation quality and external holdout assessment are separate work.

## CI

`.github/workflows/evals.yml` runs the workflow/capture tests and selected security
and FastAPI contracts against the checked-out head. Its `baseline` invocations are
absolute head checks, not a comparison against the PR base. The workflow prints
summaries and writes temporary runner-local evidence; it uploads no source
archives or private directories. Artifact publishing and retention are future
integration work.

Making this job required needs repository branch-protection configuration. Adding
the workflow does not configure that policy or establish that hosted CI passed.

## Automatic checks before Git push

Automatic blocking belongs at publication boundaries. Agents can edit files and
finish intermediate turns without a repository-wide eval gate. The former
request/edit/Stop callbacks are disabled; `scripts/eval_hook.py` remains a harmless
compatibility entry point for clients that cached an old setting.

Install the local Git check from the checkout containing this tooling:

```bash
python scripts/install_eval_push.py --python /absolute/path/to/python
```

The installer preserves an existing `pre-push` hook, including its original
arguments and update list. It pins an immutable copy of the small evaluation
harness and its reviewed fixtures under `.skylos/evals/pre-push/`. Global agent
settings are not changed. The old `install_eval_hooks.py` name delegates to this
push-only setup; it no longer installs agent lifecycle callbacks.

The resulting flow is:

1. Develop and run relevant focused tests as needed.
2. On `git push`, inspect the exact local commit IDs at the outgoing ref tips.
3. Evaluate each distinct tip in an isolated snapshot, using the pinned grader and
   expected answers. Unrelated uncommitted edits and other agents' working files
   do not enter this check.
4. Stop the push if the selected checks fail or required analysis is incomplete.
5. Run repository CI after publication and require the appropriate CI checks
   before merging.

The initial automatic scope remains three smoke cases: the SSRF positive/safe
pair and FastAPI dead-code control. It is not a complete regression suite or a
precision/recall estimate. Existing Git guards remain in force. Local hooks can
be bypassed; required CI is the independent acceptance gate.
Intermediate historical commits in a pushed range are not each checked by this
local gate.

## Who writes expected answers?

Agents and maintainers write meaningful fixtures and assertions from the requested
behavior, existing rule contracts and source evidence. A reviewer checks the
oracle. A new behavior fix should have a reproducing regression case and a safe
control where appropriate. Ambiguous product behavior needs a maintainer decision.
Do not generate a golden answer from the changed scanner's output.

The push smoke cases and their expected results are pinned separately from the
candidate analyzer. Changing a candidate commit's fixture labels cannot silently
make that candidate pass this installed suite. Updating the pinned smoke suite is
an explicit, reviewed setup change. New repository tests still run in CI; the
three-case local suite does not automatically cover every new behavior.

Git's [pre-push interface](https://git-scm.com/docs/githooks#_pre_push) and GitHub's
[required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)
support this conventional development/push/CI arrangement. There is no universal
industry mandate to block every agent edit or every agent turn.
