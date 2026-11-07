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

Case selection is explicit. The local agent hooks below automate a fixed smoke
scope; they do not infer all cases affected by a diff. Run relevant focused cases
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
marketing/editor media (`assets/` and `editors/vscode/media/`). Fixture assets stay
included. The archive preserves that inventoried source, rather than every byte
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

## Automatic checks in local coding agents

Install the repository-local configuration from the checkout being edited:

```bash
python scripts/install_eval_hooks.py --python /absolute/path/to/python
```

The installer merges private Codex/Claude hook definitions, preserves existing
settings and saves backups under `.skylos/evals/hooks/setup/`. It ignores the
configuration locally before writing it. Global settings and hook trust are not
changed. A checkout without the eval runner is rejected; another checkout's
passing results cannot validate it.

The hooks use the same deterministic CLI:

1. `UserPromptSubmit` arms a request without running the benchmark.
2. `PreToolUse` runs a baseline before the first potentially mutating tool. Shell
   commands are included because Python and other programs can write files.
3. `Stop` runs the matching candidate when inputs changed and returns the summary
   and receipt paths. A failed check asks the agent to continue; repeated unchanged
   failures remain visible without creating an endless continuation loop.

The default smoke scope is the SSRF positive/safe pair plus `fastapi-route-used`.
It protects those contracts only. Agent instructions still require cases/tests
appropriate to the actual change. Plain conversation with no covered tools does
not run these checks. Baselines and final results can be reused within the pending
request only when source, fixtures, grader, runtime/options and retained evidence
still match. Follow-up instructions and automatic continuation do not silently
replace a failed request's starting baseline.

Native hooks are supported by the inspected local Codex CLI 0.158.0 and Claude
Code 2.1.319. This adapter currently supports macOS/Linux (POSIX locking); the
installer rejects unsupported platforms. After setup, use each client's `/hooks` interface to inspect its
configuration. Codex requires project trust and review of the exact hook
definitions before they run; changed definitions need a new review. See
[Codex hooks](https://learn.chatgpt.com/docs/hooks) and
[Claude hooks](https://code.claude.com/docs/en/hooks).

Local command hooks do not run in Codex Work Cloud orchestration. Guidance remains
useful there, and repository CI is the independent check before code is accepted.
Hooks can also be disabled by their client; they are development automation, not
an immutable security boundary. No model call is needed by these command hooks.
