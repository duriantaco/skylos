# Behavior comparison integration plan

Updated: 2026-09-10.

Progress: steps 1 and 2 complete; step 3 is next. Steps 3–5 have not been executed.

## Objective

Make useful Python behavior changes visible through existing Skylos workflows,
without adding CLI flags, running target code, duplicating the static scan, or
calling every intentional change a defect.

This file is the implementation checklist. Complete and validate one numbered
step at a time. Record the result here before starting the next step.

## Starting point

- `skylos verify <path>` runs AI-code checks and compares affected Python
  functions in HEAD with the working tree. Differences and unsupported
  comparisons make otherwise passing verification incomplete (exit 2).
- Regular scans, including `-a`, and `suite` do not run behavior comparison.
- Regular `--diff` selects committed branch changes. Its baseline is different
  from the current behavior comparator's HEAD-to-working-tree baseline.
- `skylos <path> --verify` is an existing paid cloud findings-verification
  option. It is unrelated to local behavior comparison; keep its meaning.
- The model is experimental: common annotations, branches, classes and async
  code remain unsupported. A modeled difference requires intent review.
- Current reports sometimes display zero findings for checks that did not run.

## Decisions

- Initial activation belongs in existing comprehensive/change-review workflows:
  `skylos <path> -a`, `skylos <path> --diff [ref]`, and `skylos suite <path>`.
- Keep `skylos verify` as the focused comparison workflow.
- Plain scans retain their current analysis selection during this rollout.
- Share source comparison, not the entire `verify_change_path` operation.
- Behavior differences are review observations. Unsupported comparisons are
  coverage information. Neither automatically changes ordinary defect gates
  or code grades.
- Show the actual baseline, selected scope and coverage. Zero comparisons must
  never be described as preserved behavior.
- Activate regular-scan comparison only once steps 2–5 are integrated and their
  acceptance checks pass. Avoid releasing a terminal-only or JSON-only feature.

## 1. Extract the shared source-comparison service

Status: complete.

Purpose: let any workflow compare prepared source snapshots without invoking
Git, the static analyzer, a renderer, or a command's exit policy again.

Implementation:

- Add `skylos/verification/comparison.py` with `SourceSnapshot`,
  `ComparisonScope`, and `compare_source_changes(before, after, scope=...)`.
- Snapshots own read-only copies of source mappings and original-byte hashes.
  Scope carries a repository-relative file/directory, optional line range and
  excluded folders.
- Move AST indexing, helper/caller impact discovery, comparison selection,
  budgets and behavior-result aggregation from `changes.py` into that service.
- Determine Python source changes from source contents, so missing or stale
  caller-supplied hashes cannot suppress an edit. Preserve original byte hashes
  for Git evidence and environment-change detection.
- Keep `compare_working_changes(...)` as the compatible Git adapter: resolve
  scope/HEAD, load each snapshot once, handle submodule changes, call the shared
  service once, and attach Git metadata/assumptions.
- Keep overall verification status mapping in `verify_change.py`. Keep the
  explicit `verify_refactor(...)` API and its preservation obligation intact.

Acceptance checks:

- Source-only calls work with filesystem, subprocess and analyzer entry points
  blocked; snapshot inputs cannot be changed through the original mappings.
- Return-loss explanations and helper extraction still work; an edited helper
  still affects its unchanged selected caller.
- Line/exclusion scope, environment changes and deleted functions retain their
  conservative results. Existing limits remain enforced.
- Existing Git adapter output, original-byte hashes, verify CLI output and exit
  codes remain compatible. One verify invocation calls the AI analyzer once.
- New service tests and the existing behavior/verify regression suites pass.

Completion evidence (2026-09-09):

- Shared service implemented in `skylos/verification/comparison.py`; the existing
  Git adapter now loads snapshots and delegates to it. Command exit policy stays
  in `verify_change.py`.
- Added 14 source-service cases in `test/test_behavior_comparison.py` and one
  adapter integration case in `test/test_behavior_changes.py`. They cover pure
  source execution, immutable inputs, helper impact, missing/stale hashes,
  exclusions, budgets, single snapshot/service calls, and Latin-1 byte evidence.
- Fixed the excluded-file fast path: selecting an excluded unsupported file now
  respects the same scope as supported files. The regression failed before the
  fix and passes after it.
- Source service, Git discovery and refactor integration: **70 passed**.
- Engine/soundness/explanations, verify rendering/API/CLI, dependency-bump and
  ordinary CLI guardrails: **371 passed**. Total: **441 passed**.
- The real return-loss demo retains its previous behavior JSON and exit code 2.
- Independent implementation review found no blocking step-1 concerns.

## 2. Make the comparison baseline explicit

Status: complete.

Implementation:

- Introduce one resolved comparison context: repository root, immutable base
  commit, current revision/source kind, selected scopes and source snapshots.
- Local verification and comprehensive local scans compare HEAD to working
  sources. Branch review resolves the existing diff reference's merge base and
  compares it to HEAD, matching committed line/file selection.
- Dirty working files must not be mixed silently with committed branch evidence.
  Either read committed current sources for that comparison or report the
  mismatch explicitly; keep the ordinary analyzer's scope separately identified.
- Resolve from the requested target repository, including invocation from a
  different current directory. Report missing refs/shallow-history limitations
  as unavailable/incomplete comparison with an explicit reason.
- Group multiple scan paths by repository, read each pair of snapshots once,
  union overlapping selections, and deduplicate function comparisons.
- Keep `--baseline` finding fingerprints separate from source baselines.

Acceptance checks:

- The return-loss demo is detected both before commit and in a clean committed
  branch comparison. A clean local tree explicitly has no local changes.
- Cover diverged branches, dirty files, file/directory/multiple-path scopes,
  targets outside the current directory, no Git, and missing base history.
- Base/current commit identities agree with the source bytes in the report.

Completion evidence (2026-09-10):

- Added `ComparisonTarget`, immutable `ComparisonContext`, and the repository
  resolver in `skylos/verification/context.py`. Local contexts pin HEAD and load
  working sources; branch contexts pin both refs and load merge-base/HEAD blobs.
- Added `compare_target_changes(...)` for repository-grouped comparisons. The
  existing `compare_working_changes(...)` remains its local single-target
  adapter. Reports retain prior fields and add current source kind, commit
  identity and explicit context metadata.
- The source service unions scopes without repeating graph construction or
  function comparisons. Multiple explicitly selected ignored files share one
  working snapshot; existing read limits and no-follow checks remain enforced.
- Added 27 independent baseline acceptance cases, plus scope-union, snapshot
  grouping, ignored-file, submodule and compatibility regressions. Coverage
  includes refs moving during loading, dirty/index restoration, diverged and
  shallow history, multiple repositories, deleted paths, file/directory changes,
  non-Python selections and original encoded-byte hashes.
- Independent review caught and fixed the non-Python fast-path regression and
  dirty symlink scope redirection. Missing committed scopes report unavailable;
  committed file/directory transitions retain both affected selections.
- Full relevant behavior/verify/CLI and safe-output suite: **532 passed**.
  Ruff, formatting, diff and generated repo-map checks pass. Published Skylos
  **4.36.1** reports no security/secrets findings or analysis errors across all
  eight changed Python files.
- Real temporary-repository demo: uncommitted return loss is `different`; after
  commit local comparison is `unchanged`, while branch comparison is
  `different`. Restoring the return only locally leaves branch status and
  committed byte evidence unchanged.
- Regular scans, `suite`, finding baselines, grades and exit policies retain
  their existing behavior. No CLI flags were added. Step 3 remains pending.

## 3. Separate behavior review from defect policy

Status: pending; depends on step 2.

Implementation:

- Add a behavior report contract with comparison context, observations,
  equivalent/different/unsupported counts, reasons and model limitations.
- Keep differences and unknown coverage outside defect finding lists, grades,
  automatic fixes, and generic strict/gate issue counting.
- Keep the focused verify command's explicit incomplete result for differences
  and unsupported comparisons; retain existing failures from AI-code checks.
- Represent disabled, unavailable and no applicable changes as distinct report
  states; do not manufacture successful comparisons for those cases.

Acceptance checks:

- Intentional behavior edits do not silently become ordinary defect failures.
- Unsupported functions affect reported coverage, not ordinary defect counts.
- Existing real analysis errors and defect gates still fail as before; verify
  exit codes remain documented and tested.

## 4. Connect existing workflows and output formats

Status: pending; depends on steps 2 and 3; activate together with step 5.

Implementation:

- In `commands/scan_cmd.py`, call the shared service after the single static
  analyzer result is decoded. Select it through existing `-a`/`--diff` intent.
- In `core/suite.py`, reuse the same service after static analysis. Keep
  `verify_change_path` as a separate consumer, never a nested scan call.
- Attach behavior independently of generic changed-line/finding-baseline
  filters, preserving unchanged callers affected by changed helpers.
- Carry the same evidence into JSON, rich/pretty/tree/TUI, concise output,
  LLM reports, SARIF and GitHub annotations. Use review/advisory semantics in
  exports; unsupported coverage belongs in report metadata, not issue spam.
- Show concrete differences first, a compact coverage summary next, and model
  limitations. Retain complete recorded detail in machine-readable output.

Acceptance checks:

- A normal comprehensive scan and focused verify describe the same source
  change, with the same baseline and function identity.
- Analyzer and snapshot call-count tests prevent duplicate scans/reads.
- Terminal, redirected output, saved reports and CI exports preserve evidence.
- A helper edit remains visible through its unchanged caller after filtering.
- No new CLI flags; existing paid `--verify` behavior remains separate.

## 5. Make summaries describe what was actually checked

Status: pending; ship with step 4.

Implementation:

- Replace zero-for-disabled presentation with explicit checked/skipped states.
- Label grades with their scanned scope. Do not present a dead-code-only grade
  as evidence that all analysis families were checked.
- When behavior review exists, distinguish clean static checks from changes
  requiring review. Do not follow a behavior warning with an unqualified clean
  codebase message.
- Update command help and user docs with baseline, coverage and exit semantics.

Acceptance checks:

- Golden terminal/JSON examples cover disabled checks, fully clean checks,
  behavior differences, unsupported functions, no changes, and no baseline.
- The original missing-target case remains an input error before analysis.
- Run focused CLI/report/gate tests, regenerate the repo map, and check formatting.

## Later decision: enable comparison in plain scans

This is a separate rollout decision, not part of the five steps above. First
expand useful support for ordinary Python and measure real edit fixtures:
useful comparison coverage, misleading change reports, incorrect equivalence,
and added runtime. Record reproducible measurements rather than treating a high
unit-test count as evidence of broad usefulness. Add a cheap applicability check
and reuse parsed sources before considering automatic execution on every scan.

## Resume notes

- Current authorized execution: step 2.
- Step 1 is complete. Regular scans and `suite` still retain their existing
  activation behavior; their comparison integration is step 4.
- Step 1 and its I/O fixes are merged into main. Step 2 starts from updated main
  on `feat/behavior-comparison-baselines`.
- Step 2 is complete. Next is the behavior report/policy contract in step 3;
  steps 3–5 remain separate work and have not been executed.
- Preserve the user's preference for focused commits. Do not open a PR.
