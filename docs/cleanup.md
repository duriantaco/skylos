# Evidence-based cleanup for AI-assisted code

`skylos cleanup` builds a prioritized work queue from existing quality, AI-code
and dead-code findings. Each task carries a rule, location, purpose, severity,
message, next action and original finding evidence. The default scan uses local
static analysis, preserves local review decisions and saves task history under
`.skylos/cache/cleanup.json`. Source edits, tests and model review require their
explicit options below.

Detection comes from Skylos's existing rule engines. Cleanup organizes those
findings and, for supported cases, previews an edit and checks its outcome.
It is both a detection-backed work queue and an explicit cleanup workflow.
Users see a concrete rule, file, line, explanation and action, rather than a
generic label that code is "slop". JSON preserves the original finding evidence;
`--context` shows nearby source with the reported line marked. Defects,
contextual review and optional style advice retain their different purposes.

```bash
skylos cleanup . --top 5
skylos cleanup src --format json
skylos cleanup . --all-advice
skylos cleanup . --diff origin/main --context

# Reuse a saved analyzer report without rescanning source.
skylos . --quality --ai-defects --format json -o findings.json
skylos cleanup . --from-report findings.json --format json
```

The path supplied with `--from-report` defines the root used to display paths.
Use the same root as the original scan. Saved output is explicitly labeled
`source: saved_report`; it does not verify current files.
The selected report may be outside the source root, but must be a regular
UTF-8 file up to 512 MB; symlinks and special files are rejected.

Review one task and its callers, make a focused change, run the project's
relevant checks, then scan the same scope again. Dead-code candidates require
checking entry points and dynamic use before removal. For changed-line checks
and enforced regression gates, use the regular `--diff` scan and
[`skylos done`](done-gate.md) workflows.

`cleanup --diff BASE` analyzes the full Git project, then displays tasks in
changed files, including staged, unstaged and untracked source files. It pins
the comparison commit and merge base and retains the full inventory in local
history. A finding in a changed file may predate the change: this selection
does not establish that every finding was introduced by the diff. Saved
reports cannot supply a diff baseline.

## Python test-quality checks

Quality scans and the default cleanup scan include these bounded Python checks:

| Rule | What the finding identifies | Review action |
| --- | --- | --- |
| `SKY-L040` | A literal-only assertion condition that is always true | Check an observed result or expected behavior. |
| `SKY-L041` | A collected test body containing only a docstring, `pass` or `...` | Review fixture/setup checks, then implement the behavior the test names. |
| `SKY-L042` | An adjacent repeated `assert` over proven plain values, including a builtin `len()` result | Check another property or review whether the repeated check adds evidence. |
| `SKY-L043` | A fixed positive sleep immediately followed by a positive check of a locally created `threading.Event` | Consider a bounded wait on the completion signal and assert its result. |

```bash
skylos . --quality --format concise
skylos cleanup . --context
```

The task names the test, marks its source line, explains the pattern and retains
structured evidence in CLI JSON. These are low-severity review findings. They
do not identify AI authorship or prove a production defect, and no deterministic
edit is enabled for them. Make the intended change manually, run the relevant
tests, then rescan the same scope.

The checks reuse static test collection and Done's literal/skip semantics.
Proven loop jumps and returns keep unreachable statements out of test-quality
advice. Collection metadata changes apply to the affected test while preserving
eligible sibling tests.
Helpers, skipped/xfail tests, fixtures, golden source data and uncertain wrappers
are excluded where their test role cannot be established. Empty-body review
abstains when fixture inputs, setup hooks, autouse declarations or an ancestor
`conftest.py` may supply checks. Runtime expressions and self-comparisons are
not treated as constant assertions. Repeated calls, properties, subscripts and
unknown application-return values are outside duplicate-assertion proof.
The sleep check leaves explicit waits, timing tests, expected failures and
uncertain or patched Event bindings for separate review.

Done's diff checks still separately detect removed, skipped or gutted existing
tests. These snapshot checks preserve that behavior and add review of the
selected source even without a Git baseline. Cloud displays their messages,
locations and source snippets through ordinary uploaded quality findings;
the full CLI evidence object is not a stored Cloud proof receipt.

## Review, apply and check one task

```bash
skylos cleanup . --next
skylos cleanup . --task TASK_ID                 # preview only
skylos cleanup . --task TASK_ID --apply         # apply and statically rescan
skylos cleanup . --task TASK_ID --apply --test-cmd "pytest -q test/test_orders.py"
skylos cleanup . --defer TASK_ID --reason "Review public callers first"
skylos cleanup . --restore TASK_ID
skylos cleanup . --history --format json
```

IDs printed in the human report can be used as unique prefixes. History uses
the same scan target, scanner version and project configuration; an incomplete
or differently scoped scan cannot resolve earlier work. IDs survive line-only
shifts when the syntax anchor is unchanged. A finding that disappears is marked
`not_reported`, not behavior-verified. Use `--no-state` for a stateless report.
Saved reports cannot authorize edits or state changes.

On platforms without the guarded filesystem operations needed for local
history, use `--no-state` to build the queue. Deterministic edits also require
those operations and remain unavailable there.

Deterministic edits currently support conservative Python unused-function
deletions (`SKY-U001`), allowlisted standard-library import deletions
(`SKY-U002`) and freshly revalidated f-string conversion simplifications
(`SKY-L038`). Debug f-string fields retain their expression text in the output
and require manual review. Decorators, defaults, annotations, ambiguous anchors, local or
effectful imports and unsupported rules require manual review. The patch is
bound to the exact source content; changed files must be rescanned.

An applied patch receives separate test and rescan receipts. `verified` requires
the explicitly requested tests to pass and a complete comparable rescan to
remove the target without introducing new defects or high-severity review
findings. This is evidence from those checks, not universal behavioral proof.
Passing tests must be observed through fresh JUnit results; pytest generates
these automatically. An opaque command that exits zero is insufficient.
For another runner, add `--junit-report reports/tests.xml` and configure the
authorized command to write that project-relative file. Test counts, evidence
type and changed Python line exercise are recorded separately. A Python
replacement stays `applied_unverified` when tracing shows its changed lines
were not exercised. Unknown exercise requires a completed bounded source-effect
proof before the replacement can be verified. An affirmative tracing miss is
never overridden by that model. Deletion-only edits have no replacement lines
to trace; their verification is limited to the observed tests and comparable
rescan, and the receipt records that limitation.

Apply scans enable static security and secret checks before and after the
edit, alongside quality, AI-code and dead-code checks. Dependency/network
checks are not enabled. The receipt records the checked categories. A limited
Python source-effect comparison may record modeled equivalence, differences
or unknowns; it does not execute the program or prove runtime equivalence.

Skipped tests produce `applied_unverified`; unavailable checks produce
`incomplete`. Failed checks return exit `1` and attempt rollback only while
the file still matches the applied patch, preserving intervening edits.

TypeScript/TSX edits support only one explicit unused named `import type`
binding from a same-directory local provider. A local supported tsconfig,
another module marker and a self-contained structural type provider are
required. Value/mixed imports, ambient declarations, extended or custom module
resolution, ambiguous providers and uncertain use require manual review.
Provider/configuration hashes and absent resolution alternatives are rechecked
before applying and after checks. No compiler or package script runs by default.

## Ordered local plans

```bash
skylos cleanup . --create-plan imports --plan-task FIRST_ID --plan-task SECOND_ID \
  --prerequisite "Review public callers" --acceptance-check "pytest -q"
skylos cleanup . --plan imports
skylos cleanup . --plan imports --move-task SECOND_ID --before FIRST_ID
skylos cleanup . --plan imports --complete-task FIRST_ID --note "Reviewed manually"
skylos cleanup . --plans
```

Plans retain explicitly selected anchored tasks in the chosen order and scope.
They currently require the syntax anchors supplied for Python tasks;
TypeScript import edits can be selected directly with `--task`.
Source changes make steps stale. A missing finding never completes a step;
manual completion remains unverified and requires a note for stale steps.
Prerequisites and acceptance checks are recorded text and never execute commands.

## Context and optional model review

```bash
skylos cleanup . --context --format json
skylos cleanup . --review --provider anthropic --model YOUR_MODEL
skylos cleanup . --reviews
skylos cleanup . --plan imports --promote-review REVIEW_ID
```

`--context` adds bounded Python and TypeScript/JavaScript excerpts, static
graph relationships and suggested test files while respecting scan exclusions.
It reuses Skylos's graph parser and impact queries. Source-resolved relationships
stay separate from simple-name candidates, and neither proves runtime reachability.
Suggested test selections never authorize execution. Graph coverage and budget
limits remain visible; other languages retain their scanner evidence.
Human context output marks the reported source line and shows nearby lines.
`--review` sends that context to the configured model and returns separately
labeled subjective advice with source citations. It requires the LLM extra and
provider configuration, may incur provider charges, and never authorizes edits.
It is a separate step from patch application. No model is called by default.
Completed reviews persist locally with citations, model/provider provenance
and source/context hashes, unless `--no-state` is selected. `--reviews` shows
current or stale advice. Only an explicit promotion adds current advice to a
named plan, where it stays labeled `review_advice`; it cannot create a scanner
defect, authorize an edit or supply verification evidence.
Freshness covers captured excerpts and bounded context dependencies. It does
not bind the entire Git revision; new or unexamined files can require a fresh
review.

## Queue behavior and limits

Defects and findings requiring contextual review appear in `tasks`.
Maintainability and structural recommendations appear in `advisories`.
Each queue sorts by severity, then defect/review purpose, then location and
observation ID. This ordering is deterministic and introduces no new score.
`--top` bounds each queue separately; totals remain visible in `counts`.

The shared advice policy controls optional recommendations. `--all-advice`
includes those recommendations without changing their original listing marks,
severity or gate policy. Exact mirrored findings count once; evidence variants
remain separate. JSON retains the complete source finding under `finding`.

Status `ready` means work is available, and `clear` means no visible work exists
in the recorded cleanup scope. Neither is a security verdict. `incomplete`
retains available tasks while reporting failed analysis, missing analyzers,
empty source scope or recorded AI verification gaps. JSON includes the source
analysis summary and diagnostics. Exit `0` means the queue was built; exit `2`
means incomplete analysis or invalid input. Explicit edit operations also
return exit `1` when checks fail.

Observation IDs are deterministic for identical report observations. They can
change after substantive edits, evidence or path changes; they are not the
persistent review identities used by Cloud. Missing tasks alone do not prove
that a fix worked. Language
support follows the underlying [AI checks](ai-code-verification.md) and quality
analyzers. No result identifies whether a human or an AI wrote the code.

## Research and implementation trace

Research on 9 November 2026 identified four relevant projects. Skylos's queue
is an independent implementation over its own detectors and reporting
contracts, with no upstream runtime dependency or copied implementation.

| Project | What it offers | Useful idea for Skylos |
| --- | --- | --- |
| [Desloppify](https://github.com/peteromallet/desloppify/tree/3a7735d531a96b6a226bfbdc9fd662b14195f857) | Mechanical checks, subjective review, a persistent plan and prioritized work queue | A concrete scan → choose work → fix → rescan loop |
| [paslavskyi/anti-slop](https://github.com/paslavskyi/anti-slop/tree/539ed54c1bb7efb9799cf3b88a5cde7dd30b4988) | Diff cleanup and neighboring-code review with a finding ledger | Focus review on active work while retaining earlier findings |
| [miqdadbadjuber/anti-slop](https://github.com/miqdadbadjuber/anti-slop/tree/c8a7fbc688c4a3b5cbfa72206b9e477df61c8bd0) | Agent guidance for UI, copy and comment hygiene | Optional guidance; UI style checks are outside this cleanup queue |
| [cursedcoder/deslopify](https://github.com/cursedcoder/deslopify/tree/0ea9cb284321d2669df0b21440cd487438475461) | Architecture and context-pressure heuristics with agent-readable recommendations | Explicit, navigable tasks; token savings would require separate measurement |

Desloppify's
[`build_work_queue`](https://github.com/peteromallet/desloppify/blob/3a7735d531a96b6a226bfbdc9fd662b14195f857/desloppify/engine/_work_queue/core.py)
delegates to snapshot selection and finalization; the `next` command consumes
the same query service. Its
[`ranking.py`](https://github.com/peteromallet/desloppify/blob/3a7735d531a96b6a226bfbdc9fd662b14195f857/desloppify/engine/_work_queue/ranking.py)
uses plan ordering and estimated score impact. Skylos instead separates
advice from defects and orders work by recorded severity and purpose.

Desloppify's
[`merge_issues.py`](https://github.com/peteromallet/desloppify/blob/3a7735d531a96b6a226bfbdc9fd662b14195f857/desloppify/engine/_state/merge_issues.py)
tracks reappearance and disappeared findings. Its out-of-scope verification
branch illustrates why absence needs a comparable scan scope. Skylos records
absence as `not_reported`; explicit edit receipts separately record tests,
rescan results and rollback. Cloud retains its coverage-qualified issue
resolution. Desloppify's pinned
[license](https://github.com/peteromallet/desloppify/blob/3a7735d531a96b6a226bfbdc9fd662b14195f857/LICENSE)
is OSNL v0.2, another reason to keep this implementation independent.

Anti-slop's
[`ledger.mjs`](https://github.com/paslavskyi/anti-slop/blob/539ed54c1bb7efb9799cf3b88a5cde7dd30b4988/skills/domain-review/ledger.mjs)
builds a bounded neighborhood using changed files, same-directory files and
relative import relationships. It fingerprints symbol-adjacent text and
reconciles a persistent finding ledger. Its
[`domain-review` instructions](https://github.com/paslavskyi/anti-slop/blob/539ed54c1bb7efb9799cf3b88a5cde7dd30b4988/skills/domain-review/SKILL.md)
delegate blocking versus follow-up judgment to the model. Its
[`stop hook`](https://github.com/paslavskyi/anti-slop/blob/539ed54c1bb7efb9799cf3b88a5cde7dd30b4988/hooks/stop-hook.mjs)
deduplicates using filenames and change counts. Skylos's optional model review
uses bounded source excerpts, its parsed dependency graph and separately
labeled candidate callers. Dynamic and broader domain review still require
additional evidence. Patch
verification already uses comparable scans and source content rather than
treating equal change counts as equal changes.

Existing Skylos detectors already cover duplicate code, long functions,
coupling, cohesion, broad or empty exception handlers, unfinished code and
invented APIs. New detectors should address demonstrated gaps with positive
and negative controls. A new name alone does not expand detection coverage.

| Workflow gap | Skylos implementation in this round | Remaining limit |
| --- | --- | --- |
| Focus on active changes | Pinned `cleanup --diff BASE`, full-project detection, changed-file display | No claim that every displayed finding is newly introduced |
| Review neighboring effects | Existing parsed graph, separate name candidates and suggested tests | Bounded static context; dynamic or external callers can remain unknown |
| Keep ordered work | Named plans, explicit order, prerequisites and manual completion | Prose checks do not execute; manual completion does not verify behavior |
| Retain subjective review | Cited local advice with model/provider and source freshness | Advisory judgments require human review and cannot create defects |
| Check a supported edit | Observed test evidence, comparable rescan, exact-byte rollback | Passing checks are scoped evidence; broad refactors remain manual |
| Broaden language edits | Conservative Python transforms and a narrow TypeScript type-import adapter | Most TypeScript/JavaScript and architecture changes remain review-only |
| Share outcomes | Optional bounded CLI receipt metadata in existing uploads | Client claims remain separate from trusted scan resolution and gates |

The differentiator is the connection between specific detector evidence,
explicit edits and honest check receipts. This round does not add an opaque
"slop score", infer AI authorship or claim complete subjective architecture
review.

The [five-repository exploratory evaluation](../benchmarks/cleanup/2026-11-10/README.md)
records actual scans of documented AI-assisted projects, source-reviewed
examples, false positives and coverage limits. Its selected manual sample is
not a precision/recall estimate; target source was not edited or executed.

## Corpus regression checks

Cleanup patterns use the existing [Corpus Guard](../corpus/README.md), its
[manifest](../corpus/manifest.json) and [runner](../scripts/corpus_ci.py):

```bash
python scripts/corpus_ci.py --manifest corpus/manifest.json
```

The cleanup-related additions cover two Python patterns in four cases:
blocking HTTP calls inside async functions and mutation of a shared default
argument. Each problematic case has a paired control, with expectations tied
to a rule, file and line range. The runner analyzes isolated fixture copies
without executing their code; incomplete analysis is an unscored failure.
These are focused detector regression checks, not AI-authorship labels or a
whole-repository accuracy estimate.

## Cloud integration

The Cloud Cleanup workspace loads quality, AI-code and dead-code findings from
the selected native code scan, defaulting to the latest available source.
Choose a branch/source scan and an optional comparison source independently
from an active removal PR's original workflow scan. Choose a current task, move to the next,
or review related work grouped by the existing issue, otherwise by rule and
folder. These groups organize review without proving a shared root cause.
Each task links to its source finding and existing issue history. Copy task
includes the recorded source revision, finding identifiers, message and a
bounded source excerpt for an agent.

Where an existing shared issue is available, the workspace reuses its owner,
work status and comments for outcome notes, subject to the member's role.
Record the commit or PR, checks run, and reasons for deferral there. Changing
work status does not resolve scanner findings; comparable follow-up scans
remain necessary. Findings without shared history retain their source-scan
review path.

Upload through the existing scan flow; Cloud derives the queue from those
saved findings rather than trusting a second task upload:

```bash
skylos . --quality --ai-defects --upload
```

Explicit uploads also attach up to 20 valid locally stored cleanup outcome
receipts found at the Git root and selected upload root. For a cleanup rooted
in a subdirectory, upload that same path to include its local receipts. These
contain allowlisted identifiers, relative paths, source hashes,
test/rescan status and coverage limits; test commands, logs and source excerpts
are not included. A working-tree edit remains unbound to a commit. Committing
later does not silently rebind earlier test evidence. Cloud displays these as
client claims and never uses them alone to resolve findings or pass a gate.
This optional field requires the corresponding Cloud deployment.

Progress comparison requires complete raw inventories, compatible recorded
scope/check coverage and trusted source scans with matching analyzer-config
claims. Missing configuration, revision or coverage evidence shows
`not_checked`, with unknown counts. A Done check-policy digest does not prove
analyzer configuration equivalence. Comparable absence is labeled
`not reported`; it is separate from behavioral verification and issue resolution.

| Extension | Existing Cloud integration point |
| --- | --- |
| Pure task projection | `src/lib/cleanup-tasks.ts` over existing finding rows and group IDs |
| Paginated source data | `src/lib/cleanup-task-data.ts` checks exact counts and bounds retrieval at 5,000 rows |
| Select current/next work, review groups and copy context | `src/components/CleanupTaskQueue.tsx` in the project Cleanup page |
| Shared ownership, work status and notes | Existing `AssignIssue` and `IssueComments` for the task's issue group |
| Classify tasks | Reuse `finding-types.ts`; respect stored optional-advice marks when available |
| Select source scans and compare qualified progress | `CleanupSourceControls.tsx`, `cleanup-progress.ts`, existing newness and coverage helpers |
| Display bounded CLI outcome claims | `cleanup-receipts.ts` and `CleanupReceipts.tsx` over scan JSON metadata |
| Retain constrained automated PRs | Keep eligibility in `cleanup-flow.ts` and `cleanup-prs/` independent from task visibility |

The panel retains available work from incomplete scans and clearly labels
missing coverage, partial retrieval and upload failures. It never converts
those states into an empty complete queue. An active removal PR keeps its
original source scan; the task panel independently shows its labeled selected
scan. Suppressions and existing review history are retained. No database
migration or additional model call is required.

Older stored findings may lack listing metadata; their advice remains visible
in the separate advice queue. Unknown rules require review until Cloud's
catalog is synchronized. The broader queue does not expand which findings
qualify for automatic removal PRs. These changes are source integrations and
require the normal Cloud deployment before appearing on the hosted site.

Optional bounded model review already returns explicitly labeled advice.
Broader cross-module review and additional detectors need separate evidence
and benchmarks. Cloud's durable identities and comparable scan lifecycle own
shared progress; CLI observation IDs do not authorize Cloud resolutions or
automated edits.

Positioning supported by the implementation: **“Evidence-based cleanup for
AI-assisted code: find defects, prioritize cleanup, review fixes.”** Claims of
AI authorship detection, universal architecture judgment or measured token
savings would require evidence this feature does not provide.
