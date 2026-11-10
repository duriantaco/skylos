# Exploratory cleanup evaluation on AI-assisted repositories

On 10 November 2026, Skylos cleanup was run against five pinned public projects
whose owners document AI-assisted development. This evaluates concrete cleanup
findings and the workflow, not AI authorship. AI assistance does not establish
poor code quality. The cohort includes hobby applications, an archived project
and an AI-origin tool with subsequent human maintenance; it is not representative
of all AI-assisted software and has no matched human-only control group.

The detector baseline is Skylos source revision
`744e3fd293afaa554a226f5225ee6df4764aa674` (version string `5.4.0`).
The source revision matters: this development cleanup workflow is not identified
by the package version alone. Original findings and source snapshots were
retained before the task-identity fix described below.

## What cleanup does

`skylos cleanup PATH` detects and presents a review queue. It does not edit
source. `--task ID` requests a preview for a supported case; `--apply` explicitly
authorizes that edit. Tests require a separate `--test-cmd` authorization.
Findings requiring review and optional maintainability advice have different
purposes. A finding count is not a bug count or a count of safe removals.

## Method

- Fetch each exact commit in [manifest.json](manifest.json) as a GitHub archive.
  Check archive paths and byte/file budgets; reject links and special files.
  Do not install dependencies or run target scripts, package hooks or tests.
- Run the actual cleanup command twice in separate fresh scanner processes:

  ```bash
  skylos cleanup PATH --no-state --top 100000 --format json
  skylos cleanup PATH --no-state --top 100000 --format json --all-advice
  ```

- Use the default cleanup scanner profile with standardized offline
  configuration: a harness-owned TOML containing `[tool.skylos]`, a harness-owned
  synced `config.yaml` containing `{}`, `SKYLOS_CUSTOM_RULES=[]`, and
  `SKYLOS_JOBS=1`. Set `SKYLOS_CONFIG_FILE` and `SKYLOS_SYNCED_POLICY_FILE` to
  those absolute files. Remove inherited policy-base, credentials, provider and
  custom-rule settings. No project/ancestor/user YAML rule packs were present.
  These controls replace repository-specific policy; these are not measurements
  of each author's preferred Skylos configuration. Timings are serial local
  observations, not comparative speed claims.
- Run from the trusted scanner checkout, keeping target files out of Python's
  executable import path. Audit guards reject target-file code execution,
  network calls and subprocesses other than read-only Git. No guard was
  triggered in any of the ten scans. No model calls or uploads were made.
- Save full analyzer and queue JSON, errors, coverage, elapsed time and hashes.
  Count raw findings with the canonical finding iterator rather than summing
  mirrored arrays. Compare every original file hash and check additions:
  all **444 snapshot files remained identical**, with **no files added**.
- Archive snapshots contain no Git history, so diff-dependent A101/A104 checks
  were not evaluated. Dependency/registry checks, security/secrets scans,
  external-library API validation and subjective model review were outside
  this default-profile evaluation. Static local API coverage is recorded;
  zero API findings does not establish external API correctness.

Reproduction requires the pinned scanner source and its normal analysis
dependencies. Use the archive URLs in the manifest, the explicit policy files
and environment above, and the two commands for each snapshot. Inspect
`analysis_errors`, `analysis_summary.ai_verification` and queue `status`; an
incomplete result is not a successful zero-finding result.

## Whole-repository observations

| Repository and pinned snapshot | Analyzed files / LOC | Default review candidates | Default advisories | Additional optional advice | Queue status |
| --- | ---: | ---: | ---: | ---: | --- |
| [claude-game](https://github.com/mdkess/claude-game/tree/8b02fe3de81755536d8cb7376fc47db093a8ae00) | 71 / 7,363 | 188 | 3 | 50 | Incomplete: unsupported shell API verification |
| [audio-rag](https://github.com/Teygeta/audio-rag/tree/9c0d23cf414e538167f8880963f120b1b80db578) | 14 / 823 | 7 | 8 | 19 | Ready |
| [files-to-prompt](https://github.com/simonw/files-to-prompt/tree/1b234ff6dccb2ca3e56b5c256696558fb85306dc) | 4 / 670 | 1 | 4 | 12 | Ready |
| [video-gif-creator](https://github.com/jagadish-k/video-gif-creator/tree/d7a3000eeb4bc25a68dc143755cd5f3f320be4e0) | 20 / 1,416 | 6 | 3 | 19 | Ready |
| [coding-interview-reviewer](https://github.com/balbonits/coding-interview-reviewer/tree/9b5689881e324f0c8d6c07423ba86bc5b3782430) | 180 / 14,233 | 161 | 52 | 167 | Incomplete: dynamic import/API limits and unsupported shell verification |

All five scans retained findings and reported zero parser/worker analysis errors.
Incomplete API coverage is a separate condition. Default runtimes ranged from
0.88 to 5.45 seconds under the standardized serial configuration.

There were 363 default review candidates, 70 default advisories and 267
additional optional advisories. No finding was classified as a concrete
`defect` by this default profile in this cohort. Counts include overlapping
file/symbol/export observations and intentional source assets; they must not
be presented as 700 independent defects. The underlying data and rule counts
are in [results.json](results.json).

## Manual source review

We inspected every default task for the two Python projects and the GIF utility,
plus deliberately selected rule/scope samples from the larger game and Next.js
app: **41 default tasks and 16 advisory observations**. This was not a random
sample, a complete audit, an independent recall measurement or a precision
estimate. Reviewers inspected source and callers; they did not execute target
code or prove runtime behavior.

| Source-review classification | Default-task sample | Advisory sample |
| --- | ---: | ---: |
| Supported narrow finding or review opportunity | 25 | 8 |
| Intentional / context does not justify a change | 10 | 5 |
| False positive for the implied removal/liveness claim | 5 | 0 |
| Uncertain | 1 | 3 |

“Supported” includes maintenance opportunities and measured structure; it does
not mean a demonstrated runtime bug. Several supported file/symbol findings
refer to the same cleanup opportunity. Every reviewed observation, scope,
verdict, reason and source reference is retained in
[reviewed-findings.json](reviewed-findings.json).

Concrete useful examples:

- Audio-RAG has unused `os` and `json` imports in
  [transcription_pipeline/utils.py](https://github.com/Teygeta/audio-rag/blob/9c0d23cf414e538167f8880963f120b1b80db578/transcription_pipeline/utils.py#L1).
  Other unused bindings need their underlying calls preserved; removing an
  assignment does not authorize deleting a database-building side effect.
- The GIF app's
  [GifGenerator component](https://github.com/jagadish-k/video-gif-creator/blob/d7a3000eeb4bc25a68dc143755cd5f3f320be4e0/src/components/GifGenerator.tsx#L14)
  and `cn` helper have no in-repository consumers; the live Editor has its own
  generation controls. The file and symbol findings overlap. `estimateGifSize`
  is used internally, so its finding concerns public export surface, not
  deletion of the implementation.
- The game has empty catches worth reviewing in object-destruction paths.
  Review scope matters: the sampled ObjectPool implementation is itself unused,
  so its warning is not evidence of a reachable production failure.
- The Next.js app has an unused `CaptureType` import, an unused `listAiCourses`
  wrapper and runtime-validation review opportunities. These are source-backed
  candidates, not executed proof of failing behavior.
- Files-to-prompt's output file is manually closed on the normal path. An
  exception before that close has no surrounding `finally`/context manager;
  the resource finding warrants that narrower review, rather than a claim
  that the ordinary successful path leaks its handle.

Concrete noise and limits:

- Audio-RAG uses `chromadb` indirectly through `langchain_chroma.Chroma` and
  checks it dynamically during setup. Absence of a direct `chromadb` import
  does not establish an unused dependency. `pydub` is also explicitly checked
  dynamically; whether its declaration and verifier entry should both be
  removed remains uncertain.
- The game simulator is invoked by a shell script and documented in its README.
  A sampled unused-file finding misses that entrypoint.
- In the Next.js app, **132 of 161** default tasks are under `content/exercises`.
  Source is loaded with `fs.readFile` and provided to Sandpack; it also contains
  intentional starter code. Three inspected file/function removal candidates
  are false positives. This does not classify all 132 unreviewed tasks as false.
- A documented optional browser FPS fallback and test timer-handle assertions
  are intentional. Empty-catch/type-assertion patterns alone do not prove a bug.
- A main-sequence “zone of pain” warning on a small cohesive pure utility did
  not establish that adding abstractions would improve it. Optional advice
  needs contextual judgment.

## Preview capability and edits

Two Audio-RAG import-removal patches were successfully **previewed**, each
against its originating report and exact source hash. Neither was applied.
No eligible automatic-edit candidate appeared in the files-to-prompt queue.
The two sampled GIF TypeScript function removals were refused: the current
TypeScript adapter supports a narrow proven type-import case, not function
deletion. Incomplete game/Next.js analyses cannot authorize CLI patch previews
or edits. No supported TypeScript type-import example was exercised here.

Thus this run validates detection, triage, limited patch previews and refusal
behavior. It does not measure completed cleanup, test preservation, behavior
verification or before/after quality improvements. **No target source was
automatically corrected.**

## Bug found in Skylos itself

Three TypeScript/JavaScript tasks changed IDs across fresh default/all-advice
scans solely because the native top-level `calls` list arrived in a different
order. The affected examples were the GIF `cn` helper, the game's
`isValidProjectileHitEvent` and an interview exercise's `request` function.

Commit `5e50217d5dcd9f7cc9caf9581dc651e4784d729b` makes cleanup compare that
unordered metadata canonically while preserving original findings, ordered
evidence/trace lists and meaningful variants. Two new regressions failed on
the baseline before the change; 243 focused checks passed after the fix.
Replay of all ten saved native reports produces stable same-view task IDs
and unchanged counts. Ten additional fresh-process scans across all five
snapshots also retained stable default task IDs, unchanged counts/statuses and
identical source hashes. Follow-up results are recorded separately
in [post-fix-validation.json](post-fix-validation.json).

## Next priorities supported by this evaluation

1. Recognize code loaded as data and shell/manifest entrypoints in liveness
   analysis, with explicit positive and negative controls.
2. Improve unused-dependency reasoning for dynamic checks and indirect providers.
3. Consolidate overlapping file/symbol opportunities while retaining evidence.
4. Show per-task edit capability clearly, since detection coverage is broader
   than the supported automatic transforms.
5. Make mixed-language API coverage limits easier to understand without
   treating unsupported checks as completed or weakening edit authorization.

The defensible claim from this exercise is that cleanup finds concrete review
opportunities and retains visible limits. It is not evidence of AI-authorship
detection, universal “slop” detection, representative precision/recall or
automatic repair of every finding.

## Cleanup logic fix validation

The original results and source-review classifications above remain the baseline.
The [logic fix follow-up](logic-fixes-validation.json) records fresh static scans
after correcting shell-launched entrypoints, exact source-data reads and finite
native dependency probes. All five previously reviewed false positives are
absent, while all 25 supported default-task samples remain reported. The two
previous incomplete API coverage states remain incomplete. All six targets,
including pinned asgiref, retain identical source bytes; no target code or tests
ran and no network or model calls were made.

These changes also remove other queue observations covered by the same source
relationships. Those count changes are not additional independently reviewed
defects or a precision estimate. The four new test-quality rules still emit no
findings in this cohort. F-string edit preservation, affected-test evidence and
rollback are checked with separate self-authored runtime fixtures, rather than
by executing these external projects.
