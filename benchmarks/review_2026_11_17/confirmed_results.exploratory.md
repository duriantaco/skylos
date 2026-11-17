# Latest source-reviewed results — 17 November 2026

The [completed source audit and competitor results](ground_truth_audit/confirmed_results.md)
cover five new pinned repositories (Pyee, Blinker, Regexparam, Trouter, Goji),
three source-labelling agents, and Vulture/Ruff/Bandit/Knip/ESLint/Staticcheck/Gosec.
The [complete corpus inventory](CORPUS_INVENTORY.md) lists every existing case and recovered Desktop target.

Source review exposed incorrect old labels: a versioned correction benchmark
now reports **TP290 / FP1 / FN10 / TN468**, including three newly visible Skylos
misses. Only 17/44 Vulture and 6/28 Knip legacy FP labels were confirmed directly;
other mismatches include retention policies, uncertain framework contracts and
incorrect ground truth. Fresh scans confirm a callback FP and a bounded unused
helper TP; real-repository security recall remains unmeasured.

Exact-location security scoring, F1 arithmetic and Bandit pickle/eval matching
are corrected. Nine new paired source controls pass; combined tests pass192,
with a later overlapping119-test completeness check. The two earlier narrow
detector fixes remove six regression-fixture false alarms without losing
required positives. Full labels, raw results, caveats and evidence are in the linked audit.

---

The earlier exploratory phase below is retained for provenance; it describes a different five-repository cohort.

# Measured regression results and incomplete repository validation — 17 November 2026

> **Correction:** The five-repository accuracy benchmark is incomplete. Actual
> static scans were run, but their emitted security findings were not individually
> validated, dead/unsafe ground truth was not established, and missed positives
> were not measured. The 19 selected source facts contain zero dead/unsafe
> positives. The requested filename is retained; it must not be read as a
> confirmation of real-world accuracy, validated repository vulnerabilities,
> or a completed investigation of misses in those repositories.

**Two small changes remove six confirmed false positives in authored regression
fixtures, with no lost labelled positives. Existing default and challenge
benchmark outcomes are unchanged. Five fresh repository scans also show no
change in the selected outcomes. This establishes preservation on the measured
labels, not a guarantee of unchanged accuracy on arbitrary projects.**

This is a new review. The Desktop export did not contain the original
`confirmed_results.md` or `confirmed_results.combined.md`; neither did its ZIP.
The old adjudicated accuracy table cannot be reconstructed from the saved
finding counts. Nothing in this report invents or replaces missing old labels.

## Corpus inventory

The [complete inventory](CORPUS_INVENTORY.md) lists every case and repository,
including descriptions, languages, label balance, gaps and regression risks:

| Existing evidence | Scope |
| --- | --- |
| Shared corpus | 84 cases, 330 assertions; 77 cases contain Python |
| Default dead code | 151 cases, 769 selected-symbol labels |
| Default security | 277 cases, 290 selected rule-presence labels |
| Separate challenges | 17 dead-code cases; 9 security cases |
| Framework corpus | Five Python repositories; count-drift checks |
| Desktop export | 91 target directories; only 57 retain any Skylos JSON |
| Earlier holdouts | 70-repository cohort; three-repository security review; eight-repository dead-code comparisons; other pinned/manual cohorts |
| Other benchmark families | Quality, secrets, cloud, AI defects, review, verification, Jev and output contracts, all enumerated in the inventory |

These overlap and must not be added into a single independent sample count.
The Desktop list includes old targets and subprojects; it is not 91 verified,
fully scored, distinct repositories. Suites outside dead code/security/shared
corpus were inventoried, not all rerun. No paid LLM/Jev verification was used.

## Implemented changes and breakage controls

| Change | Why it was noisy | What changed | Recall guard |
| --- | --- | --- | --- |
| Node preload references | `--import=path` and `--require=path` were skipped although space-separated forms were recognized | Retain the exact preload module for Node, before the script operand | Unused siblings and script-data paths still report; unknown runtimes/options and Node `--` boundaries do not retain files |
| HTML literal-null resets | Every non-string HTML value was treated as unknown | Literal `null` on simple DOM HTML setters or sole React `__html` values is recognized as inert | Unknown variables, type assertions, fallback expressions, augmented assignments and variadic writes still warn |

Details and reproductions: [dead-code review](deadcode-notes.md),
[security review](security_review.md). No repository-specific exceptions,
confidence increases, broad framework exclusions or label removals were added.
Both changes were independently reviewed. Review caught a Node end-of-options
edge case before completion; the final patch and regression fixture cover it.

## Matched existing and extended benchmarks

TP means a labelled unused/unsafe item detected; FP means a quiet label warned
(or an unlabelled dead-code finding under strict scoring). Counts measure the
selected labels, not entire real-world repositories.

| Suite | Before TP / FP / FN / TN | After TP / FP / FN / TN | Final result |
| --- | --- | --- | --- |
| Existing dead code, strict | 290 / 1 / 7 / 471 | 290 / 1 / 7 / 471 | 149/151 cases pass; eight label failures in two existing Go cases |
| Existing security | 150 / 0 / 0 / 140 | 150 / 0 / 0 / 140 | 277/277 cases pass |
| Dead-code challenge, strict | 30 / 6 / 12 / 95 | 30 / 6 / 12 / 95 | 8/17 cases pass; existing failures preserved |
| Security challenge | 0 / 1 / 8 / 0 | 0 / 1 / 8 / 0 | 0/9 cases pass; existing failures preserved |
| New Node preload/boundary contracts | 5 / 2 / 0 / 2 | 5 / 0 / 0 / 4 | 3/3 cases pass |
| New exact-location HTML controls | 7 / 4 / 0 / 0 | 7 / 0 / 0 / 4 | All 11 facts pass |

The shared corpus passes **84/84 before and after**. Case-level comparison of
all 454 existing default/challenge cases found no changed counts, failures,
coverage status or finding-category totals; see
[comparison receipt](regression_comparison.json). The two default dead-code
failures are `go-dead-call-graph` and `go-private-test-helpers`.

Validation: 98 dead-code focused tests and 219 security focused tests passed.
The final combined changed-test/holdout-scoring check passed 67 tests, including
five tests that reject missing extraction, incomplete analysis, wrong-location
matches and unsupported-control credit. These test sets overlap; do not sum
them as unique tests. Raw JSON and logs are alongside this report.

An initial run mixed newer source with an older bundled Go binary. It produced
spurious differences. Both authoritative arms use the same freshly built
Skylos Go engine and archived HEAD/current Python source. The stale-binary
results are diagnostics, not an improvement attributed to these changes.
Build metadata and hashes: [security environment](security_environment.json),
[dead-code provenance](deadcode-provenance.json), [runtime versions](runtime_environment.json).

## Five fresh repository checks

The final cohort is in the [frozen manifest](blind_manifest.json). Labels were
chosen from source before each target's first scan and checked by another
agent. No detector was tuned using these results. This is a nonrandom,
model-reviewed open set, not an independently human-adjudicated accuracy study.

| Repository | Language/framework | Selected outcomes, unchanged before/after |
| --- | --- | --- |
| gorilla/mux | Go HTTP routing | Three used helpers retained; security output unlabelled |
| honojs/hono | TypeScript web/JSX framework | Three used helpers retained; one applicable HTML-reset control quiet |
| slimphp/Slim | PHP web framework | Three used renderer helpers retained; one source-safe HTML fact outside implemented sink scope, unscored |
| spring-projects/spring-petclinic | Java Spring MVC | Two used helpers retained; fixed redirect control quiet; one annotated method missing from exported definitions, incomplete/unscored |
| tiny-http/tiny-http | Rust HTTP library | Three used helpers retained; separate-argv command control quiet |

**17 retained controls, one not-applicable fact, one incomplete fact in both
arms.** Of the 17, fourteen are used-symbol controls and three are applicable
security controls. All five scans completed; the Java incomplete outcome is
for one label's extraction evidence. It is not silently counted as safe or
asserted to be a dead-code detector bug. Scope review:
[original source review](holdout_scope_review.json),
[final scoring scope](blind_scope_review.json), [Mux review](blind_mux_review.md).

Chi was initially selected, then found in an earlier development comparison.
Its scan remains supplementary evidence and is **excluded from the five blind
repositories**. Gorilla Mux replaced it before Mux was scanned. The original
manifest remains intact for the audit trail. No references to the final five
were found in the available pre-existing corpus/benchmark files or Desktop
target names; unavailable historical records cannot be checked.

These labels contain no unused/unsafe positives: **blind recall is unmeasured**.
Unreviewed warnings remain unreviewed. The small changes do not reduce total
warning volume on these five snapshots; the six demonstrated reductions are
on the authored regression extension. No blanket claim of real-world noise
improvement follows from these results.

Summary receipts: [before](blind_before.json), [after](blind_after.json).
The Desktop review directory retains full raw reports under `blind_before/`
and `blind_after/`, exact target Git checkouts under `checkouts/`, analyzer
source snapshots under `analyzer_before/` and `analyzer_after/`, and the matching
Go binary under `tools/`. Earlier attempt directories are diagnostic only.
Petclinic's two Windows launchers were normalized to their exact Git blob bytes
with local Git attribute overrides; neither launcher was executed. Source
files, Git blobs and checkout identity were verified before and after scans.

## Highest-priority remaining work

| Gap | Logic or evidence? | Why a broad fix can break accuracy | Safe next contract |
| --- | --- | --- | --- |
| Security rule-only scoring | Measurement gap | A warning on a different sink can satisfy a positive; extra noise can be invisible | Add backward-compatible exact rule/file/line labels; keep old positives and explicitly inventory unmatched findings |
| Framework count baselines | Measurement gap | One lost TP can cancel one new FP in a count | Freeze per-symbol used and unused facts, with positive extraction evidence |
| Go call graph/test-helper failures | Reproduced existing logic failures | Blanket public/test liveness can hide unused helpers | Provider/package-specific call edges, unused siblings and test-only usage controls |
| Go aliases and Dart sanitizer identity | Reproduced challenge failures | Suppression by API spelling or helper names can hide required warnings | Exact binding/provider identity and sink-specific safe/unsafe lookalikes |
| Java/PHP framework registrations | Historical logic gaps; fresh Java extraction limit | Broad callback/base-class exemptions can hide unregistered code | Exact registration/owner evidence plus unregistered sibling controls |
| Non-Python framework breadth | Coverage gap | More quiet cases alone create false confidence | Expand C#/Dart/Rust/PHP/Java framework controls with both used/unused and safe/unsafe labels |
| Cross-language security pairs | Coverage gap | Existing supported rules may lack opposite-polarity controls | Add missing pairs listed in inventory; unsupported rules earn no safe credit |
| Blind real-world positives | Evidence gap | Known-used and safe examples cannot constrain recall | Freeze independently reviewed unused/unsafe positives before another untouched holdout; maintain unknown outcomes |
| Desktop study reconstruction | Missing artifacts | Raw counts cannot reconstruct adjudicated precision/recall | Recover the original label store, scoring definitions, source pins and final combined report |

Do not improve these scores by ignoring entire frameworks, directories, test
trees or sanitizer names. The acceptance gate for further precision work is:
removed warnings have source-backed FP labels, old required findings remain,
paired unsafe/unused lookalikes still report, and unsupported/incomplete cases
remain visible. The [inventory](CORPUS_INVENTORY.md) gives each language/rule gap
and historical evidence separately.

## Reproduce the new checks

Use the environment versions recorded above. Build Skylos's trusted Go source
as documented in the security review, or use the saved Desktop binary on this
machine. Do not build or execute target code.

```sh
python scripts/dead_code_benchmark.py --manifest benchmarks/review_2026_11_17/deadcode-preload-manifest.json --strict-labels --json
python scripts/corpus_ci.py --manifest benchmarks/review_2026_11_17/security_null_corpus/manifest.json --json
python benchmarks/review_2026_11_17/run_holdouts.py --checkout-root /path/to/checkouts --analyzer-root /path/to/analyzer_after --output /path/to/new-output
```

Set `SKYLOS_GO_BIN` to the matching Go binary for holdouts and existing suites.
The holdout runner refuses to overwrite output; its expected nonzero status
keeps the incomplete Java label visible. It validates complete pinned trees,
source hashes and parser evidence, matches exact source locations, and gives
unreviewed findings no FP/TN label. Existing suites, raw hashes and all prior
labels are retained for future comparison.
