# Executed baseline scoring proofs — 17 November 2026

Update: the later [source audit](ground_truth_audit/confirmed_results.md) adds
exact-location security labels and fixes the zero-sum F1 fallback. The saved
JSON below is historical and unchanged; the script now expects corrected F1
and writes a [separate fixed receipt](ground_truth_audit/scoring_gap_proof_fixed.json).

The following gaps were demonstrated with the baseline benchmark runners, not
inferred from aggregate scores. [scoring_gap_proof.py](scoring_gap_proof.py)
injects harmless hypothetical finding records at the scanner boundary and
checks the runners' responses. [scoring-gap-proof.json](scoring-gap-proof.json)
contains the executed results and source locations. No detector runs, external
repository runs, vulnerability demonstrations or target-code execution are
involved. These mocks establish measurement behavior, not real scanner defects.

**Current-workspace correction:** concurrent changes outside this review team now add structured security locations and correct zero-sum F1. The results below are preserved historical evidence, not a claim that those two implementation gaps remain unresolved. The default manifest still uses 290 string labels, so its legacy location ambiguity remains a label-migration gap. See [scorer change provenance](SCORER_CHANGE_PROVENANCE.md) for source hashes, exact current behavior and validation limits.

```sh
python benchmarks/review_2026_11_17/scoring_gap_proof.py \
  --output /tmp/scoring-gap-proof-current.json
```

The historical proof executed successfully with `/private/tmp/skylos-new001-validation/bin/python`.
The original run produced the historical JSON linked above. The concurrently updated script now expects corrected F1; the invocation shown writes a separate output so the historical JSON is preserved. Its rule-only mock contracts still demonstrate legacy-label ambiguity. This provenance correction did not rerun it.

## Baseline security: a warning at the wrong place satisfies a legacy positive

The mock manifest expects `SKY-D211` present and `SKY-D209` absent. Its intended
positive is at `target.py:10`; that location could not be expressed together with
the rule in the baseline security expectation schema. All of these baseline
`security.run_case()` results are complete, pass, and receive score 100:

| Injected warning records | Runner TP / FP / FN / TN | What the score fails to distinguish |
| --- | --- | --- |
| SKY-D211 at target.py:10 | 1 / 0 / 0 / 1 | Intended location |
| SKY-D211 at unrelated.py:10 | 1 / 0 / 0 / 1 | Wrong file; intended positive absent |
| SKY-D211 at target.py:40 | 1 / 0 / 0 / 1 | Wrong line; intended positive absent |
| Intended warning plus SKY-D216 at other.py:3 | 1 / 0 / 0 / 1 | Extra unlabelled rule does not affect score |
| Wrong-file warning plus the extra rule | 1 / 0 / 0 / 1 | Both failures remain invisible to selected labels |

The extra warning is still visible in `findings_by_category`; it is unscored,
not deleted from the report. Calling it an actual false positive would require
source truth. Here its incorrectness is an explicit hypothetical premise.

Source: [`_evaluate_expectations`, security.py:448](../../skylos/benchmarks/security.py)
loops only the expected tokens; for a `SKY-*` token it compares `rule_id` alone.
[`run_case`, security.py:567](../../skylos/benchmarks/security.py) adds completeness
validation, but no unexpected-finding penalty or target matching. These source line numbers identify the baseline implementation. All 290
default security expectations remain strings, so their selected-label scores measure
rule-presence/absence contracts, not exact-finding precision or whole-repository
recall. A same-rule positive and a same-rule safe sibling cannot be separately
labelled with the legacy rule-only form. Current structured labels can distinguish them.

Current source supports structured rule/file/line-range labels within a category and matches all fields on one finding. The remaining task is to migrate reviewed fixtures to that form and retain unmatched warnings as unknown until adjudicated. Exact-location support does not create source truth or make arbitrary unlabelled production warnings false. This proof did not author those concurrent scorer changes.

## Framework corpus: identical counts can hide changed symbols

The mock baseline contains one unused function. The real
`framework_corpus.run_target()` produces:

| Mock result | Gate outcome |
| --- | --- |
| Original `dead_local` warning | Pass |
| Replace it with `live_handler`, same category/count | Pass |
| Remove the warning, count decreases from 1 to 0 | **Fail** |
| Keep original warning and add an unused-file warning | Pass when unused_files is not a baseline category |
| Replacement with explicit present(dead_local), absent(live_handler) expectations | **Fail: two label failures** |

Correction to the initial inventory wording: **lower counts do not automatically
pass**. `_compare_baseline` uses absolute count differences; every current
framework target has `max_delta: 0`. A changed count in any recorded category
fails. The demonstrated gap is replacement within an unchanged category count,
plus categories omitted from the baseline. All five current targets omit
`unused_files` and have no per-symbol `expect` records.

Source: [`_compare_baseline`, framework_corpus.py:170](../../skylos/benchmarks/framework_corpus.py),
[`_compare_expectations`, line 197](../../skylos/benchmarks/framework_corpus.py),
and [`run_target`, line 264](../../skylos/benchmarks/framework_corpus.py).
The scorer already supports precise file/symbol expectations. Frozen
used/unused labels can therefore improve these five targets without weakening
the count gate or changing production detector logic.

## Baseline security F1 defect — corrected in current source

For TP=0, FP=1, FN=8, TN=7 the executed baseline metric functions returned:

| Scorer | Precision | Recall | Reported F1 | Correct F1 |
| --- | ---: | ---: | ---: | ---: |
| Security | 0 | 0 | **1.0** | **0.0** |
| Dead code | 0 | 0 | 0.0 | 0.0 |

The direct formula is `2*TP / (2*TP + FP + FN) = 0/9 = 0`.
[`security._score_counts`, security.py:518](../../skylos/benchmarks/security.py)
used 1.0 when `precision + recall == 0`; the concurrent current implementation uses 0.0.
[`dead_code._score_counts`, dead_code.py:738](../../skylos/benchmarks/dead_code.py)
already used 0.0. The baseline defect was in security's F1 field; this is not
evidence that the dead-code scorer has the same defect. Security's composite
score is computed from precision, recall, absence and timing separately, so
this F1 fallback does not itself change those counts or that composite score.

Current source has the zero-sum fallback correction and `test/test_security_benchmark_locations.py` contains a regression with both false positives and false negatives. This provenance pass inspected that source/test without running it. No scoring production file was changed by this review team; the original executed proof stays unchanged.

## Corpus language claim: checked against actual fixture paths

The prior **77/84 Python** claim survives a direct filesystem audit:

| Measure | Result |
| --- | ---: |
| Shared corpus cases | 84 |
| Cases containing .py target files | 77 |
| Python-only cases among recognized source suffixes | 77 |
| Cases containing other source languages without Python | 7 |
| Cases still containing Python after excluding every run.py | 77 |
| Python files in all case paths | 114 |

The only `run.py` is
[`python_exec_namespace/runpkg/run.py`](../../corpus/fixtures/python_exec_namespace/runpkg/run.py).
It is actual target source for the namespace-liveness fixture, not a benchmark
harness. Seven other Python target files share that case, so removing it does
not change the case count. Only files inside each manifest's exact case path
were counted; top-level Python benchmark runner scripts were excluded.

Other observed suffix totals: 12 `.ts`, one `.tsx`, five `.js`, four `.php`, one
`.sh`, one `.astro`, one `.svelte`, and two `.vue` files. These are composition
counts. They do **not** establish that each language has independently grounded
labels, balanced used/unused controls, supported security analysis, successful
parsing or measured recall. Per-case file lists and the manifest hash are in
the JSON proof, so the distinction is auditable.

The shared corpus's 330 assertions also contain **zero `danger` or `secrets`
expectations**. They comprise dead-code/liveness checks and 37 quality checks.
The 84-case shared corpus therefore supplies no direct security-label evidence;
security coverage must be assessed from its separate security manifests.
