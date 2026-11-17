> Historical two-patch results: the no-SDK default Go counts below are superseded by [explicit-SDK results](deadcode-sdk-comparison.json), which pass all151 default cases in both saved source arms. [The later source-reviewed study](REVIEWED_GROUND_TRUTH_RESULTS.md) preserves actual labels, false positives and misses. Environment restoration is not detector improvement.

# Dead-code precision review — 17 November 2026

One narrow logic gap is fixed: JavaScript/TypeScript modules named by Node's
attached `--import=module` and `--require=module` flags were reported as unused
files. The existing command consumer handled the space-separated forms but
skipped flags with attached values. The fix preserves exactly the preload
operand, before the script operand, for `node`/`nodejs` only. It does not raise
confidence thresholds or suppress a repository, directory, framework or rule.

The module-loading behavior follows the [Node command-line documentation](https://nodejs.org/api/cli.html#--importmodule).
The recorded old Desktop export has no final item labels or source checkouts;
this finding is a newly demonstrated regression case, not a claimed reduction
in the historical Desktop false-positive count.

## Before and after

| Suite | Cases | Before TP / FP / FN / TN | After TP / FP / FN / TN | Coverage |
| --- | ---: | --- | --- | --- |
| Existing strict dead-code benchmark | 151 | 290 / 1 / 7 / 471 | 290 / 1 / 7 / 471 | Complete |
| Existing strict adversarial benchmark | 17 | 30 / 6 / 12 / 95 | 30 / 6 / 12 / 95 | Complete |
| New Node preload and boundary contracts | 3 | 5 / 2 / 0 / 2 | 5 / 0 / 0 / 4 | Complete |

The default benchmark still has eight label failures in two Go cases:
`go-dead-call-graph` and `go-private-test-helpers`. The adversarial benchmark
still has 18 failures: 12 missed unused labels and six unlabelled findings
which strict scoring counts as false positives. These failures are unchanged;
none was removed or relabelled. Complete coverage does not mean correct results.

`deadcode-baseline-stale-go-engine.json` preserves the initial environment run.
That run had two incomplete Go cases and cannot replace the authoritative
baseline. `deadcode-baseline.json` uses archived HEAD Python source and the
current source-built Go engine. `deadcode-final.json` uses the working source
and the same engine; see `deadcode-provenance.json` for hashes.

## Accuracy controls and remaining limits

- Each preload contract retains the loaded registration module and worker,
  while reporting both an unused sibling and a file passed merely as script data.
- Parser controls cover echo/prose, unknown commands, unrelated options,
  other runtimes, empty values and options after the entry script.
- Independent patch review caught a potential new false negative at Node's
  `--` end-of-options marker. The final implementation treats the next operand
  literally and stops parsing flags. A separate full-scan contract ensures
  `node -- --import=./src/register.js` does not retain `src/register.js`.
- This change does not establish package resolution, unknown shell-wrapper
  behavior, general framework discovery or population recall. The three cases
  were used during development and are not blind holdouts.
- No target scripts, packages, tests or modules were executed.

## Validation

The original 14-test regression file failed on baseline with eight failures
and six passing negative controls. Review added five boundary controls.
Final focused validation passed **98 tests** across:

```sh
python -m pytest -q test/test_node_preload_dead_code.py \
  test/test_dead_code_external_consumers.py test/test_dead_code_ts_files.py
```

Reproduce final benchmark results with the source-built Go engine configured:

```sh
SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go python scripts/dead_code_benchmark.py --strict-labels --json
SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go python scripts/dead_code_benchmark.py --manifest benchmarks/dead_code/adversarial_manifest.json --strict-labels --json
python scripts/dead_code_benchmark.py --manifest benchmarks/review_2026_11_17/deadcode-preload-manifest.json --strict-labels --json
```

The first two commands deliberately return failure because the preserved
existing labels do not all pass. The new three-case manifest passes. A missing
engine or parse failure must remain incomplete, never earn absence credit.
