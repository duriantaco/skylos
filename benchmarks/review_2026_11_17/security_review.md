# Security precision review — 17 November 2026

One narrow TypeScript/JavaScript false positive is fixed: literal `null` assigned to `innerHTML`/`outerHTML`, or supplied as the sole React `__html` value, no longer triggers `SKY-D226`. The DOM specification defines null-to-empty-string conversion on those setters ([HTML Standard](https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#the-innerhtml-property)). Null itself supplies no executable HTML. The proof inspects the expression value, never its name or type annotation.

The original implementation treated every non-string expression as unknown. This is a detector precision gap, not missing framework reachability. The fix is deliberately local to single-value property assignments and React values: it does not suppress nullable variables, nullish/OR fallbacks, a dynamic value merely asserted `as null`, augmented assignments, or variadic `document.write(null, untrusted)`.

## Evidence and regression results

| Check | Before | After | Interpretation |
| --- | --- | --- | --- |
| Default security benchmark | 277/277 pass; TP 150, FP 0, FN 0, TN 140 | Identical | Existing labelled detection accuracy preserved |
| Optional security challenge | 0/9 pass; FP 1, FN 8 | Identical | Existing gaps remain visible; no claims of full coverage |
| Four new inert-null contracts | 4 false positives | 0 false positives | Targeted precision improvement |
| New unknown/dynamic contracts | Six initial controls pass; augmented control added at review | Seven controls pass | Local uncertainty is retained |
| Focused HTML and security-proof tests | Original HTML suite: 32 pass | 219 pass across five test files | Existing and new suppression boundaries verified |

`security_html_new_tests_before.txt` captures the original 4 failures / 38 passes before the fix; the final augmented-assignment control was added following independent review. `security_focused_tests.txt` is the final focused run. These small authored fixtures are regression evidence, not independent product accuracy estimates or observed prevalence in the Desktop repositories.

Reports: `security_before.json`, `security_after.json`, `security_adversarial_before.json`, and `security_adversarial_after.json`. Baseline code comes from the root agent's frozen HEAD package at `/tmp/skylos-review-20261117-baseline`; both valid arms use the same freshly built Go engine. No manifests or labels were changed to make the existing suites pass.

## Environment correction

The initially discovered bundled Go executable was built on 14 November. Running newer source with that executable produced 15 apparent default-suite regressions: 12 false negatives and 3 false positives, all Go. `security_baseline.json` preserves that diagnostic run; it is **not** the valid before arm. Rebuilding current trusted Skylos Go source, without modifying Go detector logic, restored all 277 cases before either proposed precision fix. No target repository code was built or executed.

Build and current-suite reproduction:

```sh
cd /Users/oha/skylos/skylos/engines/go
/tmp/skylos-gap-go/go/bin/go build -trimpath -o /tmp/skylos-review-20261117-go ./cmd/skylos-go
cd /Users/oha/skylos
SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go /tmp/skylos-new001-validation/bin/python scripts/security_benchmark.py --json
SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go /tmp/skylos-new001-validation/bin/python scripts/security_benchmark.py --manifest benchmarks/security/adversarial_manifest.json --json
/tmp/skylos-new001-validation/bin/python -m pytest -q test/test_ts_innerhtml_values.py test/test_security_suppression_proofs.py test/test_security_sanitizer_identity.py test/test_security_lookalike_precision.py test/test_security_source_precision.py
```

`security_environment.json` records scanner HEAD, engine hash, compiler version, and relevant source/manifest hashes. The challenge runner exits nonzero because those nine failures are unresolved.

## Scope and gaps

The Desktop export cannot establish security precision changes: its final item-level labels, scoring manifest, exact source checkouts and immutable analyzer versions are absent. The saved 80-wrong-removed/zero-right-lost log is a development snapshot, not a recomputable accuracy claim. No inherited labels were invented or historical findings relabelled.

Current optional security challenges preserve eight detection misses and one false positive. The source-matched benchmark numbers above are scoped to existing authored labels, and should not be advertised as deployment accuracy or whole-repository recall. Five additional blind repository runs are coordinated separately by the root agent; this patch was neither developed from nor tuned against them.

A broader rule that treats *any expression involving null* as safe would hide unknown HTML; that approach was rejected. General static coercion, const aliases, numeric interpolation, custom renderer methods, and multi-argument document-write analysis were not expanded by this patch.

## Reproducible new corpus

`security_null_corpus/manifest.json` binds each of 11 facts to exact rule, file and line: four absent `SKY-D226` reset expectations and seven present unknown-input expectations. The unchanged source fixture is scanned, not executed. `security_null_before.json` records four false positives, while `security_null_after.json` records all 11 expectations passing. All seven previous unknown-input warnings remain. This is **4 false positives removed, zero required warnings dropped** on the authored extension.

```sh
SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go /tmp/skylos-new001-validation/bin/python scripts/corpus_ci.py --manifest benchmarks/review_2026_11_17/security_null_corpus/manifest.json --json
```

## Explicit Go SDK control

A later environment audit found the rebuilt `-trimpath` Go executable could lack a discoverable SDK when `GOROOT` was unset and `go` was absent from `PATH`. The security suites were therefore rerun with `GOROOT=/tmp/skylos-gap-go/go` and the same fresh executable, using the saved Desktop `analyzer_before` and `analyzer_after` trees. Every Python source hash matched the corresponding saved reviewed-run source inventory before running. The original reports remain unchanged.

The explicit-SDK results are identical in both arms and to the earlier fresh-engine security results: all 277 default cases pass (TP 150, FP 0, FN 0, TN 140); all nine challenges retain their failures (FP 1, FN 8). The Go subsets are 41 default cases (TP 24, FP 0, FN 0, TN 17) and six challenge misses. Every per-case confusion count, finding-category count, failure list, and analysis-completeness field remained unchanged. No security improvement is credited to this environment correction.

New evidence: `security_sdk_default_before.json`, `security_sdk_default_after.json`, `security_sdk_adversarial_before.json`, `security_sdk_adversarial_after.json`, and `security_sdk_diagnostic.json`. Reproduction of Go-dependent checks should explicitly set both `GOROOT=/tmp/skylos-gap-go/go` and `SKYLOS_GO_BIN=/tmp/skylos-review-20261117-go`.
