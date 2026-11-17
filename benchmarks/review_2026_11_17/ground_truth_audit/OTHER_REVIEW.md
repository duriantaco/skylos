# Goji independent source review and competitor comparison

Goji `490b001d03d16a116d7c44d95d216c69a1aae798` is the fresh Go holdout. All **29 Go files / 2,036 source lines** were read, including tests and both router build variants; README, license and `.travis.yml` were also reviewed. The complete 32-file hash inventory is in `SOURCE_LABELS_GOJI.json`. The labels are selected source facts, not exhaustive per-symbol ground truth or a proof that security bugs are absent.

Author `/root/other_truth` saved and hashed the source-only draft before scanning. Parent `/root` independently checked the source and accepted its declared scope before `GOJI_FREEZE_RECEIPT.json` sealed the unchanged bytes. No target tests, package scripts, binary or application were executed. Competitors perform source/type analysis with CGO disabled in an isolated GOPATH workspace.

## Measured comparison

| Tool / arm | Raw findings | Confirmed interpretation |
| --- | ---: | --- |
| Skylos, normal API | 0 | 13 parsed known-live controls retained; 5 live controls incomplete; 3 dead test methods outside extractor scope |
| Staticcheck U1000, production | 0 | No confirmed production dead-code positive labels exist in this cohort |
| Staticcheck U1000, tests included | 5 | All 3 frozen unused methods detected; their 2 unused receiver types are additional source-confirmed findings |
| Staticcheck U1000, simple-router build + tests | 7 | Same 5, plus 2 interfaces unused only in this build variant |
| Gosec, production | 0 | 16 files / 1,121 lines; zero load errors; no positive security labels to measure recall |
| Gosec, tests included | 0 | 42 reported file visits / 3,094 lines, including repeated production visits across test package variants |

Skylos emitted no findings, so precision has a zero denominator. **Production dead-code recall and security recall are unmeasured.** Staticcheck's selected three-method recall is 3/3 in its tests-included arm; this does not establish repository-wide recall or a matched-scope advantage over Skylos. No benchmark-wide accuracy percentage is derived from this repository.

Tools: Staticcheck 2025.1.1 (`v0.6.1`), Gosec `v2.22.0` (module build metadata; version banner says `dev`). Initial attempts against Go 1.27.4 failed because these x/tools versions cannot decode its export data. Those errors are preserved and earn no score. Successful reruns use official Go 1.23.12, whose downloaded archive SHA256 was checked against the official release record. Raw commands, exit codes, stderr, JSON and timing are under `goji_raw/compatible_go1.23/`.

## Confirmed ground truth

The package `pattern` has stale test-only receiver types `boolPattern` and `prefixPattern` that are never constructed or otherwise referenced beyond declarations/receivers. Methods at `pattern/pattern_test.go:11`, `:20` and `:23` are unused in the bounded whole-tree package scope. Their `Match` methods retain the older context-argument signature. Root package `goji` has a different, live `boolPattern`; a name-only global search would conflate them. Staticcheck reports exactly these methods and receiver types. They have no suppression annotations.

The 18 live source facts cover `sort.Interface` methods invoked through `sort.Sort`, context `Value` overrides, callback factories, trie recursion with an external root, percent-decoding helpers and legitimate alternate builds. These are useful noise-regression controls. A safe fixed regular-expression construction fact is retained as evidence but excluded from scoring because no applicable detector contract was established.

## Gaps with source and output evidence

1. **Legacy Go project identity can lose same-named definitions.** There is no `go.mod`. `skylos/visitors/languages/go/go.py:150` falls back to the current file's parent as engine root. The `pat/` engine therefore emits `match.Value`, as shown in `goji_raw/skylos_engine_pat_directory.json`. A direct whole-tree engine scan emits `pat.match.Value`, in `skylos_engine_direct.json`. Final API `definitions` contains only the root `match.Value` and loses `pat/match.go:17`. `skylos/analyzer.py:5369` uses the definition name as dictionary key for Go. This is a confirmed identity/coverage gap, not a false-positive suppression opportunity. A future fix needs different-package same-name positive and negative controls plus legacy import-path tests; broad name rescue could hide real dead code.
2. **Alternate-build implementations share identities.** `router_simple.go` and `router_trie.go` are mutually exclusive implementations selected by `goji_router_simple`. Direct engine output includes both `router.add` and `router.route` definitions; final API retains only the trie definitions. Both simple-router live controls are incomplete. Staticcheck selects one build and correctly reports `httpMethods`/`pathPrefix` unused only in the simple build. Those are not proven removable across all supported builds. A future identity fix must preserve build conditions and avoid counting both variants as simultaneously compiled.
3. **Test helper completeness differs from test method scope.** Live helpers `makeMiddleware` and `wr` are absent even from the direct engine output. `symbols.go:429` exposes test helpers only when type reachability is established; it drops helpers with unknown reachability. Missing legacy-module/type context and mutually exclusive router declarations limit proof. This conservative behavior cannot earn retained-control credit. Separately, receiver methods in `_test.go` are excluded by `symbols.go:171`, so the three actual dead methods are outside normal Skylos scope. There is no supported with-tests switch for those methods. Adding test-method coverage needs tests for Go harness entrypoints, interface callbacks and same-spelled types across packages.
4. **Security positives remain missing.** The package is routing infrastructure, with no confirmed exploitable input-to-dangerous-operation path found by this static source review. A zero-warning result is not evidence of security recall or safety. Add independently labelled real positive cases in other source snapshots before claiming improved security accuracy.

`GOJI_RESULTS.json` records each label, exact parsed-definition evidence, scanner matches, explicit incomplete/scope-out outcomes and raw artifact hashes. Source hashes remained unchanged after all scans. No analyzer change was made using the holdout results.

## Supplementary review of older non-Python holdouts

`OTHER_EXISTING_DRAFT_INDEPENDENT_REVIEW.json` independently checks all 33 existing Mux/tiny-http source facts and their exact excerpts/hashes: all approved, no hash mismatches. This was a selected evidence review, not a new whole-repository review. Public API demand and caller-dependent redirects/socket cleanup remain unknown. Rust `FusedReader.into_inner` is semantically unused but explicitly `#[allow(dead_code)]`; it must not be counted as an actionable-removal false negative. The tiny-http file-serving example has a source-supported unsafe filesystem exposure boundary if run for untrusted clients; this is an example-only finding, not a deployed-service or core-library vulnerability claim.

The parent's nine promoted regression labels were independently reviewed from source in `location_corpus/INDEPENDENT_SOURCE_REVIEW.json`: YAML unsafe/safe loaders, DOM assignment/clearing/text output and PHP SQL concatenation/parameter binding. All nine rule-contract labels were accepted with explicit environment/input assumptions. These are development fixtures, not independent deployment evidence.
