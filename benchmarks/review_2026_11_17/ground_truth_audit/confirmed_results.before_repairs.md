# Source-reviewed benchmark audit — 17 November 2026

**Five new pinned repositories were source-labelled before scanning and compared with competitors. We confirmed false positives, unused code, extraction gaps and incorrect old benchmark labels. Real-repository security recall remains unmeasured.**

Three subagents read their assigned fresh repositories' complete declared source/configuration scopes. The parent separately reviewed selected source evidence before scans. These are model judgments, not human adjudication. Full-file review is not exhaustive per-symbol truth. No target code, tests or dependency scripts ran.

## Complete corpus inventory

The [full inventory](../CORPUS_INVENTORY.md) lists every case, manifest, framework, language, historical cohort and recovered Desktop target, with individual gaps. These populations overlap and must not be summed.

| Corpus | Scope | Main evidence limitation |
| --- | --- | --- |
| Shared corpus | 84 cases / 330 assertions; 77 contain Python | Zero direct security/secret assertions |
| Default dead code | 151 cases / 769 labels | Some used labels encode retention rather than execution |
| Default security | 277 cases / 290 labels | Legacy rule-only matching can credit the wrong sink |
| Challenges | 17 dead-code / nine security cases | Known failures retained |
| Framework repo corpus | Five Python repos | Count checks can conceal changed finding identities |
| Desktop export | 91 target directories; 57 retain Skylos JSON | Original final item labels/source pins missing |
| Other evidence | 70-repo cohort; other holdouts; quality, secrets, cloud, AI defects, agents, Jev, verification, output contracts | Inventoried; different scopes and not all rerun |

[Security gap evidence](../SECURITY_GAP_EVIDENCE.md) lists missing rule polarities by language. Priorities: JS security pairs, Go package/build identity, PHP/Java callbacks, C#/Dart/Rust ecosystem breadth, non-Python frameworks. Empty Swift/C++ native security output does not establish safety. Standalone SQL and component templates have separate capability limits.

## Five fresh source-first selections

These replace neither the old evidence nor its earlier Mux/Hono/Slim/Petclinic/tiny-http exploratory cohort. No matching references were found in available pre-existing benchmark/corpus records; unavailable history cannot be checked. Selection was nonrandom. Regexparam and Trouter are related projects.

| Repository | Frozen revision | Complete review / selected facts |
| --- | --- | --- |
| jfhbrook/pyee | be2025fc579a033326157dd41b5ad1f319d7d827 | 17 Python files + seven configs; 74 used, two unknown API members, one serialization fact |
| pallets-eco/blinker | c3364059663df1ddce32799d6b1922af89a345f6 | Seven Python files + eight configs; 36 used, one bounded unused helper, two security negatives |
| lukeed/regexparam | d05da2631beb7c5620774dae207cb09c7cbf24cc | All 11 tracked files; eight used, one security negative |
| lukeed/trouter | c5176edd1cd94b439a341c6b009f2f7b3d42d5a6 | All 12 tracked files; ten used, one security negative |
| goji/goji | 490b001d03d16a116d7c44d95d216c69a1aae798 | All 29 Go files, tests and both builds; 18 used, three unused test methods, one unscored regex fact |

Read the [Python](PYTHON_REVIEW.md), [JS/TS](TYPESCRIPT_REVIEW.md), [Go](OTHER_REVIEW.md), and [parent review](PARENT_SOURCE_REVIEW.json). SOURCE_LABELS files retain exact locations, hashes, consumers and assumptions; drafts/freezes remain separate. A Pyee serialization label's line typo stays incomplete in frozen scores, with a separate postscan correction.

## Source truth changes the competitive interpretation

All 44 existing Vulture used-label mismatches and all 29 Knip mismatches were source-reviewed, rather than accepting old labels automatically.

- Vulture's legacy 44 FP count becomes **17 directly source-confirmed FPs**, five explicit framework entry contracts, eight conditional framework contracts, six unreachable-dispatch retention contracts, two signature-retention bindings, two fields of unused owners, one ambiguous identity, and **three invalid used labels**. No replacement population precision/recall is claimed.
- Knip's 28 legacy FPs become **six confirmed FPs**, **two incorrect used labels**, one incompatible export/function diagnostic, and 19 uncertain retention/configuration contracts. Its one legacy FN is confirmed. On this **mismatch-selected nine-fact semantic subset**, Knip has TP2/FP6/FN1/TN0 and Skylos TP1/FP0/FN2/TN6. This selected subset is not whole-corpus accuracy.
- Incorrect JS labels: `tools/input.ts` and `src/bundle.ts` in `javascript-path-join-literal-files`. Paths reach a no-op `run() {}`; neither file is loaded. **These are Skylos dead-file misses hidden by old labels.** Python invalid used labels include `_flush`/`launch` without method consumers and `_api_read` behind a dispatcher that always returns its first backend.
- Security review covers all 39 cases mismatching the pickle-only corrected Bandit arm. Several apparent FNs are adapter omissions or related-rule claims, not missed operations. One TLS positive is invalid at final use: Python `SSLContext.check_hostname=True` restores CERT_REQUIRED. Path findings depend on route/platform constraints. An extra offline-only Hugging Face warning was invisible to old absence labels.

Versioned evidence: [Python old-label audit](PYTHON_LEGACY_LABEL_ADJUDICATION.json), [Knip audit](KNIP_SOURCE_ADJUDICATION.json), [security audit](SOURCE_SECURITY_ADJUDICATION.md). Original manifests/raw results stay preserved. Security audit input uses the intermediate pickle-only mapping; final eval mapping changes its totals, with both arms retained.

## Fresh findings, logic gaps and breakage risks

| Evidence | Verdict | Narrow improvement / risk |
| --- | --- | --- |
| Pyee `pyee/executor.py:66`; decorator at :65 | **Skylos/Vulture dead-code FP.** `@future.add_done_callback` registers the callable. Frozen used label. | Prove registration receiver identity; test fake providers and unused siblings. A name whitelist loses recall. |
| Blinker `src/blinker/base.py:456`, `_clear_state` | **Bounded TP**, found by both tools; no repository consumer. | Review before removal; external private-API consumers outside scope. |
| Blinker `.github/workflows/tests.yaml:11`, SKY-D295 | **Postscan FP:** finite matrix entries omit `os`; fallback is ubuntu-latest. | Resolve bounded expressions; preserve self-hosted alternatives and dynamic/unknown includes. |
| Regexparam `package.json:5`, SKY-D260 | Joiner exists in an emoji; **security impact unestablished**. Raw finding already says review/unknown. | Calibrate severity/context; preserve joiners hiding instructions. Character detection itself is accurate. |
| Three Uvu test files | **Knip default file FPs:** Regexparam `test/inject.js`, `test/parse.js`; Trouter `test/index.js`. Package scripts discover them. | Explicit source-justified entries remove all three in a separate configured rerun; not blind detector improvement. |
| Goji `pattern/pattern_test.go:11,20,23` | **Three unused methods.** Staticcheck with tests finds them plus two dead receiver types. | Skylos excludes test methods. Add coverage with test-entrypoint, interface and package-identity controls; not scored default-scope FNs. |
| Goji package/build identities | **Extraction gap:** five used labels incomplete; direct engine/final API differ. | Preserve package/build identity rather than globally rescuing names. |
| JS variables RGX/MAP | **Extraction incomplete**, not quiet-control wins. | Require parsed-definition evidence. |

Fresh Skylos selected dead-code outcomes: **138 parsed used controls retained, one known-live callback flagged, one eligible bounded unused helper detected, seven used labels incomplete, three Go test positives outside scope.** One eligible unused positive cannot establish broad recall. No real-repository security positives were established: **security recall is unmeasured**.

Every emitted fresh finding has an adjudication or explicit policy/unknown classification: [Python](PYTHON_POSTSCAN_ADJUDICATION.json), [JS](JAVASCRIPT_POSTSCAN_ADJUDICATION.json), [Go](GOJI_RESULTS.json). API-policy warnings, assertions and unpinned actions are distinct from exploitable vulnerabilities. Local pickle roundtrips show no untrusted deserialization, while risky-API policy warnings can remain accurate. Repeated tool reports are not distinct defects.

## Competitor reruns

These are **legacy selected-contract scores**, not independent accuracy. Source review above overrides any interpretation that every FP column is a confirmed competitor mistake.

| Scope | Tool | TP | FP contract mismatches | FN | TN |
| --- | --- | ---: | ---: | ---: | ---: |
| Python dead code, 27 cases / 152 labels | Skylos | 54 | 0 | 0 | 98 |
| Same contracts | Vulture 2.16 | 49 | 44 | 5 | 54 |
| Same denominator, imports/locals only | Ruff 0.17.5 F401/F841 | 5 | 1 | 49 | 97 |
| Python security, 78 cases / 84 labels | Skylos | 43 | 0 | 0 | 41 |
| Same contracts, final corrected adapter | Bandit 1.9.4 | 12 | 8 | 31 | 33 |
| JS/TS dead code, common 125 labels / 35 complete cases | Skylos | 63 | 0 | 0 | 62 |
| Same legacy contracts, normal plugins | Knip 6.45.1 | 62 | 28 | 1 | 34 |
| JS/TS eval + command families, 16 labels | Skylos | 9 | 0 | 0 | 7 |
| Same families | ESLint 10.15.0 + security 4.2.1 | 2 | 0 | 7 | 7 |

Ruff's selected rules exclude unused functions/classes; its mismatched denominator is exposed rather than used for ranking. Knip has 50 unsupported labels and three missing-package-manifest failures; these earn no score. Normal/default and restricted profiles, errors and configured reruns are retained. ESLint scanned all 58 TS/JS security cases; comparison covers only eval/command families. Its child-process rule is narrower than shell-enabled spawn/execFile analysis; other families are unsupported, not scored misses.

Go scopes stay separate: Staticcheck U1000 production reports zero; with tests finds three frozen dead methods plus two dead types. Gosec production/test arms report zero issues/errors, without positive security labels to measure recall. Failed toolchain attempts remain; successful runs use SHA-verified Go1.23.12. Tests-included competitor scores are not matched production advantages over Skylos.

## Completed improvements and checks

Two narrow detector changes already in the working tree were revalidated: exact Node attached preload paths and literal-null DOM HTML resets. Their authored extensions remove **six confirmed fixture false alarms**, retaining required positives. This is not observed population-wide noise reduction.

This audit adds backward-compatible exact rule/file/line-range security labels, validates that labels name real source lines, fixes zero-precision/zero-recall F1, and corrects Bandit pickle/eval mapping. B403 import and B302 marshal warnings no longer impersonate pickle sinks; B301 needs source-coordinate evidence to distinguish load/loads. Original and intermediate comparisons remain available.

Three new independently reviewed source fixtures add **nine exact-location labels**: YAML unsafe/safe loading, JS HTML input/clearing/text output, and PHP SQL concatenation/binding. All pass: three required warnings, six quiet controls. [Manifest](location_corpus/manifest.json), [independent review](location_corpus/INDEPENDENT_SOURCE_REVIEW.json), [results](location_corpus/result.json).

| Current rerun | Outcome |
| --- | --- |
| Shared corpus | 84/84 cases pass |
| Default dead code | TP290 / FP1 / FN7 / TN471; 149/151 cases pass |
| Default security | TP150 / FP0 / FN0 / TN140; 277/277 cases pass |
| Dead-code challenge | TP30 / FP6 / FN12 / TN95; known failures retained |
| Security challenge | TP0 / FP1 / FN8 / TN0; known failures retained; F1 correctly zero |
| Combined changed-surface tests | **192 passed** after final eval mapping; later completeness guard suite **119 passed** (overlapping) |

A separate [source-corrected manifest](../../dead_code/reviewed_manifest_2026_11_17.json) changes only three independently reviewed old labels: the two unloaded JS files and unreachable Python _api_read. Original manifests stay intact. This measures newly exposed misses rather than improving a score by removing hard examples. Ambiguous _flush/launch identities remain unresolved in this overlay. The [corrected rerun](source_corrected_deadcode_results.json) reports **TP290 / FP1 / FN10 / TN468**: three additional misses, with original positives retained.

Known default Go failures and alias/sanitizer challenge failures remain visible. No thresholds, broad framework exclusions or old required positives were weakened. No detector suppression was tuned on the fresh repositories. Preservation applies to measured contracts; arbitrary-project accuracy is not guaranteed.

Raw output, failure logs, commands, source labels and reproducible runners are retained here. [Current suite receipts](current_suites/), [original scoring proof](../scoring-gap-proof.json), [fixed scoring proof](scoring_gap_proof_fixed.json). FINAL_PROVENANCE.json seals final source/evidence hashes and checkout identities. The Desktop report/evidence are updated, with earlier reports archived.

An initial relocated correction manifest bypassed fixture isolation in the existing runner. Its context-contaminated output is retained under diagnostic_nonisolated_* and earns no accuracy claim. The authoritative corrected manifest sits beside the original manifest and uses identical isolation.
