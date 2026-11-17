# Source-reviewed benchmark results — 17 November 2026

**The corrected study labels source first, uses a different agent to check every
label, freezes the evidence, then runs the scanner.** The earlier nineteen-fact
check had no positives and was insufficient; its report is preserved as
[exploratory evidence](confirmed_results.exploratory.md).

## Proof and actual outcomes

All [73 labels and outcomes](REVIEWED_GROUND_TRUTH_RESULTS.md) are listed with
pinned source locations, semantic truth, eligibility and each result.
The [manifest](reviewed_ground_truth_manifest.json), [freeze](reviewed_ground_truth_freeze.json),
[independent audit](reviewed_ground_truth_independent_audit.json) and
[hashed comparison](reviewed_comparison.json) preserve the evidence.
Freeze time: `2026-11-17T00:34:46.437693+00:00`; scored runs start afterward.

| Pinned source fact | Ground truth and proof | Before → final |
| --- | --- | --- |
| Slim `CallableResolver.php:110,118`: `isRoute` / `isMiddleware` | Used: lines 70/78 pass exact callbacks; the private helper invokes them at 93/98 | Two false positives → correctly retained |
| Slim `PlainTextErrorRenderer.php:17`: `htmlentities` import | Unused: no consumer in the complete file; other imported functions have explicit calls | Detected → still detected |
| Slim `RequestResponseNamedArgs.php:16`: `RuntimeException` import | Unused: no consumer in the complete file; alias import has no loading side effect | Detected → still detected |
| tiny-http `examples/serve-root.rs:42`: file read | Request URL reaches file-open and response without serving-root restriction | Missed → still missed |

The Rust label is a conditional risk in an intentional filesystem-serving
example, not a claim about a deployed service or library core. Its
[diagnosis](TINY_HTTP_POSTSCAN_SECURITY_DIAGNOSTIC.md) shows the sink is
recognized but tiny-http request-source modeling is missing. Blanket rules
for every `.url()` or `.recv()` would introduce noise; exact provider identity
and safe/lookalike controls are needed.

| Same frozen facts | TP | FP | FN | TN | Unscored |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original, explicit SDK | 2 | 2 | 1 | 44 | 24 |
| Node/HTML precision changes | 2 | 2 | 1 | 44 | 24 |
| Additional reviewed PHP correction | 2 | 0 | 1 | 46 | 24 |

A separate [comparison of every emitted finding identity](php_repository_finding_identity_delta.json)
across all five repositories removes only those two Slim method warnings:
no added findings, no other removed findings, and no security-warning changes.

The repositories are Mux (17 facts), tiny-http (16), Hono (13), Slim (15) and
Petclinic (12). Truth totals: 47 used, 3 unused, 11 safe, 1 conditional unsafe
and 11 unknown. One unused method is explicitly retained; four safe sites are
outside applicable sink scope. Of 57 eligible facts, eight lack required
negative extraction evidence: **49 scored, 24 unscored**. Unknowns and missing
evidence earn no pass. These are model reviews, not human adjudication.

These repositories had prior exploratory scans. Labellers/reviewers did not
read those outputs, but this is **not a new blind study**. The PHP follow-up is
informed development evidence. Two eligible unused imports and one security
example cannot establish population recall; unlabelled warnings remain unknown.

## Every corpus and language

The [complete inventory](CORPUS_INVENTORY.md) lists every case, manifest,
framework and recovered Desktop target. [Dead-code evidence](DEAD_CODE_GAP_EVIDENCE.md)
and [security evidence](SECURITY_GAP_EVIDENCE.md) cover all 14 languages, with
exact implementation, unit-test and manifest references. They distinguish
corpus omissions, unsupported capability and observed detector failures.

| Corpus | Scope |
| --- | --- |
| Shared corpus | 84 cases / 330 assertions; 77 contain Python; no direct security/secret assertions |
| Default dead code | 151 cases / 769 selected labels |
| Default security | 277 cases / 290 legacy rule-presence labels |
| Challenges | 17 dead-code and 9 security cases |
| Framework corpus | Five Python repos, category-count checks |
| Desktop export | 91 target directories; 57 retain Skylos JSON |
| Historical cohorts | 70-repo cohort and other pinned/manual studies; different scopes |
| Other suites | Quality, secrets, cloud, AI defects, review, verification, Jev, output contracts |

These populations overlap. Proven coverage gaps include JavaScript security
fixtures, missing Java/PHP/C# rule polarities, Go hash/random pairs, non-Python
framework breadth and Terraform D402–D408 contracts. Rust/Ruby/Dart native
families already have both polarities. C++/Swift lack native security-flow
adapters; Shell lacks dead-code declarations. Empty output is not safety.

## Changes and regression protection

Node preload parsing removes two authored-fixture false positives while
retaining five unused positives. Literal-null HTML handling removes four
fixture false positives while retaining seven required warnings on unknown
or dynamic controls. Those seven are warning-policy contracts, not seven
confirmed unsafe dataflows. PHP now
follows only exact private same-class callback arguments through a private
helper with direct invocation proof: two real-source false positives removed;
all six positive counterexamples in its development fixture retained.

The [PHP review](php_callable_independent_review.json) caught and excluded
overridden targets, first-class callable creation and dynamic local rebinding.
No blanket callback/string exemption, threshold increase or old-label removal
was used. [126 PHP tests and paired fixture evidence](php_callable_corpus/README.md)
pass. The scoring runner separately passes 36 mock tests, including eight
independent audit controls. Earlier 98 dead-code and 219 security checks
overlap these sets and must not be summed as independent evidence.

**All 538 existing regression cases were rerun after the PHP correction, with
zero changed expectations or reported finding-category counts** relative to their matched
baseline. [Every case and comparison](FINAL_REGRESSION_AFTER_PHP.md) and
[hashed receipts](final-regression-after-php-comparison.json) are preserved.

| Final suite | Result |
| --- | --- |
| Shared corpus | 84/84 pass |
| Default dead code | 151/151 pass; TP297 / FP0 / FN0 / TN472 |
| Default security | 277/277 pass; TP150 / FP0 / FN0 / TN140 |
| Dead-code challenge | Unchanged: TP30 / strict-unlabelled6 / FN12 / TN95 |
| Security challenge | Unchanged: TP0 / FP1 / FN8 / TN0 |

The six strict dead-code penalties are unlabelled findings, not six confirmed
false alerts. These regression expectations are not independently validated
population truth. The separate old-label audit below identifies mistakes.

Initial Go runs lacked a discoverable SDK despite reporting complete analysis.
The same engine with explicit SDK restores seven default misses and generated
retention. This is **environment restoration, not detector improvement**;
old outputs remain. [Security SDK reruns](security_sdk_diagnostic.json) are
unchanged. Final source snapshots isolate these three detector changes from
concurrent workspace edits.

## Separate evidence and historical limits

A separately produced [source-first five-repo audit](ground_truth_audit/confirmed_results.md)
covers Pyee, Blinker, Regexparam, Trouter and Goji, competitor results and old-label
corrections. It is preserved separately. Its [provenance check](EXTERNAL_STUDY_PROVENANCE_REVIEW.json)
verifies pins/hashes and the later 315-artifact ledger; Go per-run metadata does
not independently prove every ordering claim. Those executions/edits are not
attributed to this review team or pooled into the 73-fact scores.

Concurrent scorer changes already add exact location matching and fix F1;
[provenance](SCORER_CHANGE_PROVENANCE.md) distinguishes them from these detector
changes. Migrating 290 default legacy labels remains a corpus gap. Equal-count
framework substitutions remain a measurement gap.

The original Desktop final report and adjudicated label store were absent from
both folder and ZIP. Raw counts cannot reconstruct old accuracy. No historical
labels or totals were invented, and no scanned target code/tests were executed.
