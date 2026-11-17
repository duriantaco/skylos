# Source labelling, independent review, then scan

This phase corrects the incomplete five-repository evaluation. Earlier scans
and the nineteen known-used/safe facts remain exploratory evidence. They do
not establish missed detections, security vulnerabilities or population recall.

## Required order

1. Each labeller reads the pinned source and relevant consumers/configuration.
   They must not read saved scanner findings or run a scanner during labelling.
2. They save a draft containing individual source facts, exact locations,
   evidence, assumptions and unknown outcomes. The draft is hashed.
3. A different agent reads the source and checks each fact. The reviewer saves
   an independent verdict and rationale, preserving the original draft.
4. Disagreements are resolved from source before any comparison. Unsupported
   or unresolved conclusions remain explicit; a desired score is not evidence.
5. The final labels, review verdicts, source revisions, file hashes, matching
   policy and scan configuration are sealed in a freeze receipt.
6. Only then run Skylos and match its findings against the frozen facts.
   Preserve raw output and all mismatches. Do not change labels after seeing
   the result; any later correction must be a separately versioned adjudication.

## Evidence required

For dead code, a used label needs an exact consumer, registration or public
interface contract. An unused label needs bounded evidence that the declaration
is inaccessible/unreferenced in the declared scope, including exports, tests,
callbacks and dynamic registration. Lack of an obvious call is insufficient.
Intentional retention and explicit suppressions are separate from semantic
unusedness and must not be silently scored as actionable removal candidates.

For security, a positive requires a source-supported input/control boundary,
dataflow to the operation, applicable context, relevant validation/escaping,
and an explained security consequence under explicit assumptions. A risky API
name alone is not a confirmed security issue. A safe label needs positive
evidence for the relevant property. Caller-dependent behavior, missing context
and unsupported interpretation remain unknown. No exploit payloads or target
code execution are required or used for these static reviews.

## Assignments

| Sources | Draft author | Independent reviewer |
| --- | --- | --- |
| Gorilla Mux and tiny-http | deadcode_precision | security_precision |
| Hono | security_precision | corpus_inventory |
| Slim and Spring Petclinic | corpus_inventory | security_precision |

The parent agent coordinates freezes and reruns. It does not replace the
second agent's source review with agreement on scanner output. Both reviewers
are model agents, not independent human adjudicators.

## Scope limits

These repositories were already scanned during the initial exploratory phase.
This is therefore a new output-blinded source-labelling and review phase on
existing snapshots, not a claim that the repositories have never been seen.
Only labels with complete evidence are scored. Selected facts are an open set;
unreviewed findings are neither automatically false positives nor true positives.
No eligible positive labels means recall is unmeasured, never 100%.

## Executed freeze

The independent reviewer checked all 73 normalized facts and the scoring
implementation; 36 mock tests passed. The [freeze](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/reviewed_ground_truth_freeze.json)
was written at `2026-11-17T00:34:46.437693+00:00`, before the new scan starts
recorded in the result summaries. Original drafts and reviewer artifacts are
hash-bound; none was changed after scanning. Slim/Petclinic's final recorded
review was reassigned to `security_precision` while `deadcode_precision`
implemented the scoring runner.

An initial execution lacked a discoverable Go SDK. Those outputs are retained
as `reviewed_before/` and `reviewed_after/`. The explicit-SDK reruns use the same
frozen labels and runner, with environment provenance in
[reviewed_sdk_environment.json](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/reviewed_sdk_environment.json). Environment
restoration is not credited as an analyzer improvement.
