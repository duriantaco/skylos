# Security scorer status and provenance correction

The earlier [executed scoring proof](SCORING_GAP_PROOF.md) describes baseline behavior. **The current workspace already implements structured source-location labels and fixes zero-precision/zero-recall F1.** These are concurrent changes outside this review team's edits. They must not be presented as unresolved implementation work or as changes authored by this team.

| Evidence | Pinned identity / status |
| --- | --- |
| Repository HEAD | `ab5fda49b111f844e0ae3c7fa2218b3730a6bb31` |
| Baseline `skylos/benchmarks/security.py` | SHA256 `8b4ac09ddf8e161584884c98600c2704dfb50ada4e4ffea2cb3f28fb0158fd7a`; HEAD blob and `/tmp/skylos-review-20261117-baseline` copy match |
| Current scorer inspected in this correction | SHA256 `22827e28e19c5faa34d10cf930f63fe7494b23681310a131be738631f2b83d01` (latest inspected snapshot) |
| Historical mock proof | [scoring-gap-proof.json](scoring-gap-proof.json) preserved; the concurrent study updated the script to expect corrected F1 and saved a separate fixed receipt |
| Default security manifest at this inspection | 277 cases, 290 legacy string expectations, zero structured objects |

The old proof's scorer function anchors—448, 518 and 567—match the saved baseline. Its emitted JSON did not record a scorer module hash, so the baseline hash above identifies the preserved source copy rather than retroactively adding a runtime hash receipt. The concurrent study subsequently changed the script assertion to corrected F1 and wrote [a separate fixed receipt](ground_truth_audit/scoring_gap_proof_fixed.json); the historical JSON must remain separate.

The earlier inspected concurrent scorer hash was `d4a3f61280fabc7f77a019047d16c709427a1c78bbb6f9cc950c6b1a470a9358`; a further malformed-report guard changed it to the latest hash above during this audit. Both snapshots contain structured matching and the F1 correction.

Current source inspection establishes:

- `validate_manifest` at [security.py](../../skylos/benchmarks/security.py) accepts exact `{rule_id, file, start_line, end_line}` objects inside a category. It rejects absolute/traversing paths, invalid bounds, missing files and ranges beyond source lines.
- `_relative_finding_paths` at line453 normalizes scanner paths to the scanned snapshot, retaining exact relative paths rather than basename matching. The latest concurrent edit preserves malformed non-dict reports for the completeness validator.
- `_evaluate_expectations` at line559 matches rule, exact file and inclusive integer line range on the **same finding**. Legacy strings retain legacy rule/token behavior.
- `_score_counts` at line643 uses **0.0** when precision and recall sum to zero.
- The concurrent diff also changes Bandit mapping, including source-coordinate-based B301 handling and eval mapping. Those changes are separate from our two detector precision patches.

[Test source](../../test/test_security_benchmark_locations.py) includes exact/wrong file and line controls, cross-finding non-combination, invalid source locations, relative isolated paths, and the zero-F1 regression. This correction inspected source and diff only; it did **not** execute those tests, re-run the scorer proof, or validate the unrelated concurrent code changes. A separate externally authored [audit report](ground_truth_audit/confirmed_results.md) records its own tests and runs; those are not executions by this review team.

The remaining gap is concrete: the default security corpus still uses 290 legacy strings. Those labels can credit the right rule at the wrong location and cannot separately identify a same-rule unsafe/safe sibling. Migrating source-reviewed pairs to the supported structured form addresses that measurement limit. Unlabelled findings remain unknown, not automatic false positives; unsupported or incomplete analysis earns no safe/pass credit. Structured matching and F1 arithmetic do not supply absent security positives or prove recall.

The corpus inventory and security gap evidence retain their language/framework and missing-polarity distinctions. No scorer, test, security README, external study artifact or Desktop report was modified by this provenance correction.
