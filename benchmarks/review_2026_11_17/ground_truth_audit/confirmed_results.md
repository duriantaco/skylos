# Confirmed results after detector fixes — 17 November 2026

**The detector repairs are implemented. All default/shared suites and both
challenge suites pass with no incomplete cases.** Source-first labels and
competitor adjudications remain preserved; these results describe selected
regression contracts, not population accuracy.

## Integration with current main

Merged main at `bea91bd7`, preserving the corrected ground-truth labels.
All five suites below still pass. An independent merge review found that a
shadowed or replaced path helper could inherit a sanitizer proof; the fix now
requires stable callable identity, including guards for mock patching. Real
local/imported helpers and unused mock imports remain quiet.
The merged tree passed 1,102 targeted tests before this guard addition, then
915 path/precision tests including 22 new identity controls after it. These
test sets overlap. The default security suite was rerun after the guard and
remains 277/277. [Integration receipt](fixes_2026_11_17/suites/MAIN_MERGE_VALIDATION.json)
records the scope and report hashes; earlier competitor measurements are unchanged.

## Matched results

| Suite | Cases passing | TP / FP / FN / TN |
| --- | --- | --- |
| Default dead code | 151/151 | 300 / 0 / 0 / 469 |
| Dead-code challenge | 17/17 | 48 / 0 / 0 / 95 |
| Default security | 277/277 | 150 / 0 / 0 / 140 |
| Security challenge | 9/9 | 8 / 0 / 0 / 1 |
| Shared corpus | 84/84 | 330 assertions |

The corrected default dead-code facts improve from **297 TP / 0 FP / 3 FN /
469 TN** to **300 / 0 / 0 / 469** under the same SDK/workspace environment.
The completed challenge labels improve from **36 / 0 / 12 / 95** to
**48 / 0 / 0 / 95**. All earlier required positive facts remain detected.
The original security challenge improves from **0 / 1 / 8 / 0** to
**8 / 0 / 0 / 1**, retaining its original expectations.

Three mistaken used labels were corrected from independently reviewed source:
two unloaded JavaScript files and one unreachable Python backend. The previous
manifest is archived. Six previously unlabelled challenge warnings now have
explicit source-reviewed labels; five are unread-but-required parameter slots,
which cannot simply be deleted without updating caller/protocol signatures.

Some earlier Go failures were environmental: the SDK was absent or GOWORK was
disabled. Authoritative before/after arms use the same Go SDK and active
workspace support. Stale-engine, stdin-worker and disabled-workspace diagnostics
are retained separately and earn no detector-improvement credit.

## Implemented fixes and protection against regressions

| Area | Repair | Accuracy protection |
| --- | --- | --- |
| Python callbacks | Recognize canonical Future callback decorators; Pyee warning removed | Shadowed providers, aliases, member replacement and opaque receivers abstain |
| Python dispatch | First-return backend tables no longer retain unreachable private tails | Escaped records, reflection, overrides and other consumers retain uncertainty |
| Typed registries | Prove unreachable bodies in bounded source-owned instance/type/snapshot/closure registries; preserve registration effects when refactoring | Unknown consumers/control flow, definition-time effects, custom protocols, mixed roots, trace evidence and resource limits decline negative proof |
| JS/TS paths | Discarded path strings passed only to proven no-op consumers no longer keep dead files | Real require/import loaders, external effects, mutation, aliases and default effects preserve references |
| JS/TS definitions | Top-level var, module variables and duplicate declaration sites remain visible | Same-file identity handling preserves prior conservative reference semantics |
| Go definitions | Preserve legacy package/build identities and live test helpers; detect bounded dead private test methods | Live interfaces/test receivers, package boundaries and partial type information remain guarded |
| Go security | Captured function/method providers, HTTP request aliases and TLS field assignments | Fake/rebound providers and shadowed true values retain the correct behavior |
| CI runners | Resolve finite hosted fallback expressions | Self-hosted alternatives, dynamic includes, malformed and unknown expressions still warn |
| Dart security | Local canonicalize helpers cannot impersonate sanitizers | Safe literal inputs stay quiet; unsafe process/HTTP/path inputs warn |
| Kotlin command data | Fixed printf/%s argv data is quiet | Dynamic programs/formats, shell forms and unproven programs retain warnings |
| Prompt metadata | Terminal description emoji joiner no longer raises a hidden-instruction alarm | Duplicate keys, hidden words, other fields and instruction files remain checked |
| PHP callbacks | Resolve proven private callback use and reject unreachable invocation evidence | After-return/dead branches, generators, mutation and override/lookalike cases are covered |

The tracked Go executable is rebuilt from repaired source. A normal CLI smoke
scan without SKYLOS_GO_BIN selects the repaired bundled engine and reports the
three confirmed Goji dead methods without analysis errors. The earlier attached
Node preload and literal-null HTML fixes remain included and tested.

## Five pinned repositories after repair

The original source-first cohort is Pyee, Blinker, Regexparam, Trouter and Goji.
Their revisions, complete source review ledgers and independent judgements are
unchanged. Final development remeasurement retains **all 146 selected used
symbols**, detects **all four selected eligible dead-code positives**, and
preserves the two applicable security controls. No selected FP/FN remains.
Unknown/unsupported facts and the original Pyee security-label line typo are
still unscored; no missing extraction earns a quiet-control win.

Pyee's callback, Blinker's finite runner fallback and Regexparam's terminal
metadata joiner warnings are removed. Go's test-method positives represent
expanded coverage, not a matched-scope recall win over an earlier unsupported
mode. These repositories were used for development after their first scans;
the after-fix run is not another blind study. **Real-repository security recall
remains unmeasured: this five-repository cohort has no confirmed unsafe positives.**

## Competitors, rerun with corrected facts

| Comparable development contracts | Tool | TP / FP-contract / FN / TN |
| --- | --- | --- |
| Python dead code, 27 cases | Skylos | 55 / 0 / 0 / 97 |
| Same contracts | Vulture 2.16 | 50 / 43 / 5 / 54 |
| Same denominator; imports/locals only | Ruff 0.17.5 F401/F841 | 5 / 1 / 50 / 96 |
| Python security, 78 cases | Skylos | 43 / 0 / 0 / 41 |
| Same mapped contracts | Bandit 1.9.4 | 12 / 8 / 31 / 33 |
| JS/TS, same 125 eligible labels | Skylos | 65 / 0 / 0 / 60 |
| Same contracts, normal plugins | Knip 6.45.1 | 64 / 26 / 1 / 34 |
| JS/TS eval/command families, 16 labels | Skylos | 9 / 0 / 0 / 7 |
| Same families | ESLint security 4.2.1 | 2 / 0 / 7 / 7 |

These columns are contract mismatches, **not independently confirmed tool
precision**. Source review confirmed only 17 of the original 44 Vulture FP
slots and six of the original 28 Knip FP slots directly. Other rows encode
retention/conditional framework contracts, different diagnostic units or
incorrect old labels. Ruff's function/class denominator is unsupported, Knip
has 50 unsupported labels and three no-package-manifest failures, and ESLint's
child-process rule is narrower. They do not support a general tool-winner claim.
The source-adjudicated nine-label Knip mismatch subset now has Skylos
TP3/FP0/FN0/TN6 versus Knip TP2/FP6/FN1/TN0; it is a mismatch-selected subset.

Staticcheck/Gosec and the five-repo competitor outputs remain preserved with
scope separation. Staticcheck's tests-included arm finds three frozen methods
plus two receiver types. Zero Gosec issues without positive security facts does
not establish safety or recall. Corrected Bandit sink/eval mapping, policy-only
warnings and remaining conditional labels are documented in the source audit.

## Validation

**3,783 integration tests passed** across 111 test files. Native Go tests,
the full PHP suite (611), Python shared checks (258), TS checks (166) and
independent semantic/resource controls also pass; these sets overlap and
are not summed as unique tests. The source-frozen five-repository receipt is
[the compact result index](RESULTS.json); the full original receipt is archived.

## Artifact cleanup validation

The artifact-only cleanup leaves production code, tests, canonical manifests,
fixtures and final source-label bytes unchanged from `ca17bb2e`. All five
suites above were rerun and still pass; 114 focused runner/PHP tests also pass.
The [compact result index](RESULTS.json) records this validation and report hashes.

## Corpus, evidence and reproduction

The [complete inventory](../CORPUS_INVENTORY.md) lists every corpus case,
manifest, framework/language stratum, recovered Desktop target and historical
cohort. The [dead-code](../DEAD_CODE_GAP_EVIDENCE.md) and
[security](../SECURITY_GAP_EVIDENCE.md) matrices preserve the scoped gap review.

The immutable `SOURCE_LABELS_*` files and independent review receipts remain
versioned. [Label provenance](GROUND_TRUTH_PROVENANCE.json) maps their accepted
drafts to the complete archive. [Source corrections](SOURCE_CORRECTION_SUMMARY.json)
preserve selected Python verdicts and the unscored location error. The retained
Python legacy, Knip and security adjudications preserve competitor scope limits.

The [result index](RESULTS.json) retains final counts, pinned revisions, source
hashes and links to original measurements. The integration receipt above and
canonical regression fixtures remain in Git. Full scans, duplicated manifests,
intermediate runs and superseded reports are preserved in the verified
[artifact archive](../ARTIFACTS.md), with a portable source-commit recovery path.
The historical harness datasets must be restored from that complete archive
before replaying them; their unit tests create their own sealed inputs.

Coverage gaps outside the selected contracts remain listed in the inventory.
No broad framework/name exclusions, confidence increase, LLM verification or
execution of third-party applications, tests or package scripts was used.
