# Remaining corpus and capability gaps

The [completed detector repairs](review_2026_11_17/ground_truth_audit/confirmed_results.md)
supersede the audit-only status below. Corrected default dead code now has
TP300/FP0/FN0/TN469, security TP150/FP0/FN0/TN140; both challenge suites pass.
Source-confirmed callback, dispatch, identity/extraction, CI, Dart/Kotlin/Go
security and PHP reachability gaps are repaired with paired controls. Historical
descriptions below document original gaps, not continuing failures. Broader
coverage and real-repository security-positive labels remain separate needs.

This inventory separates missing benchmark evidence from missing detectors.
It records the state reviewed in November 2026. A unit test, shared synthetic
corpus and independent repository holdout answer different questions.

The [source-reviewed audit and repairs](review_2026_11_17/ground_truth_audit/confirmed_results.md)
include five source-labelled repositories and competitor reruns. The audit
exposed three mistakes in old used labels: two JS files whose paths reach a
no-op helper and an unreachable Python backend. These corrections now live in
the canonical dead-code manifest; previous manifests and detailed comparison
runs are [archived](review_2026_11_17/ARTIFACTS.md).
Only 17/44 Vulture and 6/28 Knip legacy FP labels were confirmed directly;
other mismatches include incorrect labels, retention policies and unresolved
framework contracts. These columns are not independent tool precision.

The repaired issues include receiver-proven callback decorators (Pyee), bounded
CI runner expressions (Blinker), Go package/build definition identity, excluded
Go test methods and missing JS variable extraction. The final report documents
the paired safe/unsafe or used/unused controls that guard these repairs.
Exact-location security labels and nine new paired controls now work; most
default security labels still use legacy rule-only matching. F1 arithmetic and
Bandit pickle/eval matching are corrected. Real-repository security positives
remain insufficient to measure recall.

The [archived 73-fact follow-up](review_2026_11_17/ARTIFACTS.md)
confirms two Slim callback false positives (fixed), two unused PHP imports
(still detected), and one conditional tiny-http example security miss (retained).
All labels were independently checked and frozen before scored reruns; the
previously explored cohort is not a new blind study. All 538 existing regression
cases retain their prior expectations after the PHP correction.

Explicit Go SDK discovery restores the earlier seven default misses with the
same binary, so they are an environment/completeness-reporting issue, not seven
remaining detector defects. Both challenge suites now pass; their earlier
failures remain in the archive. The
[corpus inventory](review_2026_11_17/CORPUS_INVENTORY.md) and
[dead-code](review_2026_11_17/DEAD_CODE_GAP_EVIDENCE.md) /
[security](review_2026_11_17/SECURITY_GAP_EVIDENCE.md) gap matrices give the
source, test and manifest evidence; detailed historical runs are
[archived](review_2026_11_17/ARTIFACTS.md). Unsupported, unknown and
missing-extraction outcomes receive no pass credit.

| Area | Evidence we have | Gap and next useful contract |
| --- | --- | --- |
| C++ dead code | Native conservative file-local engine; paired direct calls and address-taken callbacks in the shared corpus | Pinned independent C++ labels; templates, overloads and macros are not general supported proof |
| Ruby/Rails | Paired private-method owners, closure scopes and same-file inherited controller callbacks; explicit Kernel command pairs; five independently labelled used helpers in pinned Rake source | Cross-file Rails ancestry and independent Rails used/unused labels; Rails request/SQL provenance, broader security and quality detectors. Override/dynamic cases stay unknown |
| Terraform/AWS | 22 parser/resource contracts, including sibling locals and modern ingress TFJSON; five pinned TerraGoat facts: two unsafe, two not applicable and one unknown | TerraGoat is training code, not production deployment evidence. Its 59 unsupported resources remain visible. Need independent production labels, IAM, S3, module/data evaluation, CloudFormation, Kubernetes RBAC, Helm and other providers |
| Security rule breadth | Shared positive/control pairs now include Python/TS TLS (`SKY-D210`), Python hashes (`SKY-D207`/`208`), randomness (`SKY-D250`) and sensitive logs (`SKY-D251`), plus Rust/Dart command/path cases | Add counterparts for other supported language/rule combinations; these source contracts do not prove deployed exploitability or unsupported detector coverage |
| Quality evidence | 33 quality cases, including Go/Java parameter boundaries, local async-result controls, Rust/C# unreachable-code and duplicate-body controls; structured expectations bind rule and source target on the same finding | Broader native quality-rule and independent repository labels. PHP, Kotlin, Dart, Ruby, C++ and Shell need detector capability before an empty quality scan can be labelled safe |
| JS/TS package usage | Bounded npm source/config imports, script binary providers, workspace declaration ownership, local enums and closed private enums with direct named imports; source imports from component scripts feed the project graph | Dynamic tool configuration, unknown shell wrappers, external SDK signatures and general public enum member demand remain unresolved rather than safe |
| AI verification evidence | 56 contracts, including JS/TS assertion diffs and nine explicitly unsupported language outcomes; incomplete results earn no accuracy or absence credit | Add independent multi-language change labels and deeper semantic API proofs. A successful unsupported-outcome contract is excluded from accuracy scoring |
| Independent dead-code evidence | Existing pinned repository comparisons, a small Python fresh holdout and five known-used Rake methods | Extend independently labelled holdouts to C#, Kotlin, Rust, Dart, PHP and C++; broaden Ruby labels to unused symbols and frameworks. Keep holdout labels separate from tuning fixtures |
| Framework evidence | Existing framework repository corpus checks count drift | Add per-symbol used/unused labels and negative controls; a lower finding count alone does not prove fewer false positives |
| Existing challenge cases | Separate adversarial manifests retain their reviewed contracts; all 17 dead-code and nine security cases now pass | Extend the challenge patterns while preserving existing labels and explicit unknown outcomes; passing these contracts is not broad capability evidence |
| Python random method capture | Constructor-instance aliases, copied methods and visible rebinding have native/direct regression controls | A method copied directly from an imported `random` module before that module alias is rebound can still be missed at a later credential sink. Its required warning remains a strict expected-failure contract; it is not labelled safe |
| Go security callable identity | Default corpus pairs SQL, SSRF, command, redirect, path, XSS, TLS and cookie behavior; six captured-provider/request-alias/TLS challenge cases now pass | Broaden source and mutation controls beyond these matched patterns; their success does not establish general provider or taint coverage |
| Dart sanitizer identity | Default command/path/SSRF pairs remain; local identity helpers named `canonicalize` no longer hide the two unsafe command/URL challenge cases | Broader provider proof and sink-specific sanitizer semantics still need deeper contracts; unknown helpers do not establish safety |
| Local API verification | Python, TS/JS, Go and Java have supported checks | PHP, Rust, Dart, C#, C++, Kotlin, Shell, Ruby and Swift explicitly report unsupported verification; static scanning is a separate capability |
| Dependency ecosystems | Existing Cargo, Composer, NuGet, Pub and RubyGems inventory/SCA | SwiftPM, CocoaPods and Hex remain unsupported; a lockfile inventory alone does not prove vulnerability coverage |
| WebAssembly artifacts | No dedicated Wasm analyzer or labelled artifact corpus | Proposed next artifact corpus: host imports and granted capabilities against an explicit policy, runtime resource limits and malformed/unsupported modules; host configuration can make a module's outcome unknown |
| LLVM IR | C++ source analysis exists; no LLVM IR analysis engine | Lower priority: establish a separate versioned IR corpus and source mapping before adding deeper compiled-code checks |

Priorities: extend the remaining language/rule control pairs, add quality
controls for implemented engines, and broaden independent labels for the newly
covered languages. Expand cloud rule families with resource coverage and explicit
unknown outcomes. Avoid repository-name exceptions or suppressions to improve a
benchmark total.

The default corpus manifest has both polarities for every Go, Java and
Kotlin rule it labels. Shell `SKY-D212` still needs a
negative counterpart; TS `SKY-D211` and Python `SKY-D206` need positive
counterparts. Python `SKY-D231`/`232` need negative counterparts. C#
`SKY-D233` and PHP `SKY-D255` retain both polarities.
This is a corpus inventory result; it is
not a reproduced detector bug. Rust and Dart now have both polarities for
their supported command/path rules (and Dart SSRF).

The PHP include guard now requires an explicit strict comparison against a
known allowlist; loose string-only comparisons remain conservative warnings.
Proving their operand types is a remaining precision task. C++ similarly keeps
its conservative all-identifier reference policy: a same-named local may retain
an otherwise unused helper until owner/binding evidence is modelled. Neither
limit should be hidden by a repository-specific suppression.

The [pinned upstream runner](holdouts/README.md) verifies checkout identity,
source hashes and positive parse coverage before matching selected facts.
Unreviewed findings have no FP/TN label, and unknown/not-applicable Terraform
checks do not earn safe credit. Rake checks five used helpers only; TerraGoat
does not measure production cloud security or all AWS resources.

Wasm and LLVM IR are tracked future work; this change implements neither engine.
Start with Wasm evidence before choosing rules. An imported host function or a
missing module-level memory maximum alone does not establish a vulnerability:
host grants and runtime limits must be part of the labelled contract.
See the [Wasm security model](https://webassembly.org/docs/security/) and
[LLVM IR reference](https://llvm.org/docs/LangRef.html).

No table entry is a claim that an unexecuted suite passed. Unsupported, parser
failure and unresolved outcomes must remain visible and cannot count as safe.
