# Remaining corpus and capability gaps

This inventory separates missing benchmark evidence from missing detectors.
It records the state reviewed in November 2026. A unit test, shared synthetic
corpus and independent repository holdout answer different questions.

| Area | Evidence we have | Gap and next useful contract |
| --- | --- | --- |
| C++ dead code | Native conservative file-local engine; paired direct calls and address-taken callbacks in the shared corpus | Pinned independent C++ labels; templates, overloads and macros are not general supported proof |
| Ruby/Rails | Paired private-method owners and literal controller callbacks; explicit Kernel command pairs; five independently labelled used helpers in pinned Rake source | Ruby unused-symbol recall and independent Rails labels; Rails request/SQL provenance, broader security and quality detectors. Override/dynamic cases stay unknown |
| Terraform/AWS | 16 parser/resource contracts; five pinned TerraGoat facts: two unsafe, two not applicable and one unknown | TerraGoat is training code, not production deployment evidence. Its 59 unsupported resources remain visible. Need independent production labels, IAM, S3, module/data evaluation, CloudFormation, Kubernetes RBAC, Helm and other providers |
| Security rule breadth | Shared positive/control pairs now include Python/TS TLS (`SKY-D210`), Python hashes (`SKY-D207`/`208`), randomness (`SKY-D250`) and sensitive logs (`SKY-D251`), plus Rust/Dart command/path cases | Add counterparts for other supported language/rule combinations; these source contracts do not prove deployed exploitability or unsupported detector coverage |
| Quality evidence | Shared corpus mainly Python and TypeScript, with Go/Java examples; Rust has native quality checks | Add Rust/C# shared controls. PHP, Kotlin and Dart need detector capability before an empty scan can be labelled safe |
| Independent dead-code evidence | Existing pinned repository comparisons, a small Python fresh holdout and five known-used Rake methods | Extend independently labelled holdouts to C#, Kotlin, Rust, Dart, PHP and C++; broaden Ruby labels to unused symbols and frameworks. Keep holdout labels separate from tuning fixtures |
| Framework evidence | Existing framework repository corpus checks count drift | Add per-symbol used/unused labels and negative controls; a lower finding count alone does not prove fewer false positives |
| Existing challenge cases | Separate adversarial manifests preserve unresolved cases | The C# executable entry class and Kotlin fixed-format `printf` argv control still have known false positives; keep their labels fixed while investigating |
| Python random method capture | Constructor-instance aliases, copied methods and visible rebinding have native/direct regression controls | A method copied directly from an imported `random` module before that module alias is rebound can still be missed at a later credential sink. Its required warning remains a strict expected-failure contract; it is not labelled safe |
| Local API verification | Python, TS/JS, Go and Java have supported checks | PHP, Rust, Dart, C#, C++, Kotlin, Shell and Ruby explicitly report unsupported verification; static scanning is a separate capability |
| Dependency ecosystems | Existing Cargo, Composer, NuGet, Pub and RubyGems inventory/SCA | SwiftPM, CocoaPods and Hex remain unsupported; a lockfile inventory alone does not prove vulnerability coverage |
| WebAssembly artifacts | No dedicated Wasm analyzer or labelled artifact corpus | Proposed next artifact corpus: host imports and granted capabilities against an explicit policy, runtime resource limits and malformed/unsupported modules; host configuration can make a module's outcome unknown |
| LLVM IR | C++ source analysis exists; no LLVM IR analysis engine | Lower priority: establish a separate versioned IR corpus and source mapping before adding deeper compiled-code checks |

Priorities: extend the remaining language/rule control pairs, add quality
controls for implemented engines, and broaden independent labels for the newly
covered languages. Expand cloud rule families with resource coverage and explicit
unknown outcomes. Avoid repository-name exceptions or suppressions to improve a
benchmark total.

The default manifest inventory also lacks the opposite polarity for C#
`SKY-D233`, Go `SKY-D212`, Java `SKY-D216`/`229`/`230`/`239`, PHP `SKY-D255`,
Shell `SKY-D212`, and TS `SKY-D211`. This is a corpus inventory result; it is
not a reproduced detector bug. Rust and Dart now have both polarities for
their supported command/path rules (and Dart SSRF).

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
