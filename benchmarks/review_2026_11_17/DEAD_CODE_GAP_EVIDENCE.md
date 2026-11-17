# Dead-code/framework gaps: evidence and limits

This is the task-start gap review. Challenge failures and detector line
references below describe that earlier snapshot. The [completed repairs and
current results](ground_truth_audit/confirmed_results.md) supersede those failure
statuses; historical run evidence is in the [artifact archive](ARTIFACTS.md).

Reviewed 17 November 2026 from existing source, expectations, tests and saved results. No target code, tests or new scans were executed for this audit. Cited unit tests were read, not rerun. This is an audit of development evidence, not independent ground truth.

**Broad accuracy proof is incomplete.** The earlier nineteen-fact check had no positives. The subsequent [73-fact source review](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/REVIEWED_GROUND_TRUTH_RESULTS.md) preserves independent verdicts and frozen labels, including two eligible unused imports and one conditional security example. These small selected denominators cannot establish whole-repository accuracy. The explicit-SDK reruns below supersede the earlier Go environment diagnosis.

An **observed contract failure** is output differing from a frozen expectation. Source review must establish the expectation's meaning. A **conservative boundary** is an explicit limitation encoded in tests/implementation. A **suite gap** is missing/one-sided evidence in the named suite, even when unit tests cover it. An **independent-evidence gap** is missing real-source labels, not missing implementation. No behavior is presumed broken because its benchmark count is small.

## Evidence across fourteen languages

| Language | Exact existing coverage | Proven gap/boundary and accuracy risk |
| --- | --- | --- |
| Python | [FastAPI pair](../dead_code/manifest.json#L72); [unregistered framework siblings](../../test/test_corpus_ci_framework_controls.py#L14) include Flask, FastAPI, Celery, pytest, Django and DRF. [Dependency alias controls](../../test/test_framework_aware.py#L485). | Twelve Python challenge unused-body expectations are missing; source review below establishes the narrow closed-fixture claim. Individual [pytest](../dead_code/manifest.json#L655) and [package-entry](../dead_code/manifest.json#L906) cases have no unused labels, but global negative coverage clearly exists. Do not rescue all registrations; preserve selected owner/type/rebinding distinctions. |
| TypeScript | [VS Code pair](../dead_code/manifest.json#L1110), [plain open/close lookalikes](../../test/test_typescript_framework.py#L455). [Expo](../../test/test_ts_framework_conventions.py#L83) and [React Email](../../test/test_ts_framework_conventions.py#L130) already have paired units. | **Default-suite promotion gap:** all TS-labelled default fixture files have zero `expo-router`/`react-email` matches. Not absent implementation. The reviewed Hono sample now has six used labels, but no unused positive. Dependency/directory roots must preserve unused siblings, absent dependency and wrong-root controls. |
| JavaScript | [Storybook](../dead_code/manifest.json#L5873), [absent dependency](../dead_code/manifest.json#L5945), [public package entry plus dead sibling](../../test/test_ts_framework_conventions.py#L218), [new exact Node preload corpus](deadcode-preload-manifest.json). | Attached preload noise is addressed within synthetic controls, not independent broad accuracy. No distinct JavaScript repo is in the final five. Preserve `--` termination and script-data operands; do not equate public package exports with dead private app exports. |
| Go | [Graph contract](../dead_code/manifest.json#L2569), [test-helper contract](../dead_code/manifest.json#L3125), [native/analyzer unit](../../test/test_go_deadcode_depth.py#L73), [private-helper unit](../../test/test_go_project_reachability.py#L30). | Seven source-supported unused expectations were missed in the no-SDK run; explicit SDK discovery restores them. `generatedOnly` follows generated-retention policy, not proven runtime liveness. The actionable gap is silent analysis degradation when package/type proof is unavailable. Keep init/startup/test/callback roots while rejecting self/mutual recursion as roots. |
| Java | [FXML paired case](../dead_code/manifest.json#L1058), [annotated but unused siblings](../dead_code/fixtures/java_fxml_controller/PrintController.java#L4), [programmatic loader controls](../../test/test_analyzer.py#L4517). | [Petclinic result](ARTIFACTS.md) lacks exact `initCreationForm` definition and scores incomplete despite its source `@GetMapping`. Missing report evidence is established; parsing versus filtering cause is not. Keep missing definitions unscored, and preserve unselected annotated callbacks as negatives. |
| PHP | [PHPUnit pair](../dead_code/manifest.json#L7519), [SpeedTest not TestCase](../dead_code/fixtures/php_phpunit_colocated_tests/src/SpeedTest.php#L5). Drupal [real metadata](../../test/test_php_drupal_discovery_regressions.py#L130) and [retired/non-plugin controls](../../test/test_php_drupal_discovery_regressions.py#L152). | **Default-suite promotion gap:** four default PHP fixture trees contain no Drupal/plugin/hook markers; unit support exists. Slim's used helpers are not Drupal/Laravel evidence or recall. Do not rescue all Plugin directories, Test names, ordinary attributes or commented registrations. |
| Rust | [Trait identity pair](../dead_code/manifest.json#L3629), [cross-file traits](../../test/test_rust_project_trait_imports.py#L41), [inherent/by-value precedence](../../test/test_rust_project_trait_imports.py#L68). | **Explicit proof boundary:** [missing](../../test/test_rust_project_trait_imports.py#L111), [ambiguous](../../test/test_rust_project_trait_imports.py#L119), [attributed](../../test/test_rust_project_trait_imports.py#L130) modules supply no project-trait proof. Not universally absent cross-file support. Exact provider identity and excluded-provider controls must accompany any expansion. |
| Dart | [Extension pair](../dead_code/manifest.json#L8148), [imported provider](../../test/test_dart_binding_regressions.py#L654), [native precedence](../../test/test_dart_binding_regressions.py#L709). | **Uncertainty boundary:** [missing namespace](../../test/test_dart_binding_regressions.py#L339), [possible external extension](../../test/test_dart_binding_regressions.py#L424) retain zero reference credit with uncertainty; [resolved unused sibling](../../test/test_dart_binding_regressions.py#L452) reports. Preserve prefix/show/owner/native precedence; unknown cannot earn used credit. |
| C# | [Markup pair](../dead_code/manifest.json#L7909), [commented/unmatched handlers](../../test/test_csharp_overload_and_markup_refs.py#L66), [generated partial owner](../../test/test_csharp_static_owner_binding.py#L27). | [Same-arity overload unit](../../test/test_csharp_overload_and_markup_refs.py#L21) intentionally retains both one-argument overloads despite typed integer call; only two-argument overload reports. This is tested conservative granularity, not missing tests or independent whole-assembly deadness. Refinement needs types/conversions/optional/generic/owner controls. |
| C++ | [Local call chain](../dead_code/manifest.json#L2080), [address-taken callback](../dead_code/fixtures/cpp_address_taken_callback/main.cpp#L11), [shadowing](../../test/test_cpp_scanner.py#L67). | [Headers](../../test/test_cpp_scanner.py#L125), [external/member declarations](../../test/test_cpp_scanner.py#L143), [templates/overloads/macros](../../test/test_cpp_scanner.py#L154), [token pasting](../../test/test_cpp_scanner.py#L173) are explicitly protected. Claims they lack tests are withdrawn. General expansion needs translation-unit/instantiation evidence and header/pointer/generated-name controls. |
| Kotlin | [Member-extension pair](../dead_code/manifest.json#L6889), [exact receiver source](../dead_code/fixtures/kotlin_same_file_member_extension/Server.kt#L6), [non-call reads](../../test/test_kotlin.py#L141). | [Test-annotation unit](../../test/test_kotlin.py#L83) is one-sided in that test. No default Kotlin fixture contains `@Test`/`kotlin.test`. This is narrow promotion/negative-counterpart evidence, not global missing support. Add real annotation versus namesake/unannotated helper with owner controls. |
| Ruby | [Inherited Rails pair](../dead_code/manifest.json#L2409), [actual callback/dead sibling](../dead_code/fixtures/ruby_inherited_callback/main.rb#L3), [macro/name controls](../../test/test_ruby.py#L277). | [80-link alias limit](../../test/test_ruby_scope_callbacks.py#L167) explicitly reports unknown; [late alias](../../test/test_ruby_scope_callbacks.py#L184) cannot prove earlier ancestry. Rake labels five used helpers only. Exact ancestry/binding time must preserve non-Rails namesakes and private unused siblings. |
| Swift | [Codable](../dead_code/manifest.json#L5062), [reflection](../dead_code/manifest.json#L5146), [wrapper](../dead_code/manifest.json#L5441). Existing reflection [spare-method](../../test/test_swift_reflection.py#L23), [lookalike/unreachable](../../test/test_swift_reflection.py#L47), [cross-file](../../test/test_swift_project_reflection.py#L38) units. | **Named-case one-sidedness:** those three default cases have `unused: []`; paired reflection units already exist. Promote those controls rather than claiming missing logic. Preserve spare methods, computed/static fields and shadowed providers; do not root every reflected/Codable member. |
| Shell | [Adapter](../../skylos/visitors/languages/shell/__init__.py#L41) runs danger rules and returns empty definition/reference slots at63–66; [dead-code language set](../../skylos/benchmarks/dead_code.py#L78) excludes Shell. | **Source-proven capability boundary:** this adapter has no shell dead-code declarations. Shell security and shell-launched JS recognition are separate. A shell engine needs source/eval/exec/traps/aliases and unused siblings; empty-definition silence cannot be success. |

## Historical eight default failures: expectation versus source truth

[Before](ARTIFACTS.md) and [after](ARTIFACTS.md) retain TP290/scored FP1/FN7/TN471. They lacked discoverable SDK type/reachability evidence despite reporting complete analysis. The later [SDK-controlled comparison](ARTIFACTS.md) restores all seven missing findings and generated-code retention with the same engine: both saved analyzers pass 151/151, TP297/FP0/FN0/TN472. This is an environment correction, not detector improvement. The source distinctions below explain the old expectations; they are no longer unresolved default-suite misses under the recorded SDK environment.

| Expectation | Source proof | Interpretation |
| --- | --- | --- |
| staleA/staleB | [main.go:10](../dead_code/fixtures/go_dead_call_graph/main.go#L10): private cycle; no incoming fixture root. Public reaches rooted/callback; init reaches initialized. | Source-supported unrooted bodies; two expected warnings absent. Runner-level recall failure; loss layer unisolated. |
| self | [main.go:12](../dead_code/fixtures/go_dead_call_graph/main.go#L12): only self-reference. | Self-reference is not an entrypoint; expected warning absent. |
| deadValue | [main.go:13](../dead_code/fixtures/go_dead_call_graph/main.go#L13): returned only from uncalled unusedOwner. | Function-value reference in dead owner is not a root; expected warning absent. |
| alpha/beta/stale | [core_test.go:5](../dead_code/fixtures/go_private_test_helpers/core_test.go#L5): TestRun roots only liveTestHelper/testLeaf/core. Separate private cycle and isolated helper at8–10. | Three source-supported unrooted bodies; warnings absent. [Unit policy](../../test/test_go_project_reachability.py#L72) distinguishes proven unused helpers from blanket test-path suppression. |
| generatedOnly, labelled used | [generated.go:1](../dead_code/fixtures/go_dead_call_graph/generated.go#L1): generated banner and call from generatedEntry, itself private/uninvoked. [Unit label](../../test/test_go_deadcode_depth.py#L19) nevertheless retains it. | **Retention-policy mismatch, not proven runtime liveness.** A call from an unrooted function cannot prove execution. Preserve frozen label without calling this a source-proven false alert. |

The [benchmark scan helper](../../skylos/benchmarks/dead_code.py#L528) passes confidence and grep policy without explicit generated-file inclusion. Unit counterparts copy fixtures into temporary roots, call native analysis and disable grep caching. Native source admission and scope differences need isolation before blaming one algorithm. This audit changes neither labels nor scanner scope.

## Twelve Python challenge misses: source review

The [final challenge report](ARTIFACTS.md) records twelve missing unused expectations. Proof below concerns **callback bodies not invoked by these closed fixtures**. Registration may still store functions or have side effects; this does not authorize deleting decorated declarations. These are inspected development fixtures, not independent labels.

| Case / missing expectations | Exact source proof | Distinction needed |
| --- | --- | --- |
| owner: format_beta/format_gamma/format_delta | [registration/call](../dead_code/fixtures/corpus_type_registry_owner/app.py#L8), [dispatcher](../dead_code/fixtures/corpus_type_registry_owner/routes.py#L12): first.apply receives string only; beta is bytes, gamma on second, delta unregistered. | Type, instance and registration. |
| mismatch: process_alpha | [source](../dead_code/fixtures/corpus_type_registry_mismatch/app.py#L7), [dispatcher](../dead_code/fixtures/corpus_type_registry_mismatch/routes.py#L12): string callback, integer17 only. | Selected versus registered key. |
| rebound: subscribe/save/consume_alpha | [replacement](../dead_code/fixtures/corpus_type_registry_rebound/app.py#L11), [original](../dead_code/fixtures/corpus_type_registry_rebound/routes.py#L5): preserve replaces subscribe before decoration; original subscribe/save never run; callback never enters empty handlers. | Assignment time, callable identity. |
| snapshot: convert_beta | [fork/replacement](../dead_code/fixtures/corpus_type_registry_snapshot/app.py#L7), [copy](../dead_code/fixtures/corpus_type_registry_snapshot/routes.py#L12): copied branch retains alpha; beta replaces original only; branch alone dispatched. | Copied table versus alias. |
| closure: normalize_beta | [registrations/send](../dead_code/fixtures/corpus_type_registry_closure/app.py#L7), [closure dispatcher](../dead_code/fixtures/corpus_type_registry_closure/channels.py#L11): integer4 sent, never string. | Closure table and exact key. |
| hierarchy: describe_beta | [instances/call](../dead_code/fixtures/corpus_type_registry_hierarchy/app.py#L8), [MRO](../dead_code/fixtures/corpus_type_registry_hierarchy/routes.py#L20): mailbox selects Envelope for Note; beta belongs to other. | MRO plus owner. |
| private: _encode_beta/_encode_gamma | [registration/call](../dead_code/fixtures/corpus_type_registry_private/app.py#L1), [dispatcher](../dead_code/fixtures/corpus_type_registry_private/routes.py#L12): only _router.convert(string); bytes and _peer callbacks never selected. | Private owners, MRO/channel key. |

Summaries show missing expected findings but do not isolate decorator conservatism, object-state flow or output policy for each. A fix needs layer-specific evidence and the actually selected callback as a live countercase.

## Six strict-unlabelled rows are not six confirmed false positives

The [scorer](../../skylos/benchmarks/dead_code.py#L940) adds every unlabelled finding to false_positives in strict mode. This is an oracle-completeness penalty. None of the known-used labels fails in these two cases. Preserve numeric results, but describe these as **six unlabelled observations**, not six proven false alerts.

| Observation | Source evidence | Review conclusion |
| --- | --- | --- |
| extreme-grounding preview | [app.py:11](../dead_code/fixtures/extreme_grounding_framework/app.py#L11); no other fixture file references preview; project.scripts names a different function. | Internally unreferenced helper; not evidence of FP. External consumers unestablished; manifest omitted a label. |
| extreme-grounding query/params | [query_all stub](../dead_code/fixtures/extreme_grounding_framework/services/db.py#L1) returns [] without reading formals; callers pass arguments. | Unread parameters are source-true; intentional API/stub signature may require retention. No automatic removal or FP judgment follows. |
| static-blind-plugin query/params | [query_all stub](../dead_code/fixtures/static_blind_plugin_dispatch/plugins/db.py#L1) ignores formals. | Missing oracle coverage, not demonstrated false detection. |
| static-blind-plugin payload | [fetch_fixed_status](../dead_code/fixtures/static_blind_plugin_dispatch/plugins/network.py#L9) uses fixed URL, ignores payload; generic registry passes one argument. | Source-true unread argument but deliberate callable contract. Removing parameter would break caller shape; strict penalty is not proof of FP. |

## Scoped cross-suite checks

Read default/adversarial/Jev manifests, shared corpus, framework targets, Rake/TerraGoat holdout, historical 70-repository report, real-repository score ledgers and final-five labels. Synthetic or negative-only facts cannot fill missing independent positive denominators.

These searches covered **all files under default manifest fixture paths for the named language**, not just case names:

| Search | Observed | Permitted conclusion |
| --- | --- | --- |
| TS: expo-router or react-email | Zero matches; paired units inspected | Concrete default-fixture promotion gap, not missing support. |
| PHP: Drupal/Plugin/hook-attribute markers | Zero matches; paired Drupal units inspected | That fixture subset lacks these providers; no global absence claim. |
| Kotlin: @Test or kotlin.test | Zero matches; annotation unit inspected | That fixture subset lacks explicit contract; existing unit positive matters. |
| Swift named Codable/reflection/wrapper expectations | unused arrays empty; reflection negative units inspected | Named cases are one-sided, not the whole language's tests. |

These checks cannot exclude differently encoded semantics in every other test, and make no such claim. Earlier blanket statements overlooking C++ macro/template tests, TS Expo/Email tests, PHP Drupal tests or Swift reflection negatives should be withdrawn.

Five [framework targets](../framework_corpus/manifest.json) are Python-only. The guard uses absolute category-count drift, so lower counts fail too. Equal category counts can hide substituted symbol identities; unused-file findings are outside its count list. This is a measurement gap, not evidence that lowering counts passes.

## Required next evidence

Source-review and freeze exact live/dead facts before findings, including an independently justified unused positive beside each framework root where one exists. State public API/generated/test scope; require actual declaration extraction and applicable complete analysis. The 73-fact review now performs that sequence; retain it for future additions. Review each removed warning for exact provider/reference proof and each missed positive for recall impact. Unknowns, policy retention, unsupported scopes and parser/report gaps earn no success credit. Five repositories with only known-used labels do not complete that procedure.

## Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| `benchmarks/dead_code/manifest.json` | `ed93a997edcbb37104348c1f11fc7c7a5df015fcd048a197ee77bb965223ebe8` |
| `benchmarks/dead_code/adversarial_manifest.json` | `679ea87b6d86ceb1dcc7a6f4197fe32151b5e6780e2020b26607de6d51dc91c5` |
| `benchmarks/review_2026_11_17/deadcode-final.json` | `42d83c7a681460670bb4bb7d8d928a4259f15972be53de12c1dedb401a983d80` |
| `benchmarks/review_2026_11_17/deadcode-adversarial-final.json` | `81897c2c1b516eec697f103e81adf3b393ec1ad156d4277f8350f29a445feacf` |
| `benchmarks/review_2026_11_17/blind_manifest.json` | `f40ff39bdec8f5cd6c03fa6a9a16b83a33f53479f619a3538a60f7da26bb1b26` |

## Amendment: the seven Go misses are now isolated

A separate static diagnostic used only the two trusted benchmark fixtures, the same `/tmp/skylos-review-20261117-go` binary, and unchanged labels. No target tests/builds/code were executed and no detector was edited. This supersedes the earlier “loss layer unisolated” statements; old benchmark reports remain unchanged. Reproduction scripts: [initial environment](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/diagnose_go_loss_layer.py), [explicit SDK control](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/diagnose_go_host_sdk.py). Raw reports and hashes: [initial receipt](ARTIFACTS.md), [SDK receipt](ARTIFACTS.md), [provenance](ARTIFACTS.md).

| Controlled condition | Native extraction/reachability | Analyzer result |
| --- | --- | --- |
| Existing environment: GOROOT unset and no `go` executable on PATH | Every function lacks reachability metadata. Private test helpers are omitted. | Isolated fixture copies reproduce all seven missing positives; grep on/off makes no difference. |
| Same binary and source, `GOROOT=/tmp/skylos-gap-go/go` | All seven missing functions have `unreachable`; private test helpers are extracted. | All ten unused expectations across both cases report, with grep on/off. No frozen known-used control reports. |
| Direct in-repository fixture path | Same native SDK failure in initial environment | Separate `benchmark entrypoint path` uncertainty suppresses findings. The benchmark itself copies fixtures to a temporary root, so direct-path silence is not the cause of the saved seven misses. |

The source explains the intervention. The trimmed engine requires a discoverable host SDK ([host_imports.go:22](../../skylos/engines/go/internal/symbols/host_imports.go#L22)); without it, standard-library `testing` cannot be imported ([host_imports.go:94](../../skylos/engines/go/internal/symbols/host_imports.go#L94)). Package type-check failure returns without reachability proof ([reachability.go:90](../../skylos/engines/go/internal/symbols/reachability.go#L90)). The adapter then retains syntactic references unless the target has an explicit `unreachable` attestation ([go.py:112](../../skylos/visitors/languages/go/go.py#L112), [go.py:138](../../skylos/visitors/languages/go/go.py#L138)); the four dead graph functions therefore receive live reference evidence. Private test helpers without reachability are deliberately removed earlier ([symbols.go:429](../../skylos/engines/go/internal/symbols/symbols.go#L429)), accounting for alpha/beta/stale. This is an environment-triggered proof loss, not a demonstrated failure of the rooted graph algorithm when its inputs are available.

`generatedOnly` is separate: native reachability deliberately roots generated declarations ([reachability.go:121](../../skylos/engines/go/internal/symbols/reachability.go#L121)). The explicit SDK arm restores that retention contract. It does not establish runtime use of the uninvoked generated caller or justify redefining its frozen “used” label as semantic reachability truth.

The initial runs still expose `analysis_errors: []` and an available Go engine despite missing type proof. Thus **completion reporting has a concrete gap**: binary availability and successful JSON output do not establish complete Go reachability. Record host SDK identity with engine identity, and distinguish proof-unavailable analysis in future reporting. Do not silently replace the saved results or claim that a detector patch fixed these seven misses.

The exact full default and challenge manifests were then rerun against both saved `analyzer_before` and `analyzer_after` snapshots, with the same hashed Go binary and explicit SDK (`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`). [Per-case comparison](ARTIFACTS.md) proves identical before/after label outcomes across every case. [Before provenance](ARTIFACTS.md) and [after provenance](ARTIFACTS.md) bind snapshots, environment, manifests and captured raw reports.

| Suite with SDK available | Before | After | Interpretation |
| --- | --- | --- | --- |
| Default151 | TP297 / FP0 / FN0 / TN472;151 cases pass | Same | Seven misses and generated-retention mismatch restore equally in both snapshots. This is environment restoration, not a detector improvement. |
| Challenge17 | TP30 / strict-unlabelled6 / FN12 / TN95;8 cases pass | Same | Existing challenge limitations remain. The six strict penalties retain the source interpretation above. |

Only the two diagnosed Go cases differ from their saved no-SDK results. The old files and all frozen labels remain unchanged. Reproduction: [run_deadcode_sdk.py](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/run_deadcode_sdk.py); [default before](ARTIFACTS.md), [default after](ARTIFACTS.md), [challenge before](ARTIFACTS.md), [challenge after](ARTIFACTS.md). These deterministic labels still cannot establish whole-repository accuracy.
