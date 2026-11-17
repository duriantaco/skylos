# Corpus inventory and precision risks — 17 November 2026

Later additions are documented in the [source-reviewed audit](ground_truth_audit/confirmed_results.md):
five fresh repositories (Pyee, Blinker, Regexparam, Trouter and Goji), three
exact-location security cases with nine independently reviewed labels, and a
versioned 151-case manifest correcting three old liveness labels. The corrected
manifest reuses the original fixtures and is not an independent new corpus.
Full source ledgers, competitor output and per-row adjudications accompany it.

This inventory describes the task-start manifests and available historical evidence. It does not claim a suite passed, label unreviewed warnings as false positives, or count missing/unsupported analysis as safe. New execution results and the five newly selected repositories belong in the companion benchmark update. These existing fixtures have already been used for development and are not blind evaluation data.

## Main findings

- The shared corpus contains **84 cases / 330 assertions**: 186 absence and 144 presence checks. **77 of 84** cases contain Python; just seven contain other source languages without Python. It is primarily a Python/framework regression guard, not a balanced cross-language benchmark.
- The default dead-code suite contains **151 cases / 769 selected-symbol labels** (297 unused, 472 used). The default security suite contains **277 cases / 290 selected rule-presence labels** (150 present, 140 absent). Multi-language cases are counted once in these totals.
- The task-start security scorer matched rule presence anywhere in a case. **Concurrent current source now supports exact rule/file/line-range labels and fixes the zero-sum F1 fallback; this review team did not author those changes.** All 290 default expectations still use legacy strings, so a wrong-location warning can satisfy those labels and unlabelled findings remain unscored. The remaining default-corpus issue is **label granularity/migration**, not absent structured-matching support or evidence that a detector is wrong. See [scorer provenance](SCORER_CHANGE_PROVENANCE.md).
- The framework repository corpus has only **five Python repositories** and gates absolute per-category count drift; its zero tolerance rejects lower as well as higher counts. Equal category counts can still conceal substituted symbol identities, and the guard does not score unused-file findings. It does not establish improved accuracy.
- Desktop evidence has **91 target output directories / 2,305 files**, plus logs. Only 57 targets retain any Skylos JSON; saved main dead-code and all-check reports exist for 56 and 50 targets respectively. A directory or successful command log is not a recoverable scored result.
- Previous reports contain both genuine logic defects and incomplete measurement. They must remain separated: known-used controls alone cannot demonstrate recall, and removed warnings that become explicit unknowns are not true-negative wins.

## Suite inventory

| Manifest | Entries | Declared/inferred fixture languages | Evidence type |
| --- | --- | --- | --- |
| [corpus/manifest.json](../../corpus/manifest.json) | 84 cases | Astro, Svelte, Vue, javascript, php, python, shell, typescript | Regression fixtures |
| [benchmarks/agent_behavior/manifest.json](../../benchmarks/agent_behavior/manifest.json) | 3 cases | See manifest | Regression fixtures |
| [benchmarks/agent_review/adversarial_manifest.json](../../benchmarks/agent_review/adversarial_manifest.json) | 2 cases | python | Separate challenge contracts; unresolved outcomes remain visible; LLM execution is optional and provider-dependent |
| [benchmarks/agent_review/manifest.json](../../benchmarks/agent_review/manifest.json) | 25 cases | python | Regression fixtures; LLM execution is optional and provider-dependent |
| [benchmarks/ai_code_defects/manifest.json](../../benchmarks/ai_code_defects/manifest.json) | 56 cases | cpp, csharp, dart, go, java, javascript, kotlin, php, python, ruby, rust, shell, swift, typescript | Regression fixtures |
| [benchmarks/cleanup/2026-11-10/manifest.json](../../benchmarks/cleanup/2026-11-10/manifest.json) | 5 repositories | See manifest | Pinned exploratory cleanup study; no automatic deletion |
| [benchmarks/cloud/manifest.json](../../benchmarks/cloud/manifest.json) | 22 cases | hcl | Regression fixtures |
| [benchmarks/dead_code/adversarial_manifest.json](../../benchmarks/dead_code/adversarial_manifest.json) | 17 cases | csharp, javascript, python | Separate challenge contracts; unresolved outcomes remain visible |
| [benchmarks/dead_code/jev_challenge_manifest.json](../../benchmarks/dead_code/jev_challenge_manifest.json) | 1 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_dispatch_matrix_manifest.json](../../benchmarks/dead_code/jev_dispatch_matrix_manifest.json) | 2 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_hard_matrix_manifest.json](../../benchmarks/dead_code/jev_hard_matrix_manifest.json) | 3 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_hard_suite_manifest.json](../../benchmarks/dead_code/jev_hard_suite_manifest.json) | 5 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_hard_suite_v2_manifest.json](../../benchmarks/dead_code/jev_hard_suite_v2_manifest.json) | 8 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_method_surface_manifest.json](../../benchmarks/dead_code/jev_method_surface_manifest.json) | 1 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_package_surface_manifest.json](../../benchmarks/dead_code/jev_package_surface_manifest.json) | 1 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/jev_realistic_repo_manifest.json](../../benchmarks/dead_code/jev_realistic_repo_manifest.json) | 1 cases | python | Synthetic Jev research; overlaps other suites, not additive independent evidence |
| [benchmarks/dead_code/manifest.json](../../benchmarks/dead_code/manifest.json) | 151 cases | cpp, csharp, dart, go, java, javascript, kotlin, php, python, ruby, rust, swift, typescript | Regression fixtures |
| [benchmarks/done_gate/manifest.json](../../benchmarks/done_gate/manifest.json) | 1 external source; 2 exclusions | See manifest | External agent-run replay; distinct benchmark question |
| [benchmarks/framework_corpus/manifest.json](../../benchmarks/framework_corpus/manifest.json) | 5 targets | See manifest | Pinned repository count-drift guard; Python only |
| [benchmarks/holdouts/manifest.json](../../benchmarks/holdouts/manifest.json) | 2 targets | See manifest | Pinned open-set source facts; Ruby Rake and Terraform TerraGoat |
| [benchmarks/output_validation/manifest.json](../../benchmarks/output_validation/manifest.json) | 20 cases | See manifest | Regression fixtures |
| [benchmarks/quality/manifest.json](../../benchmarks/quality/manifest.json) | 33 cases | csharp, go, java, python, rust, typescript | Regression fixtures |
| [benchmarks/secrets/cross_language_manifest.json](../../benchmarks/secrets/cross_language_manifest.json) | 16 cases | See manifest | Regression fixtures |
| [benchmarks/secrets/manifest.json](../../benchmarks/secrets/manifest.json) | 20 cases | See manifest | Regression fixtures |
| [benchmarks/security/adversarial_manifest.json](../../benchmarks/security/adversarial_manifest.json) | 9 cases | dart, go, kotlin | Separate challenge contracts; unresolved outcomes remain visible |
| [benchmarks/security/manifest.json](../../benchmarks/security/manifest.json) | 277 cases | csharp, dart, go, java, kotlin, php, python, ruby, rust, shell, typescript | Regression fixtures |
| [benchmarks/verify_benchmark/manifest.json](../../benchmarks/verify_benchmark/manifest.json) | 10 cases | python | Regression fixtures |

Counts are entries, not disjoint populations: Jev suites reuse fixtures; cases may cover several languages; corpus and regression suites can encode the same contract. A manifest path does not imply its target checkout exists locally.

### Additional corpora outside manifest naming

| Artifact | Scope | Validity limit |
| --- | --- | --- |
| [benchmarks/holdout_2026_11_08/REPORT.md](../../benchmarks/holdout_2026_11_08/REPORT.md) | 70 pinned repositories, 14 language strata, 651 source-first candidates | 562 retained, 1 unused, 29 safe, 0 unsafe, 59 unknown. The sole unused positive failed parsing; recall was not measurable. |
| [benchmarks/holdout_2026_11_08/REMEASURE_EVIDENCE.json](../../benchmarks/holdout_2026_11_08/REMEASURE_EVIDENCE.json) | 10 Dart/C# repositories, post-fix remeasurement | 309 original false warnings became 20; 12 removed warnings abstained. Three known-unused observations stayed reported. Now development data. |
| [benchmarks/security/holdout_2026_11_09/labels.json](../../benchmarks/security/holdout_2026_11_09/labels.json) | HTTPie, Datasette, ArchiveBox; 217 reviewed union rows | Final historical engine: 1 REAL, 26 NOISE, 97 WRONG, 36 UNRESOLVED. Post-scan source classification is not a population recall estimate. |
| [benchmarks/dead_code/real_repo_scores/2026-11-07.json](../../benchmarks/dead_code/real_repo_scores/2026-11-07.json) | p-queue, mitt, xid, uuid, arrayvec, memchr, LRUCache, SwiftSoup | Pinned eight-repository evidence; review its scope before pooling. |
| [benchmarks/dead_code/external_targets.json](../../benchmarks/dead_code/external_targets.json) | skylos-demo; 12 unused and 12 used labels | Selected labels; many unlabelled findings; local checkout required. |
| [benchmarks/holdouts/analysis_gap_manual_2026_11_16.json](../../benchmarks/holdouts/analysis_gap_manual_2026_11_16.json) | vitesse-lite, defu, laravel/prompts, fmt | Open-set manual source review; not exhaustive truth. |
| [benchmarks/holdouts/analysis_gap_before_after_2026_11_16.json](../../benchmarks/holdouts/analysis_gap_before_after_2026_11_16.json) | Matched reruns of those four repositories | Post-development controls; no longer unseen. |
| [benchmarks/dead_code/source_label_review_2026_11_16.json](../../benchmarks/dead_code/source_label_review_2026_11_16.json) | Nineteen previously unlabelled findings in eight existing fixtures | Source-based label repairs; not new independent accuracy evidence. |
| [benchmarks/agent-pr-bench/corpus/real_commits.json](../../benchmarks/agent-pr-bench/corpus/real_commits.json) | 36 selected real commits | Agent-attribution and review benchmark; different categories/scope from scanner-wide accuracy. |
| [benchmarks/deep_audit_logic/expected.json](../../benchmarks/deep_audit_logic/expected.json) | 11 deep-audit logic cases | Separate logic evidence; do not merge into dead-code/security denominators. |

## Cross-language balance and gaps

| Language | Dead-code cases | Unused / used labels | Security cases | Present / absent labels |
| --- | --- | --- | --- | --- |
| cpp | 3 | 4 / 6 | 0 | 0 / 0 |
| csharp | 9 | 25 / 33 | 19 | 8 / 11 |
| dart | 5 | 11 / 17 | 6 | 3 / 3 |
| go | 10 | 28 / 39 | 41 | 24 / 17 |
| java | 4 | 12 / 12 | 21 | 10 / 13 |
| javascript | 12 | 47 / 30 | 0 | 0 / 0 |
| kotlin | 4 | 6 / 14 | 18 | 10 / 8 |
| php | 4 | 6 / 14 | 8 | 5 / 3 |
| python | 27 | 54 / 98 | 84 | 46 / 44 |
| ruby | 7 | 13 / 25 | 4 | 2 / 2 |
| rust | 11 | 19 / 49 | 15 | 8 / 7 |
| shell | 0 | 0 / 0 | 13 | 8 / 5 |
| swift | 30 | 25 / 72 | 0 | 0 / 0 |
| typescript | 32 | 77 / 86 | 58 | 30 / 34 |

This table follows declared manifest languages (default Python), and attributes each mixed case to every declared language. Consequently columns sum above unique totals. Security has no JavaScript-specific declared cases, despite JS/TS sharing some implementation. C++ and Swift have no default security cases. Shell has no default dead-code cases. These are evidence gaps, not claims about complete capability.

### Missing counterparts in the default security suite

| Language | Rule | Missing default-suite counterpart |
| --- | --- | --- |
| java | SKY-S101 | positive case |
| python | SKY-D206 | positive case |
| python | SKY-D217 | positive case |
| python | SKY-D231 | safe/lookalike control |
| python | SKY-D232 | safe/lookalike control |
| python | SKY-D345 | safe/lookalike control |
| shell | SKY-D212 | safe/lookalike control |
| typescript | SKY-D211 | positive case |
| typescript | SKY-S102 | positive case |

A paired rule can still lack framework-specific sources, wrappers, receiver identity, cross-file flow, sanitizer rebinding, or positive reachability controls. Count balance is only the first screen. Multi-language secrets cases need per-file labels before their individual language coverage can be claimed precisely.

## Noise causes, logic gaps and regression risks

| Area | Evidence and classification | Why noise/misses happen | Small next step and breakage guard |
| --- | --- | --- | --- |
| Security scoring | Baseline missing-location support is fixed by concurrent current source; default manifest still has 290 legacy string expectations | Those legacy labels cannot prove the correct sink was found; unlabelled findings remain outside the selected-label score | Use the now-implemented exact rule/file/line-range form for reviewed paired fixtures; retain old positives and keep unknowns unscored. This is remaining corpus migration, not an unresolved scorer implementation gap. |
| Framework count baseline | Confirmed evidence gap: five Python targets in framework_corpus | Counts do not identify declarations; one disappearing TP can cancel a new FP | Add frozen used/unused symbol facts and parse/definition checks; keep count drift only as a smoke test. |
| Python-heavy shared corpus | Confirmed coverage imbalance: 77/84 cases contain Python | Framework root/registration contracts from other languages receive little shared-corpus pressure | Add native paired controls for documented registration and public API roots; same-name unrelated owners and unmounted registrations must remain detectable. |
| C#/Dart native binding | Historical demonstrated defects; REMEASURE.md documents remaining cases, not a fresh current reproduction | Missing callback, receiver, extension, public API and generator identity caused many false dead-code claims | Bind exact owner/provider using source evidence; retain unused sibling, shadowing and ambiguous-provider controls. Abstention cannot be scored as safe. |
| Java/PHP framework roots | Historical demonstrated false alerts in Nov 8 report | Reflectively selected Java adapters and registered PHP stream filters lack direct constructor/call sites | Prove registrations and selected names; avoid whitelisting every class with the same base or method prefix. |
| JS/TS framework loaders | Existing source-backed cleanup audit; newer fixes already encoded in corpus | Entrypoints launched by scripts and code consumed as data do not look like imports | Resolve exact script operands/asset paths/components; do not keep neighbouring orphan files or all exports live. Test fresh framework versions separately. |
| Go security aliases | Existing documented unresolved challenge contracts; not rerun by this inventory | Callable aliases, copied client methods, request type aliases and field assignment need semantic identity/flow | Handle exact provider and source propagation with safe/unsafe shadowed-provider pairs; do not suppress by friendly names. |
| Dart sanitizers | Existing documented unresolved challenge contracts; not rerun by this inventory | A helper name alone can be mistaken for a sanitizer | Require provider and sink-specific safety evidence; retain identity helpers and tainted lookalikes as positive controls. |
| Python random aliases | Existing documented unresolved challenge contract; not rerun by this inventory | Copied method identity can be lost after an imported module binding changes | Track binding at capture time; pair cryptographic providers and rebinding controls. |
| Security context / policy vs vulnerability | Historical Nov 9 labels explicitly distinguish REAL/NOISE/WRONG/UNRESOLVED | An operation can be real while its input is operator-configured or a security impact is unproven | Preserve evidence and uncertainty; reduce false claims only with source-to-sink/constant/allowlist proof. Do not suppress all helper parameters or all test paths. |
| Generated/vendored/test code | Historical cleanup and Nov 8 source classifications | Expected test probes or generated catalogs can be unactionable despite a mechanically true observation | Report scope and generated-code policy separately. Do not call excluded material safe or add repository-name exceptions. |
| Cross-language security breadth | Manifest inventory: Rust/Dart/Ruby/PHP have relatively few rule families | A clean small suite says little about framework request sources or missing sink families | Add independently source-labelled cases for implemented combinations first; unsupported language/rule combinations remain unscored. |
| Incomplete parsing/tooling | Historical 70-repo report: 20 incomplete primary scans | Missing definitions and failed native/toolchain scopes can resemble quiet scans | Require source hash, expected definition, positive file/parse coverage and complete status before awarding absence credit. |
| Desktop reproducibility | Confirmed missing report/labels/checkouts in recovered Desktop tree | Raw warnings and command receipts cannot reconstruct adjudicated truth, scan source or consistent before/after cohorts | Preserve raw files; reconstruct only observable counts/status. Do not regenerate a claimed confirmed accuracy table from counts alone. |

The lowest-risk improvement is stronger measurement plus exact reference/provider binding. Broadly increasing confidence thresholds, ignoring test directories, whitelisting framework classes or treating sanitizer names as proof can reduce warnings while silently losing recall. Any detector change needs positive controls beside the quiet example, unchanged frozen old labels, and held-out source facts selected before target findings are viewed.

## Complete shared-corpus case list

| Case | Source languages | Present / absent | Categories | Contract |
| --- | --- | --- | --- | --- |
| flask-route-handler | python | 1 / 1 | unused_functions | Flask route handlers are framework entrypoints, not dead code. |
| fastapi-depends-route | python | 1 / 2 | unused_functions | FastAPI route functions and Depends providers should stay alive. |
| celery-task | python | 1 / 1 | unused_functions | Celery tasks are worker entrypoints and should not be flagged. |
| pluggy-hookimpl | python | 1 / 1 | unused_functions | Pluggy hook implementations are invoked by the plugin manager. |
| pytest-plugin-hooks | python | 2 / 7 | unused_functions, unused_parameters | Pytest plugin hooks should not regress into dead-code findings. |
| typer-callback | python | 1 / 1 | unused_functions | Typer callback functions are CLI entrypoints. |
| starlette-add-route | python | 1 / 1 | unused_functions | Imperative Starlette route registration should keep handlers alive. |
| sanic-register-listener | python | 1 / 1 | unused_functions | Sanic listener registration should keep async callbacks alive. |
| django-urlpatterns | python | 1 / 1 | unused_functions | Django URL patterns should keep view functions alive. |
| django-error-handlers | python | 1 / 4 | unused_variables | Django root URLconf error handler aliases should not be flagged as dead variables. |
| django-path-converter | python | 4 / 5 | unused_classes, unused_functions, unused_variables | Django custom path converter protocol members should stay alive when the converter class is registered in URLconf. |
| gunicorn-config | python | 2 / 12 | unused_functions, unused_variables | Gunicorn config settings and lifecycle hooks should not be flagged as dead code. |
| django-class-based-view | python | 2 / 3 | unused_classes, unused_functions | Django class-based views should not be treated as dead framework classes. |
| drf-viewset | python | 2 / 3 | unused_classes, unused_functions | DRF viewsets should keep action methods and classes alive. |
| drf-serializer | python | 3 / 4 | unused_classes, unused_functions, unused_variables | DRF serializer classes, fields, and validator methods are framework-owned. |
| sqlalchemy-model | python | 3 / 3 | unused_classes, unused_variables | SQLAlchemy declarative model classes and columns should not regress into dead-code reports. |
| fastapi-pydantic-model | python | 3 / 4 | unused_classes, unused_functions | FastAPI route models and pydantic validators should stay alive. |
| pydantic-settings-model | python | 1 / 1 | unused_classes | Pydantic settings models should not be flagged as dead classes. |
| aiohttp-routes | python | 2 / 2 | unused_functions, unused_parameters | aiohttp route table decorators should keep handlers alive. |
| attrs-define-fields | python | 2 / 2 | unused_variables | attrs fields should not be reported as unused variables. |
| always-false-loop | python | 2 / 0 | quality | An always-false loop body should be reported as unreachable dead branch. |
| marshmallow-schema | python | 2 / 3 | unused_classes, unused_functions | Marshmallow schema classes and lifecycle hooks should not be treated as dead code. |
| sqlalchemy-event-listener | python | 2 / 3 | unused_functions, unused_parameters | Imperative SQLAlchemy event listeners should keep callbacks alive. |
| flask-add-url-rule | python | 1 / 1 | unused_functions | Imperative Flask route registration should keep handlers alive. |
| fastapi-add-api-route | python | 1 / 1 | unused_functions | Imperative FastAPI route registration should keep endpoint callables alive. |
| fastapi-include-router | python | 1 / 1 | unused_functions | APIRouter handlers should stay alive when the router is included on the app. |
| django-management-command | python | 2 / 2 | unused_classes, unused_functions | Django management command handlers are framework entrypoints. |
| django-signal-receiver | python | 1 / 1 | unused_functions | Django signal receivers should not be reported as dead code. |
| sqlalchemy-listens-for | python | 2 / 3 | unused_functions, unused_parameters | Decorator-based SQLAlchemy event listeners should keep callbacks alive. |
| marshmallow-validates-schema | python | 2 / 2 | unused_classes, unused_functions | Marshmallow schema validators are framework-owned callbacks. |
| python-cached-property | python | 1 / 1 | unused_functions | cached_property accessors are runtime attributes, not dead methods. |
| python-property-chain | python | 1 / 1 | unused_functions | Property getters and setters should stay alive as a linked descriptor chain. |
| python-type-checking-imports | python | 1 / 1 | unused_imports | TYPE_CHECKING-only imports used in annotations should not be flagged as unused imports. |
| python-public-api-exports | python | 2 / 2 | unused_classes, unused_functions | Explicit package exports in __init__.py/__all__ should protect public API symbols. |
| python-pyproject-entrypoint | python | 1 / 1 | unused_functions | PEP 621 script entrypoints declared in pyproject.toml should keep target callables alive. |
| django-admin-register | python | 1 / 1 | unused_classes | Django admin registrations should keep admin classes alive. |
| django-appconfig-ready | python | 2 / 2 | unused_classes, unused_functions | Django AppConfig classes and ready hooks are framework lifecycle entrypoints. |
| celery-task-class | python | 2 / 2 | unused_classes, unused_functions | Custom Celery task subclasses and run methods should not be reported as dead code. |
| click-command-subclass | python | 2 / 3 | dead_code_abstentions, unused_classes, unused_functions | Click command subclasses and invoke methods should stay alive. |
| pydantic-computed-field | python | 2 / 3 | dead_code_abstentions, unused_classes, unused_functions | Pydantic computed fields are runtime-backed descriptors, not dead methods. |
| pydantic-serializer-hooks | python | 3 / 3 | unused_classes, unused_functions | Pydantic serializer hooks should not be treated as dead callback methods. |
| pydantic-model-post-init | python | 2 / 2 | unused_classes, unused_functions | Pydantic lifecycle hooks like model_post_init should not regress into dead-code findings. |
| python-enum-members | python | 1 / 2 | unused_variables | Enum members are runtime-accessed through the enum class and should not be flagged as dead variables. |
| python-abstract-base | python | 1 / 1 | unused_functions | Abstract base class declarations are contracts, not dead code. |
| python-protocol-implementation | python | 1 / 1 | unused_functions | Protocol implementations should not regress into dead method findings. |
| sqlalchemy-hybrid-property | python | 1 / 1 | unused_functions | SQLAlchemy hybrid properties behave like descriptors and should not be flagged as dead methods. |
| python-unittest-lifecycle | python | 2 / 5 | unused_functions, whitelisted | unittest lifecycle hooks should not be reported as dead code in test files. |
| runtime-dependent-loop | python | 0 / 2 | quality | A loop whose condition depends on an input collection remains reachable. |
| pydantic-model-use-boundary | python | 2 / 2 | unused_classes | Constructed model/settings classes stay live while unreferenced siblings remain findings. |
| typing-protocol-attributes | python | 3 / 1 | unused_variables | Attributes declared on a typing.Protocol are contract members, not dead code. |
| cleanup-async-blocking-problematic | python | 1 / 0 | quality | A synchronous HTTP request inside a coroutine blocks its event-loop thread. |
| cleanup-async-blocking-control | python | 0 / 1 | quality | The paired coroutine awaits an asynchronous HTTP client request. |
| cleanup-mutable-default-problematic | python | 1 / 0 | quality | Mutating a default dictionary leaks badge assignments across calls that omit the mapping. |
| cleanup-mutable-default-control | python | 0 / 1 | quality | A None default creates a fresh mapping for each call that omits it. |
| test-quality-constant-assertion-problematic | python | 1 / 0 | quality | A literal-true assertion does not check a runtime result; the counterpart checks an actual function result. |
| test-quality-constant-assertion-control | python | 0 / 1 | quality | A literal-true assertion does not check a runtime result; the counterpart checks an actual function result. |
| test-quality-empty-test-problematic | python | 1 / 0 | quality | A placeholder-only test body merits review; the counterpart delegates to an asserting helper. |
| test-quality-empty-test-control | python | 0 / 1 | quality | A placeholder-only test body merits review; the counterpart delegates to an asserting helper. |
| test-quality-duplicate-assertion-problematic | python | 1 / 0 | quality | An adjacent repeated assertion over a proven builtin integer adds no distinct check; the counterpart checks another property. |
| test-quality-duplicate-assertion-control | python | 0 / 1 | quality | An adjacent repeated assertion over a proven builtin integer adds no distinct check; the counterpart checks another property. |
| test-quality-sleep-completion-problematic | python | 1 / 0 | quality | A fixed delay before checking an Event can race with completion; the counterpart waits for an explicit signal with a bounded timeout. |
| test-quality-sleep-completion-control | python | 0 / 1 | quality | A fixed delay before checking an Event can race with completion; the counterpart waits for an explicit signal with a bounded timeout. |
| test-quality-flow-reachable | python | 3 / 0 | quality | Conditional loop exits preserve reachable constant, repeated-assertion and Event synchronization findings. |
| test-quality-flow-unreachable | python | 0 / 3 | quality | Unconditional loop exits leave later weak-test patterns unreachable; no weak-test advice should be emitted for them. |
| test-quality-collection-mutation | python | 0 / 2 | quality | Opted-out and namespace-removed functions are not collected tests. |
| test-quality-collection-live | python | 1 / 0 | quality | Read-only metadata and namespace inspection preserve an ordinary collected test. |
| cleanup-fstring-debug-label | python | 0 / 1 | quality | Debug f-string expression text contributes to output and must not be claimed equivalent to a different expression label. |
| cleanup-fstring-ordinary-field | python | 1 / 0 | quality | A literal prefix resembling a debug label does not suppress an ordinary equivalent f-string conversion. |
| typescript-npx-entrypoint | shell, typescript | 1 / 1 | unused_files | A known npx TypeScript runtime invokes its script operand; an unreferenced sibling remains dead. |
| typescript-source-assets | javascript, typescript | 4 / 6 | unused_files, unused_functions | Live native filesystem reads consume exact source assets and their public exports; unselected siblings and lookalike directories remain unused. |
| python-dependency-probe | python | 1 / 1 | quality | A finite native importlib.util.find_spec loop is dependency exposure; an unrelated declared dependency still reports. |
| python-src-package-routes | python | 2 / 3 | unused_functions | FastAPI routes in a top-level package named src, imported as src.api.routes, stay alive when their router is included; an unmounted router and a plain helper are still reported. |
| python-wrapper-decorator-registration | python | 7 / 6 | unused_functions | A project decorator that applies a server tool registration to its argument keeps decorated functions alive; decorators that only wrap, cache or return the function do not. |
| python-decorator-factory-registration | python | 5 / 2 | unused_functions | A third-party decorator factory called with a key registers the function; standard-library and retry wrappers, project wrap-only factories and argument-less calls do not. |
| python-string-forward-references | python | 4 / 8 | unused_classes, unused_imports, unused_variables | Strings inside typing subscripts, cast() and TypeVar(bound=...) are forward references; names that only appear in prose strings are still reported. |
| python-dotted-path-registry | python | 3 / 2 | unused_classes | Classes named by full dotted path in a registry that a reachable function resolves with import_module and getattr stay alive; an unresolved path, an unused registry and an unlisted class are still reported. |
| python-local-import-binding | python | 4 / 4 | unused_imports | A function-local import that rebinds a parameter and is then read is used, and importing readline is an import for effect; unread, overwritten and ordinary unused imports are still reported. |
| python-base-class-protocol-members | python | 4 / 7 | unused_classes, unused_functions, unused_variables | Members a documented base class reads by name stay alive (twisted Resource render_<METHOD>, distutils Command option attributes, pydantic inner Config); other members of the same classes are still reported. |
| python-exec-namespace | python | 4 / 5 | unused_functions, unused_imports | Module bindings handed to exec(code, globals()), including names copied in by a star import, stay alive; imports beside exec/eval with a fresh namespace are still reported. |
| frontend-component-import-graph | Astro, Svelte, Vue, typescript | 5 / 3 | unused_files, unused_functions | Component imports retain exact helper bindings through Vue, Svelte and Astro without loading orphan components. |
| module-local-enum-members | typescript | 1 / 5 | unused_variables | Unused members of a local enum are distinguished from used members and opaque/public enum boundaries. |
| npm-dependency-usage | typescript | 3 / 5 | quality | Complete package usage distinguishes unused declarations, undeclared imports and undeclared script binaries. |
| php-blade-helper-consumers | php | 2 / 2 | unused_classes, unused_functions | Blade reads preserve used helpers and owning classes beside unused siblings. |
| private-exported-enum-members | typescript | 1 / 1 | unused_variables | Private package enum imports preserve consumed members and report an unused sibling by exact provider identity. |

## Complete default dead-code case list

| Case | Declared languages | Unused / used | Taxonomy | Contract |
| --- | --- | --- | --- | --- |
| basic-unused-symbols | python | 5 / 3 | basic_detection | Basic unused functions, classes, imports, and module variables should be found while referenced symbols stay alive. |
| fastapi-route-used | python | 1 / 2 | framework_precision, fastapi | FastAPI route handlers and dependency providers are framework entrypoints, not dead code. |
| dynamic-registry-used | python | 2 / 2 | dynamic_dispatch, precision_guard | Handlers registered through an explicit local registry should stay alive while unregistered handlers are reported. |
| local-registration-decorator-entrypoints | python | 2 / 5 | dynamic_dispatch, precision_guard | Locally defined decorators that register and return functions should keep decorated entrypoints alive while unregistered helpers are still reported. |
| explicit-same-name-reexports | python | 2 / 2 | package_entrypoint, precision_guard | Python explicit same-name aliases are public re-export signals and should not be reported as unused imports. |
| annotation-metadata-import-scope | python | 3 / 2 | pydantic, precision_guard | Annotation metadata should bind to imported decorators even when a function parameter has the same leaf name. |
| sqlalchemy-mixed-models | python | 2 / 7 | sqlalchemy, multi_file, precision_guard | A realistic model module should report only the unreferenced SQLAlchemy model while keeping used models and ORM columns quiet. |
| flask-cli-blueprint | python | 2 / 3 | framework_precision, flask, cli_entrypoint, precision_guard | Flask blueprint routes and app CLI commands are entrypoints, while nearby unregistered helpers remain dead code. |
| package-service-layers | python | 5 / 4 | multi_file, service_layer, basic_detection | A small service/repository package should resolve cross-file references and still find stale local strategy code. |
| django-management-command | python | 2 / 6 | framework_precision, django, cli_entrypoint, precision_guard | Django management command classes and lifecycle methods are CLI entrypoints while unrelated helpers remain dead code. |
| celery-task-entrypoints | python | 2 / 3 | framework_precision, celery, dynamic_dispatch, precision_guard | Celery task decorators should keep worker functions alive while unregistered helpers are reported. |
| pytest-fixture-entrypoints | python | 0 / 3 | framework_precision, pytest, dynamic_dispatch, precision_guard | Pytest tests and fixtures are runtime entrypoints even when referenced through parameter injection. |
| pydantic-validator-entrypoints | python | 3 / 7 | framework_precision, pydantic, precision_guard | Pydantic validators are framework-called methods while unrelated helpers are still reportable. |
| alembic-migration-entrypoints | python | 2 / 4 | framework_precision, alembic, precision_guard | Alembic migration lifecycle functions and revision metadata are entrypoints; helper code can still be dead. |
| importlib-plugin-loading | python | 4 / 4 | dynamic_dispatch, plugin_loading, precision_guard | String-based importlib plugin loading should keep loaded plugin hooks alive while stale plugin code is reported. |
| package-entrypoints | python | 0 / 2 | package_entrypoint, cli_entrypoint, precision_guard | pyproject project.scripts entrypoints should keep CLI functions alive. |
| go-service-entrypoints | go | 1 / 3 | go, basic_detection, precision_guard | Go HTTP handler references should keep live handlers reachable while stale package-private helpers are reported. |
| java-service-entrypoints | java | 2 / 4 | java, basic_detection, precision_guard | Java application entrypoints and method calls should stay live while unused methods and classes are reported. |
| java-fxml-controller-callbacks | java | 2 / 2 | java, framework_precision, precision_guard | JavaFX methods wired through FXML action metadata are framework callbacks, while unwired @FXML methods and ordinary helpers remain dead code. |
| typescript-vscode-pseudoterminal-callbacks | typescript | 2 / 7 | typescript, framework_precision, precision_guard | VS Code Pseudoterminal and provider contract methods are host-invoked callbacks, while unrelated methods on the same classes remain dead code. |
| ts-js-package-reachability | typescript, javascript | 3 / 2 | typescript, javascript, package_entrypoint, basic_detection, precision_guard | TypeScript package entrypoints and imports should keep live exports reachable while stale TS and JS exports are reported. |
| robot-programmatic-library | python | 1 / 1 | framework_precision, dynamic_dispatch, precision_guard | A native Robot library decorator applied as a function retains its keyword and leaves an unregistered helper unused. |
| robot-variable-object-methods | python | 2 / 1 | framework_precision, multi_file, precision_guard | Robot variable expressions call the exact exported object method while unused helpers and another object remain reported. |
| robot-variable-literal-control | python | 1 / 0 | framework_precision, precision_guard | Escaped Robot variable text, comments and a constant-false branch do not call an exported object method. |
| wildcard-provider-binding | python | 1 / 1 | multi_file, precision_guard | A package consumer reads the exact wildcard-exported import binding without retaining an unrelated import of the same module. |
| finite-globals-dispatch | python | 1 / 2 | dynamic_dispatch, precision_guard | A reachable caller selects a literal callback name through globals without retaining an unselected callback. |
| finite-inherited-method-registry | python | 2 / 4 | dynamic_dispatch, multi_file, precision_guard | An inherited receiver dispatches through a finite tuple-valued method registry and leaves unrelated or unselected methods unused. |
| php-direct-calls | php | 1 / 2 | php, basic_detection, precision_guard | Native PHP source-owned calls and unreferenced siblings. |
| php-member-calls | php | 1 / 3 | php, basic_detection, precision_guard | Native PHP source-owned calls and unreferenced siblings. |
| csharp-private-call-chain | csharp | 1 / 4 | csharp, basic_detection, precision_guard | Main constructs Pipeline and calls Emit→Normalize; Parse has no call, registration, reflection or exported API in this executable. |
| kotlin-private-call-chain | kotlin | 1 / 3 | kotlin, basic_detection, precision_guard | main calls displayRecord→formatRecord; private parseRecord has no caller or exposed entrypoint. |
| kotlin-owner-call-identity | kotlin | 1 / 5 | kotlin, basic_detection, precision_guard | main constructs both classes, but only Primary.run calls its private process. Same-spelled Secondary.process remains uncalled; constructing the owner prevents dead-parent aggregation. |
| csharp-top-level-owner-identity | csharp | 1 / 4 | csharp, multi_file, precision_guard | Top-level application statements construct both namespace-specific workers; only the Primary owner calls its private Process method. |
| rust-direct-calls | rust | 1 / 3 | rust, basic_detection, precision_guard | Closed source calls retain the selected implementation and report unreferenced siblings. |
| rust-member-owners | rust | 2 / 5 | rust, basic_detection, precision_guard | Concrete receiver calls retain only the selected member owner. |
| dart-direct-calls | dart | 1 / 3 | dart, basic_detection, precision_guard | Closed source calls retain the selected implementation and report unreferenced siblings. |
| dart-member-owners | dart | 2 / 6 | dart, basic_detection, precision_guard | Concrete receiver calls retain only the selected member owner. |
| cpp-direct-call-chain | cpp | 1 / 3 | cpp, basic_detection, precision_guard | Main calls render, which calls normalize; file-local summarize has no caller, address reference, macro or exported contract. |
| cpp-address-taken-callback | cpp | 1 / 2 | cpp, basic_detection, precision_guard | The address of parse_record flows into the called function pointer; serialize_record has no reference. This is file-local free-function coverage, not C++ linking/template/class analysis. |
| ruby-private-chain | ruby | 1 / 4 | ruby, precision_guard | Ruby private chain; bounded native Ruby source contract. |
| ruby-member-owners | ruby | 1 / 4 | ruby, precision_guard | Ruby member owners; bounded native Ruby source contract. |
| ruby-callback-owner | ruby | 2 / 6 | ruby, precision_guard | Ruby callback owner; bounded native Ruby source contract. |
| ruby-block-scope | ruby | 1 / 1 | ruby, precision_guard | Ruby closure parameter scope and outer method identity. |
| ruby-inherited-callback | ruby | 1 / 1 | ruby, precision_guard, framework_precision | Ruby Rails callbacks through source-visible ApplicationController ancestry. |
| typescript-javascript-namespace-members | typescript, javascript | 2 / 3 | typescript, javascript, basic_detection, precision_guard | Static namespace member reads and stable aliases retain selected exports without crediting unrelated or shadowed members. |
| typescript-namespace-escape-boundaries | typescript | 1 / 4 | typescript, dynamic_dispatch, precision_guard, basic_detection | Escaped namespaces and dynamic member keys keep all their exports while an unrelated internal helper remains unused. |
| go-dead-call-graph | go | 6 / 8 | go, basic_detection, precision_guard | Private Go declaration-use roots and object identity, with genuine used and unused controls. |
| go-scope-identity | go | 3 / 2 | go, basic_detection, precision_guard | Private Go declaration-use roots and object identity, with genuine used and unused controls. |
| rust-value-bindings | rust | 1 / 3 | rust, precision_guard, basic_detection | Real callback initializer references remain live while shadowed parameter and local reads do not rescue an unrelated function. |
| rust-callback-scopes | rust | 2 / 5 | rust, precision_guard, basic_detection | Lexical callback scopes preserve outer function calls and report callbacks referenced only from dead initializers. |
| typescript-lexical-value-identity | typescript | 1 / 3 | typescript, basic_detection, precision_guard, multi_file | Lexical value and selected-program module reachability with used and unused controls. |
| typescript-dead-import-consumers | typescript | 4 / 4 | typescript, basic_detection, precision_guard, multi_file | Lexical value and selected-program module reachability with used and unused controls. |
| typescript-loaded-import-consumers | typescript | 1 / 5 | typescript, basic_detection, precision_guard, multi_file | Lexical value and selected-program module reachability with used and unused controls. |
| go-project-import-graph | go | 3 / 3 | go, basic_detection, precision_guard | Visible same-module package imports retain complete object reachability so private dead cycles are reported and returned callbacks remain used. |
| go-private-test-helpers | go | 4 / 4 | go, basic_detection, precision_guard | Full native proof reports unused private internal test helpers while test entries and their live helper chains remain used. |
| rust-import-expression-uses | rust | 1 / 9 | rust, basic_detection, precision_guard | Enum payload types, trait extension calls and derive-attribute expressions keep their actual imports; an unrelated import remains unused. |
| rust-private-function-cycles | rust | 3 / 5 | rust, basic_detection, precision_guard | Unrooted private cycles are unused; a called cycle and callback returned by a public factory stay live. |
| rust-cross-file-cycle-roots | rust | 1 / 4 | rust, basic_detection, precision_guard | A child module can call a private parent function and thereby keep its whole cycle live. |
| typescript-reexport-demand-chain | typescript | 1 / 2 | typescript, basic_detection, precision_guard, multi_file | Resolved named and wildcard export forwarding with exact unused and used source controls. |
| typescript-reexport-public-and-escape | typescript | 1 / 5 | typescript, basic_detection, precision_guard, multi_file | Resolved named and wildcard export forwarding with exact unused and used source controls. |
| go-local-module-replacement | go | 3 / 3 | go, basic_detection, precision_guard, multi_file | A required module replaced by already scanned local source supplies type identity for private cycles while callbacks and its public API remain used. |
| go-local-replacement-live-callback-cycle | go | 1 / 5 | go, basic_detection, precision_guard, multi_file | A callback sent through a declared local module replacement retains the private cycle it calls; an unused sibling is still reported. |
| rust-local-trait-receiver-identity | rust | 2 / 3 | rust, precision_guard, basic_detection | Local trait declarations and concrete receiver types preserve the required alias import while unused imports and private siblings remain reportable. |
| typescript-reexport-enumerated-aliases | typescript | 1 / 3 | typescript, basic_detection, precision_guard, multi_file | Literal module namespace key enumeration follows resolved wildcard bindings even when generated package outputs are unavailable; private helpers remain unused. |
| rust-macro-import-evidence | rust | 2 / 4 | rust, precision_guard, basic_detection | Standard writer macro receiver types and feature-matched wrapped attribute names preserve required imports while unused trait and attribute siblings remain reportable. |
| typescript-nested-namespace-export | typescript | 1 / 1 | typescript, basic_detection, precision_guard, multi_file | A closed application reads compact through two namespace exports; expanded has no consumer. A native-valid tagged template must not make the source scope incomplete or disable exact export demand. |
| typescript-namespace-export-public-and-opaque | typescript | 2 / 4 | typescript, basic_detection, precision_guard, multi_file | Escaping namespace preserves exported service functions; declared package API preserves renderer functions; private uncalled helpers remain dead in both providers. |
| go-workspace-private-cycle | go | 3 / 3 | go, basic_detection, precision_guard, multi_file | An active contained Go workspace supplies indexed module type identity while used callbacks and public APIs remain roots. |
| go-workspace-live-callback | go | 1 / 5 | go, basic_detection, precision_guard, multi_file | An active contained Go workspace supplies indexed module type identity while used callbacks and public APIs remain roots. |
| rust-source-module-trait | rust | 2 / 3 | rust, precision_guard, basic_detection, multi_file | Ordinary local Rust modules supply exact trait receiver evidence while unused sibling imports and private functions remain visible. |
| swift-private-functions | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: private functions. |
| swift-callback | swift | 1 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: callback. |
| swift-dead-cycle | swift | 3 / 1 | swift, basic_detection, precision_guard | Swift source-defined private reachability: dead cycle. |
| swift-live-cycle | swift | 1 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: live cycle. |
| swift-parameter-shadow | swift | 1 / 1 | swift, basic_detection, precision_guard | Swift source-defined private reachability: parameter shadow. |
| swift-local-shadow | swift | 1 / 1 | swift, basic_detection, precision_guard | Swift source-defined private reachability: local shadow. |
| swift-initializer-before-binding | swift | 0 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: initializer before binding. |
| swift-owner-identity | swift | 1 / 5 | swift, basic_detection, precision_guard | Swift source-defined private reachability: owner identity. |
| swift-extension | swift | 1 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: extension. |
| swift-fileprivate | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: fileprivate. |
| swift-function-value | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: function value. |
| swift-keypath | swift | 0 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: keypath. |
| swift-property-read | swift | 1 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: property read. |
| swift-string-not-use | swift | 1 / 1 | swift, basic_detection, precision_guard | Swift source-defined private reachability: string not use. |
| swift-comment-not-use | swift | 1 / 1 | swift, basic_detection, precision_guard | Swift source-defined private reachability: comment not use. |
| swift-overload-labels | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: overload labels. |
| swift-default-argument | swift | 0 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: default argument. |
| swift-raw-identifiers | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: raw identifiers. |
| swift-protocol-witness | swift | 0 / 4 | swift, basic_detection, precision_guard | Swift source-defined private reachability: protocol witness. |
| swift-codable | swift | 0 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: codable. |
| swift-equatable | swift | 0 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: equatable. |
| swift-reflection | swift | 0 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: reflection. |
| swift-objc-selector | swift | 0 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: objc selector. |
| swift-conditional | swift | 0 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: conditional. |
| swift-closure-capture | swift | 1 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: closure capture. |
| swift-private-type | swift | 1 / 3 | swift, basic_detection, precision_guard | Swift source-defined private reachability: private type. |
| swift-member-cycle | swift | 2 / 2 | swift, basic_detection, precision_guard | Swift source-defined private reachability: member cycle. |
| swift-property-wrapper | swift | 0 / 5 | swift, basic_detection, precision_guard | Swift source-defined private reachability: property wrapper. |
| typescript-jsx-classic-runtime | typescript | 1 / 2 | typescript, framework_precision, precision_guard | With tsconfig jsx: react, JSX reads the React binding; a React import in a file without JSX is still unused. |
| typescript-jsx-automatic-runtime | typescript | 1 / 0 | typescript, basic_detection | With tsconfig jsx: react-jsx the compiler imports the runtime itself, so an unread React import is unused. |
| typescript-jsx-pragma-factory | typescript | 1 / 1 | typescript, framework_precision, precision_guard | A @jsx pragma makes JSX read the named factory in that file only. |
| typescript-jsx-configured-factory | typescript | 1 / 2 | typescript, framework_precision, precision_guard | tsconfig jsxFactory names the binding JSX reads; React is unused under a custom factory. |
| typescript-qualified-type-import-use | typescript | 2 / 2 | typescript, precision_guard, basic_detection | A type namespace import used as the root of a qualified type name is read; unnamed type imports are unused. |
| typescript-destructuring-default-reads | typescript | 2 / 2 | typescript, precision_guard, basic_detection | Default values of destructured bindings and parameters read the import or constant they name. |
| typescript-dependency-base-overrides | typescript | 2 / 2 | typescript, dynamic_dispatch, precision_guard | Methods of a class that extends a dependency's class can be overrides the dependency calls; methods of base-less and project-base classes are judged normally. |
| typescript-member-call-same-name-local | typescript | 2 / 1 | typescript, dynamic_dispatch, precision_guard | A method called through an instance inside a declaration of the same name is used; a local variable that only shares a method's name is not a call. |
| javascript-storybook-config-files | javascript | 4 / 4 | javascript, framework_precision, precision_guard | Storybook loads its named .storybook config files; other files there and orphans need an importer. |
| javascript-storybook-config-without-storybook | javascript | 2 / 1 | javascript, basic_detection | Without a Storybook dependency or script, a .storybook file is an ordinary unused file. |
| typescript-runner-conf-files | typescript | 3 / 3 | typescript, framework_precision, precision_guard | karma.conf and wdio.conf in a package that uses the runner are loaded by it; WebdriverIO reads only the exported config. |
| javascript-runner-conf-without-runner | javascript | 1 / 0 | javascript, basic_detection | A karma.conf.js in a package that neither depends on nor runs Karma is unused. |
| typescript-tool-config-path-strings | typescript, javascript | 11 / 6 | typescript, javascript, multi_file, precision_guard | Path strings in a tool configuration file load the files they name; comments, prose and path strings in ordinary modules do not. |
| typescript-tsconfig-include-exact-file | typescript | 3 / 1 | typescript, multi_file, precision_guard | A tsconfig include entry that names one file is a compilation root; globs, excludes and unlisted files are not. |
| javascript-path-join-literal-files | javascript, typescript | 4 / 3 | javascript, typescript, multi_file, precision_guard | path.join/path.resolve from node:path with literal segments name the file they build; comments, Array.join and local lookalikes do not. |
| typescript-runtime-command-template-files | typescript, javascript | 3 / 2 | typescript, javascript, multi_file, precision_guard | A runtime command built in a template literal runs the script it names; prose and non-command joins do not. |
| typescript-markdown-run-instructions | typescript | 6 / 3 | typescript, multi_file, cli_entrypoint, precision_guard | A runtime command in a Markdown code block or code span is a run instruction; prose, links and non-runtime commands are mentions. |
| typescript-package-manifest-named-files | typescript, javascript | 5 / 3 | typescript, javascript, package_entrypoint, precision_guard | package.json files entries that name one file and path values of custom keys load that file; folder entries, descriptions and ignore lists do not. |
| typescript-react-native-platform-extensions | typescript | 6 / 4 | typescript, framework_precision, multi_file, precision_guard | In a React Native project an import loads every platform sibling of its target; platform files nobody imports stay unused. |
| typescript-platform-suffix-without-react-native | typescript | 2 / 0 | typescript, basic_detection | Without React Native or Expo, scale.web.ts is an ordinary module that needs its own importer. |
| typescript-source-reexport-import-binding | typescript | 1 / 3 | typescript, basic_detection, precision_guard | An `export { X } from` statement re-exports from the module and does not read a local import of X; a local `export { X }` does. |
| typescript-default-reexport-from-entry | typescript | 0 / 2 | typescript, package_entrypoint, precision_guard | A default export re-exported by name from the package entry is public API. |
| go-plugin-lookup-symbols | go | 3 / 3 | go, basic_detection, precision_guard | Exported package-main symbols named by plugin.Lookup in a file importing the standard plugin package stay live; unnamed, lowercase and project-Lookup names are still reported. |
| java-same-name-method-receivers | java | 6 / 2 | java, basic_detection, precision_guard | A call on a variable whose declared type is written in the same file reaches that type's method even when another class declares the name; uncalled same-named methods, and ones whose name is only called on another type, are still reported. |
| kotlin-same-file-member-extension | kotlin | 2 / 2 | kotlin, basic_detection, precision_guard | A private member extension called through this stays live when another file has a private top-level function of the same name; uncalled private members are still reported. |
| rust-signature-type-uses | rust | 2 / 5 | rust, basic_detection, precision_guard | Imports named only as a plain return type or in trait, struct and impl header bounds are used; an import never named again or named only in a comment and a string is still reported. |
| java-reserved-domain-package | java, kotlin | 2 / 4 | java, kotlin, basic_detection, precision_guard | Application code under the com.example / org.example default package namespace is analysed like any other source; real examples folders and other example packages keep their standalone role. |
| python-module-variable-same-name | python | 1 / 5 | multi_file, basic_detection, precision_guard | A module variable nobody imports is unused even when other modules bind and read their own variable of the same name; imports, star imports, module attribute reads and namespace reads keep theirs. |
| python-unnamed-receiver-methods | python | 2 / 10 | dynamic_dispatch, basic_detection, precision_guard | Methods of an escaped instance that nothing in the project names are unused; literal and prefix lookups, names held as data, proxies, callbacks, protocol members, sibling implementations and instances handed outside the project keep theirs. |
| python-direct-call-parameters | python | 2 / 10 | basic_detection, precision_guard | An unread parameter of a private function that is defined once and only called directly is unused; callbacks, partials, variadics, public functions, string lookups, constant-return default hooks, alternative definitions, abstract implementations and overridden hooks keep theirs. |
| ruby-external-base-macros | ruby | 5 / 7 | ruby, precision_guard, framework_precision | Class macros with symbol arguments in classes whose superclass is defined in another file: callbacks, validations, helper_method and rescue_from keep the named private methods; unnamed methods, body-level symbol data, visibility calls and a source-defined macro stay reported. |
| ruby-constructor-other-file | ruby | 2 / 2 | ruby, precision_guard | A class instantiated only from another file keeps initialize and the private helper it calls; private methods nobody calls, including one sharing the initialize prefix, stay reported. |
| php-use-const-import | php | 2 / 3 | php, precision_guard | A use const import is used when the bare constant is read (expression or parameter default); an import never read, or named only in a comment, stays reported. |
| php-phpunit-colocated-tests | php | 2 / 6 | php, precision_guard, framework_precision | PHPUnit test classes colocated with sources in *Test.php files (direct TestCase subclasses and classes inheriting tests from a test base) are framework-run; a production class named *Test and an abstract test base nobody extends stay reported. |
| csharp-extension-instance-calls | csharp | 3 / 3 | csharp, precision_guard | Extension methods called with instance syntax keep the method and its static class; an uncalled private extension, a non-extension method whose only namesake call has one fewer argument on another type, and an extension class nobody calls stay reported. |
| csharp-attribute-consumers | csharp | 6 / 4 | csharp, precision_guard, framework_precision | Members and types consumed through attributes (source-generator command, EF Core [DbContext] snapshot, [StructLayout] storage) and a primary constructor stay quiet; compiler-marker attributes, a [Serializable] class, an unreferenced primary-constructor class and a plain struct field stay reported. |
| csharp-global-using-binding | csharp | 3 / 3 | csharp, precision_guard | Types, attribute classes and typed-receiver members reached through project-wide global using directives stay quiet; unused siblings in the same namespaces stay reported. |
| csharp-call-shapes | csharp | 3 / 2 | csharp, precision_guard | A method group passed as a named argument and a call whose only argument is a string literal keep their private targets; a callback never passed, a helper never called and a two-parameter helper stay reported. |
| csharp-reflected-methods | csharp | 1 / 3 | csharp, precision_guard, dynamic_dispatch | Methods of a type whose methods are enumerated by reflection (typeof(T).GetTypeInfo().DeclaredMethods) stay quiet; an uncalled method of a type nobody reflects over stays reported. |
| csharp-markup-references | csharp | 6 / 4 | csharp, precision_guard, framework_precision | C# members named from Razor components, XAML event attributes and a cshtml @model stay quiet; members absent from markup or named only inside markup comments, and an unreferenced type that merely shares its name with the type C# code uses, stay reported. |
| swift-shorthand-optional-binding | swift | 2 / 2 | swift, precision_guard | Shorthand optional bindings (if let x, guard let x) read the outer private property; a binding with an initializer and a shorthand that reads a same-named local do not. |
| swift-coding-keys | swift | 2 / 1 | swift, precision_guard, framework_precision | A nested CodingKeys enum conforming to CodingKey inside a Codable type is used by the synthesised conformance; a differently named key enum and a CodingKeys enum in a non-Codable type stay reported. |
| dart-import-binding-kinds | dart | 2 / 3 | dart, precision_guard | An import is used when the file reads a top-level getter, a typedef or a typed top-level variable it supplies; an import nothing is read from, and one whose getter name only matches a parameter, stay reported. |
| dart-extension-open-receiver | dart | 4 / 3 | dart, precision_guard | Extension members called on a receiver whose static type the file does not state (a call result) keep the member and its import; an unnamed member, a member named only as a static call on a class, and an extension nobody calls stay reported. |
| dart-field-initializer-call | dart | 2 / 2 | dart, precision_guard | Private methods called from instance and static field initializers stay quiet; an uncalled method and one whose name only resembles a literal-initialised field stay reported. |
| string-named-backend-dispatch | python | 1 / 3 | dynamic_dispatch, precision_guard | Method names a class builds as strings inside a method and a dispatcher calls through getattr(channel, name) stay alive; an unlisted sibling is reported. |
| decorator-factory-registry | python | 3 / 2 | dynamic_dispatch, precision_guard | Callbacks registered through a source-owned decorator factory are alive regardless of the factory's method name; a factory that does not store its argument registers nothing. |
| cpp-local-shadow | cpp | 2 / 1 | cpp, precision_guard | An ordinary local binding cannot keep a same-named file-local function alive; an actual call preserves its target. |
| corpus-conditional-assets-direct | javascript | 4 / 2 | javascript, multi_file, precision_guard | Direct HTML script references preserve exact paths while ordinary and malformed comments do not load scripts. |
| corpus-conditional-assets-plain | javascript | 4 / 2 | javascript, multi_file, precision_guard | Legacy IE conditional HTML script references preserve the exact asset without treating ordinary or malformed comments as loads. |
| corpus-conditional-assets-jinja | javascript | 4 / 2 | javascript, multi_file, precision_guard | Legacy IE conditional HTML script references support the native Jinja safe filter on simple literal paths while comments and wrong paths remain unused. |
| csharp-owner-call-identity | csharp | 1 / 6 | csharp, multi_file, precision_guard | Main constructs both namespace-specific Worker classes but only invokes Primary.Run→Primary.Process. The Secondary private method has no caller; its owner is constructed so parent grouping cannot hide it. |
| private-exported-enum-members | typescript | 1 / 1 | typescript, precision_guard | Imported aliases in a closed private package consume individual enum members. |

## Complete default security case list

| Case | Declared languages | Required findings | Quiet controls | Contract |
| --- | --- | --- | --- | --- |
| sql-tainted-param | python | SKY-D211 | — | Request-supplied SQL passed through a helper remains injection even when execute() binds a separate ID value. |
| sql-constant-format | python | — | SKY-D211, SKY-D217 | Statically built SQL using constant .format() arguments should not be reported as SQL injection. |
| ssrf-tainted-host | python | SKY-D216 | — | A request parameter interpolated into the URL host of a route handler should be detected as SSRF. |
| ssrf-helper-parameter-safe | python | — | SKY-D216 | A helper whose URL host comes only from its own parameter (no route, request, CLI, MCP-tool or stdin source) is not reported as SSRF. |
| ssrf-fixed-host-path | python | — | SKY-D216 | Fixed-host URL interpolation should not be reported as SSRF when only the path segment is tainted. |
| subprocess-alias-shell | python | SKY-D209 | — | subprocess imported with an alias should still be detected when shell=True is used. |
| yaml-safeloader-positional | python | — | SKY-D206 | yaml.load with positional yaml.SafeLoader should not be reported as unsafe deserialization. |
| path-traversal-tainted-join | python | SKY-D215 | — | User-controlled path segments joined into a filesystem path should be reported as path traversal. |
| path-traversal-basename | python | — | SKY-D215 | Path input sanitized with os.path.basename before opening a fixed directory should stay quiet. |
| xss-mark-safe | python | SKY-D226 | — | Tainted HTML interpolated into Markup should be reported as XSS. |
| xss-escape-safe | python | — | SKY-D226 | Escaped content wrapped with Markup should not be reported as XSS. |
| open-redirect-tainted | python | SKY-D230 | — | User-controlled redirect targets should be reported as open redirect. |
| open-redirect-local-guard | python | SKY-D230 | — | A leading-slash check still accepts protocol-relative external redirect targets. |
| open-redirect-literal-allowlist | python | — | SKY-D230 | A redirect restricted to explicit local destinations should stay quiet. |
| jwt-verify-disabled | python | SKY-D232 | — | JWT decode with signature verification disabled should be reported. |
| cors-wildcard | python | SKY-D231 | — | Wildcard CORS configuration should be reported. |
| go-zip-slip | go | SKY-D215 | — | Go archive extraction that joins an archive entry name into a filesystem path should be reported as Zip Slip path traversal. |
| go-zip-slip-safe | go | — | SKY-D215 | Go archive extraction guarded with filepath.IsLocal should stay quiet. |
| java-path-traversal | java | SKY-D215 | — | Java servlet request parameters used in filesystem paths should be reported as path traversal. |
| java-path-traversal-safe | java | — | SKY-D215 | Java request path resolution guarded with normalize and startsWith should stay quiet. |
| typescript-eval | typescript | SKY-D201 | — | TypeScript eval of caller-controlled input should be reported as code execution. |
| csharp-command-injection | csharp | SKY-D212 | — | C# Process.Start with a controller action parameter as the command should be reported as command injection. |
| csharp-command-literal-safe | csharp | — | SKY-D212 | C# Process.Start with literal argv should not be reported as command injection. |
| csharp-sql-injection | csharp | SKY-D211 | — | C# SqlCommand text concatenated with a controller action parameter should be reported. |
| csharp-sql-parameterized-safe | csharp | — | SKY-D211 | C# parameterized SqlCommand with literal query text should stay quiet. |
| csharp-ssrf | csharp | SKY-D216 | — | C# HttpClient request using a controller action parameter as the URL should be reported as SSRF. |
| csharp-ssrf-fixed-host-safe | csharp | — | SKY-D216 | C# HttpClient request to a literal fixed URL should stay quiet. |
| csharp-path-traversal | csharp | SKY-D215 | — | C# File.ReadAllText with a controller action parameter as the path should be reported as path traversal. |
| csharp-path-basename-safe | csharp | — | SKY-D215 | C# path input sanitized with Path.GetFileName before fixed-directory access should stay quiet. |
| csharp-open-redirect | csharp | SKY-D230 | — | C# MVC Redirect using caller-controlled target should be reported as open redirect. |
| csharp-open-redirect-literal-safe | csharp | — | SKY-D230 | C# MVC Redirect to a literal local route should stay quiet. |
| csharp-local-redirect-safe | csharp | — | SKY-D230 | C# LocalRedirect and an Url.IsLocalUrl-guarded Redirect of a request parameter should stay quiet. |
| csharp-repository-getasync-safe | csharp | — | SKY-D216 | C# repository GetAsync with a route value is a data lookup, not an outbound HTTP request. |
| csharp-binaryformatter-deserialization | csharp | SKY-D233 | — | C# BinaryFormatter.Deserialize of a request body should be reported as unsafe deserialization. |
| php-unserialize | php | SKY-D204 | — | PHP unserialize on request-controlled data should be reported as unsafe deserialization. |
| php-json-decode-safe | php | — | SKY-D204 | PHP JSON decoding request data should not be treated as unsafe deserialization. |
| php-path-traversal | php | SKY-D215 | — | PHP filesystem read using request-controlled path should be reported as path traversal. |
| php-path-basename-safe | php | — | SKY-D215 | PHP path input sanitized with basename before fixed-directory access should stay quiet. |
| typescript-eval-safe | typescript | — | SKY-D201 | TypeScript JSON parsing should not be treated as eval or code execution. |
| typescript-nextjs-author-shadow-missing-auth | typescript | SKY-D280 | — | Next.js mutating route without an authorization check should be reported even when unrelated identifiers contain the substring auth. |
| typescript-nextjs-auth-decoys | typescript | SKY-D280 | — | Next.js mutating route without an authentication guard should be reported even when comments, imports, headers, and cookies look auth-related. |
| typescript-nextjs-session-guard-safe | typescript | — | SKY-D280 | Next.js mutating route with an explicit server-session guard should stay quiet. |
| typescript-nextjs-authjs-v5-safe | typescript | — | SKY-D280 | Next.js mutating route guarded through the official Auth.js v5 local auth adapter should stay quiet. |
| typescript-server-action-prisma-unsafe | typescript | SKY-D281 | — | Next.js server action using Prisma unsafe raw SQL with interpolated form input should be reported. |
| typescript-server-action-constant-safe | typescript | — | SKY-D211, SKY-D281 | Next.js server action with compile-time constant SQL substitutions should stay quiet. |
| typescript-server-action-inline-unsafe | typescript | SKY-D281 | — | Inline Next.js server action with dynamic SQL interpolation should be reported. |
| typescript-server-action-repository-unsafe | typescript | SKY-D281 | — | Next.js server action input reaching concatenated SQL through a same-file repository class should be reported. |
| typescript-server-action-query-config-safe | typescript | — | SKY-D211, SKY-D281 | Next.js server action using a helper-built parameterized text-and-values query config should stay quiet. |
| typescript-server-action-trusted-runtime-safe | typescript | — | SKY-D211, SKY-D281 | Next.js server action interpolating a trusted server timestamp should stay quiet because runtime variability is not user taint. |
| typescript-server-action-prisma-tag-safe | typescript | — | SKY-D211, SKY-D281 | Next.js server action using a proven Prisma parameterizing tagged template should stay quiet. |
| typescript-webhook-unverified | typescript | SKY-D282 | — | Stripe webhook handler that parses raw request body before signature verification should be reported. |
| typescript-webhook-nondominating-verifier | typescript | SKY-D282 | — | Stripe webhook verification of an unrelated payload after a side effect must not prove the handler safe. |
| typescript-webhook-verified-safe | typescript | — | SKY-D282, SKY-S102 | Stripe webhook handler that uses provider signature verification before trusting the event should stay quiet. |
| typescript-cookie-explicit-false | typescript | SKY-D252 | — | A session cookie with explicit false secure and httpOnly flags should be reported as insecure. |
| typescript-cookie-literal-safe | typescript | — | SKY-D252 | A session cookie with literal true secure and httpOnly flags should stay quiet. |
| java-ssrf-httpclient-send | java | SKY-D216 | — | Java HttpClient request built from servlet-controlled URL and sent outbound should be reported as SSRF. |
| java-open-redirect-protocol-relative | java | SKY-D230 | — | Java redirect guarded only by startsWith('/') should still be reported because protocol-relative URLs bypass that guard. |
| java-ldap-xpath-injection | java | SKY-D239, SKY-D229 | — | Java servlet parameters concatenated into LDAP filters and XPath expressions should be reported. |
| go-command-shell-query | go | SKY-D212 | — | Go HTTP query parameter concatenated into a shell command should be reported as command injection. |
| go-tar-symlink-escape | go | SKY-D215 | — | Go tar extraction that creates archive-controlled symlinks without resolving the final target should be reported. |
| rust-shell-arg-taint | rust | SKY-D212 | — | Rust CLI argument passed through sh -c should be reported as command injection. |
| rust-path-filename-safe | rust | — | SKY-D215 | Rust path input reduced to file_name before fixed-directory access should stay quiet. |
| dart-http-tainted-url | dart | SKY-D216 | — | Dart http.get with caller-controlled Uri.parse input should be reported as SSRF. |
| dart-uri-https-safe | dart | — | SKY-D216 | Dart request built with Uri.https fixed host and tainted query parameter should stay quiet. |
| php-request-include | php | SKY-D255 | — | PHP include using request-controlled template path should be reported as file inclusion. |
| shell-eval-arg | shell | SKY-D212 | — | Shell positional argument assigned to a command and passed to eval should be reported as command injection. |
| shell-source-arg | shell | SKY-D212 | — | Shell source of a positional-argument path should be reported because the sourced file executes in-process. |
| shell-c-flag-arg | shell | SKY-D212 | — | Shell command string passed to bash -c from a positional argument should be reported. |
| shell-curl-tainted-url | shell | SKY-D216 | — | Shell read input passed as a curl URL should be reported as SSRF. |
| shell-curl-fixed-host-path | shell | — | SKY-D216 | Shell curl to a fixed host with only the path segment tainted should stay quiet for SSRF. |
| shell-path-read-arg | shell | SKY-D215 | — | Shell positional argument interpolated into a filesystem path should be reported as path traversal. |
| shell-basename-safe | shell | — | SKY-D215 | Shell positional argument reduced with basename before fixed-directory file access should stay quiet for path traversal. |
| kotlin-sql-interpolation | kotlin | SKY-D211 | — | Spring request parameter term is interpolated into SQL text passed to JdbcTemplate. |
| kotlin-sql-binding | kotlin | — | SKY-D211 | SQL text is fixed and term is a separate bound argument, not SQL syntax. |
| kotlin-sql-other-scalar | kotlin | SKY-D211 | — | Converting page cannot sanitize the separate request parameter term interpolated into SQL. |
| kotlin-command-shell | kotlin | SKY-D212 | — | Servlet command data is passed as shell source to sh -c. |
| kotlin-command-text | kotlin | — | SKY-D212 | Sink syntax appears only in a comment and a raw string; no process or shell is invoked. |
| kotlin-ssrf-destination | kotlin | SKY-D216 | — | Ktor request data controls the complete network destination. |
| kotlin-ssrf-fixed-origin | kotlin | — | SKY-D216 | Request data is appended after a fixed origin and path prefix; it cannot choose the initial destination host. |
| kotlin-ssrf-unrelated-allowlist | kotlin | SKY-D216 | — | An unused allowlist is not a validation guard for destination. |
| kotlin-path-segment | kotlin | SKY-D215 | — | An unvalidated request segment can contain parent components and reaches a filesystem read. |
| kotlin-path-basename | kotlin | — | SKY-D215 | The final child argument is only a platform basename, removing path components for this path-traversal contract. |
| kotlin-path-prefix | kotlin | SKY-D215 | — | The lexical docs/ prefix still permits docs/../../outside; it is not canonical containment. |
| kotlin-command-numeric-argv | kotlin | — | SKY-D212 | Request text is parsed to an integer and formatted as a decimal scalar before occupying a fixed-format argv data position. |
| rust-shell-literal-command | rust | — | SKY-D212 | The shell program and complete command text are fixed literals; the existing tainted shell case is its unsafe counterpart. |
| rust-path-argument | rust | SKY-D215 | — | A command-line argument controls the complete filesystem path, without a base directory or containment check. |
| dart-process-command-argument | dart | SKY-D212 | — | A caller-supplied executable controls which program starts; disabling the shell does not restrict executable selection. |
| dart-process-literal-command | dart | — | SKY-D212 | The executable and all arguments are fixed literals and shell execution is disabled. |
| dart-file-path-argument | dart | SKY-D215 | — | A caller-supplied path flows through an assignment directly to File/readAsString without a containment or basename guard. |
| dart-file-basename-guard | dart | — | SKY-D215 | The imported path.basename library operation removes directory components before the fixed-base read; this guards path traversal, not separate symlink/file-authorization policy. |
| ruby-command-shell | ruby | SKY-D212 | — | Ruby command shell; bounded native Ruby source contract. |
| ruby-command-string | ruby | SKY-D212 | — | Ruby command string; bounded native Ruby source contract. |
| ruby-command-argv | ruby | — | SKY-D212 | Ruby command argv; bounded native Ruby source contract. |
| ruby-command-literal | ruby | — | SKY-D212 | Ruby command literal; bounded native Ruby source contract. |
| tls-corpus-requests-disabled | python | SKY-D210 | — | An ordinary Requests client explicitly disables certificate verification. |
| tls-corpus-requests-verified | python | — | SKY-D210 | The paired Requests client explicitly keeps certificate verification enabled. |
| tls-corpus-context-alias-disabled | python | SKY-D210 | — | A native client context is made non-verifying through an alias after its secure-looking constructor. |
| tls-corpus-context-default-verified | python | — | SKY-D210 | A native PROTOCOL_TLS_CLIENT context preserves certificate and hostname verification. |
| tls-corpus-inert-helper | python | — | SKY-D210 | A local inert helper stores a similarly named option and performs no TLS operation. |
| tls-corpus-imported-helper-patch | python | SKY-D210 | — | Import-time code replaces the inert-looking helper with BrowserConfig, so the later disabling option retains a finding. |
| tls-corpus-context-required-tampered | python | SKY-D210 | — | A replaced CERT_REQUIRED value cannot prove certificate checking is enabled. |
| tls-corpus-context-explicit-verified | python | — | SKY-D210 | A native legacy client context has both chain and hostname verification explicitly enabled. |
| tls-corpus-ts-agent-disabled | typescript | SKY-D210 | — | A native Node HTTPS agent disables certificate verification. |
| tls-corpus-ts-agent-verified | typescript | — | SKY-D210 | The paired native HTTPS agent explicitly enables certificate verification. |
| tls-corpus-ts-env-disabled | typescript | SKY-D210 | — | The actual Node process TLS verification environment switch is set to zero. |
| tls-corpus-ts-env-verified | typescript | — | SKY-D210 | The paired Node process switch is set to one rather than disabling verification. |
| tls-corpus-ts-string-lookalike | typescript | — | SKY-D210 | Text describing disabling flags is not an environment assignment or a TLS options object. |
| crypto-corpus-md5-password | python | SKY-D207 | — | Password bytes enter native hashlib.md5; weak algorithm remains a finding. |
| crypto-corpus-md5-nonsecurity | python | — | SKY-D207 | Explicit usedforsecurity=False marks a nonsecurity content fingerprint under the documented opt-out policy. |
| crypto-corpus-sha1-token-factory | python | SKY-D208 | — | The aliased hashlib.new factory explicitly chooses SHA1 over an API token. |
| crypto-corpus-sha1-nonsecurity | python | — | SKY-D208 | The native factory uses the explicit nonsecurity opt-out. |
| crypto-corpus-sha256-password | python | — | SKY-D207, SKY-D208 | SHA256 is neither MD5 nor SHA1. This control makes no claim that unsalted SHA256 is an adequate password storage scheme. |
| crypto-corpus-hash-named-lookalike | python | — | SKY-D207, SKY-D208 | A local method named md5 actually uses SHA256 and is not a native weak-hash API. |
| crypto-corpus-misleading-cache-name | python | SKY-D207 | — | A cache_key name does not prove nonsecurity use; the value is a credential and security use is explicitly true. |
| crypto-corpus-weak-random-cookie | python | SKY-D250 | — | Native random.getrandbits controls a session cookie value. |
| crypto-corpus-secrets-cookie | python | — | SKY-D250 | Native secrets.token_urlsafe supplies cookie entropy. |
| crypto-corpus-system-random-cookie | python | — | SKY-D250 | SystemRandom uses OS entropy rather than random.Random PRNG state. |
| crypto-corpus-retry-jitter | python | — | SKY-D250 | Randomness changes retry delay, not a credential, cookie or authentication value. |
| crypto-corpus-reassigned-strong | python | — | SKY-D250 | The weak value is overwritten with strong entropy before the only security sink. |
| crypto-corpus-branch-weak-cookie | python | SKY-D250 | — | One reachable branch replaces strong entropy with random.getrandbits before the cookie sink. |
| crypto-corpus-random-named-lookalike | python | — | SKY-D250 | A local random-named method delegates to secrets.token_urlsafe; no native weak-random source exists. |
| logging-corpus-env-token | python | SKY-D251 | — | Credential environment data reaches a real logger unchanged. |
| logging-corpus-public-name | python | — | SKY-D251 | A password-like variable name holds an explicitly public literal, not credential source data. |
| logging-corpus-literal-redaction | python | — | SKY-D251 | The credential binding is overwritten with a literal before output. |
| logging-corpus-partial-redaction | python | SKY-D251 | — | The branch where redaction is declined still sends the credential to logging. |
| logging-corpus-http-status | python | — | SKY-D251 | The HTTP response status is server data; it is not the password in the request payload. |
| logging-corpus-http-request-url | python | SKY-D251 | — | The response URL retains the credential query parameter sent in the request. |
| logging-corpus-redact-identity | python | SKY-D251 | — | The helper named redact explicitly returns its input unchanged; its name cannot prove redaction. |
| logging-corpus-alias-mutation | python | — | SKY-D251 | Mutating the shared container through an alias actually removes the credential before logging. |
| logging-corpus-alias-rebind | python | SKY-D251 | — | Rebinding the alias leaves the original credential-bearing container unchanged. |
| crypto-corpus-alias-rebound-strong | python | — | SKY-D250 | The weak-module alias is explicitly rebound to native SystemRandom before its only credential sink. |
| crypto-corpus-alias-rebound-weak | python | SKY-D250 | — | The secrets alias is explicitly rebound to native random.Random before its cookie entropy call. |
| review-php-strict-page-allowlist | php | — | SKY-D255 | A strict comparison against two source literals permits only those exact files. |
| review-php-loose-boolean-allowlist | php | SKY-D255 | — | Loose PHP comparison against true accepts any nonempty path string; this does not constrain inclusion. |
| review-php-tainted-allowlist | php | SKY-D255 | — | The attacker controls the allowed element as well as the page; strict equality is not trusted source proof. |
| review-csharp-json-data-only | csharp | — | SKY-D233 | System.Text.Json uses a source-selected data type and is not the unsafe formatter family. |
| review-csharp-formatter-named-lookalike | csharp | — | SKY-D233 | The source-defined helper returns a new plain object; it is unrelated to the framework formatter despite the same name. |
| review-csharp-newtonsoft-unsafe | csharp | SKY-D233 | — | Actual Json.NET settings enable unrestricted polymorphic type names. |
| review-csharp-settings-named-lookalike | csharp | — | SKY-D233 | A source-defined display option and enum perform no deserialization; the property spelling alone is not security evidence. |
| go-command-direct | go | SKY-D212 | — | HTTP input selects an executable with -c script supplied by the same request. |
| go-command-basename | go | SKY-D212 | — | filepath.Base removes directory components but still lets the request select sh or another interpreter; the request also controls its -c script. |
| go-command-fixed-data | go | — | SKY-D212 | A fixed printf executable receives a fixed %s format with request data as a separate argument, without a shell. |
| go-ssrf-direct | go | SKY-D216 | — | HTTP input chooses destination authority after a fixed http scheme. |
| go-ssrf-basename | go | SKY-D216 | — | Base does not validate network destinations; a host such as 127.0.0.1:8080 contains no path separator and survives unchanged. |
| go-path-log-only-guard | go | SKY-D215 | — | An IsLocal check that only logs and does not return, throw or dominate the sink cannot prevent unsafe os.ReadFile. |
| go-path-reject-guard | go | — | SKY-D215 | The IsLocal rejection branch returns before the path reaches the file read under a fixed directory. |
| go-redirect-log-only-guard | go | SKY-D230 | — | Comparing a request redirect target with /home only logs; it does not restrict the target before http.Redirect. |
| go-redirect-literal-guard | go | — | SKY-D230 | A strict comparison rejects every target other than the single literal /home before redirect. |
| go-ssrf-fixed-destination | go | — | SKY-D216 | A fixed HTTPS destination stays quiet; no request value chooses its authority. |
| go-sql-query-value | go | SKY-D211 | — | Request input is concatenated into SQL syntax before reaching database/sql. |
| go-sql-bound-value | go | — | SKY-D211 | Request input occupies a bound query value; SQL syntax is fixed. |
| go-html-response-unsafe | go | SKY-D228 | — | Request HTML reaches a response explicitly served as text/html without escaping. |
| go-html-response-escaped | go | — | SKY-D228 | The real html.EscapeString provider escapes request text before an HTML response. |
| go-tls-verification-disabled | go | SKY-D210 | — | A real crypto/tls.Config explicitly disables peer certificate validation. |
| go-tls-verification-enabled | go | — | SKY-D210 | The real TLS configuration keeps peer verification enabled. |
| go-cookie-secure-disabled | go | SKY-D252 | — | A session cookie explicitly disables Secure while preserving HttpOnly. |
| go-cookie-flags-enabled | go | — | SKY-D252 | Both browser transport and script-access flags are explicitly enabled. |
| ts-exec-direct | typescript | SKY-D212 | — | Existing exec positive. |
| ts-spawn-command-shell | typescript | SKY-D212 | — | Request command interpreted by shell. |
| ts-spawn-arg-shell | typescript | SKY-D212 | — | Request argument incorporated in shell command. |
| ts-execfile-arg-shell | typescript | SKY-D212 | — | Execfile shell opt in. |
| ts-spawn-sync-shell | typescript | SKY-D212 | — | String shell option. |
| ts-execfile-sync-shell | typescript | SKY-D212 | — | Synchronous shell opt in. |
| ts-spawn-default-argv | typescript | — | SKY-D212 | Request argument remains separate argv. |
| ts-spawn-false-argv | typescript | — | SKY-D212 | Shell explicitly disabled. |
| ts-execfile-default-argv | typescript | — | SKY-D212 | Execfile defaults to argv. |
| ts-spawn-spread-unsafe | typescript | SKY-D212 | — | Last own property enables shell. |
| ts-spawn-spread-safe | typescript | — | SKY-D212 | Last own property disables shell. |
| ts-spawn-alias-shell | typescript | SKY-D212 | — | Imported sink function value alias. |
| ts-spawn-shadow-safe | typescript | — | SKY-D212 | Local provider lookalike does not execute. |
| ts-spawn-literal-shell | typescript | — | SKY-D212 | No request-controlled command text. |
| python-pickle-direct-unsafe | python | SKY-D205 | — | Request bytes are passed directly to the actual pickle.loads provider. |
| python-pickle-capture-unsafe | python | SKY-D205 | — | A captured pickle.loads function still deserializes request bytes. |
| python-pickle-capture-rebind-unsafe | python | SKY-D205 | — | Rebinding the pickle module name to json does not change a previously captured pickle.loads callable. |
| python-pickle-json-rebind-safe | python | — | SKY-D205 | The module name is rebound to json before loads is looked up, so this call parses data without unpickling. |
| python-pickle-custom-local-safe | python | — | SKY-D205 | A source-owned DataParser.loads method returns its input and does not unpickle. |
| python-json-capture-safe | python | — | SKY-D205 | A captured json.loads callable parses JSON and is not a pickle provider. |
| python-eval-direct-unsafe | python | SKY-D201 | — | Request text reaches the builtin eval function directly. |
| python-eval-capture-unsafe | python | SKY-D201 | — | Request text reaches the builtin eval function captured in a variable. |
| python-eval-custom-function-safe | python | — | SKY-D201 | A source-owned function named eval returns text without interpreting it. |
| python-command-direct-unsafe | python | SKY-D209, SKY-D212 | — | Request text reaches the real subprocess.run provider with shell=True. |
| python-command-capture-unsafe | python | SKY-D209, SKY-D212 | — | A captured subprocess.run provider still executes request text with shell=True. |
| python-command-custom-local-safe | python | — | SKY-D209, SKY-D212 | A source-owned DataSink.run method accepts a shell keyword but only returns its input. |
| go-parsed-host-only | go | SKY-D230 | — | An empty parsed Host still permits http:outside.example. A redirect from an HTTPS base can leave the origin; reject nonempty Scheme as well. |
| go-parsed-host-and-scheme | go | — | SKY-D230 | Both the parsed Host and Scheme must be empty and parsing must succeed before redirecting a relative destination. |
| go-global-allowlist-other-file-mutation | go | SKY-D230 | — | A sibling helper inserts the request destination into the package map before its membership check; a literal initializer alone is not an allowlist proof. |
| go-global-boundary-other-file-mutation | go | SKY-D215 | — | A sibling init function replaces the directory boundary with the filesystem root; the original package variable is not a fixed containment boundary. |
| go-path-and-late-write | go | SKY-D215 | — | IsLocal checks the old string; the RHS operand overwrites it before the guarded sink. |
| go-path-and-check-after-write | go | — | SKY-D215 | The final check sees the replacement and every path to the sink requires it to be local. |
| go-redirect-and-late-write | go | SKY-D230 | — | The old literal comparison is true before an independent request-controlled destination replaces the string. |
| go-redirect-and-check-after-write | go | — | SKY-D230 | The final comparison constrains the actual replacement destination to the trusted literal. |
| go-parallel-old-check-new-value | go | SKY-D215 | — | Go evaluates both RHS expressions before assigning either LHS: local checks the old name while the sink uses the replacement. |
| go-parallel-same-value-check | go | — | SKY-D215 | The parallel assignment preserves the same string that IsLocal checked. |
| go-parsed-url-pointer-alias-cleared | go | SKY-D230 | — | url.Parse returns a pointer. Clearing Host/Scheme through its alias makes checks pass, while redirect still uses the original unmodified external string. |
| go-parsed-url-unmodified | go | — | SKY-D230 | The actual parsed value is checked for both external authority and scheme before redirecting the original string. |
| go-inner-shadow-guard-outer-unsafe | go | SKY-D215 | — | The checked inner name is a different Go lexical variable. The unvalidated outer request value reaches the sink. |
| go-outer-guard-inner-shadow-safe | go | — | SKY-D215 | The outer variable remains checked and unchanged; reading an unrelated inner lexical variable cannot invalidate it. |
| typescript-redirect-operator-env-safe | typescript | — | SKY-D230 | An unmodified operator environment setting plus a fixed profile path is independent of HTTP request input. |
| typescript-redirect-env-request-suffix | typescript | SKY-D230 | — | A request value is appended to the operator setting; the environment reference does not sanitize that request input. |
| typescript-redirect-env-request-write | typescript | SKY-D230 | — | Request input overwrites the environment setting before it reaches the redirect; a static environment key is not a safety proof. |
| go-cookie-flag-from-config | go | — | SKY-D252 | Secure follows a parameter, a config field or the request scheme while HttpOnly is true; no flag is missing or literally off. |
| go-cookie-secure-absent | go | SKY-D252 | — | A session cookie sets HttpOnly but leaves the Secure key out. |
| go-cookie-httponly-disabled | go | SKY-D252 | — | HttpOnly is literally false even though Secure is computed at run time. |
| go-handle-stored-in-literal | go | — | SKY-G260 | An opened file placed in a struct literal that outlives the function is owned by that value and closed later. |
| go-handle-name-only-literal | go | SKY-G260 | — | A literal that copies only the file name and descriptor number does not take over the open handle. |
| java-ssrf-fixed-host | java | — | SKY-D216 | A request value appended after a literal scheme and host cannot choose the destination. |
| java-open-redirect-fixed-local-prefix | java | — | SKY-D230 | A Spring redirect view with a fixed local path prefix keeps the browser on the same site. |
| java-ldap-filter-arguments | java | — | SKY-D239 | A request value passed as a {0} filter argument is escaped by JNDI and is not part of the filter text. |
| java-xpath-variable-resolver | java | — | SKY-D229 | A constant XPath expression reads the request value through a variable resolver. |
| java-sql-jdbctemplate-concat | java | SKY-D211 | — | A Spring request parameter is concatenated into JdbcTemplate query text. |
| java-sql-jdbctemplate-bound | java | — | SKY-D211 | The same query binds the request parameter through a placeholder. |
| java-command-shell-request | java | SKY-D212 | — | A Spring request parameter is the command text of sh -c. |
| java-command-fixed-argv | java | — | SKY-D212 | A fixed argument vector runs while the request value only labels the response. |
| java-xss-response-writer | java | SKY-D226 | — | A request parameter is written into an HTML servlet response. |
| java-xss-response-writer-escaped | java | — | SKY-D226 | The same response writes the parameter through HtmlUtils.htmlEscape. |
| java-deserialize-request-stream | java | SKY-D204 | — | ObjectInputStream reads Java objects straight from the request body. |
| java-deserialize-jackson-class | java | — | SKY-D204 | Jackson binds the request body to one concrete class without polymorphic typing. |
| java-weak-hash-md5 | java | SKY-D207 | — | MessageDigest MD5 digests a password. |
| java-hash-sha256 | java | — | SKY-D207 | The same digest uses SHA-256. |
| kotlin-redirect-request-target | kotlin | SKY-D230 | — | A Ktor query parameter is the redirect target. |
| kotlin-redirect-literal-target | kotlin | — | SKY-D230 | The redirect target is a literal; the query parameter is only measured for a log line. |
| kotlin-xss-respond-html | kotlin | SKY-D226 | — | A Ktor query parameter is interpolated into a text/html response. |
| kotlin-xss-respond-plain | kotlin | — | SKY-D226 | The same text is sent as text/plain, which browsers do not render as markup. |
| kotlin-deserialize-request-stream | kotlin | SKY-D204 | — | ObjectInputStream reads Java objects from the Ktor request body. |
| kotlin-deserialize-json-class | kotlin | — | SKY-D204 | kotlinx.serialization decodes the request body into one data class. |
| secret-bun-lock-current-versions | typescript | — | SKY-S101 | A Bun 1.4 lockfile (lockfileVersion 2): registry integrity digests and the owner-repo-commit id of a GitHub dependency are not credentials. |
| secret-bun-lock-unproven-values | typescript | SKY-S101 | — | The integrity slot and the Git resolution slot of a Bun lockfile hold random tokens that are neither an SRI digest nor the descriptor's own id. |
| secret-reader-text-and-names | typescript, java, python, shell | — | SKY-S101 | Credential-named keys holding UI sentences, a description, a storage key name, an environment variable name and interpolation references in TypeScript, Java, Python, YAML and shell. |
| secret-reader-text-lookalikes | typescript, python, shell | SKY-S101 | — | The same shapes carrying a random value: a sentence with a code, a storage name with a random part, a description key holding a token, and interpolations with a literal default. |
| secret-base64-of-text | typescript, java | — | SKY-S101, SKY-S101 | Base64 literals that decode to printable CSS selectors in TypeScript and Java: their entropy comes from the encoding. |
| secret-base64-of-binary-or-pair | typescript | SKY-S101 | — | Base64 literals that decode to random bytes and to a user:password pair stay reported. |
| prompt-native-script-and-shown-characters | python | — | SKY-D260 | Ukrainian and Greek translation files with JSON escapes, zero-width characters passed as whole literals to str.replace, and Japanese text with word-break hints. |
| prompt-homoglyph-and-split-keyword | python | SKY-D260 | — | A Cyrillic letter inside Latin identifiers (also inside a translation file) and a zero-width character splitting an instruction keyword. |
| ci-env-file-literal-write | python, shell | — | SKY-D300 | Quoted and bare literals written to GITHUB_PATH and GITHUB_ENV: nothing computed or attacker-supplied. |
| ci-env-file-expanded-write | python, shell | SKY-D300 | — | A variable, an Actions expression and a command substitution written to GITHUB_PATH and GITHUB_ENV. |
| ci-called-workflow-drops-write-scope | python, shell | — | SKY-D291 | The caller's workflow-level id-token: write is inherited by one ordinary job and by a job that calls a local workflow whose own permissions are contents: read. |
| ci-called-workflow-inherits-write-scope | python, shell | SKY-D291 | — | The called local workflow has a job that takes id-token: write, so the caller's workflow-level scope reaches it. |
| rust-path-private-helper-fixed-caller | rust | — | SKY-D215 | A private helper takes a path parameter, but its only caller passes a path built from constants; there is no untrusted source. |
| rust-path-private-helper-argument-caller | rust | SKY-D215 | — | The same private helper also receives the first command-line argument from one caller, so the path can be chosen from outside. |
| rust-path-test-module-helper | rust | — | SKY-D215 | A helper inside a #[cfg(test)] module removes a directory the test created; test-only code has no external caller. |
| rust-path-not-test-export | rust | SKY-D215 | — | #[cfg(not(test))] marks production code: a public function writes to a caller-supplied path. |
| rust-path-cargo-build-script | rust | — | SKY-D215 | A Cargo build script writes a generated file under OUT_DIR, a variable Cargo sets for build scripts. |
| rust-path-build-script-custom-variable | rust | SKY-D215 | — | A build script writes to a path taken from a variable Cargo does not set, so the environment chooses the file. |
| rust-path-axum-extractor | rust | SKY-D215 | — | An axum handler joins a request path segment into a file read. |
| rust-path-local-extractor-lookalike | rust | — | SKY-D215 | A tuple struct from the application's own module is destructured like an extractor; it is not request input. |
| typescript-axios-type-guard | typescript | — | SKY-D216 | axios.isAxiosError and axios.isCancel inspect an error object and send no request. |
| typescript-axios-request-beside-guard | typescript | SKY-D216 | — | The same module also sends axios.get to a URL taken from the request. |
| typescript-fetch-asset-url-import | typescript | — | SKY-D216 | A default import from a ?url specifier is an asset URL fixed at build time. |
| typescript-fetch-module-default-import | typescript | SKY-D216 | — | A default import from an ordinary module can hold any URL. |
| typescript-fetch-device-package | typescript | — | SKY-D216 | The package depends on react-native and no server runtime: fetch runs on the user's device and has no server network position. |
| typescript-fetch-device-package-with-server | typescript | SKY-D216 | — | The package also depends on a server framework, so the fetch of a request-supplied URL can run on a server. |
| typescript-fetch-client-component | typescript | — | SKY-D216 | A module with the "use client" directive runs its fetcher in the browser. |
| typescript-fetch-route-handler | typescript | SKY-D216 | — | A Next.js route handler in the same kind of package fetches a query parameter on the server. |
| typescript-fetch-browser-package | typescript | — | SKY-D216 | The package depends on a browser UI runtime and no server runtime: its HTTP helper runs in the browser. |
| typescript-fetch-browser-package-node-script | typescript | SKY-D216 | — | A module of the same package imports node:fs, so it runs in Node and its fetch of a caller-supplied URL is reported. |
| typescript-timing-undefined-presence | typescript | — | SKY-D253 | Comparing an optional key with the global undefined is a presence check, not a comparison of secret contents. |
| typescript-timing-webhook-token | typescript | SKY-D253 | — | A request token is compared with the configured webhook token using ===. |
| python-ssrf-mapping-lookup | python | — | SKY-D216 | self._session_replacements is only ever a dict, so .get(key) is a lookup and not an HTTP request. |
| python-ssrf-mapping-or-client | python | SKY-D216 | — | The same attribute can also hold an httpx.Client, so .get(value) can be a request to a request-supplied URL. |
| python-secret-log-masked-helper | python | — | SKY-D251 | The printed values are the key file path and a mask that keeps six leading and four trailing characters. |
| python-secret-log-raw-beside-mask | python | SKY-D251 | — | The raw key is printed next to its masked form. |
| python-secret-log-helper-named-redact | python | SKY-D251 | — | A helper named redact returns the whole key without dashes; its name is not a proof. |
| python-dynamic-import-fixed-table | python | — | SKY-D357 | The module name is a value of a constant table; the command-line argument only selects a key. |
| python-dynamic-import-alias-fallback | python | SKY-D357 | — | The table lookup falls back to the raw command-line argument, so any module can be imported. |
| python-hf-local-checkpoint-path | python | SKY-D345 | — | A Path annotation may still hold a Hub repository id; offline-only and explicit absolute-path controls do not fetch mutable artifacts. |
| python-hf-string-reference | python | SKY-D345 | — | A str parameter may be a Hub repository id, so the download has no pinned revision. |
| python-path-fullmatch-validated-name | python | — | SKY-D215 | The route rejects every name that does not fully match letters, digits, dash and underscore before joining it into a path. |
| python-path-prefix-match-name | python | SKY-D215 | — | match without an end anchor accepts a/../../x, so the joined path can leave the directory. |
| python-path-search-checked-name | python | SKY-D215 | — | re.search finds one allowed character anywhere; ../x still passes. |
| python-mcp-constructor-bind-all | python | SKY-D243 | — | FastMCP takes host=0.0.0.0 in its constructor and run() starts a network transport without authentication. |
| python-mcp-constructor-host-stdio | python | — | SKY-D243 | The same constructor host is unused when the server runs on stdio; no socket is opened. |
| rust-path-declared-test-module-file | rust | — | SKY-D215 | The parent module declares the file as #[cfg(test)] mod storage_tests; so the whole file is test-only code. |
| rust-path-plain-module-file | rust | SKY-D215 | — | The same file declared with a plain mod is production code: a public function reads under a caller-supplied directory. |
| python-secret-log-client-result | python | — | SKY-D251 | A helper reads the key and builds a client; the printed value is an API result of that client, not the key. |
| rust-path-private-helper-child-module-caller | rust | SKY-D215 | — | A private helper has one fixed caller in its own file, but a child module file calls it through super:: with a caller-supplied name. |
| csharp-open-redirect-member-guard-safe | csharp | — | SKY-D230 | A Redirect of model.ReturnUrl inside if (Url.IsLocalUrl(model.ReturnUrl)) is guarded by the framework check and should stay quiet. |
| csharp-open-redirect-member-guard-other-property | csharp | SKY-D230 | — | An IsLocalUrl check of one property does not guard a redirect of another property or of the same property on another object. |

## Separate adversarial case lists

### dead_code

| Case | Description |
| --- | --- |
| extreme-grounding-framework-dead-code | Dead-code view of framework, package-entrypoint, app-root, and CLI-root grounding. |
| static-blind-plugin-dispatch-dead-code | Dead-code view of dynamic plugin dispatch through module:function strings and importlib. |
| corpus-type-registry-owner | An exact-type callback is selected from one registry instance; another type, another instance and an unregistered function stay uncalled. |
| corpus-type-registry-mismatch | Registering a string callback does not call its body when the only message has integer type. |
| corpus-type-registry-rebound | Replacing a decorator method with an identity decorator leaves the original registry empty and its callback uncalled. |
| corpus-type-registry-snapshot | A copied callback table preserves its earlier function after the original registry replaces the same type key. |
| corpus-type-registry-closure | A closure-owned type registry returns its decorator and sender; only the callback for the supplied integer is called. |
| corpus-type-registry-hierarchy | An MRO-based type registry selects the base-class callback for a concrete subclass while another owner remains separate. |
| corpus-type-registry-private | A module-private registry selects a typed callback by MRO and channel while another type, another owner and an unregistered callback remain separate. |
| corpus-protocol-fields-native | An assigned native protocol callback is read for metadata when a completion callback constructs a nested record. |
| corpus-protocol-fields-alias | A module import alias and an assigned named function descriptor preserve the native metadata protocol through a method-local record. |
| corpus-protocol-fields-local | A local API with the same class spelling has no callback metadata reader, so its assigned attributes remain unused. |
| corpus-protocol-fields-source | A source-owned base constructor reads an arbitrarily named assigned callback for metadata while a sibling has no reader. |
| corpus-conditional-assets-direct | Direct HTML script references preserve exact paths while ordinary and malformed comments do not load scripts. |
| corpus-conditional-assets-plain | Legacy IE conditional HTML script references preserve the exact asset without treating ordinary or malformed comments as loads. |
| corpus-conditional-assets-jinja | Legacy IE conditional HTML script references support the native Jinja safe filter on simple literal paths while comments and wrong paths remain unused. |
| csharp-owner-call-identity | Main constructs both namespace-specific Worker classes but only invokes Primary.Run→Primary.Process. The Secondary private method has no caller; its owner is constructed so parent grouping cannot hide it. |

### security

| Case | Description |
| --- | --- |
| kotlin-command-argv | The executable and printf format are fixed; request data occupies an argv data element and no shell runs. |
| go-ssrf-function-alias | Same get function invoked via local value; known unresolved native detector miss. |
| go-ssrf-method-alias | Bound http client method value; known unresolved native detector miss. |
| go-command-function-alias | Same command function via local value; known unresolved native detector miss. |
| go-path-function-alias | Same filesystem sink via value; known unresolved native detector miss. |
| go-ssrf-request-alias | Go type alias preserves exact http.request identity; known unresolved native detector miss. |
| go-tls-field-assignment | Typed tls config field assignment disables validation; known unresolved native detector miss. |
| dart-process-fake-canonicalize | A local identity helper named canonicalize does not make an environment-controlled executable safe. |
| dart-http-fake-canonicalize | A local identity helper named canonicalize does not restrict an environment-controlled URL destination. |

### agent_review

| Case | Description |
| --- | --- |
| extreme-grounding-framework | Adversarial repo with app roots, decorator roots, package script roots, safe lookalikes, mutable allowlist traps, and dead risky decoys. |
| static-blind-plugin-dispatch | Dynamic plugin dispatch through module:function strings and importlib, with live vulnerabilities, safe lookalikes, and dead risky decoys. |

These challenge expectations preserve known hard cases; inclusion is not a claim they currently pass. Their results belong separately in the execution report, not hidden from a default-suite score.

## Desktop benchmark recovery

Inspected `/Users/oha/Desktop/skylos-benchmark-2026-11-14`: `out/` and `logs/`; no report named `confirmed_results.md` or `confirmed_results.combined.md`, label manifest, source checkouts or archive is present in that directory. The recovered `logs/score40b.txt` records an original report at `/Users/oha/skylos-bench-5.3.0/round-2026-11-13/confirmed_results.combined.md`. That log reports 6,525 Python dead-code, 848 TS dead-code, 4,816 security and 4,067 slop label items; the labels themselves are not in this recovered tree. Those numbers are historical log claims, not reconstructed scores.

All 91 target directory names appear below exactly as recovered. Names prefixed `old__` are preserved; `old__fastapi-template__frontend` and `old__locust__webui` are separate scan scopes, so 91 directories do not mean 91 distinct repositories. Languages are copied from the first parseable saved Skylos JSON with `analysis_summary.languages`, preferring main dead-code, main all-checks, then other arms. They describe that saved arm only. Missing JSON is marked unknown rather than inferred from a project name.

| Target directory | Recorded language/file counts | Language source | Recorded coverage | Saved Skylos JSON arms |
| --- | --- | --- | --- | --- |
| agenticseek | Unknown (no usable saved summary) | — | — | None |
| ai-goofish-monitor | JavaScript (4), Python (115), Shell (2), TypeScript (46) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| browser-harness | Unknown (no usable saved summary) | — | — | None |
| ccg-workflow | Unknown (no usable saved summary) | — | — | None |
| convert | Unknown (no usable saved summary) | — | — | None |
| cookiecutter | Python (90), Shell (7) | skylos-main.json | partial | edit-a, edit, fixed-a, fixed, main-a, main |
| cuawright | Unknown (no usable saved summary) | — | — | None |
| dev-browser | JavaScript (3), TypeScript (75) | skylos-main.json | partial | edit, fixed, main |
| dexter | JavaScript (1), Shell (1), TypeScript (217) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| elephant-goldfish-model | JavaScript (10), Python (30), TypeScript (3) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| etcher | JavaScript (4), TypeScript (89) | skylos-main.json | partial | edit, fixed, main |
| fingerprintjs | JavaScript (1), TypeScript (116) | skylos-main.json | complete | edit, fixed, main |
| fugleramme | JavaScript (10), Python (85), Shell (7) | skylos-main.json | complete | main-a, main |
| ghostty-web | JavaScript (3), Shell (2), TypeScript (40) | skylos-main.json | complete | main-a, main |
| github1s | Unknown (no usable saved summary) | — | — | None |
| gooey | Unknown (no usable saved summary) | — | — | None |
| gpt-oss | C++ (21), Python (62), TypeScript (6) | skylos-main.json | partial | main-a, main |
| harness2 | Python (72), Shell (4) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| kirara-ai | Python (288), Shell (1) | skylos-main.json | complete | main-a, main |
| magic-wormhole | JavaScript (1), Python (99), Shell (2) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| mamba | C++ (1), Python (68), Shell (4) | skylos-main.json | partial | main-a, main |
| mini-swe-agent | Unknown (no usable saved summary) | — | — | None |
| newsnow | JavaScript (2), TypeScript (125) | skylos-main.json | complete | main-a, main |
| old__annotated_deep_learning_paper_implementations | JavaScript (4), Python (228) | skylos-main.json | partial | edit-a, edit, fixed, main-a, main |
| old__asgiref | Unknown (no usable saved summary) | — | — | None |
| old__asn1crypto | Python (61), Shell (1) | skylos-main.json | complete | main-a, main |
| old__asyncpg | Unknown (no usable saved summary) | — | — | None |
| old__attrs | Unknown (no usable saved summary) | — | — | None |
| old__authlib | Python (349) | skylos-main.json | complete | main-a, main |
| old__ChatDev | Unknown (no usable saved summary) | — | — | None |
| old__click | Python (63), Shell (1) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__CloakBrowser | Unknown (no usable saved summary) | — | — | None |
| old__code-server | JavaScript (2), Shell (18), TypeScript (85) | skylos-main.json | complete | main-a, main |
| old__docker-py | Python (136), Shell (2) | skylos-main.json | complete | main-a, main |
| old__fastapi-template | Unknown (no usable saved summary) | — | — | None |
| old__fastapi-template__frontend | TypeScript (101) | skylos-main.json | complete | main |
| old__fish-speech | Unknown (no usable saved summary) | — | — | None |
| old__flask | Unknown (no usable saved summary) | — | — | None |
| old__google-api-python-client | JavaScript (1), Python (86), Shell (13) | skylos-main.json | partial | main-a, main |
| old__gpt-pilot | JavaScript (52), Python (151), Shell (3), TypeScript (136) | skylos-main.json | partial | edit-a, edit, main-a, main |
| old__graphrag | JavaScript (1), Python (579), Shell (3), TypeScript (2) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__HanLP | Java (13), Python (479) | skylos-main.json | partial | edit-a, edit, main-a, main |
| old__heretic | Unknown (no usable saved summary) | — | — | None |
| old__homebridge | Unknown (no usable saved summary) | — | — | None |
| old__httplib2 | JavaScript (2), Python (29), Shell (1) | skylos-main.json | complete | main-a, main |
| old__httpx | Python (60) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__intro.js | JavaScript (8), PHP (1), Shell (1), TypeScript (128) | skylos-main.json | complete | main |
| old__iptv | JavaScript (5), TypeScript (63) | skylos-main.json | complete | main-a, main |
| old__khoj | Unknown (no usable saved summary) | — | — | None |
| old__langextract | Python (93), Shell (4) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| old__locust | Unknown (no usable saved summary) | — | — | None |
| old__locust__webui | JavaScript (1), TypeScript (151) | skylos-main.json | complete | main |
| old__maigret | Unknown (no usable saved summary) | — | — | None |
| old__MediaCrawler | JavaScript (5), Python (186), TypeScript (41) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| old__microblog | Python (34), Shell (1) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__NextChat | Unknown (no usable saved summary) | — | — | None |
| old__OCRmyPDF | Unknown (no usable saved summary) | — | — | None |
| old__OpenManus | Python (90), TypeScript (1) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| old__PDFMathTranslate | Unknown (no usable saved summary) | — | — | None |
| old__pre-commit | Go (1), Python (134), Rust (1), Shell (13) | skylos-main.json | partial | main-a, main |
| old__pydantic | Unknown (no usable saved summary) | — | — | edit-a, main-a |
| old__rapidfuzz | Unknown (no usable saved summary) | — | — | None |
| old__rembg | Python (46) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__requests | Unknown (no usable saved summary) | — | — | None |
| old__rich | Python (213) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| old__Scrapegraph-ai | Python (269) | skylos-main.json | complete | main-a, main |
| old__searxng | Unknown (no usable saved summary) | — | — | None |
| old__starlette | Python (84) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__tabby | C++ (2), JavaScript (37), TypeScript (297) | skylos-main.json | partial | main-a, main |
| old__timesfm | Unknown (no usable saved summary) | — | — | None |
| old__tqdm | Python (67), Shell (1) | skylos-main.json | complete | edit-a, edit, main-a, main |
| old__traitlets | Unknown (no usable saved summary) | — | — | None |
| old__yolov5 | Python (52), Shell (7) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| old__you-get | Python (137), Shell (2) | skylos-main.json | complete | edit-a, edit, main-a, main |
| open-r1 | Python (39), Shell (3) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| openreply | JavaScript (2), Shell (1), TypeScript (187) | skylos-main.json | partial | main-a, main |
| oriontv | JavaScript (3), TypeScript (83) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| pocket-tts | Python (92), Rust (13), Shell (1) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| qwerty-learner | JavaScript (5), Rust (2), Shell (2), TypeScript (156) | skylos-main.json | complete | main-a, main |
| rea-video | Python (88), Shell (1) | skylos-main.json | complete | edit-a, edit, fixed, main-a, main |
| react-use | Unknown (no usable saved summary) | — | — | None |
| rlm | Unknown (no usable saved summary) | — | — | None |
| sol-pi | Unknown (no usable saved summary) | — | — | None |
| spotify-downloader | Unknown (no usable saved summary) | — | — | None |
| superclaude_framework | Python (52), Shell (6), TypeScript (4) | skylos-main.json | complete | edit, fixed-a, fixed, main |
| surya | Python (55) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| switchhosts | JavaScript (5), Rust (59), TypeScript (159) | skylos-main.json | complete | edit-a, edit, fixed-a, fixed, main-a, main |
| tradingagents-astock | Python (133) | skylos-main.json | complete | main-a, main |
| universal-modder | C# (28), C++ (14), Java (44), JavaScript (9), Python (95), Shell (11), TypeScript (1) | skylos-main.json | partial | edit-a, edit, fixed, main-a, main |
| vit-pytorch | Unknown (no usable saved summary) | — | — | None |
| youtu-agent | JavaScript (3), Python (268), Shell (2), TypeScript (56) | skylos-main.json | partial | edit-a, edit, fixed, main-a, main |

Saved JSON availability does not certify complete or comparable execution. `main`, `edit`, `fixed` and `-a` arms differ in source/profile, and timestamps/version strings alone do not establish exact detector identity. Some recorded language inventories contain unsupported/unchecked files or multiple languages. Confirm completeness separately before scoring.

## Historical 70-repository cohort

Copied identities and statuses from the checked-in 8 November report for de-duplication when choosing new repositories. These are historical outcomes, not reruns on today's scanner.

| Language | Repository / exact commit | Skylos default status | Source-confirmed FP | Emitted dead-code/security diagnostics | Unreviewed quality diagnostics | Comparator execution statuses |
| --- | --- | --- | ---: | ---: | ---: | --- |
| python | [tox-dev/pyproject-api@ab35d3ab13](https://github.com/tox-dev/pyproject-api/tree/ab35d3ab1333f0b4033752d1809164abe7ca2fb3) | completed (guard replay) | 0 | 2 | 13 | vulture: completed; ruff-unused: completed; bandit: completed; semgrep-python: completed |
| python | [python-trio/outcome@03ed6218b0](https://github.com/python-trio/outcome/tree/03ed6218b08001877745bb1a9e180c8c5cf7c903) | completed (guard replay) | 0 | 5 | 3 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [tkem/cachetools@1ce79efa55](https://github.com/tkem/cachetools/tree/1ce79efa552d1bdda70d144d401ef9105d999184) | completed | 0 | 14 | 30 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [pypa/pyproject-hooks@184c9f56a8](https://github.com/pypa/pyproject-hooks/tree/184c9f56a87ede1276a5b33f5024204adb792cd2) | completed | 1 | 1 | 7 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [python-humanize/humanize@d16e6352c9](https://github.com/python-humanize/humanize/tree/d16e6352c9785c5ab86de0133222bd22e89b0db2) | completed | 0 | 0 | 28 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| typescript | [privatenumber/resolve-pkg-maps@6d78804995](https://github.com/privatenumber/resolve-pkg-maps/tree/6d788049958514dbce52ef2bebc633f0ad336b51) | completed | 0 | 10 | 18 | knip-static: completed; semgrep-typescript: completed |
| typescript | [unjs/defu@82632b66f5](https://github.com/unjs/defu/tree/82632b66f5914e9946edce300e10633a3d5c0cb7) | completed | 1 | 5 | 8 | knip-static: incomplete; semgrep-typescript: completed |
| typescript | [unjs/scule@5bc68048ca](https://github.com/unjs/scule/tree/5bc68048caad7c0e7de35842c83a510e8e1a7c4f) | completed | 0 | 8 | 5 | knip-static: completed; semgrep-typescript: completed |
| typescript | [danielroe/errx@cb8ff401ad](https://github.com/danielroe/errx/tree/cb8ff401ad07e8aa2b1c448a535248a357de5744) | completed | 0 | 1 | 5 | knip-static: completed; semgrep-typescript: incomplete |
| typescript | [unjs/untun@dfd84231c7](https://github.com/unjs/untun/tree/dfd84231c740a514120e4d7c0efd622822908798) | completed | 2 | 7 | 4 | knip-static: completed; semgrep-typescript: completed |
| javascript | [lukeed/uvu@1a47ca1434](https://github.com/lukeed/uvu/tree/1a47ca14347e085330759911fc6c090e584be12f) | completed | 1 | 10 | 54 | knip-static: incomplete; semgrep-javascript: completed |
| javascript | [ai/nanoid@055d1700cc](https://github.com/ai/nanoid/tree/055d1700cc67ac843e3efb5235d806b419ec7b2b) | completed | 7 | 7 | 13 | knip-static: completed; semgrep-javascript: completed |
| javascript | [sindresorhus/yoctocolors@a85b98a90e](https://github.com/sindresorhus/yoctocolors/tree/a85b98a90e5731914567d8c209e7ec45ac2d24e2) | completed | 4 | 10 | 2 | knip-static: completed; semgrep-javascript: completed |
| javascript | [isaacs/once@0fbb41ec58](https://github.com/isaacs/once/tree/0fbb41ec58d13f6f222fdccd03429a892606000b) | completed | 1 | 10 | 2 | knip-static: completed; semgrep-javascript: completed |
| javascript | [sindresorhus/slash@2e8a56bd8b](https://github.com/sindresorhus/slash/tree/2e8a56bd8b2863be09d4fc85283c0e465131a6d3) | completed | 2 | 6 | 2 | knip-static: completed; semgrep-javascript: completed |
| go | [cenkalti/backoff@ce2ae81589](https://github.com/cenkalti/backoff/tree/ce2ae81589e4316be0722e20928b2f9a6d28335a) | completed | 0 | 4 | 7 | staticcheck: incomplete; semgrep-go: completed |
| go | [hashicorp/go-cleanhttp@b0e8488e2f](https://github.com/hashicorp/go-cleanhttp/tree/b0e8488e2fe29dce6a369099f264aa046c27b659) | completed | 0 | 3 | 3 | staticcheck: incomplete; semgrep-go: completed |
| go | [google/go-querystring@854f39986c](https://github.com/google/go-querystring/tree/854f39986c87d97512b6cc5c59ccee17a72b248e) | completed | 0 | 3 | 13 | staticcheck: incomplete; semgrep-go: completed |
| go | [rs/cors@7ca5fe28f7](https://github.com/rs/cors/tree/7ca5fe28f7d56465f559f143e5ee3758f8baf33d) | completed | 0 | 4 | 11 | staticcheck: incomplete; semgrep-go: completed |
| go | [dustin/go-humanize@f5b54ae139](https://github.com/dustin/go-humanize/tree/f5b54ae1392365a578bb43ab728e3fcdc291f0cd) | completed | 0 | 4 | 13 | staticcheck: incomplete; semgrep-go: completed |
| java | [EsotericSoftware/minlog@f032e8c7c5](https://github.com/EsotericSoftware/minlog/tree/f032e8c7c56f8a4b70ec7a9692f47a72e06ec9b4) | completed | 0 | 0 | 2 | pmd: unavailable; semgrep-java: completed |
| java | [kohsuke/wordnet-random-name@91f2497c0c](https://github.com/kohsuke/wordnet-random-name/tree/91f2497c0c98a0400474c484a95cc984981f2521) | completed | 0 | 0 | 2 | pmd: unavailable; semgrep-java: completed |
| java | [jhalterman/typetools@4d3e59a465](https://github.com/jhalterman/typetools/tree/4d3e59a4651170a920309754e70a1fc9a2b9e6d5) | completed | 4 | 4 | 14 | pmd: unavailable; semgrep-java: completed |
| java | [davidmoten/word-wrap@e33d8eed74](https://github.com/davidmoten/word-wrap/tree/e33d8eed74918bf34bd3f79d464b94bb6f18c3c8) | completed | 4 | 7 | 10 | pmd: unavailable; semgrep-java: completed |
| java | [jchambers/java-otp@06c26e8b55](https://github.com/jchambers/java-otp/tree/06c26e8b5586cc4032a08be2021a9a1b129b0492) | completed | 0 | 4 | 2 | pmd: unavailable; semgrep-java: completed |
| php | [clue/stream-filter@a291df9574](https://github.com/clue/stream-filter/tree/a291df95744d459cb35704b10c2db64ec2506b87) | completed | 1 | 6 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [ramsey/collection@1678fd9462](https://github.com/ramsey/collection/tree/1678fd9462f52aa77532479fdf37c3bae47dd8fe) | completed | 0 | 14 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [theseer/tokenizer@52a7b89c4a](https://github.com/theseer/tokenizer/tree/52a7b89c4aa776e5dfbb1ae05d29495d55dbea6e) | completed | 3 | 6 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [paragonie/constant_time_encoding@5efef6e6cb](https://github.com/paragonie/constant_time_encoding/tree/5efef6e6cb43e088ccab7d0c1e2f2ab25b9e8b54) | completed | 5 | 21 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [reactphp/promise@63cde9c050](https://github.com/reactphp/promise/tree/63cde9c050a876ac25d2d2880c0a2a000b26e211) | completed | 0 | 3 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| rust | [dtolnay/anyhow@87c8571326](https://github.com/dtolnay/anyhow/tree/87c8571326d60b90391d0555c9675b5ac6f044b1) | incomplete | 1 | 12 | 2 | clippy: unavailable; semgrep-rust: incomplete |
| rust | [matklad/once_cell@80fe900b21](https://github.com/matklad/once_cell/tree/80fe900b21f6d76c1a2ed74d3343e8a3a88c46d0) | completed | 0 | 2 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [petgraph/fixedbitset@111fb25521](https://github.com/petgraph/fixedbitset/tree/111fb2552130f6f4c06a4a1a2e0de7ea6e28b922) | completed | 0 | 4 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [dtolnay/dyn-clone@23fcf09d96](https://github.com/dtolnay/dyn-clone/tree/23fcf09d96222d9f0f11a204ae6193af27362f72) | completed | 1 | 13 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [sfackler/rust-fallible-iterator@0b4fdb728e](https://github.com/sfackler/rust-fallible-iterator/tree/0b4fdb728e643c1cbd9ce06868715bbf98f9052a) | completed | 0 | 4 | 2 | clippy: unavailable; semgrep-rust: completed |
| dart | [felangel/equatable@8329906781](https://github.com/felangel/equatable/tree/832990678125b10103b26500ce8ce7188d775925) | completed | 8 | 13 | 2 | dart-analyzer: incomplete |
| dart | [tekartik/synchronized.dart@65b41ed7a3](https://github.com/tekartik/synchronized.dart/tree/65b41ed7a31344a224431a2b1fd43792b1bc2b53) | completed | 57 | 67 | 2 | dart-analyzer: incomplete |
| dart | [felangel/mocktail@d6a96e15b9](https://github.com/felangel/mocktail/tree/d6a96e15b9203d33af61083e02e8c40ac07192d6) | completed | 35 | 46 | 2 | dart-analyzer: incomplete |
| dart | [daegalus/dart-uuid@bf552fbad0](https://github.com/daegalus/dart-uuid/tree/bf552fbad09f15217e098a8082b86bb36c90fe0f) | completed | 87 | 100 | 106 | dart-analyzer: incomplete |
| dart | [jogboms/flutter_offline@8062f547c6](https://github.com/jogboms/flutter_offline/tree/8062f547c66677f14509185a90e5eb5f07fde52f) | completed | 16 | 21 | 2 | dart-analyzer: incomplete |
| csharp | [ardalis/GuardClauses@61dde6c9d3](https://github.com/ardalis/GuardClauses/tree/61dde6c9d3e1715286bd100144a9edff1ad0664c) | completed | 6 | 119 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| csharp | [ardalis/SmartEnum@e06da55095](https://github.com/ardalis/SmartEnum/tree/e06da550950b347f0ee47b1ec370a7416e79b030) | completed | 18 | 69 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| csharp | [Tyrrrz/CliWrap@6d1c90bced](https://github.com/Tyrrrz/CliWrap/tree/6d1c90bced37aa384d609d2a31f891d8b3c33734) | completed | 13 | 15 | 2 | csharp-native: unavailable; semgrep-csharp: incomplete |
| csharp | [drewnoakes/figgle@804efc8e65](https://github.com/drewnoakes/figgle/tree/804efc8e65276154ff7d71e2062ecd475ccd4e9f) | completed | 15 | 31 | 5 | csharp-native: unavailable; semgrep-csharp: incomplete |
| csharp | [WalkerCodeRanger/semver@4e10217ce1](https://github.com/WalkerCodeRanger/semver/tree/4e10217ce1fd5d51721ea3ca98cfe6abc0375c36) | completed | 54 | 54 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| cpp | [jarro2783/cxxopts@7af8aad55e](https://github.com/jarro2783/cxxopts/tree/7af8aad55eddd73715ded20d4478e242424a0bda) | incomplete | 0 | 15 | 4 | cppcheck: incomplete |
| cpp | [Neargye/magic_enum@d7b75f1407](https://github.com/Neargye/magic_enum/tree/d7b75f140707769031519fbe463449614433f285) | incomplete | 5 | 9 | 8 | cppcheck: incomplete |
| cpp | [Tessil/ordered-map@88b7a58f5e](https://github.com/Tessil/ordered-map/tree/88b7a58f5e9be7f87998bbcbdd3865023738ef92) | incomplete | 0 | 2 | 2 | cppcheck: incomplete |
| cpp | [serge-sans-paille/frozen@d53e0a1157](https://github.com/serge-sans-paille/frozen/tree/d53e0a11578d56dc331dc267c2084d52bcdee1d9) | incomplete | 0 | 7 | 2 | cppcheck: incomplete |
| cpp | [nemtrif/utfcpp@b54cc2d4bc](https://github.com/nemtrif/utfcpp/tree/b54cc2d4bc1a76985d383d9b814afa52a5b2ba0a) | incomplete | 0 | 6 | 4 | cppcheck: incomplete |
| kotlin | [michaelbull/kotlin-retry@2f2617e85a](https://github.com/michaelbull/kotlin-retry/tree/2f2617e85a18f5eee317328ba6c4f39e15c8175a) | completed | 0 | 0 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [michaelbull/kotlin-result@aed7438b2b](https://github.com/michaelbull/kotlin-result/tree/aed7438b2bd92adc704b5022e64cddf263e38800) | completed | 0 | 0 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [h0tk3y/better-parse@51557fd3a8](https://github.com/h0tk3y/better-parse/tree/51557fd3a89bddf86adeafe85a9eddc7d870b0ca) | completed | 0 | 11 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [skydoves/WhatIf@a5aa2ae068](https://github.com/skydoves/WhatIf/tree/a5aa2ae0685787c79c7b17b6d5552646095a7383) | completed | 0 | 8 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [jsoizo/kotlin-csv@8b557f2be1](https://github.com/jsoizo/kotlin-csv/tree/8b557f2be10ea89775fd38eb49a7336a26c6f9c1) | completed | 0 | 5 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| ruby | [mperham/connection_pool@17c1eefdac](https://github.com/mperham/connection_pool/tree/17c1eefdacebead60c5ac706b4c1088094e3b86b) | incomplete | 0 | 4 | 2 | semgrep-ruby: completed |
| ruby | [collectiveidea/interactor@c0e0079375](https://github.com/collectiveidea/interactor/tree/c0e0079375e8d447eadcd062d7bb3b550fcb60bb) | incomplete | 1 | 4 | 2 | semgrep-ruby: completed |
| ruby | [laserlemon/figaro@a2d7dcb70c](https://github.com/laserlemon/figaro/tree/a2d7dcb70c1af1e758089b7d529e0089177c5f51) | incomplete | 8 | 11 | 2 | semgrep-ruby: completed |
| ruby | [dry-rb/dry-inflector@65f186bb68](https://github.com/dry-rb/dry-inflector/tree/65f186bb68e5a40be8552dafc203d03cd35223a9) | incomplete | 5 | 9 | 2 | semgrep-ruby: completed |
| ruby | [dry-rb/dry-configurable@54da11fe9c](https://github.com/dry-rb/dry-configurable/tree/54da11fe9c85d8e170cf42be1028c21b07339981) | incomplete | 3 | 8 | 2 | semgrep-ruby: completed |
| swift | [pointfreeco/swift-tagged@6a85175780](https://github.com/pointfreeco/swift-tagged/tree/6a8517578035408b6c14ccba00ee990a1435515c) | incomplete | 0 | 3 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [mxcl/Version@3043fcd2a5](https://github.com/mxcl/Version/tree/3043fcd2a50375db76d89ff206a612471833d1c2) | completed | 0 | 11 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [apple/swift-numerics@669f618518](https://github.com/apple/swift-numerics/tree/669f6185187f8e1b5857a25c4bbe6c34a3a02b96) | incomplete | 0 | 2 | 2 | periphery: incomplete; semgrep-swift: incomplete |
| swift | [pointfreeco/swift-case-paths@57160303c3](https://github.com/pointfreeco/swift-case-paths/tree/57160303c3954432637a536d503d4c50f42bcaf6) | incomplete | 0 | 9 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [pointfreeco/swift-custom-dump@4fb9e7cbb4](https://github.com/pointfreeco/swift-custom-dump/tree/4fb9e7cbb4b8f5a7354005db39447f570d6b3e19) | incomplete | 0 | 10 | 2 | periphery: incomplete; semgrep-swift: incomplete |
| shell | [rcaloras/bash-preexec@5ae4758c36](https://github.com/rcaloras/bash-preexec/tree/5ae4758c36e8391fb3932e6ae68c283489fc813d) | incomplete | 0 | 3 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [basherpm/basher@7c3d238ce2](https://github.com/basherpm/basher/tree/7c3d238ce263856edbb99fee000613c01ba5712d) | incomplete | 15 | 20 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [nvm-sh/nvm@4e8758a801](https://github.com/nvm-sh/nvm/tree/4e8758a801eea9479b32a904f31093e410ddaba4) | incomplete | 34 | 101 | 2 | semgrep-shell: incomplete; shellcheck: incomplete |
| shell | [zsh-users/zsh-autosuggestions@85919cd1ff](https://github.com/zsh-users/zsh-autosuggestions/tree/85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5) | incomplete | 3 | 7 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [babarot/enhancd@190d739d59](https://github.com/babarot/enhancd/tree/190d739d597a486a9922363f3c1c4daa792f6cf1) | incomplete | 1 | 5 | 2 | shellcheck: incomplete; semgrep-shell: incomplete |

## Additions made during this review

These additions are separate from the unchanged task-start counts above. The
regression controls were authored while developing the patches; they are not
independent accuracy evidence.

| Manifest or receipt | Added evidence | Scope |
| --- | --- | --- |
| [deadcode-preload-manifest.json](deadcode-preload-manifest.json) | Three JavaScript cases: `node-import-preload`, `node-require-preload`, `node-preload-terminator`; four used-file and five unused-file controls | Exact Node attached preload operands, unused data/siblings, and end-of-options boundary |
| [security_null_corpus/manifest.json](security_null_corpus/manifest.json) | One TSX case, `typescript-null-html-reset-boundaries`; four quiet and seven required-warning locations | Literal-null DOM/React resets, dynamic nullable values, assertions, fallbacks, variadic output and augmented assignment; required warnings are conservative contracts, not seven demonstrated vulnerabilities |
| [blind_manifest.json](blind_manifest.json) | Final five pinned repositories: gorilla/mux, honojs/hono, slimphp/Slim, spring-projects/spring-petclinic, tiny-http/tiny-http; fifteen known-used and four narrow source-safe facts | Source labels frozen before scans; three applicable security controls, one not applicable, no unsafe/unused positives and no population recall measurement |
| [blind_scope_review.json](blind_scope_review.json) and [blind_mux_review.md](blind_mux_review.md) | Second-agent source review, consumer-file hashes, Mux freshness audit, and one not-applicable security control | Slim string construction is outside the selected rule's implemented sink contract and earns no TN or passed-label credit. Mux security findings are unlabelled |
| [holdout_manifest.json](holdout_manifest.json) and [holdout_scope_review.json](holdout_scope_review.json) | Preserved initial cohort with Chi, plus original review receipt | Chi had an existing development-corpus reference and is supplementary, not blind. Its response-write security control is also not applicable. The original manifest and labels remain unchanged |

The final cohort replaces Chi with Gorilla Mux because a freshness audit found
prior Chi development references. Mux had no references in the available old
corpus/benchmark files or recovered Desktop target names; its three used labels
were reviewed from source before scanning. The other four targets retain their
original pre-scan labels. This is a limited local freshness check, not proof of
absence from all historical experiments.

The original holdout source claims were checked against each pinned checkout.
All five declared source-hash sets and Git revisions matched and all checkouts
were clean at that initial review; Mux separately passed the same checks.
Applicable labels still need successful exact-source parsing and
complete required analysis before they can earn quiet-control credit. Scan
outcomes remain in the separate execution report. The missing extracted Spring
Petclinic `initCreationForm` declaration stays incomplete and earns no credit.

## Inventory provenance

The following hashes identify the inventory snapshot so subsequent benchmark additions do not silently change the denominators reported above.

| Manifest | SHA-256 |
| --- | --- |
| corpus/manifest.json | 72ad4624c7c0860b18ad66cfc455582be14c8b1dabc0df54757be618ae9878f5 |
| benchmarks/dead_code/manifest.json | ed93a997edcbb37104348c1f11fc7c7a5df015fcd048a197ee77bb965223ebe8 |
| benchmarks/security/manifest.json | 1de242ea6020a1915d3fcbaeb4e49baa3871918d2483f81f23c65cffde4038f7 |
| benchmarks/framework_corpus/manifest.json | ea031db619d61ecb97a32d853c6f521707017e911a2b7d521538051182b9dfc8 |

This document was built by reading manifests, evaluator source, checked-in source-review evidence and the recovered Desktop output structure. It did not run target code or execute benchmark suites. New suite pass/fail results are intentionally left to the separately recorded execution artifacts.
