# Improving dead code detection across languages

Fix incorrect findings on working code first, then improve detection of unused
code. Each change needs a working example, an unused control and a real project
check. A higher confidence threshold cannot repair a reference assigned to the
wrong declaration.

The audit used Skylos `db69589` and eleven pinned public repositories. Its source
anchors, scanner output and reductions are in
`/private/tmp/skylos-language-audit`. The default labelled benchmark contains
96 Python labels out of 124; Kotlin, Rust, PHP, Dart, C# and C++ have no cases in
that manifest. Existing tests cover these languages, but miss the failures below.

## First batch

Worktree: `/Users/oha/skylos/.worktrees/dead-code-correctness`.
Branch: `fix/dead-code-language-identity`, based on `origin/main` at `db69589`.
The original checkout and other active worktrees stay on their current branches.

| Change | Failure to fix | Required controls |
| --- | --- | --- |
| Shared reference matching and reachability | A JS property or called TS function makes an unrelated C++ or PHP function appear used | Mixed-language and isolated scans agree; valid JS/TS, Java/Kotlin and legacy unknown-source references still work |
| Rust method ownership | `fd`'s free `scan` loses its call to `WorkerState.scan`; a call can select the first same-named method | Real two-file `fd` reduction, both declaration orders, correct owner edges and a dead sibling |
| PHP method ownership and namespaces | `$this` or static calls credit another class; bracketed namespace bodies vanish; qualified references lose aliases | Both declaration orders, namespace variants, Symfony alias/static-call reduction, used and unused constants, trait composition and overridden dead trait methods |
| Dart method ownership | An implicit member call credits the first same-named method in another class | Both declaration orders, `this`, local constructors, typed receivers, factory implementations, unknown receiver control and a dead sibling |

Use exact owner identities when syntax provides them. An unresolved receiver
must not select a declaration just because it appeared first. Keep unresolved
calls conservative and record the remaining limitations. Do not add broad
framework or method-name exemptions.

This batch preserves public finding fields and CLI behavior. Full lexical
binding identities, overload types and compiler integrations follow in later
batches; they are not prerequisites for these contained fixes.

### Implemented changes

- Reference matching and entry reachability stay within supported language
  families. JS/TS and Java/Kotlin remain grouped for their supported interop.
  Unknown-source legacy definitions retain wildcard behavior. Python attribute
  evidence and inferred receiver types no longer credit foreign declarations.
- Rust preserves method owners and same-named function-to-method calls, including
  simple aliases, scoped `impl` owners, constructor return types and simple macro
  method calls. Ambiguous imports and unresolved generic/Deref dispatch remain
  conservative.
- PHP preserves qualified method/property/constant references and namespace
  aliases. Bracketed namespaces are traversed. Local trait resolution respects
  class-over-trait-over-base precedence, nested traits, aliases and adaptations.
- Dart resolves known receivers after collecting declarations. Local inheritance,
  virtual overrides, interface/factory implementations and explicit `super`
  calls have separate controls. Unknown or shadowed receivers stay conservative.
- One Rust integration test now checks both an exported caller and a disconnected
  private caller. A constructor used only by an unreachable private function
  must follow that function's reachability.

Peer review reproduced and corrected overly strict matching for PHP traits,
Rust aliases/wrappers/scoped owners and Dart factory implementations. Tests pair
working methods with unused sibling or overridden methods; neither broad
method-name protection nor declaration order decides the result.

### Real-project results

All scans below use the actual CLI at confidence 60 with grep verification
enabled. No target build, package script or target test execution was needed.

| Pinned project | Scanned files | Incorrect findings removed | New findings | Analysis errors |
| --- | --- | --- | --- | --- |
| [fd](https://github.com/sharkdp/fd/tree/24c8a829f6c92ef57082cae000b52a1d27c899a4) | 24 Rust + 5 shell | 6 functions in its search path | 0 | 0 |
| [Symfony PHP83 polyfill](https://github.com/symfony/polyfill-php83/tree/80ccff923a8d61f73ebe9da0aa94e25232f004ce) | 15 PHP | 1 helper class, 3 alias imports, 1 read constant | 0 | 0 |
| [Wonderous](https://github.com/gskinnerTeam/flutter-wonderous-app/tree/747b945a7e5239356bf2664261aa2f3b020b8898) | 192 Dart | 1 method, 3 classes | 0 | 0 |

Wonderous's manually checked unused `_runSuggestions` still appears at
confidence 90. The unused sibling controls in the new Rust/PHP/Dart tests remain
reported. The mixed-language CLI reductions now report the unused PHP/C++
`amber` functions while keeping their JS/TS counterparts live.

These results cover the reviewed declarations, not all remaining warnings.
`fd` still has an unresolved clap callback and trait imports; Wonderous still
has callback/type-reference gaps; Symfony still has external polyfill exports
and classmap stubs that need entrypoint modelling.

Remaining first-batch limits: storage keys and lexical bindings can still
collide within a language; explicit bridges between unrelated languages need
their own evidence; unknown receivers can keep unused candidates alive.
PHP's fully qualified versus implicit global free-function fallback remains
indistinguishable in shared matching. Full compiler type resolution and
cross-file trait/override graphs are not implemented.

## Next batches

### 1 Finish reference and declaration correctness

- Fix TS conditional reads, literal bracket-member calls, default-export
  bindings and overwritten declarations in nested scopes.
- Fix Kotlin callable references, class literals, type annotations, qualified
  uses and extension properties. Check the actual Sunflower preview providers.
- Fix Dart function values and type references using the Wonderous callbacks.
- Fix C# containing-type liveness for `Main`, method groups, event callbacks and
  multiline parameters wrongly collected as fields. Check `seqcli`.
- Complete qualified PHP callable/static/constant forms and callback references.
- Resolve Rust trait imports and registration metadata, including `fd`'s clap
  parser callback and `IsTerminal` import.

Acceptance: known working declarations disappear from unused findings while
their genuinely unused controls remain. Tests assert exact declarations and
call edges, not a count of references sharing the same spelling.

### 2 Add framework consumers and entrypoints

- Extract Vue/Svelte script imports and template references.
- Recognise SvelteKit route and hook contracts, component entries and aliases.
- Scope C# command registration, Kotlin preview providers and Rust callback
  metadata to their actual contracts.
- Surface incomplete consumer coverage before treating omitted framework files
  as evidence that their dependencies are dead.

Acceptance: Vue/Svelte RealWorld caller paths stay live; arbitrary unused
functions named `load`, `handle` or `render` are still detectable. Configuration
inspection stays static.

### 3 Detect unreachable functions and files

- Retain Go's native `call_pairs` in the Python call graph.
- Add missing caller ownership in Kotlin and C++.
- Traverse callable and module graphs from actual entrypoints, including
  disconnected cycles and downstream helpers.
- Keep library exports, runtime entries, tests, side effects and uncertain
  dynamic consumers explicit.

Acceptance: disconnected cycles and dead chains are caught; equivalent rooted
cycles, rooted chains and supported public library entrypoints remain live.

### 4 Expand syntax and semantic coverage

- Collect TS class arrow fields and private methods, Kotlin properties, and
  Rust constants/statics.
- Resolve known overload signatures and local trait relationships.
- Replace or constrain C# regex parsing where it invents declarations.
- Investigate optional Clang and compile-database support for C++. Reproduce
  `nchat`'s valid macro and preprocessor forms; incomplete scans remain explicit.

Compiler or SDK assistance must be optional and explicit. Normal static scans
must not build foreign projects or execute their configuration and package
scripts. C++ and C# remain partial until their stated scope is expanded. Shell
currently has no dead-code engine.

### 5 Add representative regression evidence

- Add pinned non-Python project manifests and source provenance.
- Keep live and dead labels, framework cases, syntax coverage and parse failures
  separate. Unnecessary exports are distinct from unused function bodies.
- Reserve independent projects for hold-out checks; report coverage alongside
  precision and recall.
- Track runtime and memory when changing shared matching or graph traversal.

The audit's warning-driven sample is useful for regressions, not an overall
accuracy percentage.

## Existing implementations to learn from

| Analyzer | Mechanism to adopt |
| --- | --- |
| Knip and Fallow | Resolved bindings, traversal from entries, component consumers and scoped framework contracts |
| rustc and Staticcheck | Definition/object identities, typed method targets and usage graphs |
| Dart analyzer and detekt | Resolved element/descriptor references, library or lexical scope and conservative handling when binding information is unavailable |
| PHPStan and ShipMonk | Typed receivers, namespace aliases, qualified class/member graph keys and separate framework usage providers |
| Roslyn | Semantic operations for calls, method groups, construction and field/property/event references |
| Clang | Preprocessing and typed declarations for valid macro-heavy C++ sources |

The audit subreports record implementation pins and licenses. Preserve required
attribution if adapting source code; implementing the same mechanism does not
require copying a tool's execution model.

## Validation for each batch

1. Reproduce the failure on the base revision and save the expected live/dead
   labels.
2. Add focused regressions with paired controls and declaration-order variants
   where relevant.
3. Run the affected language suites, then shared analyzer and dead-code suites.
4. Rescan the relevant pinned real projects at confidence 60 with grep enabled.
   Inspect changed findings against their actual callers.
5. Run the existing labelled benchmark and corpus gate for shared changes,
   lint changed files and check the security gate for newly introduced findings.
6. Review the diff for unrelated changes and update this plan with completed
   items, exact test results and remaining limitations.

## Progress

- [x] Completed the audit and pinned real-project evidence.
- [x] Created an isolated branch and worktree.
- [x] Shared reference boundary and reachability regressions and fix.
- [x] Rust receiver and self-reference regressions and fix.
- [x] PHP receiver, namespace and trait regressions and fix.
- [x] Dart receiver and factory regressions and fix.
- [x] Combined tests, real-project rescans and first-batch review.
- [x] Second audit: confirmed Python, JS/TS, Java, Go, Dart and C# fixes,
  source-reader/error hardening, and secret-scanner failure handling. See
  [the hardening audit](analyzer-hardening-audit.md) for 13 pinned projects,
  final validation and the remaining coverage gaps.
- [ ] Later batches above.

## First-batch verification, 6 October 2026

- Shared analyzer, dead-code, C++, benchmark/corpus harness, Rust/security,
  PHP and Dart suites: **520 passed**. The existing `TestAwareVisitor`
  collection warning remains.
- TS/JS, Vue, Kotlin, Java, Go and C# suites: **914 passed, 4 skipped** in the
  final broad run; its remaining timing assertion passed on an isolated rerun
  (**1 passed in 0.56 seconds**). This checks **1,435 distinct tests** across
  the two suite selections. The four skips require optional TS benchmark
  fixture files absent from this checkout.
- The timing failure checked the unchanged esbuild glob helper: its complete
  result was correct, but it exceeded five seconds while other scans/tests
  ran. A concurrent benchmark run similarly exceeded six time budgets with
  all 124 labels still correct. The final isolated benchmark passed **21/21
  cases in 3.7442 seconds**, including its original time budgets: 47 dead and
  77 live labels, zero incorrect or missed labelled findings. No budgets or
  assertions were relaxed.
- Corpus gate: **47/47 cases**, zero failures.
- Final changed-file security/secrets scan, including untracked tests:
  zero findings and zero analysis errors. New fixture writers use temporary-root
  containment, exclusive creation and no-follow flags, without suppressions.
- Ruff lint and `git diff --check`: clean. The implementation preserves other
  checkouts and contains no unrelated source changes. No PR was opened.

Commands ran from the implementation worktree with its source directory in
`PYTHONPATH` and the trusted native engine selected with
`SKYLOS_GO_BIN=/private/tmp/skylos-language-audit-go`. The shared interpreter is
`/Users/oha/skylos/.venv/bin/python`.

```sh
export PYTHONPATH="$PWD"
export SKYLOS_GO_BIN=/private/tmp/skylos-language-audit-go
export SKYLOS_JOBS=2

/Users/oha/skylos/.venv/bin/python -m pytest -q -p no:cacheprovider \
  test/test_analyzer.py test/test_reference_index.py test/test_performance.py \
  test/test_dead_code.py test/test_dead_code_liveness.py \
  test/test_dead_code_evidence.py test/test_dead_code_language_boundaries.py \
  test/test_cpp_scanner.py test/test_cpp_integration.py \
  test/test_dead_code_benchmark.py test/test_corpus_ci.py \
  test/test_rust.py test/test_rust_dead_code_identity.py test/test_rust_security.py \
  test/test_php.py test/test_php_dead_code_identity.py test/test_dart.py

/Users/oha/skylos/.venv/bin/python -m pytest -q -p no:cacheprovider \
  test/test_typescript.py test/test_typescript_expanded.py \
  test/test_typescript_resolve.py test/test_ts_exports.py \
  test/test_ts_e003_entrypoints.py test/test_typescript_framework.py \
  test/test_ts_convention_entrypoints.py test/test_vue_scan.py \
  test/test_kotlin.py test/test_go_runner.py test/test_java_source_helpers.py \
  test/test_java_source_helper_limits.py test/test_csharp_symbols_identity.py \
  test/test_csharp_app_reachability.py test/test_csharp_raw_lex.py

/Users/oha/skylos/.venv/bin/python -m pytest -q -p no:cacheprovider \
  test/test_ts_e003_entrypoints.py::test_esbuild_many_globs_reuse_the_file_inventory

/Users/oha/skylos/.venv/bin/python scripts/dead_code_benchmark.py --json
/Users/oha/skylos/.venv/bin/python scripts/corpus_ci.py \
  --manifest corpus/manifest.json --json
```

Raw test logs, security output, full before/after real-project snapshots and
exact finding deltas are in `/private/tmp/skylos-language-audit/first-batch-*`.
The new regression tests and this plan are stored in the worktree. The audit
artifacts are local evidence and should be archived before temporary-directory
cleanup if needed later.
