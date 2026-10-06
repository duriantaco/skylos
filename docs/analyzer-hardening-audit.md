# Analyzer hardening audit, 6 October 2026

This audit follows the first batch in [the language plan](dead-code-language-plan.md).
Its baseline is `b8be9c4400d696b7abd5c81e13d98c11a76f618a` on Skylos main.
Implementation branch: `fix/analyzer-audit-hardening`.

The audit reviewed language dispatch, source readers, parser errors, references,
entrypoints, quality rules, native Go output, and the existing regression suites.
Thirteen pinned public projects supplied real consumers and syntax. They were
scanned as source; no target tests, package scripts, builds, tracing, or coverage
were executed. No target is assumed to be entirely free of dead code. Finding
counts below are scanner output, not a precision or recall percentage.

## Confirmed failures and changes

- **Python branch selection:** constant `and`/`or` expressions now preserve the
  selected operand. Branch truth is evaluated separately from expression values.
  Unknown values cannot prove comparisons, and identity comparisons do not rely
  on integer or string interning. Paired visitor tests check the actual live
  function and its unused sibling.
- **Python unreachable code:** a single literal `yield` required to make a
  function a generator is not reported after a terminator. Nested generators,
  `yield from`, call-valued yields, subsequent executable work, and a second
  yield in an already live generator retain their existing checks. Trusted
  fixture bytecode verifies the generator and async-generator calling convention.
- **JS/TS references:** parenthesized conditions, ordinary `for` conditions,
  ternary conditions, and literal bracket-member references are collected.
  Unrelated strings and computed names cannot invent those references.
- **JS/TS unreachable declarations:** SKY-UC002 distinguishes hoisted functions,
  erased types/overloads, and uninitialized `var` declarations from executable
  statements after a terminator. It still checks executable work inside hoisted
  helpers and reports unreachable initialized or lexical declarations.
- **JS/TS test entrypoints:** AVA and tsd require a declared dependency and an
  actual package-script invocation. Static file selection and exclusions are
  honored. Unknown configuration and commands that change the working directory
  do not create guessed roots. Test roots are development evidence.
- **Java forwarding:** `Worker.work` calling `Helper.work` no longer disappears
  as self recursion merely because the method names match. The actual self-call
  and unused sibling controls still appear.
- **Java/Go quality settings:** global and per-language complexity, nesting,
  argument-count, and function-length limits reach the appropriate scanner.
  Existing language precedence is retained. Go worker category flags are honored.
- **Go complexity and edges:** switch/type-switch/select count non-default case
  decisions without an extra switch/default decision; native `call_pairs` are
  retained in definition metadata. This does not establish full detection of
  disconnected call cycles.
- **Go native empty results:** valid extraction with no declarations or no
  references serializes JSON arrays instead of `null`. Unavailable extraction
  is still reported as unavailable.
- **Dart callbacks and constructors:** function/method values and tear-offs are
  collected from ordinary expression consumers. Actual default constructor calls
  retain their exact constructor; named declarations keep distinct identities.
  Local shadows and genuinely unused constructors have separate controls.
- **C# containing types:** actual static member consumers retain their owners.
  Qualified and alias owner references use exact identities, so external
  `System.Console` cannot rescue an unrelated `App.Console`. Method/constructor
  parameters, scoped locals, lambdas, loop bindings, catch bindings, fields and
  properties have shadow controls. A type's own qualified static reads and
  self-recursive calls do not establish an external consumer; paired external
  callers still retain the owner. A unique recognized Main retains its owner
  only within the existing complete executable-project contract, including
  static signature, generic-type, custom Task and StartupObject checks.
- **C# exposed inventory/call failures:** method-group arguments and literal
  argument counts are preserved. Constructors are not invented as methods, and
  callable parameters are not invented as fields. Genuine unused methods and
  fields have paired controls.
- **Incomplete analysis:** Java, Go, PHP, Rust, and Dart source/grammar failures
  produce explicit analysis-error metadata while retaining partial findings.
  The CLI marks the result incomplete and exits 2 instead of presenting an A+
  result as a complete clean scan. Unsupported valid syntax is described as a
  parser limitation, rather than proof that the source itself is invalid.
- **Source readers:** Java, Go, PHP, Rust and Dart preserve original bytes while
  enforcing a 2 MB per-file cap, regular-file checks and inode/device checks.
  Actual workers pass their trusted scan root; descriptor-relative traversal
  rejects symlink children and outside-root paths. Direct scanner calls trust
  the explicitly requested file's parent, while keeping its leaf unfollowed.
  The fallback checks containment and parents before and after opening, but is
  not claimed race-proof on platforms without descriptor-relative support.
- **Secrets fail-closed behavior:** source/config scanner exceptions and an
  unavailable explicitly enabled scanner mark analysis incomplete. An actual
  CLI reproduction previously returned exit 0 and A+ when its secret scanner
  raised; it now exits 2 and withholds the grade. Healthy secret findings still
  exit 1; disabled scans and candidate exclusions keep their existing behavior.

## Pinned real-source checks

Before and after use the same confidence (60), default grep verification, target
revision, and scan scope. Reductions describe reviewed failures; unchanged
findings are not certified true positives.

| Target | Revision | Scope | Result |
| --- | --- | --- | --- |
| [Click](https://github.com/pallets/click/tree/2247b35ea1c47c727d7a06e51fa280e12a863ff6) | `2247b35ea1c47c727d7a06e51fa280e12a863ff6` | Python checkout | Required generator-marker warning removed; quality 387 → 386; other findings unchanged; no analysis errors |
| [HTTPX](https://github.com/encode/httpx/tree/b5addb64f0161ff6bfe94c124ef76f6a1fba5254) | `b5addb64f0161ff6bfe94c124ef76f6a1fba5254` | Python checkout | Three required generator markers removed; quality 213 → 210; real unreachable second yield retained; other findings unchanged; no errors |
| [TypeScript](https://github.com/microsoft/TypeScript/tree/c63de15a992d37f0d6cec03ac7631872838602cb) | `c63de15a992d37f0d6cec03ac7631872838602cb` | 77 compiler TS files, partial | UC002 222 → 0: 215 hoisted functions, six erased overloads, one type alias; 1,842 other quality findings unchanged; same two parser errors |
| [p-limit](https://github.com/sindresorhus/p-limit/tree/a8a6fbec4e0e866d6d779b10889bb4f5567e70eb) | `a8a6fbec4e0e866d6d779b10889bb4f5567e70eb` | Checkout, six analyzed files | Two known live test files reported unused → zero; eight quality findings unchanged; no errors |
| [Lodash](https://github.com/lodash/lodash/tree/2b5e6f7399a7b48005140b5d5c6bc6c0e62919a8) | `2b5e6f7399a7b48005140b5d5c6bc6c0e62919a8` | Main `lodash.js`, partial | Dead-code output and 57 quality findings unchanged; no errors |
| [chi](https://github.com/go-chi/chi/tree/167e1e3bd039d060696b99c8da4e876ae04f42c1) | `167e1e3bd039d060696b99c8da4e876ae04f42c1` | 84 Go files | Quality 69 → 67: two incorrectly inflated complexity counts; five reviewed unused color constants retained; security unchanged; no errors |
| [Gson](https://github.com/google/gson/tree/845664ba1c307e6c1910d07cfed2f622e0ad8df1) | `845664ba1c307e6c1910d07cfed2f622e0ad8df1` | 264 Java files | Dead-code and 95 quality findings unchanged; security unchanged; no errors |
| [Wonderous](https://github.com/gskinnerTeam/flutter-wonderous-app/tree/747b945a7e5239356bf2664261aa2f3b020b8898) | `747b945a7e5239356bf2664261aa2f3b020b8898` | 192 Dart files under `lib`, partial | Unused functions 161 → 48, classes 31 → 21, imports 596 → 594, variables 128 → 60; no newly reported unused symbols; known dead `_runSuggestions` retained; no errors |
| [fd](https://github.com/sharkdp/fd/tree/14dcd92fb76ca0ebc2e82671a275f67c790d25fc) | `14dcd92fb76ca0ebc2e82671a275f67c790d25fc` | 24 Rust + five shell files | One function and 18 imports remain; confirmed callback/trait limitations below; no errors |
| [Symfony PHP83 polyfill](https://github.com/symfony/polyfill-php83/tree/80ccff923a8d61f73ebe9da0aa94e25232f004ce) | `80ccff923a8d61f73ebe9da0aa94e25232f004ce` | 15 PHP files | Seven functions and nine classes remain; external export/stub limitations below; no errors |
| [seqcli](https://github.com/datalust/seqcli/tree/a8467b1dff0e569b3124ccf9ad5d99540bc45563) | `a8467b1dff0e569b3124ccf9ad5d99540bc45563` | 490 C# + one JS file | Classes 168 → 100, methods 55 → 26, variables 52 → 17; one newly visible reviewed dead method; security/quality unchanged; no errors |
| [Sunflower](https://github.com/android/sunflower/tree/2a357a31551bb53f3fe80382a9ce6d30bcc8b960) | `2a357a31551bb53f3fe80382a9ce6d30bcc8b960` | 71 Kotlin + one shell file | Three live preview-provider classes and 293 imports remain reported; no scanner errors; regex parsing is not compiler verification |
| [fmt](https://github.com/fmtlib/fmt/tree/4afd0e498e9e1dd68775cc52087df774a19c761f) | `4afd0e498e9e1dd68775cc52087df774a19c761f` | 47 C++ + four Python + one JS + one shell file | 19 explicit parser errors on macro/module-heavy source; no whole-repository accuracy conclusion |

Wonderous's reduction restores reachability through actual callbacks. It does
not mean all 113 removed function findings were independently labelled. Reviewed
consumers include GoRouter's redirect handler, keyboard and scroll listeners,
controller listeners, conditional `onTap`, and `_CutoutClipper()` construction.

TypeScript's two remaining diagnostics occur at `transformers/utilities.ts:806`
(`in out` variance) and `types.ts:6322` (a labelled tuple member). They remain
visible. Worker-order changes for colliding declaration keys are not counted as
improvements.

seqcli's original live-class examples are `SeqCli.Program` (its executable Main),
`SeqConnectionFactory` (`LogCommand.cs:106` and other consumers), and
`ApiConstants` (`LogCommand.cs:102,109,111`). The class reduction is not 68
independently labelled false positives. All 35 removed variable findings were
checked against source spans: they were callable parameters invented as fields.
The only newly reported method is `SeqCli.Util.PasswordHash.Calculate`, line 20;
its spelling occurs only at its definition in this snapshot. External/dynamic
use cannot be ruled out from source alone. Its used sibling `GenerateSalt`
remains live.

## Reproduction

Use a baseline checkout at the commit above and the implementation checkout in
separate runs. Use the same installed interpreter and freshly build the trusted
Skylos Go engine from the selected source; do not build target repositories.

```sh
# Run in the Skylos source checkout being measured.
export PYTHONPATH="$PWD"
export SKYLOS_JOBS=2
skylos /path/to/pinned/target --confidence 60 --quality --format json \
  --no-cache --no-upload --no-provenance --no-clipboard --output report.json
```

The native Go changes were verified with `go test ./...` and a fresh trusted
engine built from this branch. CI builds the engine from source. The tracked
platform-specific binary is not part of this change; local source users should
rebuild the engine or select the rebuilt binary through `SKYLOS_GO_BIN`.

The `Wonderous/lib`, TypeScript compiler, and Lodash scopes above must be kept
identical. Do not silently expand a partial scan into a whole-project accuracy
claim. Exit 2 still provides JSON for parser-incomplete results.

chi and Gson used an explicit configuration to avoid inheriting the parent
Skylos checkout's settings. Add `--config-file audit.toml --danger`:

```toml
[tool.skylos]
complexity = 10
nesting = 4
max_args = 5
max_lines = 50
security_enabled = false
quality_enabled = false
secrets_enabled = false
```

CLI `--quality` and `--danger` enable those two families for this comparison.
Separate high-limit controls prove configuration forwarding; their reductions
are not precision measurements.

## Remaining failures, ordered by evidence

1. **References and framework consumers:** Rust clap registration does not see
   fd's `parse_millis` callback (`src/cli.rs:563`, definition 967). Rust trait
   imports such as `IsTerminal` are not tied to method calls (`src/main.rs:21`,
   use 282). PHP Composer `autoload.files`/classmap export contracts are not
   complete. Sunflower's three private providers are used in actual
   `@PreviewParameter(Provider::class)` annotations. These need scoped consumer
   evidence and dead sibling controls, not blanket name exemptions.
2. **Dart initializer/type coverage:** field/getter consumers, type values,
   explicit `new`/`const`, and constructor initializer traversal remain partial.
   A broad type-token attempt was discarded after the real rescan exposed
   incomplete owning-class/getter reachability.
3. **Binding identities and call graphs:** same-name storage collisions, shadow
   bindings, overloads and dynamic receiver resolution remain incomplete.
   Retaining Go edge metadata does not solve disconnected-cycle detection.
   TS default-export binding and Vue/Svelte consumer graphs need further work.
4. **Parser coverage:** valid C++ macros/modules exceed the present grammar;
   C# and Kotlin still use partial syntax extraction. `.c` and ambiguous `.h`
   files are not supported by the current C++ engine. A zero-finding result from
   an incomplete or limited scanner is not proof of clean code.
5. **Quality coverage:** Rust, PHP, Dart, Kotlin and C++ currently have no native
   quality-rule implementation. Shell has no dead-code/quality engine. C# checks
   only a subset of unreachable statements. Cross-language repository checks
   can appear, but do not close these language-specific gaps.
6. **Intent-sensitive quality and protocols:** p-limit's intentional empty catch
   still triggers L007 because the explanation precedes the try. Python
   transitive IO protocols and external duck-typed consumers need actual
   consumer modelling. These were recorded rather than hidden by broad ignores.

The Python per-file cap is not a native Go module-wide memory bound. C# retains
conservative simple-name matching for unresolved ordinary imports; full compiler
binding, global usings, conditional compilation and all pattern scopes are not
implemented. A remaining C# formatting-sensitive case was reproduced: a multiline
method/constructor parameter can still be treated as a field shadow by the
reference-binding helper, hiding a later static type reference outside that
parameter's scope. Field inventory now excludes the parameter, but that binding
helper needs the same exclusion in a follow-up. The baseline also misses the
reference; this is not a newly introduced live-to-dead regression. Existing
readers in other parts of the repository were not broadly rewritten or suppressed.

## Mechanisms checked against primary implementations

- [gocyclo](https://github.com/fzipp/gocyclo/blob/main/complexity.go): count
  non-default case decisions.
- [ESLint no-unreachable](https://eslint.org/docs/latest/rules/no-unreachable):
  distinguish hoisted declarations from unreachable executable statements.
- [AVA selection](https://github.com/avajs/ava/blob/v6.4.1/lib/globs.js) and
  [tsd selection](https://github.com/tsdjs/tsd/blob/v0.33.0/source/lib/index.ts):
  derive development entrypoints from the actual runner contract.

The changes use Skylos's own traversal and configuration code; no external
analyzer source was copied. Typed bindings and framework providers from the
existing language plan remain later work.

## Final validation

- Full trusted Skylos suite: **16,579 passed, 24 skipped, 16 subtests passed**
  in 37 minutes 16 seconds. This run began before the final four-line C#
  self-owner guard. After that guard and the final fixture path checks, all
  **347 new audit cases** were rerun against the final source and passed.
  The C# guard also passed 221 C# cases and 81 shared analyzer controls;
  its fresh seqcli rescan produced identical findings.
- Deterministic dead-code benchmark: **21/21 cases**, all 47 labelled dead
  symbols detected, all 77 labelled live symbols retained, no label failures
  or runtime-budget failures. This is evidence for this fixture set, not an
  estimate of deployment precision.
- Quality benchmark: **19/19 cases**, no failures.
- Curated upstream-pattern corpus: **47/47 cases**, no failures.
- Native Go: `go test ./...` passed with the engine built from this source.
  The original tracked platform binary was restored byte-for-byte before
  committing; the engine source and regression tests are the shipped changes.
- Security and secrets: the whole changed-source scan found no analysis errors
  or secrets. Its two new HIGH findings were fixture-writing helpers; explicit
  path containment was added, and both complete helper files then scanned
  with **zero security, secret or analysis-error findings**. The final scan
  using the trusted pre-audit scanner covered 1,166 files with the repository's
  existing exclusions and produced **zero new security findings, zero secrets
  and zero analysis errors**. No rule suppressions were added.
- Ruff passed for all 31 changed/new Python files. Rule-documentation parity
  passed at **239/239** against the updated docs alignment checkout. The
  regenerated repository map passed its freshness check; `git diff --check`
  passed. Focused suite counts overlap and are not added to the full-suite total.

```sh
# From this implementation worktree, using the trusted Skylos virtualenv.
export PYTHONPATH="$PWD"
export SKYLOS_JOBS=2
export SKYLOS_GO_BIN=/path/to/engine/built/from/this/source
python -m pytest -q -p no:cacheprovider
python -m pytest -q -p no:cacheprovider \
  test/test_audit_csharp_owners.py test/test_audit_java_go.py \
  test/test_audit_language_errors.py test/test_audit_other_languages.py \
  test/test_audit_python_quality.py test/test_audit_secret_failures.py \
  test/test_audit_ts_quality.py
python scripts/dead_code_benchmark.py --json
python scripts/quality_benchmark.py --json
python scripts/corpus_ci.py --manifest corpus/manifest.json --json
python scripts/build_repo_map.py --check
```
