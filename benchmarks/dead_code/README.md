# Dead-Code Benchmark

This benchmark suite measures Skylos dead-code detection against labeled fixtures and optional external targets.

The [7 November 2026 fresh-repository comparison](real_repo_scores/2026-11-07.md)
logs eight pinned targets, competitor results, verified false positives, missed
findings and incomplete scans. Its reviewed-set scores are separate from the
synthetic fixture scores below.

The benchmark framework lives in the Skylos repo because it must version with analyzer output and CI. Larger realistic targets, such as `/Users/oha/skylos-demo`, stay external and are referenced by config.

The default manifest contains **98 cases and 466 symbol labels**: 149 unused and
317 used. The first 65 cases and their 351 labels retain their expectations.
Five new cases cover nested namespace exports, contained Go workspaces and Rust
source-module trait identity. Twenty-eight Swift cases cover private declarations,
lexical and owner identity, callbacks, overloads, call cycles and runtime consumers.

| Current depth contracts | Cases / labels |
|---|---:|
| TS namespace forwarding and public/opaque controls | 2 / 8 |
| Go workspace private cycles and live callbacks | 2 / 12 |
| Rust ordinary source-module trait imports | 1 / 5 |
| Swift private declaration and runtime-use controls | 28 / 90 |

The preceding seven cases cover export forwarding, local Go module replacements,
and Rust trait, writer-macro and conditional-attribute imports.

| Latest source contracts | Cases / labels |
|---|---:|
| TS named export demand, public/escaping namespaces and enumerated aliases | 3 / 13 |
| Go local replacement modules and live callback cycles | 2 / 12 |
| Rust local receiver identity and macro/attribute import evidence | 2 / 11 |

The enumerated-alias fixture already passed on the baseline with grep enabled;
it protects live API bindings rather than measuring an incremental detection
gain. Separate AST contracts reproduce the missing export propagation.

The eight cases from the preceding real-repository audit are also retained:

| New cases from the real-repository audit | Cases / labels |
|---|---:|
| TS lexical values, disconnected import consumers and loaded controls | 3 / 18 |
| Go project imports and private test helpers | 2 / 14 |
| Rust import expressions, private cycles and cross-file roots | 3 / 23 |

Used-import controls inside disconnected TS files describe lexical reads for
the unused-import rule; the file itself and unreachable functions/data remain
reportable. Those controls do not claim that the selected program executes the
file. Entry, test, callback and unused sibling controls remain explicit.

The earlier six TS/JS, Go and Rust depth cases are also retained:

| Language | Added patterns | Used controls | Cases / labels |
|---|---|---|---:|
| TS/JS | Static namespace members, literal destructuring, stable aliases and shadowed receivers | Escaped namespaces and unknown computed keys retain all exports | 2 / 10 |
| Go | Unreachable private call cycles, self-recursion and local/function name collisions | Public APIs, function values, initialization, test and generated consumers | 2 / 19 |
| Rust | Function-valued initializers and lexical callback bindings | Outer-scope calls, closure captures and separate match arms | 2 / 11 |

These fixtures are original static source contracts, with labels based on the
source before checking analyzer output. They do not run their programs. Rust
uses confidence 40, retaining its experimental policy. The Go cases require a
source-built native engine; the declaration-use proof requires complete package
type information and preserves conservative references when that is unavailable.

The implementations adapt approaches studied in
[Knip](https://github.com/webpro-nl/knip/tree/2305dad9b0d76e5f603cd353a1820c24ae0e720d)
(ISC), [Staticcheck U1000](https://github.com/dominikh/go-tools/blob/8371db75e9daf10073dc2ba684c2a24a1d6ead95/unused/unused.go)
(MIT), and [rustc's dead-code pass](https://github.com/rust-lang/rust/blob/c6ac6ea53f6c8234fd06ddf0b88d89fe8b46edf5/compiler/rustc_passes/src/dead.rs)
(MIT OR Apache-2.0). No upstream implementation code was copied. These are
bounded Skylos checks, not compiler parity. Named TS re-export chains follow
selected bindings through aliases and wildcard hops. Unknown local export
bindings, competing star providers and opaque namespaces retain conservative
handling. Direct namespace exports (`export * as tools`) now preserve selected
member identity through named, default, wildcard and nested forwarding. Native-valid
tagged templates and generic import-type queries retain correct syntax structure.
Go workspace proof requires contained modules, the exact admitted source inventory
and supported module language metadata. Unresolved dependencies do not gain an
unreachability proof. Rust ordinary source-module closures can supply selected
trait identity; macro expansion, Cargo feature evaluation and general compiler
type resolution remain outside this change. Swift analysis retains public/internal
APIs and uncertain runtime/compiler contexts; it does not infer unused imports
from textual module names or provide Swift security-flow and quality rules.
Swift cases were checked with Swift 5.9.2 and Periphery 2.21.2 before scoring.
Additional compiler-backed probes cover reflection-provider shadowing, separate
modules, lazy initialization, capture binding order and source-limit failures.
Production-source scans of Rainbow 4.1.0, Files 4.2.0, Path 1.4.0 and
swift-log 1.5.4 completed without unused-private findings. These are preservation
checks, not evidence of whole-program recall: public/internal declarations stay
roots. In swift-log, two unreferenced internal lock-wrapper methods remain
outside that scope. Other competitor warnings had test/build-configuration
consumers or described redundant conformances rather than unused private code.
Separate paired probes also retain existing
false positives for escaped exports behind wildcard barrels and cross-file
classic JS globals; those cases are not counted as passing coverage.

The real-repository audit distinguished source evidence from competitor
warnings: compiler checks proved nine required Rust imports; some Knip file and
export warnings instead had actual script, declaration or test consumers. New
contracts cover the language patterns without repository-name exemptions.
Rust private-cycle proofs preserve cross-file and conditional roots, unknown
macros and later grep rescues. Go can statically load indexed same-module
providers; unresolved external or opaque providers decline the proof. TS
consumer pruning requires a closed source slice and declines unbounded runtime
loaders and escaping loader capabilities. TSX's user-facing dynamic loader is
therefore an explicit uncertain boundary, not a forced dead-provider finding.

## Metrics

- TP: an expected unused symbol was reported.
- FP: an expected used symbol was reported as unused.
- FN: an expected unused symbol was missed.
- TN: an expected used symbol stayed quiet.
- Precision: `TP / (TP + FP)`.
- Recall: `TP / (TP + FN)`.
- F1: harmonic mean of precision and recall.

Labels are scanner-independent ground truth: they describe whether the symbol is
semantically live in the fixture, not whether Skylos currently reports it. The
default run reports unlabeled findings separately. `--strict-labels` counts any
finding outside the explicit `unused` and `used` labels as a false positive, and
the comparison runner uses that strict mode by default.

Skylos cases with parse errors, incomplete analysis, or no analyzed source files
are reported as `UNSCORED`. They add no TP, FP, FN or TN and make the run fail.
Summary metrics cover only scored cases; an incomplete run remains failed even
when its valid cases score 100. If no cases can be scored, scores are zero and
`score_unavailable_reason` is `no_valid_cases`. An intentionally selected scan
scope can still be scored when its files were analyzed successfully.

## Run

```bash
python scripts/dead_code_benchmark.py
python scripts/dead_code_benchmark.py --json
python scripts/dead_code_benchmark.py --case basic-unused-symbols
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
python scripts/dead_code_benchmark.py --strict-labels
```

Adversarial liveness cases live in a separate manifest:

```bash
python scripts/dead_code_benchmark.py --manifest benchmarks/dead_code/adversarial_manifest.json
```

The adversarial manifest is public but not part of the default required gate.
It includes cases that deliberately stress framework/package entrypoints and
dynamic dispatch patterns where one or more scanners may currently fail.

It also contains 14 neutral coverage cases distilled from a fresh repository
audit. The fixture code uses independent implementations and application names;
the expected behavior belongs to a language pattern, not to a repository name.

| Pattern | Variations and controls | Cases | Labels |
|---|---|---:|---:|
| Typed callback registries | Selected and wrong receiver/type, replaced registration method, copied registry, closure-owned implementation, inherited type lookup and private module registry | 7 | 75 |
| Callable protocol attributes | Native and aliased `unittest.TestCase`, local lookalike without a reader, source-owned metadata reader, and unused sibling attributes | 4 | 15 |
| Conditional asset references | Ordinary script load, valid legacy IE conditional comments in HTML/Jinja, ordinary and malformed comments, orphan files and same-name files at another path | 3 | 18 |

The registry cases describe closed programs with fixed calls and private,
unexposed callback storage. Their unselected callbacks have no external
registration contract. The existing default cases that declare public
registration entrypoints retain their original expectations. Protocol attribute
use includes a constructor reading callable metadata; it does not require the
callable itself to execute. Conditional HTML comments apply to the legacy
browser versions they name, not to modern browsers.

Run the complete challenge suite, including its original two cases:

```bash
python scripts/dead_code_benchmark.py \
  --manifest benchmarks/dead_code/adversarial_manifest.json --strict-labels
```

Or inspect one pattern:

```bash
python scripts/dead_code_benchmark.py \
  --manifest benchmarks/dead_code/adversarial_manifest.json \
  --case corpus-type-registry-private --strict-labels
```

These cases include known false positives and false negatives in the current
scanner. A nonzero exit reports the remaining coverage gaps. Keep their semantic
labels fixed when improving the analyzer, including controls the scanner
currently misses. The original 27 default cases and their 141 labels retain
their expectations; two PHP cases add seven labels to the default suite.
Some misses reflect conservative retention or uncertainty policies; investigate
their evidence before treating a benchmark miss as a detector bug. The original
two adversarial cases also retain their existing unlabeled findings, which
`--strict-labels` reports separately. The 14 added cases have closed labels.
The new cases are development coverage, not an unseen holdout or evidence that
the analyzer handles every implementation of these patterns.

The default manifest includes paired cases for programmatic Robot library
decorators, method calls in Robot variable expressions, imports read through a
wildcard export, finite `globals()` dispatch and inherited method registries.
Each has unused controls. A separate Robot case checks that escaped expressions,
comments and a constant-false branch do not keep a method alive. These fixtures use source inspection;
Robot Framework and the fixture programs do not need to run.

The PHP cases cover direct and chained function calls, class construction,
public and private method calls, and unreferenced siblings. They add two unused
and five used controls. Skylos reads their source; PHP and the fixture programs
do not need to run. These are basic coverage cases, not evidence that all PHP
frameworks or dynamic dispatch patterns are covered.

Eight cases add shared coverage for C#, Kotlin, Rust and Dart: each language has
a direct call chain and an owner/member control, with both used and unused
symbols. That language-parity stage had 37 cases and 191 labels. The original 29 cases
and 148 labels retain their expectations. Rust cases explicitly use confidence
40, matching its experimental analyzer policy; other new cases use 60.

These cases set `symbol_identity: "qualified"` so `Primary.process` and
`Secondary.process` are different symbols. Qualified mode requires the native
`full_name` identity and fails unscored if it is missing; aliases must be declared
explicitly. Existing cases keep their simple-name matching. This tests the named
patterns, not general compiler or framework parity.

The adversarial manifest also retains a C# executable whose static `Main` is
recognized but whose declaring class is still reported as unused. Its live-class
label remains fixed. This known false positive is separate from the passing
top-level-statements C# owner case.

Dart requires the optional `skylos[dart]` grammar. Core CI tests the other cases;
the Dart test group runs when that extra is installed. A CLI run requesting Dart
without its engine reports unscored failure, not a clean scan.

Optional competitor baseline:

```bash
python scripts/dead_code_benchmark.py --scanner vulture
python scripts/dead_code_benchmark.py --scanner ruff
python scripts/dead_code_compare_scanners.py
```

Competitor scanners are not project dependencies. Install them separately when
you want a head-to-head run, then score them against the same manifest labels.
The comparison command uses strict labels by default, so any scanner finding
outside the explicit unused/used labels is counted as a false positive.
Python-only scanners are scored only on Python cases; non-Python cases are
reported as skipped for that scanner instead of being counted as false
negatives.

## Jev semantic research benchmark

The Jev runner tests whether a typed decision model can add useful semantic
evidence to dead-code review. Production review uses
`skylos agent verify . --dead-code-review jev` for Jev alone, or
`--dead-code-review jev-llm` for Jev with LLM fallback. The benchmark also
retains historical `--jev-precheck` router and `--jev-judge` arms for
comparison; those flags remain available for CLI compatibility. See the
[user guide](../../docs/dead-code-review.md) for current setup and behavior.
This synthetic benchmark is not a release gate, and Jev does not authorize
deletion.

First inspect the request plan. This does not use the network or require a key:

```bash
python3 scripts/jev_dead_code_benchmark.py
```

The default checked-in manifest contains 466 ground-truth symbols: 149 unused
and 317 used. It is useful for request validation and regression testing.
A Jev tie on an already-correct static result does not demonstrate incremental
value. The runner always asks the
`original` question, and adds a second arm only when safe:

1. `original` uses the checked-in fixture.
2. `neutralized` attempts to remove obvious answer cues in identifiers. It
   is not sent when a safe transformation cannot be demonstrated (for example,
   dynamic string references), rather than changing the fixture's behavior or
   paying for an unchanged duplicate request.

The local plan reports how many cases had neutralization applied, skipped, or
not applicable. Only applied cases contribute paired-consistency statistics;
do not interpret a skipped case as a successful neutralization test.

`jev_challenge_manifest.json` is a separate, synthetic development probe. Its
four neutral-named functions include two invoked through `getattr` or
`globals()`, one direct call, and one uninvoked function. Skylos currently
reports both dynamically invoked functions as unused at confidence 0, while
the source contains no comments or names that disclose the answer. This probe
is intentionally outside the passing default benchmark and is not a release
gate. Jev plans one original-arm request; string-based dispatch makes
identifier neutralization unsafe. A four-label result is exploratory, not
evidence of general performance.

The manifest labels and case descriptions are joined to the answers locally
after the response. They are never included in the API request. Each request
contains only one selected fixture's source/config files, the target kind,
file and symbol, and the fixed decision rubric.

For the real comparison with existing classifiers, point the same runner at
the frozen sibling benchmark corpus. The runner accepts
`skylos-golden-benchmark/v1`, requires frozen labels and closed label coverage,
and preserves each label ID in the local result so it can be joined with the
existing Skylos, Vulture, and Ruff results. Label IDs, expectations, review
reasons, and manifest descriptions are withheld from Jev.

From the Skylos repository, inspect the golden development plan:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --manifest ../skylos-benchmarks/manifests/dead_code.dev.json
```

That development split currently contains 48 labels across 9 cases. Use it to
choose the prompt and confidence threshold after a live run. Run the existing
Skylos baseline against exactly the same label IDs from the sibling repository:

```bash
cd ../skylos-benchmarks
python3 runners/run_benchmark.py \
  --manifest manifests/dead_code.dev.json \
  --tool skylos
```

A live run requires a TypeSafe API key from the official
[TypeSafe console](https://console.typesafe.ai/). Store it in
`TYPESAFE_API_KEY`; do not
put it in a command argument, source file, contract, or committed shell script.
Use the project environment (`.venv/bin/python` or an installed Skylos Python)
so the required `requests` dependency is available. The TypeSafe SDK is not
required. For an interactive zsh session, enter the key without shell history:

```zsh
read -rs "TYPESAFE_API_KEY?TypeSafe API key: "
export TYPESAFE_API_KEY
echo
```

Jev is a hosted service: live benchmark mode and both opt-in verification modes
send source over the network; neither is an offline model run. The local
benchmark report omits source and the key, but TypeSafe still
receives the source. The runner refuses known credential, private-key, and
answer-key paths, but this is not a substitute for reviewing every fixture
file before upload. Use only public or approved fixtures; TypeSafe's normal
retention policy applies unless your account has a separate zero-data-retention
arrangement. See the official [API reference](https://docs.typesafe.ai/api),
[model list](https://docs.typesafe.ai/models), and
[confidence guide](https://docs.typesafe.ai/confidence). TypeSafe's
[privacy policy](https://typesafe.ai/legal/privacy-policy) says customer input
is not used to train its models.

Run one public synthetic case first (two requests, one per arm):

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live --case basic-unused-symbols --max-requests 2 \
  --output jev-dead-code-smoke-results.json
```

Live mode is explicit because it sends the benchmark fixture source to
`https://api.typesafe.ai/v1/systemone` and incurs API usage. The runner pins
`jev-1.13.0`, rejects redirects and malformed responses, stops on the first
failed batch, and checkpoints to the ignored
`jev-dead-code-results.json` file. The key and source text are not stored in
that report. It does not automatically replay a failed network request because
the server may already have processed and charged for it. A new run refuses to
overwrite an existing output file. To
continue a matching incomplete run without repeating successful paid batches,
use `--resume` with the same manifest, case selection, and output path:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live --resume --case basic-unused-symbols \
  --output jev-dead-code-smoke-results.json
```

`--max-requests N` caps **new** requests in one invocation. It does not limit
tokens or guarantee a dollar amount; inspect the account's credits and the
reported token usage. A network timeout may leave the server's processing
status unknown; manually resuming such a failed batch can duplicate a charge.

Run the full checked-in regression pilot only if needed:

```bash
python3 scripts/jev_dead_code_benchmark.py --live
```

Then run the golden development split:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live \
  --manifest ../skylos-benchmarks/manifests/dead_code.dev.json \
  --output jev-dead-code-golden-dev-results.json
```

Compare that completed run with Skylos on the same frozen labels. This step is
offline and needs no key:

```bash
python3 scripts/jev_compare.py \
  --manifest ../skylos-benchmarks/manifests/dead_code.dev.json \
  --jev-report jev-dead-code-golden-dev-results.json \
  --scanner-summary ../skylos-benchmarks/results/local/dead_code/dev/dead_code.dev/skylos/summary.json \
  --threshold 0.8 \
  --output jev-dead-code-golden-dev-comparison.json
```

The comparison requires exact label coverage and reports which Skylos errors
Jev corrects, which correct labels it regresses, abstentions, and per-case,
language, and category counts. Unlabeled Skylos findings are counted
separately. The sibling benchmark runner does not store a manifest digest, so
the comparator checks its case/label inventory against the supplied manifest;
this cannot prove which source bytes that earlier scanner run consumed.

After choosing a prompt and threshold on development data, freeze the prompt
digest, model, and threshold before touching the Jev-unseen fresh holdout. Run
that holdout once with frozen digests:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live \
  --manifest ../skylos-benchmarks/manifests/dead_code.fresh_holdout.json \
  --expect-prompt-digest YOUR_FROZEN_PROMPT_SHA256 \
  --expect-manifest-digest YOUR_FROZEN_HOLDOUT_MANIFEST_SHA256 \
  --output jev-dead-code-golden-holdout-results.json
```

Both expected digests are checked before the first paid request. Take the
holdout manifest digest from its local `--json` plan; keep the development
prompt digest unchanged. Do not tune the prompt or threshold against holdout
answers. Compare the completed holdout report offline with the same frozen
threshold and its Skylos summary:

```bash
python3 scripts/jev_compare.py \
  --manifest ../skylos-benchmarks/manifests/dead_code.fresh_holdout.json \
  --jev-report jev-dead-code-golden-holdout-results.json \
  --scanner-summary ../skylos-benchmarks/results/local/dead_code/fresh_holdout/dead_code.fresh_holdout/skylos/summary.json \
  --threshold 0.8 \
  --output jev-dead-code-golden-holdout-comparison.json
```

The `0.8` values are examples; use the one threshold selected from the
development comparison in both commands.

On 2026-09-22, we ran the paid `jev-1.13.0` fresh holdout at threshold 0.8
with frozen manifest and prompt digests. Of 33 labels, Jev decided 26 and
abstained on seven; 24/26 decided classifications were correct, with zero
known-used symbols classified as unused. The offline comparison against the
historical Skylos summary found four corrected labels and one regression,
but that summary used a different scanner run than the live cascade below.
These numbers do not justify automatic removal.

For the production path, `scripts/jev_cascade_benchmark.py` scores four arms
on isolated copies of the same frozen case sources: pure Skylos, the ordinary
LLM verification harness, `--jev-precheck`, and `--jev-judge`. The Jev judge
mode accepts both used and unused decisions only when **both** confidence and
chosen-answer probability are >=0.9; uncertain or unavailable answers fall
back to the broad LLM verifier. Neither Jev-only judgment authorizes `--fix`.
Inspect the free local plan first, then explicitly opt into network calls.
This runner needs
`TYPESAFE_API_KEY`, `OPENAI_API_KEY`, and a Python environment with the
project's `[llm]` dependencies installed:

```bash
python3 scripts/jev_cascade_benchmark.py \
  --manifest ../skylos-benchmarks/manifests/dead_code.fresh_holdout.json
python3 scripts/jev_cascade_benchmark.py --live \
  --manifest ../skylos-benchmarks/manifests/dead_code.fresh_holdout.json \
  --output jev-dead-code-cascade-holdout-results.json
```

An earlier 2026-09-22 paired run (before the four-arm runner) scored both arms
at TP=9, FP=0, FN=7, TN=17
(F1=0.72). Broad-verifier calls fell from 8 to 4; its reported broad LLM
token usage fell from 18,622 to 2,708 tokens. Jev agreed on nine candidate findings,
all correctly labeled unused, and one unlabeled candidate went to the general
verifier. There were no labeled disagreements, so this holdout tests cost
routing but does not establish performance on hard Jev/Skylos conflicts.
Jev usage is reported separately by the Jev-only runner, not folded into
those broad-LLM token counts. Other verification phases still call the LLM.

The harder checked-in `jev_dispatch_matrix_manifest.json` freezes 19 labels
across two dynamic-dispatch cases (JSON-configured functions and constructed
callback names). All 19 are static candidates, including 11 live functions
that require semantic context to recognize. Its manifest SHA-256 is
`867e9ef8074a2604ca9fd7b10ac0be73eabf7cbf36813dae8cf80b471bf14116`.
The source is synthetic and contains no secrets; review it before any upload.
To repeat the paired paid benchmark from the Skylos checkout:

```bash
python3 scripts/jev_cascade_benchmark.py \
  --manifest benchmarks/dead_code/jev_dispatch_matrix_manifest.json
python3 scripts/jev_cascade_benchmark.py --live \
  --manifest benchmarks/dead_code/jev_dispatch_matrix_manifest.json \
  --output jev-dead-code-dispatch-matrix-results.json
```

The 2026-09-22 paid run from the main checkout yielded the same score in
both arms: TP=8, FP=6, FN=0, TN=5, F1=0.727. Jev agreed with six static
unused candidates (all truly unused), disagreed on all 11 truly used
candidates, and was uncertain on two unused candidates. The general verifier
ran for those 13 non-agreements, but neither arm suppressed the six live
handlers selected by JSON configuration. Broad LLM calls fell from 20 to 16,
reported broad-LLM tokens from 37,259 to 24,865, and measured arm elapsed
time from 43.15 to 28.065 seconds. Jev API usage is not included in those
LLM token counts or a total-cost comparison. This synthetic challenge shows
the routing behaves conservatively; it also shows the current broad verifier
does not resolve every dynamic-dispatch false positive.
The report's suppression-audit counters show that the broad LLM initially
judged the ten config-router candidates live, then its audit reopened all ten
as dead. Code-path inspection suggests the fallback context omits
`routes.json`, even though Jev receives it. The report does not retain exact
prompts, so this is a diagnostic inference, not a transcript-backed claim.

For the latest same-run five-case, 59-label four-arm comparison, see
[benchmark_jev.md](../../benchmark_jev.md). The opt-in Jev judge mode scored
52/59 (88.1%) versus 41/59 (69.5%) for LLM-only in the initial paired run.
After safety fixes, a separate final-code judge-only run scored 51/59 (86.4%),
without a same-run LLM-only arm. The threshold was chosen on this synthetic
suite; neither is an independent holdout result. Broad-LLM
tokens exclude Jev API usage. To reproduce the four-arm comparison:

```bash
python3 scripts/jev_cascade_benchmark.py \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json
python3 scripts/jev_cascade_benchmark.py --live \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json \
  --output jev-dead-code-hard-suite-live-results.json
```

The expanded `jev_hard_suite_v2_manifest.json` adds 66 labels in three
repository-style projects, for 125 total labels across eight cases. It covers
JSON/config-driven cross-file workflows, plugin registries, an installable
package with TOML entry points and tests, and async event dispatch. Its
no-model local Skylos baseline is 71/125 (56.8%); **no paid Jev or LLM result
exists for v2 yet**. The runner now preflights label closure and arm inventory
equality, honors each case's scan confidence/grep settings, and records source
and candidate-inventory digests. See the
[expanded-suite method and per-case results](../../benchmark_jev.md#expanded-repository-style-suite-v2-no-paid-results-yet).

```bash
python3 scripts/jev_cascade_benchmark.py \
  --manifest benchmarks/dead_code/jev_hard_suite_v2_manifest.json \
  --expect-manifest-digest a4ef654fcfb4f1d0eba4915d800419f44b589b28efea8e41274c020624fb3c5e
python3 scripts/jev_cascade_benchmark.py --static-only \
  --manifest benchmarks/dead_code/jev_hard_suite_v2_manifest.json \
  --expect-manifest-digest a4ef654fcfb4f1d0eba4915d800419f44b589b28efea8e41274c020624fb3c5e \
  --output jev-dead-code-hard-suite-v2-static-results.json
```

The checked-in adversarial manifest remains useful as a public stress set:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live \
  --manifest benchmarks/dead_code/adversarial_manifest.json \
  --output jev-dead-code-adversarial-results.json
```

The report preserves the full Choice probability distribution and scores
coverage, accuracy on decided items, unused precision/recall, unsafe removals,
Brier score, log loss, latency, token usage, and original/neutralized decision
consistency. Latency is split into end-to-end request time and local response
contract validation time, with mean, p50, p95, and maximum values. Request time
still combines network transfer, TypeSafe service work, response download, and
JSON decoding. The API does not expose enough timing data to isolate server-side
constrained generation or schema enforcement, so the report says that directly
instead of attributing service latency to one step.

The Jev judge mode is an opt-in suppression decision, not an automatic removal
decision. Before considering it as a default or using it to authorize removal,
measure it on a larger independent frozen holdout, including the rate at which
known-used symbols are incorrectly classified as unused. The current holdout
is too small for that inference even though it observed zero such errors.

Judge incremental value label by label: whether Jev corrects existing Skylos
errors, how many known-live symbols it marks unreferenced, how often it abstains,
and the latency and cost at the frozen threshold. Aggregate accuracy alone is
not enough for a removal decision.

## Case Shape

Each case declares explicit unused and used symbols:

```json
{
  "id": "basic-unused-symbols",
  "path": "fixtures/basic_unused_symbols",
  "languages": ["python"],
  "expect": {
    "unused": [
      {"kind": "function", "file": "app.py", "symbol": "unused_helper"}
    ],
    "used": [
      {"kind": "function", "file": "app.py", "symbol": "used_helper"}
    ]
  }
}
```

Supported kinds:

- `import`
- `function`
- `class`
- `variable`
- `parameter`
- `file`

## Adding Cases

1. Add a minimal fixture under `benchmarks/dead_code/fixtures/`.
2. Add a manifest entry in `benchmarks/dead_code/manifest.json`.
3. Keep the case focused on one semantic claim when possible.
4. Add both `unused` and `used` expectations when the fixture can validate recall and precision together.
5. Run `python scripts/dead_code_benchmark.py` before and after analyzer changes.

Current stricter cases include FastAPI dependency entrypoints, Flask blueprint
and CLI entrypoints, decorator registries, SQLAlchemy mixed model modules,
multi-file service/repository layers, Django management commands, Celery tasks,
pytest fixtures, Pydantic validators, Alembic revisions, importlib plugins, and
package console-script entrypoints. The cross-language cases currently cover Go
HTTP handler reachability, Java application entrypoints and stale methods, and
mixed TypeScript/JavaScript package reachability, plus PHP function and member
calls with unused controls.

For larger accuracy discovery against pinned upstream framework repositories,
use `benchmarks/framework_corpus`:

```bash
python scripts/framework_corpus.py --checkout-root /private/tmp/skylos-biglib-scan
```

That runner is a manual/nightly drift signal, not the blocking CI suite. Promote
confirmed real-repo false positives and false negatives into small fixtures here
so the normal benchmark keeps exact TP/FP/FN/TN coverage.

### C++ and Ruby control pairs

The current default suite has 44 cases and 220 labels: 75 unused and 145 used.
All 42 cases from the preceding stage retain their original labels.

The default corpus also includes C++ direct-call and address-taken callback
pairs, plus Ruby private call chains, same-named methods on different owners,
and Rails callback versus ordinary-class lookalikes. Every case preserves used
and unused labels. Ruby classes and public methods remain possible external
API; dynamic dispatch is conservative. Generic grep name matches do not prove a
Ruby receiver and cannot hide a native Ruby finding.

Two further pairs cover Ruby block-parameter scope and Rails callbacks inherited
through a source-visible `ApplicationController` in the same file. A closure's
parameter does not shadow a method outside that closure. Inherited callback
registration requires a supported ancestry chain and no visible override of the
registration method. Genuine unused siblings stay reported. Cross-file Rails
ancestry remains outside this engine's type-resolution model.

These original synthetic cases add regression coverage. Independent pinned
holdouts for the newer languages are still needed; passing the default corpus
does not establish deployment accuracy. See [the remaining gap list](../GAPS.md).
