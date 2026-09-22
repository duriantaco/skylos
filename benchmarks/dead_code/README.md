# Dead-Code Benchmark

This benchmark suite measures Skylos dead-code detection against labeled fixtures and optional external targets.

The benchmark framework lives in the Skylos repo because it must version with analyzer output and CI. Larger realistic targets, such as `/Users/oha/skylos-demo`, stay external and are referenced by config.

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

The default checked-in manifest contains 124 ground-truth symbols: 47 unused
and 77 used. It is useful for request validation and regression testing, but
Skylos already scores every labeled symbol correctly there. A Jev tie on this
suite does not demonstrate incremental value. The runner always asks the
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
mixed TypeScript/JavaScript package reachability.

For larger accuracy discovery against pinned upstream framework repositories,
use `benchmarks/framework_corpus`:

```bash
python scripts/framework_corpus.py --checkout-root /private/tmp/skylos-biglib-scan
```

That runner is a manual/nightly drift signal, not the blocking CI suite. Promote
confirmed real-repo false positives and false negatives into small fixtures here
so the normal benchmark keeps exact TP/FP/FN/TN coverage.
