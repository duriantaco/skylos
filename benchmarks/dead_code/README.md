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
evidence to dead-code review. It is a research benchmark, not part of the
Skylos analyzer or a release gate.

First inspect the request plan. This does not use the network or require a key:

```bash
python3 scripts/jev_dead_code_benchmark.py
```

The default checked-in manifest contains 124 ground-truth symbols: 47 unused
and 77 used. It is useful for request validation and regression testing, but
Skylos already scores every labeled symbol correctly there. A Jev tie on this
suite does not demonstrate incremental value. The runner asks for each decision
twice:

1. `original` uses the checked-in fixture.
2. `neutralized` replaces obvious answer cues in names such as
   `unused_helper` and `staleHelper` before asking the same question.

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

A live run requires a TypeSafe API key. Store it in `TYPESAFE_API_KEY`; do not
put it in a command argument, source file, contract, or committed shell script.
The experiment runs outside the production path, but Jev itself is a hosted
service: live mode sends fixture source over the network and is not an offline
model run. See the official [API reference](https://docs.typesafe.ai/api),
[model list](https://docs.typesafe.ai/models), and
[confidence guide](https://docs.typesafe.ai/confidence).

Run the checked-in smoke suite with:

```bash
python3 scripts/jev_dead_code_benchmark.py --live
```

Live mode is explicit because it sends the benchmark fixture source to
`https://api.typesafe.ai/v1/systemone` and incurs API usage. The runner pins
`jev-1.13.0`, rejects redirects and malformed responses, stops on the first
failed batch, and checkpoints to the ignored
`jev-dead-code-results.json` file. The key and source text are not stored in
that report.

Run a small smoke case before the whole suite:

```bash
python3 scripts/jev_dead_code_benchmark.py --live --case basic-unused-symbols
```

Then run the golden development split:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live \
  --manifest ../skylos-benchmarks/manifests/dead_code.dev.json \
  --output jev-dead-code-golden-dev-results.json
```

After choosing a confidence threshold on that development result, freeze the
prompt digest. The checked-in adversarial manifest remains useful as a public
stress set:

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

A Jev decision must remain advisory until a frozen holdout has zero known-used
symbols classified as removable at the selected threshold. The current holdout
is small, so even zero observed errors is not enough by itself for automatic
deletion.

For the actual frozen-corpus experiment, tune on `dead_code.dev.json`, then run
the Jev-unseen fresh holdout once with the same prompt digest and threshold:

```bash
python3 scripts/jev_dead_code_benchmark.py \
  --live \
  --manifest ../skylos-benchmarks/manifests/dead_code.fresh_holdout.json \
  --output jev-dead-code-golden-holdout-results.json
```

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
