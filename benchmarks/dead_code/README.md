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
