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

The benchmark also reports unlabeled findings separately. Those are not counted as false positives unless they match an explicit `used` expectation, because a fixture may contain additional real dead code that is outside the specific claim being tested.

## Run

```bash
python scripts/dead_code_benchmark.py
python scripts/dead_code_benchmark.py --json
python scripts/dead_code_benchmark.py --case basic-unused-symbols
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
```

Optional competitor baseline:

```bash
python scripts/dead_code_benchmark.py --scanner vulture
```

Competitor scanners are not project dependencies. Install them separately when
you want a head-to-head run, then score them against the same manifest labels.

## Case Shape

Each case declares explicit unused and used symbols:

```json
{
  "id": "basic-unused-symbols",
  "path": "fixtures/basic_unused_symbols",
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
and CLI entrypoints, decorator registries, SQLAlchemy mixed model modules, and
multi-file service/repository layers.
