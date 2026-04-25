# Security Benchmark

This benchmark suite measures deterministic Skylos security-analysis behavior against labeled fixtures.

It is intentionally separate from `/Users/oha/skylos-demo`. The demo repo is useful for whole-repo comparisons, but this suite is designed to produce precise TP/FP/FN/TN metrics for individual vulnerability classes and rule IDs.

## Metrics

- TP: an expected finding appeared.
- FN: an expected finding was missed.
- FP: a finding appeared where the manifest says it must be absent.
- TN: an absent expectation stayed quiet.
- Precision: `TP / (TP + FP)`.
- Recall: `TP / (TP + FN)`.
- F1: harmonic mean of precision and recall.

The benchmark uses two expectation modes:

- `present`: required findings. Missing these creates false negatives.
- `absent`: forbidden findings. Seeing these creates false positives.

## Run

```bash
python scripts/security_benchmark.py
python scripts/security_benchmark.py --json
python scripts/security_benchmark.py --case sql-tainted-param
```

## Adding Cases

1. Add a minimal fixture under `benchmarks/security/fixtures/`.
2. Add a manifest entry in `benchmarks/security/manifest.json`.
3. Keep expectations rule-specific where possible.
4. Prefer one semantic claim per fixture.
5. Add both positive and negative cases for risky rule changes.
