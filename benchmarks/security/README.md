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

Labels are scanner-independent ground truth: they describe the vulnerable or
safe behavior in the fixture, not the current Skylos output. Positive and
negative fixtures should be paired when a rule has realistic sanitizer or guard
logic.

## Run

```bash
python scripts/security_benchmark.py
python scripts/security_benchmark.py --json
python scripts/security_benchmark.py --case sql-tainted-param
python scripts/security_benchmark.py --scanner bandit
python scripts/security_compare_scanners.py
```

Competitor scanners are optional local tools, not project dependencies. If a
competitor such as Bandit is unavailable, the comparison script reports it as
skipped and still prints the Skylos scorecard. Python-only scanners are scored
only on Python cases; Go, Java, TypeScript, C#, PHP, Rust, and Dart cases are
reported as skipped for that scanner instead of being counted as false
negatives.

Each Skylos benchmark case is scanned with a fixture-local changed-file set.
This keeps repository-level config findings from the Skylos repo itself out of
the case score while still allowing a fixture to include and test its own
workflow or config files.

## Adding Cases

1. Add a minimal fixture under `benchmarks/security/fixtures/`.
2. Add a manifest entry in `benchmarks/security/manifest.json`.
3. Keep expectations rule-specific where possible.
4. Prefer one semantic claim per fixture.
5. Add both positive and negative cases for risky rule changes.

Current golden cases cover SQL injection, SSRF, command injection, YAML loader
precision, path traversal, XSS, open redirect, JWT verification bypass, and CORS
misconfiguration. The cross-language cases currently cover Go Zip Slip
path traversal, Java servlet path traversal, TypeScript unsafe eval, C# command
execution/SQL/SSRF/path/open-redirect flows, and PHP unsafe
deserialization/path traversal with matched safe guards.
