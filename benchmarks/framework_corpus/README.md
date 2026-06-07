# Framework Corpus

This is the pinned real-repo layer for Skylos dead-code accuracy work.

The normal benchmark in `benchmarks/dead_code` is the blocking CI suite: small,
labeled fixtures with exact TP/FP/FN/TN scoring. This corpus is deliberately
larger and slower. It scans pinned upstream framework checkouts, compares the
dead-code category counts against checked-in baselines, and lets us promote any
confirmed FP or FN into a small fixture.

The runner treats target repositories as untrusted input. It does not install
dependencies, run tests, import target packages, or execute package scripts.

## Run

```bash
python scripts/framework_corpus.py
python scripts/framework_corpus.py --checkout-root /private/tmp/skylos-biglib-scan
python scripts/framework_corpus.py --target fastapi --checkout-root /private/tmp/skylos-biglib-scan
python scripts/framework_corpus.py --json --checkout-root /private/tmp/skylos-biglib-scan
```

Missing checkouts are skipped by default so this can run in developer
environments without network access:

```bash
python scripts/framework_corpus.py --require-checkouts
```

## Accuracy Loop

1. Pin a popular upstream repo and commit SHA in `manifest.json`.
2. Scan only source paths, not generated artifacts or dependency directories.
3. Manually inspect any surprising count change or known symbol anchor.
4. If the issue is generic, add a distilled fixture under
   `benchmarks/dead_code/fixtures`.
5. Keep the real-repo baseline as a nightly/manual drift signal.

This keeps CI deterministic while still using large real repositories to find
framework conventions that small fixtures would miss.
