# Skylos Dead-Code Reference

Use this reference for unused-code findings, false-positive reduction, liveness
analysis, framework entrypoints, traces, and benchmark comparisons.

## Default Commands

```bash
skylos . --format json
skylos . --confidence 80 --format json
skylos . --diff origin/main --format json
python scripts/dead_code_benchmark.py
python scripts/dead_code_compare_scanners.py
```

Use `--confidence` to tune dead-code reporting. Higher confidence reduces
candidate volume. Lower confidence surfaces riskier candidates.

## False-Positive Reduction Ladder

Prefer evidence in this order:

1. Static symbol references and imports.
2. Framework entrypoints and decorators.
3. Package entrypoints and configuration files.
4. Tests and fixtures that legitimately call the symbol.
5. Runtime traces, only when executing the target code is acceptable.
6. Suppressions, whitelist, or baseline for intentionally dynamic patterns.

Do not treat absence of a simple text reference as proof of dead code when the
framework commonly resolves names dynamically.

## Framework Areas

Skylos has framework-aware behavior for patterns such as:

- FastAPI, Flask, and Django routes.
- pytest tests, fixtures, and hooks.
- SQLAlchemy models and metadata.
- Next.js and React entrypoints.
- package entrypoints and plugin hooks.

When adding support, include a minimal positive fixture and a negative fixture
so the analyzer does not simply whitelist too much.

## Trace Mode Caution

`skylos . --trace` and coverage-style checks can execute project code. Only use
them on trusted repositories or when the user explicitly asks for runtime
evidence. Do not use trace mode as the default answer for untrusted PR review.

## Suppression Options

- `# skylos: ignore`: suppress a finding on one line.
- `# skylos: ignore-start` / `# skylos: ignore-end`: suppress a block.
- `ignore = ["SKY-XXX"]` in `[tool.skylos]`: suppress a rule project-wide.
- `skylos whitelist <pattern>`: manage whitelisted symbols.
- `skylos baseline .`: store current findings as accepted baseline.

Prefer analyzer improvements or precise suppressions over broad project-wide
ignores.

## Benchmark Expectations

For benchmark changes:

1. Use fixtures where ground truth is clear but not encoded in filenames.
2. Include framework and dynamic-reference patterns that static-only scanners
   commonly struggle with.
3. Compare Skylos against Vulture when relevant.
4. Report score, timing, and examples of true positives and false positives.
5. Keep public benchmark fixtures understandable and non-secret.

Useful files:

- `benchmarks/`
- `corpus/fixtures/`
- `scripts/dead_code_benchmark.py`
- `scripts/dead_code_compare_scanners.py`
- `test/test_dead_code*.py`
- `test/test_framework_aware.py`
