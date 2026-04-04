# Quality Benchmark

This suite measures how well Skylos catches code-quality issues while staying fast.

Unlike the dead-code corpus guard, this benchmark is score-based. Each case records:

- expected quality findings that must be present
- symbols or rule ids that must stay absent
- a per-case latency budget
- a taxonomy label so we can see where quality coverage is weak

Current scoring:

- `presence_recall` weights must-find quality issues
- `absence_guard` weights false-positive protection on clean or near-clean code
- `latency_score` rewards staying under the case budget
- `overall_score` combines them as `50% recall`, `35% absence guard`, `15% latency`

Why this exists:

- Codex-style quality review is not just about finding more issues.
- It also has to avoid noisy findings and stay fast enough to use in CI and local iteration.
- A benchmark lets us improve selectors, prompts, context, and verification loops without guessing.

Starter benchmark policy:

- Cases must be minimal and deterministic.
- Cases should be grounded in reputable upstream projects or official docs.
- Every case should protect either a common quality issue class or an important precision guard.
- Latency budgets should be generous enough for CI stability but strict enough to catch regressions.

How to add a case:

1. Add a fixture directory under `quality_benchmarks/fixtures/`.
2. Add a manifest entry in `quality_benchmarks/manifest.json`.
3. Pick one or more taxonomy labels from the allowed set in `skylos/quality_benchmark.py`.
4. Add explicit `present` and/or `absent` expectations plus a `max_seconds` budget.
5. Update `test/test_quality_benchmark.py` if the runner contract changes.
